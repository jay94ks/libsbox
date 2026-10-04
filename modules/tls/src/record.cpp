#include "record.hpp"
#include "protocol.hpp"
#include <cerrno>
#include <cstdio>

namespace sbox {
namespace tls {

    namespace {

        const SuiteInfo SUITES[] = {
            { TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", true, AEAD_AES128_GCM, HASH_SHA256, 16, 12, false },
            { TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", true, AEAD_AES256_GCM, HASH_SHA384, 32, 12, false },
            { TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", true, AEAD_CHACHA20_POLY1305, HASH_SHA256, 32, 12, false },
            { TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false, AEAD_AES128_GCM, HASH_SHA256, 16, 4, true },
            { TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false, AEAD_AES256_GCM, HASH_SHA384, 32, 4, true },
            { TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", false, AEAD_CHACHA20_POLY1305, HASH_SHA256, 32, 12, true },
            { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, AEAD_AES128_GCM, HASH_SHA256, 16, 4, false },
            { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, AEAD_AES256_GCM, HASH_SHA384, 32, 4, false },
            { TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, AEAD_CHACHA20_POLY1305, HASH_SHA256, 32, 12, false },
        };

        /* Writes a record header. */
        void putHeader(std::vector<uint8_t>& out, uint8_t type, size_t length) {
            out.push_back(type);
            out.push_back(0x03);
            out.push_back(0x03);
            out.push_back(uint8_t(length >> 8));
            out.push_back(uint8_t(length));
        }

    }

    /* Looks a suite up. */
    const SuiteInfo* FindSuite(uint16_t id) {
        for (const SuiteInfo& s : SUITES) {
            if (s.id == id) {
                return &s;
            }
        }

        return nullptr;
    }

    /* Suite name for diagnostics. */
    std::string SuiteName(uint16_t id) {
        if (const SuiteInfo* s = FindSuite(id)) {
            return s->name;
        }

        char buf[16];
        std::snprintf(buf, sizeof(buf), "0x%04x", id);
        return buf;
    }

    /* Keys the direction. */
    bool RecordCipher::init(const SuiteInfo& suite, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& iv) {
        if (key.size != suite.keyLength || iv.size != suite.ivLength) {
            return false;
        }

        _gcm.reset();
        _chacha.reset();

        if (suite.aead == AEAD_CHACHA20_POLY1305) {
            _chacha = std::make_unique<certpp::crypto::CChaCha20Poly1305>();
            if (!_chacha->reset(Cp(key))) {
                return false;
            }
        }
        else {
            _gcm = std::make_unique<certpp::crypto::CAesGcm>();
            if (!_gcm->reset(Cp(key))) {
                return false;
            }
        }

        _iv.assign(iv.data, iv.data + iv.size);
        _seq = 0;
        _suite = &suite;
        return true;
    }

    /* Per-record nonce. */
    void RecordCipher::nonce(uint8_t out[12], const uint8_t* explicitPart) const {
        if (_iv.size() == 4) {
            // --> TLS 1.2 AES-GCM (RFC 5288 3): 4-byte implicit salt || 8-byte explicit nonce.
            std::memcpy(out, _iv.data(), 4);
            std::memcpy(out + 4, explicitPart, 8);
            return;
        }

        // --> TLS 1.3 and TLS 1.2 ChaCha20 (RFC 7905 2): IV XOR the padded sequence number.
        std::memcpy(out, _iv.data(), 12);
        for (int32_t i = 0; i < 8; ++i) {
            out[11 - i] ^= uint8_t(_seq >> (8 * i));
        }
    }

    /* AEAD seal. */
    bool RecordCipher::seal(const uint8_t nonceBytes[12], const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& in,
                            uint8_t* out, uint8_t* tag) const {
        certpp::SReadOnlyByteSpan n(nonceBytes, 12);
        certpp::SByteSpan o(out, in.size);
        certpp::SByteSpan t(tag, TAG);

        if (_chacha) {
            return _chacha->seal(n, Cp(aad), Cp(in), o, t);
        }

        return _gcm->seal(n, Cp(aad), Cp(in), o, t);
    }

    /* AEAD open, in place. */
    bool RecordCipher::open(const uint8_t nonceBytes[12], const SReadOnlyByteSpan& aad, uint8_t* data, size_t length,
                            const uint8_t* tag) const {
        certpp::SReadOnlyByteSpan n(nonceBytes, 12);
        certpp::SReadOnlyByteSpan in(data, length);
        certpp::SReadOnlyByteSpan t(tag, TAG);
        certpp::SByteSpan o(data, length);

        if (_chacha) {
            return _chacha->open(n, Cp(aad), in, t, o);
        }

        return _gcm->open(n, Cp(aad), in, t, o);
    }

    /* TLS 1.3 record protection. */
    bool RecordCipher::seal13(uint8_t type, const SReadOnlyByteSpan& plaintext, size_t padding, std::vector<uint8_t>& out) {
        if (!_suite || _seq == UINT64_MAX || plaintext.size > MAX_PLAINTEXT) {
            return false;
        }

        if (plaintext.size + 1 + padding > MAX_PLAINTEXT + 1) {
            padding = MAX_PLAINTEXT - plaintext.size;
        }

        size_t inner = plaintext.size + 1 + padding;
        size_t start = out.size();
        putHeader(out, CT_APPLICATION_DATA, inner + TAG);

        out.resize(start + 5 + inner + TAG, 0);
        uint8_t* body = out.data() + start + 5;
        if (plaintext.size) {
            std::memcpy(body, plaintext.data, plaintext.size);
        }
        body[plaintext.size] = type;

        uint8_t n[12];
        nonce(n, nullptr);

        // --> The AAD is the record header itself (RFC 8446 5.2).
        std::vector<uint8_t> aad(out.begin() + long(start), out.begin() + long(start) + 5);
        if (!seal(n, BytesOf(aad), SReadOnlyByteSpan(body, inner), body, body + inner)) {
            out.resize(start);
            return false;
        }

        ++_seq;
        return true;
    }

    /* TLS 1.3 record deprotection. */
    int32_t RecordCipher::open13(const uint8_t header[5], const SByteSpan& body, uint8_t& type, size_t& length) {
        if (!_suite || _seq == UINT64_MAX) {
            return -EBADMSG;
        }

        if (body.size < TAG + 1) {
            return -EBADMSG;
        }

        size_t clen = body.size - TAG;
        uint8_t n[12];
        nonce(n, nullptr);

        if (!open(n, SReadOnlyByteSpan(header, 5), body.data, clen, body.data + clen)) {
            return -EBADMSG;
        }

        ++_seq;

        // --> Strip the zero padding; the last non-zero byte is the real content type.
        size_t i = clen;
        while (i > 0 && body.data[i - 1] == 0) {
            --i;
        }

        if (i == 0) {
            return -EBADMSG;
        }

        type = body.data[i - 1];
        length = i - 1;

        if (length > MAX_PLAINTEXT) {
            return -EMSGSIZE;
        }

        return SBOX_OK;
    }

    /* TLS 1.2 record protection. */
    bool RecordCipher::seal12(uint8_t type, const SReadOnlyByteSpan& plaintext, std::vector<uint8_t>& out) {
        if (!_suite || _seq == UINT64_MAX || plaintext.size > MAX_PLAINTEXT) {
            return false;
        }

        bool explicitNonce = _iv.size() == 4;
        size_t explicitLen = explicitNonce ? 8 : 0;
        size_t start = out.size();
        putHeader(out, type, explicitLen + plaintext.size + TAG);
        out.resize(start + 5 + explicitLen + plaintext.size + TAG);

        uint8_t* p = out.data() + start + 5;
        uint8_t seqBytes[8];
        for (int32_t i = 0; i < 8; ++i) {
            seqBytes[7 - i] = uint8_t(_seq >> (8 * i));
        }

        if (explicitNonce) {
            // --> The sequence number is a fine explicit nonce: unique per key by construction.
            std::memcpy(p, seqBytes, 8);
        }

        uint8_t aad[13];
        std::memcpy(aad, seqBytes, 8);
        aad[8] = type;
        aad[9] = 0x03;
        aad[10] = 0x03;
        aad[11] = uint8_t(plaintext.size >> 8);
        aad[12] = uint8_t(plaintext.size);

        uint8_t n[12];
        nonce(n, seqBytes);

        uint8_t* ct = p + explicitLen;
        if (plaintext.size) {
            std::memcpy(ct, plaintext.data, plaintext.size);
        }

        if (!seal(n, SReadOnlyByteSpan(aad, 13), SReadOnlyByteSpan(ct, plaintext.size), ct, ct + plaintext.size)) {
            out.resize(start);
            return false;
        }

        ++_seq;
        return true;
    }

    /* TLS 1.2 record deprotection. */
    int32_t RecordCipher::open12(const uint8_t header[5], const SByteSpan& body, size_t& offset, size_t& length) {
        if (!_suite || _seq == UINT64_MAX) {
            return -EBADMSG;
        }

        bool explicitNonce = _iv.size() == 4;
        size_t explicitLen = explicitNonce ? 8 : 0;
        if (body.size < explicitLen + TAG) {
            return -EBADMSG;
        }

        size_t plen = body.size - explicitLen - TAG;
        if (plen > MAX_PLAINTEXT) {
            return -EMSGSIZE;
        }

        uint8_t aad[13];
        for (int32_t i = 0; i < 8; ++i) {
            aad[7 - i] = uint8_t(_seq >> (8 * i));
        }
        aad[8] = header[0];
        aad[9] = header[1];
        aad[10] = header[2];
        aad[11] = uint8_t(plen >> 8);
        aad[12] = uint8_t(plen);

        uint8_t n[12];
        nonce(n, body.data);

        uint8_t* ct = body.data + explicitLen;
        if (!open(n, SReadOnlyByteSpan(aad, 13), ct, plen, ct + plen)) {
            return -EBADMSG;
        }

        ++_seq;
        offset = explicitLen;
        length = plen;
        return SBOX_OK;
    }

}
}
