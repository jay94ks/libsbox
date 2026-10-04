#include <sbox/vpn/l2tp/ikev1crypto.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "ipsec/crypto.hpp"
#include <certpp/crypto/sym.hpp>
#include <certpp/utils/secure.hpp>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace certpp::crypto;
    using ipsec::Cp;

    namespace {

        /* Maps a Phase 1 hash to the certpp hasher. */
        EHashers hasherOf(uint16_t hash) {
            switch (hash) {
            case EIKE1_HASH_MD5: return EHASH_MD5;
            case EIKE1_HASH_SHA1: return EHASH_SHA1;
            case EIKE1_HASH_SHA256: return EHASH_SHA256;
            case EIKE1_HASH_SHA384: return EHASH_SHA384;
            case EIKE1_HASH_SHA512: return EHASH_SHA512;
            default: return EHASH_UNKNOWN;
            }
        }

        /* Appends a big-endian cookie. */
        void putCookie(std::vector<uint8_t>& out, uint64_t cookie) {
            ipsec::PutBe64(out, cookie);
        }

        /* Name of a Phase 1 hash. */
        const char* hashName(uint16_t hash) {
            switch (hash) {
            case EIKE1_HASH_MD5: return "MD5";
            case EIKE1_HASH_SHA1: return "SHA1";
            case EIKE1_HASH_SHA256: return "SHA2_256";
            case EIKE1_HASH_SHA384: return "SHA2_384";
            case EIKE1_HASH_SHA512: return "SHA2_512";
            default: return "HASH?";
            }
        }

    }

    /* Suite name. */
    std::string SIkev1Suite::toString() const {
        std::string text;
        if (encr == EIKE1_ENCR_AES) {
            text = "AES_CBC_" + std::to_string(keyBits);
        }
        else if (encr == EIKE1_ENCR_3DES) {
            text = "3DES_CBC";
        }
        else {
            text = "ENCR" + std::to_string(encr);
        }

        text += "/";
        text += hashName(hash);
        text += "/" + IkeTransformName(EIKE_TT_DH, group);
        return text;
    }

    /* Hash output size. */
    size_t Ikev1HashSize(uint16_t hash) noexcept {
        switch (hash) {
        case EIKE1_HASH_MD5: return 16;
        case EIKE1_HASH_SHA1: return 20;
        case EIKE1_HASH_SHA256: return 32;
        case EIKE1_HASH_SHA384: return 48;
        case EIKE1_HASH_SHA512: return 64;
        default: return 0;
        }
    }

    /* Block size. */
    size_t Ikev1BlockSize(uint16_t encr) noexcept {
        switch (encr) {
        case EIKE1_ENCR_3DES: return 8;
        case EIKE1_ENCR_AES: return 16;
        default: return 0;
        }
    }

    /* Key size. */
    size_t Ikev1KeySize(uint16_t encr, uint16_t keyBits) noexcept {
        if (encr == EIKE1_ENCR_3DES) {
            return keyBits == 0 || keyBits == 192 ? 24 : 0;
        }

        if (encr == EIKE1_ENCR_AES) {
            return keyBits == 128 || keyBits == 192 || keyBits == 256 ? keyBits / 8 : 0;
        }

        return 0;
    }

    /* Plain hash. */
    int32_t Ikev1Hash(uint16_t hash, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        EHashers which = hasherOf(hash);
        if (which == EHASH_UNKNOWN) {
            return -ENOTSUP;
        }

        out = ipsec::Hash(which, data);
        return out.empty() ? -EIO : SBOX_OK;
    }

    /* HMAC PRF. */
    int32_t Ikev1Prf(uint16_t hash, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        EHashers which = hasherOf(hash);
        if (which == EHASH_UNKNOWN) {
            return -ENOTSUP;
        }

        out = ipsec::Hmac(which, key, data);
        return out.empty() ? -EIO : SBOX_OK;
    }

    /* Wipes keys. */
    void SIkev1Keys::wipe() noexcept {
        IkeWipe(skeyid);
        IkeWipe(skeyidD);
        IkeWipe(skeyidA);
        IkeWipe(skeyidE);
        IkeWipe(encKey);
        IkeWipe(iv);
    }

    /* SKEYID (PSK). */
    int32_t Ikev1SkeyidPsk(uint16_t hash, const SReadOnlyByteSpan& psk, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr,
                           std::vector<uint8_t>& out) {
        std::vector<uint8_t> data;
        ipsec::Append(data, ni);
        ipsec::Append(data, nr);
        return Ikev1Prf(hash, psk, BytesOf(data), out);
    }

    /* SKEYID (signatures). */
    int32_t Ikev1SkeyidSig(uint16_t hash, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, const SReadOnlyByteSpan& gxy,
                           std::vector<uint8_t>& out) {
        std::vector<uint8_t> key;
        ipsec::Append(key, ni);
        ipsec::Append(key, nr);
        return Ikev1Prf(hash, BytesOf(key), gxy, out);
    }

    /* Key expansion. */
    int32_t Ikev1ExpandKey(uint16_t hash, const SReadOnlyByteSpan& skeyidE, size_t length, std::vector<uint8_t>& out) {
        out.clear();
        if (skeyidE.size >= length) {
            out.assign(skeyidE.data, skeyidE.data + length);
            return SBOX_OK;
        }

        uint8_t zero = 0;
        std::vector<uint8_t> k;
        int32_t r = Ikev1Prf(hash, skeyidE, SReadOnlyByteSpan(&zero, 1), k);
        if (r != SBOX_OK) {
            return r;
        }

        while (true) {
            out.insert(out.end(), k.begin(), k.end());
            if (out.size() >= length) {
                break;
            }

            std::vector<uint8_t> nk;
            r = Ikev1Prf(hash, skeyidE, BytesOf(k), nk);
            if (r != SBOX_OK) {
                return r;
            }

            k = std::move(nk);
        }

        IkeWipe(k);
        out.resize(length);
        return SBOX_OK;
    }

    /* SKEYID_d/a/e, encryption key, IV. */
    int32_t Ikev1DeriveKeys(const SIkev1Suite& suite, const SReadOnlyByteSpan& skeyid, const SReadOnlyByteSpan& gxy, uint64_t cookieI,
                            uint64_t cookieR, const SReadOnlyByteSpan& gxi, const SReadOnlyByteSpan& gxr, SIkev1Keys& out) {
        size_t keySize = Ikev1KeySize(suite.encr, suite.keyBits);
        size_t blockSize = Ikev1BlockSize(suite.encr);
        if (!keySize || !blockSize || !Ikev1HashSize(suite.hash)) {
            return -ENOTSUP;
        }

        out.wipe();
        out.skeyid.assign(skeyid.data, skeyid.data + skeyid.size);

        // --> SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0), then each next key is chained
        // in front: SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1), and so on.
        std::vector<uint8_t>* outs[3] = { &out.skeyidD, &out.skeyidA, &out.skeyidE };
        const std::vector<uint8_t>* previous = nullptr;
        for (uint8_t i = 0; i < 3; ++i) {
            std::vector<uint8_t> data;
            if (previous) {
                ipsec::Append(data, BytesOf(*previous));
            }

            ipsec::Append(data, gxy);
            putCookie(data, cookieI);
            putCookie(data, cookieR);
            data.push_back(i);
            int32_t r = Ikev1Prf(suite.hash, skeyid, BytesOf(data), *outs[i]);
            IkeWipe(data);
            if (r != SBOX_OK) {
                return r;
            }

            previous = outs[i];
        }

        int32_t r = Ikev1ExpandKey(suite.hash, BytesOf(out.skeyidE), keySize, out.encKey);
        if (r != SBOX_OK) {
            return r;
        }

        std::vector<uint8_t> ivData;
        ipsec::Append(ivData, gxi);
        ipsec::Append(ivData, gxr);
        r = Ikev1Hash(suite.hash, BytesOf(ivData), out.iv);
        if (r != SBOX_OK) {
            return r;
        }

        if (out.iv.size() < blockSize) {
            return -EINVAL;
        }

        out.iv.resize(blockSize);
        return SBOX_OK;
    }

    /* HASH_I / HASH_R. */
    int32_t Ikev1Phase1Hash(uint16_t hash, const SReadOnlyByteSpan& skeyid, const SReadOnlyByteSpan& gxa, const SReadOnlyByteSpan& gxb,
                            uint64_t ckyA, uint64_t ckyB, const SReadOnlyByteSpan& saiB, const SReadOnlyByteSpan& idB,
                            std::vector<uint8_t>& out) {
        std::vector<uint8_t> data;
        ipsec::Append(data, gxa);
        ipsec::Append(data, gxb);
        putCookie(data, ckyA);
        putCookie(data, ckyB);
        ipsec::Append(data, saiB);
        ipsec::Append(data, idB);
        return Ikev1Prf(hash, skeyid, BytesOf(data), out);
    }

    /* Phase 2 IV. */
    int32_t Ikev1Phase2Iv(uint16_t hash, size_t blockSize, const SReadOnlyByteSpan& phase1Iv, uint32_t messageId,
                          std::vector<uint8_t>& out) {
        std::vector<uint8_t> data;
        ipsec::Append(data, phase1Iv);
        ipsec::PutBe32(data, messageId);
        int32_t r = Ikev1Hash(hash, BytesOf(data), out);
        if (r != SBOX_OK) {
            return r;
        }

        if (out.size() < blockSize) {
            return -EINVAL;
        }

        out.resize(blockSize);
        return SBOX_OK;
    }

    /* Quick Mode KEYMAT. */
    int32_t Ikev1QuickKeymat(uint16_t hash, const SReadOnlyByteSpan& skeyidD, const SReadOnlyByteSpan& gxyQm, uint8_t protocol,
                             const SReadOnlyByteSpan& spi, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, size_t length,
                             std::vector<uint8_t>& out) {
        std::vector<uint8_t> seed;
        ipsec::Append(seed, gxyQm);
        seed.push_back(protocol);
        ipsec::Append(seed, spi);
        ipsec::Append(seed, ni);
        ipsec::Append(seed, nr);

        out.clear();
        std::vector<uint8_t> k;
        while (out.size() < length) {
            std::vector<uint8_t> data;
            ipsec::Append(data, BytesOf(k));
            ipsec::Append(data, BytesOf(seed));
            std::vector<uint8_t> next;
            int32_t r = Ikev1Prf(hash, skeyidD, BytesOf(data), next);
            IkeWipe(data);
            if (r != SBOX_OK) {
                IkeWipe(seed);
                return r;
            }

            out.insert(out.end(), next.begin(), next.end());
            IkeWipe(k);
            k = std::move(next);
        }

        IkeWipe(k);
        IkeWipe(seed);
        out.resize(length);
        return SBOX_OK;
    }

    /* NAT-D hash. */
    int32_t Ikev1NatHash(uint16_t hash, uint64_t cookieI, uint64_t cookieR, const net::SIpAddress& address, uint16_t port,
                         std::vector<uint8_t>& out) {
        std::vector<uint8_t> data;
        putCookie(data, cookieI);
        putCookie(data, cookieR);
        data.insert(data.end(), address.bytes, address.bytes + address.length());
        ipsec::PutBe16(data, port);
        return Ikev1Hash(hash, BytesOf(data), out);
    }

    // ---------------------------------------------------------------------------------------
    // Phase 1 CBC

    struct CIkev1Cipher::SImpl {
        ISymmetricPtr algo;
        std::vector<uint8_t> key;
        size_t blockSize = 0;

        ~SImpl() {
            IkeWipe(key);
        }

        /* Runs unpadded CBC. */
        bool run(const std::vector<uint8_t>& iv, bool encrypt, const SReadOnlyByteSpan& in, std::vector<uint8_t>& out) const {
            ISymmetricKeyPtr k = algo->createKey(certpp::SReadOnlyByteSpan(key.data(), key.size()));
            if (!k) {
                return false;
            }

            ISymmetricContextPtr ctx = algo->createContext(k);
            if (!ctx) {
                return false;
            }

            ctx->padding(ESYMPAD_NONE);
            ctx->key(k, certpp::CBuffer(iv.data(), iv.size()));
            ISymmetricTransformerPtr t;
            if ((encrypt ? ctx->createEncrypter(t) : ctx->createDecrypter(t)) != certpp::ERET_OK || !t) {
                return false;
            }

            // --> One block of slack: the transformer may hold the last block until the final call.
            std::vector<uint8_t> buffer(in.size + blockSize);
            certpp::SByteSpan step(buffer.data(), buffer.size());
            if (t->transform(Cp(in), step) != certpp::ERET_OK) {
                return false;
            }

            size_t written = step.size;
            certpp::SByteSpan last(buffer.data() + written, buffer.size() - written);
            if (t->transformFinal(last) != certpp::ERET_OK) {
                return false;
            }

            written += last.size;
            if (written != in.size) {
                return false;
            }

            out.assign(buffer.begin(), buffer.begin() + long(in.size));
            certpp::CSecure::zero(certpp::SByteSpan(buffer.data(), buffer.size()));
            return true;
        }
    };

    CIkev1Cipher::CIkev1Cipher() = default;

    CIkev1Cipher::~CIkev1Cipher() = default;

    /* Keys the cipher. */
    int32_t CIkev1Cipher::init(uint16_t encr, const SReadOnlyByteSpan& key) {
        auto impl = std::make_shared<SImpl>();
        impl->blockSize = Ikev1BlockSize(encr);
        if (!impl->blockSize) {
            return -ENOTSUP;
        }

        if (encr == EIKE1_ENCR_3DES ? key.size != 24 : (key.size != 16 && key.size != 24 && key.size != 32)) {
            return -EINVAL;
        }

        impl->algo = ISymmetric::builtIn(encr == EIKE1_ENCR_3DES ? ESYM_3DES : ESYM_AES);
        if (!impl->algo) {
            return -ENOTSUP;
        }

        impl->key.assign(key.data, key.data + key.size);
        _impl = std::move(impl);
        return SBOX_OK;
    }

    /* Keyed state. */
    bool CIkev1Cipher::isValid() const noexcept {
        return bool(_impl);
    }

    /* Block size. */
    size_t CIkev1Cipher::blockSize() const noexcept {
        return _impl ? _impl->blockSize : 0;
    }

    /* Encrypts. */
    int32_t CIkev1Cipher::encrypt(std::vector<uint8_t>& iv, const SReadOnlyByteSpan& plain, std::vector<uint8_t>& out) const {
        if (!_impl || iv.size() != _impl->blockSize || plain.size % _impl->blockSize != 0 || plain.size == 0) {
            return -EINVAL;
        }

        if (!_impl->run(iv, true, plain, out)) {
            return -EIO;
        }

        iv.assign(out.end() - long(_impl->blockSize), out.end());
        return SBOX_OK;
    }

    /* Decrypts. */
    int32_t CIkev1Cipher::decrypt(std::vector<uint8_t>& iv, const SReadOnlyByteSpan& cipher, std::vector<uint8_t>& out) const {
        if (!_impl || iv.size() != _impl->blockSize) {
            return -EINVAL;
        }

        if (cipher.size == 0 || cipher.size % _impl->blockSize != 0) {
            return -EBADMSG;
        }

        if (!_impl->run(iv, false, cipher, out)) {
            return -EIO;
        }

        iv.assign(cipher.data + cipher.size - _impl->blockSize, cipher.data + cipher.size);
        return SBOX_OK;
    }

    /* ESP transform mapping. */
    bool Ikev1EspTransform(uint8_t espId, uint16_t keyLength, uint16_t authAlg, uint16_t& encr, uint16_t& keyBits,
                           uint16_t& integ) noexcept {
        switch (espId) {
        case EIKE1_ESP_3DES:
            if (keyLength != 0 && keyLength != 192) {
                return false;
            }

            encr = EIKE_ENCR_3DES;
            keyBits = 0;
            break;

        case EIKE1_ESP_AES:
            // --> RFC 3602: the key length attribute is mandatory; 128 is the common default.
            keyBits = keyLength ? keyLength : 128;
            if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
                return false;
            }

            encr = EIKE_ENCR_AES_CBC;
            break;

        case EIKE1_ESP_AES_GCM_12:
        case EIKE1_ESP_AES_GCM_16:
            keyBits = keyLength ? keyLength : 128;
            if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
                return false;
            }

            encr = espId == EIKE1_ESP_AES_GCM_16 ? EIKE_ENCR_AES_GCM_16 : EIKE_ENCR_AES_GCM_12;
            if (authAlg != EIKE1_AA_NONE) {
                return false;
            }

            integ = EIKE_INTEG_NONE;
            return IkeEncrKeyBitsValid(encr, keyBits);

        default:
            return false;
        }

        switch (authAlg) {
        case EIKE1_AA_HMAC_SHA1: integ = EIKE_INTEG_HMAC_SHA1_96; break;
        case EIKE1_AA_HMAC_SHA256: integ = EIKE_INTEG_HMAC_SHA2_256_128; break;
        case EIKE1_AA_HMAC_SHA384: integ = EIKE_INTEG_HMAC_SHA2_384_192; break;
        case EIKE1_AA_HMAC_SHA512: integ = EIKE_INTEG_HMAC_SHA2_512_256; break;
        default: return false;
        }

        return IkeEncrKeyBitsValid(encr, keyBits);
    }

}
}
