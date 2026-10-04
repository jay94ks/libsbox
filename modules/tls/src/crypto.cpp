#include "crypto.hpp"
#include "protocol.hpp"
#include "wire.hpp"
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/hmac.hpp>
#include <certpp/crypto/hkdf.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/utils/secure.hpp>
#include <cerrno>

namespace sbox {
namespace tls {

    using namespace certpp::crypto;

    /* Output length of a suite hash. */
    size_t HashSize(HashAlg alg) {
        return alg == HASH_SHA384 ? 48 : 32;
    }

    /* certpp identifier of a suite hash. */
    EHashers HashId(HashAlg alg) {
        return alg == HASH_SHA384 ? EHASH_SHA384 : EHASH_SHA256;
    }

    namespace {

        /* Hashes `data` with any certpp hasher. */
        std::vector<uint8_t> hashWith(EHashers which, const SReadOnlyByteSpan& data) {
            IHasherPtr hasher;
            if (IHasher::create(which, hasher) != certpp::ERET_OK || !hasher) {
                return {};
            }

            std::vector<uint8_t> out(hasher->byteWidth());
            if (data.size) {
                hasher->push(Cp(data));
            }

            if (!hasher->finish(certpp::SByteSpan(out.data(), out.size()))) {
                return {};
            }

            return out;
        }

        /* Maps a NamedGroup to the certpp algorithm and key size. */
        bool groupAlgorithm(uint16_t group, EAsymmetrics& which, size_t& bits) {
            switch (group) {
            case GROUP_X25519: which = EASYM_X25519; bits = 256; return true;
            case GROUP_SECP256R1: which = EASYM_P256; bits = 256; return true;
            case GROUP_SECP384R1: which = EASYM_P384; bits = 384; return true;
            default: return false;
            }
        }

    }

    /* Hashes data with a suite hash. */
    std::vector<uint8_t> Hash(HashAlg alg, const SReadOnlyByteSpan& data) {
        return hashWith(HashId(alg), data);
    }

    /* HMAC with a suite hash. */
    std::vector<uint8_t> Hmac(HashAlg alg, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data) {
        std::vector<uint8_t> out(HashSize(alg));
        if (CHmac::compute(HashId(alg), Cp(key), Cp(data), certpp::SByteSpan(out.data(), out.size())) != certpp::ERET_OK) {
            return {};
        }

        return out;
    }

    /* HKDF-Extract. */
    std::vector<uint8_t> HkdfExtract(HashAlg alg, const SReadOnlyByteSpan& salt, const SReadOnlyByteSpan& ikm) {
        std::vector<uint8_t> out(HashSize(alg));
        std::vector<uint8_t> zeros(HashSize(alg), 0);

        // --> RFC 8446 7.1 feeds a string of hashLen zeroes as IKM where there is no (EC)DHE or
        // PSK input; callers pass an empty span for that and it is spelled out here.
        SReadOnlyByteSpan key = ikm.size ? ikm : BytesOf(zeros);
        if (CHkdf::extract(HashId(alg), Cp(salt), Cp(key), certpp::SByteSpan(out.data(), out.size())) != certpp::ERET_OK) {
            return {};
        }

        return out;
    }

    /* HKDF-Expand-Label. */
    std::vector<uint8_t> HkdfExpandLabel(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                                         const SReadOnlyByteSpan& context, size_t length) {
        std::vector<uint8_t> info;
        Writer w(info);
        w.u16(uint32_t(length));
        w.begin(1);
        w.bytes(BytesOf("tls13 "));
        w.bytes(BytesOf(label));
        w.end();
        w.begin(1);
        w.bytes(context);
        w.end();

        std::vector<uint8_t> out(length);
        if (CHkdf::expand(HashId(alg), Cp(secret), certpp::SReadOnlyByteSpan(info.data(), info.size()),
                          certpp::SByteSpan(out.data(), out.size())) != certpp::ERET_OK) {
            return {};
        }

        return out;
    }

    /* Derive-Secret over an already hashed transcript. */
    std::vector<uint8_t> DeriveSecret(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                                      const SReadOnlyByteSpan& transcriptHash) {
        return HkdfExpandLabel(alg, secret, label, transcriptHash, HashSize(alg));
    }

    /* TLS 1.2 PRF. */
    std::vector<uint8_t> Prf12(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                               const SReadOnlyByteSpan& seed, size_t length) {
        std::vector<uint8_t> labelSeed;
        Writer w(labelSeed);
        w.bytes(BytesOf(label));
        w.bytes(seed);

        std::vector<uint8_t> out;
        std::vector<uint8_t> a = Hmac(alg, secret, BytesOf(labelSeed));

        while (out.size() < length && !a.empty()) {
            std::vector<uint8_t> input = a;
            input.insert(input.end(), labelSeed.begin(), labelSeed.end());

            std::vector<uint8_t> block = Hmac(alg, secret, BytesOf(input));
            if (block.empty()) {
                return {};
            }

            out.insert(out.end(), block.begin(), block.end());
            a = Hmac(alg, secret, BytesOf(a));
        }

        if (out.size() < length) {
            return {};
        }

        out.resize(length);
        return out;
    }

    /* OS randomness. */
    bool RandomBytes(const SByteSpan& out) {
        return CRng::fill(Cp(out)) == certpp::ERET_OK;
    }

    /* Constant-time comparison. */
    bool SecureEquals(const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b) {
        return certpp::CSecure::equals(Cp(a), Cp(b));
    }

    /* Zeroizes and clears. */
    void Wipe(std::vector<uint8_t>& v) {
        if (!v.empty()) {
            certpp::CSecure::zero(certpp::SByteSpan(v.data(), v.size()));
        }

        v.clear();
    }

    /* Groups this implementation can use. */
    bool KeyShare::supported(uint16_t group) {
        EAsymmetrics which;
        size_t bits;
        return groupAlgorithm(group, which, bits);
    }

    /* Generates an ephemeral key pair. */
    int32_t KeyShare::generate(uint16_t group) {
        EAsymmetrics which;
        size_t bits;
        if (!groupAlgorithm(group, which, bits)) {
            return -ENOTSUP;
        }

        _asym = IAsymmetric::builtIn(which);
        if (!_asym) {
            return -ENOTSUP;
        }

        // --> generateKeyPair asks to be retried when its candidate fails validation.
        certpp::ERetCode rc = certpp::ERET_AGAIN;
        for (int32_t attempt = 0; attempt < 8 && rc == certpp::ERET_AGAIN; ++attempt) {
            rc = _asym->generateKeyPair(bits, _pair);
        }

        if (rc != certpp::ERET_OK || _pair.empty()) {
            return -EIO;
        }

        certpp::COctet pub;
        if (_pair.publicKey->serialize(pub) != certpp::ERET_OK) {
            return -EIO;
        }

        _public.assign(pub.toPtr(), pub.toPtr() + pub.size());
        _group = group;
        return SBOX_OK;
    }

    /* Installs a known private key. */
    int32_t KeyShare::loadPrivate(uint16_t group, const SReadOnlyByteSpan& privateKey) {
        EAsymmetrics which;
        size_t bits;
        if (!groupAlgorithm(group, which, bits) || !(_asym = IAsymmetric::builtIn(which))) {
            return -ENOTSUP;
        }

        IPrivateKeyPtr key = _asym->createPrivateKey(Cp(privateKey));
        if (!key || !key->publicKey()) {
            return -EINVAL;
        }

        _pair = SKeyPair(key->publicKey(), key);

        certpp::COctet pub;
        if (_pair.publicKey->serialize(pub) != certpp::ERET_OK) {
            return -EIO;
        }

        _public.assign(pub.toPtr(), pub.toPtr() + pub.size());
        _group = group;
        return SBOX_OK;
    }

    /* Key agreement with the peer's public value. */
    int32_t KeyShare::agree(const SReadOnlyByteSpan& peer, std::vector<uint8_t>& secret) const {
        if (!_asym || _pair.empty()) {
            return -EINVAL;
        }

        // --> TLS 1.3 (4.2.8.2) and our TLS 1.2 ClientHello (ec_point_formats) both mandate the
        // uncompressed point form, so the length is fixed per group.
        size_t expected = _group == GROUP_X25519 ? 32 : _group == GROUP_SECP256R1 ? 65 : 97;
        if (peer.size != expected || (_group != GROUP_X25519 && peer[0] != 0x04)) {
            return -EINVAL;
        }

        IPublicKeyPtr peerKey = _asym->createPublicKey(Cp(peer));
        if (!peerKey) {
            return -EINVAL;
        }

        IAsymmetricContextPtr ctx = _asym->createContext();
        if (!ctx) {
            return -EIO;
        }

        ctx->keyPair(_pair);

        std::vector<uint8_t> buffer(80, 0);
        certpp::SByteSpan out(buffer.data(), buffer.size());
        if (ctx->deriveSharedSecret(peerKey, out) != certpp::ERET_OK || out.size == 0) {
            return -EINVAL;
        }

        buffer.resize(out.size);

        // --> An all-zero X25519 output means a small-order peer point (RFC 7748 6.1).
        std::vector<uint8_t> zeros(buffer.size(), 0);
        if (SecureEquals(BytesOf(buffer), BytesOf(zeros))) {
            Wipe(buffer);
            return -EINVAL;
        }

        secret = std::move(buffer);
        return SBOX_OK;
    }

    /* Hash of a signature scheme. */
    EHashers SchemeHash(uint16_t scheme) {
        switch (scheme) {
        case SIG_RSA_PKCS1_SHA256:
        case SIG_ECDSA_SECP256R1_SHA256:
        case SIG_RSA_PSS_RSAE_SHA256:
            return EHASH_SHA256;

        case SIG_RSA_PKCS1_SHA384:
        case SIG_ECDSA_SECP384R1_SHA384:
        case SIG_RSA_PSS_RSAE_SHA384:
            return EHASH_SHA384;

        case SIG_RSA_PKCS1_SHA512:
        case SIG_ECDSA_SECP521R1_SHA512:
        case SIG_RSA_PSS_RSAE_SHA512:
            return EHASH_SHA512;

        default:
            return EHASH_UNKNOWN;
        }
    }

    /* Whether a scheme fits a certificate key. */
    bool SchemeFitsKey(const certpp::x509::CCert& cert, uint16_t scheme, bool tls13) {
        IPublicKeyPtr pub = cert.publicKey();
        if (!pub) {
            return false;
        }

        EAsymmetrics which = pub->algorithm();

        switch (scheme) {
        case SIG_ECDSA_SECP256R1_SHA256:
            return tls13 ? which == EASYM_P256 : (which == EASYM_P256 || which == EASYM_P384 || which == EASYM_P521);

        case SIG_ECDSA_SECP384R1_SHA384:
            return tls13 ? which == EASYM_P384 : (which == EASYM_P256 || which == EASYM_P384 || which == EASYM_P521);

        case SIG_ECDSA_SECP521R1_SHA512:
            return tls13 ? which == EASYM_P521 : (which == EASYM_P256 || which == EASYM_P384 || which == EASYM_P521);

        case SIG_RSA_PSS_RSAE_SHA256:
        case SIG_RSA_PSS_RSAE_SHA384:
        case SIG_RSA_PSS_RSAE_SHA512:
            return which == EASYM_RSA;

        case SIG_RSA_PKCS1_SHA256:
        case SIG_RSA_PKCS1_SHA384:
        case SIG_RSA_PKCS1_SHA512:
            // --> RFC 8446 4.4.3: PKCS#1 v1.5 is for certificate signatures only in TLS 1.3.
            return !tls13 && which == EASYM_RSA;

        case SIG_ED25519:
            return which == EASYM_ED25519;

        default:
            return false;
        }
    }

    namespace {

        /* Returns true for the RSASSA-PSS schemes. */
        bool isPss(uint16_t scheme) {
            return scheme == SIG_RSA_PSS_RSAE_SHA256 || scheme == SIG_RSA_PSS_RSAE_SHA384 || scheme == SIG_RSA_PSS_RSAE_SHA512;
        }

    }

    /* Verifies a handshake signature. */
    int32_t VerifySignature(const certpp::x509::CCert& cert, uint16_t scheme, bool tls13,
                            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& signature) {
        if (!SchemeFitsKey(cert, scheme, tls13)) {
            return -ENOTSUP;
        }

        IAsymmetricContextPtr ctx = cert.createAsymmetricContext();
        if (!ctx) {
            return -ENOTSUP;
        }

        certpp::ERetCode rc;
        if (scheme == SIG_ED25519) {
            // --> Pure EdDSA signs the message itself, not a digest.
            rc = ctx->verify(Cp(message), Cp(signature));
        }
        else {
            EHashers hash = SchemeHash(scheme);
            std::vector<uint8_t> digest = hashWith(hash, message);
            if (digest.empty()) {
                return -EIO;
            }

            certpp::SReadOnlyByteSpan d(digest.data(), digest.size());
            // --> RFC 8446 4.2.3: the PSS salt length equals the digest length.
            rc = isPss(scheme) ? ctx->verifyPss(d, hash, digest.size(), Cp(signature)) : ctx->verify(d, Cp(signature));
        }

        return rc == certpp::ERET_OK ? SBOX_OK : -EKEYREJECTED;
    }

    /* Signs a message for client authentication. */
    int32_t SignMessage(const certpp::x509::CCert& cert, const IPrivateKeyPtr& key, uint16_t scheme,
                        const SReadOnlyByteSpan& message, std::vector<uint8_t>& signature) {
        IPublicKeyPtr pub = cert.publicKey();
        if (!pub || !key) {
            return -ENOTSUP;
        }

        IAsymmetricPtr asym = IAsymmetric::builtIn(pub->algorithm());
        IAsymmetricContextPtr ctx = asym ? asym->createContext() : nullptr;
        if (!ctx) {
            return -ENOTSUP;
        }

        ctx->keyPair(pub, key);

        std::vector<uint8_t> buffer(ctx->sizeOfSign() ? ctx->sizeOfSign() : 1024);
        certpp::SByteSpan out(buffer.data(), buffer.size());
        certpp::ERetCode rc;

        if (scheme == SIG_ED25519) {
            rc = ctx->sign(Cp(message), out);
        }
        else {
            EHashers hash = SchemeHash(scheme);
            std::vector<uint8_t> digest = hashWith(hash, message);
            if (digest.empty()) {
                return -EIO;
            }

            certpp::SReadOnlyByteSpan d(digest.data(), digest.size());
            rc = isPss(scheme) ? ctx->signPss(d, hash, digest.size(), out) : ctx->sign(d, out);
        }

        if (rc != certpp::ERET_OK) {
            return -EIO;
        }

        buffer.resize(out.size);
        signature = std::move(buffer);
        return SBOX_OK;
    }

}
}
