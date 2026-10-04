#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "crypto.hpp"
#include <certpp/crypto/aeads/aesgcm.hpp>
#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/hmac.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/sym.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/montgomery.hpp>
#include <certpp/utils/secure.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace certpp::crypto;
    using ipsec::Cp;

    namespace ipsec {

        /* Hashes data. */
        std::vector<uint8_t> Hash(EHashers which, const SReadOnlyByteSpan& data) {
            return HashParts(which, { data });
        }

        /* Hashes several parts. */
        std::vector<uint8_t> HashParts(EHashers which, std::initializer_list<SReadOnlyByteSpan> parts) {
            IHasherPtr hasher;
            if (IHasher::create(which, hasher) != certpp::ERET_OK || !hasher) {
                return {};
            }

            for (const SReadOnlyByteSpan& part : parts) {
                if (part.size) {
                    hasher->push(Cp(part));
                }
            }

            std::vector<uint8_t> out(hasher->byteWidth());
            if (!hasher->finish(certpp::SByteSpan(out.data(), out.size()))) {
                return {};
            }

            return out;
        }

        /* HMAC. */
        std::vector<uint8_t> Hmac(EHashers which, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data) {
            IHasherPtr probe;
            if (IHasher::create(which, probe) != certpp::ERET_OK || !probe) {
                return {};
            }

            std::vector<uint8_t> out(probe->byteWidth());
            if (CHmac::compute(which, Cp(key), Cp(data), certpp::SByteSpan(out.data(), out.size())) != certpp::ERET_OK) {
                return {};
            }

            return out;
        }

        /* Hash behind a PRF. */
        EHashers PrfHash(uint16_t prf) {
            switch (prf) {
            case EIKE_PRF_HMAC_SHA1: return EHASH_SHA1;
            case EIKE_PRF_HMAC_SHA2_256: return EHASH_SHA256;
            case EIKE_PRF_HMAC_SHA2_384: return EHASH_SHA384;
            case EIKE_PRF_HMAC_SHA2_512: return EHASH_SHA512;
            default: return EHASH_UNKNOWN;
            }
        }

        /* Hash behind an integrity transform. */
        EHashers IntegHash(uint16_t integ) {
            switch (integ) {
            case EIKE_INTEG_HMAC_SHA1_96: return EHASH_SHA1;
            case EIKE_INTEG_HMAC_SHA2_256_128: return EHASH_SHA256;
            case EIKE_INTEG_HMAC_SHA2_384_192: return EHASH_SHA384;
            case EIKE_INTEG_HMAC_SHA2_512_256: return EHASH_SHA512;
            default: return EHASH_UNKNOWN;
            }
        }

        /* Hex formatting. */
        std::string ToHex(const SReadOnlyByteSpan& bytes, bool upper) {
            static const char LOWER[] = "0123456789abcdef";
            static const char UPPER[] = "0123456789ABCDEF";
            const char* digits = upper ? UPPER : LOWER;

            std::string out;
            out.reserve(bytes.size * 2);
            for (size_t i = 0; i < bytes.size; ++i) {
                out.push_back(digits[bytes[i] >> 4]);
                out.push_back(digits[bytes[i] & 15]);
            }

            return out;
        }

        /* Hex parsing. */
        bool FromHex(std::string_view text, std::vector<uint8_t>& out) {
            out.clear();
            int32_t high = -1;
            for (char c : text) {
                int32_t v;
                if (c >= '0' && c <= '9') {
                    v = c - '0';
                }
                else if (c >= 'a' && c <= 'f') {
                    v = c - 'a' + 10;
                }
                else if (c >= 'A' && c <= 'F') {
                    v = c - 'A' + 10;
                }
                else if (c == ' ' || c == ':' || c == '\n' || c == '\t' || c == '\r') {
                    continue;
                }
                else {
                    return false;
                }

                if (high < 0) {
                    high = v;
                }
                else {
                    out.push_back(uint8_t((high << 4) | v));
                    high = -1;
                }
            }

            return high < 0;
        }

    }

    namespace {

        const SIkeEncrInfo ENCRS[] = {
            { EIKE_ENCR_3DES, false, false, 192, 8, 8, 0, 0, "3DES" },
            { EIKE_ENCR_AES_CBC, false, true, 128, 16, 16, 0, 0, "AES_CBC" },
            { EIKE_ENCR_AES_GCM_12, true, true, 128, 4, 8, 12, 4, "AES_GCM_12" },
            { EIKE_ENCR_AES_GCM_16, true, true, 128, 4, 8, 16, 4, "AES_GCM_16" },
            { EIKE_ENCR_CHACHA20_POLY1305, true, false, 256, 4, 8, 16, 4, "CHACHA20_POLY1305" },
        };

        // --> RFC 2409 6.2 (Oakley group 2) and RFC 3526 3 (group 14); both use generator 2.
        const char* MODP1024 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
            "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
            "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

        const char* MODP2048 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
            "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
            "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
            "1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
            "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
            "955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

        /* Returns true for a MODP group and its prime. */
        bool modpPrime(uint16_t group, const char*& hex, size_t& bytes) {
            if (group == EIKE_DH_MODP1024) {
                hex = MODP1024;
                bytes = 128;
                return true;
            }

            if (group == EIKE_DH_MODP2048) {
                hex = MODP2048;
                bytes = 256;
                return true;
            }

            return false;
        }

        /* Maps an ECP/Curve25519 group to the certpp algorithm. */
        bool ecGroup(uint16_t group, EAsymmetrics& which, size_t& bits, size_t& coord) {
            switch (group) {
            case EIKE_DH_ECP256: which = EASYM_P256; bits = 256; coord = 32; return true;
            case EIKE_DH_ECP384: which = EASYM_P384; bits = 384; coord = 48; return true;
            case EIKE_DH_CURVE25519: which = EASYM_X25519; bits = 256; coord = 32; return true;
            default: return false;
            }
        }

    }

    /* Encryption transform description. */
    const SIkeEncrInfo* IkeEncrInfo(uint16_t id) noexcept {
        for (const SIkeEncrInfo& info : ENCRS) {
            if (info.id == id) {
                return &info;
            }
        }

        return nullptr;
    }

    /* Key length validity. */
    bool IkeEncrKeyBitsValid(uint16_t id, uint16_t keyBits) noexcept {
        const SIkeEncrInfo* info = IkeEncrInfo(id);
        if (!info) {
            return false;
        }

        if (!info->keyLengthAttr) {
            return keyBits == 0 || keyBits == info->defaultBits;
        }

        // --> AES transforms must carry the attribute (RFC 7296 3.3.5); the AEAD ones are AES too.
        return keyBits == 128 || keyBits == 192 || keyBits == 256;
    }

    /* Key material size. */
    size_t IkeEncrKeyMaterial(uint16_t id, uint16_t keyBits) noexcept {
        const SIkeEncrInfo* info = IkeEncrInfo(id);
        if (!info) {
            return 0;
        }

        uint16_t bits = keyBits ? keyBits : info->defaultBits;
        return bits / 8 + info->saltSize;
    }

    /* PRF output size. */
    size_t IkePrfSize(uint16_t prf) noexcept {
        switch (prf) {
        case EIKE_PRF_HMAC_SHA1: return 20;
        case EIKE_PRF_HMAC_SHA2_256: return 32;
        case EIKE_PRF_HMAC_SHA2_384: return 48;
        case EIKE_PRF_HMAC_SHA2_512: return 64;
        default: return 0;
        }
    }

    /* Integrity key size. */
    size_t IkeIntegKeySize(uint16_t integ) noexcept {
        switch (integ) {
        case EIKE_INTEG_HMAC_SHA1_96: return 20;
        case EIKE_INTEG_HMAC_SHA2_256_128: return 32;
        case EIKE_INTEG_HMAC_SHA2_384_192: return 48;
        case EIKE_INTEG_HMAC_SHA2_512_256: return 64;
        default: return 0;
        }
    }

    /* Integrity ICV size. */
    size_t IkeIntegIcvSize(uint16_t integ) noexcept {
        switch (integ) {
        case EIKE_INTEG_HMAC_SHA1_96: return 12;
        case EIKE_INTEG_HMAC_SHA2_256_128: return 16;
        case EIKE_INTEG_HMAC_SHA2_384_192: return 24;
        case EIKE_INTEG_HMAC_SHA2_512_256: return 32;
        default: return 0;
        }
    }

    /* DH group support. */
    bool IkeDhSupported(uint16_t group) noexcept {
        return CIkeDh::publicSize(group) != 0;
    }

    /* Transform names. */
    std::string IkeTransformName(uint8_t type, uint16_t id) {
        switch (type) {
        case EIKE_TT_ENCR:
            if (const SIkeEncrInfo* info = IkeEncrInfo(id)) {
                return info->name;
            }
            break;

        case EIKE_TT_PRF:
            switch (id) {
            case EIKE_PRF_HMAC_SHA1: return "PRF_HMAC_SHA1";
            case EIKE_PRF_HMAC_SHA2_256: return "PRF_HMAC_SHA2_256";
            case EIKE_PRF_HMAC_SHA2_384: return "PRF_HMAC_SHA2_384";
            case EIKE_PRF_HMAC_SHA2_512: return "PRF_HMAC_SHA2_512";
            default: break;
            }
            break;

        case EIKE_TT_INTEG:
            switch (id) {
            case EIKE_INTEG_NONE: return "NONE";
            case EIKE_INTEG_HMAC_SHA1_96: return "HMAC_SHA1_96";
            case EIKE_INTEG_HMAC_SHA2_256_128: return "HMAC_SHA2_256_128";
            case EIKE_INTEG_HMAC_SHA2_384_192: return "HMAC_SHA2_384_192";
            case EIKE_INTEG_HMAC_SHA2_512_256: return "HMAC_SHA2_512_256";
            default: break;
            }
            break;

        case EIKE_TT_DH:
            switch (id) {
            case EIKE_DH_NONE: return "NONE";
            case EIKE_DH_MODP1024: return "MODP_1024";
            case EIKE_DH_MODP2048: return "MODP_2048";
            case EIKE_DH_ECP256: return "ECP_256";
            case EIKE_DH_ECP384: return "ECP_384";
            case EIKE_DH_CURVE25519: return "CURVE_25519";
            default: break;
            }
            break;

        case EIKE_TT_ESN:
            return id == EIKE_ESN_YES ? "ESN" : "NO_ESN";

        default:
            break;
        }

        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u/%u", uint32_t(type), uint32_t(id));
        return buf;
    }

    /* prf(key, data). */
    int32_t IkePrf(uint16_t prf, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        EHashers which = ipsec::PrfHash(prf);
        if (which == EHASH_UNKNOWN) {
            return -ENOTSUP;
        }

        out = ipsec::Hmac(which, key, data);
        return out.empty() ? -EIO : SBOX_OK;
    }

    /* prf+(key, seed). */
    int32_t IkePrfPlus(uint16_t prf, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& seed, size_t length,
                       std::vector<uint8_t>& out) {
        size_t width = IkePrfSize(prf);
        EHashers which = ipsec::PrfHash(prf);
        if (!width || which == EHASH_UNKNOWN) {
            return -ENOTSUP;
        }

        // --> RFC 7296 2.13: the counter is one octet, so at most 255 blocks.
        if (length > width * 255) {
            return -EINVAL;
        }

        out.clear();
        out.reserve(length + width);

        std::vector<uint8_t> block;
        std::vector<uint8_t> input;
        uint8_t counter = 1;

        while (out.size() < length) {
            input.clear();
            ipsec::Append(input, BytesOf(block));
            ipsec::Append(input, seed);
            input.push_back(counter);

            std::vector<uint8_t> next = ipsec::Hmac(which, key, BytesOf(input));
            if (next.empty()) {
                IkeWipe(input);
                return -EIO;
            }

            IkeWipe(block);
            block = std::move(next);
            ipsec::Append(out, BytesOf(block));
            ++counter;
        }

        IkeWipe(block);
        IkeWipe(input);
        out.resize(length);
        return SBOX_OK;
    }

    /* CSPRNG. */
    bool IkeRandom(const SByteSpan& out) noexcept {
        if (out.size == 0) {
            return true;
        }

        return CRng::fill(Cp(out)) == certpp::ERET_OK;
    }

    /* Constant-time compare. */
    bool IkeSecureEquals(const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b) noexcept {
        if (a.size != b.size) {
            return false;
        }

        if (a.size == 0) {
            return true;
        }

        return certpp::CSecure::equals(Cp(a), Cp(b));
    }

    /* Wipe. */
    void IkeWipe(std::vector<uint8_t>& v) noexcept {
        if (!v.empty()) {
            certpp::CSecure::zero(certpp::SByteSpan(v.data(), v.size()));
        }

        v.clear();
    }

    // ---------------------------------------------------------------------------------------
    // Diffie-Hellman

    struct CIkeDh::SImpl {
        // --> MODP state.
        certpp::CBigNum prime;
        certpp::CBigNum exponent;
        size_t modBytes = 0;

        // --> ECP / Curve25519 state.
        IAsymmetricPtr asym;
        SKeyPair pair;
        size_t coord = 0;

        ~SImpl() {
            exponent.secureClear();
        }
    };

    CIkeDh::CIkeDh() : _group(0) {}

    CIkeDh::~CIkeDh() = default;

    CIkeDh::CIkeDh(CIkeDh&&) noexcept = default;

    CIkeDh& CIkeDh::operator=(CIkeDh&&) noexcept = default;

    /* KE data length of a group. */
    size_t CIkeDh::publicSize(uint16_t group) noexcept {
        const char* hex;
        size_t bytes;
        if (modpPrime(group, hex, bytes)) {
            return bytes;
        }

        EAsymmetrics which;
        size_t bits;
        size_t coord;
        if (ecGroup(group, which, bits, coord)) {
            return which == EASYM_X25519 ? coord : coord * 2;
        }

        return 0;
    }

    namespace {

        /* Serializes a big number left-padded to `bytes`. */
        bool fixedBytes(const certpp::CBigNum& value, size_t bytes, std::vector<uint8_t>& out) {
            out.assign(bytes, 0);
            return value.toBigEndian(certpp::SByteSpan(out.data(), out.size()));
        }

    }

    /* Generates a key pair. */
    int32_t CIkeDh::generate(uint16_t group) {
        auto impl = std::make_unique<SImpl>();
        const char* hex;
        size_t bytes;

        if (modpPrime(group, hex, bytes)) {
            if (!certpp::CBigNum::fromHex(hex, impl->prime)) {
                return -EIO;
            }

            // --> A 256-bit exponent gives well over the 2x-strength margin RFC 3526 asks for
            // both MODP groups; zero (vanishingly unlikely) is redrawn.
            do {
                if (!certpp::CBigNum::random(256, impl->exponent)) {
                    return -EIO;
                }
            } while (impl->exponent.isZero());

            certpp::CMontgomery mont(impl->prime);
            certpp::CBigNum pub = mont.modExp(certpp::CBigNum(2), impl->exponent);
            impl->modBytes = bytes;

            std::vector<uint8_t> encoded;
            if (!fixedBytes(pub, bytes, encoded)) {
                return -EIO;
            }

            _impl = std::move(impl);
            _public = std::move(encoded);
            _group = group;
            return SBOX_OK;
        }

        EAsymmetrics which;
        size_t bits;
        size_t coord;
        if (!ecGroup(group, which, bits, coord)) {
            return -ENOTSUP;
        }

        impl->asym = IAsymmetric::builtIn(which);
        if (!impl->asym) {
            return -ENOTSUP;
        }

        certpp::ERetCode rc = certpp::ERET_AGAIN;
        for (int32_t attempt = 0; attempt < 8 && rc == certpp::ERET_AGAIN; ++attempt) {
            rc = impl->asym->generateKeyPair(bits, impl->pair);
        }

        if (rc != certpp::ERET_OK || impl->pair.empty()) {
            return -EIO;
        }

        certpp::COctet pub;
        if (impl->pair.publicKey->serialize(pub) != certpp::ERET_OK) {
            return -EIO;
        }

        std::vector<uint8_t> encoded(pub.toPtr(), pub.toPtr() + pub.size());
        if (which != EASYM_X25519) {
            // --> RFC 5903 7: the KE data is x || y without SEC1's 0x04 prefix.
            if (encoded.size() != coord * 2 + 1 || encoded[0] != 0x04) {
                return -EIO;
            }

            encoded.erase(encoded.begin());
        }

        impl->coord = coord;
        _impl = std::move(impl);
        _public = std::move(encoded);
        _group = group;
        return SBOX_OK;
    }

    /* Installs a known private value. */
    int32_t CIkeDh::loadPrivate(uint16_t group, const SReadOnlyByteSpan& privateValue) {
        auto impl = std::make_unique<SImpl>();
        const char* hex;
        size_t bytes;

        if (modpPrime(group, hex, bytes)) {
            if (!certpp::CBigNum::fromHex(hex, impl->prime)) {
                return -EIO;
            }

            impl->exponent = certpp::CBigNum::fromBigEndian(Cp(privateValue));
            if (impl->exponent.isZero()) {
                return -EINVAL;
            }

            certpp::CMontgomery mont(impl->prime);
            certpp::CBigNum pub = mont.modExp(certpp::CBigNum(2), impl->exponent);
            impl->modBytes = bytes;

            std::vector<uint8_t> encoded;
            if (!fixedBytes(pub, bytes, encoded)) {
                return -EIO;
            }

            _impl = std::move(impl);
            _public = std::move(encoded);
            _group = group;
            return SBOX_OK;
        }

        EAsymmetrics which;
        size_t bits;
        size_t coord;
        if (!ecGroup(group, which, bits, coord) || !(impl->asym = IAsymmetric::builtIn(which))) {
            return -ENOTSUP;
        }

        IPrivateKeyPtr key = impl->asym->createPrivateKey(Cp(privateValue));
        if (!key || !key->publicKey()) {
            return -EINVAL;
        }

        impl->pair = SKeyPair(key->publicKey(), key);

        certpp::COctet pub;
        if (impl->pair.publicKey->serialize(pub) != certpp::ERET_OK) {
            return -EIO;
        }

        std::vector<uint8_t> encoded(pub.toPtr(), pub.toPtr() + pub.size());
        if (which != EASYM_X25519) {
            if (encoded.size() != coord * 2 + 1 || encoded[0] != 0x04) {
                return -EIO;
            }

            encoded.erase(encoded.begin());
        }

        impl->coord = coord;
        _impl = std::move(impl);
        _public = std::move(encoded);
        _group = group;
        return SBOX_OK;
    }

    /* Computes the shared secret. */
    int32_t CIkeDh::agree(const SReadOnlyByteSpan& peer, std::vector<uint8_t>& secret) const {
        if (!_impl) {
            return -EINVAL;
        }

        if (_impl->modBytes) {
            if (peer.size != _impl->modBytes) {
                return -EINVAL;
            }

            certpp::CBigNum y = certpp::CBigNum::fromBigEndian(Cp(peer));
            certpp::CBigNum pMinus1 = _impl->prime;
            pMinus1.sub(certpp::CBigNum(1));

            // --> RFC 6989 2.1: reject 0, 1 and p-1 (and anything >= p) as peer values.
            if (y <= certpp::CBigNum(1) || y >= pMinus1) {
                return -EINVAL;
            }

            certpp::CMontgomery mont(_impl->prime);
            certpp::CBigNum shared = mont.modExp(y, _impl->exponent);

            std::vector<uint8_t> out;
            if (!fixedBytes(shared, _impl->modBytes, out)) {
                return -EIO;
            }

            shared.secureClear();
            secret = std::move(out);
            return SBOX_OK;
        }

        bool x25519 = _group == EIKE_DH_CURVE25519;
        size_t expected = x25519 ? _impl->coord : _impl->coord * 2;
        if (peer.size != expected) {
            return -EINVAL;
        }

        std::vector<uint8_t> encoded;
        if (!x25519) {
            encoded.push_back(0x04);
        }

        ipsec::Append(encoded, peer);

        IPublicKeyPtr peerKey = _impl->asym->createPublicKey(certpp::SReadOnlyByteSpan(encoded.data(), encoded.size()));
        if (!peerKey) {
            return -EINVAL;
        }

        IAsymmetricContextPtr ctx = _impl->asym->createContext();
        if (!ctx) {
            return -EIO;
        }

        ctx->keyPair(_impl->pair);

        std::vector<uint8_t> buffer(_impl->coord * 2 + 8, 0);
        certpp::SByteSpan out(buffer.data(), buffer.size());
        if (ctx->deriveSharedSecret(peerKey, out) != certpp::ERET_OK || out.size != _impl->coord) {
            IkeWipe(buffer);
            return -EINVAL;
        }

        buffer.resize(out.size);

        // --> An all-zero result means a small-order (Curve25519, RFC 8031 2.3) or otherwise
        // degenerate peer point.
        std::vector<uint8_t> zeros(buffer.size(), 0);
        if (IkeSecureEquals(BytesOf(buffer), BytesOf(zeros))) {
            IkeWipe(buffer);
            return -EINVAL;
        }

        secret = std::move(buffer);
        return SBOX_OK;
    }

    // ---------------------------------------------------------------------------------------
    // Cipher

    struct CIpsecCipher::SImpl {
        const SIkeEncrInfo* info = nullptr;
        uint16_t integ = EIKE_INTEG_NONE;
        EHashers integHash = EHASH_UNKNOWN;
        size_t icv = 0;
        std::vector<uint8_t> key;           // --> Block cipher key (non-AEAD).
        std::vector<uint8_t> integKey;
        std::vector<uint8_t> salt;
        std::unique_ptr<CAesGcm> gcm;
        std::unique_ptr<CChaCha20Poly1305> chacha;
        ISymmetricPtr block;
        mutable uint64_t counter = 0;       // --> AEAD IV counter (unique per key).

        ~SImpl() {
            IkeWipe(key);
            IkeWipe(integKey);
            IkeWipe(salt);
        }
    };

    CIpsecCipher::CIpsecCipher() = default;

    CIpsecCipher::~CIpsecCipher() = default;

    CIpsecCipher::CIpsecCipher(CIpsecCipher&&) noexcept = default;

    CIpsecCipher& CIpsecCipher::operator=(CIpsecCipher&&) noexcept = default;

    /* Keys the transform. */
    int32_t CIpsecCipher::init(uint16_t encr, uint16_t keyBits, uint16_t integ, const SReadOnlyByteSpan& encKey,
                               const SReadOnlyByteSpan& integKey) {
        const SIkeEncrInfo* info = IkeEncrInfo(encr);
        if (!info) {
            return -ENOTSUP;
        }

        if (!IkeEncrKeyBitsValid(encr, keyBits)) {
            return -EINVAL;
        }

        size_t keyBytes = (keyBits ? keyBits : info->defaultBits) / 8;
        if (encKey.size != keyBytes + info->saltSize) {
            return -EINVAL;
        }

        auto impl = std::make_unique<SImpl>();
        impl->info = info;

        if (info->aead) {
            if (integ != EIKE_INTEG_NONE) {
                return -EINVAL;
            }

            impl->icv = info->icvSize;
            impl->salt.assign(encKey.data + keyBytes, encKey.data + encKey.size);
            certpp::SReadOnlyByteSpan k(encKey.data, keyBytes);

            if (encr == EIKE_ENCR_CHACHA20_POLY1305) {
                impl->chacha = std::make_unique<CChaCha20Poly1305>();
                if (!impl->chacha->reset(k)) {
                    return -EINVAL;
                }
            }
            else {
                impl->gcm = std::make_unique<CAesGcm>();
                if (!impl->gcm->reset(k)) {
                    return -EINVAL;
                }
            }

            // --> A random starting point keeps two SAs that share a key by mistake from
            // colliding; uniqueness within one key is what the counter guarantees.
            IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&impl->counter), sizeof(impl->counter)));
        }
        else {
            impl->integHash = ipsec::IntegHash(integ);
            if (impl->integHash == EHASH_UNKNOWN || integKey.size != IkeIntegKeySize(integ)) {
                return -EINVAL;
            }

            impl->integ = integ;
            impl->icv = IkeIntegIcvSize(integ);
            impl->integKey.assign(integKey.data, integKey.data + integKey.size);
            impl->key.assign(encKey.data, encKey.data + encKey.size);
            impl->block = ISymmetric::builtIn(encr == EIKE_ENCR_3DES ? ESYM_3DES : ESYM_AES);
            if (!impl->block) {
                return -ENOTSUP;
            }
        }

        _impl = std::move(impl);
        return SBOX_OK;
    }

    /* Keyed state. */
    bool CIpsecCipher::isValid() const noexcept {
        return bool(_impl);
    }

    /* AEAD flag. */
    bool CIpsecCipher::isAead() const noexcept {
        return _impl && _impl->info->aead;
    }

    /* Plaintext alignment. */
    size_t CIpsecCipher::blockSize() const noexcept {
        return _impl ? _impl->info->blockSize : 1;
    }

    /* IV size. */
    size_t CIpsecCipher::ivSize() const noexcept {
        return _impl ? _impl->info->ivSize : 0;
    }

    /* ICV size. */
    size_t CIpsecCipher::icvSize() const noexcept {
        return _impl ? _impl->icv : 0;
    }

    namespace {

        /* Runs unpadded CBC over `in` into `out` (same size). */
        bool runCbc(const ISymmetricPtr& algo, const std::vector<uint8_t>& key, const uint8_t* iv, size_t ivSize,
                    bool encrypt, const SReadOnlyByteSpan& in, uint8_t* out) {
            ISymmetricKeyPtr k = algo->createKey(certpp::SReadOnlyByteSpan(key.data(), key.size()));
            if (!k) {
                return false;
            }

            ISymmetricContextPtr ctx = algo->createContext(k);
            if (!ctx) {
                return false;
            }

            ctx->padding(ESYMPAD_NONE);
            ctx->key(k, certpp::CBuffer(iv, ivSize));

            ISymmetricTransformerPtr t;
            if ((encrypt ? ctx->createEncrypter(t) : ctx->createDecrypter(t)) != certpp::ERET_OK || !t) {
                return false;
            }

            // --> The transformer may hold the last block back until transformFinal(), so the
            // output buffer has one block of slack.
            std::vector<uint8_t> buffer(in.size + ivSize);
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

            std::memcpy(out, buffer.data(), in.size);
            certpp::CSecure::zero(certpp::SByteSpan(buffer.data(), buffer.size()));
            return true;
        }

    }

    /* Protects a padded plaintext. */
    int32_t CIpsecCipher::seal(const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& plain, std::vector<uint8_t>& out,
                               const SReadOnlyByteSpan& iv) const {
        if (!_impl) {
            return -EINVAL;
        }

        const SIkeEncrInfo* info = _impl->info;
        if (plain.size % info->blockSize != 0) {
            return -EINVAL;
        }

        if (!iv.empty() && iv.size != info->ivSize) {
            return -EINVAL;
        }

        uint8_t ivBytes[16];
        if (!iv.empty()) {
            std::memcpy(ivBytes, iv.data, iv.size);
        }
        else if (info->aead) {
            uint64_t c = _impl->counter++;
            for (size_t i = 0; i < 8; ++i) {
                ivBytes[i] = uint8_t(c >> (56 - 8 * i));
            }
        }
        else if (!IkeRandom(SByteSpan(ivBytes, info->ivSize))) {
            return -EIO;
        }

        size_t start = out.size();
        out.resize(start + info->ivSize + plain.size + _impl->icv);
        uint8_t* ivOut = out.data() + start;
        uint8_t* ctOut = ivOut + info->ivSize;
        uint8_t* icvOut = ctOut + plain.size;
        std::memcpy(ivOut, ivBytes, info->ivSize);

        if (info->aead) {
            uint8_t nonce[12];
            std::memcpy(nonce, _impl->salt.data(), 4);
            std::memcpy(nonce + 4, ivBytes, 8);

            bool ok;
            certpp::SReadOnlyByteSpan n(nonce, 12);
            certpp::SByteSpan ct(ctOut, plain.size);
            certpp::SByteSpan tag(icvOut, _impl->icv);
            if (_impl->chacha) {
                ok = _impl->chacha->seal(n, Cp(aad), Cp(plain), ct, tag);
            }
            else {
                ok = _impl->gcm->seal(n, Cp(aad), Cp(plain), ct, tag);
            }

            if (!ok) {
                out.resize(start);
                return -EIO;
            }

            return SBOX_OK;
        }

        if (!runCbc(_impl->block, _impl->key, ivBytes, info->ivSize, true, plain, ctOut)) {
            out.resize(start);
            return -EIO;
        }

        CHmac mac;
        if (mac.reset(_impl->integHash, certpp::SReadOnlyByteSpan(_impl->integKey.data(), _impl->integKey.size())) != certpp::ERET_OK) {
            out.resize(start);
            return -EIO;
        }

        if (aad.size) {
            mac.push(Cp(aad));
        }

        mac.push(certpp::SReadOnlyByteSpan(ivOut, info->ivSize + plain.size));

        uint8_t full[64];
        if (!mac.finish(certpp::SByteSpan(full, mac.byteWidth()))) {
            out.resize(start);
            return -EIO;
        }

        std::memcpy(icvOut, full, _impl->icv);
        return SBOX_OK;
    }

    /* Verifies and decrypts. */
    int32_t CIpsecCipher::open(const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& sealed, std::vector<uint8_t>& plain) const {
        if (!_impl) {
            return -EINVAL;
        }

        const SIkeEncrInfo* info = _impl->info;
        if (sealed.size < info->ivSize + _impl->icv) {
            return -EBADMSG;
        }

        size_t ctSize = sealed.size - info->ivSize - _impl->icv;
        if (ctSize % info->blockSize != 0) {
            return -EBADMSG;
        }

        const uint8_t* ivIn = sealed.data;
        const uint8_t* ctIn = ivIn + info->ivSize;
        const uint8_t* icvIn = ctIn + ctSize;

        if (info->aead) {
            uint8_t nonce[12];
            std::memcpy(nonce, _impl->salt.data(), 4);
            std::memcpy(nonce + 4, ivIn, 8);

            std::vector<uint8_t> out(ctSize);
            bool ok;
            certpp::SReadOnlyByteSpan n(nonce, 12);
            certpp::SReadOnlyByteSpan ct(ctIn, ctSize);
            certpp::SReadOnlyByteSpan tag(icvIn, _impl->icv);
            certpp::SByteSpan o(out.data(), out.size());
            if (_impl->chacha) {
                ok = _impl->chacha->open(n, Cp(aad), ct, tag, o);
            }
            else {
                ok = _impl->gcm->open(n, Cp(aad), ct, tag, o);
            }

            if (!ok) {
                return -EKEYREJECTED;
            }

            plain = std::move(out);
            return SBOX_OK;
        }

        CHmac mac;
        if (mac.reset(_impl->integHash, certpp::SReadOnlyByteSpan(_impl->integKey.data(), _impl->integKey.size())) != certpp::ERET_OK) {
            return -EIO;
        }

        if (aad.size) {
            mac.push(Cp(aad));
        }

        mac.push(certpp::SReadOnlyByteSpan(ivIn, info->ivSize + ctSize));

        uint8_t full[64];
        if (!mac.finish(certpp::SByteSpan(full, mac.byteWidth()))) {
            return -EIO;
        }

        if (!IkeSecureEquals(SReadOnlyByteSpan(full, _impl->icv), SReadOnlyByteSpan(icvIn, _impl->icv))) {
            return -EKEYREJECTED;
        }

        std::vector<uint8_t> out(ctSize);
        if (ctSize && !runCbc(_impl->block, _impl->key, ivIn, info->ivSize, false, SReadOnlyByteSpan(ctIn, ctSize), out.data())) {
            return -EIO;
        }

        plain = std::move(out);
        return SBOX_OK;
    }

}
}
