#include <sbox/vpn/wg/key.hpp>
#include <certpp/crypto/asyms/x25519.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/utils/secure.hpp>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    namespace {

        constexpr char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        /* Maps a base64 character to its value, or -1. */
        int32_t b64Value(char c) noexcept {
            if (c >= 'A' && c <= 'Z') {
                return c - 'A';
            }

            if (c >= 'a' && c <= 'z') {
                return c - 'a' + 26;
            }

            if (c >= '0' && c <= '9') {
                return c - '0' + 52;
            }

            if (c == '+') {
                return 62;
            }

            if (c == '/') {
                return 63;
            }

            return -1;
        }

        /* Maps a hex digit to its value, or -1. */
        int32_t hexValue(char c) noexcept {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }

            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }

            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }

            return -1;
        }

        /* Returns the shared X25519 algorithm instance. */
        const certpp::crypto::IAsymmetricPtr& x25519() {
            static certpp::crypto::IAsymmetricPtr algo = certpp::crypto::IAsymmetric::builtIn(certpp::crypto::EASYM_X25519);
            return algo;
        }

    }

    /* Constructs an unset key. */
    SWgKey::SWgKey() noexcept : valid(false) {
        std::memset(bytes, 0, sizeof(bytes));
    }

    /* Builds a key from raw bytes. */
    SWgKey SWgKey::fromBytes(const uint8_t* data) noexcept {
        SWgKey k;
        std::memcpy(k.bytes, data, WG_KEY_BYTES);
        k.valid = true;
        return k;
    }

    /* Parses base64. */
    int32_t SWgKey::fromBase64(std::string_view text, SWgKey& out) noexcept {
        // --> 32 bytes encode to 43 significant characters plus one '='.
        if (text.size() != 44 || text[43] != '=') {
            return -EINVAL;
        }

        uint8_t raw[33];
        size_t n = 0;
        uint32_t acc = 0;
        int32_t bits = 0;

        for (size_t i = 0; i < 43; ++i) {
            int32_t v = b64Value(text[i]);
            if (v < 0) {
                return -EINVAL;
            }

            acc = (acc << 6) | uint32_t(v);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                raw[n++] = uint8_t(acc >> bits);
            }
        }

        // --> The two leftover bits of the last character must be zero (canonical encoding).
        if (n != 32 || (acc & ((1u << bits) - 1u)) != 0) {
            return -EINVAL;
        }

        out = fromBytes(raw);
        return SBOX_OK;
    }

    /* Parses hex. */
    int32_t SWgKey::fromHex(std::string_view text, SWgKey& out) noexcept {
        if (text.size() != 64) {
            return -EINVAL;
        }

        uint8_t raw[32];
        for (size_t i = 0; i < 32; ++i) {
            int32_t hi = hexValue(text[2 * i]);
            int32_t lo = hexValue(text[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                return -EINVAL;
            }

            raw[i] = uint8_t((hi << 4) | lo);
        }

        out = fromBytes(raw);
        return SBOX_OK;
    }

    /* Formats base64. */
    std::string SWgKey::toBase64() const {
        if (!valid) {
            return std::string();
        }

        std::string out;
        out.reserve(44);

        size_t i = 0;
        for (; i + 3 <= WG_KEY_BYTES; i += 3) {
            uint32_t v = (uint32_t(bytes[i]) << 16) | (uint32_t(bytes[i + 1]) << 8) | bytes[i + 2];
            out.push_back(B64[(v >> 18) & 63]);
            out.push_back(B64[(v >> 12) & 63]);
            out.push_back(B64[(v >> 6) & 63]);
            out.push_back(B64[v & 63]);
        }

        // --> 32 = 30 + 2: the last group has two bytes.
        uint32_t v = (uint32_t(bytes[i]) << 16) | (uint32_t(bytes[i + 1]) << 8);
        out.push_back(B64[(v >> 18) & 63]);
        out.push_back(B64[(v >> 12) & 63]);
        out.push_back(B64[(v >> 6) & 63]);
        out.push_back('=');
        return out;
    }

    /* Formats hex. */
    std::string SWgKey::toHex() const {
        if (!valid) {
            return std::string();
        }

        static const char HEX[] = "0123456789abcdef";
        std::string out(64, '0');
        for (size_t i = 0; i < WG_KEY_BYTES; ++i) {
            out[2 * i] = HEX[bytes[i] >> 4];
            out[2 * i + 1] = HEX[bytes[i] & 15];
        }

        return out;
    }

    /* Checks for an all-zero key. */
    bool SWgKey::isZero() const noexcept {
        uint8_t acc = 0;
        for (size_t i = 0; i < WG_KEY_BYTES; ++i) {
            acc |= bytes[i];
        }

        return valid && acc == 0;
    }

    /* Wipes the key. */
    void SWgKey::clear() noexcept {
        certpp::CSecure::zero(certpp::SByteSpan(bytes, WG_KEY_BYTES));
        valid = false;
    }

    /* Constant-time equality. */
    bool SWgKey::operator==(const SWgKey& other) const noexcept {
        if (valid != other.valid) {
            return false;
        }

        return certpp::CSecure::equals(certpp::SReadOnlyByteSpan(bytes, WG_KEY_BYTES),
            certpp::SReadOnlyByteSpan(other.bytes, WG_KEY_BYTES));
    }

    /* Generates a clamped private key. */
    int32_t GenerateWgPrivateKey(SWgKey& out) noexcept {
        int32_t r = GenerateWgPresharedKey(out);
        if (r != SBOX_OK) {
            return r;
        }

        // --> Curve25519 clamping, stored pre-clamped exactly as `wg genkey` does.
        out.bytes[0] &= 248;
        out.bytes[31] &= 127;
        out.bytes[31] |= 64;
        return SBOX_OK;
    }

    /* Generates 32 random bytes. */
    int32_t GenerateWgPresharedKey(SWgKey& out) noexcept {
        out.valid = false;
        if (certpp::crypto::CRng::fill(certpp::SByteSpan(out.bytes, WG_KEY_BYTES)) != certpp::ERET_OK) {
            return -EIO;
        }

        out.valid = true;
        return SBOX_OK;
    }

    /* Derives the public key. */
    int32_t DeriveWgPublicKey(const SWgKey& privateKey, SWgKey& out) noexcept {
        if (!privateKey.valid) {
            return -EINVAL;
        }

        try {
            const certpp::crypto::IAsymmetricPtr& algo = x25519();
            if (!algo) {
                return -ENOTSUP;
            }

            certpp::crypto::IPrivateKeyPtr priv = algo->createPrivateKey(certpp::SReadOnlyByteSpan(privateKey.bytes, WG_KEY_BYTES));
            if (!priv) {
                return -EINVAL;
            }

            certpp::crypto::IPublicKeyPtr pub = priv->publicKey();
            certpp::COctet bytes;
            if (!pub || pub->serialize(bytes) != certpp::ERET_OK || bytes.size() != WG_KEY_BYTES) {
                return -EIO;
            }

            out = SWgKey::fromBytes(bytes.toPtr());
            return SBOX_OK;
        }
        catch (const std::bad_alloc&) {
            return -ENOMEM;
        }
    }

    /* X25519 key agreement. */
    int32_t WgSharedSecret(const SWgKey& privateKey, const SWgKey& publicKey, uint8_t out[WG_KEY_BYTES]) noexcept {
        if (!privateKey.valid || !publicKey.valid) {
            return -EINVAL;
        }

        try {
            const certpp::crypto::IAsymmetricPtr& algo = x25519();
            if (!algo) {
                return -ENOTSUP;
            }

            certpp::crypto::IPrivateKeyPtr priv = algo->createPrivateKey(certpp::SReadOnlyByteSpan(privateKey.bytes, WG_KEY_BYTES));
            certpp::crypto::IPublicKeyPtr pub = algo->createPublicKey(certpp::SReadOnlyByteSpan(publicKey.bytes, WG_KEY_BYTES));
            if (!priv || !pub) {
                return -EINVAL;
            }

            certpp::crypto::IAsymmetricContextPtr ctx = algo->createContext();
            ctx->keyPair(certpp::crypto::IPublicKeyPtr(), priv);

            certpp::SByteSpan span(out, WG_KEY_BYTES);
            if (ctx->deriveSharedSecret(pub, span) != certpp::ERET_OK) {
                // --> libcertpp refuses an all-zero result (a low-order point), as WireGuard must.
                std::memset(out, 0, WG_KEY_BYTES);
                return -EKEYREJECTED;
            }

            return SBOX_OK;
        }
        catch (const std::bad_alloc&) {
            return -ENOMEM;
        }
    }

}
}
