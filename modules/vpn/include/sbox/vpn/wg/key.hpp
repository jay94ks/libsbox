#ifndef __INCLUDE_SBOX_VPN_WG_KEY_HPP__
#define __INCLUDE_SBOX_VPN_WG_KEY_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace vpn {

    /** Length of every WireGuard key (Curve25519 private/public keys and preshared keys). */
    constexpr size_t WG_KEY_BYTES = 32;

    /**
     * A 32-byte WireGuard key: Curve25519 private key, public key or preshared key.
     * The text forms are the ones `wg` uses: base64 (44 characters ending in '=') in
     * configuration files and on the command line, lowercase hex in the cross-platform UAPI.
     */
    struct SBOX_API SWgKey {
        uint8_t bytes[WG_KEY_BYTES];
        bool valid;     // --> False for an unset key (bytes are then all zero).

        /**
         * Constructs an unset key.
         */
        SWgKey() noexcept;

        /**
         * Builds a key from 32 raw bytes.
         */
        static SWgKey fromBytes(const uint8_t* data) noexcept;

        /**
         * Parses the base64 form (exactly 44 characters, as `wg genkey` prints it).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromBase64(std::string_view text, SWgKey& out) noexcept;

        /**
         * Parses the hex form used by the UAPI (64 hex digits).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromHex(std::string_view text, SWgKey& out) noexcept;

        /**
         * Formats the key as base64 (44 characters); empty for an unset key.
         */
        std::string toBase64() const;

        /**
         * Formats the key as 64 lowercase hex digits; empty for an unset key.
         */
        std::string toHex() const;

        /**
         * Returns true when the key is set and all of its bytes are zero.
         */
        bool isZero() const noexcept;

        /**
         * Overwrites the key bytes with zeros and marks it unset.
         */
        void clear() noexcept;

        /** Returns the key bytes as a read-only span. */
        inline SReadOnlyByteSpan span() const noexcept { return SReadOnlyByteSpan(bytes, WG_KEY_BYTES); }

        /** Compares validity and bytes (constant time over the bytes). */
        bool operator==(const SWgKey& other) const noexcept;

        /** Compares validity and bytes. */
        inline bool operator!=(const SWgKey& other) const noexcept { return !(*this == other); }
    };

    /**
     * Generates a new Curve25519 private key (clamped, like `wg genkey`).
     * @return SBOX_OK or -EIO when the random source failed.
     */
    SBOX_API int32_t GenerateWgPrivateKey(SWgKey& out) noexcept;

    /**
     * Generates a random preshared key (like `wg genpsk`).
     */
    SBOX_API int32_t GenerateWgPresharedKey(SWgKey& out) noexcept;

    /**
     * Derives the public key of a private key (like `wg pubkey`).
     * @return SBOX_OK, -EINVAL for an unset key, or -EIO.
     */
    SBOX_API int32_t DeriveWgPublicKey(const SWgKey& privateKey, SWgKey& out) noexcept;

    /**
     * Computes the X25519 shared secret of a private key and a peer's public key.
     * @return SBOX_OK, -EINVAL for unset keys, or -EKEYREJECTED for a low-order peer key (the
     *         shared secret would be all zero).
     */
    SBOX_API int32_t WgSharedSecret(const SWgKey& privateKey, const SWgKey& publicKey, uint8_t out[WG_KEY_BYTES]) noexcept;

}
}

#endif
