#ifndef __INCLUDE_SBOX_VPN_IPSEC_IKECRYPTO_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_IKECRYPTO_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <memory>
#include <string>
#include <vector>

// --> Cryptographic building blocks shared by IKEv2, the user-space ESP data path and (later)
// IKEv1: IANA transform identifiers, the IKE PRF and prf+, Diffie-Hellman groups and the
// encrypt-then-MAC / AEAD transform used both for the IKE SK payload and for ESP. Every
// primitive comes from libcertpp; this layer only shapes inputs and outputs.

namespace sbox {
namespace vpn {

    /**
     * IKEv2 transform types (RFC 7296 3.3.2).
     */
    enum EIkeTransformType : uint8_t {
        EIKE_TT_ENCR = 1,
        EIKE_TT_PRF = 2,
        EIKE_TT_INTEG = 3,
        EIKE_TT_DH = 4,
        EIKE_TT_ESN = 5,
    };

    /**
     * Encryption algorithm identifiers (IANA "Transform Type 1").
     */
    enum EIkeEncr : uint16_t {
        EIKE_ENCR_NONE = 0,
        EIKE_ENCR_3DES = 3,                 // --> Legacy, 168-bit key, 8-byte block.
        EIKE_ENCR_AES_CBC = 12,             // --> Needs a KEY_LENGTH attribute (128/192/256).
        EIKE_ENCR_AES_GCM_12 = 19,          // --> AEAD with a 12-byte ICV (RFC 4106 / RFC 5282).
        EIKE_ENCR_AES_GCM_16 = 20,          // --> AEAD with a 16-byte ICV.
        EIKE_ENCR_CHACHA20_POLY1305 = 28,   // --> AEAD (RFC 7634), 256-bit key.
    };

    /**
     * Pseudo-random function identifiers (IANA "Transform Type 2").
     */
    enum EIkePrf : uint16_t {
        EIKE_PRF_NONE = 0,
        EIKE_PRF_HMAC_SHA1 = 2,
        EIKE_PRF_HMAC_SHA2_256 = 5,
        EIKE_PRF_HMAC_SHA2_384 = 6,
        EIKE_PRF_HMAC_SHA2_512 = 7,
    };

    /**
     * Integrity algorithm identifiers (IANA "Transform Type 3").
     */
    enum EIkeInteg : uint16_t {
        EIKE_INTEG_NONE = 0,
        EIKE_INTEG_HMAC_SHA1_96 = 2,
        EIKE_INTEG_HMAC_SHA2_256_128 = 12,
        EIKE_INTEG_HMAC_SHA2_384_192 = 13,
        EIKE_INTEG_HMAC_SHA2_512_256 = 14,
    };

    /**
     * Diffie-Hellman group identifiers (IANA "Transform Type 4").
     */
    enum EIkeDhGroup : uint16_t {
        EIKE_DH_NONE = 0,
        EIKE_DH_MODP1024 = 2,       // --> Legacy (Windows default without a custom policy).
        EIKE_DH_MODP2048 = 14,
        EIKE_DH_ECP256 = 19,
        EIKE_DH_ECP384 = 20,
        EIKE_DH_CURVE25519 = 31,
    };

    /**
     * Extended sequence number identifiers (IANA "Transform Type 5").
     */
    enum EIkeEsn : uint16_t {
        EIKE_ESN_NO = 0,
        EIKE_ESN_YES = 1,
    };

    /**
     * Static description of an encryption transform.
     */
    struct SIkeEncrInfo {
        uint16_t id;
        bool aead;              // --> Combined mode: no separate integrity transform.
        bool keyLengthAttr;     // --> The proposal carries a KEY_LENGTH attribute.
        uint16_t defaultBits;   // --> Key length used when the attribute is absent.
        size_t blockSize;       // --> Cipher block size (1 for stream ciphers).
        size_t ivSize;          // --> Explicit IV bytes on the wire.
        size_t icvSize;         // --> AEAD tag bytes (0 for non-AEAD).
        size_t saltSize;        // --> Bytes of key material used as nonce salt (AEAD).
        const char* name;
    };

    /**
     * Returns the description of an encryption transform, or nullptr when unsupported.
     */
    SBOX_API const SIkeEncrInfo* IkeEncrInfo(uint16_t id) noexcept;

    /**
     * Returns true when `keyBits` is a valid key length for encryption transform `id`
     * (0 means "no attribute" and is only valid for fixed-key transforms).
     */
    SBOX_API bool IkeEncrKeyBitsValid(uint16_t id, uint16_t keyBits) noexcept;

    /**
     * Returns the key material bytes an encryption transform consumes from prf+ (key plus salt),
     * or 0 when unsupported.
     */
    SBOX_API size_t IkeEncrKeyMaterial(uint16_t id, uint16_t keyBits) noexcept;

    /**
     * Returns the output (and preferred key) size of a PRF, or 0 when unsupported.
     */
    SBOX_API size_t IkePrfSize(uint16_t prf) noexcept;

    /**
     * Returns the key size of an integrity transform, or 0 for NONE/unsupported.
     */
    SBOX_API size_t IkeIntegKeySize(uint16_t integ) noexcept;

    /**
     * Returns the truncated ICV size of an integrity transform, or 0 for NONE/unsupported.
     */
    SBOX_API size_t IkeIntegIcvSize(uint16_t integ) noexcept;

    /**
     * Returns true when this implementation supports Diffie-Hellman group `group`.
     */
    SBOX_API bool IkeDhSupported(uint16_t group) noexcept;

    /**
     * Returns a printable name of a transform ("AES_CBC", "HMAC_SHA2_256_128", "MODP_2048"...).
     */
    SBOX_API std::string IkeTransformName(uint8_t type, uint16_t id);

    /**
     * Computes prf(key, data) of an IKE PRF (HMAC family).
     * @return SBOX_OK or -ENOTSUP for an unknown PRF.
     */
    SBOX_API int32_t IkePrf(uint16_t prf, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data,
                            std::vector<uint8_t>& out);

    /**
     * Computes prf+(key, seed) (RFC 7296 2.13) producing `length` bytes.
     * @return SBOX_OK, -ENOTSUP for an unknown PRF, -EINVAL when more than 255 blocks are needed.
     */
    SBOX_API int32_t IkePrfPlus(uint16_t prf, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& seed,
                                size_t length, std::vector<uint8_t>& out);

    /**
     * Fills `out` from the CSPRNG (libcertpp).
     * @return true on success.
     */
    SBOX_API bool IkeRandom(const SByteSpan& out) noexcept;

    /**
     * Compares two byte strings in time that depends only on their lengths.
     */
    SBOX_API bool IkeSecureEquals(const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b) noexcept;

    /**
     * Zeroizes a buffer (not elided by the optimizer) and empties it.
     */
    SBOX_API void IkeWipe(std::vector<uint8_t>& v) noexcept;

    /**
     * Ephemeral Diffie-Hellman key pair of one IKE group (MODP 1024/2048, ECP 256/384,
     * Curve25519), with the RFC 7296 / RFC 5903 / RFC 8031 wire encodings.
     */
    class SBOX_API CIkeDh {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;
        uint16_t _group;
        std::vector<uint8_t> _public;

    public:
        CIkeDh();

        ~CIkeDh();

        CIkeDh(CIkeDh&&) noexcept;

        CIkeDh& operator=(CIkeDh&&) noexcept;

        /**
         * Generates a fresh key pair for `group`.
         * @return SBOX_OK, -ENOTSUP for an unknown group, -EIO when generation failed.
         */
        int32_t generate(uint16_t group);

        /**
         * Installs a known private value (test vectors only). For MODP groups this is the
         * big-endian exponent, for ECP the scalar, for Curve25519 the 32-byte private key.
         */
        int32_t loadPrivate(uint16_t group, const SReadOnlyByteSpan& privateValue);

        /** Returns the group. */
        inline uint16_t group() const noexcept { return _group; }

        /** Returns the public value in KE payload encoding. */
        inline const std::vector<uint8_t>& publicValue() const noexcept { return _public; }

        /**
         * Computes the shared secret g^ir (fixed length, left-padded) with the peer's KE data.
         * @return SBOX_OK, or -EINVAL when the peer value is malformed or degenerate.
         */
        int32_t agree(const SReadOnlyByteSpan& peer, std::vector<uint8_t>& secret) const;

        /**
         * Returns the expected KE data length of a group (0 when unsupported).
         */
        static size_t publicSize(uint16_t group) noexcept;
    };

    /**
     * One direction of an IPsec protection transform: AES-CBC/3DES with an HMAC (encrypt then
     * MAC) or an AEAD (AES-GCM, ChaCha20-Poly1305). The same layout -- explicit IV, ciphertext,
     * ICV -- serves the IKEv2 Encrypted payload (RFC 7296 3.14, RFC 5282, RFC 7634) and ESP
     * (RFC 4303, RFC 4106, RFC 7634), so both use this class.
     */
    class SBOX_API CIpsecCipher {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        CIpsecCipher();

        ~CIpsecCipher();

        CIpsecCipher(CIpsecCipher&&) noexcept;

        CIpsecCipher& operator=(CIpsecCipher&&) noexcept;

        /**
         * Keys the transform.
         * @param encr Encryption transform id (EIkeEncr).
         * @param keyBits Key length (0 for the transform's default).
         * @param integ Integrity transform (must be NONE for AEAD, set otherwise).
         * @param encKey Encryption key material (key plus salt for AEAD).
         * @param integKey Integrity key.
         * @return SBOX_OK, -ENOTSUP or -EINVAL.
         */
        int32_t init(uint16_t encr, uint16_t keyBits, uint16_t integ, const SReadOnlyByteSpan& encKey,
                     const SReadOnlyByteSpan& integKey);

        /** Returns true once keyed. */
        bool isValid() const noexcept;

        /** Returns true for an AEAD transform. */
        bool isAead() const noexcept;

        /** Returns the plaintext alignment the padding must reach. */
        size_t blockSize() const noexcept;

        /** Returns the explicit IV size. */
        size_t ivSize() const noexcept;

        /** Returns the ICV size. */
        size_t icvSize() const noexcept;

        /**
         * Protects `plain` (already padded by the caller to blockSize()) and appends
         * IV || ciphertext || ICV to `out`.
         * @param aad Bytes authenticated but not encrypted that precede the IV on the wire
         *        (IKE header and payload header, or ESP SPI and sequence number). For
         *        encrypt-then-MAC transforms the ICV covers aad || IV || ciphertext.
         * @param iv Explicit IV to use (ivSize() bytes), or an empty span to generate one
         *        (random for CBC, a per-key counter for AEAD).
         * @return SBOX_OK or -EIO.
         */
        int32_t seal(const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& plain, std::vector<uint8_t>& out,
                     const SReadOnlyByteSpan& iv = SReadOnlyByteSpan()) const;

        /**
         * Verifies and decrypts IV || ciphertext || ICV.
         * @param aad The authenticated prefix (see seal()).
         * @param sealed IV || ciphertext || ICV.
         * @param plain Receives the plaintext (still padded).
         * @return SBOX_OK, -EBADMSG for a malformed length, -EKEYREJECTED for a bad ICV.
         */
        int32_t open(const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& sealed, std::vector<uint8_t>& plain) const;
    };

}
}

#endif
