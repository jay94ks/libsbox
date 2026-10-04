#ifndef __INCLUDE_SBOX_VPN_L2TP_IKEV1CRYPTO_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_IKEV1CRYPTO_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/l2tp/ikev1.hpp>
#include <memory>
#include <string>
#include <vector>

// --> IKEv1 key derivation and Phase 1 encryption (RFC 2409 5, 5.5, Appendix B): the hash and
// its HMAC PRF, SKEYID for pre-shared keys, SKEYID_d/a/e, encryption key expansion, the CBC
// IV chain of Phase 1 and of every Phase 2 / informational exchange, Quick Mode KEYMAT and the
// NAT-D hash of RFC 3947. Hashes, HMAC and the block ciphers come from libcertpp.

namespace sbox {
namespace vpn {

    /**
     * Negotiated Phase 1 (ISAKMP SA) parameters.
     */
    struct SIkev1Suite {
        uint16_t encr = EIKE1_ENCR_AES;     // --> EIkev1Encr.
        uint16_t keyBits = 128;             // --> AES key length; 192 for 3DES.
        uint16_t hash = EIKE1_HASH_SHA1;    // --> EIkev1Hash.
        uint16_t auth = EIKE1_AUTH_PSK;
        uint16_t group = 2;                 // --> Diffie-Hellman group (EIkeDhGroup numbering).
        uint32_t lifeSeconds = 28800;

        /** Formats "AES_CBC_256/SHA1/MODP_1024". */
        std::string toString() const;
    };

    /**
     * Returns the output size of a Phase 1 hash, or 0 when unsupported.
     */
    SBOX_API size_t Ikev1HashSize(uint16_t hash) noexcept;

    /**
     * Returns the cipher block size of a Phase 1 encryption algorithm (0 when unsupported).
     */
    SBOX_API size_t Ikev1BlockSize(uint16_t encr) noexcept;

    /**
     * Returns the key size in bytes of a Phase 1 encryption algorithm and key length (0 when
     * the combination is invalid).
     */
    SBOX_API size_t Ikev1KeySize(uint16_t encr, uint16_t keyBits) noexcept;

    /**
     * Computes the plain hash of `data`.
     * @return SBOX_OK or -ENOTSUP.
     */
    SBOX_API int32_t Ikev1Hash(uint16_t hash, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out);

    /**
     * Computes prf(key, data): HMAC with the negotiated hash.
     * @return SBOX_OK or -ENOTSUP.
     */
    SBOX_API int32_t Ikev1Prf(uint16_t hash, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out);

    /**
     * Keying material of an ISAKMP SA.
     */
    struct SIkev1Keys {
        std::vector<uint8_t> skeyid;
        std::vector<uint8_t> skeyidD;
        std::vector<uint8_t> skeyidA;
        std::vector<uint8_t> skeyidE;
        std::vector<uint8_t> encKey;        // --> SKEYID_e expanded/truncated to the cipher key.
        std::vector<uint8_t> iv;            // --> Initial Phase 1 IV: hash(g^xi | g^xr), block size.

        /** Zeroizes everything. */
        void wipe() noexcept;
    };

    /**
     * SKEYID for pre-shared keys: prf(psk, Ni_b | Nr_b).
     */
    SBOX_API int32_t Ikev1SkeyidPsk(uint16_t hash, const SReadOnlyByteSpan& psk, const SReadOnlyByteSpan& ni,
                                    const SReadOnlyByteSpan& nr, std::vector<uint8_t>& out);

    /**
     * SKEYID for signatures: prf(Ni_b | Nr_b, g^xy).
     */
    SBOX_API int32_t Ikev1SkeyidSig(uint16_t hash, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr,
                                    const SReadOnlyByteSpan& gxy, std::vector<uint8_t>& out);

    /**
     * Derives SKEYID_d/a/e, the encryption key (RFC 2409 Appendix B expansion) and the initial
     * IV from SKEYID.
     * @param gxi Initiator's public value; @param gxr responder's public value.
     * @return SBOX_OK, -ENOTSUP or -EINVAL.
     */
    SBOX_API int32_t Ikev1DeriveKeys(const SIkev1Suite& suite, const SReadOnlyByteSpan& skeyid, const SReadOnlyByteSpan& gxy,
                                     uint64_t cookieI, uint64_t cookieR, const SReadOnlyByteSpan& gxi,
                                     const SReadOnlyByteSpan& gxr, SIkev1Keys& out);

    /**
     * Expands SKEYID_e into a `length`-byte cipher key: K = K1 | K2 | ..., K1 = prf(SKEYID_e, 0),
     * Kn = prf(SKEYID_e, Kn-1); used only when SKEYID_e is shorter than the key.
     */
    SBOX_API int32_t Ikev1ExpandKey(uint16_t hash, const SReadOnlyByteSpan& skeyidE, size_t length, std::vector<uint8_t>& out);

    /**
     * Phase 1 hash HASH_I / HASH_R: prf(SKEYID, g^xa | g^xb | CKY-A | CKY-B | SAi_b | IDa_b).
     * For HASH_I pass (gxi, gxr, ckyI, ckyR, IDii_b), for HASH_R (gxr, gxi, ckyR, ckyI, IDir_b).
     */
    SBOX_API int32_t Ikev1Phase1Hash(uint16_t hash, const SReadOnlyByteSpan& skeyid, const SReadOnlyByteSpan& gxa,
                                     const SReadOnlyByteSpan& gxb, uint64_t ckyA, uint64_t ckyB, const SReadOnlyByteSpan& saiB,
                                     const SReadOnlyByteSpan& idB, std::vector<uint8_t>& out);

    /**
     * IV of a new Phase 2 or informational exchange: hash(last Phase 1 block | M-ID), cut to
     * the block size.
     */
    SBOX_API int32_t Ikev1Phase2Iv(uint16_t hash, size_t blockSize, const SReadOnlyByteSpan& phase1Iv, uint32_t messageId,
                                   std::vector<uint8_t>& out);

    /**
     * Quick Mode KEYMAT (RFC 2409 5.5): prf(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b)
     * expanded as K1 | K2 | ... with Kn = prf(SKEYID_d, Kn-1 | [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b).
     * @param spi SPI of the receiving side of the SA (network order bytes).
     */
    SBOX_API int32_t Ikev1QuickKeymat(uint16_t hash, const SReadOnlyByteSpan& skeyidD, const SReadOnlyByteSpan& gxyQm,
                                      uint8_t protocol, const SReadOnlyByteSpan& spi, const SReadOnlyByteSpan& ni,
                                      const SReadOnlyByteSpan& nr, size_t length, std::vector<uint8_t>& out);

    /**
     * NAT-D hash (RFC 3947 3.2): HASH(CKY-I | CKY-R | IP | Port).
     */
    SBOX_API int32_t Ikev1NatHash(uint16_t hash, uint64_t cookieI, uint64_t cookieR, const net::SIpAddress& address,
                                  uint16_t port, std::vector<uint8_t>& out);

    /**
     * Phase 1 CBC cipher (3DES or AES) without explicit IVs: the caller keeps the IV chain.
     */
    class SBOX_API CIkev1Cipher {
    private:
        struct SImpl;
        std::shared_ptr<SImpl> _impl;

    public:
        CIkev1Cipher();

        ~CIkev1Cipher();

        /**
         * Keys the cipher.
         * @return SBOX_OK, -ENOTSUP or -EINVAL.
         */
        int32_t init(uint16_t encr, const SReadOnlyByteSpan& key);

        /** Returns true once keyed. */
        bool isValid() const noexcept;

        /** Returns the block size. */
        size_t blockSize() const noexcept;

        /**
         * Encrypts `plain` (a multiple of the block size) with `iv`; `iv` receives the last
         * ciphertext block (the IV of the next message).
         * @return SBOX_OK, -EINVAL or -EIO.
         */
        int32_t encrypt(std::vector<uint8_t>& iv, const SReadOnlyByteSpan& plain, std::vector<uint8_t>& out) const;

        /**
         * Decrypts `cipher` (a multiple of the block size) with `iv`; `iv` receives the last
         * ciphertext block.
         * @return SBOX_OK, -EBADMSG or -EIO.
         */
        int32_t decrypt(std::vector<uint8_t>& iv, const SReadOnlyByteSpan& cipher, std::vector<uint8_t>& out) const;
    };

    /**
     * Maps an IKEv1 ESP transform (transform id, key length attribute, authentication
     * algorithm) to the IKEv2/ESP identifiers CIpsecCipher and the data paths use.
     * @return true when supported (`encr`, `keyBits`, `integ` are set).
     */
    SBOX_API bool Ikev1EspTransform(uint8_t espId, uint16_t keyLength, uint16_t authAlg, uint16_t& encr, uint16_t& keyBits,
                                    uint16_t& integ) noexcept;

}
}

#endif
