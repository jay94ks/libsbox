#ifndef __SRC_TLS_CRYPTO_HPP__
#define __SRC_TLS_CRYPTO_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/x509/cert.hpp>
#include <string>

// --> Thin adapters from the TLS protocol code to libcertpp. Every primitive (hashes, HMAC,
// HKDF, AEADs, key agreement, signatures, randomness, constant-time compare) comes from
// libcertpp; this file only shapes inputs and outputs for the TLS call sites.

namespace sbox {
namespace tls {

    /** Hash function of a cipher suite's PRF / key schedule. */
    enum HashAlg {
        HASH_SHA256 = 0,
        HASH_SHA384,
    };

    /** Converts an sbox read-only span to the identically laid out certpp one. */
    inline certpp::SReadOnlyByteSpan Cp(const SReadOnlyByteSpan& s) {
        return certpp::SReadOnlyByteSpan(s.data, s.size);
    }

    /** Converts an sbox mutable span to the identically laid out certpp one. */
    inline certpp::SByteSpan Cp(const SByteSpan& s) {
        return certpp::SByteSpan(s.data, s.size);
    }

    /** Returns the output length of a hash in bytes. */
    size_t HashSize(HashAlg alg);

    /** Returns the certpp identifier of a hash. */
    certpp::crypto::EHashers HashId(HashAlg alg);

    /** Hashes `data` (empty vector only on an internal failure). */
    std::vector<uint8_t> Hash(HashAlg alg, const SReadOnlyByteSpan& data);

    /** HMAC over `data` keyed with `key`. */
    std::vector<uint8_t> Hmac(HashAlg alg, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data);

    /** HKDF-Extract (RFC 5869). An empty salt means hashLen zero bytes. */
    std::vector<uint8_t> HkdfExtract(HashAlg alg, const SReadOnlyByteSpan& salt, const SReadOnlyByteSpan& ikm);

    /** HKDF-Expand-Label (RFC 8446 7.1) with the "tls13 " label prefix. */
    std::vector<uint8_t> HkdfExpandLabel(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                                         const SReadOnlyByteSpan& context, size_t length);

    /** Derive-Secret (RFC 8446 7.1) given the transcript hash (already hashed). */
    std::vector<uint8_t> DeriveSecret(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                                      const SReadOnlyByteSpan& transcriptHash);

    /** TLS 1.2 PRF (RFC 5246 5): P_hash(secret, label || seed). */
    std::vector<uint8_t> Prf12(HashAlg alg, const SReadOnlyByteSpan& secret, std::string_view label,
                               const SReadOnlyByteSpan& seed, size_t length);

    /** Fills `out` from the OS CSPRNG; false on failure. */
    bool RandomBytes(const SByteSpan& out);

    /** Compares two byte strings in time that depends only on their lengths. */
    bool SecureEquals(const SReadOnlyByteSpan& a, const SReadOnlyByteSpan& b);

    /** Zeroizes a buffer (not elided by the optimizer) and empties it. */
    void Wipe(std::vector<uint8_t>& v);

    /**
     * Ephemeral key pair of one (EC)DHE group: X25519, secp256r1 or secp384r1.
     */
    class KeyShare {
    private:
        uint16_t _group = 0;
        certpp::crypto::IAsymmetricPtr _asym;
        certpp::crypto::SKeyPair _pair;
        std::vector<uint8_t> _public;

    public:
        /** Returns true when `group` is a NamedGroup this implementation can use. */
        static bool supported(uint16_t group);

        /**
         * Generates a fresh key pair for `group`.
         * @return SBOX_OK, -ENOTSUP for an unknown group, -EIO when key generation failed.
         */
        int32_t generate(uint16_t group);

        /**
         * Installs a known private key (test vectors only).
         */
        int32_t loadPrivate(uint16_t group, const SReadOnlyByteSpan& privateKey);

        /** Returns the group. */
        inline uint16_t group() const { return _group; }

        /** Returns the public value in TLS encoding (raw u for X25519, SEC1 uncompressed for EC). */
        inline const std::vector<uint8_t>& publicValue() const { return _public; }

        /**
         * Computes the shared secret with the peer's public value.
         * @return SBOX_OK, or -EINVAL when the peer value is malformed or yields no secret.
         */
        int32_t agree(const SReadOnlyByteSpan& peer, std::vector<uint8_t>& secret) const;
    };

    /**
     * Returns the hash a signature scheme uses (EHASH_UNKNOWN for Ed25519, which signs the
     * message itself).
     */
    certpp::crypto::EHashers SchemeHash(uint16_t scheme);

    /**
     * Returns true when `scheme` fits the key of `cert` (and, in TLS 1.3, its curve and the
     * rule that PKCS#1 v1.5 is not used for handshake signatures).
     */
    bool SchemeFitsKey(const certpp::x509::CCert& cert, uint16_t scheme, bool tls13);

    /**
     * Verifies a handshake signature (CertificateVerify, ServerKeyExchange) made with the key of
     * `cert` under signature scheme `scheme`.
     * @return SBOX_OK, -ENOTSUP for an unusable scheme/key combination, -EKEYREJECTED when the
     *         signature does not verify.
     */
    int32_t VerifySignature(const certpp::x509::CCert& cert, uint16_t scheme, bool tls13,
                            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& signature);

    /**
     * Signs `message` with a private key under `scheme` (client authentication).
     * @return SBOX_OK, -ENOTSUP or -EIO.
     */
    int32_t SignMessage(const certpp::x509::CCert& cert, const certpp::crypto::IPrivateKeyPtr& key,
                        uint16_t scheme, const SReadOnlyByteSpan& message, std::vector<uint8_t>& signature);

}
}

#endif
