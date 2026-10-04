#ifndef __SRC_TLS_RECORD_HPP__
#define __SRC_TLS_RECORD_HPP__

#include "crypto.hpp"
#include <certpp/crypto/aeads/aesgcm.hpp>
#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <memory>

namespace sbox {
namespace tls {

    /** AEAD algorithm of a cipher suite. */
    enum AeadKind {
        AEAD_AES128_GCM = 0,
        AEAD_AES256_GCM,
        AEAD_CHACHA20_POLY1305,
    };

    /**
     * Static description of a supported cipher suite.
     */
    struct SuiteInfo {
        uint16_t id;
        const char* name;
        bool tls13;         // --> TLS 1.3 suite (otherwise a TLS 1.2 ECDHE suite).
        AeadKind aead;
        HashAlg hash;
        size_t keyLength;
        size_t ivLength;    // --> 12, or 4 for the TLS 1.2 AES-GCM implicit salt.
        bool ecdsa;         // --> TLS 1.2: the server authenticates with ECDSA (else RSA).
    };

    /**
     * Returns the description of a supported suite, or nullptr.
     */
    const SuiteInfo* FindSuite(uint16_t id);

    /**
     * Returns the name of a suite for diagnostics ("0x....") when unknown.
     */
    std::string SuiteName(uint16_t id);

    /**
     * Protection state of one direction of a connection: an AEAD key, its IV and the record
     * sequence number. Implements the TLS 1.3 record protection (RFC 8446 5.2/5.3) and the
     * TLS 1.2 AEAD record protection (RFC 5246 6.2.3.3, RFC 5288, RFC 7905).
     */
    class RecordCipher {
    private:
        const SuiteInfo* _suite = nullptr;
        std::unique_ptr<certpp::crypto::CAesGcm> _gcm;
        std::unique_ptr<certpp::crypto::CChaCha20Poly1305> _chacha;
        std::vector<uint8_t> _iv;
        uint64_t _seq = 0;

        /** Builds the per-record nonce. */
        void nonce(uint8_t out[12], const uint8_t* explicitPart) const;

        /** Runs the AEAD seal. */
        bool seal(const uint8_t nonceBytes[12], const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& in,
                  uint8_t* out, uint8_t* tag) const;

        /** Runs the AEAD open. */
        bool open(const uint8_t nonceBytes[12], const SReadOnlyByteSpan& aad, uint8_t* data, size_t length,
                  const uint8_t* tag) const;

    public:
        /** Authentication tag length of every supported AEAD. */
        static constexpr size_t TAG = 16;

        /**
         * Keys this direction.
         * @return false when the key or IV length does not match the suite.
         */
        bool init(const SuiteInfo& suite, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& iv);

        /** Returns true when keyed. */
        inline bool active() const { return _suite != nullptr; }

        /** Returns the sequence number of the next record. */
        inline uint64_t sequence() const { return _seq; }

        /**
         * TLS 1.3: protects one record and appends it (header included) to `out`.
         * @param type Inner content type.
         * @param padding Number of zero padding bytes to add to the inner plaintext.
         */
        bool seal13(uint8_t type, const SReadOnlyByteSpan& plaintext, size_t padding, std::vector<uint8_t>& out);

        /**
         * TLS 1.3: decrypts a record body in place.
         * @param header The 5-byte record header (the AAD).
         * @param body The encrypted record body; on success its prefix holds the plaintext.
         * @param type Receives the inner content type.
         * @param length Receives the plaintext length.
         * @return SBOX_OK, -EBADMSG on authentication failure or a malformed inner plaintext,
         *         -EMSGSIZE when the plaintext exceeds 2^14 bytes.
         */
        int32_t open13(const uint8_t header[5], const SByteSpan& body, uint8_t& type, size_t& length);

        /**
         * TLS 1.2: protects one record and appends it (header included) to `out`.
         */
        bool seal12(uint8_t type, const SReadOnlyByteSpan& plaintext, std::vector<uint8_t>& out);

        /**
         * TLS 1.2: decrypts a record body in place.
         * @param header The 5-byte record header.
         * @param body The record body; on success `offset`/`length` locate the plaintext in it.
         * @return SBOX_OK, -EBADMSG or -EMSGSIZE.
         */
        int32_t open12(const uint8_t header[5], const SByteSpan& body, size_t& offset, size_t& length);
    };

}
}

#endif
