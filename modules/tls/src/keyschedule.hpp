#ifndef __SRC_TLS_KEYSCHEDULE_HPP__
#define __SRC_TLS_KEYSCHEDULE_HPP__

#include "crypto.hpp"
#include "record.hpp"

namespace sbox {
namespace tls {

    /**
     * TLS 1.3 handshake secret from the (EC)DHE shared secret without a PSK (RFC 8446 7.1):
     * HKDF-Extract(Derive-Secret(HKDF-Extract(0, 0), "derived", ""), ecdhe).
     */
    std::vector<uint8_t> Tls13HandshakeSecret(HashAlg hash, const SReadOnlyByteSpan& ecdhe);

    /**
     * TLS 1.3 master secret: HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
     */
    std::vector<uint8_t> Tls13MasterSecret(HashAlg hash, const SReadOnlyByteSpan& handshakeSecret);

    /**
     * Traffic key and IV of a traffic secret (RFC 8446 7.3).
     */
    bool Tls13TrafficKeys(const SuiteInfo& suite, const SReadOnlyByteSpan& secret,
                          std::vector<uint8_t>& key, std::vector<uint8_t>& iv);

    /**
     * Keys a record cipher from a TLS 1.3 traffic secret.
     */
    bool Tls13InstallKeys(RecordCipher& cipher, const SuiteInfo& suite, const SReadOnlyByteSpan& secret);

    /**
     * Finished verify_data: HMAC(HKDF-Expand-Label(base, "finished", "", Hash.length),
     * transcriptHash) (RFC 8446 4.4.4).
     */
    std::vector<uint8_t> Tls13Finished(HashAlg hash, const SReadOnlyByteSpan& baseSecret,
                                       const SReadOnlyByteSpan& transcriptHash);

    /**
     * Next-generation application traffic secret for KeyUpdate (RFC 8446 7.2).
     */
    std::vector<uint8_t> Tls13NextSecret(HashAlg hash, const SReadOnlyByteSpan& secret);

    /**
     * Content signed by a TLS 1.3 CertificateVerify (RFC 8446 4.4.3).
     */
    std::vector<uint8_t> Tls13SignedContent(bool server, const SReadOnlyByteSpan& transcriptHash);

    /**
     * TLS 1.2 extended master secret (RFC 7627 4).
     */
    std::vector<uint8_t> Tls12ExtendedMasterSecret(HashAlg hash, const SReadOnlyByteSpan& preMaster,
                                                   const SReadOnlyByteSpan& sessionHash);

    /**
     * Keys both TLS 1.2 record ciphers from the master secret (RFC 5246 6.3).
     */
    bool Tls12InstallKeys(const SuiteInfo& suite, const SReadOnlyByteSpan& master,
                          const SReadOnlyByteSpan& clientRandom, const SReadOnlyByteSpan& serverRandom,
                          RecordCipher& clientWrite, RecordCipher& serverWrite);

    /**
     * TLS 1.2 Finished verify_data (12 bytes) for "client finished" / "server finished".
     */
    std::vector<uint8_t> Tls12Finished(HashAlg hash, const SReadOnlyByteSpan& master, bool client,
                                       const SReadOnlyByteSpan& transcriptHash);

}
}

#endif
