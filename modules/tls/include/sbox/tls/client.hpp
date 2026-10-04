#ifndef __INCLUDE_SBOX_TLS_CLIENT_HPP__
#define __INCLUDE_SBOX_TLS_CLIENT_HPP__

#include <sbox/common.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/task.hpp>
#include <sbox/tls/trust.hpp>

namespace sbox {
namespace tls {

    /**
     * TLS protocol versions (the wire values).
     */
    enum ETlsVersion : uint16_t {
        ETLSV_INVALID = 0,
        ETLSV_1_2 = 0x0303,
        ETLSV_1_3 = 0x0304,
    };

    /**
     * Outcome and diagnostics of a TLS client handshake.
     */
    struct STlsReport {
        int32_t error = SBOX_OK;            // --> SBOX_OK or the negated errno ConnectTls returned.
        std::string reason;                 // --> Human-readable failure reason (empty on success).
        int32_t alertSent = -1;             // --> Alert description we sent, -1 for none.
        int32_t alertReceived = -1;         // --> Alert description the peer sent, -1 for none.
        ETlsVersion version = ETLSV_INVALID;
        uint16_t cipherSuite = 0;           // --> IANA value of the negotiated suite.
        std::string cipherSuiteName;
        uint16_t group = 0;                 // --> Key exchange group (0x001d X25519, 0x0017 P-256, ...).
        uint16_t signatureScheme = 0;       // --> Scheme of the server's handshake signature.
        bool helloRetry = false;            // --> TLS 1.3 HelloRetryRequest happened.
        bool clientCertificateSent = false; // --> We authenticated with a client certificate.
        std::string alpn;                   // --> Negotiated application protocol ("" when none).
        std::vector<std::vector<uint8_t>> peerCertificates;    // --> DER, leaf first.
    };

    /**
     * Options of a TLS client connection.
     */
    struct STlsClientOptions {
        /**
         * Host name of the server: sent as SNI (unless it is an IP literal) and verified
         * against the certificate (dNSName, or iPAddress for an IP literal). Required unless
         * `insecure` is set.
         */
        std::string serverName;

        /**
         * ALPN protocols to offer, in preference order (empty: no ALPN extension).
         */
        std::vector<std::string> alpn = { "http/1.1" };

        /**
         * Trust anchors; null means CTrustStore::system().
         */
        CTrustStorePtr trustStore;

        /** Lowest acceptable protocol version. */
        ETlsVersion minVersion = ETLSV_1_2;

        /** Highest offered protocol version. */
        ETlsVersion maxVersion = ETLSV_1_3;

        /**
         * Disables certificate chain, validity and host name verification.
         *
         * DANGEROUS: anyone on the path can impersonate the server. Only for explicitly
         * configured insecure registries (Docker's "insecure-registries") and tests. The server
         * must still prove possession of the key of the certificate it sends.
         */
        bool insecure = false;

        /** Bound on the whole handshake in milliseconds (negative: none). */
        int64_t handshakeTimeoutMs = 30000;

        /**
         * Client certificate chain (PEM, leaf first) for mutual TLS; empty for none. Sent only
         * when the server asks for one.
         */
        std::string clientCertificatePem;

        /**
         * Private key of the client certificate (PEM: PKCS#8 "PRIVATE KEY", "EC PRIVATE KEY" or
         * "RSA PRIVATE KEY"; unencrypted).
         */
        std::string clientKeyPem;

        /**
         * TLS 1.3 record padding: inner plaintexts are padded with zeros to a multiple of this
         * many bytes (0 or 1: no padding). Hides exact lengths from an observer.
         */
        size_t recordPadding = 0;

        /**
         * Unix time used for certificate validity checks; 0 means the current time.
         */
        int64_t verifyTimeSeconds = 0;

        /**
         * Receives the handshake outcome (failure reason, alerts, negotiated parameters) when
         * not null. Written whether the handshake succeeds or fails.
         */
        STlsReport* report = nullptr;
    };

    /**
     * Client side of an established TLS connection, as a byte stream.
     *
     * Created by ConnectTls. recv/send carry application data; post-handshake messages are
     * handled inside recv (TLS 1.3 NewSessionTicket is ignored, KeyUpdate is honoured and
     * answered; TLS 1.2 HelloRequest is refused with a no_renegotiation warning).
     *
     * recv returns 0 bytes with SBOX_OK after the peer's close_notify. A transport EOF without
     * close_notify is reported as -ECONNRESET (a possible truncation). A fatal alert from the
     * peer yields -ECONNABORTED, a record that fails authentication -EBADMSG; after any error
     * the connection is unusable and failureReason() says why.
     *
     * One reader and one writer may be active at the same time, like CStream.
     */
    class SBOX_API CTlsStream : public IStream {
    public:
        struct SImpl;

    private:
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Wraps a connected transport; the handshake runs in ConnectTls.
         */
        CTlsStream(IStreamPtr transport, const STlsClientOptions& options);

        CTlsStream(const CTlsStream&) = delete;

        CTlsStream& operator=(const CTlsStream&) = delete;

        ~CTlsStream() override;

        /**
         * Runs the handshake (called by ConnectTls).
         * @return SBOX_OK or a negated errno (see ConnectTls).
         */
        TTask<int32_t> handshake();

        /**
         * Reads decrypted application data (see IStream::recv).
         */
        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Encrypts and writes the whole buffer (see IStream::send).
         */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Sends close_notify (once) and half-closes the TLS session for writing. The transport
         * stays open so the peer's remaining data and close_notify can still be read.
         * @return SBOX_OK or the transport's error.
         */
        TTask<int32_t> shutdown(int64_t timeoutMs = 5000);

        /**
         * Closes the transport immediately (no close_notify; use shutdown() first for a clean
         * close), waking pending recv/send with -ECANCELED.
         */
        void close() noexcept override;

        /**
         * Returns the handshake outcome and negotiated parameters.
         */
        const STlsReport& info() const noexcept;

        /**
         * Returns the error that made the connection unusable (SBOX_OK while healthy).
         */
        int32_t lastError() const noexcept;

        /**
         * Returns a human-readable description of lastError() (empty while healthy).
         */
        const std::string& failureReason() const noexcept;
    };

    /**
     * Runs a TLS client handshake over a connected transport and returns the encrypted stream.
     *
     * Offers TLS 1.3 (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
     * TLS_CHACHA20_POLY1305_SHA256 over X25519 / P-256 / P-384) and TLS 1.2 (ECDHE with
     * AES-GCM or ChaCha20-Poly1305, extended master secret required), within
     * options.minVersion..maxVersion, and verifies the server certificate unless
     * options.insecure.
     *
     * @param transport Connected byte stream (TCP socket, proxy CONNECT tunnel, ...). The TLS
     *        stream takes shared ownership.
     * @param options Connection options; options.report receives the outcome.
     * @param out Receives the TLS stream on success.
     * @return SBOX_OK, or a negated errno:
     *         -EPROTO handshake failure (protocol violation, no common parameters, peer alert),
     *         -EPROTONOSUPPORT no acceptable protocol version,
     *         -EKEYREJECTED server certificate or signature verification failed,
     *         -EBADMSG a record failed authentication or was malformed,
     *         -ECONNRESET the transport closed during the handshake,
     *         -ETIMEDOUT the handshake exceeded options.handshakeTimeoutMs,
     *         -EINVAL invalid options (no server name, unreadable client key, ...),
     *         or the transport's own error.
     */
    SBOX_API TTask<int32_t> ConnectTls(IStreamPtr transport, const STlsClientOptions& options, IStreamPtr& out);

    /**
     * Returns the RFC name of a TLS alert description ("handshake_failure", ...).
     */
    SBOX_API const char* TlsAlertName(int32_t description) noexcept;

}
}

#endif
