#ifndef __SRC_TLS_SESSION_HPP__
#define __SRC_TLS_SESSION_HPP__

#include <sbox/tls/client.hpp>
#include <sbox/core/eventloop.hpp>
#include "crypto.hpp"
#include "record.hpp"
#include "protocol.hpp"
#include <certpp/x509/cert.hpp>
#include <coroutine>
#include <deque>
#include <set>

namespace sbox {
namespace tls {

    /**
     * FIFO lock for coroutines on one event loop: serializes writers of the transport so a
     * KeyUpdate or alert produced by the reader never interleaves with application records.
     */
    class AsyncMutex {
    private:
        bool _locked = false;
        std::deque<std::coroutine_handle<>> _waiters;

    public:
        /**
         * Awaiter returned by lock().
         */
        struct Awaiter {
            AsyncMutex& mutex;

            inline bool await_ready() noexcept {
                if (!mutex._locked) {
                    mutex._locked = true;
                    return true;
                }

                return false;
            }

            inline void await_suspend(std::coroutine_handle<> h) { mutex._waiters.push_back(h); }

            inline void await_resume() const noexcept {}
        };

        /** Acquires the lock (ownership passes directly to the next waiter on unlock). */
        inline Awaiter lock() noexcept { return Awaiter{ *this }; }

        /** Releases the lock, resuming the next waiter on the current loop. */
        inline void unlock() {
            if (_waiters.empty()) {
                _locked = false;
                return;
            }

            std::coroutine_handle<> next = _waiters.front();
            _waiters.pop_front();
            CEventLoop::current()->post(next);
        }
    };

    /**
     * One reassembled handshake message.
     */
    struct HsMessage {
        int32_t type = -1;              // --> Handshake type, or MSG_CCS for a TLS 1.2 ChangeCipherSpec.
        std::vector<uint8_t> body;
        std::vector<uint8_t> raw;       // --> Header and body, as hashed into the transcript.
    };

    constexpr int32_t MSG_CCS = 0x100;

    /**
     * Parsed ServerHello (or HelloRetryRequest).
     */
    struct ServerHello {
        uint16_t legacyVersion = 0;
        std::vector<uint8_t> random;
        std::vector<uint8_t> sessionId;
        uint16_t suite = 0;
        uint16_t selectedVersion = 0;   // --> supported_versions value, 0 when absent.
        bool hasKeyShare = false;
        uint16_t keyShareGroup = 0;
        std::vector<uint8_t> keyShare;  // --> Empty in a HelloRetryRequest.
        std::vector<uint8_t> cookie;
        bool extendedMasterSecret = false;
        bool hasAlpn = false;
        std::string alpn;
        bool helloRetry = false;
    };

    /**
     * Private state of CTlsStream: record layer, handshake state machines and the IStream
     * operations.
     */
    struct CTlsStream::SImpl {
        enum Phase {
            PHASE_HANDSHAKE = 0,
            PHASE_OPEN,
            PHASE_CLOSED,       // --> Peer sent close_notify.
            PHASE_FAILED,
        };

        IStreamPtr transport;
        STlsClientOptions options;
        STlsReport report;
        Phase phase = PHASE_HANDSHAKE;
        int32_t error = SBOX_OK;
        std::string reason;
        int64_t deadline = -1;              // --> Handshake deadline (monotonic ms), -1 for none.
        bool closeNotifySent = false;

        // -- Record layer.
        uint16_t version = 0;               // --> Negotiated version, 0 before ServerHello.
        const SuiteInfo* suite = nullptr;
        RecordCipher readCipher;
        RecordCipher writeCipher;
        std::vector<uint8_t> inBuf;         // --> Raw bytes from the transport.
        size_t inPos = 0;
        std::vector<uint8_t> hsBuf;         // --> Handshake bytes not yet forming a message.
        std::vector<uint8_t> appBuf;        // --> Decrypted application data not yet returned.
        size_t appPos = 0;
        AsyncMutex writeLock;
        bool writing = false;

        // -- Handshake.
        std::vector<uint8_t> transcript;
        std::vector<uint8_t> clientRandom;
        std::vector<uint8_t> sessionId;
        std::vector<KeyShare> shares;
        std::set<uint16_t> offeredExtensions;
        std::vector<uint16_t> offeredSuites;
        std::vector<uint16_t> offeredSchemes;
        bool compatCcsSent = false;
        bool serverFinished = false;
        std::string sniName;                // --> Empty when the server name is an IP literal.
        certpp::x509::CCert leaf;

        // -- Client authentication material.
        std::vector<std::vector<uint8_t>> clientChain;
        certpp::x509::CCert clientLeaf;
        certpp::crypto::IPrivateKeyPtr clientKey;

        // -- TLS 1.3 application traffic secrets (for KeyUpdate).
        std::vector<uint8_t> clientAppSecret;
        std::vector<uint8_t> serverAppSecret;

        SImpl(IStreamPtr t, const STlsClientOptions& o);

        ~SImpl();

        /** Returns true once TLS 1.3 has been negotiated. */
        inline bool tls13() const { return version == VER_TLS13; }

        /** Remaining handshake time, or `fallback` outside the handshake. */
        int64_t remaining(int64_t fallback) const;

        // -- record layer (session.cpp)

        /** Ensures `need` unread raw bytes are buffered. */
        TTask<int32_t> fill(size_t need, int64_t timeoutMs);

        /**
         * Reads and deprotects one record.
         * @return SBOX_OK with `type`/`data`, or a negated errno (state already failed for
         *         protocol errors; -ETIMEDOUT / -ECANCELED leave the connection usable).
         */
        TTask<int32_t> readRecord(uint8_t& type, std::vector<uint8_t>& data, int64_t timeoutMs);

        /** Sends records of `type` carrying `data`, fragmented and protected as needed. */
        TTask<int32_t> writeRecords(uint8_t type, const SReadOnlyByteSpan& data, int64_t timeoutMs, uint16_t recordVersion = VER_TLS12);

        /** Sends an unprotected ChangeCipherSpec record. */
        TTask<int32_t> writeCcs(int64_t timeoutMs);

        /** Appends a handshake message to the transcript and sends it. */
        TTask<int32_t> sendHandshake(uint8_t type, const std::vector<uint8_t>& body, uint16_t recordVersion = VER_TLS12);

        /** Reads the next complete handshake message (or a TLS 1.2 ChangeCipherSpec). */
        TTask<int32_t> readHandshake(HsMessage& out);

        /** Interprets a received alert. */
        TTask<int32_t> onAlert(const std::vector<uint8_t>& data);

        /** Records a failure, sends a fatal alert (when `alert` >= 0) and returns `err`. */
        TTask<int32_t> fail(int32_t err, int32_t alert, std::string why);

        /** Records a failure without sending anything. */
        int32_t failQuiet(int32_t err, std::string why);

        /** Sends one alert record (best effort). */
        TTask<int32_t> sendAlert(uint8_t level, uint8_t description);

        /** Adds a handshake message to the transcript. */
        inline void addTranscript(const std::vector<uint8_t>& raw) { transcript.insert(transcript.end(), raw.begin(), raw.end()); }

        /** Hash of the transcript so far with the suite hash. */
        std::vector<uint8_t> transcriptHash() const;

        // -- handshake (handshake.cpp, handshake13.cpp, handshake12.cpp)

        /** Runs the whole handshake. */
        TTask<int32_t> handshake();

        /** Loads the client certificate and key from the options. */
        int32_t loadClientIdentity();

        /** Builds the ClientHello body. */
        std::vector<uint8_t> buildClientHello(const std::vector<uint8_t>& cookie);

        /** Parses a ServerHello / HelloRetryRequest. */
        int32_t parseServerHello(const std::vector<uint8_t>& body, ServerHello& out, int32_t& alert, std::string& why);

        /** Validates the parsed ALPN choice. */
        bool alpnAcceptable(const std::string& proto) const;

        /** Verifies the server chain; returns SBOX_OK or fails the handshake. */
        TTask<int32_t> verifyServerCertificates(const std::vector<std::vector<uint8_t>>& chain);

        /** Picks a signature scheme for our client certificate from the server's list. */
        uint16_t pickClientScheme(const std::vector<uint16_t>& serverSchemes, bool tls13) const;

        /** TLS 1.3 handshake after the first ServerHello. */
        TTask<int32_t> handshake13(ServerHello sh, HsMessage shMsg);

        /** TLS 1.2 handshake after the ServerHello. */
        TTask<int32_t> handshake12(ServerHello sh, HsMessage shMsg);

        /** Fills report fields once the handshake succeeded. */
        void finishReport();

        // -- post-handshake (session.cpp)

        /** Handles post-handshake handshake messages buffered in hsBuf. */
        TTask<int32_t> postHandshake();

        /** Performs a TLS 1.3 KeyUpdate of our sending keys (caller holds writeLock). */
        TTask<int32_t> updateWriteKeys(bool requestPeer, int64_t timeoutMs);

        /** IStream::recv. */
        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs);

        /** IStream::send. */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs);

        /** Sends close_notify. */
        TTask<int32_t> shutdown(int64_t timeoutMs);
    };

}
}

#endif
