#include <sbox/tls/client.hpp>
#include "session.hpp"
#include "keyschedule.hpp"
#include "wire.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace tls {

    namespace {

        constexpr size_t READ_CHUNK = MAX_CIPHERTEXT_12 + 5;
        constexpr uint64_t KEY_UPDATE_AFTER = uint64_t(1) << 23;   // --> Well below AES-GCM's 2^24.5 records.
        constexpr size_t WRITE_BATCH = 4;                           // --> Records per transport send.

        /* Splits a deadline into the time left (or -1 for none). */
        int64_t timeLeft(int64_t deadline) {
            if (deadline < 0) {
                return -1;
            }

            int64_t left = deadline - CEventLoop::nowMs();
            return left > 0 ? left : 0;
        }

    }

    /* Alert names. */
    const char* TlsAlertName(int32_t description) noexcept {
        switch (description) {
        case AD_CLOSE_NOTIFY: return "close_notify";
        case AD_UNEXPECTED_MESSAGE: return "unexpected_message";
        case AD_BAD_RECORD_MAC: return "bad_record_mac";
        case AD_RECORD_OVERFLOW: return "record_overflow";
        case AD_HANDSHAKE_FAILURE: return "handshake_failure";
        case AD_BAD_CERTIFICATE: return "bad_certificate";
        case AD_UNSUPPORTED_CERTIFICATE: return "unsupported_certificate";
        case AD_CERTIFICATE_REVOKED: return "certificate_revoked";
        case AD_CERTIFICATE_EXPIRED: return "certificate_expired";
        case AD_CERTIFICATE_UNKNOWN: return "certificate_unknown";
        case AD_ILLEGAL_PARAMETER: return "illegal_parameter";
        case AD_UNKNOWN_CA: return "unknown_ca";
        case AD_ACCESS_DENIED: return "access_denied";
        case AD_DECODE_ERROR: return "decode_error";
        case AD_DECRYPT_ERROR: return "decrypt_error";
        case AD_PROTOCOL_VERSION: return "protocol_version";
        case AD_INSUFFICIENT_SECURITY: return "insufficient_security";
        case AD_INTERNAL_ERROR: return "internal_error";
        case AD_INAPPROPRIATE_FALLBACK: return "inappropriate_fallback";
        case AD_USER_CANCELED: return "user_canceled";
        case AD_NO_RENEGOTIATION: return "no_renegotiation";
        case AD_MISSING_EXTENSION: return "missing_extension";
        case AD_UNSUPPORTED_EXTENSION: return "unsupported_extension";
        case AD_UNRECOGNIZED_NAME: return "unrecognized_name";
        case AD_BAD_CERTIFICATE_STATUS_RESPONSE: return "bad_certificate_status_response";
        case AD_UNKNOWN_PSK_IDENTITY: return "unknown_psk_identity";
        case AD_CERTIFICATE_REQUIRED: return "certificate_required";
        case AD_NO_APPLICATION_PROTOCOL: return "no_application_protocol";
        default: return "unknown_alert";
        }
    }

    /* Session state. */
    CTlsStream::SImpl::SImpl(IStreamPtr t, const STlsClientOptions& o) : transport(std::move(t)), options(o) {}

    /* Wipes secrets. */
    CTlsStream::SImpl::~SImpl() {
        Wipe(clientAppSecret);
        Wipe(serverAppSecret);
    }

    /* Remaining handshake time. */
    int64_t CTlsStream::SImpl::remaining(int64_t fallback) const {
        if (phase == PHASE_HANDSHAKE && deadline >= 0) {
            return timeLeft(deadline);
        }

        return fallback;
    }

    /* Buffers raw transport bytes. */
    TTask<int32_t> CTlsStream::SImpl::fill(size_t need, int64_t timeoutMs) {
        int64_t until = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        if (inPos == inBuf.size()) {
            inBuf.clear();
            inPos = 0;
        }
        else if (inPos >= 65536) {
            inBuf.erase(inBuf.begin(), inBuf.begin() + long(inPos));
            inPos = 0;
        }

        while (inBuf.size() - inPos < need) {
            int64_t left = timeLeft(until);
            if (until >= 0 && left == 0) {
                co_return -ETIMEDOUT;
            }

            size_t base = inBuf.size();
            size_t want = need - (base - inPos);
            if (want < READ_CHUNK) {
                want = READ_CHUNK;
            }

            inBuf.resize(base + want);
            SIoResult r = co_await transport->recv(SByteSpan(inBuf.data() + base, want), left);
            inBuf.resize(base + r.bytes);

            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return -ENODATA;
            }
        }

        co_return SBOX_OK;
    }

    /* Reads and deprotects one record. */
    TTask<int32_t> CTlsStream::SImpl::readRecord(uint8_t& type, std::vector<uint8_t>& data, int64_t timeoutMs) {
        int64_t until = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        int32_t rc = co_await fill(5, timeoutMs);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        uint8_t header[5];
        std::memcpy(header, inBuf.data() + inPos, 5);
        uint8_t t = header[0];
        size_t length = (size_t(header[3]) << 8) | header[4];

        if (t < CT_CHANGE_CIPHER_SPEC || t > CT_APPLICATION_DATA) {
            co_return co_await fail(-EBADMSG, AD_UNEXPECTED_MESSAGE, "received a record of unknown content type " + std::to_string(t));
        }

        if (header[1] != 0x03) {
            co_return co_await fail(-EBADMSG, AD_PROTOCOL_VERSION, "received a record with an invalid version (not TLS)");
        }

        bool protectedRecord = readCipher.active() && !(tls13() && t == CT_CHANGE_CIPHER_SPEC);
        size_t limit = !protectedRecord ? MAX_PLAINTEXT : tls13() ? MAX_CIPHERTEXT_13 : MAX_CIPHERTEXT_12;
        if (length > limit) {
            co_return co_await fail(-EBADMSG, AD_RECORD_OVERFLOW, "received an oversized record (" + std::to_string(length) + " bytes)");
        }

        if (length == 0 && !protectedRecord && t != CT_APPLICATION_DATA) {
            co_return co_await fail(-EBADMSG, AD_DECODE_ERROR, "received an empty record");
        }

        rc = co_await fill(5 + length, timeLeft(until));
        if (rc != SBOX_OK) {
            co_return rc;
        }

        std::vector<uint8_t> body(inBuf.begin() + long(inPos + 5), inBuf.begin() + long(inPos + 5 + length));
        inPos += 5 + length;

        if (!protectedRecord) {
            if (t == CT_APPLICATION_DATA) {
                co_return co_await fail(-EBADMSG, AD_UNEXPECTED_MESSAGE, "received unprotected application data");
            }

            type = t;
            data = std::move(body);
            co_return SBOX_OK;
        }

        if (tls13()) {
            if (t != CT_APPLICATION_DATA) {
                co_return co_await fail(-EBADMSG, AD_UNEXPECTED_MESSAGE, "received an unprotected record after keys were installed");
            }

            uint8_t inner = 0;
            size_t plain = 0;
            rc = readCipher.open13(header, BytesOf(body), inner, plain);
            if (rc == -EMSGSIZE) {
                co_return co_await fail(-EBADMSG, AD_RECORD_OVERFLOW, "decrypted record exceeds 2^14 bytes");
            }

            if (rc != SBOX_OK) {
                co_return co_await fail(-EBADMSG, AD_BAD_RECORD_MAC, "record authentication failed (bad_record_mac)");
            }

            body.resize(plain);
            if (inner < CT_CHANGE_CIPHER_SPEC || inner > CT_APPLICATION_DATA || inner == CT_CHANGE_CIPHER_SPEC) {
                co_return co_await fail(-EBADMSG, AD_UNEXPECTED_MESSAGE, "decrypted record has an invalid content type");
            }

            if (plain == 0 && inner != CT_APPLICATION_DATA) {
                co_return co_await fail(-EBADMSG, AD_UNEXPECTED_MESSAGE, "received an empty protected record");
            }

            type = inner;
            data = std::move(body);
            co_return SBOX_OK;
        }

        size_t offset = 0, plain = 0;
        rc = readCipher.open12(header, BytesOf(body), offset, plain);
        if (rc == -EMSGSIZE) {
            co_return co_await fail(-EBADMSG, AD_RECORD_OVERFLOW, "decrypted record exceeds 2^14 bytes");
        }

        if (rc != SBOX_OK) {
            co_return co_await fail(-EBADMSG, AD_BAD_RECORD_MAC, "record authentication failed (bad_record_mac)");
        }

        type = t;
        data.assign(body.begin() + long(offset), body.begin() + long(offset + plain));
        co_return SBOX_OK;
    }

    namespace {

        /* Appends one unprotected record. */
        void plainRecord(std::vector<uint8_t>& out, uint8_t type, uint16_t version, const SReadOnlyByteSpan& data) {
            out.push_back(type);
            out.push_back(uint8_t(version >> 8));
            out.push_back(uint8_t(version));
            out.push_back(uint8_t(data.size >> 8));
            out.push_back(uint8_t(data.size));
            out.insert(out.end(), data.data, data.data + data.size);
        }

    }

    /* Sends records (fragmenting and protecting). */
    TTask<int32_t> CTlsStream::SImpl::writeRecords(uint8_t type, const SReadOnlyByteSpan& data, int64_t timeoutMs, uint16_t recordVersion) {
        co_await writeLock.lock();

        std::vector<uint8_t> wire;
        size_t off = 0;
        bool ok = true;

        do {
            size_t n = data.size - off < MAX_PLAINTEXT ? data.size - off : MAX_PLAINTEXT;
            SReadOnlyByteSpan chunk(data.data + off, n);

            if (!writeCipher.active()) {
                plainRecord(wire, type, recordVersion, chunk);
            }
            else if (tls13()) {
                size_t block = options.recordPadding;
                size_t pad = block > 1 ? (block - (n + 1) % block) % block : 0;
                ok = writeCipher.seal13(type, chunk, pad, wire);
            }
            else {
                ok = writeCipher.seal12(type, chunk, wire);
            }

            off += n;
        } while (ok && off < data.size);

        int32_t rc = SBOX_OK;
        if (!ok) {
            rc = -EIO;
        }
        else {
            SIoResult r = co_await transport->send(BytesOf(wire), timeoutMs);
            rc = r.error;
        }

        writeLock.unlock();
        co_return rc;
    }

    /* Sends a compatibility ChangeCipherSpec. */
    TTask<int32_t> CTlsStream::SImpl::writeCcs(int64_t timeoutMs) {
        static const uint8_t ONE[1] = { 1 };
        co_await writeLock.lock();

        std::vector<uint8_t> wire;
        plainRecord(wire, CT_CHANGE_CIPHER_SPEC, VER_TLS12, SReadOnlyByteSpan(ONE, 1));
        SIoResult r = co_await transport->send(BytesOf(wire), timeoutMs);

        writeLock.unlock();
        co_return r.error;
    }

    /* Sends one handshake message and records it in the transcript. */
    TTask<int32_t> CTlsStream::SImpl::sendHandshake(uint8_t type, const std::vector<uint8_t>& body, uint16_t recordVersion) {
        std::vector<uint8_t> msg;
        Writer w(msg);
        w.u8(type);
        w.u24(uint32_t(body.size()));
        w.bytes(body);
        addTranscript(msg);

        int32_t rc = co_await writeRecords(CT_HANDSHAKE, BytesOf(msg), remaining(-1), recordVersion);
        if (rc != SBOX_OK) {
            co_return failQuiet(rc == -ENODATA ? -ECONNRESET : rc, "failed to send a handshake message: " + std::string(std::strerror(-rc)));
        }

        co_return SBOX_OK;
    }

    /* Sends an alert record. */
    TTask<int32_t> CTlsStream::SImpl::sendAlert(uint8_t level, uint8_t description) {
        uint8_t alert[2] = { level, description };
        if (level == ALERT_FATAL || description != AD_CLOSE_NOTIFY) {
            report.alertSent = description;
        }

        co_return co_await writeRecords(CT_ALERT, SReadOnlyByteSpan(alert, 2), 1000);
    }

    /* Fails the session with an alert. */
    TTask<int32_t> CTlsStream::SImpl::fail(int32_t err, int32_t alert, std::string why) {
        if (phase == PHASE_FAILED) {
            co_return error;
        }

        failQuiet(err, std::move(why));
        if (alert >= 0) {
            co_await sendAlert(ALERT_FATAL, uint8_t(alert));
        }

        co_return err;
    }

    /* Fails the session without sending anything. */
    int32_t CTlsStream::SImpl::failQuiet(int32_t err, std::string why) {
        if (phase == PHASE_FAILED) {
            return error;
        }

        phase = PHASE_FAILED;
        error = err;
        reason = std::move(why);
        report.error = err;
        report.reason = reason;
        return err;
    }

    /* Interprets an alert: < 0 failure, 0 ignored, 1 close_notify. */
    TTask<int32_t> CTlsStream::SImpl::onAlert(const std::vector<uint8_t>& data) {
        if (data.size() != 2) {
            co_return co_await fail(-EBADMSG, AD_DECODE_ERROR, "received a malformed alert");
        }

        uint8_t level = data[0];
        uint8_t description = data[1];
        report.alertReceived = description;

        if (description == AD_CLOSE_NOTIFY) {
            if (phase == PHASE_HANDSHAKE) {
                co_return failQuiet(-EPROTO, "the server closed the connection during the handshake (close_notify)");
            }

            phase = PHASE_CLOSED;
            co_return 1;
        }

        // --> TLS 1.3 treats every alert but close_notify/user_canceled as fatal whatever its
        // level (RFC 8446 6); TLS 1.2 warnings (e.g. no_renegotiation) are informational.
        if (level == ALERT_WARNING && (description == AD_USER_CANCELED || !tls13())) {
            report.alertReceived = -1;
            co_return 0;
        }

        std::string why = std::string("the server sent a fatal alert: ") + TlsAlertName(description);
        if (phase == PHASE_HANDSHAKE) {
            co_return failQuiet(description == AD_PROTOCOL_VERSION ? -EPROTONOSUPPORT : -EPROTO, why);
        }

        co_return failQuiet(-ECONNABORTED, why);
    }

    /* Transcript hash. */
    std::vector<uint8_t> CTlsStream::SImpl::transcriptHash() const {
        return Hash(suite ? suite->hash : HASH_SHA256, BytesOf(transcript));
    }

    /* Reads the next handshake message. */
    TTask<int32_t> CTlsStream::SImpl::readHandshake(HsMessage& out) {
        while (true) {
            if (hsBuf.size() >= 4) {
                size_t length = (size_t(hsBuf[1]) << 16) | (size_t(hsBuf[2]) << 8) | hsBuf[3];
                if (length > MAX_HANDSHAKE_MESSAGE) {
                    co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "handshake message too large");
                }

                if (hsBuf.size() >= 4 + length) {
                    out.type = hsBuf[0];
                    out.raw.assign(hsBuf.begin(), hsBuf.begin() + long(4 + length));
                    out.body.assign(out.raw.begin() + 4, out.raw.end());
                    hsBuf.erase(hsBuf.begin(), hsBuf.begin() + long(4 + length));
                    co_return SBOX_OK;
                }
            }

            uint8_t type = 0;
            std::vector<uint8_t> data;
            int32_t rc = co_await readRecord(type, data, remaining(-1));
            if (rc != SBOX_OK) {
                if (phase == PHASE_FAILED) {
                    co_return error;
                }

                if (rc == -ENODATA) {
                    co_return failQuiet(-ECONNRESET, "the connection was closed during the handshake");
                }

                if (rc == -ETIMEDOUT) {
                    co_return failQuiet(-ETIMEDOUT, "the handshake timed out");
                }

                co_return failQuiet(rc, "transport error during the handshake: " + std::string(std::strerror(-rc)));
            }

            if (type == CT_HANDSHAKE) {
                hsBuf.insert(hsBuf.end(), data.begin(), data.end());
                continue;
            }

            if (!hsBuf.empty()) {
                co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "a handshake message was interleaved with another record type");
            }

            if (type == CT_ALERT) {
                int32_t a = co_await onAlert(data);
                if (a < 0) {
                    co_return a;
                }

                if (a == 1) {
                    co_return error;
                }

                continue;
            }

            if (type == CT_CHANGE_CIPHER_SPEC) {
                if (data.size() != 1 || data[0] != 1) {
                    co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "received a malformed change_cipher_spec");
                }

                // --> TLS 1.3 middlebox compatibility (RFC 8446 D.4): drop it.
                if (version == 0 || tls13()) {
                    if (serverFinished) {
                        co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "received change_cipher_spec after the server Finished");
                    }

                    continue;
                }

                out.type = MSG_CCS;
                out.body.clear();
                out.raw.clear();
                co_return SBOX_OK;
            }

            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "received application data during the handshake");
        }
    }

    /* Rekeys our sending direction (writeLock held by the caller). */
    TTask<int32_t> CTlsStream::SImpl::updateWriteKeys(bool requestPeer, int64_t timeoutMs) {
        uint8_t msg[5] = { HS_KEY_UPDATE, 0, 0, 1, uint8_t(requestPeer ? 1 : 0) };
        std::vector<uint8_t> wire;
        if (!writeCipher.seal13(CT_HANDSHAKE, SReadOnlyByteSpan(msg, 5), 0, wire)) {
            co_return -EIO;
        }

        SIoResult r = co_await transport->send(BytesOf(wire), timeoutMs);
        if (!r.ok()) {
            co_return r.error;
        }

        std::vector<uint8_t> next = Tls13NextSecret(suite->hash, BytesOf(clientAppSecret));
        Wipe(clientAppSecret);
        clientAppSecret = std::move(next);
        co_return Tls13InstallKeys(writeCipher, *suite, BytesOf(clientAppSecret)) ? SBOX_OK : -EIO;
    }

    /* Post-handshake messages. */
    TTask<int32_t> CTlsStream::SImpl::postHandshake() {
        while (hsBuf.size() >= 4) {
            size_t length = (size_t(hsBuf[1]) << 16) | (size_t(hsBuf[2]) << 8) | hsBuf[3];
            if (length > MAX_HANDSHAKE_MESSAGE) {
                co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "post-handshake message too large");
            }

            if (hsBuf.size() < 4 + length) {
                co_return SBOX_OK;
            }

            uint8_t type = hsBuf[0];
            std::vector<uint8_t> body(hsBuf.begin() + 4, hsBuf.begin() + long(4 + length));
            hsBuf.erase(hsBuf.begin(), hsBuf.begin() + long(4 + length));

            if (!tls13()) {
                if (type == HS_HELLO_REQUEST && body.empty()) {
                    // --> Renegotiation is never performed (RFC 5746 4.5 lets us decline).
                    co_await sendAlert(ALERT_WARNING, AD_NO_RENEGOTIATION);
                    continue;
                }

                co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "unexpected post-handshake message " + std::to_string(type));
            }

            if (type == HS_NEW_SESSION_TICKET) {
                // --> Resumption is not implemented: tickets are parsed for shape and dropped.
                Reader r(BytesOf(body));
                r.bytes(8);     // --> ticket_lifetime, ticket_age_add.
                r.block(1);
                r.block(2);
                r.block(2);
                if (!r.done()) {
                    co_return co_await fail(-EPROTO, AD_DECODE_ERROR, "malformed NewSessionTicket");
                }

                continue;
            }

            if (type == HS_KEY_UPDATE) {
                if (body.size() != 1 || body[0] > 1) {
                    co_return co_await fail(-EPROTO, AD_ILLEGAL_PARAMETER, "malformed KeyUpdate");
                }

                if (!hsBuf.empty()) {
                    co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "KeyUpdate is not at a record boundary");
                }

                std::vector<uint8_t> next = Tls13NextSecret(suite->hash, BytesOf(serverAppSecret));
                Wipe(serverAppSecret);
                serverAppSecret = std::move(next);
                if (!Tls13InstallKeys(readCipher, *suite, BytesOf(serverAppSecret))) {
                    co_return co_await fail(-EIO, AD_INTERNAL_ERROR, "key derivation failed");
                }

                if (body[0] == 1 && !closeNotifySent) {
                    co_await writeLock.lock();
                    int32_t rc = co_await updateWriteKeys(false, 5000);
                    writeLock.unlock();

                    if (rc != SBOX_OK) {
                        co_return failQuiet(rc, "failed to answer KeyUpdate");
                    }
                }

                continue;
            }

            co_return co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "unexpected post-handshake message " + std::to_string(type));
        }

        co_return SBOX_OK;
    }

    /* Reads application data. */
    TTask<SIoResult> CTlsStream::SImpl::recv(const SByteSpan& buffer, int64_t timeoutMs) {
        int64_t until = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            if (appPos < appBuf.size()) {
                size_t n = appBuf.size() - appPos;
                if (n > buffer.size) {
                    n = buffer.size;
                }

                if (n) {
                    std::memcpy(buffer.data, appBuf.data() + appPos, n);
                }

                appPos += n;
                if (appPos == appBuf.size()) {
                    Wipe(appBuf);
                    appPos = 0;
                }

                co_return SIoResult{ SBOX_OK, n };
            }

            if (buffer.size == 0) {
                co_return SIoResult{ SBOX_OK, 0 };
            }

            if (phase == PHASE_CLOSED) {
                co_return SIoResult{ SBOX_OK, 0 };
            }

            if (phase == PHASE_FAILED) {
                co_return SIoResult{ error, 0 };
            }

            if (phase != PHASE_OPEN) {
                co_return SIoResult{ -ENOTCONN, 0 };
            }

            uint8_t type = 0;
            std::vector<uint8_t> data;
            int32_t rc = co_await readRecord(type, data, timeLeft(until));
            if (rc != SBOX_OK) {
                if (phase == PHASE_FAILED) {
                    co_return SIoResult{ error, 0 };
                }

                if (rc == -ETIMEDOUT || rc == -ECANCELED) {
                    co_return SIoResult{ rc, 0 };
                }

                if (rc == -ENODATA) {
                    rc = failQuiet(-ECONNRESET, "the connection was closed without close_notify (possible truncation)");
                    co_return SIoResult{ rc, 0 };
                }

                co_return SIoResult{ failQuiet(rc, "transport error: " + std::string(std::strerror(-rc))), 0 };
            }

            if (type == CT_APPLICATION_DATA) {
                if (!hsBuf.empty()) {
                    co_return SIoResult{ co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "application data interleaved with a handshake message"), 0 };
                }

                appBuf = std::move(data);
                appPos = 0;
                continue;
            }

            if (type == CT_HANDSHAKE) {
                hsBuf.insert(hsBuf.end(), data.begin(), data.end());
                rc = co_await postHandshake();
                if (rc != SBOX_OK) {
                    co_return SIoResult{ rc, 0 };
                }

                continue;
            }

            if (type == CT_ALERT) {
                int32_t a = co_await onAlert(data);
                if (a < 0) {
                    co_return SIoResult{ a, 0 };
                }

                if (a == 1) {
                    co_return SIoResult{ SBOX_OK, 0 };
                }

                continue;
            }

            co_return SIoResult{ co_await fail(-EPROTO, AD_UNEXPECTED_MESSAGE, "unexpected change_cipher_spec after the handshake"), 0 };
        }
    }

    /* Writes application data. */
    TTask<SIoResult> CTlsStream::SImpl::send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs) {
        if (phase == PHASE_FAILED) {
            co_return SIoResult{ error, 0 };
        }

        if (phase == PHASE_HANDSHAKE) {
            co_return SIoResult{ -ENOTCONN, 0 };
        }

        if (closeNotifySent) {
            co_return SIoResult{ -EPIPE, 0 };
        }

        int64_t until = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        co_await writeLock.lock();

        size_t sent = 0;
        int32_t rc = SBOX_OK;

        while (sent < buffer.size && rc == SBOX_OK) {
            if (tls13() && writeCipher.sequence() >= KEY_UPDATE_AFTER) {
                rc = co_await updateWriteKeys(false, timeLeft(until));
                if (rc != SBOX_OK) {
                    break;
                }
            }

            std::vector<uint8_t> wire;
            size_t batchStart = sent;
            for (size_t i = 0; i < WRITE_BATCH && sent < buffer.size; ++i) {
                size_t n = buffer.size - sent < MAX_PLAINTEXT ? buffer.size - sent : MAX_PLAINTEXT;
                SReadOnlyByteSpan chunk(buffer.data + sent, n);
                bool ok;

                if (tls13()) {
                    size_t block = options.recordPadding;
                    size_t pad = block > 1 ? (block - (n + 1) % block) % block : 0;
                    ok = writeCipher.seal13(CT_APPLICATION_DATA, chunk, pad, wire);
                }
                else {
                    ok = writeCipher.seal12(CT_APPLICATION_DATA, chunk, wire);
                }

                if (!ok) {
                    rc = -EIO;
                    break;
                }

                sent += n;
            }

            if (rc != SBOX_OK) {
                break;
            }

            SIoResult r = co_await transport->send(BytesOf(wire), timeLeft(until));
            if (!r.ok()) {
                rc = r.error;
                sent = batchStart;
            }
        }

        writeLock.unlock();

        if (rc != SBOX_OK) {
            // --> A partially written record cannot be resumed: the session is unusable.
            failQuiet(rc, "failed to send application data: " + std::string(std::strerror(-rc)));
            co_return SIoResult{ rc, sent };
        }

        co_return SIoResult{ SBOX_OK, sent };
    }

    /* Sends close_notify. */
    TTask<int32_t> CTlsStream::SImpl::shutdown(int64_t timeoutMs) {
        if (phase == PHASE_FAILED) {
            co_return error;
        }

        if (closeNotifySent || phase == PHASE_HANDSHAKE) {
            co_return SBOX_OK;
        }

        closeNotifySent = true;
        uint8_t alert[2] = { ALERT_WARNING, AD_CLOSE_NOTIFY };
        co_return co_await writeRecords(CT_ALERT, SReadOnlyByteSpan(alert, 2), timeoutMs);
    }

    /* Wraps a transport. */
    CTlsStream::CTlsStream(IStreamPtr transport, const STlsClientOptions& options)
        : _impl(std::make_unique<SImpl>(std::move(transport), options)) {}

    /* Destroys the stream (the transport is released, not closed). */
    CTlsStream::~CTlsStream() = default;

    /* Runs the handshake. */
    TTask<int32_t> CTlsStream::handshake() {
        co_return co_await _impl->handshake();
    }

    /* Reads application data. */
    TTask<SIoResult> CTlsStream::recv(const SByteSpan& buffer, int64_t timeoutMs) {
        co_return co_await _impl->recv(buffer, timeoutMs);
    }

    /* Writes application data. */
    TTask<SIoResult> CTlsStream::send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs) {
        co_return co_await _impl->send(buffer, timeoutMs);
    }

    /* Sends close_notify. */
    TTask<int32_t> CTlsStream::shutdown(int64_t timeoutMs) {
        co_return co_await _impl->shutdown(timeoutMs);
    }

    /* Closes the transport. */
    void CTlsStream::close() noexcept {
        if (_impl->transport) {
            _impl->transport->close();
        }
    }

    /* Handshake report. */
    const STlsReport& CTlsStream::info() const noexcept {
        return _impl->report;
    }

    /* Last error. */
    int32_t CTlsStream::lastError() const noexcept {
        return _impl->error;
    }

    /* Failure reason. */
    const std::string& CTlsStream::failureReason() const noexcept {
        return _impl->reason;
    }

    /* Connects TLS over a transport. */
    TTask<int32_t> ConnectTls(IStreamPtr transport, const STlsClientOptions& options, IStreamPtr& out) {
        // --> Copied before the first suspension: the caller's options need not outlive it.
        STlsClientOptions copy = options;

        if (!transport) {
            if (copy.report) {
                copy.report->error = -EINVAL;
                copy.report->reason = "no transport";
            }

            co_return -EINVAL;
        }

        auto stream = std::make_shared<CTlsStream>(std::move(transport), copy);
        int32_t rc = co_await stream->handshake();

        if (copy.report) {
            *copy.report = stream->info();
        }

        if (rc == SBOX_OK) {
            out = stream;
        }

        co_return rc;
    }

}
}
