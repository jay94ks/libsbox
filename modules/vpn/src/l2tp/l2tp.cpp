#include <sbox/vpn/l2tp/l2tp.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "ipsec/crypto.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>

namespace sbox {
namespace vpn {

    using ipsec::GetBe16;
    using ipsec::GetBe32;
    using ipsec::PutBe16;
    using ipsec::PutBe32;

    namespace {

        /* MD5 of concatenated parts. */
        std::vector<uint8_t> md5(std::initializer_list<SReadOnlyByteSpan> parts) {
            return ipsec::HashParts(certpp::crypto::EHASH_MD5, parts);
        }

        /* Hides or reveals an AVP value in place (RFC 2661 4.3). */
        void hideValue(uint16_t type, std::string_view secret, const std::vector<uint8_t>& vector, std::vector<uint8_t>& data, bool hide) {
            uint8_t typeBytes[2] = { uint8_t(type >> 8), uint8_t(type) };
            std::vector<uint8_t> b = md5({ SReadOnlyByteSpan(typeBytes, 2), BytesOf(secret), BytesOf(vector) });
            for (size_t at = 0; at < data.size(); at += 16) {
                size_t n = data.size() - at < 16 ? data.size() - at : 16;
                std::vector<uint8_t> cipherChunk;
                if (!hide) {
                    cipherChunk.assign(data.begin() + long(at), data.begin() + long(at + n));
                }

                for (size_t i = 0; i < n; ++i) {
                    data[at + i] ^= b[i];
                }

                if (hide) {
                    cipherChunk.assign(data.begin() + long(at), data.begin() + long(at + n));
                }

                if (n == 16) {
                    b = md5({ BytesOf(secret), BytesOf(cipherChunk) });
                }
            }
        }

        /* Appends one encoded AVP. */
        void encodeAvp(const SL2tpAvp& a, const std::vector<uint8_t>& value, bool hidden, std::vector<uint8_t>& out) {
            uint16_t flags = uint16_t((a.mandatory ? 0x8000 : 0) | (hidden ? 0x4000 : 0));
            PutBe16(out, flags | uint16_t((value.size() + 6) & 0x3ff));
            PutBe16(out, a.vendor);
            PutBe16(out, a.type);
            out.insert(out.end(), value.begin(), value.end());
        }

    }

    /* Header parser. */
    int32_t ParseL2tpHeader(const SReadOnlyByteSpan& packet, SL2tpHeader& out) noexcept {
        out = SL2tpHeader();
        if (packet.size < 6) {
            return -EBADMSG;
        }

        uint16_t flags = GetBe16(packet.data);
        out.version = uint8_t(flags & 0x0f);
        if (out.version != 2) {
            return -EPROTONOSUPPORT;
        }

        out.control = (flags & L2TP_F_TYPE) != 0;
        out.hasLength = (flags & L2TP_F_LENGTH) != 0;
        out.hasSequence = (flags & L2TP_F_SEQUENCE) != 0;
        out.priority = (flags & L2TP_F_PRIORITY) != 0;
        bool offset = (flags & L2TP_F_OFFSET) != 0;
        if (out.control && (!out.hasLength || !out.hasSequence || offset)) {
            return -EBADMSG;
        }

        size_t at = 2;
        out.packetSize = packet.size;
        if (out.hasLength) {
            out.length = GetBe16(packet.data + at);
            at += 2;
            if (out.length < 6 || out.length > packet.size) {
                return -EBADMSG;
            }

            out.packetSize = out.length;
        }

        if (out.packetSize < at + 4) {
            return -EBADMSG;
        }

        out.tunnelId = GetBe16(packet.data + at);
        out.sessionId = GetBe16(packet.data + at + 2);
        at += 4;
        if (out.hasSequence) {
            if (out.packetSize < at + 4) {
                return -EBADMSG;
            }

            out.ns = GetBe16(packet.data + at);
            out.nr = GetBe16(packet.data + at + 2);
            at += 4;
        }

        if (offset) {
            if (out.packetSize < at + 2) {
                return -EBADMSG;
            }

            size_t pad = GetBe16(packet.data + at);
            at += 2;
            if (out.packetSize < at + pad) {
                return -EBADMSG;
            }

            at += pad;
        }

        out.payloadOffset = at;
        return SBOX_OK;
    }

    /* 16-bit value. */
    uint16_t SL2tpAvp::u16() const noexcept {
        return value.size() == 2 ? GetBe16(value.data()) : 0;
    }

    /* 32-bit value. */
    uint32_t SL2tpAvp::u32() const noexcept {
        return value.size() == 4 ? GetBe32(value.data()) : 0;
    }

    /* Text value. */
    std::string SL2tpAvp::text() const {
        std::string out;
        for (uint8_t c : value) {
            out.push_back(c >= 0x20 && c < 0x7f ? char(c) : '?');
        }

        return out;
    }

    /* 16-bit AVP. */
    SL2tpAvp SL2tpAvp::of16(uint16_t type, uint16_t value, bool mandatory) {
        SL2tpAvp a;
        a.type = type;
        a.mandatory = mandatory;
        PutBe16(a.value, value);
        return a;
    }

    /* 32-bit AVP. */
    SL2tpAvp SL2tpAvp::of32(uint16_t type, uint32_t value, bool mandatory) {
        SL2tpAvp a;
        a.type = type;
        a.mandatory = mandatory;
        PutBe32(a.value, value);
        return a;
    }

    /* Byte AVP. */
    SL2tpAvp SL2tpAvp::ofBytes(uint16_t type, const SReadOnlyByteSpan& value, bool mandatory) {
        SL2tpAvp a;
        a.type = type;
        a.mandatory = mandatory;
        a.value.assign(value.data, value.data + value.size);
        return a;
    }

    /* AVP parser. */
    int32_t ParseL2tpAvps(const SReadOnlyByteSpan& data, std::string_view secret, std::vector<SL2tpAvp>& out) {
        out.clear();
        std::vector<uint8_t> vector;
        size_t at = 0;
        while (at < data.size) {
            if (data.size - at < 6) {
                return -EBADMSG;
            }

            uint16_t first = GetBe16(data.data + at);
            size_t length = first & 0x3ff;
            if (length < 6 || length > data.size - at || (first & 0x3c00) != 0) {
                return -EBADMSG;
            }

            SL2tpAvp a;
            a.mandatory = (first & 0x8000) != 0;
            a.hidden = (first & 0x4000) != 0;
            a.vendor = GetBe16(data.data + at + 2);
            a.type = GetBe16(data.data + at + 4);
            a.value.assign(data.data + at + 6, data.data + at + length);
            at += length;

            if (a.hidden) {
                if (secret.empty() || vector.empty() || a.value.size() < 2) {
                    return -EACCES;
                }

                hideValue(a.type, secret, vector, a.value, false);
                size_t original = GetBe16(a.value.data());
                if (original > a.value.size() - 2) {
                    return -EACCES;
                }

                a.value = std::vector<uint8_t>(a.value.begin() + 2, a.value.begin() + 2 + long(original));
            }

            if (a.vendor == 0 && a.type == EL2TP_AVP_RANDOM_VECTOR) {
                vector = a.value;
            }

            out.push_back(std::move(a));
            if (out.size() > 512) {
                return -EBADMSG;
            }
        }

        return SBOX_OK;
    }

    /* AVP encoder. */
    void EncodeL2tpAvps(const std::vector<SL2tpAvp>& avps, std::string_view secret, std::vector<uint8_t>& out) {
        std::vector<uint8_t> vector;
        for (const SL2tpAvp& a : avps) {
            bool hide = a.hidden && !secret.empty();
            if (!hide) {
                encodeAvp(a, a.value, false, out);
                continue;
            }

            if (vector.empty()) {
                vector.resize(16);
                IkeRandom(SByteSpan(vector.data(), vector.size()));
                SL2tpAvp rv = SL2tpAvp::ofBytes(EL2TP_AVP_RANDOM_VECTOR, BytesOf(vector));
                encodeAvp(rv, rv.value, false, out);
            }

            std::vector<uint8_t> sub;
            PutBe16(sub, uint32_t(a.value.size()));
            sub.insert(sub.end(), a.value.begin(), a.value.end());
            // --> Random padding to a whole number of chunks hides the original length.
            size_t pad = (16 - sub.size() % 16) % 16;
            std::vector<uint8_t> padding(pad);
            IkeRandom(SByteSpan(padding.data(), padding.size()));
            sub.insert(sub.end(), padding.begin(), padding.end());
            hideValue(a.type, secret, vector, sub, true);
            encodeAvp(a, sub, true, out);
        }
    }

    /* AVP lookup. */
    const SL2tpAvp* FindL2tpAvp(const std::vector<SL2tpAvp>& avps, uint16_t type) noexcept {
        for (const SL2tpAvp& a : avps) {
            if (a.vendor == 0 && a.type == type) {
                return &a;
            }
        }

        return nullptr;
    }

    /* Control message builder. */
    std::vector<uint8_t> BuildL2tpControl(uint16_t tunnelId, uint16_t sessionId, uint16_t ns, uint16_t nr, const std::vector<SL2tpAvp>& avps,
                                          std::string_view secret) {
        std::vector<uint8_t> out;
        PutBe16(out, L2TP_F_TYPE | L2TP_F_LENGTH | L2TP_F_SEQUENCE | 2);
        PutBe16(out, 0);
        PutBe16(out, tunnelId);
        PutBe16(out, sessionId);
        PutBe16(out, ns);
        PutBe16(out, nr);
        EncodeL2tpAvps(avps, secret, out);
        ipsec::SetBe16(out.data() + 2, uint32_t(out.size()));
        return out;
    }

    /* Data message builder. */
    std::vector<uint8_t> BuildL2tpData(uint16_t tunnelId, uint16_t sessionId, const SReadOnlyByteSpan& ppp, bool sequence, uint16_t ns,
                                       uint16_t nr) {
        std::vector<uint8_t> out;
        out.reserve(ppp.size + 12);
        PutBe16(out, uint32_t(sequence ? L2TP_F_SEQUENCE : 0) | 2);
        PutBe16(out, tunnelId);
        PutBe16(out, sessionId);
        if (sequence) {
            PutBe16(out, ns);
            PutBe16(out, nr);
        }

        out.insert(out.end(), ppp.data, ppp.data + ppp.size);
        return out;
    }

    /* Message names. */
    std::string L2tpMessageName(uint16_t type) {
        switch (type) {
        case EL2TP_ZLB: return "ZLB";
        case EL2TP_SCCRQ: return "SCCRQ";
        case EL2TP_SCCRP: return "SCCRP";
        case EL2TP_SCCCN: return "SCCCN";
        case EL2TP_STOPCCN: return "StopCCN";
        case EL2TP_HELLO: return "HELLO";
        case EL2TP_OCRQ: return "OCRQ";
        case EL2TP_OCRP: return "OCRP";
        case EL2TP_OCCN: return "OCCN";
        case EL2TP_ICRQ: return "ICRQ";
        case EL2TP_ICRP: return "ICRP";
        case EL2TP_ICCN: return "ICCN";
        case EL2TP_CDN: return "CDN";
        case EL2TP_WEN: return "WEN";
        case EL2TP_SLI: return "SLI";
        default: return "MSG" + std::to_string(type);
        }
    }

    // ----------------------------------------------------------------------------------------
    // Tunnel

    namespace {

        enum SessionState {
            SS_WAIT_ICRP = 0,       // --> LAC: ICRQ sent.
            SS_WAIT_ICCN,           // --> LNS: ICRP sent.
            SS_ESTABLISHED,
        };

        /**
         * One session of a tunnel.
         */
        struct Session {
            uint16_t localId = 0;
            uint16_t peerId = 0;
            int state = SS_WAIT_ICRP;
            bool sequencing = false;
            uint16_t dataNs = 0;
            uint16_t dataNr = 0;
        };

        /**
         * One queued control message.
         */
        struct Outgoing {
            std::vector<uint8_t> packet;
            uint16_t ns = 0;
            bool sent = false;
            int64_t nextSend = 0;
            uint32_t tries = 0;
            uint16_t type = 0;
        };

        /* Signed 16-bit sequence distance a - b. */
        int32_t seqDiff(uint16_t a, uint16_t b) {
            return int32_t(int16_t(uint16_t(a - b)));
        }

    }

    struct CL2tpTunnel::SState {
        SL2tpTunnelConfig config;
        bool lns = true;
        uint16_t localId = 0;
        uint16_t peerId = 0;
        EL2tpTunnelState state = EL2TS_IDLE;
        uint16_t ns = 0;
        uint16_t nr = 0;
        uint16_t peerWindow = 4;
        std::deque<Outgoing> queue;
        std::map<uint16_t, std::vector<uint8_t>> early;     // --> Out-of-order control messages by Ns.
        std::map<uint16_t, Session> sessions;
        uint32_t callSerial = 1;
        std::string peerHost;
        std::vector<uint8_t> ourChallenge;
        bool ackPending = false;
        int64_t now = 0;
        int64_t lastRx = 0;
        int64_t closeAt = 0;
        std::string closeReason;
        bool closedNotified = false;
        std::function<void(const SReadOnlyByteSpan&)> send;
        std::function<void(const std::string&)> log;
        std::function<void()> established;
        std::function<void(uint16_t)> sessionUp;
        std::function<void(uint16_t, const SReadOnlyByteSpan&)> sessionData;
        std::function<void(uint16_t, const std::string&)> sessionDown;
        std::function<void(const std::string&)> closed;

        /* Current time. */
        int64_t clock() {
            int64_t t = CEventLoop::nowMs();
            now = t > now ? t : now;
            return now;
        }

        /* Logs. */
        void logf(const std::string& m) {
            if (log) {
                log("l2tp tunnel " + std::to_string(localId) + "/" + std::to_string(peerId) + ": " + m);
            }
        }

        /* Raw send. */
        void transmit(const std::vector<uint8_t>& packet) {
            if (send) {
                send(BytesOf(packet));
            }
        }

        /* Queues a control message (Ns assigned now, Nr patched on every transmission). */
        void sendControl(uint16_t sessionPeerId, std::vector<SL2tpAvp> avps, uint16_t type) {
            avps.insert(avps.begin(), SL2tpAvp::of16(EL2TP_AVP_MESSAGE_TYPE, type));
            Outgoing o;
            o.ns = ns++;
            o.type = type;
            o.packet = BuildL2tpControl(peerId, sessionPeerId, o.ns, nr, avps, config.secret);
            queue.push_back(std::move(o));
            pump();
        }

        /* Transmits queued messages the peer's window allows. */
        void pump() {
            size_t inFlight = 0;
            for (Outgoing& o : queue) {
                if (o.sent) {
                    ++inFlight;
                    continue;
                }

                if (inFlight >= peerWindow) {
                    break;
                }

                ipsec::SetBe16(o.packet.data() + 10, nr);
                o.sent = true;
                o.tries = 0;
                o.nextSend = clock() + config.retransmitMs;
                ackPending = false;
                transmit(o.packet);
                ++inFlight;
            }
        }

        /* Sends a ZLB acknowledgement. */
        void sendZlb() {
            ackPending = false;
            std::vector<SL2tpAvp> none;
            transmit(BuildL2tpControl(peerId, 0, ns, nr, none));
        }

        /* Removes acknowledged messages. */
        void acknowledge(uint16_t peerNr) {
            bool changed = false;
            while (!queue.empty() && queue.front().sent && seqDiff(queue.front().ns, peerNr) < 0) {
                if (queue.front().type == EL2TP_STOPCCN && state == EL2TS_CLOSING) {
                    // --> Our StopCCN arrived; keep a short linger for retransmissions.
                    closeAt = std::min(closeAt, clock() + 500);
                }

                queue.pop_front();
                changed = true;
            }

            if (changed) {
                pump();
            }
        }

        /* Ends every session. */
        void dropSessions(const std::string& reason) {
            std::vector<uint16_t> ids;
            for (auto& [id, s] : sessions) {
                if (s.state == SS_ESTABLISHED) {
                    ids.push_back(id);
                }
            }

            sessions.clear();
            for (uint16_t id : ids) {
                if (sessionDown) {
                    sessionDown(id, reason);
                }
            }
        }

        /* Enters CLOSING (after StopCCN in either direction). */
        void beginClose(const std::string& reason) {
            if (state == EL2TS_CLOSING || state == EL2TS_CLOSED) {
                return;
            }

            state = EL2TS_CLOSING;
            closeReason = reason;
            closeAt = clock() + config.closeLingerMs;
            dropSessions(reason);
        }

        /* Final state. */
        void finish(const std::string& reason) {
            if (state != EL2TS_CLOSING && state != EL2TS_CLOSED) {
                dropSessions(reason);
            }

            state = EL2TS_CLOSED;
            queue.clear();
            if (!closedNotified) {
                closedNotified = true;
                logf("closed: " + (closeReason.empty() ? reason : closeReason));
                if (closed) {
                    closed(closeReason.empty() ? reason : closeReason);
                }
            }
        }

        /* Sends StopCCN. */
        void stop(uint16_t result, uint16_t error, const std::string& message) {
            if (state == EL2TS_CLOSING || state == EL2TS_CLOSED) {
                return;
            }

            std::vector<SL2tpAvp> avps;
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_TUNNEL_ID, localId));
            std::vector<uint8_t> rc;
            PutBe16(rc, result);
            if (error || !message.empty()) {
                PutBe16(rc, error);
                rc.insert(rc.end(), message.begin(), message.end());
            }

            avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_RESULT_CODE, BytesOf(rc)));
            logf("sending StopCCN result " + std::to_string(result) + (message.empty() ? "" : " (" + message + ")"));
            sendControl(0, avps, EL2TP_STOPCCN);
            beginClose(message.empty() ? "StopCCN sent" : message);
        }

        /* Sends CDN for a session and forgets it. */
        void cdn(uint16_t localSid, uint16_t result, const std::string& message) {
            auto it = sessions.find(localSid);
            uint16_t peerSid = it != sessions.end() ? it->second.peerId : 0;
            std::vector<SL2tpAvp> avps;
            std::vector<uint8_t> rc;
            PutBe16(rc, result);
            if (!message.empty()) {
                PutBe16(rc, 0);
                rc.insert(rc.end(), message.begin(), message.end());
            }

            avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_RESULT_CODE, BytesOf(rc)));
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_SESSION_ID, localSid));
            sendControl(peerSid, avps, EL2TP_CDN);
            if (it != sessions.end()) {
                bool wasUp = it->second.state == SS_ESTABLISHED;
                sessions.erase(it);
                if (wasUp && sessionDown) {
                    sessionDown(localSid, message.empty() ? "CDN sent" : message);
                }
            }
        }

        /* Challenge response value: MD5(type | secret | challenge). */
        std::vector<uint8_t> challengeResponse(uint8_t type, const std::vector<uint8_t>& challenge) {
            return md5({ SReadOnlyByteSpan(&type, 1), BytesOf(config.secret), BytesOf(challenge) });
        }

        /* Allocates a session ID. */
        uint16_t newSessionId() {
            for (int32_t i = 0; i < 256; ++i) {
                uint16_t id = 0;
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&id), sizeof(id)));
                if (id != 0 && !sessions.count(id)) {
                    return id;
                }
            }

            return 0;
        }

        /* Common SCCRQ/SCCRP AVPs. */
        std::vector<SL2tpAvp> setupAvps() {
            std::vector<SL2tpAvp> avps;
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_PROTOCOL_VERSION, 0x0100));
            avps.push_back(SL2tpAvp::of32(EL2TP_AVP_FRAMING_CAPABILITIES, 3));
            avps.push_back(SL2tpAvp::of32(EL2TP_AVP_BEARER_CAPABILITIES, 0));
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_FIRMWARE_REVISION, 0x0100, false));
            avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_HOST_NAME, BytesOf(config.hostName)));
            avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_VENDOR_NAME, BytesOf(config.vendorName), false));
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_TUNNEL_ID, localId));
            avps.push_back(SL2tpAvp::of16(EL2TP_AVP_RECEIVE_WINDOW_SIZE, config.receiveWindow));
            return avps;
        }

        /* Returns the first mandatory AVP we do not understand, or nullptr. */
        static const SL2tpAvp* unknownMandatory(const std::vector<SL2tpAvp>& avps) {
            for (const SL2tpAvp& a : avps) {
                if (!a.mandatory) {
                    continue;
                }

                if (a.vendor != 0 || a.type > EL2TP_AVP_SEQUENCING_REQUIRED || a.type == 20) {
                    return &a;
                }
            }

            return nullptr;
        }

        /* Handles one in-order control message. */
        void process(const SL2tpHeader& h, const SReadOnlyByteSpan& packet) {
            std::vector<SL2tpAvp> avps;
            int32_t r = ParseL2tpAvps(packet.slice(h.payloadOffset), config.secret, avps);
            if (r != SBOX_OK || avps.empty() || avps[0].vendor != 0 || avps[0].type != EL2TP_AVP_MESSAGE_TYPE ||
                avps[0].value.size() != 2) {
                logf("malformed control message");
                stop(EL2TP_RES_STOP_ERROR, 6, "malformed control message");
                return;
            }

            uint16_t type = avps[0].u16();
            const SL2tpAvp* unknown = unknownMandatory(avps);
            if (unknown) {
                std::string what = "unknown mandatory AVP " + std::to_string(unknown->vendor) + ":" + std::to_string(unknown->type);
                if (h.sessionId && sessions.count(h.sessionId) && type >= EL2TP_OCRQ) {
                    cdn(h.sessionId, EL2TP_RES_CDN_ERROR, what);
                }
                else {
                    stop(EL2TP_RES_STOP_ERROR, 8, what);
                }

                return;
            }

            logf("received " + L2tpMessageName(type));
            switch (type) {
            case EL2TP_SCCRQ: onSccrq(avps); break;
            case EL2TP_SCCRP: onSccrp(avps); break;
            case EL2TP_SCCCN: onScccn(avps); break;
            case EL2TP_STOPCCN: {
                const SL2tpAvp* rc = FindL2tpAvp(avps, EL2TP_AVP_RESULT_CODE);
                std::string reason = "StopCCN from peer";
                if (rc && rc->value.size() >= 2) {
                    reason += ", result " + std::to_string(GetBe16(rc->value.data()));
                    if (rc->value.size() > 4) {
                        reason += " (" + std::string(rc->value.begin() + 4, rc->value.end()) + ")";
                    }
                }

                // --> Acknowledge it now: no message will follow to carry the ack.
                sendZlb();
                beginClose(reason);
                break;
            }

            case EL2TP_HELLO: break;
            case EL2TP_ICRQ: onIcrq(avps); break;
            case EL2TP_ICRP: onIcrp(h, avps); break;
            case EL2TP_ICCN: onIccn(h, avps); break;
            case EL2TP_CDN: onCdn(h, avps); break;
            case EL2TP_OCRQ: {
                // --> We never accept outgoing calls.
                const SL2tpAvp* sid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_SESSION_ID);
                std::vector<SL2tpAvp> out;
                std::vector<uint8_t> rc;
                PutBe16(rc, EL2TP_RES_CDN_NO_RESOURCES);
                out.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_RESULT_CODE, BytesOf(rc)));
                out.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_SESSION_ID, 0));
                sendControl(sid ? sid->u16() : 0, out, EL2TP_CDN);
                break;
            }

            default:
                // --> WEN, SLI and anything else: acknowledged only.
                break;
            }
        }

        /* SCCRQ (LNS). */
        void onSccrq(const std::vector<SL2tpAvp>& avps) {
            if (!lns || state != EL2TS_IDLE) {
                return;
            }

            const SL2tpAvp* tid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_TUNNEL_ID);
            const SL2tpAvp* ver = FindL2tpAvp(avps, EL2TP_AVP_PROTOCOL_VERSION);
            const SL2tpAvp* host = FindL2tpAvp(avps, EL2TP_AVP_HOST_NAME);
            const SL2tpAvp* rws = FindL2tpAvp(avps, EL2TP_AVP_RECEIVE_WINDOW_SIZE);
            const SL2tpAvp* chal = FindL2tpAvp(avps, EL2TP_AVP_CHALLENGE);
            if (!tid || tid->u16() == 0 || !ver || !host || !FindL2tpAvp(avps, EL2TP_AVP_FRAMING_CAPABILITIES)) {
                state = EL2TS_CLOSED;
                logf("SCCRQ without the mandatory AVPs");
                return;
            }

            peerId = tid->u16();
            peerHost = host->text();
            if (rws && rws->u16()) {
                peerWindow = rws->u16();
            }

            if (ver->value.size() != 2 || ver->value[0] != 1) {
                stop(EL2TP_RES_STOP_BAD_VERSION, 0, "unsupported protocol version");
                return;
            }

            std::vector<SL2tpAvp> out = setupAvps();
            if (chal) {
                if (config.secret.empty()) {
                    stop(EL2TP_RES_STOP_NOT_AUTHORIZED, 0, "peer requests tunnel authentication, no secret configured");
                    return;
                }

                out.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_CHALLENGE_RESPONSE, BytesOf(challengeResponse(EL2TP_SCCRP, chal->value))));
            }

            if (!config.secret.empty()) {
                ourChallenge.resize(16);
                IkeRandom(SByteSpan(ourChallenge.data(), ourChallenge.size()));
                out.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_CHALLENGE, BytesOf(ourChallenge)));
            }

            state = EL2TS_WAIT_CONNECT;
            sendControl(0, out, EL2TP_SCCRP);
        }

        /* SCCRP (LAC). */
        void onSccrp(const std::vector<SL2tpAvp>& avps) {
            if (lns || state != EL2TS_WAIT_REPLY) {
                return;
            }

            const SL2tpAvp* tid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_TUNNEL_ID);
            const SL2tpAvp* host = FindL2tpAvp(avps, EL2TP_AVP_HOST_NAME);
            const SL2tpAvp* rws = FindL2tpAvp(avps, EL2TP_AVP_RECEIVE_WINDOW_SIZE);
            const SL2tpAvp* chal = FindL2tpAvp(avps, EL2TP_AVP_CHALLENGE);
            const SL2tpAvp* resp = FindL2tpAvp(avps, EL2TP_AVP_CHALLENGE_RESPONSE);
            if (!tid || tid->u16() == 0) {
                finish("SCCRP without an assigned tunnel ID");
                return;
            }

            peerId = tid->u16();
            peerHost = host ? host->text() : std::string();
            if (rws && rws->u16()) {
                peerWindow = rws->u16();
            }

            if (!ourChallenge.empty()) {
                if (!resp || !IkeSecureEquals(BytesOf(resp->value), BytesOf(challengeResponse(EL2TP_SCCRP, ourChallenge)))) {
                    stop(EL2TP_RES_STOP_NOT_AUTHORIZED, 0, "tunnel authentication failed");
                    return;
                }
            }

            std::vector<SL2tpAvp> out;
            if (chal) {
                if (config.secret.empty()) {
                    stop(EL2TP_RES_STOP_NOT_AUTHORIZED, 0, "peer requests tunnel authentication, no secret configured");
                    return;
                }

                out.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_CHALLENGE_RESPONSE, BytesOf(challengeResponse(EL2TP_SCCCN, chal->value))));
            }

            sendControl(0, out, EL2TP_SCCCN);
            state = EL2TS_ESTABLISHED;
            logf("established with '" + peerHost + "'");
            if (established) {
                established();
            }
        }

        /* SCCCN (LNS). */
        void onScccn(const std::vector<SL2tpAvp>& avps) {
            if (!lns || state != EL2TS_WAIT_CONNECT) {
                return;
            }

            if (!ourChallenge.empty()) {
                const SL2tpAvp* resp = FindL2tpAvp(avps, EL2TP_AVP_CHALLENGE_RESPONSE);
                if (!resp || !IkeSecureEquals(BytesOf(resp->value), BytesOf(challengeResponse(EL2TP_SCCCN, ourChallenge)))) {
                    stop(EL2TP_RES_STOP_NOT_AUTHORIZED, 0, "tunnel authentication failed");
                    return;
                }
            }

            state = EL2TS_ESTABLISHED;
            logf("established with '" + peerHost + "'");
            if (established) {
                established();
            }
        }

        /* ICRQ (LNS). */
        void onIcrq(const std::vector<SL2tpAvp>& avps) {
            const SL2tpAvp* sid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_SESSION_ID);
            if (!lns || state != EL2TS_ESTABLISHED || !sid || sid->u16() == 0) {
                return;
            }

            // --> A retransmitted ICRQ (our ICRP lost and already acknowledged) maps to the same session.
            for (auto& [id, s] : sessions) {
                if (s.peerId == sid->u16()) {
                    (void)id;
                    return;
                }
            }

            if (sessions.size() >= config.maxSessions) {
                std::vector<SL2tpAvp> out;
                std::vector<uint8_t> rc;
                PutBe16(rc, EL2TP_RES_CDN_NO_RESOURCES);
                out.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_RESULT_CODE, BytesOf(rc)));
                out.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_SESSION_ID, 0));
                sendControl(sid->u16(), out, EL2TP_CDN);
                return;
            }

            Session s;
            s.localId = newSessionId();
            s.peerId = sid->u16();
            s.state = SS_WAIT_ICCN;
            if (!s.localId) {
                return;
            }

            sessions[s.localId] = s;
            std::vector<SL2tpAvp> out;
            out.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_SESSION_ID, s.localId));
            sendControl(s.peerId, out, EL2TP_ICRP);
        }

        /* ICRP (LAC). */
        void onIcrp(const SL2tpHeader& h, const std::vector<SL2tpAvp>& avps) {
            auto it = sessions.find(h.sessionId);
            const SL2tpAvp* sid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_SESSION_ID);
            if (lns || it == sessions.end() || it->second.state != SS_WAIT_ICRP || !sid || sid->u16() == 0) {
                return;
            }

            it->second.peerId = sid->u16();
            std::vector<SL2tpAvp> out;
            out.push_back(SL2tpAvp::of32(EL2TP_AVP_TX_CONNECT_SPEED, 100000000));
            out.push_back(SL2tpAvp::of32(EL2TP_AVP_FRAMING_TYPE, 1));
            sendControl(it->second.peerId, out, EL2TP_ICCN);
            it->second.state = SS_ESTABLISHED;
            uint16_t local = it->second.localId;
            logf("session " + std::to_string(local) + "/" + std::to_string(it->second.peerId) + " established");
            if (sessionUp) {
                sessionUp(local);
            }
        }

        /* ICCN (LNS). */
        void onIccn(const SL2tpHeader& h, const std::vector<SL2tpAvp>& avps) {
            auto it = sessions.find(h.sessionId);
            if (!lns || it == sessions.end() || it->second.state != SS_WAIT_ICCN) {
                return;
            }

            it->second.state = SS_ESTABLISHED;
            it->second.sequencing = FindL2tpAvp(avps, EL2TP_AVP_SEQUENCING_REQUIRED) != nullptr;
            uint16_t local = it->second.localId;
            logf("session " + std::to_string(local) + "/" + std::to_string(it->second.peerId) + " established");
            if (sessionUp) {
                sessionUp(local);
            }
        }

        /* CDN. */
        void onCdn(const SL2tpHeader& h, const std::vector<SL2tpAvp>& avps) {
            uint16_t local = h.sessionId;
            if (local == 0) {
                // --> A CDN for a call we never answered names the peer's session instead.
                const SL2tpAvp* sid = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_SESSION_ID);
                for (auto& [id, s] : sessions) {
                    if (sid && s.peerId == sid->u16()) {
                        local = id;
                    }
                }
            }

            auto it = sessions.find(local);
            if (it == sessions.end()) {
                return;
            }

            bool wasUp = it->second.state == SS_ESTABLISHED;
            sessions.erase(it);
            std::string reason = "CDN from peer";
            const SL2tpAvp* rc = FindL2tpAvp(avps, EL2TP_AVP_RESULT_CODE);
            if (rc && rc->value.size() >= 2) {
                reason += ", result " + std::to_string(GetBe16(rc->value.data()));
                if (rc->value.size() > 4) {
                    reason += " (" + std::string(rc->value.begin() + 4, rc->value.end()) + ")";
                }
            }

            logf("session " + std::to_string(local) + ": " + reason);
            if (wasUp && sessionDown) {
                sessionDown(local, reason);
            }
        }

        /* Packet entry. */
        void input(const SReadOnlyByteSpan& packet) {
            clock();
            SL2tpHeader h;
            if (ParseL2tpHeader(packet, h) != SBOX_OK || state == EL2TS_CLOSED) {
                return;
            }

            SReadOnlyByteSpan bounded(packet.data, h.packetSize);
            if (!h.control) {
                if (h.tunnelId != localId) {
                    return;
                }

                auto it = sessions.find(h.sessionId);
                if (it == sessions.end() || it->second.state != SS_ESTABLISHED) {
                    return;
                }

                if (h.hasSequence) {
                    it->second.dataNr = uint16_t(h.ns + 1);
                }

                if (sessionData) {
                    sessionData(h.sessionId, bounded.slice(h.payloadOffset));
                }

                return;
            }

            if (h.tunnelId != localId && !(h.tunnelId == 0 && lns && state == EL2TS_IDLE)) {
                return;
            }

            lastRx = now;
            acknowledge(h.nr);
            if (h.payloadOffset == h.packetSize) {
                return;     // --> ZLB.
            }

            int32_t diff = seqDiff(h.ns, nr);
            if (diff < 0) {
                // --> Duplicate: our acknowledgement was lost.
                sendZlb();
                return;
            }

            if (diff > 0) {
                if (diff < int32_t(config.receiveWindow) && early.size() < config.receiveWindow) {
                    early[h.ns] = std::vector<uint8_t>(bounded.data, bounded.data + bounded.size);
                }

                return;
            }

            ++nr;
            ackPending = true;
            process(h, bounded);

            // --> Messages that arrived early are now in order.
            while (state != EL2TS_CLOSED) {
                auto it = early.find(nr);
                if (it == early.end()) {
                    break;
                }

                std::vector<uint8_t> next = std::move(it->second);
                early.erase(it);
                SL2tpHeader nh;
                if (ParseL2tpHeader(BytesOf(next), nh) != SBOX_OK) {
                    break;
                }

                ++nr;
                ackPending = true;
                acknowledge(nh.nr);
                process(nh, BytesOf(next));
            }

            early.erase(early.begin(), early.lower_bound(nr));
            if (ackPending && state != EL2TS_CLOSED) {
                sendZlb();
            }
        }

        /* Timers. */
        void tick(int64_t nowMs) {
            now = nowMs > now ? nowMs : now;
            if (state == EL2TS_CLOSED) {
                return;
            }

            if (state == EL2TS_CLOSING && now >= closeAt) {
                finish("closed");
                return;
            }

            for (Outgoing& o : queue) {
                if (!o.sent || now < o.nextSend) {
                    continue;
                }

                if (o.tries >= config.retransmitTries) {
                    logf(L2tpMessageName(o.type) + " not acknowledged, peer is gone");
                    if (state != EL2TS_CLOSING) {
                        closeReason = "peer not responding";
                    }

                    finish("peer not responding");
                    return;
                }

                ++o.tries;
                int64_t delay = int64_t(config.retransmitMs) << std::min<uint32_t>(o.tries, 8);
                o.nextSend = now + std::min<int64_t>(delay, config.retransmitCapMs);
                ipsec::SetBe16(o.packet.data() + 10, nr);
                transmit(o.packet);
            }

            if (state == EL2TS_ESTABLISHED && config.helloSeconds && queue.empty() && now - lastRx >= int64_t(config.helloSeconds) * 1000) {
                lastRx = now;
                sendControl(0, {}, EL2TP_HELLO);
            }

            // --> Unfinished setups do not linger forever.
            if ((state == EL2TS_WAIT_CONNECT || state == EL2TS_WAIT_REPLY) && queue.empty() && now - lastRx > 30000) {
                finish("setup timed out");
            }
        }
    };

    CL2tpTunnel::CL2tpTunnel(SL2tpTunnelConfig config, bool lns, uint16_t localId) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
        if (_state->config.receiveWindow == 0) {
            _state->config.receiveWindow = 1;
        }

        _state->lns = lns;
        _state->localId = localId;
        _state->lastRx = _state->clock();
    }

    CL2tpTunnel::~CL2tpTunnel() = default;

    /* Send function. */
    void CL2tpTunnel::sender(std::function<void(const SReadOnlyByteSpan&)> send) {
        _state->send = std::move(send);
    }

    /* Log sink. */
    void CL2tpTunnel::logger(std::function<void(const std::string&)> log) {
        _state->log = std::move(log);
    }

    /* Established handler. */
    void CL2tpTunnel::onEstablished(std::function<void()> handler) {
        _state->established = std::move(handler);
    }

    /* Session up handler. */
    void CL2tpTunnel::onSessionUp(std::function<void(uint16_t)> handler) {
        _state->sessionUp = std::move(handler);
    }

    /* Session data handler. */
    void CL2tpTunnel::onSessionData(std::function<void(uint16_t, const SReadOnlyByteSpan&)> handler) {
        _state->sessionData = std::move(handler);
    }

    /* Session down handler. */
    void CL2tpTunnel::onSessionDown(std::function<void(uint16_t, const std::string&)> handler) {
        _state->sessionDown = std::move(handler);
    }

    /* Closed handler. */
    void CL2tpTunnel::onClosed(std::function<void(const std::string&)> handler) {
        _state->closed = std::move(handler);
    }

    /* Packet input. */
    void CL2tpTunnel::input(const SReadOnlyByteSpan& packet) {
        std::shared_ptr<SState> keep = _state;
        keep->input(packet);
    }

    /* Timers. */
    void CL2tpTunnel::tick(int64_t nowMs) {
        std::shared_ptr<SState> keep = _state;
        keep->tick(nowMs);
    }

    /* LAC start. */
    void CL2tpTunnel::start() {
        std::shared_ptr<SState> keep = _state;
        if (keep->lns || keep->state != EL2TS_IDLE) {
            return;
        }

        keep->clock();
        keep->lastRx = keep->now;
        std::vector<SL2tpAvp> avps = keep->setupAvps();
        if (!keep->config.secret.empty()) {
            keep->ourChallenge.resize(16);
            IkeRandom(SByteSpan(keep->ourChallenge.data(), keep->ourChallenge.size()));
            avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_CHALLENGE, BytesOf(keep->ourChallenge)));
        }

        keep->state = EL2TS_WAIT_REPLY;
        keep->sendControl(0, avps, EL2TP_SCCRQ);
    }

    /* LAC incoming call. */
    uint16_t CL2tpTunnel::openSession() {
        std::shared_ptr<SState> keep = _state;
        if (keep->lns || keep->state != EL2TS_ESTABLISHED) {
            return 0;
        }

        Session s;
        s.localId = keep->newSessionId();
        if (!s.localId) {
            return 0;
        }

        s.state = SS_WAIT_ICRP;
        keep->sessions[s.localId] = s;
        std::vector<SL2tpAvp> avps;
        avps.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_SESSION_ID, s.localId));
        avps.push_back(SL2tpAvp::of32(EL2TP_AVP_CALL_SERIAL_NUMBER, keep->callSerial++));
        avps.push_back(SL2tpAvp::of32(EL2TP_AVP_BEARER_TYPE, 0, false));
        keep->sendControl(0, avps, EL2TP_ICRQ);
        return s.localId;
    }

    /* Data. */
    int32_t CL2tpTunnel::sendData(uint16_t sessionId, const SReadOnlyByteSpan& ppp) {
        auto it = _state->sessions.find(sessionId);
        if (it == _state->sessions.end()) {
            return -ENOENT;
        }

        Session& s = it->second;
        if (s.state != SS_ESTABLISHED || _state->state != EL2TS_ESTABLISHED) {
            return -ENOTCONN;
        }

        std::vector<uint8_t> packet = BuildL2tpData(_state->peerId, s.peerId, ppp, s.sequencing, s.dataNs, s.dataNr);
        if (s.sequencing) {
            ++s.dataNs;
        }

        _state->transmit(packet);
        return SBOX_OK;
    }

    /* Session clear. */
    void CL2tpTunnel::closeSession(uint16_t sessionId, uint16_t result, const std::string& message) {
        std::shared_ptr<SState> keep = _state;
        if (keep->sessions.count(sessionId) && keep->state == EL2TS_ESTABLISHED) {
            keep->cdn(sessionId, result, message);
        }
    }

    /* Tunnel clear. */
    void CL2tpTunnel::close(uint16_t result, const std::string& message) {
        std::shared_ptr<SState> keep = _state;
        keep->clock();
        if (keep->state == EL2TS_IDLE || keep->peerId == 0) {
            keep->finish(message.empty() ? "closed" : message);
            return;
        }

        keep->stop(result, 0, message);
    }

    /* Our tunnel ID. */
    uint16_t CL2tpTunnel::localId() const noexcept {
        return _state->localId;
    }

    /* Peer tunnel ID. */
    uint16_t CL2tpTunnel::peerId() const noexcept {
        return _state->peerId;
    }

    /* State. */
    EL2tpTunnelState CL2tpTunnel::state() const noexcept {
        return _state->state;
    }

    /* Peer host name. */
    std::string CL2tpTunnel::peerHostName() const {
        return _state->peerHost;
    }

    /* Established sessions. */
    size_t CL2tpTunnel::sessionCount() const noexcept {
        size_t n = 0;
        for (const auto& [id, s] : _state->sessions) {
            (void)id;
            n += s.state == SS_ESTABLISHED ? 1 : 0;
        }

        return n;
    }

    /* Peer session ID. */
    uint16_t CL2tpTunnel::peerSessionId(uint16_t sessionId) const noexcept {
        auto it = _state->sessions.find(sessionId);
        return it != _state->sessions.end() ? it->second.peerId : 0;
    }

}
}
