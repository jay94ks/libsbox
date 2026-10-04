#include <sbox/vpn/l2tp/ppp.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include "ipsec/crypto.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using ipsec::GetBe16;
    using ipsec::GetBe32;
    using ipsec::PutBe16;
    using ipsec::PutBe32;

    /* Auth names. */
    const char* PppAuthName(EPppAuth auth) noexcept {
        switch (auth) {
        case EPPPA_PAP: return "PAP";
        case EPPPA_CHAP_MD5: return "CHAP-MD5";
        case EPPPA_MSCHAPV2: return "MS-CHAPv2";
        default: return "none";
        }
    }

    /* Auth parser. */
    bool ParsePppAuth(std::string_view text, EPppAuth& out) noexcept {
        std::string t;
        for (char c : text) {
            if (c != '-' && c != '_') {
                t.push_back(char(c >= 'A' && c <= 'Z' ? c + 32 : c));
            }
        }

        if (t == "mschapv2" || t == "mschap2") {
            out = EPPPA_MSCHAPV2;
        }
        else if (t == "chap" || t == "chapmd5" || t == "md5") {
            out = EPPPA_CHAP_MD5;
        }
        else if (t == "pap") {
            out = EPPPA_PAP;
        }
        else {
            return false;
        }

        return true;
    }

    namespace {

        // --> Packet codes shared by LCP and the NCPs.
        enum Code : uint8_t {
            CONF_REQ = 1,
            CONF_ACK = 2,
            CONF_NAK = 3,
            CONF_REJ = 4,
            TERM_REQ = 5,
            TERM_ACK = 6,
            CODE_REJ = 7,
            PROT_REJ = 8,
            ECHO_REQ = 9,
            ECHO_REP = 10,
            DISCARD_REQ = 11,
            IDENTIFICATION = 12,
            TIME_REMAINING = 13,
        };

        // --> LCP options.
        enum LcpOption : uint8_t {
            LCP_MRU = 1,
            LCP_ACCM = 2,
            LCP_AUTH = 3,
            LCP_QUALITY = 4,
            LCP_MAGIC = 5,
            LCP_PFC = 7,
            LCP_ACFC = 8,
        };

        // --> IPCP options.
        enum IpcpOption : uint8_t {
            IPCP_ADDRESSES = 1,
            IPCP_COMPRESSION = 2,
            IPCP_ADDRESS = 3,
            IPCP_DNS1 = 129,
            IPCP_NBNS1 = 130,
            IPCP_DNS2 = 131,
            IPCP_NBNS2 = 132,
        };

        const uint8_t CHAP_MD5 = 5;
        const uint8_t CHAP_MSV2 = 0x81;

        enum FsmState {
            FS_INITIAL = 0,
            FS_REQ_SENT,
            FS_ACK_RCVD,
            FS_ACK_SENT,
            FS_OPENED,
            FS_CLOSING,
            FS_CLOSED,
        };

        enum Phase {
            PH_DEAD = 0,
            PH_ESTABLISH,
            PH_AUTHENTICATE,
            PH_NETWORK,
            PH_TERMINATE,
        };

        struct Option {
            uint8_t type = 0;
            std::vector<uint8_t> data;
        };

        /* Parses an option list. */
        bool parseOptions(const SReadOnlyByteSpan& data, std::vector<Option>& out) {
            out.clear();
            size_t at = 0;
            while (at < data.size) {
                if (data.size - at < 2) {
                    return false;
                }

                size_t len = data.data[at + 1];
                if (len < 2 || len > data.size - at) {
                    return false;
                }

                Option o;
                o.type = data.data[at];
                o.data.assign(data.data + at + 2, data.data + at + len);
                out.push_back(std::move(o));
                at += len;
                if (out.size() > 64) {
                    return false;
                }
            }

            return true;
        }

        /* Encodes an option list. */
        std::vector<uint8_t> encodeOptions(const std::vector<Option>& opts) {
            std::vector<uint8_t> out;
            for (const Option& o : opts) {
                out.push_back(o.type);
                out.push_back(uint8_t(o.data.size() + 2));
                out.insert(out.end(), o.data.begin(), o.data.end());
            }

            return out;
        }

        /* Option with an address value. */
        Option addressOption(uint8_t type, const net::SIpAddress& a) {
            Option o;
            o.type = type;
            if (a.isV4()) {
                o.data.assign(a.bytes, a.bytes + 4);
            }
            else {
                o.data.assign(4, 0);
            }

            return o;
        }

        /* Address of a 4-byte option. */
        net::SIpAddress optionAddress(const Option& o) {
            net::SIpAddress a;
            if (o.data.size() == 4) {
                net::SIpAddress::fromBytes(o.data.data(), 4, a);
            }

            return a;
        }

        /* Upper-case hex. */
        std::string hexUpper(const SReadOnlyByteSpan& b) {
            return ipsec::ToHex(b, true);
        }

        /* Case-insensitive equality. */
        bool equalsIgnoreCase(std::string_view a, std::string_view b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                char x = a[i] >= 'A' && a[i] <= 'Z' ? char(a[i] + 32) : a[i];
                char y = b[i] >= 'A' && b[i] <= 'Z' ? char(b[i] + 32) : b[i];
                if (x != y) {
                    return false;
                }
            }

            return true;
        }

        /**
         * Option negotiation automaton of one protocol (RFC 1661 4).
         */
        struct Fsm {
            uint16_t protocol = 0;
            int state = FS_INITIAL;
            uint8_t nextId = 1;
            uint8_t reqId = 0;
            uint32_t restart = 0;
            int64_t timer = 0;
            uint32_t naksSent = 0;
            uint32_t naksReceived = 0;
            std::vector<uint8_t> lastAcked;     // --> Id and options of the last request we acked.
        };

    }

    struct CPppSession::SState {
        SPppConfig config;
        int phase = PH_DEAD;
        Fsm lcp;
        Fsm ipcp;
        int64_t now = 0;
        int64_t started = 0;
        int64_t lastRx = 0;

        // -- LCP: our options.
        uint16_t ourMru = 1500;
        bool mruRejected = false;
        uint32_t magic = 0;
        bool magicRejected = false;
        EPppAuth authProposal = EPPPA_NONE;     // --> Server: the method we ask for.
        std::vector<EPppAuth> authTried;
        // -- LCP: the peer's.
        uint16_t peerMru = 1500;
        uint32_t peerMagic = 0;
        EPppAuth authAgreed = EPPPA_NONE;       // --> Client: what we accepted.

        // -- Authentication.
        EPppAuth authMethod = EPPPA_NONE;
        std::vector<uint8_t> challenge;
        uint8_t authId = 0;
        uint32_t authTries = 0;
        int64_t authTimer = 0;
        bool authDone = false;
        std::string authUser;
        std::string fixedAddress;
        std::vector<uint8_t> peerChallenge;     // --> Client MS-CHAPv2.
        std::vector<uint8_t> ntResponse;
        std::vector<uint8_t> lastAuthPacket;    // --> Client: retransmitted PAP request.

        // -- IPCP.
        net::SIpAddress local;
        net::SIpAddress peer;
        std::vector<net::SIpAddress> dns;       // --> Client: received DNS servers.
        bool dns1Rejected = false;
        bool dns2Rejected = false;

        // -- Keepalive and termination.
        uint32_t echoOutstanding = 0;
        int64_t echoNext = 0;
        int64_t terminateTimer = 0;
        uint32_t terminateTries = 0;
        std::string downReason;
        bool upNotified = false;
        bool downNotified = false;

        std::function<void(const SReadOnlyByteSpan&)> send;
        std::function<void(const std::string&)> log;
        FPppAllocate allocate;
        std::function<void(const SPppInfo&)> up;
        std::function<void(const std::string&)> down;
        std::function<void(const SReadOnlyByteSpan&)> ip;

        /* Current time. */
        int64_t clock() {
            int64_t t = CEventLoop::nowMs();
            now = t > now ? t : now;
            return now;
        }

        /* Logs. */
        void logf(const std::string& m) {
            if (log) {
                log(std::string("ppp") + (config.server ? "" : "-client") + ": " + m);
            }
        }

        /* Sends a frame with address/control and a 2-byte protocol. */
        void sendFrame(uint16_t protocol, const std::vector<uint8_t>& payload) {
            std::vector<uint8_t> frame;
            frame.reserve(payload.size() + 4);
            frame.push_back(0xff);
            frame.push_back(0x03);
            PutBe16(frame, protocol);
            frame.insert(frame.end(), payload.begin(), payload.end());
            if (send) {
                send(BytesOf(frame));
            }
        }

        /* Sends a code/id/length packet. */
        void sendPacket(uint16_t protocol, uint8_t code, uint8_t id, const std::vector<uint8_t>& data) {
            std::vector<uint8_t> p;
            p.push_back(code);
            p.push_back(id);
            PutBe16(p, uint32_t(data.size() + 4));
            p.insert(p.end(), data.begin(), data.end());
            sendFrame(protocol, p);
        }

        /* Ends the link once. */
        void finish(const std::string& reason) {
            if (phase == PH_DEAD && downNotified) {
                return;
            }

            phase = PH_DEAD;
            lcp.state = FS_CLOSED;
            ipcp.state = FS_CLOSED;
            if (!downNotified) {
                downNotified = true;
                downReason = reason;
                logf("link down: " + reason);
                if (down) {
                    down(reason);
                }
            }
        }

        /* Starts termination (LCP Terminate-Request). */
        void terminate(const std::string& reason) {
            if (phase == PH_DEAD || phase == PH_TERMINATE) {
                return;
            }

            downReason = reason;
            phase = PH_TERMINATE;
            ipcp.state = FS_CLOSED;
            lcp.state = FS_CLOSING;
            terminateTries = 1;
            terminateTimer = clock() + config.restartMs;
            std::vector<uint8_t> msg(reason.begin(), reason.end());
            sendPacket(EPPP_LCP, TERM_REQ, lcp.nextId++, msg);
        }

        // -------------------------------------------------------------------------------
        // Generic option negotiation

        /* Our Configure-Request options. */
        std::vector<Option> ourOptions(Fsm& f) {
            std::vector<Option> opts;
            if (f.protocol == EPPP_LCP) {
                if (!mruRejected && ourMru != 1500) {
                    Option o;
                    o.type = LCP_MRU;
                    PutBe16(o.data, ourMru);
                    opts.push_back(o);
                }

                if (config.server && authProposal != EPPPA_NONE) {
                    Option o;
                    o.type = LCP_AUTH;
                    if (authProposal == EPPPA_PAP) {
                        PutBe16(o.data, EPPP_PAP);
                    }
                    else {
                        PutBe16(o.data, EPPP_CHAP);
                        o.data.push_back(authProposal == EPPPA_MSCHAPV2 ? CHAP_MSV2 : CHAP_MD5);
                    }

                    opts.push_back(o);
                }

                if (!magicRejected) {
                    Option o;
                    o.type = LCP_MAGIC;
                    PutBe32(o.data, magic);
                    opts.push_back(o);
                }
            }
            else {
                if (config.server) {
                    opts.push_back(addressOption(IPCP_ADDRESS, local));
                }
                else {
                    opts.push_back(addressOption(IPCP_ADDRESS, local));
                    if (!dns1Rejected) {
                        opts.push_back(addressOption(IPCP_DNS1, dns.size() > 0 ? dns[0] : net::SIpAddress()));
                    }

                    if (!dns2Rejected) {
                        opts.push_back(addressOption(IPCP_DNS2, dns.size() > 1 ? dns[1] : net::SIpAddress()));
                    }
                }
            }

            return opts;
        }

        /* Sends a Configure-Request (`again`: a retransmission keeps the identifier). */
        void sendRequest(Fsm& f, bool again = false) {
            if (!again) {
                f.reqId = f.nextId++;
            }

            f.timer = clock() + config.restartMs;
            sendPacket(f.protocol, CONF_REQ, f.reqId, encodeOptions(ourOptions(f)));
        }

        /* Opens an automaton. */
        void open(Fsm& f) {
            f.state = FS_REQ_SENT;
            f.restart = config.maxConfigure;
            f.naksSent = 0;
            f.naksReceived = 0;
            sendRequest(f);
        }

        /* Classifies the peer's request; fills the reply lists. */
        void checkRequest(Fsm& f, const std::vector<Option>& opts, std::vector<Option>& nak, std::vector<Option>& rej) {
            for (const Option& o : opts) {
                if (f.protocol == EPPP_LCP) {
                    checkLcpOption(o, nak, rej);
                }
                else {
                    checkIpcpOption(o, nak, rej);
                }
            }
        }

        /* One LCP option of the peer. */
        void checkLcpOption(const Option& o, std::vector<Option>& nak, std::vector<Option>& rej) {
            switch (o.type) {
            case LCP_MRU:
                if (o.data.size() != 2) {
                    rej.push_back(o);
                }
                else if (GetBe16(o.data.data()) < 128) {
                    Option n;
                    n.type = LCP_MRU;
                    PutBe16(n.data, 1500);
                    nak.push_back(n);
                }

                break;

            case LCP_ACCM:
                if (o.data.size() != 4) {
                    rej.push_back(o);
                }

                break;

            case LCP_MAGIC:
                if (o.data.size() != 4) {
                    rej.push_back(o);
                }
                else if (!magicRejected && GetBe32(o.data.data()) == magic && magic != 0) {
                    // --> Looped back link (or a collision): suggest another number.
                    Option n;
                    n.type = LCP_MAGIC;
                    uint32_t v = 0;
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&v), sizeof(v)));
                    PutBe32(n.data, v | 1);
                    nak.push_back(n);
                }

                break;

            case LCP_PFC:
            case LCP_ACFC:
                if (!o.data.empty()) {
                    rej.push_back(o);
                }

                break;

            case LCP_AUTH: {
                if (config.server) {
                    // --> We never authenticate ourselves to the client.
                    rej.push_back(o);
                    break;
                }

                EPppAuth want = EPPPA_NONE;
                if (o.data.size() == 2 && GetBe16(o.data.data()) == EPPP_PAP) {
                    want = EPPPA_PAP;
                }
                else if (o.data.size() == 3 && GetBe16(o.data.data()) == EPPP_CHAP) {
                    want = o.data[2] == CHAP_MSV2 ? EPPPA_MSCHAPV2 : (o.data[2] == CHAP_MD5 ? EPPPA_CHAP_MD5 : EPPPA_NONE);
                }

                if (want != EPPPA_NONE && std::find(config.auth.begin(), config.auth.end(), want) != config.auth.end()) {
                    authAgreed = want;
                    break;
                }

                // --> Suggest the first method we accept.
                if (config.auth.empty()) {
                    rej.push_back(o);
                    break;
                }

                Option n;
                n.type = LCP_AUTH;
                if (config.auth[0] == EPPPA_PAP) {
                    PutBe16(n.data, EPPP_PAP);
                }
                else {
                    PutBe16(n.data, EPPP_CHAP);
                    n.data.push_back(config.auth[0] == EPPPA_MSCHAPV2 ? CHAP_MSV2 : CHAP_MD5);
                }

                nak.push_back(n);
                break;
            }

            default:
                // --> Callback, multilink (MRRU, endpoint discriminator), quality protocol, ...
                rej.push_back(o);
                break;
            }
        }

        /* One IPCP option of the peer. */
        void checkIpcpOption(const Option& o, std::vector<Option>& nak, std::vector<Option>& rej) {
            if (!config.server) {
                if (o.type == IPCP_ADDRESS && o.data.size() == 4) {
                    peer = optionAddress(o);
                    return;
                }

                rej.push_back(o);
                return;
            }

            const std::vector<net::SIpAddress>* list = nullptr;
            size_t index = 0;
            switch (o.type) {
            case IPCP_ADDRESS:
                if (o.data.size() != 4) {
                    rej.push_back(o);
                }
                else if (optionAddress(o) != peer) {
                    nak.push_back(addressOption(IPCP_ADDRESS, peer));
                }

                return;

            case IPCP_DNS1: list = &config.dns; index = 0; break;
            case IPCP_DNS2: list = &config.dns; index = 1; break;
            case IPCP_NBNS1: list = &config.nbns; index = 0; break;
            case IPCP_NBNS2: list = &config.nbns; index = 1; break;
            default:
                rej.push_back(o);
                return;
            }

            if (o.data.size() != 4 || list->size() <= index || !(*list)[index].isV4()) {
                rej.push_back(o);
                return;
            }

            if (optionAddress(o) != (*list)[index]) {
                nak.push_back(addressOption(o.type, (*list)[index]));
            }
        }

        /* Applies the peer's Nak to our options. */
        void applyNak(Fsm& f, const std::vector<Option>& opts) {
            for (const Option& o : opts) {
                if (f.protocol == EPPP_LCP) {
                    if (o.type == LCP_MRU && o.data.size() == 2) {
                        uint16_t v = GetBe16(o.data.data());
                        ourMru = v >= 576 && v < ourMru ? v : ourMru;
                    }
                    else if (o.type == LCP_MAGIC) {
                        IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&magic), sizeof(magic)));
                        magic |= 1;
                    }
                    else if (o.type == LCP_AUTH && config.server) {
                        EPppAuth suggested = EPPPA_NONE;
                        if (o.data.size() >= 2 && GetBe16(o.data.data()) == EPPP_PAP) {
                            suggested = EPPPA_PAP;
                        }
                        else if (o.data.size() >= 3 && GetBe16(o.data.data()) == EPPP_CHAP) {
                            suggested = o.data[2] == CHAP_MSV2 ? EPPPA_MSCHAPV2 : (o.data[2] == CHAP_MD5 ? EPPPA_CHAP_MD5 : EPPPA_NONE);
                        }

                        nextAuth(suggested);
                    }
                }
                else if (!config.server) {
                    net::SIpAddress a = optionAddress(o);
                    if (o.type == IPCP_ADDRESS && a.isValid()) {
                        local = a;
                    }
                    else if (o.type == IPCP_DNS1 && a.isValid()) {
                        if (dns.empty()) {
                            dns.resize(1);
                        }

                        dns[0] = a;
                    }
                    else if (o.type == IPCP_DNS2 && a.isValid()) {
                        if (dns.size() < 2) {
                            dns.resize(2);
                        }

                        dns[1] = a;
                    }
                }
            }
        }

        /* Picks the next authentication method after a Nak/Reject. */
        void nextAuth(EPppAuth suggested) {
            authTried.push_back(authProposal);
            if (suggested != EPPPA_NONE && std::find(config.auth.begin(), config.auth.end(), suggested) != config.auth.end() &&
                std::find(authTried.begin(), authTried.end(), suggested) == authTried.end()) {
                authProposal = suggested;
                return;
            }

            for (EPppAuth a : config.auth) {
                if (std::find(authTried.begin(), authTried.end(), a) == authTried.end()) {
                    authProposal = a;
                    return;
                }
            }

            authProposal = EPPPA_NONE;
        }

        /* Applies the peer's Reject to our options; false when the link cannot continue. */
        bool applyReject(Fsm& f, const std::vector<Option>& opts) {
            for (const Option& o : opts) {
                if (f.protocol == EPPP_LCP) {
                    if (o.type == LCP_MRU) {
                        mruRejected = true;
                    }
                    else if (o.type == LCP_MAGIC) {
                        magicRejected = true;
                    }
                    else if (o.type == LCP_AUTH && config.server) {
                        nextAuth(EPPPA_NONE);
                        if (authProposal == EPPPA_NONE) {
                            return false;
                        }
                    }
                }
                else if (!config.server) {
                    if (o.type == IPCP_DNS1) {
                        dns1Rejected = true;
                    }
                    else if (o.type == IPCP_DNS2) {
                        dns2Rejected = true;
                    }
                    else if (o.type == IPCP_ADDRESS) {
                        return false;
                    }
                }
                else if (o.type == IPCP_ADDRESS) {
                    return false;
                }
            }

            return true;
        }

        /* This-Layer-Up. */
        void layerUp(Fsm& f) {
            if (f.protocol == EPPP_LCP) {
                logf("LCP open (mru " + std::to_string(peerMru) + ")");
                echoNext = now + int64_t(config.echoSeconds) * 1000;
                beginAuth();
            }
            else {
                if (!config.server && !local.isValid()) {
                    terminate("no address assigned");
                    return;
                }

                logf("IPCP open: local " + local.toString() + ", peer " + peer.toString());
                if (!upNotified) {
                    upNotified = true;
                    if (up) {
                        up(snapshot());
                    }
                }
            }
        }

        /* Handles a Configure-* packet of an automaton. */
        void onConfigure(Fsm& f, uint8_t code, uint8_t id, const SReadOnlyByteSpan& data) {
            if (f.state == FS_INITIAL || f.state == FS_CLOSED || f.state == FS_CLOSING) {
                if (code == CONF_REQ && f.state == FS_CLOSED && f.protocol != EPPP_LCP) {
                    sendPacket(f.protocol, TERM_ACK, id, {});
                }

                return;
            }

            std::vector<Option> opts;
            if (!parseOptions(data, opts)) {
                return;
            }

            if (code == CONF_REQ) {
                std::vector<uint8_t> signature;
                signature.push_back(id);
                signature.insert(signature.end(), data.data, data.data + data.size);
                if (f.state == FS_OPENED && signature == f.lastAcked) {
                    // --> A retransmission whose Ack was lost: acknowledge again instead of
                    // renegotiating (which would bounce the link on every lost Ack).
                    sendPacket(f.protocol, CONF_ACK, id, std::vector<uint8_t>(data.data, data.data + data.size));
                    return;
                }

                if (f.protocol == EPPP_LCP) {
                    for (const Option& o : opts) {
                        if (o.type == LCP_MRU && o.data.size() == 2) {
                            peerMru = GetBe16(o.data.data());
                        }
                        else if (o.type == LCP_MAGIC && o.data.size() == 4) {
                            peerMagic = GetBe32(o.data.data());
                        }
                    }
                }

                std::vector<Option> nak;
                std::vector<Option> rej;
                checkRequest(f, opts, nak, rej);
                if (!rej.empty()) {
                    sendPacket(f.protocol, CONF_REJ, id, encodeOptions(rej));
                }
                else if (!nak.empty()) {
                    if (++f.naksSent > config.maxFailure) {
                        // --> RFC 1661: after Max-Failure, Naks become Rejects.
                        sendPacket(f.protocol, CONF_REJ, id, encodeOptions(nak));
                    }
                    else {
                        sendPacket(f.protocol, CONF_NAK, id, encodeOptions(nak));
                    }
                }
                else {
                    f.lastAcked = signature;
                    sendPacket(f.protocol, CONF_ACK, id, encodeOptions(opts));
                    if (f.state == FS_ACK_RCVD) {
                        f.state = FS_OPENED;
                        layerUp(f);
                    }
                    else if (f.state == FS_OPENED) {
                        // --> Renegotiation: the layer goes down and comes back.
                        f.state = FS_ACK_SENT;
                        sendRequest(f);
                    }
                    else {
                        f.state = FS_ACK_SENT;
                    }

                    return;
                }

                if (f.state == FS_ACK_SENT) {
                    f.state = FS_REQ_SENT;
                }
                else if (f.state == FS_OPENED) {
                    f.state = FS_REQ_SENT;
                    sendRequest(f);
                }

                return;
            }

            if (id != f.reqId) {
                return;     // --> Stale or bogus reply.
            }

            if (code == CONF_ACK) {
                if (f.state == FS_REQ_SENT) {
                    f.state = FS_ACK_RCVD;
                    f.restart = config.maxConfigure;
                    f.timer = now + config.restartMs;
                }
                else if (f.state == FS_ACK_SENT) {
                    f.state = FS_OPENED;
                    f.restart = config.maxConfigure;
                    layerUp(f);
                }
                else if (f.state == FS_ACK_RCVD || f.state == FS_OPENED) {
                    f.state = FS_REQ_SENT;
                    sendRequest(f);
                }

                return;
            }

            // --> Nak or Reject.
            if (++f.naksReceived > config.maxFailure * 2) {
                terminate(std::string(f.protocol == EPPP_LCP ? "LCP" : "IPCP") + " negotiation does not converge");
                return;
            }

            if (code == CONF_NAK) {
                applyNak(f, opts);
                if (f.protocol == EPPP_LCP && config.server && authProposal == EPPPA_NONE) {
                    terminate("no common authentication protocol");
                    return;
                }
            }
            else if (!applyReject(f, opts)) {
                terminate(f.protocol == EPPP_LCP ? "peer refuses to authenticate" : "peer rejects IP address negotiation");
                return;
            }

            if (f.state == FS_OPENED || f.state == FS_ACK_RCVD) {
                f.state = FS_REQ_SENT;
            }

            sendRequest(f);
        }

        // -------------------------------------------------------------------------------
        // Authentication

        /* Enters the authentication phase (or skips it). */
        void beginAuth() {
            phase = PH_AUTHENTICATE;
            authTries = 0;
            if (config.server) {
                authMethod = authProposal;
                if (authMethod == EPPPA_NONE) {
                    authDone = true;
                    beginNetwork();
                    return;
                }

                if (authMethod == EPPPA_CHAP_MD5 || authMethod == EPPPA_MSCHAPV2) {
                    sendChallenge();
                }
                else {
                    authTimer = now + int64_t(config.setupSeconds) * 1000;
                }

                return;
            }

            authMethod = authAgreed;
            if (authMethod == EPPPA_NONE) {
                beginNetwork();
                return;
            }

            if (authMethod == EPPPA_PAP) {
                std::vector<uint8_t> d;
                d.push_back(uint8_t(std::min<size_t>(config.user.size(), 255)));
                d.insert(d.end(), config.user.begin(), config.user.begin() + long(std::min<size_t>(config.user.size(), 255)));
                d.push_back(uint8_t(std::min<size_t>(config.password.size(), 255)));
                d.insert(d.end(), config.password.begin(), config.password.begin() + long(std::min<size_t>(config.password.size(), 255)));
                authId = lcp.nextId++;
                lastAuthPacket = d;
                authTimer = now + config.restartMs;
                sendPacket(EPPP_PAP, 1, authId, d);
            }
        }

        /* Server: sends a CHAP challenge. */
        void sendChallenge() {
            challenge.assign(16, 0);
            IkeRandom(SByteSpan(challenge.data(), challenge.size()));
            authId = uint8_t(authId + 1);
            std::vector<uint8_t> d;
            d.push_back(uint8_t(challenge.size()));
            d.insert(d.end(), challenge.begin(), challenge.end());
            d.insert(d.end(), config.name.begin(), config.name.end());
            authTimer = now + config.restartMs;
            sendPacket(EPPP_CHAP, 1, authId, d);
        }

        /* Finds an account. */
        const SPppUser* findUser(const std::string& name) {
            for (const SPppUser& u : config.users) {
                if (equalsIgnoreCase(u.name, name)) {
                    return &u;
                }
            }

            return nullptr;
        }

        /* Password hash of an account (empty on failure). */
        static std::vector<uint8_t> passwordHash(const SPppUser& u) {
            if (u.ntHash.size() == 16) {
                return u.ntHash;
            }

            std::vector<uint8_t> h(16);
            if (MsChapNtPasswordHash(u.password, SByteSpan(h.data(), h.size())) != SBOX_OK) {
                return {};
            }

            return h;
        }

        /* Authentication succeeded (server). */
        void authSucceeded(const SPppUser& u) {
            authDone = true;
            authUser = u.name;
            fixedAddress = u.address;
            logf("user '" + u.name + "' authenticated (" + PppAuthName(authMethod) + ")");
            if (!allocate || !allocate(u.name, u.address, peer) || !peer.isV4()) {
                logf("no address available for '" + u.name + "'");
                terminate("address pool exhausted");
                return;
            }

            beginNetwork();
        }

        /* PAP packets. */
        void onPap(uint8_t code, uint8_t id, const SReadOnlyByteSpan& data) {
            if (phase != PH_AUTHENTICATE || authMethod != EPPPA_PAP) {
                return;
            }

            if (config.server && code == 1) {
                if (authDone) {
                    // --> Our Ack was lost.
                    std::vector<uint8_t> msg = { 0 };
                    sendPacket(EPPP_PAP, 2, id, msg);
                    return;
                }

                if (data.size < 1 || data.size < size_t(1 + data[0] + 1)) {
                    return;
                }

                std::string user(reinterpret_cast<const char*>(data.data + 1), data[0]);
                size_t pwLen = data[1 + data[0]];
                if (data.size < 2 + data[0] + pwLen) {
                    return;
                }

                std::string pw(reinterpret_cast<const char*>(data.data + 2 + data[0]), pwLen);
                const SPppUser* u = findUser(MsChapUserName(user));
                bool ok = false;
                if (u) {
                    if (!u->password.empty()) {
                        ok = IkeSecureEquals(BytesOf(u->password), BytesOf(pw));
                    }
                    else if (u->ntHash.size() == 16) {
                        std::vector<uint8_t> h(16);
                        ok = MsChapNtPasswordHash(pw, SByteSpan(h.data(), h.size())) == SBOX_OK && IkeSecureEquals(BytesOf(h), BytesOf(u->ntHash));
                    }
                }

                if (!ok) {
                    std::string m = "Authentication failure";
                    std::vector<uint8_t> msg;
                    msg.push_back(uint8_t(m.size()));
                    msg.insert(msg.end(), m.begin(), m.end());
                    sendPacket(EPPP_PAP, 3, id, msg);
                    logf("PAP authentication failed for '" + user + "'");
                    terminate("authentication failed");
                    return;
                }

                std::string m = "Access granted";
                std::vector<uint8_t> msg;
                msg.push_back(uint8_t(m.size()));
                msg.insert(msg.end(), m.begin(), m.end());
                sendPacket(EPPP_PAP, 2, id, msg);
                authSucceeded(*u);
                return;
            }

            if (!config.server && id == authId) {
                if (code == 2) {
                    authDone = true;
                    beginNetwork();
                }
                else if (code == 3) {
                    terminate("PAP authentication rejected");
                }
            }
        }

        /* CHAP packets (MD5 and MS-CHAPv2). */
        void onChap(uint8_t code, uint8_t id, const SReadOnlyByteSpan& data) {
            if (phase != PH_AUTHENTICATE && !(phase == PH_NETWORK && config.server && code == 2)) {
                return;
            }

            if (authMethod != EPPPA_CHAP_MD5 && authMethod != EPPPA_MSCHAPV2) {
                return;
            }

            if (config.server) {
                if (code != 2 || id != authId) {
                    return;
                }

                if (authDone) {
                    // --> Our Success was lost: the peer repeats its Response.
                    if (!lastAuthPacket.empty()) {
                        sendPacket(EPPP_CHAP, 3, id, lastAuthPacket);
                    }

                    return;
                }

                if (data.size < 1 || data.size < size_t(1) + data[0]) {
                    return;
                }

                size_t valueSize = data[0];
                SReadOnlyByteSpan value(data.data + 1, valueSize);
                std::string name(reinterpret_cast<const char*>(data.data + 1 + valueSize), data.size - 1 - valueSize);
                std::string user = MsChapUserName(name);
                const SPppUser* u = findUser(user);

                if (authMethod == EPPPA_CHAP_MD5) {
                    bool ok = false;
                    if (u && valueSize == 16 && !u->password.empty()) {
                        uint8_t idByte = id;
                        std::vector<uint8_t> expect = ipsec::HashParts(certpp::crypto::EHASH_MD5, { SReadOnlyByteSpan(&idByte, 1), BytesOf(u->password),
                                                                                                    BytesOf(challenge) });
                        ok = IkeSecureEquals(BytesOf(expect), value);
                    }

                    if (!ok) {
                        std::string m = "Authentication failure";
                        sendPacket(EPPP_CHAP, 4, id, std::vector<uint8_t>(m.begin(), m.end()));
                        logf("CHAP-MD5 authentication failed for '" + name + "'");
                        terminate("authentication failed");
                        return;
                    }

                    std::string m = "Access granted";
                    lastAuthPacket.assign(m.begin(), m.end());
                    sendPacket(EPPP_CHAP, 3, id, lastAuthPacket);
                    authSucceeded(*u);
                    return;
                }

                // --> MS-CHAPv2 (RFC 2759 4): PeerChallenge(16) | Reserved(8) | NT-Response(24) | Flags(1).
                bool ok = false;
                std::string authResponse;
                if (u && valueSize == 49) {
                    std::vector<uint8_t> hash = passwordHash(*u);
                    SReadOnlyByteSpan peerChal(value.data, 16);
                    SReadOnlyByteSpan ntResp(value.data + 24, 24);
                    uint8_t expect[24];
                    if (hash.size() == 16 && MsChapNtResponse(BytesOf(challenge), peerChal, user, BytesOf(hash), SByteSpan(expect, 24)) == SBOX_OK &&
                        IkeSecureEquals(SReadOnlyByteSpan(expect, 24), ntResp)) {
                        authResponse = MsChapAuthenticatorResponse(BytesOf(hash), ntResp, peerChal, BytesOf(challenge), user);
                        ok = !authResponse.empty();
                    }

                    IkeWipe(hash);
                }

                if (!ok) {
                    std::vector<uint8_t> retry(16);
                    IkeRandom(SByteSpan(retry.data(), retry.size()));
                    std::string m = "E=691 R=0 C=" + hexUpper(BytesOf(retry)) + " V=3 M=Authentication failure";
                    sendPacket(EPPP_CHAP, 4, id, std::vector<uint8_t>(m.begin(), m.end()));
                    logf("MS-CHAPv2 authentication failed for '" + name + "'");
                    terminate("authentication failed");
                    return;
                }

                std::string m = authResponse + " M=Access granted";
                lastAuthPacket.assign(m.begin(), m.end());
                sendPacket(EPPP_CHAP, 3, id, lastAuthPacket);
                authSucceeded(*u);
                return;
            }

            // --> Client.
            if (code == 1) {
                if (data.size < 1 || data.size < size_t(1) + data[0]) {
                    return;
                }

                challenge.assign(data.data + 1, data.data + 1 + data[0]);
                authId = id;
                std::vector<uint8_t> resp;
                if (authMethod == EPPPA_CHAP_MD5) {
                    uint8_t idByte = id;
                    std::vector<uint8_t> v = ipsec::HashParts(certpp::crypto::EHASH_MD5, { SReadOnlyByteSpan(&idByte, 1), BytesOf(config.password),
                                                                                            BytesOf(challenge) });
                    resp.push_back(uint8_t(v.size()));
                    resp.insert(resp.end(), v.begin(), v.end());
                }
                else {
                    if (challenge.size() != 16) {
                        return;
                    }

                    std::vector<uint8_t> hash(16);
                    peerChallenge.assign(16, 0);
                    IkeRandom(SByteSpan(peerChallenge.data(), peerChallenge.size()));
                    ntResponse.assign(24, 0);
                    std::string user = MsChapUserName(config.user);
                    if (MsChapNtPasswordHash(config.password, SByteSpan(hash.data(), 16)) != SBOX_OK ||
                        MsChapNtResponse(BytesOf(challenge), BytesOf(peerChallenge), user, BytesOf(hash), SByteSpan(ntResponse.data(), 24)) !=
                            SBOX_OK) {
                        return;
                    }

                    IkeWipe(hash);
                    resp.push_back(49);
                    resp.insert(resp.end(), peerChallenge.begin(), peerChallenge.end());
                    resp.insert(resp.end(), 8, 0);
                    resp.insert(resp.end(), ntResponse.begin(), ntResponse.end());
                    resp.push_back(0);
                }

                resp.insert(resp.end(), config.user.begin(), config.user.end());
                // --> Kept for retransmission: a lost Success is recovered by repeating the Response.
                lastAuthPacket = resp;
                authTimer = now + config.restartMs;
                sendPacket(EPPP_CHAP, 2, id, resp);
                return;
            }

            if (id != authId) {
                return;
            }

            if (code == 3) {
                if (authMethod == EPPPA_MSCHAPV2) {
                    std::string msg(reinterpret_cast<const char*>(data.data), data.size);
                    std::vector<uint8_t> hash(16);
                    std::string user = MsChapUserName(config.user);
                    std::string expect;
                    if (MsChapNtPasswordHash(config.password, SByteSpan(hash.data(), 16)) == SBOX_OK) {
                        expect = MsChapAuthenticatorResponse(BytesOf(hash), BytesOf(ntResponse), BytesOf(peerChallenge), BytesOf(challenge), user);
                    }

                    IkeWipe(hash);
                    if (expect.empty() || msg.compare(0, expect.size(), expect) != 0) {
                        terminate("server failed MS-CHAPv2 mutual authentication");
                        return;
                    }
                }

                if (!authDone) {
                    authDone = true;
                    beginNetwork();
                }
            }
            else if (code == 4) {
                terminate("authentication rejected by server");
            }
        }

        // -------------------------------------------------------------------------------
        // Network phase and data

        /* Opens IPCP. */
        void beginNetwork() {
            if (phase == PH_NETWORK) {
                return;
            }

            phase = PH_NETWORK;
            if (config.server) {
                local = config.localAddress;
            }

            open(ipcp);
        }

        /* Sends LCP Protocol-Reject for an unsupported protocol. */
        void protocolReject(uint16_t protocol, const SReadOnlyByteSpan& info) {
            if (lcp.state != FS_OPENED) {
                return;
            }

            std::vector<uint8_t> d;
            PutBe16(d, protocol);
            size_t room = peerMru > 8 ? size_t(peerMru) - 8 : 0;
            size_t n = std::min(info.size, room);
            d.insert(d.end(), info.data, info.data + n);
            sendPacket(EPPP_LCP, PROT_REJ, lcp.nextId++, d);
        }

        /* LCP packets other than Configure-*. */
        void onLcp(uint8_t code, uint8_t id, const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& whole) {
            switch (code) {
            case CONF_REQ:
            case CONF_ACK:
            case CONF_NAK:
            case CONF_REJ:
                if (phase == PH_TERMINATE || phase == PH_DEAD) {
                    return;
                }

                if (lcp.state == FS_OPENED && code == CONF_REQ) {
                    std::vector<uint8_t> signature;
                    signature.push_back(id);
                    signature.insert(signature.end(), data.data, data.data + data.size);
                    if (signature != lcp.lastAcked) {
                        if (upNotified) {
                            // --> The owner already routes the address; a fresh link must start over.
                            terminate("LCP renegotiation on an established link");
                            return;
                        }

                        // --> LCP renegotiation drops the network layer.
                        ipcp.state = FS_INITIAL;
                        phase = PH_ESTABLISH;
                    }
                }

                onConfigure(lcp, code, id, data);
                return;

            case TERM_REQ:
                sendPacket(EPPP_LCP, TERM_ACK, id, {});
                if (phase == PH_TERMINATE) {
                    finish(downReason.empty() ? "terminated" : downReason);
                    return;
                }

                finish("peer terminated the link" + (data.size ? " (" + std::string(reinterpret_cast<const char*>(data.data), data.size) + ")" : std::string()));
                return;

            case TERM_ACK:
                if (phase == PH_TERMINATE) {
                    finish(downReason.empty() ? "terminated" : downReason);
                }

                return;

            case ECHO_REQ:
                if (lcp.state == FS_OPENED) {
                    std::vector<uint8_t> d;
                    PutBe32(d, magicRejected ? 0 : magic);
                    if (data.size > 4) {
                        d.insert(d.end(), data.data + 4, data.data + data.size);
                    }

                    sendPacket(EPPP_LCP, ECHO_REP, id, d);
                }

                return;

            case ECHO_REP:
                echoOutstanding = 0;
                return;

            case CODE_REJ:
            case PROT_REJ:
                if (code == PROT_REJ && data.size >= 2 && GetBe16(data.data) == EPPP_IPCP) {
                    terminate("peer rejects IPCP");
                }

                return;

            case DISCARD_REQ:
            case IDENTIFICATION:
            case TIME_REMAINING:
                return;

            default:
                if (lcp.state == FS_OPENED) {
                    std::vector<uint8_t> d(whole.data, whole.data + std::min<size_t>(whole.size, peerMru > 4 ? size_t(peerMru) - 4 : 0));
                    sendPacket(EPPP_LCP, CODE_REJ, lcp.nextId++, d);
                }

                return;
            }
        }

        /* One frame. */
        void input(const SReadOnlyByteSpan& frame) {
            clock();
            if (phase == PH_DEAD) {
                return;
            }

            SReadOnlyByteSpan f = frame;
            if (f.size >= 2 && f[0] == 0xff && f[1] == 0x03) {
                f = f.slice(2);
            }

            if (f.size < 1) {
                return;
            }

            uint16_t protocol;
            if (f[0] & 1) {
                protocol = f[0];
                f = f.slice(1);
            }
            else {
                if (f.size < 2) {
                    return;
                }

                protocol = GetBe16(f.data);
                f = f.slice(2);
            }

            lastRx = now;
            echoOutstanding = 0;

            if (protocol == EPPP_IP) {
                if (phase == PH_NETWORK && ipcp.state == FS_OPENED && f.size >= 20 && (f[0] >> 4) == 4) {
                    net::SIpAddress src;
                    net::SIpAddress::fromBytes(f.data + 12, 4, src);
                    if (config.server && src != peer) {
                        return;     // --> Spoofed source address.
                    }

                    if (ip) {
                        ip(f);
                    }
                }

                return;
            }

            if (protocol == EPPP_IPV6) {
                return;
            }

            // --> Control protocols: code, id, length.
            if (f.size < 4) {
                return;
            }

            uint8_t code = f[0];
            uint8_t id = f[1];
            size_t length = GetBe16(f.data + 2);
            if (length < 4 || length > f.size) {
                return;
            }

            SReadOnlyByteSpan whole(f.data, length);
            SReadOnlyByteSpan data(f.data + 4, length - 4);
            switch (protocol) {
            case EPPP_LCP:
                onLcp(code, id, data, whole);
                break;

            case EPPP_PAP:
                onPap(code, id, data);
                break;

            case EPPP_CHAP:
                onChap(code, id, data);
                break;

            case EPPP_IPCP:
                if (phase != PH_NETWORK) {
                    return;     // --> RFC 1661: NCP packets before the network phase are discarded.
                }

                if (code >= CONF_REQ && code <= CONF_REJ) {
                    onConfigure(ipcp, code, id, data);
                }
                else if (code == TERM_REQ) {
                    sendPacket(EPPP_IPCP, TERM_ACK, id, {});
                    terminate("peer closed IPCP");
                }
                else if (code != TERM_ACK && code != CODE_REJ) {
                    sendPacket(EPPP_IPCP, CODE_REJ, ipcp.nextId++, std::vector<uint8_t>(whole.data, whole.data + whole.size));
                }

                break;

            default:
                // --> CCP (no MPPE over IPsec), IPv6CP and everything else.
                protocolReject(protocol, whole);
                break;
            }
        }

        /* Timers. */
        void tick(int64_t nowMs) {
            now = nowMs > now ? nowMs : now;
            if (phase == PH_DEAD) {
                return;
            }

            if (phase == PH_TERMINATE) {
                if (now >= terminateTimer) {
                    if (terminateTries >= config.maxTerminate) {
                        finish(downReason.empty() ? "terminated" : downReason);
                        return;
                    }

                    ++terminateTries;
                    terminateTimer = now + config.restartMs;
                    sendPacket(EPPP_LCP, TERM_REQ, lcp.nextId++, {});
                }

                return;
            }

            if (!upNotified && now - started > int64_t(config.setupSeconds) * 1000) {
                terminate("link setup timed out");
                return;
            }

            for (Fsm* f : { &lcp, &ipcp }) {
                if ((f->state == FS_REQ_SENT || f->state == FS_ACK_SENT || f->state == FS_ACK_RCVD) && now >= f->timer) {
                    if (f->restart == 0) {
                        terminate(std::string(f->protocol == EPPP_LCP ? "LCP" : "IPCP") + " negotiation timed out");
                        return;
                    }

                    --f->restart;
                    if (f->state == FS_ACK_RCVD) {
                        f->state = FS_REQ_SENT;
                    }

                    sendRequest(*f, true);
                }
            }

            if (phase == PH_AUTHENTICATE && now >= authTimer && authTimer) {
                if (++authTries > config.maxConfigure) {
                    terminate("authentication timed out");
                    return;
                }

                if (config.server && (authMethod == EPPPA_CHAP_MD5 || authMethod == EPPPA_MSCHAPV2) && !authDone) {
                    sendChallenge();
                }
                else if (!config.server && authMethod == EPPPA_PAP && !authDone) {
                    authTimer = now + config.restartMs;
                    sendPacket(EPPP_PAP, 1, authId, lastAuthPacket);
                }
                else if (!config.server && !authDone && !lastAuthPacket.empty()) {
                    authTimer = now + config.restartMs;
                    sendPacket(EPPP_CHAP, 2, authId, lastAuthPacket);
                }
                else if (config.server && authMethod == EPPPA_PAP) {
                    terminate("no PAP request");
                    return;
                }
                else {
                    authTimer = 0;
                }
            }

            if (config.echoSeconds && lcp.state == FS_OPENED && now >= echoNext) {
                if (now - lastRx >= int64_t(config.echoSeconds) * 1000 || echoOutstanding) {
                    if (echoOutstanding >= config.echoFailures) {
                        finish("peer not responding (LCP echo)");
                        return;
                    }

                    ++echoOutstanding;
                    std::vector<uint8_t> d;
                    PutBe32(d, magicRejected ? 0 : magic);
                    sendPacket(EPPP_LCP, ECHO_REQ, lcp.nextId++, d);
                    echoNext = now + std::min<int64_t>(int64_t(config.echoSeconds) * 1000, 5000);
                }
                else {
                    echoNext = lastRx + int64_t(config.echoSeconds) * 1000;
                }
            }
        }

        /* Snapshot. */
        SPppInfo snapshot() const {
            SPppInfo i;
            i.user = config.server ? authUser : config.user;
            i.auth = authMethod;
            i.localAddress = local;
            i.peerAddress = peer;
            i.dns = config.server ? config.dns : dns;
            i.peerMru = peerMru;
            return i;
        }
    };

    CPppSession::CPppSession(SPppConfig config) : _state(std::make_shared<SState>()) {
        SState& st = *_state;
        st.config = std::move(config);
        st.lcp.protocol = EPPP_LCP;
        st.ipcp.protocol = EPPP_IPCP;
        st.ourMru = st.config.mru ? st.config.mru : 1500;
        IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&st.magic), sizeof(st.magic)));
        st.magic |= 1;
        if (st.config.server && !st.config.auth.empty()) {
            st.authProposal = st.config.auth[0];
        }
    }

    CPppSession::~CPppSession() = default;

    /* Frame sender. */
    void CPppSession::sender(std::function<void(const SReadOnlyByteSpan&)> send) {
        _state->send = std::move(send);
    }

    /* Log sink. */
    void CPppSession::logger(std::function<void(const std::string&)> log) {
        _state->log = std::move(log);
    }

    /* Address allocator. */
    void CPppSession::allocator(FPppAllocate allocate) {
        _state->allocate = std::move(allocate);
    }

    /* Up handler. */
    void CPppSession::onUp(std::function<void(const SPppInfo&)> handler) {
        _state->up = std::move(handler);
    }

    /* Down handler. */
    void CPppSession::onDown(std::function<void(const std::string&)> handler) {
        _state->down = std::move(handler);
    }

    /* IP handler. */
    void CPppSession::onIp(std::function<void(const SReadOnlyByteSpan&)> handler) {
        _state->ip = std::move(handler);
    }

    /* Starts LCP. */
    void CPppSession::start() {
        std::shared_ptr<SState> keep = _state;
        if (keep->phase != PH_DEAD || keep->downNotified) {
            return;
        }

        keep->clock();
        keep->started = keep->now;
        keep->lastRx = keep->now;
        keep->phase = PH_ESTABLISH;
        keep->open(keep->lcp);
    }

    /* Frame input. */
    void CPppSession::input(const SReadOnlyByteSpan& frame) {
        std::shared_ptr<SState> keep = _state;
        keep->input(frame);
    }

    /* Timers. */
    void CPppSession::tick(int64_t nowMs) {
        std::shared_ptr<SState> keep = _state;
        keep->tick(nowMs);
    }

    /* IP output. */
    int32_t CPppSession::sendIp(const SReadOnlyByteSpan& packet) {
        SState& st = *_state;
        if (st.phase != PH_NETWORK || st.ipcp.state != FS_OPENED) {
            return -ENOTCONN;
        }

        if (packet.size > st.peerMru) {
            return -EMSGSIZE;
        }

        std::vector<uint8_t> frame;
        frame.reserve(packet.size + 4);
        frame.push_back(0xff);
        frame.push_back(0x03);
        PutBe16(frame, EPPP_IP);
        frame.insert(frame.end(), packet.data, packet.data + packet.size);
        if (st.send) {
            st.send(BytesOf(frame));
        }

        return SBOX_OK;
    }

    /* Termination. */
    void CPppSession::close(const std::string& reason) {
        std::shared_ptr<SState> keep = _state;
        keep->clock();
        if (keep->phase == PH_ESTABLISH && keep->lcp.state != FS_OPENED) {
            keep->finish(reason);
            return;
        }

        keep->terminate(reason);
    }

    /* Up state. */
    bool CPppSession::isUp() const noexcept {
        return _state->phase == PH_NETWORK && _state->ipcp.state == FS_OPENED;
    }

    /* Down state. */
    bool CPppSession::isDown() const noexcept {
        return _state->downNotified;
    }

    /* Parameters. */
    SPppInfo CPppSession::info() const {
        return _state->snapshot();
    }

    /* Last activity. */
    int64_t CPppSession::lastActivity() const noexcept {
        return _state->lastRx;
    }

}
}
