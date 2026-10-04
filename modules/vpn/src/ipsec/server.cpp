#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/ipsec/eap.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/net/sysctl.hpp>
#include "crypto.hpp"
#include "ikesa.hpp"
#include "pool.hpp"
#include "queue.hpp"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>

namespace sbox {
namespace vpn {

    using namespace ipsec;

    namespace {

        enum SaState {
            ST_INIT = 0,        // --> IKE_SA_INIT done, waiting for IKE_AUTH.
            ST_EAP,             // --> EAP conversation running.
            ST_EAP_DONE,        // --> EAP succeeded, waiting for the MSK-based AUTH.
            ST_ESTABLISHED,
            ST_DEAD,
        };

        const char* stateName(SaState s) {
            switch (s) {
            case ST_INIT: return "connecting";
            case ST_EAP: return "eap";
            case ST_EAP_DONE: return "eap-done";
            case ST_ESTABLISHED: return "established";
            default: return "dead";
            }
        }

        /**
         * One CHILD SA of a session.
         */
        struct Child {
            SIpsecChildSa sa;
            Suite suite;
            int64_t created = 0;
            bool replaced = false;          // --> Rekeyed; waiting for the peer's DELETE.
            int64_t replacedAt = 0;
        };

        /**
         * CHILD SA request carried by the first IKE_AUTH (answered once authentication ends).
         */
        struct PendingChild {
            bool present = false;
            std::vector<SIkeProposal> proposals;
            std::vector<SIkeTrafficSelector> tsi;
            std::vector<SIkeTrafficSelector> tsr;
            bool hasCp = false;
            SIkeConfig cp;
        };

        /**
         * Responder-side IKE SA.
         */
        struct Session : IkeSa {
            SaState state = ST_INIT;
            int64_t created = 0;
            int64_t lastSeen = 0;
            int64_t establishedAt = 0;
            std::vector<uint8_t> initRequest;
            std::vector<uint8_t> initResponse;
            SIkeId idi;
            bool hasWantedIdr = false;
            SIkeId wantedIdr;               // --> IDr the client asked for (Apple/Android/strongSwan).
            std::vector<uint8_t> idrBody;
            std::string identity;
            bool peerFragmentation = false;
            bool mobike = false;
            bool initialContact = false;
            std::vector<uint16_t> peerHashes;
            PendingChild pendingChild;
            std::unique_ptr<CEapMsChapV2Server> eap;
            std::vector<uint8_t> msk;
            bool hasVip = false;
            net::SIpAddress vip;
            std::vector<Child> children;
            std::string proposalText;
            bool deleteAfterResponse = false;
            std::string halfOpenKey;
            uint64_t rekeyedTo = 0;
            int64_t rekeyedAt = 0;
            bool deleting = false;          // --> Our DELETE is outstanding.
            int64_t lastKeepalive = 0;

            ~Session() {
                IkeWipe(msk);
            }
        };

        using SessionPtr = std::shared_ptr<Session>;

        enum WorkKind {
            WORK_DATAGRAM = 0,
            WORK_TICK,
            WORK_DISCONNECT,
            WORK_STOP,
        };

        /**
         * Completion signal for work submitted by stop()/disconnect().
         */
        struct Completion {
            AsyncQueue<int32_t> done;
        };

        struct WorkItem {
            WorkKind kind = WORK_TICK;
            SIkeDatagram datagram;
            std::string text;
            std::shared_ptr<Completion> completion;
        };

        /* Compares strings ignoring ASCII case. */
        bool sameNoCase(std::string_view a, std::string_view b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                char x = a[i] >= 'A' && a[i] <= 'Z' ? char(a[i] - 'A' + 'a') : a[i];
                char y = b[i] >= 'A' && b[i] <= 'Z' ? char(b[i] - 'A' + 'a') : b[i];
                if (x != y) {
                    return false;
                }
            }

            return true;
        }

        /* Formats an SPI pair for logs. */
        std::string spiText(uint64_t spiI, uint64_t spiR) {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "%016llx_i %016llx_r", static_cast<unsigned long long>(spiI),
                          static_cast<unsigned long long>(spiR));
            return buf;
        }

        /* Builds a payload. */
        SIkePayload payload(uint8_t type, std::vector<uint8_t> body) {
            SIkePayload pl;
            pl.type = type;
            pl.body = std::move(body);
            return pl;
        }

        /* Collects notifies. */
        std::vector<SIkeNotify> notifiesOf(const std::vector<SIkePayload>& payloads) {
            std::vector<SIkeNotify> out;
            for (const SIkePayload& pl : payloads) {
                if (pl.type != EIKE_PL_NOTIFY) {
                    continue;
                }

                SIkeNotify n;
                if (DecodeIkeNotify(BytesOf(pl.body), n) == SBOX_OK) {
                    out.push_back(std::move(n));
                }
            }

            return out;
        }

        /* Finds a notify of a type. */
        const SIkeNotify* findNotify(const std::vector<SIkeNotify>& list, uint16_t type) {
            for (const SIkeNotify& n : list) {
                if (n.type == type) {
                    return &n;
                }
            }

            return nullptr;
        }

        /* Narrows offered selectors to the allowed ones. */
        bool narrow(const std::vector<SIkeTrafficSelector>& offered, const std::vector<SIkeTrafficSelector>& allowed,
                    std::vector<SIkeTrafficSelector>& out) {
            out.clear();
            for (const SIkeTrafficSelector& o : offered) {
                for (const SIkeTrafficSelector& a : allowed) {
                    SIkeTrafficSelector x;
                    if (!SIkeTrafficSelector::intersect(o, a, x)) {
                        continue;
                    }

                    bool dup = false;
                    for (const SIkeTrafficSelector& y : out) {
                        dup = dup || y == x;
                    }

                    if (!dup) {
                        out.push_back(x);
                    }
                }
            }

            return !out.empty();
        }

    }

    struct CIkeServer::SState : std::enable_shared_from_this<CIkeServer::SState> {
        SIkeServerConfig config;
        std::function<void(EIkeLogLevel, const std::string&)> sink;
        FIkeDatagramHandler v1;
        CIkeSocket socket;
        IIpsecDataPathPtr dataPath;
        AsyncQueue<WorkItem> queue;
        std::map<uint64_t, SessionPtr> sessions;
        std::map<std::string, uint64_t> halfOpen;
        std::vector<uint8_t> cookieSecret;
        AddressPool pool;
        uint32_t nextReqid = 1;
        bool running = false;
        bool stopped = false;
        CEventLoop* loop = nullptr;
        std::vector<std::vector<uint8_t>> userHashes;

        // ------------------------------------------------------------------------------------
        // Helpers

        /* Logs a message. */
        void log(EIkeLogLevel level, const std::string& message) {
            if (sink) {
                sink(level, message);
            }
        }

        /* Our identity payload. */
        SIkeId ourId(const SEndpoint& local) const {
            SIkeId id;
            if (!config.serverId.empty() && SIkeId::fromString(config.serverId, id) == SBOX_OK) {
                return id;
            }

            if (config.certificate.isValid()) {
                std::vector<std::string> dns = config.certificate.dnsNames();
                if (!dns.empty()) {
                    id.type = EIKE_ID_FQDN;
                    id.data.assign(dns[0].begin(), dns[0].end());
                    return id;
                }

                id.type = EIKE_ID_DER_ASN1_DN;
                id.data = config.certificate.subjectDer();
                return id;
            }

            net::SIpAddress a = AddressOf(local);
            id.type = a.isV6() ? EIKE_ID_IPV6_ADDR : EIKE_ID_IPV4_ADDR;
            id.data.assign(a.bytes, a.bytes + a.length());
            return id;
        }

        /**
         * Identity we answer with: the IDr the client asked for when it is one of ours (the
         * configured serverId, or a name/address bound to our certificate), so clients that dial
         * by address and clients that dial by name both see what they expect; else our default.
         */
        SIkeId responderId(const SessionPtr& s) const {
            SIkeId fallback = ourId(s->local);
            if (!s->hasWantedIdr) {
                return fallback;
            }

            if (s->wantedIdr == fallback) {
                return fallback;
            }

            SIkeId configured;
            if (!config.serverId.empty() && SIkeId::fromString(config.serverId, configured) == SBOX_OK
                && configured.data == s->wantedIdr.data) {
                return s->wantedIdr;
            }

            if (config.certificate.isValid() && IdMatchesCertificate(s->wantedIdr, config.certificate)) {
                return s->wantedIdr;
            }

            return fallback;
        }

        /* Looks up a PSK for a peer identity. */
        const SIkePsk* findPsk(const SIkeId& peer) const {
            const SIkePsk* fallback = nullptr;
            for (const SIkePsk& p : config.psks) {
                if (p.id.empty()) {
                    if (!fallback) {
                        fallback = &p;
                    }

                    continue;
                }

                // --> Clients pick the ID type from the text ("phone.example" may arrive as FQDN,
                // RFC822 or KEY_ID), so the bytes decide; "@phone.example" and "phone.example"
                // name the same identity.
                SIkeId want;
                if (SIkeId::fromString(p.id, want) == SBOX_OK && want.data == peer.data) {
                    return &p;
                }

                if (p.id == peer.toString()) {
                    return &p;
                }
            }

            return fallback;
        }

        /* Looks up an EAP account. */
        const SIkeUser* findUser(const std::string& name, size_t* index = nullptr) const {
            for (size_t i = 0; i < config.users.size(); ++i) {
                if (sameNoCase(config.users[i].name, name)) {
                    if (index) {
                        *index = i;
                    }

                    return &config.users[i];
                }
            }

            return nullptr;
        }

        /* Cookie for a peer (RFC 7296 2.6). */
        std::vector<uint8_t> cookie(const SReadOnlyByteSpan& ni, const SEndpoint& remote, uint64_t spiI) const {
            std::vector<uint8_t> data;
            Append(data, ni);
            Append(data, BytesOf(remote.toString()));
            PutBe64(data, spiI);
            std::vector<uint8_t> mac = Hmac(certpp::crypto::EHASH_SHA256, BytesOf(cookieSecret), BytesOf(data));
            mac.insert(mac.begin(), 0x00);  // --> Version of the secret.
            return mac;
        }

        /* Sends datagrams to a peer. */
        void sendAll(const std::vector<std::vector<uint8_t>>& datagrams, const SEndpoint& local, const SEndpoint& remote, bool natT) {
            for (const std::vector<uint8_t>& d : datagrams) {
                socket.send(BytesOf(d), local, remote, natT);
            }
        }

        /* Sends an unprotected IKE_SA_INIT response carrying one notify. */
        void sendInitError(const SIkeHeader& request, const SIkeDatagram& dg, uint16_t type, const SReadOnlyByteSpan& data) {
            SIkeHeader h;
            h.spiI = request.spiI;
            h.spiR = 0;
            h.exchange = EIKE_X_SA_INIT;
            h.flags = EIKE_F_RESPONSE;
            h.messageId = 0;
            std::vector<SIkePayload> payloads;
            payloads.push_back(MakeIkeNotify(type, data));
            std::vector<uint8_t> msg = EncodePlainMessage(h, payloads);
            socket.send(BytesOf(msg), dg.local, dg.remote, dg.natT);
        }

        /* Allocates a reqid. */
        uint32_t newReqid() {
            uint32_t r = config.dataPath.reqidBase + (nextReqid & 0x00ffffffu);
            nextReqid = nextReqid % 0x00fffffeu + 1;
            return r;
        }

        /* CHILD SA traffic selectors we allow on our side. */
        std::vector<SIkeTrafficSelector> localSelectors() const {
            std::vector<SIkeTrafficSelector> out;
            for (const net::SIpPrefix& p : config.routes) {
                out.push_back(SIkeTrafficSelector::fromPrefix(p));
            }

            if (out.empty()) {
                out.push_back(SIkeTrafficSelector::any(false));
                if (config.ipv6) {
                    out.push_back(SIkeTrafficSelector::any(true));
                }
            }

            return out;
        }

        // ------------------------------------------------------------------------------------
        // Main loops

        /* Processes work items one at a time. */
        static TTask<void> processor(std::shared_ptr<SState> st) {
            while (co_await st->queue.wait()) {
                WorkItem w = st->queue.pop();
                switch (w.kind) {
                case WORK_DATAGRAM:
                    if (!st->stopped) {
                        co_await st->handle(w.datagram);
                    }
                    break;

                case WORK_TICK:
                    if (!st->stopped) {
                        co_await st->tick();
                    }
                    break;

                case WORK_DISCONNECT: {
                    int32_t count = st->stopped ? 0 : co_await st->disconnectMatching(w.text);
                    if (w.completion) {
                        w.completion->done.push(count);
                    }
                    break;
                }

                case WORK_STOP:
                    co_await st->shutdown();
                    if (w.completion) {
                        w.completion->done.push(SBOX_OK);
                    }

                    st->queue.close();
                    break;
                }
            }
        }

        /* Pushes a tick every second. */
        static TTask<void> ticker(std::shared_ptr<SState> st) {
            while (st->running && !st->stopped) {
                co_await st->loop->sleepFor(1000);
                if (st->running && !st->stopped) {
                    WorkItem w;
                    w.kind = WORK_TICK;
                    st->queue.push(std::move(w));
                }
            }
        }

        // ------------------------------------------------------------------------------------
        // Dispatch

        /* Handles one datagram. */
        TTask<void> handle(SIkeDatagram& dg) {
            SIkeHeader h;
            if (SIkeHeader::parse(BytesOf(dg.data), h) != SBOX_OK) {
                co_return;
            }

            dg.data.resize(h.length);
            if ((h.version >> 4) == 1) {
                if (v1) {
                    v1(dg);
                }

                co_return;
            }

            if ((h.version >> 4) != 2) {
                co_return;
            }

            if (h.isResponse()) {
                co_await handleResponse(h, dg);
                co_return;
            }

            if (h.exchange == EIKE_X_SA_INIT) {
                handleSaInit(h, dg);
                co_return;
            }

            auto it = sessions.find(h.spiR);
            if (it == sessions.end() || it->second->spiI != h.spiI || it->second->state == ST_DEAD) {
                co_return;
            }

            SessionPtr s = it->second;
            if (!h.fromInitiator()) {
                co_return;
            }

            if (s->hasLast && h.messageId == s->lastMid) {
                // --> Retransmitted request: replay the cached response (for fragmented
                // requests only on the first fragment, RFC 7383 2.6.1).
                bool first = true;
                if (h.nextPayload == EIKE_PL_SKF && dg.data.size() >= IKE_HEADER_SIZE + 8) {
                    first = GetBe16(dg.data.data() + IKE_HEADER_SIZE + 4) == 1;
                }

                if (first) {
                    sendAll(s->lastResponse, dg.local, dg.remote, dg.natT);
                }

                co_return;
            }

            if (h.messageId != s->expectMid) {
                co_return;
            }

            std::vector<SIkePayload> payloads;
            int32_t r = s->decrypt(h, BytesOf(dg.data), payloads);
            if (r == -EAGAIN) {
                co_return;
            }

            if (r != SBOX_OK) {
                log(EIKE_LOG_DEBUG, spiText(s->spiI, s->spiR) + ": dropping undecryptable message (" + std::to_string(r) + ")");
                co_return;
            }

            s->lastSeen = CEventLoop::nowMs();

            std::vector<SIkePayload> response;
            for (const SIkePayload& pl : payloads) {
                if (pl.critical && !IsKnownIkePayload(pl.type)) {
                    response.push_back(MakeIkeNotify(EIKE_N_UNSUPPORTED_CRITICAL_PAYLOAD, SReadOnlyByteSpan(&pl.type, 1)));
                    respond(s, h, dg, response);
                    co_return;
                }
            }

            // --> An authenticated message from a new address after a NAT rebinding moves the
            // SA there (RFC 7296 2.23); MOBIKE peers announce moves explicitly instead.
            if (s->state == ST_ESTABLISHED && !s->mobike && (s->natRemote || s->natLocal)
                && dg.remote.toString() != s->remote.toString()) {
                co_await moveSession(s, dg);
            }

            // --> CHILD SAs created by this request use the endpoints it arrived on (after NAT
            // detection the client moves from port 500 to 4500 between IKE_SA_INIT and IKE_AUTH).
            s->local = dg.local;
            s->remote = dg.remote;
            s->natT = dg.natT;

            switch (h.exchange) {
            case EIKE_X_AUTH:
                co_await onAuth(s, payloads, response);
                break;

            case EIKE_X_CREATE_CHILD_SA:
                co_await onCreateChild(s, payloads, response);
                break;

            case EIKE_X_INFORMATIONAL:
                co_await onInformational(s, dg, payloads, response);
                break;

            default:
                co_return;
            }

            if (s->state == ST_DEAD) {
                co_return;
            }

            respond(s, h, dg, response);

            if (s->deleteAfterResponse) {
                co_await destroy(s, false);
            }
        }

        /* Sends and caches a response. */
        void respond(const SessionPtr& s, const SIkeHeader& h, const SIkeDatagram& dg, const std::vector<SIkePayload>& payloads) {
            std::vector<std::vector<uint8_t>> datagrams;
            if (s->encrypt(h.exchange, true, h.messageId, payloads, datagrams) != SBOX_OK) {
                return;
            }

            sendAll(datagrams, dg.local, dg.remote, dg.natT);
            s->lastResponse = std::move(datagrams);
            s->lastMid = h.messageId;
            s->hasLast = true;
            s->expectMid = h.messageId + 1;

            // --> Requests come from wherever the peer is now; our own requests follow it.
            s->local = dg.local;
            s->remote = dg.remote;
            s->natT = dg.natT;
        }

        /* Sends a request of ours (DPD, DELETE). */
        void request(const SessionPtr& s, uint8_t exchange, const std::vector<SIkePayload>& payloads) {
            std::vector<std::vector<uint8_t>> datagrams;
            if (s->encrypt(exchange, false, s->nextMid, payloads, datagrams) != SBOX_OK) {
                return;
            }

            sendAll(datagrams, s->local, s->remote, s->natT);
            s->pending = true;
            s->pendingMid = s->nextMid;
            s->pendingExchange = exchange;
            s->pendingRequest = std::move(datagrams);
            s->retries = 0;
            s->retransmitAt = CEventLoop::nowMs() + config.retransmitBaseMs;
        }

        /* Handles a response to one of our requests. */
        TTask<void> handleResponse(const SIkeHeader& h, SIkeDatagram& dg) {
            auto it = sessions.find(h.spiR);
            if (it == sessions.end() || it->second->spiI != h.spiI) {
                co_return;
            }

            SessionPtr s = it->second;
            if (!s->pending || h.messageId != s->pendingMid || h.exchange != s->pendingExchange) {
                co_return;
            }

            std::vector<SIkePayload> payloads;
            int32_t r = s->decrypt(h, BytesOf(dg.data), payloads);
            if (r != SBOX_OK) {
                co_return;
            }

            s->pending = false;
            s->pendingRequest.clear();
            s->nextMid++;
            s->lastSeen = CEventLoop::nowMs();

            if (s->deleting) {
                co_await destroy(s, false);
            }
        }

        // ------------------------------------------------------------------------------------
        // IKE_SA_INIT

        /* Handles an IKE_SA_INIT request. */
        void handleSaInit(const SIkeHeader& h, const SIkeDatagram& dg) {
            if (h.spiR != 0 || h.messageId != 0 || !h.fromInitiator() || h.spiI == 0) {
                return;
            }

            std::string key = ToHex(SReadOnlyByteSpan(dg.data.data(), 8)) + "|" + dg.remote.toString();
            auto known = halfOpen.find(key);
            if (known != halfOpen.end()) {
                auto it = sessions.find(known->second);
                if (it != sessions.end() && it->second->state == ST_INIT) {
                    if (it->second->initRequest == dg.data) {
                        sendAll(it->second->lastResponse, dg.local, dg.remote, dg.natT);
                        return;
                    }
                }
            }

            std::vector<SIkePayload> payloads;
            if (ParseIkePayloads(h.nextPayload, BytesOf(dg.data).slice(IKE_HEADER_SIZE), payloads) != SBOX_OK) {
                return;
            }

            const SIkePayload* saPl = FindIkePayload(payloads, EIKE_PL_SA);
            const SIkePayload* kePl = FindIkePayload(payloads, EIKE_PL_KE);
            const SIkePayload* noncePl = FindIkePayload(payloads, EIKE_PL_NONCE);
            if (!saPl || !kePl || !noncePl) {
                sendInitError(h, dg, EIKE_N_INVALID_SYNTAX, SReadOnlyByteSpan());
                return;
            }

            if (noncePl->body.size() < 16 || noncePl->body.size() > 256) {
                sendInitError(h, dg, EIKE_N_INVALID_SYNTAX, SReadOnlyByteSpan());
                return;
            }

            if (sessions.size() >= config.maxSessions) {
                sendInitError(h, dg, EIKE_N_TEMPORARY_FAILURE, SReadOnlyByteSpan());
                return;
            }

            std::vector<SIkeNotify> notifies = notifiesOf(payloads);

            // --> Under load, demand a COOKIE first (stateless until the peer proves it can
            // receive at its source address).
            size_t pendingCount = 0;
            for (auto& [spi, s] : sessions) {
                (void)spi;
                pendingCount += s->state != ST_ESTABLISHED ? 1 : 0;
            }

            if (pendingCount >= config.cookieThreshold) {
                std::vector<uint8_t> expected = cookie(BytesOf(noncePl->body), dg.remote, h.spiI);
                const SIkeNotify* c = findNotify(notifies, EIKE_N_COOKIE);
                if (!c || payloads[0].type != EIKE_PL_NOTIFY || !IkeSecureEquals(BytesOf(c->data), BytesOf(expected))) {
                    sendInitError(h, dg, EIKE_N_COOKIE, BytesOf(expected));
                    return;
                }
            }

            std::vector<SIkeProposal> offered;
            uint16_t keGroup = 0;
            std::vector<uint8_t> keData;
            if (DecodeIkeSa(BytesOf(saPl->body), offered) != SBOX_OK || DecodeIkeKe(BytesOf(kePl->body), keGroup, keData) != SBOX_OK) {
                sendInitError(h, dg, EIKE_N_INVALID_SYNTAX, SReadOnlyByteSpan());
                return;
            }

            SIkeProposal chosen;
            if (!SelectIkeProposal(offered, config.ikeProposals, keGroup, EIKE_DHM_REQUIRED, nullptr, chosen)) {
                std::string text;
                for (const SIkeProposal& p : offered) {
                    text += " " + p.toString();
                }

                log(EIKE_LOG_WARNING, dg.remote.toString() + ": no acceptable IKE proposal among" + text);
                sendInitError(h, dg, EIKE_N_NO_PROPOSAL_CHOSEN, SReadOnlyByteSpan());
                return;
            }

            Suite suite = Suite::from(chosen);
            if (keGroup != suite.dh) {
                std::vector<uint8_t> group;
                PutBe16(group, suite.dh);
                sendInitError(h, dg, EIKE_N_INVALID_KE_PAYLOAD, BytesOf(group));
                return;
            }

            auto s = std::make_shared<Session>();
            s->spiI = h.spiI;
            do {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&s->spiR), sizeof(s->spiR)));
            } while (s->spiR == 0 || sessions.count(s->spiR));

            s->initiator = false;
            s->suite = suite;
            s->ni = noncePl->body;
            s->nr.assign(32, 0);
            IkeRandom(BytesOf(s->nr));

            CIkeDh dh;
            std::vector<uint8_t> gir;
            if (dh.generate(suite.dh) != SBOX_OK || dh.agree(BytesOf(keData), gir) != SBOX_OK) {
                sendInitError(h, dg, EIKE_N_INVALID_SYNTAX, SReadOnlyByteSpan());
                return;
            }

            std::vector<uint8_t> skeyseed;
            int32_t r = ComputeSkeyseed(suite.prf, BytesOf(s->ni), BytesOf(s->nr), BytesOf(gir), skeyseed);
            IkeWipe(gir);
            if (r != SBOX_OK || s->installKeys(BytesOf(skeyseed)) != SBOX_OK) {
                IkeWipe(skeyseed);
                return;
            }

            IkeWipe(skeyseed);

            // --> NAT detection (RFC 7296 2.23): the request's hashes use SPIr = 0.
            bool sawNatD = false;
            bool srcMatch = false;
            bool dstMatch = false;
            std::vector<uint8_t> remoteHash = NatHash(h.spiI, 0, dg.remote);
            std::vector<uint8_t> localHash = NatHash(h.spiI, 0, dg.local);
            for (const SIkeNotify& n : notifies) {
                if (n.type == EIKE_N_NAT_DETECTION_SOURCE_IP) {
                    sawNatD = true;
                    srcMatch = srcMatch || n.data == remoteHash;
                }
                else if (n.type == EIKE_N_NAT_DETECTION_DESTINATION_IP) {
                    sawNatD = true;
                    dstMatch = dstMatch || n.data == localHash;
                }
            }

            s->natRemote = sawNatD && !srcMatch;
            s->natLocal = sawNatD && (!dstMatch || config.forceEncap);
            s->peerFragmentation = findNotify(notifies, EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED) != nullptr;
            s->fragmentation = s->peerFragmentation;
            s->fragmentSize = IkeMessageLimit(config.fragmentSize);
            if (const SIkeNotify* hashes = findNotify(notifies, EIKE_N_SIGNATURE_HASH_ALGORITHMS)) {
                s->peerHashes = ParseHashAlgorithms(BytesOf(hashes->data));
            }

            chosen.spi.clear();
            std::vector<SIkePayload> response;
            std::vector<uint8_t> body;
            EncodeIkeSa({ chosen }, body);
            response.push_back(payload(EIKE_PL_SA, std::move(body)));

            body.clear();
            EncodeIkeKe(suite.dh, BytesOf(dh.publicValue()), body);
            response.push_back(payload(EIKE_PL_KE, std::move(body)));
            response.push_back(payload(EIKE_PL_NONCE, s->nr));

            if (sawNatD) {
                std::vector<uint8_t> src = NatHash(h.spiI, s->spiR, dg.local);
                if (config.forceEncap) {
                    // --> A hash that cannot match makes the peer believe we are behind a NAT,
                    // so it switches to UDP 4500 and encapsulates ESP.
                    IkeRandom(BytesOf(src));
                }

                response.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_SOURCE_IP, BytesOf(src)));
                std::vector<uint8_t> dst = NatHash(h.spiI, s->spiR, dg.remote);
                response.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_DESTINATION_IP, BytesOf(dst)));
            }

            if (!config.caCertificates.empty()) {
                std::vector<uint8_t> hashes;
                for (const CIkeCertificate& ca : config.caCertificates) {
                    Append(hashes, BytesOf(ca.keyHash()));
                }

                body.clear();
                EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(hashes), body);
                response.push_back(payload(EIKE_PL_CERTREQ, std::move(body)));
            }

            if (s->peerFragmentation) {
                response.push_back(MakeIkeNotify(EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED));
            }

            if (!s->peerHashes.empty()) {
                std::vector<uint8_t> ours = OurHashAlgorithms();
                response.push_back(MakeIkeNotify(EIKE_N_SIGNATURE_HASH_ALGORITHMS, BytesOf(ours)));
            }

            SIkeHeader rh;
            rh.spiI = s->spiI;
            rh.spiR = s->spiR;
            rh.exchange = EIKE_X_SA_INIT;
            rh.flags = EIKE_F_RESPONSE;
            rh.messageId = 0;
            std::vector<uint8_t> msg = EncodePlainMessage(rh, response);
            socket.send(BytesOf(msg), dg.local, dg.remote, dg.natT);

            int64_t now = CEventLoop::nowMs();
            s->initRequest = dg.data;
            s->initResponse = msg;
            s->lastResponse = { msg };
            s->lastMid = 0;
            s->hasLast = true;
            s->expectMid = 1;
            s->local = dg.local;
            s->remote = dg.remote;
            s->natT = dg.natT;
            s->created = now;
            s->lastSeen = now;
            s->halfOpenKey = key;
            s->proposalText = FormatIkeProposal(chosen);

            sessions[s->spiR] = s;
            halfOpen[key] = s->spiR;
            log(EIKE_LOG_INFO, dg.remote.toString() + ": IKE_SA_INIT " + spiText(s->spiI, s->spiR) + " " + s->proposalText
                + (s->natRemote || s->natLocal ? " (NAT)" : ""));
        }

        // ------------------------------------------------------------------------------------
        // IKE_AUTH

        /* Builds the payloads that authenticate us with the certificate. */
        bool certAuthPayloads(const SessionPtr& s, std::vector<SIkePayload>& resp) {
            if (!config.certificate.hasPrivateKey()) {
                return false;
            }

            SIkeId id = responderId(s);
            s->idrBody = id.body();
            resp.push_back(payload(EIKE_PL_IDR, s->idrBody));

            std::vector<uint8_t> body;
            EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(config.certificate.der()), body);
            resp.push_back(payload(EIKE_PL_CERT, std::move(body)));
            for (const std::vector<uint8_t>& c : config.certificate.chain()) {
                body.clear();
                EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(c), body);
                resp.push_back(payload(EIKE_PL_CERT, std::move(body)));
            }

            std::vector<uint8_t> octets = AuthOctets(BytesOf(s->initResponse), BytesOf(s->ni), s->suite.prf,
                                                     BytesOf(s->keys.pr), BytesOf(s->idrBody));
            uint8_t method = 0;
            std::vector<uint8_t> sig;
            if (SignAuth(config.certificate, BytesOf(octets), s->peerHashes, method, sig) != SBOX_OK) {
                return false;
            }

            body.clear();
            EncodeIkeAuth(method, BytesOf(sig), body);
            resp.push_back(payload(EIKE_PL_AUTH, std::move(body)));
            return true;
        }

        /* Rejects authentication: AUTHENTICATION_FAILED and the SA goes away. */
        void authFailed(const SessionPtr& s, std::vector<SIkePayload>& resp, const std::string& why) {
            log(EIKE_LOG_WARNING, s->remote.toString() + ": authentication failed: " + why);
            resp.clear();
            resp.push_back(MakeIkeNotify(EIKE_N_AUTHENTICATION_FAILED));
            s->deleteAfterResponse = true;
        }

        /* Handles IKE_AUTH. */
        TTask<void> onAuth(SessionPtr s, std::vector<SIkePayload>& payloads, std::vector<SIkePayload>& resp) {
            std::vector<SIkeNotify> notifies = notifiesOf(payloads);

            if (s->state == ST_INIT) {
                const SIkePayload* idPl = FindIkePayload(payloads, EIKE_PL_IDI);
                if (!idPl || DecodeIkeId(BytesOf(idPl->body), s->idi) != SBOX_OK) {
                    authFailed(s, resp, "missing IDi");
                    co_return;
                }

                s->initialContact = findNotify(notifies, EIKE_N_INITIAL_CONTACT) != nullptr;
                s->mobike = config.mobike && findNotify(notifies, EIKE_N_MOBIKE_SUPPORTED) != nullptr;
                if (const SIkePayload* idrPl = FindIkePayload(payloads, EIKE_PL_IDR)) {
                    s->hasWantedIdr = DecodeIkeId(BytesOf(idrPl->body), s->wantedIdr) == SBOX_OK;
                }

                PendingChild& pc = s->pendingChild;
                const SIkePayload* saPl = FindIkePayload(payloads, EIKE_PL_SA);
                const SIkePayload* tsiPl = FindIkePayload(payloads, EIKE_PL_TSI);
                const SIkePayload* tsrPl = FindIkePayload(payloads, EIKE_PL_TSR);
                const SIkePayload* cpPl = FindIkePayload(payloads, EIKE_PL_CP);
                pc.present = saPl && tsiPl && tsrPl && DecodeIkeSa(BytesOf(saPl->body), pc.proposals) == SBOX_OK
                    && DecodeIkeTs(BytesOf(tsiPl->body), pc.tsi) == SBOX_OK && DecodeIkeTs(BytesOf(tsrPl->body), pc.tsr) == SBOX_OK;
                pc.hasCp = cpPl && DecodeIkeConfig(BytesOf(cpPl->body), pc.cp) == SBOX_OK;

                const SIkePayload* authPl = FindIkePayload(payloads, EIKE_PL_AUTH);
                if (!authPl) {
                    // --> No AUTH: the initiator wants EAP (RFC 7296 2.16).
                    if (config.users.empty()) {
                        authFailed(s, resp, "EAP requested but no users are configured");
                        co_return;
                    }

                    if (!certAuthPayloads(s, resp)) {
                        authFailed(s, resp, "EAP requires a server certificate with its key");
                        co_return;
                    }

                    std::shared_ptr<SState> self = shared_from_this();
                    s->eap = std::make_unique<CEapMsChapV2Server>([self](const std::string& user, std::vector<uint8_t>& hash) {
                        size_t index = 0;
                        if (!self->findUser(user, &index)) {
                            return false;
                        }

                        hash = self->userHashes[index];
                        return true;
                    });

                    std::vector<uint8_t> first = s->eap->start(config.eapIdentity);
                    resp.push_back(payload(EIKE_PL_EAP, std::move(first)));
                    s->state = ST_EAP;
                    co_return;
                }

                uint8_t method = 0;
                std::vector<uint8_t> authData;
                if (DecodeIkeAuth(BytesOf(authPl->body), method, authData) != SBOX_OK) {
                    authFailed(s, resp, "malformed AUTH");
                    co_return;
                }

                std::vector<uint8_t> octets = AuthOctets(BytesOf(s->initRequest), BytesOf(s->nr), s->suite.prf,
                                                         BytesOf(s->keys.pi), BytesOf(idPl->body));
                std::string idText = s->idi.toString();

                if (method == EIKE_AUTH_PSK) {
                    const SIkePsk* psk = findPsk(s->idi);
                    std::vector<uint8_t> expected;
                    if (!psk || SharedKeyAuth(s->suite.prf, BytesOf(psk->secret), BytesOf(octets), expected) != SBOX_OK
                        || !IkeSecureEquals(BytesOf(expected), BytesOf(authData))) {
                        authFailed(s, resp, "pre-shared key mismatch for '" + idText + "'");
                        co_return;
                    }

                    SIkeId id = responderId(s);
                    s->idrBody = id.body();
                    resp.push_back(payload(EIKE_PL_IDR, s->idrBody));

                    std::vector<uint8_t> ours = AuthOctets(BytesOf(s->initResponse), BytesOf(s->ni), s->suite.prf,
                                                           BytesOf(s->keys.pr), BytesOf(s->idrBody));
                    std::vector<uint8_t> mac;
                    SharedKeyAuth(s->suite.prf, BytesOf(psk->secret), BytesOf(ours), mac);
                    std::vector<uint8_t> body;
                    EncodeIkeAuth(EIKE_AUTH_PSK, BytesOf(mac), body);
                    resp.push_back(payload(EIKE_PL_AUTH, std::move(body)));
                    s->identity = idText;
                }
                else {
                    std::vector<CIkeCertificate> certs;
                    for (const SIkePayload& pl : payloads) {
                        if (pl.type != EIKE_PL_CERT) {
                            continue;
                        }

                        uint8_t encoding = 0;
                        std::vector<uint8_t> der;
                        CIkeCertificate c;
                        if (DecodeIkeCert(BytesOf(pl.body), encoding, der) == SBOX_OK && encoding == EIKE_CERT_X509_SIGNATURE
                            && CIkeCertificate::fromDer(BytesOf(der), c) == SBOX_OK) {
                            certs.push_back(std::move(c));
                        }
                    }

                    if (certs.empty() || config.caCertificates.empty()) {
                        authFailed(s, resp, "certificate authentication without a usable CERT payload or trust anchor");
                        co_return;
                    }

                    std::vector<CIkeCertificate> intermediates(certs.begin() + 1, certs.end());
                    int32_t r = VerifyIkeCertificate(certs[0], intermediates, config.caCertificates);
                    if (r != SBOX_OK) {
                        authFailed(s, resp, "untrusted certificate '" + certs[0].subject() + "' (" + std::to_string(r) + ")");
                        co_return;
                    }

                    if (config.strictCertificateId && !IdMatchesCertificate(s->idi, certs[0])) {
                        authFailed(s, resp, "identity '" + idText + "' is not bound to certificate '" + certs[0].subject() + "'");
                        co_return;
                    }

                    r = VerifyAuth(certs[0], method, BytesOf(authData), BytesOf(octets));
                    if (r != SBOX_OK) {
                        authFailed(s, resp, "bad signature from '" + certs[0].subject() + "' (method " + std::to_string(method) + ")");
                        co_return;
                    }

                    if (!certAuthPayloads(s, resp)) {
                        authFailed(s, resp, "no server certificate to answer certificate authentication");
                        co_return;
                    }

                    s->identity = certs[0].subject();
                }

                co_await establish(s, resp);
                co_return;
            }

            if (s->state == ST_EAP) {
                const SIkePayload* eapPl = FindIkePayload(payloads, EIKE_PL_EAP);
                if (!eapPl || !s->eap) {
                    authFailed(s, resp, "expected an EAP payload");
                    co_return;
                }

                std::vector<uint8_t> next;
                EEapStatus status = s->eap->process(BytesOf(eapPl->body), next);
                resp.push_back(payload(EIKE_PL_EAP, std::move(next)));

                if (status == EEAPS_SUCCESS) {
                    s->msk = s->eap->msk();
                    s->identity = s->eap->user();
                    s->state = ST_EAP_DONE;
                    s->eap.reset();
                }
                else if (status == EEAPS_FAILURE) {
                    log(EIKE_LOG_WARNING, s->remote.toString() + ": EAP-MSCHAPv2 failed: " + s->eap->error());
                    s->deleteAfterResponse = true;
                }

                co_return;
            }

            if (s->state == ST_EAP_DONE) {
                const SIkePayload* authPl = FindIkePayload(payloads, EIKE_PL_AUTH);
                uint8_t method = 0;
                std::vector<uint8_t> authData;
                if (!authPl || DecodeIkeAuth(BytesOf(authPl->body), method, authData) != SBOX_OK || method != EIKE_AUTH_PSK) {
                    authFailed(s, resp, "expected the EAP MSK AUTH payload");
                    co_return;
                }

                std::vector<uint8_t> idiBody = s->idi.body();
                std::vector<uint8_t> octets = AuthOctets(BytesOf(s->initRequest), BytesOf(s->nr), s->suite.prf,
                                                         BytesOf(s->keys.pi), BytesOf(idiBody));
                std::vector<uint8_t> expected;
                if (SharedKeyAuth(s->suite.prf, BytesOf(s->msk), BytesOf(octets), expected) != SBOX_OK
                    || !IkeSecureEquals(BytesOf(expected), BytesOf(authData))) {
                    authFailed(s, resp, "EAP MSK AUTH mismatch for '" + s->identity + "'");
                    co_return;
                }

                std::vector<uint8_t> ours = AuthOctets(BytesOf(s->initResponse), BytesOf(s->ni), s->suite.prf,
                                                       BytesOf(s->keys.pr), BytesOf(s->idrBody));
                std::vector<uint8_t> mac;
                SharedKeyAuth(s->suite.prf, BytesOf(s->msk), BytesOf(ours), mac);
                std::vector<uint8_t> body;
                EncodeIkeAuth(EIKE_AUTH_PSK, BytesOf(mac), body);
                resp.push_back(payload(EIKE_PL_AUTH, std::move(body)));
                IkeWipe(s->msk);

                co_await establish(s, resp);
                co_return;
            }

            resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
        }

        /* Completes authentication: INITIAL_CONTACT, CP, the first CHILD SA. */
        TTask<void> establish(SessionPtr s, std::vector<SIkePayload>& resp) {
            s->state = ST_ESTABLISHED;
            s->establishedAt = CEventLoop::nowMs();
            halfOpen.erase(s->halfOpenKey);

            if (s->initialContact) {
                std::vector<SessionPtr> old;
                for (auto& [spi, other] : sessions) {
                    (void)spi;
                    if (other != s && other->state == ST_ESTABLISHED && other->identity == s->identity) {
                        old.push_back(other);
                    }
                }

                for (const SessionPtr& o : old) {
                    log(EIKE_LOG_INFO, "INITIAL_CONTACT from '" + s->identity + "': removing " + spiText(o->spiI, o->spiR));
                    co_await destroy(o, false);
                }
            }

            log(EIKE_LOG_INFO, s->remote.toString() + ": IKE SA " + spiText(s->spiI, s->spiR) + " established for '"
                + s->identity + "' (" + s->proposalText + ")");

            if (s->mobike) {
                resp.push_back(MakeIkeNotify(EIKE_N_MOBIKE_SUPPORTED));
            }

            if (!s->pendingChild.present) {
                co_return;
            }

            PendingChild pc = std::move(s->pendingChild);
            s->pendingChild = PendingChild();
            std::vector<uint8_t> none;
            co_await createChild(s, pc.proposals, pc.tsi, pc.tsr, pc.hasCp ? &pc.cp : nullptr, BytesOf(s->ni), BytesOf(s->nr),
                                 BytesOf(none), EIKE_DHM_IGNORED, nullptr, resp, nullptr);
        }

        /* Assigns the virtual address and builds the CP reply. */
        bool configure(const SessionPtr& s, const SIkeConfig& request, std::vector<SIkePayload>& resp) {
            if (request.cfgType != EIKE_CFG_REQUEST || !pool.valid()) {
                return true;
            }

            bool wantV4 = false;
            net::SIpAddress requested;
            std::vector<uint16_t> asked;
            for (const SIkeCfgAttribute& a : request.attributes) {
                asked.push_back(a.type);
                if (a.type == EIKE_CA_INTERNAL_IP4_ADDRESS) {
                    wantV4 = true;
                    if (a.value.size() == 4) {
                        net::SIpAddress::fromBytes(a.value.data(), 4, requested);
                        if (requested.isUnspecified()) {
                            requested = net::SIpAddress();
                        }
                    }
                }
            }

            if (!wantV4) {
                return true;
            }

            if (!s->hasVip) {
                net::SIpAddress fixed;
                if (const SIkeUser* u = findUser(s->identity)) {
                    if (!u->address.empty()) {
                        net::SIpAddress::parse(u->address, fixed);
                    }
                }

                if (!pool.allocate(s->identity, s->spiR, fixed, requested, s->vip)) {
                    log(EIKE_LOG_WARNING, "address pool exhausted for '" + s->identity + "'");
                    return false;
                }

                s->hasVip = true;
            }

            auto wanted = [&](uint16_t type) {
                for (uint16_t t : asked) {
                    if (t == type) {
                        return true;
                    }
                }

                return false;
            };

            SIkeConfig reply;
            reply.cfgType = EIKE_CFG_REPLY;
            SIkeCfgAttribute addr;
            addr.type = EIKE_CA_INTERNAL_IP4_ADDRESS;
            addr.value.assign(s->vip.bytes, s->vip.bytes + 4);
            reply.attributes.push_back(addr);

            if (wanted(EIKE_CA_INTERNAL_IP4_NETMASK)) {
                SIkeCfgAttribute mask;
                mask.type = EIKE_CA_INTERNAL_IP4_NETMASK;
                net::SIpAddress m = config.pool.mask();
                mask.value.assign(m.bytes, m.bytes + 4);
                reply.attributes.push_back(mask);
            }

            for (const net::SIpAddress& dns : config.dns) {
                if (dns.isV4() && wanted(EIKE_CA_INTERNAL_IP4_DNS)) {
                    SIkeCfgAttribute a;
                    a.type = EIKE_CA_INTERNAL_IP4_DNS;
                    a.value.assign(dns.bytes, dns.bytes + 4);
                    reply.attributes.push_back(a);
                }
                else if (dns.isV6() && wanted(EIKE_CA_INTERNAL_IP6_DNS)) {
                    SIkeCfgAttribute a;
                    a.type = EIKE_CA_INTERNAL_IP6_DNS;
                    a.value.assign(dns.bytes, dns.bytes + 16);
                    reply.attributes.push_back(a);
                }
            }

            for (const net::SIpAddress& nbns : config.nbns) {
                if (nbns.isV4() && wanted(EIKE_CA_INTERNAL_IP4_NBNS)) {
                    SIkeCfgAttribute a;
                    a.type = EIKE_CA_INTERNAL_IP4_NBNS;
                    a.value.assign(nbns.bytes, nbns.bytes + 4);
                    reply.attributes.push_back(a);
                }
            }

            // --> Split-tunnel prefixes as INTERNAL_IP4_SUBNET (address + netmask) for clients
            // that build routes from it (Apple, strongSwan-based Android).
            for (const net::SIpPrefix& route : config.routes) {
                if (route.address.isV4() && wanted(EIKE_CA_INTERNAL_IP4_SUBNET)) {
                    SIkeCfgAttribute a;
                    a.type = EIKE_CA_INTERNAL_IP4_SUBNET;
                    net::SIpPrefix n = route.network();
                    net::SIpAddress m = n.mask();
                    a.value.assign(n.address.bytes, n.address.bytes + 4);
                    a.value.insert(a.value.end(), m.bytes, m.bytes + 4);
                    reply.attributes.push_back(a);
                }
            }

            if (!config.dnsDomain.empty() && wanted(EIKE_CA_INTERNAL_DNS_DOMAIN)) {
                SIkeCfgAttribute a;
                a.type = EIKE_CA_INTERNAL_DNS_DOMAIN;
                a.value.assign(config.dnsDomain.begin(), config.dnsDomain.end());
                reply.attributes.push_back(a);
            }

            std::vector<uint8_t> body;
            EncodeIkeConfig(reply, body);
            resp.push_back(payload(EIKE_PL_CP, std::move(body)));
            return true;
        }

        /**
         * Negotiates and installs a CHILD SA.
         * @param cp CP request (IKE_AUTH only).
         * @param gir Shared secret of the exchange's KE (empty without PFS).
         * @param replaces Child being rekeyed (its reqid is reused).
         * @param kePayload Our KE payload body to append after the nonce (CREATE_CHILD_SA).
         * @return true when a child was installed.
         */
        TTask<bool> createChild(SessionPtr s, std::vector<SIkeProposal> offered, std::vector<SIkeTrafficSelector> tsi,
                                std::vector<SIkeTrafficSelector> tsr, const SIkeConfig* cp, SReadOnlyByteSpan ni,
                                SReadOnlyByteSpan nr, SReadOnlyByteSpan gir, EIkeDhMode dhMode, Child* replaces,
                                std::vector<SIkePayload>& resp, std::vector<SIkePayload>* afterSa) {
            if (cp && !configure(s, *cp, resp)) {
                resp.push_back(MakeIkeNotify(EIKE_N_INTERNAL_ADDRESS_FAILURE));
                co_return false;
            }

            std::vector<SIkeTrafficSelector> allowedI;
            if (s->hasVip) {
                allowedI.push_back(SIkeTrafficSelector::fromPrefix(net::SIpPrefix(s->vip, 32)));
            }
            else {
                for (const net::SIpPrefix& p : config.remoteSubnets) {
                    allowedI.push_back(SIkeTrafficSelector::fromPrefix(p));
                }

                if (allowedI.empty()) {
                    allowedI.push_back(SIkeTrafficSelector::any(false));
                    allowedI.push_back(SIkeTrafficSelector::any(true));
                }
            }

            std::vector<SIkeTrafficSelector> narrowedI;
            std::vector<SIkeTrafficSelector> narrowedR;
            if (!narrow(tsi, allowedI, narrowedI) || !narrow(tsr, localSelectors(), narrowedR)) {
                log(EIKE_LOG_WARNING, "'" + s->identity + "': traffic selectors unacceptable");
                resp.push_back(MakeIkeNotify(EIKE_N_TS_UNACCEPTABLE));
                co_return false;
            }

            IIpsecDataPathPtr path = dataPath;
            SIkeProposal chosen;
            bool ok = SelectIkeProposal(offered, config.espProposals, s->suite.dh, dhMode,
                                        [path](uint16_t encr, uint16_t keyBits, uint16_t integ) {
                                            return path && path->supports(encr, keyBits, integ);
                                        }, chosen);
            if (!ok || chosen.spi.size() != 4 || chosen.protocol != EIKE_PROTO_ESP) {
                std::string text;
                for (const SIkeProposal& p : offered) {
                    text += " " + p.toString();
                }

                log(EIKE_LOG_WARNING, "'" + s->identity + "': no acceptable ESP proposal among" + text);
                resp.push_back(MakeIkeNotify(EIKE_N_NO_PROPOSAL_CHOSEN));
                co_return false;
            }

            Suite child = Suite::from(chosen);
            if (dhMode != EIKE_DHM_REQUIRED) {
                child.dh = EIKE_DH_NONE;
            }

            Child c;
            c.suite = child;
            c.created = CEventLoop::nowMs();
            SIpsecChildSa& sa = c.sa;
            sa.reqid = replaces ? replaces->sa.reqid : newReqid();
            sa.mode = EXMODE_TUNNEL;
            sa.local = AddressOf(s->local);
            sa.remote = AddressOf(s->remote);
            sa.encap = s->natLocal || s->natRemote;
            sa.localPort = s->local.port();
            sa.remotePort = s->remote.port();
            sa.outboundSpi = GetBe32(chosen.spi.data());
            sa.encr = child.encr;
            sa.keyBits = child.keyBits;
            sa.integ = child.integ;
            sa.esn = child.esn == EIKE_ESN_YES;
            sa.localTs = narrowedR;
            sa.remoteTs = narrowedI;

            int32_t r = co_await dataPath->allocateSpi(sa.local, sa.remote, sa.reqid, sa.inboundSpi);
            if (r != SBOX_OK) {
                resp.push_back(MakeIkeNotify(EIKE_N_TEMPORARY_FAILURE));
                co_return false;
            }

            ChildKeys keys;
            r = DeriveChildKeys(s->suite.prf, BytesOf(s->keys.d), gir, ni, nr, child, keys);
            if (r != SBOX_OK) {
                resp.push_back(MakeIkeNotify(EIKE_N_NO_PROPOSAL_CHOSEN));
                co_return false;
            }

            // --> The peer initiated this exchange: initiator-to-responder keys protect what we
            // receive.
            sa.inEncKey = keys.encIr;
            sa.inIntegKey = keys.integIr;
            sa.outEncKey = keys.encRi;
            sa.outIntegKey = keys.integRi;
            keys.wipe();

            r = co_await dataPath->installChild(sa);
            if (r != SBOX_OK) {
                log(EIKE_LOG_ERROR, "'" + s->identity + "': installing CHILD SA failed (" + std::to_string(r) + ")");
                resp.push_back(MakeIkeNotify(EIKE_N_TEMPORARY_FAILURE));
                co_return false;
            }

            chosen.spi.clear();
            PutBe32(chosen.spi, sa.inboundSpi);
            std::vector<uint8_t> body;
            EncodeIkeSa({ chosen }, body);
            resp.push_back(payload(EIKE_PL_SA, std::move(body)));

            if (afterSa) {
                for (SIkePayload& pl : *afterSa) {
                    resp.push_back(std::move(pl));
                }
            }

            body.clear();
            EncodeIkeTs(narrowedI, body);
            resp.push_back(payload(EIKE_PL_TSI, std::move(body)));
            body.clear();
            EncodeIkeTs(narrowedR, body);
            resp.push_back(payload(EIKE_PL_TSR, std::move(body)));

            std::string tsText;
            for (const SIkeTrafficSelector& t : narrowedI) {
                tsText += t.toString() + " ";
            }

            tsText += "===";
            for (const SIkeTrafficSelector& t : narrowedR) {
                tsText += " " + t.toString();
            }

            char spis[32];
            std::snprintf(spis, sizeof(spis), "%08x_i %08x_o", sa.inboundSpi, sa.outboundSpi);
            log(EIKE_LOG_INFO, "'" + s->identity + "': CHILD SA " + spis + " " + FormatIkeProposal(chosen) + " " + tsText
                + (s->hasVip ? " vip " + s->vip.toString() : std::string()) + (sa.encap ? " (UDP encap)" : ""));

            if (replaces) {
                replaces->replaced = true;
                replaces->replacedAt = CEventLoop::nowMs();
            }

            s->children.push_back(std::move(c));
            co_return true;
        }

        // ------------------------------------------------------------------------------------
        // CREATE_CHILD_SA

        /* Handles CREATE_CHILD_SA (CHILD SA creation/rekey and IKE SA rekey). */
        TTask<void> onCreateChild(SessionPtr s, std::vector<SIkePayload>& payloads, std::vector<SIkePayload>& resp) {
            if (s->state != ST_ESTABLISHED || s->rekeyedTo) {
                resp.push_back(MakeIkeNotify(EIKE_N_TEMPORARY_FAILURE));
                co_return;
            }

            const SIkePayload* saPl = FindIkePayload(payloads, EIKE_PL_SA);
            const SIkePayload* noncePl = FindIkePayload(payloads, EIKE_PL_NONCE);
            const SIkePayload* kePl = FindIkePayload(payloads, EIKE_PL_KE);
            std::vector<SIkeProposal> offered;
            if (!saPl || !noncePl || DecodeIkeSa(BytesOf(saPl->body), offered) != SBOX_OK || offered.empty()
                || noncePl->body.size() < 16 || noncePl->body.size() > 256) {
                resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                co_return;
            }

            uint16_t keGroup = 0;
            std::vector<uint8_t> keData;
            if (kePl && DecodeIkeKe(BytesOf(kePl->body), keGroup, keData) != SBOX_OK) {
                resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                co_return;
            }

            std::vector<uint8_t> nr(32);
            IkeRandom(BytesOf(nr));

            if (offered[0].protocol == EIKE_PROTO_IKE) {
                co_await rekeyIke(s, offered, noncePl->body, kePl ? keGroup : 0, keData, nr, resp);
                co_return;
            }

            std::vector<SIkeNotify> notifies = notifiesOf(payloads);
            Child* old = nullptr;
            if (const SIkeNotify* rekey = findNotify(notifies, EIKE_N_REKEY_SA)) {
                if (rekey->protocol != EIKE_PROTO_ESP || rekey->spi.size() != 4) {
                    resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                    co_return;
                }

                uint32_t spi = GetBe32(rekey->spi.data());
                for (Child& c : s->children) {
                    if (c.sa.outboundSpi == spi && !c.replaced) {
                        old = &c;
                        break;
                    }
                }

                if (!old) {
                    SIkeNotify n;
                    n.protocol = EIKE_PROTO_ESP;
                    n.spi = rekey->spi;
                    n.type = EIKE_N_CHILD_SA_NOT_FOUND;
                    SIkePayload pl;
                    pl.type = EIKE_PL_NOTIFY;
                    EncodeIkeNotify(n, pl.body);
                    resp.push_back(std::move(pl));
                    co_return;
                }
            }

            const SIkePayload* tsiPl = FindIkePayload(payloads, EIKE_PL_TSI);
            const SIkePayload* tsrPl = FindIkePayload(payloads, EIKE_PL_TSR);
            std::vector<SIkeTrafficSelector> tsi;
            std::vector<SIkeTrafficSelector> tsr;
            if (!tsiPl || !tsrPl || DecodeIkeTs(BytesOf(tsiPl->body), tsi) != SBOX_OK || DecodeIkeTs(BytesOf(tsrPl->body), tsr) != SBOX_OK) {
                resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                co_return;
            }

            // --> PFS: the KE group must be the one the selected proposal uses.
            std::vector<uint8_t> gir;
            std::vector<SIkePayload> keResp;
            if (kePl) {
                IIpsecDataPathPtr path = dataPath;
                SIkeProposal probe;
                if (!SelectIkeProposal(offered, config.espProposals, keGroup, EIKE_DHM_REQUIRED,
                                       [path](uint16_t e, uint16_t k, uint16_t i) { return path && path->supports(e, k, i); }, probe)) {
                    resp.push_back(MakeIkeNotify(EIKE_N_NO_PROPOSAL_CHOSEN));
                    co_return;
                }

                uint16_t group = Suite::from(probe).dh;
                if (group != keGroup) {
                    std::vector<uint8_t> g;
                    PutBe16(g, group);
                    resp.push_back(MakeIkeNotify(EIKE_N_INVALID_KE_PAYLOAD, BytesOf(g)));
                    co_return;
                }

                CIkeDh dh;
                if (dh.generate(group) != SBOX_OK || dh.agree(BytesOf(keData), gir) != SBOX_OK) {
                    resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                    co_return;
                }

                std::vector<uint8_t> body;
                EncodeIkeKe(group, BytesOf(dh.publicValue()), body);
                keResp.push_back(payload(EIKE_PL_KE, std::move(body)));
            }

            std::vector<SIkePayload> after;
            after.push_back(payload(EIKE_PL_NONCE, nr));
            for (SIkePayload& pl : keResp) {
                after.push_back(std::move(pl));
            }

            uint32_t oldReqid = old ? old->sa.reqid : 0;
            uint32_t oldOut = old ? old->sa.outboundSpi : 0;
            Child copy;
            if (old) {
                copy = *old;
            }

            bool installed = co_await createChild(s, offered, tsi, tsr, nullptr, BytesOf(noncePl->body), BytesOf(nr),
                                                  BytesOf(gir), kePl ? EIKE_DHM_REQUIRED : EIKE_DHM_NONE,
                                                  old ? &copy : nullptr, resp, &after);
            IkeWipe(gir);

            // --> createChild() may have grown the vector; mark the original by SPI.
            if (installed && old) {
                for (Child& c : s->children) {
                    if (c.sa.reqid == oldReqid && c.sa.outboundSpi == oldOut) {
                        c.replaced = true;
                        c.replacedAt = CEventLoop::nowMs();
                    }
                }
            }
        }

        /* Rekeys the IKE SA (RFC 7296 2.18). */
        TTask<void> rekeyIke(SessionPtr s, const std::vector<SIkeProposal>& offered, const std::vector<uint8_t>& ni, uint16_t keGroup,
                             const std::vector<uint8_t>& keData, const std::vector<uint8_t>& nr, std::vector<SIkePayload>& resp) {
            SIkeProposal chosen;
            if (!SelectIkeProposal(offered, config.ikeProposals, keGroup, EIKE_DHM_REQUIRED, nullptr, chosen) || chosen.spi.size() != 8) {
                resp.push_back(MakeIkeNotify(EIKE_N_NO_PROPOSAL_CHOSEN));
                co_return;
            }

            Suite suite = Suite::from(chosen);
            if (keGroup != suite.dh) {
                std::vector<uint8_t> g;
                PutBe16(g, suite.dh);
                resp.push_back(MakeIkeNotify(EIKE_N_INVALID_KE_PAYLOAD, BytesOf(g)));
                co_return;
            }

            CIkeDh dh;
            std::vector<uint8_t> gir;
            if (dh.generate(suite.dh) != SBOX_OK || dh.agree(BytesOf(keData), gir) != SBOX_OK) {
                resp.push_back(MakeIkeNotify(EIKE_N_INVALID_SYNTAX));
                co_return;
            }

            auto n = std::make_shared<Session>();
            n->spiI = GetBe64(chosen.spi.data());
            do {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&n->spiR), sizeof(n->spiR)));
            } while (n->spiR == 0 || sessions.count(n->spiR));

            n->initiator = false;
            n->suite = suite;
            n->ni = ni;
            n->nr = nr;

            std::vector<uint8_t> skeyseed;
            int32_t r = ComputeRekeySkeyseed(s->suite.prf, BytesOf(s->keys.d), BytesOf(gir), BytesOf(ni), BytesOf(nr), skeyseed);
            IkeWipe(gir);
            if (r != SBOX_OK || n->installKeys(BytesOf(skeyseed)) != SBOX_OK) {
                IkeWipe(skeyseed);
                resp.push_back(MakeIkeNotify(EIKE_N_NO_PROPOSAL_CHOSEN));
                co_return;
            }

            IkeWipe(skeyseed);

            int64_t now = CEventLoop::nowMs();
            n->state = ST_ESTABLISHED;
            n->created = now;
            n->lastSeen = now;
            n->establishedAt = now;
            n->local = s->local;
            n->remote = s->remote;
            n->natT = s->natT;
            n->natLocal = s->natLocal;
            n->natRemote = s->natRemote;
            n->fragmentation = s->fragmentation;
            n->peerFragmentation = s->peerFragmentation;
            n->fragmentSize = s->fragmentSize;
            n->peerHashes = s->peerHashes;
            n->idi = s->idi;
            n->idrBody = s->idrBody;
            n->identity = s->identity;
            n->mobike = s->mobike;
            n->children = std::move(s->children);
            s->children.clear();
            n->hasVip = s->hasVip;
            n->vip = s->vip;
            if (n->hasVip) {
                pool.transfer(n->vip, n->spiR);
            }

            s->hasVip = false;
            s->rekeyedTo = n->spiR;
            s->rekeyedAt = now;
            n->proposalText = FormatIkeProposal(chosen);
            sessions[n->spiR] = n;

            chosen.spi.clear();
            PutBe64(chosen.spi, n->spiR);
            std::vector<uint8_t> body;
            EncodeIkeSa({ chosen }, body);
            resp.push_back(payload(EIKE_PL_SA, std::move(body)));
            resp.push_back(payload(EIKE_PL_NONCE, nr));
            body.clear();
            EncodeIkeKe(suite.dh, BytesOf(dh.publicValue()), body);
            resp.push_back(payload(EIKE_PL_KE, std::move(body)));

            log(EIKE_LOG_INFO, "'" + n->identity + "': IKE SA rekeyed " + spiText(s->spiI, s->spiR) + " -> " + spiText(n->spiI, n->spiR));
        }

        // ------------------------------------------------------------------------------------
        // INFORMATIONAL

        /* Handles INFORMATIONAL (DPD, DELETE, MOBIKE). */
        TTask<void> onInformational(SessionPtr s, SIkeDatagram& dg, std::vector<SIkePayload>& payloads, std::vector<SIkePayload>& resp) {
            std::vector<uint32_t> ourSpis;
            for (const SIkePayload& pl : payloads) {
                if (pl.type != EIKE_PL_DELETE) {
                    continue;
                }

                SIkeDelete del;
                if (DecodeIkeDelete(BytesOf(pl.body), del) != SBOX_OK) {
                    continue;
                }

                if (del.protocol == EIKE_PROTO_IKE) {
                    log(EIKE_LOG_INFO, "'" + s->identity + "': peer deleted IKE SA " + spiText(s->spiI, s->spiR));
                    s->deleteAfterResponse = true;
                    resp.clear();
                    co_return;
                }

                if (del.protocol != EIKE_PROTO_ESP) {
                    continue;
                }

                for (uint32_t spi : del.spis) {
                    for (size_t i = 0; i < s->children.size(); ++i) {
                        if (s->children[i].sa.outboundSpi != spi) {
                            continue;
                        }

                        Child c = s->children[i];
                        s->children.erase(s->children.begin() + long(i));
                        ourSpis.push_back(c.sa.inboundSpi);
                        co_await removeChild(s, c);
                        break;
                    }
                }
            }

            if (!ourSpis.empty()) {
                SIkeDelete del;
                del.protocol = EIKE_PROTO_ESP;
                del.spis = ourSpis;
                std::vector<uint8_t> body;
                EncodeIkeDelete(del, body);
                resp.push_back(payload(EIKE_PL_DELETE, std::move(body)));
            }

            std::vector<SIkeNotify> notifies = notifiesOf(payloads);
            if (findNotify(notifies, EIKE_N_UPDATE_SA_ADDRESSES) && s->mobike) {
                co_await moveSession(s, dg);

                // --> RFC 4555 3.5: recompute NAT state from the request's NAT_D payloads.
                bool sawNatD = false;
                bool srcMatch = false;
                bool dstMatch = false;
                std::vector<uint8_t> remoteHash = NatHash(s->spiI, s->spiR, dg.remote);
                std::vector<uint8_t> localHash = NatHash(s->spiI, s->spiR, dg.local);
                for (const SIkeNotify& n : notifies) {
                    if (n.type == EIKE_N_NAT_DETECTION_SOURCE_IP) {
                        sawNatD = true;
                        srcMatch = srcMatch || n.data == remoteHash;
                    }
                    else if (n.type == EIKE_N_NAT_DETECTION_DESTINATION_IP) {
                        sawNatD = true;
                        dstMatch = dstMatch || n.data == localHash;
                    }
                }

                if (sawNatD) {
                    s->natRemote = !srcMatch;
                    s->natLocal = !dstMatch || config.forceEncap;
                    std::vector<uint8_t> src = NatHash(s->spiI, s->spiR, dg.local);
                    if (config.forceEncap) {
                        IkeRandom(BytesOf(src));
                    }

                    resp.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_SOURCE_IP, BytesOf(src)));
                    std::vector<uint8_t> dst = NatHash(s->spiI, s->spiR, dg.remote);
                    resp.push_back(MakeIkeNotify(EIKE_N_NAT_DETECTION_DESTINATION_IP, BytesOf(dst)));
                }

                log(EIKE_LOG_INFO, "'" + s->identity + "': MOBIKE update to " + dg.remote.toString());
            }

            if (const SIkeNotify* c2 = findNotify(notifies, EIKE_N_COOKIE2)) {
                resp.push_back(MakeIkeNotify(EIKE_N_COOKIE2, BytesOf(c2->data)));
            }
        }

        /* Moves a session and its children to the datagram's addresses. */
        TTask<void> moveSession(SessionPtr s, const SIkeDatagram& dg) {
            s->local = dg.local;
            s->remote = dg.remote;
            s->natT = dg.natT;
            for (Child& c : s->children) {
                c.sa.local = AddressOf(dg.local);
                c.sa.remote = AddressOf(dg.remote);
                c.sa.localPort = dg.local.port();
                c.sa.remotePort = dg.remote.port();
                c.sa.encap = c.sa.encap || dg.natT;
                co_await dataPath->updateChild(c.sa);
            }
        }

        // ------------------------------------------------------------------------------------
        // Lifecycle

        /* Removes one child from the data path. */
        TTask<void> removeChild(SessionPtr s, const Child& c) {
            bool lastOfReqid = true;
            for (const Child& other : s->children) {
                lastOfReqid = lastOfReqid && other.sa.reqid != c.sa.reqid;
            }

            co_await dataPath->removeChild(c.sa, lastOfReqid);
        }

        /* Tears an IKE SA down. */
        TTask<void> destroy(SessionPtr s, bool notifyPeer) {
            if (s->state == ST_DEAD) {
                co_return;
            }

            if (notifyPeer && s->state == ST_ESTABLISHED && !s->pending) {
                SIkeDelete del;
                del.protocol = EIKE_PROTO_IKE;
                std::vector<uint8_t> body;
                EncodeIkeDelete(del, body);
                std::vector<SIkePayload> payloads;
                payloads.push_back(payload(EIKE_PL_DELETE, std::move(body)));
                std::vector<std::vector<uint8_t>> datagrams;
                if (s->encrypt(EIKE_X_INFORMATIONAL, false, s->nextMid, payloads, datagrams) == SBOX_OK) {
                    sendAll(datagrams, s->local, s->remote, s->natT);
                }
            }

            s->state = ST_DEAD;
            std::vector<Child> children = std::move(s->children);
            s->children.clear();
            for (size_t i = 0; i < children.size(); ++i) {
                bool lastOfReqid = true;
                for (size_t j = i + 1; j < children.size(); ++j) {
                    lastOfReqid = lastOfReqid && children[j].sa.reqid != children[i].sa.reqid;
                }

                co_await dataPath->removeChild(children[i].sa, lastOfReqid);
            }

            if (s->hasVip) {
                pool.release(s->vip, s->spiR);
                s->hasVip = false;
            }

            halfOpen.erase(s->halfOpenKey);
            sessions.erase(s->spiR);
            s->keys.wipe();

            if (!s->identity.empty() && !s->rekeyedTo) {
                log(EIKE_LOG_INFO, "'" + s->identity + "': IKE SA " + spiText(s->spiI, s->spiR) + " closed");
            }
        }

        /* Timer work: retransmissions, DPD, expiry. */
        TTask<void> tick() {
            int64_t now = CEventLoop::nowMs();
            std::vector<SessionPtr> all;
            for (auto& [spi, s] : sessions) {
                (void)spi;
                all.push_back(s);
            }

            for (const SessionPtr& s : all) {
                if (s->state == ST_DEAD) {
                    continue;
                }

                if (s->state != ST_ESTABLISHED) {
                    if (now - s->created > int64_t(config.halfOpenSeconds) * 1000) {
                        log(EIKE_LOG_DEBUG, s->remote.toString() + ": half-open IKE SA timed out");
                        co_await destroy(s, false);
                    }

                    continue;
                }

                if (s->rekeyedTo) {
                    // --> The peer should have deleted the old IKE SA right after rekeying.
                    if (now - s->rekeyedAt > 60000) {
                        co_await destroy(s, false);
                    }

                    continue;
                }

                if (s->pending) {
                    if (now >= s->retransmitAt) {
                        if (uint32_t(s->retries) + 1 >= config.retransmitTries) {
                            log(EIKE_LOG_INFO, "'" + s->identity + "': peer " + s->remote.toString() + " is not responding, removing");
                            co_await destroy(s, false);
                            continue;
                        }

                        ++s->retries;
                        sendAll(s->pendingRequest, s->local, s->remote, s->natT);
                        s->retransmitAt = now + int64_t(config.retransmitBaseMs) * (int64_t(1) << s->retries);
                    }
                }
                else if (config.ikeLifetimeSeconds && now - s->establishedAt > int64_t(config.ikeLifetimeSeconds) * 1000) {
                    log(EIKE_LOG_INFO, "'" + s->identity + "': IKE SA lifetime exceeded without rekey");
                    sendDelete(s);
                }
                else if (config.dpdSeconds && now - s->lastSeen > int64_t(config.dpdSeconds) * 1000) {
                    request(s, EIKE_X_INFORMATIONAL, {});
                }

                // --> Behind a NAT ourselves: keep the mapping alive (RFC 3948 2.3).
                if (s->natLocal && s->natT && now - s->lastKeepalive > 20000) {
                    socket.sendKeepalive(s->local, s->remote);
                    s->lastKeepalive = now;
                }

                // --> Rekeyed children the peer never deleted.
                for (size_t i = 0; i < s->children.size();) {
                    if (s->children[i].replaced && now - s->children[i].replacedAt > 60000) {
                        Child c = s->children[i];
                        s->children.erase(s->children.begin() + long(i));
                        co_await removeChild(s, c);
                    }
                    else {
                        ++i;
                    }
                }
            }
        }

        /* Sends DELETE for the IKE SA and removes it once answered. */
        void sendDelete(const SessionPtr& s) {
            SIkeDelete del;
            del.protocol = EIKE_PROTO_IKE;
            std::vector<uint8_t> body;
            EncodeIkeDelete(del, body);
            std::vector<SIkePayload> payloads;
            payloads.push_back(payload(EIKE_PL_DELETE, std::move(body)));
            s->deleting = true;
            request(s, EIKE_X_INFORMATIONAL, payloads);
        }

        /* Disconnects sessions by identity or virtual IP. */
        TTask<int32_t> disconnectMatching(std::string what) {
            std::vector<SessionPtr> matches;
            for (auto& [spi, s] : sessions) {
                (void)spi;
                if (s->state == ST_ESTABLISHED && (s->identity == what || (s->hasVip && s->vip.toString() == what))) {
                    matches.push_back(s);
                }
            }

            for (const SessionPtr& s : matches) {
                co_await destroy(s, true);
            }

            co_return int32_t(matches.size());
        }

        /* Stops everything. */
        TTask<void> shutdown() {
            stopped = true;
            running = false;
            std::vector<SessionPtr> all;
            for (auto& [spi, s] : sessions) {
                (void)spi;
                all.push_back(s);
            }

            for (const SessionPtr& s : all) {
                co_await destroy(s, true);
            }

            if (dataPath) {
                co_await dataPath->stop();
            }

            socket.close();
        }
    };

    CIkeServer::CIkeServer(SIkeServerConfig config) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
    }

    CIkeServer::~CIkeServer() {
        if (_state) {
            _state->stopped = true;
            _state->running = false;
            _state->queue.close();
            _state->socket.close();
        }
    }

    /* Installs the log sink. */
    void CIkeServer::logger(std::function<void(EIkeLogLevel, const std::string&)> sink) {
        _state->sink = std::move(sink);
    }

    /* Starts serving. */
    TTask<int32_t> CIkeServer::start(IIpsecDataPathPtr dataPath) {
        SState& st = *_state;
        st.loop = CEventLoop::current();
        if (!st.loop || st.running) {
            co_return -EINVAL;
        }

        SIkeServerConfig& c = st.config;
        if (c.ikeProposals.empty()) {
            c.ikeProposals = DefaultIkeProposals();
        }

        if (c.espProposals.empty()) {
            c.espProposals = DefaultEspProposals();
        }

        if (c.users.empty() && c.psks.empty() && c.caCertificates.empty()) {
            st.log(EIKE_LOG_ERROR, "no users, pre-shared keys or client CAs configured");
            co_return -EINVAL;
        }

        if (!c.users.empty() && !c.certificate.hasPrivateKey()) {
            st.log(EIKE_LOG_ERROR, "EAP users need a server certificate with its private key");
            co_return -EINVAL;
        }

        st.userHashes.clear();
        for (const SIkeUser& u : c.users) {
            std::vector<uint8_t> hash = u.ntHash;
            if (hash.size() != 16) {
                hash.assign(16, 0);
                if (MsChapNtPasswordHash(u.password, BytesOf(hash)) != SBOX_OK) {
                    st.log(EIKE_LOG_ERROR, "user '" + u.name + "': password is not valid UTF-8");
                    co_return -EINVAL;
                }
            }

            st.userHashes.push_back(std::move(hash));
        }

        st.pool.reset(c.pool);
        if (c.pool.isValid() && !st.pool.valid()) {
            st.log(EIKE_LOG_ERROR, "address pool " + c.pool.toString() + " is too small or not IPv4");
            co_return -EINVAL;
        }

        st.cookieSecret.assign(32, 0);
        IkeRandom(BytesOf(st.cookieSecret));

        SIkeSocketOptions so;
        so.address = c.listenAddress;
        so.port = c.port;
        so.natPort = c.natPort;
        so.ipv6 = c.ipv6;
        so.netnsPath = c.netnsPath;
        int32_t r = st.socket.open(so);
        if (r != SBOX_OK) {
            st.log(EIKE_LOG_ERROR, "cannot bind UDP " + std::to_string(c.port) + "/" + std::to_string(c.natPort) + " (" + std::to_string(r) + ")");
            co_return r;
        }

        SIpsecDataPathOptions dpo = c.dataPath;
        dpo.netnsPath = c.netnsPath;
        if (st.pool.valid()) {
            net::SIpPrefix gw(st.pool.gateway(), c.pool.length);
            dpo.addresses.push_back(gw);
        }

        if (!dataPath) {
            r = co_await CreateIpsecDataPath(dpo, dataPath);
            if (r != SBOX_OK) {
                st.socket.close();
                co_return r;
            }
        }

        st.dataPath = dataPath;
        st.dataPath->attachSocket(&st.socket);
        r = co_await st.dataPath->start();
        if (r != SBOX_OK) {
            st.log(EIKE_LOG_ERROR, std::string("data path (") + st.dataPath->kind() + ") failed to start (" + std::to_string(r) + ")");
            st.socket.close();
            co_return r;
        }

        if (c.forwarding) {
            net::WriteSysctl("net.ipv4.ip_forward", "1", c.netnsPath);
        }

        if (!c.bridge.empty()) {
            net::WriteSysctl("net.ipv4.conf." + c.bridge + ".proxy_arp", "1", c.netnsPath);
        }

        std::weak_ptr<SState> weak = _state;
        st.socket.start([weak](SIkeDatagram& dg) {
            if (auto s = weak.lock()) {
                WorkItem w;
                w.kind = WORK_DATAGRAM;
                w.datagram = std::move(dg);
                s->queue.push(std::move(w));
            }
        });

        st.running = true;
        st.loop->spawn(SState::processor(_state));
        st.loop->spawn(SState::ticker(_state));
        st.log(EIKE_LOG_INFO, "IKEv2 responder listening on UDP " + std::to_string(st.socket.port()) + "/"
               + std::to_string(st.socket.natPort()) + ", data path " + st.dataPath->kind()
               + (st.dataPath->interfaceName().empty() ? std::string() : " (" + st.dataPath->interfaceName() + ")"));
        co_return SBOX_OK;
    }

    /* Stops serving. */
    TTask<void> CIkeServer::stop() {
        if (!_state->running && !_state->dataPath) {
            co_return;
        }

        auto done = std::make_shared<Completion>();
        WorkItem w;
        w.kind = WORK_STOP;
        w.completion = done;
        _state->queue.push(std::move(w));
        if (co_await done->done.wait()) {
            done->done.pop();
        }
    }

    /* IKEv1 forwarding. */
    void CIkeServer::ikev1Handler(FIkeDatagramHandler handler) {
        _state->v1 = std::move(handler);
    }

    /* Shared sockets. */
    CIkeSocket* CIkeServer::socket() noexcept {
        return &_state->socket;
    }

    /* Bound IKE port. */
    uint16_t CIkeServer::port() const noexcept {
        return _state->socket.port();
    }

    /* Bound NAT-T port. */
    uint16_t CIkeServer::natPort() const noexcept {
        return _state->socket.natPort();
    }

    /* Data path. */
    IIpsecDataPathPtr CIkeServer::dataPath() const {
        return _state->dataPath;
    }

    /* Session snapshot. */
    std::vector<SIkeSessionInfo> CIkeServer::sessions() const {
        std::vector<SIkeSessionInfo> out;
        for (auto& [spi, s] : _state->sessions) {
            (void)spi;
            SIkeSessionInfo info;
            info.spiI = s->spiI;
            info.spiR = s->spiR;
            info.state = stateName(s->state);
            info.identity = s->identity;
            info.remote = s->remote.toString();
            info.virtualIp = s->hasVip ? s->vip.toString() : std::string();
            info.proposal = s->proposalText;
            info.nat = s->natLocal || s->natRemote;
            info.establishedMs = s->establishedAt;
            for (const Child& c : s->children) {
                SIkeChildInfo ci;
                ci.inboundSpi = c.sa.inboundSpi;
                ci.outboundSpi = c.sa.outboundSpi;
                SIkeProposal p;
                p.protocol = EIKE_PROTO_ESP;
                SIkeTransform t;
                t.type = EIKE_TT_ENCR;
                t.id = c.suite.encr;
                t.keyLength = c.suite.keyBits;
                p.transforms.push_back(t);
                if (c.suite.integ) {
                    t = SIkeTransform();
                    t.type = EIKE_TT_INTEG;
                    t.id = c.suite.integ;
                    p.transforms.push_back(t);
                }

                ci.proposal = FormatIkeProposal(p);
                for (const SIkeTrafficSelector& ts : c.sa.localTs) {
                    ci.localTs.push_back(ts.toString());
                }

                for (const SIkeTrafficSelector& ts : c.sa.remoteTs) {
                    ci.remoteTs.push_back(ts.toString());
                }

                info.children.push_back(std::move(ci));
            }

            out.push_back(std::move(info));
        }

        return out;
    }

    /* Disconnects sessions. */
    TTask<int32_t> CIkeServer::disconnect(std::string identityOrAddress) {
        if (!_state->running) {
            co_return 0;
        }

        auto done = std::make_shared<Completion>();
        WorkItem w;
        w.kind = WORK_DISCONNECT;
        w.text = std::move(identityOrAddress);
        w.completion = done;
        _state->queue.push(std::move(w));
        if (!co_await done->done.wait()) {
            co_return 0;
        }

        co_return done->done.pop();
    }

}
}
