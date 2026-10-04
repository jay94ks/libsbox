#include <sbox/vpn/wg/engine.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/vpn/wg/allowedips.hpp>
#include "noise.hpp"

#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <certpp/utils/secure.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <string>
#include <unordered_map>

namespace sbox {
namespace vpn {

    namespace {

        constexpr int64_t NONE = INT64_MAX;
        constexpr int64_t NEVER = -(int64_t(1) << 60);     // --> "Long ago", safe to subtract from.
        constexpr int64_t JITTER_MAX_MS = 333;
        constexpr int64_t INITIATIONS_PER_SECOND = 50;

        /* Returns the address bytes and port of an IP endpoint; false for other families. */
        bool endpointAddress(const SEndpoint& ep, const uint8_t*& addr, size_t& length, uint16_t& port) noexcept {
            if (ep.family() == AF_INET) {
                const sockaddr_in* sa = reinterpret_cast<const sockaddr_in*>(&ep.storage);
                addr = reinterpret_cast<const uint8_t*>(&sa->sin_addr);
                length = 4;
                port = ntohs(sa->sin_port);
                return true;
            }

            if (ep.family() == AF_INET6) {
                const sockaddr_in6* sa = reinterpret_cast<const sockaddr_in6*>(&ep.storage);
                addr = reinterpret_cast<const uint8_t*>(&sa->sin6_addr);
                length = 16;
                port = ntohs(sa->sin6_port);
                return true;
            }

            return false;
        }

        /* Compares two IP endpoints (address and port). */
        bool sameEndpoint(const SEndpoint& a, const SEndpoint& b) noexcept {
            const uint8_t* aa = nullptr;
            const uint8_t* ba = nullptr;
            size_t al = 0, bl = 0;
            uint16_t ap = 0, bp = 0;
            if (!endpointAddress(a, aa, al, ap) || !endpointAddress(b, ba, bl, bp)) {
                return false;
            }

            return al == bl && ap == bp && std::memcmp(aa, ba, al) == 0;
        }

        /* Returns a uniformly random value in [0, bound). */
        int64_t randomBelow(int64_t bound) noexcept {
            uint32_t v = 0;
            NoiseRandom(reinterpret_cast<uint8_t*>(&v), sizeof(v));
            return bound > 0 ? int64_t(v % uint32_t(bound)) : 0;
        }

        /* Constant-time 16-byte comparison. */
        bool macEquals(const uint8_t* a, const uint8_t* b) noexcept {
            return certpp::CSecure::equals(certpp::SReadOnlyByteSpan(a, NOISE_MAC_BYTES), certpp::SReadOnlyByteSpan(b, NOISE_MAC_BYTES));
        }

        /* Hash functor over 32-byte keys held in strings. */
        struct KeyHash {
            size_t operator()(const std::string& k) const noexcept {
                size_t h = 0;
                std::memcpy(&h, k.data(), sizeof(h) < k.size() ? sizeof(h) : k.size());
                return h;
            }
        };

        /* Returns the map key of a public key. */
        inline std::string keyOf(const SWgKey& k) {
            return std::string(reinterpret_cast<const char*>(k.bytes), WG_KEY_BYTES);
        }

        /* One transport session. */
        struct Keypair {
            certpp::crypto::CChaCha20Poly1305 sendAead;
            certpp::crypto::CChaCha20Poly1305 recvAead;
            uint64_t sendCounter = 0;
            CWgReplayWindow replay;
            uint32_t localIndex = 0;
            uint32_t remoteIndex = 0;
            int64_t created = 0;
            bool initiator = false;
        };

        enum HandshakeState {
            HS_NONE = 0,
            HS_INITIATION_SENT,         // --> Waiting for the response; hs.localIndex is registered.
        };

        /* A staged plaintext packet waiting for a session. */
        struct Staged {
            uint8_t* buffer;
            size_t length;
        };

        /* Per-peer state. */
        struct Peer {
            uint64_t id = 0;
            SWgKey publicKey;
            uint8_t psk[32];
            bool hasPsk = false;
            uint8_t staticStatic[32];
            bool staticStaticValid = false;
            uint8_t mac1Key[32];            // --> HASH("mac1----" || peer key): MAC1 of what we send it.
            uint8_t cookieKey[32];          // --> HASH("cookie--" || peer key): opens its cookie replies.
            SEndpoint endpoint;
            uint16_t keepalive = 0;

            // -- Handshake.
            NoiseHandshake hs;
            HandshakeState hsState = HS_NONE;
            uint8_t latestTimestamp[NOISE_TIMESTAMP_BYTES];
            int64_t lastInitiationConsumed = NEVER;
            int64_t lastHandshakeSent = NEVER;
            uint32_t attempts = 0;
            uint8_t lastMac1[NOISE_MAC_BYTES];
            bool hasSentMac1 = false;
            uint8_t cookie[NOISE_COOKIE_BYTES];
            int64_t cookieBirth = NEVER;
            bool hasCookie = false;

            // -- Sessions.
            std::unique_ptr<Keypair> current;
            std::unique_ptr<Keypair> previous;
            std::unique_ptr<Keypair> next;

            // -- Timers (deadlines in clock ms, NONE when not armed).
            int64_t tRetransmit = NONE;
            int64_t tSendKeepalive = NONE;
            int64_t tNewHandshake = NONE;
            int64_t tZeroKeys = NONE;
            int64_t tPersistent = NONE;
            bool needAnotherKeepalive = false;
            bool sentLastMinuteHandshake = false;

            std::deque<Staged> staged;

            // -- Statistics.
            uint64_t rxBytes = 0;
            uint64_t txBytes = 0;
            int64_t lastHandshakeSec = 0;
            int64_t lastHandshakeNsec = 0;

            Peer() {
                std::memset(psk, 0, sizeof(psk));
                std::memset(staticStatic, 0, sizeof(staticStatic));
                std::memset(mac1Key, 0, sizeof(mac1Key));
                std::memset(cookieKey, 0, sizeof(cookieKey));
                std::memset(latestTimestamp, 0, sizeof(latestTimestamp));
                std::memset(lastMac1, 0, sizeof(lastMac1));
                std::memset(cookie, 0, sizeof(cookie));
                std::memset(&hs, 0, sizeof(hs));
            }

            ~Peer() {
                NoiseWipe(psk, sizeof(psk));
                NoiseWipe(staticStatic, sizeof(staticStatic));
                hs.clear();
            }
        };

        /* Token bucket per source (under load only). */
        struct Bucket {
            double tokens;
            int64_t last;
        };

    }

    /* Engine internals. */
    struct CWgEngine::SImpl {
        IWgOutput* output;
        SWgEngineOptions options;
        SWgEngineStats stats;

        SWgKey privateKey;
        SWgKey publicKey;
        uint8_t mac1KeySelf[32];        // --> Validates MAC1 of what peers send us.
        uint8_t cookieKeySelf[32];      // --> Seals the cookie replies we send.

        std::unordered_map<std::string, std::unique_ptr<Peer>, KeyHash> peers;
        std::vector<Peer*> order;       // --> Insertion order for listings.
        std::unordered_map<uint32_t, Peer*> indices;
        CWgAllowedIps allowedIps;
        uint64_t nextPeerId = 1;

        // -- Cookies and load.
        uint8_t cookieSecret[32];
        int64_t cookieSecretBirth = NEVER;
        int64_t loadWindowStart = 0;
        uint32_t loadWindowCount = 0;
        int64_t underLoadUntil = NEVER;
        bool forcedUnderLoad = false;
        std::unordered_map<uint64_t, Bucket> buckets;

        int64_t earliest = NONE;
        CWgBufferPool pool;

        SImpl(IWgOutput* out, SWgEngineOptions opts)
            : output(out), options(std::move(opts)),
              pool(WG_DATA_HEADROOM + (options.mtu < 1500 ? 1500 : options.mtu) + WG_DATA_TAILROOM, 4096)
        {
            std::memset(mac1KeySelf, 0, sizeof(mac1KeySelf));
            std::memset(cookieKeySelf, 0, sizeof(cookieKeySelf));
            std::memset(cookieSecret, 0, sizeof(cookieSecret));
        }

        ~SImpl() {
            for (auto& kv : peers) {
                dropStaged(*kv.second);
            }

            NoiseWipe(cookieSecret, sizeof(cookieSecret));
            privateKey.clear();
        }

        /* Returns the clock. */
        int64_t now() const {
            return options.clock ? options.clock() : CEventLoop::nowMs();
        }

        /* Arms a timer slot. */
        void arm(int64_t& slot, int64_t at) noexcept {
            slot = at;
            if (at < earliest) {
                earliest = at;
            }
        }

        /* Returns the wall clock now. */
        static void wallNow(int64_t& sec, int64_t& nsec) noexcept {
            timespec ts;
            ::clock_gettime(CLOCK_REALTIME, &ts);
            sec = ts.tv_sec;
            nsec = ts.tv_nsec;
        }

        // -- Index table.

        /* Allocates and registers a fresh random index for `peer`. */
        uint32_t newIndex(Peer* peer) {
            for (;;) {
                uint32_t idx = 0;
                NoiseRandom(reinterpret_cast<uint8_t*>(&idx), sizeof(idx));
                if (idx != 0 && indices.find(idx) == indices.end()) {
                    indices.emplace(idx, peer);
                    return idx;
                }
            }
        }

        /* Unregisters an index. */
        void dropIndex(uint32_t idx) {
            if (idx != 0) {
                indices.erase(idx);
            }
        }

        /* Drops a keypair and its index. */
        void dropKeypair(std::unique_ptr<Keypair>& kp) {
            if (kp) {
                dropIndex(kp->localIndex);
                kp.reset();
            }
        }

        /* Forgets the handshake in progress. */
        void clearHandshake(Peer& p) {
            if (p.hsState == HS_INITIATION_SENT) {
                dropIndex(p.hs.localIndex);
            }

            p.hs.clear();
            p.hsState = HS_NONE;
        }

        /* Frees the staged packets. */
        void dropStaged(Peer& p) {
            for (const Staged& s : p.staged) {
                pool.release(s.buffer);
            }

            p.staged.clear();
        }

        /* Drops every session and the handshake (zero_key_material). */
        void zeroKeys(Peer& p) {
            dropKeypair(p.current);
            dropKeypair(p.previous);
            dropKeypair(p.next);
            clearHandshake(p);
        }

        /* Computes the per-peer precomputed values. */
        void precompute(Peer& p) {
            NoiseLabelKey("mac1----", p.publicKey, p.mac1Key);
            NoiseLabelKey("cookie--", p.publicKey, p.cookieKey);
            p.staticStaticValid = privateKey.valid
                && WgSharedSecret(privateKey, p.publicKey, p.staticStatic) == SBOX_OK;
        }

        /* Looks a peer up by key. */
        Peer* findPeer(const SWgKey& key) const {
            auto it = peers.find(keyOf(key));
            return it == peers.end() ? nullptr : it->second.get();
        }

        /* Removes a peer completely. */
        void erasePeer(Peer* p) {
            zeroKeys(*p);
            dropStaged(*p);
            allowedIps.removeValue(p->id);
            for (size_t i = 0; i < order.size(); ++i) {
                if (order[i] == p) {
                    order.erase(order.begin() + ptrdiff_t(i));
                    break;
                }
            }

            peers.erase(keyOf(p->publicKey));
        }

        /* Maps an allowed-IP owner value back to its peer. */
        Peer* peerById(uint64_t id) const {
            // --> Owner values are the Peer pointers themselves (ids are only for removal).
            return reinterpret_cast<Peer*>(uintptr_t(id));
        }

        // -- Timer events (named after the kernel's wg_timers_* hooks).

        void onAnyAuthenticatedPacketTraversal(Peer& p, int64_t t) {
            if (p.keepalive) {
                arm(p.tPersistent, t + int64_t(p.keepalive) * 1000);
            }
        }

        void onAnyAuthenticatedPacketSent(Peer& p) {
            p.tSendKeepalive = NONE;
        }

        void onAnyAuthenticatedPacketReceived(Peer& p) {
            p.tNewHandshake = NONE;
        }

        void onDataSent(Peer& p, int64_t t) {
            if (p.tNewHandshake == NONE) {
                arm(p.tNewHandshake, t + options.timers.keepaliveTimeoutMs + options.timers.rekeyTimeoutMs + randomBelow(JITTER_MAX_MS + 1));
            }
        }

        void onDataReceived(Peer& p, int64_t t) {
            if (p.tSendKeepalive == NONE) {
                arm(p.tSendKeepalive, t + options.timers.keepaliveTimeoutMs);
            }
            else {
                p.needAnotherKeepalive = true;
            }
        }

        void onHandshakeInitiated(Peer& p, int64_t t) {
            arm(p.tRetransmit, t + options.timers.rekeyTimeoutMs + randomBelow(JITTER_MAX_MS + 1));
        }

        void onHandshakeComplete(Peer& p) {
            p.tRetransmit = NONE;
            p.attempts = 0;
            p.sentLastMinuteHandshake = false;
            wallNow(p.lastHandshakeSec, p.lastHandshakeNsec);
        }

        void onSessionDerived(Peer& p, int64_t t) {
            arm(p.tZeroKeys, t + options.timers.rejectAfterTimeMs * 3);
        }

        // -- Load and cookies.

        /* Counts a handshake message and tells whether we are under load. */
        bool underLoad(int64_t t) {
            if (t - loadWindowStart >= 1000) {
                loadWindowStart = t;
                loadWindowCount = 0;
            }

            if (++loadWindowCount > options.underLoadThreshold) {
                underLoadUntil = t + 1000;
            }

            return forcedUnderLoad || t < underLoadUntil;
        }

        /* Returns the current cookie secret, rotating it every cookieRefreshMs. */
        const uint8_t* currentCookieSecret(int64_t t) {
            if (t - cookieSecretBirth >= options.timers.cookieRefreshMs) {
                NoiseRandom(cookieSecret, sizeof(cookieSecret));
                cookieSecretBirth = t;
            }

            return cookieSecret;
        }

        /* Token bucket per source address (IPv4 address or IPv6 /64). */
        bool allowHandshake(const SEndpoint& from, int64_t t) {
            const uint8_t* addr = nullptr;
            size_t len = 0;
            uint16_t port = 0;
            if (!endpointAddress(from, addr, len, port)) {
                return false;
            }

            uint64_t key = 0;
            std::memcpy(&key, addr, len == 4 ? 4 : 8);
            key ^= len == 4 ? 0x4000000000000000ull : 0;

            if (buckets.size() > 8192) {
                for (auto it = buckets.begin(); it != buckets.end();) {
                    it = t - it->second.last > 1000 ? buckets.erase(it) : std::next(it);
                }
            }

            auto it = buckets.find(key);
            if (it == buckets.end()) {
                buckets.emplace(key, Bucket{ double(options.handshakeBurst) - 1.0, t });
                return true;
            }

            Bucket& b = it->second;
            b.tokens += double(t - b.last) * double(options.handshakeRatePerSecond) / 1000.0;
            if (b.tokens > double(options.handshakeBurst)) {
                b.tokens = double(options.handshakeBurst);
            }

            b.last = t;
            if (b.tokens < 1.0) {
                return false;
            }

            b.tokens -= 1.0;
            return true;
        }

        /* Fills MAC1 and MAC2 of a handshake message we send to `p`. */
        void addMacs(Peer& p, uint8_t* msg, size_t macOffset, int64_t t) {
            NoiseMac(msg + macOffset, SReadOnlyByteSpan(p.mac1Key, 32), SReadOnlyByteSpan(msg, macOffset));
            std::memcpy(p.lastMac1, msg + macOffset, NOISE_MAC_BYTES);
            p.hasSentMac1 = true;

            // --> A cookie is used until it is about to expire on the other side.
            bool fresh = p.hasCookie && t - p.cookieBirth < options.timers.cookieRefreshMs - options.timers.rekeyTimeoutMs;
            if (fresh) {
                NoiseMac(msg + macOffset + NOISE_MAC_BYTES, SReadOnlyByteSpan(p.cookie, NOISE_COOKIE_BYTES),
                    SReadOnlyByteSpan(msg, macOffset + NOISE_MAC_BYTES));
            }
            else {
                std::memset(msg + macOffset + NOISE_MAC_BYTES, 0, NOISE_MAC_BYTES);
            }
        }

        /* Verdict of the MAC checks of an incoming handshake message. */
        enum MacVerdict { MAC_OK, MAC_DROP, MAC_NEED_COOKIE };

        /* Checks MAC1, and MAC2 when under load. */
        MacVerdict checkMacs(const SEndpoint& from, uint8_t* msg, size_t macOffset, int64_t t) {
            uint8_t expected[NOISE_MAC_BYTES];
            NoiseMac(expected, SReadOnlyByteSpan(mac1KeySelf, 32), SReadOnlyByteSpan(msg, macOffset));
            if (!macEquals(expected, msg + macOffset)) {
                ++stats.invalidMac;
                return MAC_DROP;
            }

            if (!underLoad(t)) {
                return MAC_OK;
            }

            const uint8_t* addr = nullptr;
            size_t len = 0;
            uint16_t port = 0;
            if (!endpointAddress(from, addr, len, port)) {
                return MAC_DROP;
            }

            uint8_t cookieValue[NOISE_COOKIE_BYTES];
            NoiseMakeCookie(currentCookieSecret(t), addr, len, port, cookieValue);
            NoiseMac(expected, SReadOnlyByteSpan(cookieValue, NOISE_COOKIE_BYTES), SReadOnlyByteSpan(msg, macOffset + NOISE_MAC_BYTES));
            if (!macEquals(expected, msg + macOffset + NOISE_MAC_BYTES)) {
                return MAC_NEED_COOKIE;
            }

            if (!allowHandshake(from, t)) {
                ++stats.rateLimited;
                return MAC_DROP;
            }

            return MAC_OK;
        }

        /* Answers a handshake message with a cookie reply. */
        void sendCookieReply(const SEndpoint& from, const uint8_t* msg, size_t macOffset, int64_t t) {
            const uint8_t* addr = nullptr;
            size_t len = 0;
            uint16_t port = 0;
            if (!endpointAddress(from, addr, len, port)) {
                return;
            }

            uint8_t cookieValue[NOISE_COOKIE_BYTES];
            uint8_t nonce[NOISE_COOKIE_NONCE_BYTES];
            uint8_t reply[MSG_COOKIE_REPLY_BYTES];
            NoiseMakeCookie(currentCookieSecret(t), addr, len, port, cookieValue);
            NoiseRandom(nonce, sizeof(nonce));

            if (NoiseCreateCookieReply(cookieKeySelf, LoadLe32(msg + OFF_SENDER), nonce, cookieValue, msg + macOffset, reply)) {
                ++stats.cookieRepliesSent;
                output->sendDatagram(from, SReadOnlyByteSpan(reply, sizeof(reply)), false);
            }
        }

        // -- Handshake.

        /* Sends a handshake initiation (wg_packet_send_queued_handshake_initiation). */
        void sendInitiation(Peer& p, bool retry) {
            int64_t t = now();
            if (!retry) {
                p.attempts = 0;
            }

            if (t - p.lastHandshakeSent < options.timers.rekeyTimeoutMs) {
                return;
            }

            if (!p.endpoint.isValid() || !p.staticStaticValid || !privateKey.valid) {
                return;
            }

            p.lastHandshakeSent = t;

            uint8_t ephemeral[32];
            NoiseRandom(ephemeral, sizeof(ephemeral));
            ephemeral[0] &= 248;
            ephemeral[31] &= 127;
            ephemeral[31] |= 64;

            uint8_t timestamp[NOISE_TIMESTAMP_BYTES];
            NoiseTai64n(timestamp);

            clearHandshake(p);
            uint32_t idx = newIndex(&p);

            uint8_t msg[MSG_INITIATION_BYTES];
            bool ok = NoiseCreateInitiation(publicKey, p.publicKey, p.staticStatic, ephemeral, timestamp, idx, p.hs, msg);
            NoiseWipe(ephemeral, sizeof(ephemeral));
            if (!ok) {
                dropIndex(idx);
                p.hs.clear();
                return;
            }

            p.hsState = HS_INITIATION_SENT;
            addMacs(p, msg, OFF_INIT_MAC1, t);

            ++stats.initiationsSent;
            p.txBytes += sizeof(msg);
            output->sendDatagram(p.endpoint, SReadOnlyByteSpan(msg, sizeof(msg)), false);

            onAnyAuthenticatedPacketTraversal(p, t);
            onAnyAuthenticatedPacketSent(p);
            onHandshakeInitiated(p, t);
        }

        /* Installs a new session (wg_noise_handshake_begin_session / add_new_keypair). */
        void installKeypair(Peer& p, std::unique_ptr<Keypair> kp) {
            if (kp->initiator) {
                if (p.next) {
                    // --> A responder session that was never confirmed is superseded; keep it as
                    // previous so in-flight packets still decrypt.
                    dropKeypair(p.previous);
                    p.previous = std::move(p.next);
                    dropKeypair(p.current);
                }
                else {
                    dropKeypair(p.previous);
                    p.previous = std::move(p.current);
                }

                p.current = std::move(kp);
            }
            else {
                dropKeypair(p.next);
                p.next = std::move(kp);
                dropKeypair(p.previous);
            }
        }

        /* Builds a keypair from a finished handshake. */
        std::unique_ptr<Keypair> deriveKeypair(Peer& p, bool initiator, uint32_t localIndex, int64_t t) {
            std::unique_ptr<Keypair> kp(new Keypair());
            uint8_t sendKey[32], recvKey[32];
            NoiseDeriveKeys(p.hs, initiator, sendKey, recvKey);
            kp->sendAead.reset(certpp::SReadOnlyByteSpan(sendKey, 32));
            kp->recvAead.reset(certpp::SReadOnlyByteSpan(recvKey, 32));
            NoiseWipe(sendKey, sizeof(sendKey));
            NoiseWipe(recvKey, sizeof(recvKey));
            kp->localIndex = localIndex;
            kp->remoteIndex = p.hs.remoteIndex;
            kp->created = t;
            kp->initiator = initiator;
            ++stats.sessionsDerived;
            return kp;
        }

        /* Handles a handshake initiation (we are the responder). */
        void receiveInitiation(const SEndpoint& from, uint8_t* msg, size_t length, int64_t t) {
            if (length != MSG_INITIATION_BYTES || !privateKey.valid) {
                ++stats.dropped;
                return;
            }

            MacVerdict v = checkMacs(from, msg, OFF_INIT_MAC1, t);
            if (v == MAC_NEED_COOKIE) {
                sendCookieReply(from, msg, OFF_INIT_MAC1, t);
                return;
            }

            if (v != MAC_OK) {
                return;
            }

            NoiseHandshake hs;
            SWgKey remote;
            if (!NoiseConsumeInitiationStatic(privateKey, publicKey, msg, hs, remote)) {
                ++stats.invalidMac;
                hs.clear();
                return;
            }

            Peer* p = findPeer(remote);
            if (!p || !p->staticStaticValid) {
                hs.clear();
                ++stats.dropped;
                return;
            }

            uint8_t timestamp[NOISE_TIMESTAMP_BYTES];
            if (!NoiseConsumeInitiationFinish(hs, p->staticStatic, msg, timestamp)) {
                hs.clear();
                ++stats.invalidMac;
                return;
            }

            bool replay = !NoiseTimestampAfter(timestamp, p->latestTimestamp);
            bool flood = t - p->lastInitiationConsumed < 1000 / INITIATIONS_PER_SECOND;
            if (replay || flood) {
                hs.clear();
                ++stats.replayed;
                return;
            }

            std::memcpy(p->latestTimestamp, timestamp, sizeof(timestamp));
            p->lastInitiationConsumed = t;

            clearHandshake(*p);
            p->hs = hs;
            hs.clear();

            p->endpoint = from;
            p->rxBytes += length;
            onAnyAuthenticatedPacketReceived(*p);
            onAnyAuthenticatedPacketTraversal(*p, t);

            // -- Respond.
            uint8_t ephemeral[32];
            NoiseRandom(ephemeral, sizeof(ephemeral));
            ephemeral[0] &= 248;
            ephemeral[31] &= 127;
            ephemeral[31] |= 64;

            uint32_t idx = newIndex(p);
            uint8_t reply[MSG_RESPONSE_BYTES];
            bool ok = NoiseCreateResponse(p->hs, p->publicKey, p->psk, ephemeral, idx, reply);
            NoiseWipe(ephemeral, sizeof(ephemeral));
            if (!ok) {
                dropIndex(idx);
                clearHandshake(*p);
                return;
            }

            addMacs(*p, reply, OFF_RESP_MAC1, t);

            std::unique_ptr<Keypair> kp = deriveKeypair(*p, false, idx, t);
            clearHandshake(*p);
            installKeypair(*p, std::move(kp));

            ++stats.responsesSent;
            p->txBytes += sizeof(reply);
            output->sendDatagram(p->endpoint, SReadOnlyByteSpan(reply, sizeof(reply)), false);

            onSessionDerived(*p, t);
            onAnyAuthenticatedPacketTraversal(*p, t);
            onAnyAuthenticatedPacketSent(*p);
        }

        /* Handles a handshake response (we are the initiator). */
        void receiveResponse(const SEndpoint& from, uint8_t* msg, size_t length, int64_t t) {
            if (length != MSG_RESPONSE_BYTES || !privateKey.valid) {
                ++stats.dropped;
                return;
            }

            MacVerdict v = checkMacs(from, msg, OFF_RESP_MAC1, t);
            if (v == MAC_NEED_COOKIE) {
                sendCookieReply(from, msg, OFF_RESP_MAC1, t);
                return;
            }

            if (v != MAC_OK) {
                return;
            }

            uint32_t receiver = LoadLe32(msg + OFF_RESP_RECEIVER);
            auto it = indices.find(receiver);
            if (it == indices.end()) {
                ++stats.dropped;
                return;
            }

            Peer& p = *it->second;
            if (p.hsState != HS_INITIATION_SENT || p.hs.localIndex != receiver) {
                ++stats.dropped;
                return;
            }

            NoiseHandshake hs = p.hs;
            if (!NoiseConsumeResponse(hs, privateKey, p.psk, msg)) {
                hs.clear();
                ++stats.invalidMac;
                return;
            }

            p.hs = hs;
            hs.clear();

            // --> The handshake's index now names the session.
            std::unique_ptr<Keypair> kp = deriveKeypair(p, true, receiver, t);
            p.hs.clear();
            p.hsState = HS_NONE;
            installKeypair(p, std::move(kp));

            p.endpoint = from;
            p.rxBytes += length;
            onAnyAuthenticatedPacketReceived(p);
            onAnyAuthenticatedPacketTraversal(p, t);
            onSessionDerived(p, t);
            onHandshakeComplete(p);

            // --> Confirm the session to the responder: staged data, or else a keepalive.
            sendKeepalive(p);
        }

        /* Handles a cookie reply. */
        void receiveCookieReply(uint8_t* msg, size_t length, int64_t t) {
            if (length != MSG_COOKIE_REPLY_BYTES) {
                ++stats.dropped;
                return;
            }

            auto it = indices.find(LoadLe32(msg + OFF_COOKIE_RECEIVER));
            if (it == indices.end()) {
                ++stats.dropped;
                return;
            }

            Peer& p = *it->second;
            if (!p.hasSentMac1) {
                ++stats.dropped;
                return;
            }

            uint8_t value[NOISE_COOKIE_BYTES];
            if (!NoiseConsumeCookieReply(p.cookieKey, msg, p.lastMac1, value)) {
                ++stats.invalidMac;
                return;
            }

            std::memcpy(p.cookie, value, sizeof(value));
            p.cookieBirth = t;
            p.hasCookie = true;
            p.hasSentMac1 = false;
            ++stats.cookieRepliesReceived;
        }

        // -- Transport.

        /* Returns true when a session may still be used to send. */
        bool canSend(const Keypair* kp, int64_t t) const {
            return kp && t - kp->created < options.timers.rejectAfterTimeMs
                && kp->sendCounter < options.timers.rejectAfterMessages;
        }

        /* Encrypts the plaintext at buffer + HEADROOM in place and sends it. */
        bool encryptAndSend(Peer& p, Keypair& kp, uint8_t* buffer, size_t length, size_t capacity, bool stable, int64_t t) {
            size_t padded = (length + 15) & ~size_t(15);
            size_t mtu = options.mtu;
            if (padded > mtu && length <= mtu) {
                padded = mtu;
            }

            if (padded < length) {
                padded = length;
            }

            if (WG_DATA_HEADROOM + padded + NOISE_TAG_BYTES > capacity) {
                ++stats.dropped;
                return false;
            }

            uint8_t* plain = buffer + WG_DATA_HEADROOM;
            if (padded > length) {
                std::memset(plain + length, 0, padded - length);
            }

            uint64_t counter = kp.sendCounter++;
            StoreLe32(buffer, MSG_DATA);
            StoreLe32(buffer + OFF_DATA_RECEIVER, kp.remoteIndex);
            StoreLe64(buffer + OFF_DATA_COUNTER, counter);

            uint8_t nonce[12];
            std::memset(nonce, 0, 4);
            StoreLe64(nonce + 4, counter);
            if (!kp.sendAead.seal(certpp::SReadOnlyByteSpan(nonce, 12), certpp::SReadOnlyByteSpan(),
                certpp::SReadOnlyByteSpan(plain, padded), certpp::SByteSpan(plain, padded),
                certpp::SByteSpan(plain + padded, NOISE_TAG_BYTES)))
            {
                ++stats.dropped;
                return false;
            }

            size_t total = WG_DATA_HEADROOM + padded + NOISE_TAG_BYTES;
            p.txBytes += total;
            if (length == 0) {
                ++stats.keepalivesSent;
            }
            else {
                ++stats.dataSent;
            }

            output->sendDatagram(p.endpoint, SReadOnlyByteSpan(buffer, total), stable);

            onAnyAuthenticatedPacketTraversal(p, t);
            onAnyAuthenticatedPacketSent(p);
            if (length > 0) {
                onDataSent(p, t);
            }

            return true;
        }

        /* Initiates a rekey when the sending session is getting old (keep_key_fresh on send). */
        void keepKeyFreshSend(Peer& p, int64_t t) {
            const Keypair* kp = p.current.get();
            if (kp && kp->initiator && (kp->sendCounter > options.timers.rekeyAfterMessages
                || t - kp->created >= options.timers.rekeyAfterTimeMs))
            {
                sendInitiation(p, false);
            }
        }

        /* Initiates a rekey before the session expires (keep_key_fresh on receive). */
        void keepKeyFreshReceive(Peer& p, int64_t t) {
            if (p.sentLastMinuteHandshake) {
                return;
            }

            const Keypair* kp = p.current.get();
            int64_t limit = options.timers.rejectAfterTimeMs - options.timers.keepaliveTimeoutMs - options.timers.rekeyTimeoutMs;
            if (kp && kp->initiator && t - kp->created >= limit) {
                p.sentLastMinuteHandshake = true;
                sendInitiation(p, false);
            }
        }

        /* Sends staged packets with the current session, or starts a handshake. */
        void flushStaged(Peer& p) {
            int64_t t = now();
            while (!p.staged.empty()) {
                if (!canSend(p.current.get(), t) || !p.endpoint.isValid()) {
                    sendInitiation(p, false);
                    return;
                }

                Staged s = p.staged.front();
                p.staged.pop_front();
                encryptAndSend(p, *p.current, s.buffer, s.length, pool.bufferSize(), false, t);
                pool.release(s.buffer);
            }

            keepKeyFreshSend(p, t);
        }

        /* Sends a keepalive: staged data first, else an empty packet (wg_packet_send_keepalive). */
        void sendKeepalive(Peer& p) {
            if (!p.staged.empty()) {
                flushStaged(p);
                return;
            }

            int64_t t = now();
            if (!canSend(p.current.get(), t) || !p.endpoint.isValid()) {
                sendInitiation(p, false);
                return;
            }

            uint8_t buffer[WG_DATA_HEADROOM + WG_DATA_TAILROOM];
            encryptAndSend(p, *p.current, buffer, 0, sizeof(buffer), false, t);
            keepKeyFreshSend(p, t);
        }

        /* Copies a packet into the peer's staging queue. */
        void stage(Peer& p, const uint8_t* packet, size_t length) {
            if (WG_DATA_HEADROOM + length + WG_DATA_TAILROOM > pool.bufferSize()) {
                ++stats.dropped;
                return;
            }

            if (p.staged.size() >= options.maxStagedPackets) {
                pool.release(p.staged.front().buffer);
                p.staged.pop_front();
                ++stats.dropped;
            }

            uint8_t* buf = pool.acquire();
            if (!buf) {
                ++stats.dropped;
                return;
            }

            std::memcpy(buf + WG_DATA_HEADROOM, packet, length);
            p.staged.push_back(Staged{ buf, length });
        }

        /* Finds the session of a receiver index. */
        std::unique_ptr<Keypair>* findKeypair(Peer& p, uint32_t idx) {
            if (p.current && p.current->localIndex == idx) {
                return &p.current;
            }

            if (p.next && p.next->localIndex == idx) {
                return &p.next;
            }

            if (p.previous && p.previous->localIndex == idx) {
                return &p.previous;
            }

            return nullptr;
        }

        /* Handles a transport data message. */
        void receiveData(const SEndpoint& from, uint8_t* msg, size_t length, int64_t t) {
            if (length < MSG_DATA_MIN_BYTES) {
                ++stats.dropped;
                return;
            }

            uint32_t receiver = LoadLe32(msg + OFF_DATA_RECEIVER);
            auto it = indices.find(receiver);
            if (it == indices.end()) {
                ++stats.dropped;
                return;
            }

            Peer& p = *it->second;
            std::unique_ptr<Keypair>* slot = findKeypair(p, receiver);
            if (!slot) {
                ++stats.dropped;
                return;
            }

            Keypair& kp = **slot;
            uint64_t counter = LoadLe64(msg + OFF_DATA_COUNTER);
            if (t - kp.created >= options.timers.rejectAfterTimeMs || counter >= options.timers.rejectAfterMessages) {
                ++stats.dropped;
                return;
            }

            size_t boxLength = length - MSG_DATA_HEADER_BYTES;
            size_t plainLength = boxLength - NOISE_TAG_BYTES;
            uint8_t* plain = msg + MSG_DATA_HEADER_BYTES;

            uint8_t nonce[12];
            std::memset(nonce, 0, 4);
            StoreLe64(nonce + 4, counter);
            if (!kp.recvAead.open(certpp::SReadOnlyByteSpan(nonce, 12), certpp::SReadOnlyByteSpan(),
                certpp::SReadOnlyByteSpan(plain, plainLength), certpp::SReadOnlyByteSpan(plain + plainLength, NOISE_TAG_BYTES),
                certpp::SByteSpan(plain, plainLength)))
            {
                ++stats.invalidMac;
                return;
            }

            if (!kp.replay.accept(counter, options.timers.rejectAfterMessages)) {
                ++stats.replayed;
                return;
            }

            bool confirmed = false;
            if (slot == &p.next) {
                // --> The initiator used the session we answered: it becomes current.
                dropKeypair(p.previous);
                p.previous = std::move(p.current);
                p.current = std::move(p.next);
                confirmed = true;
            }

            if (!sameEndpoint(p.endpoint, from)) {
                p.endpoint = from;      // --> Roaming: follow the authenticated source.
            }

            p.rxBytes += length;
            onAnyAuthenticatedPacketReceived(p);
            onAnyAuthenticatedPacketTraversal(p, t);

            if (confirmed) {
                onHandshakeComplete(p);
                flushStaged(p);
            }

            keepKeyFreshReceive(p, t);

            if (plainLength == 0) {
                return;     // --> Keepalive.
            }

            onDataReceived(p, t);

            // -- Trim the padding using the IP header and apply cryptokey routing.
            size_t ipLength = 0;
            const uint8_t* source = nullptr;
            uint8_t family = 0;
            uint8_t version = plain[0] >> 4;
            if (version == 4 && plainLength >= 20) {
                ipLength = (size_t(plain[2]) << 8) | plain[3];
                source = plain + 12;
                family = 4;
            }
            else if (version == 6 && plainLength >= 40) {
                ipLength = 40 + ((size_t(plain[4]) << 8) | plain[5]);
                source = plain + 8;
                family = 6;
            }

            if (family == 0 || ipLength > plainLength || ipLength < (family == 4 ? 20u : 40u)) {
                ++stats.dropped;
                return;
            }

            if (peerById(allowedIps.lookup(source, family)) != &p) {
                ++stats.invalidSource;
                return;
            }

            ++stats.dataReceived;
            output->writePacket(SReadOnlyByteSpan(plain, ipLength));
        }

        // -- Timers.

        /* Fires the due timers of one peer. */
        void runPeerTimers(Peer& p, int64_t t) {
            if (p.tRetransmit <= t) {
                p.tRetransmit = NONE;
                uint32_t maxAttempts = uint32_t(options.timers.rekeyAttemptTimeMs / options.timers.rekeyTimeoutMs);
                if (p.attempts > maxAttempts) {
                    // --> Give up: drop what was waiting and schedule the key wipe.
                    p.tSendKeepalive = NONE;
                    dropStaged(p);
                    if (p.tZeroKeys == NONE) {
                        arm(p.tZeroKeys, t + options.timers.rejectAfterTimeMs * 3);
                    }
                }
                else {
                    ++p.attempts;
                    sendInitiation(p, true);
                }
            }

            if (p.tSendKeepalive <= t) {
                p.tSendKeepalive = NONE;
                sendKeepalive(p);
                if (p.needAnotherKeepalive) {
                    p.needAnotherKeepalive = false;
                    arm(p.tSendKeepalive, t + options.timers.keepaliveTimeoutMs);
                }
            }

            if (p.tNewHandshake <= t) {
                p.tNewHandshake = NONE;
                sendInitiation(p, false);
            }

            if (p.tZeroKeys <= t) {
                p.tZeroKeys = NONE;
                zeroKeys(p);
            }

            if (p.tPersistent <= t) {
                p.tPersistent = NONE;
                if (p.keepalive) {
                    sendKeepalive(p);
                }
            }
        }

        /* Recomputes the earliest deadline. */
        void recomputeEarliest() {
            earliest = NONE;
            for (Peer* p : order) {
                for (int64_t d : { p->tRetransmit, p->tSendKeepalive, p->tNewHandshake, p->tZeroKeys, p->tPersistent }) {
                    if (d < earliest) {
                        earliest = d;
                    }
                }
            }
        }
    };

    /* Creates a pool. */
    CWgBufferPool::CWgBufferPool(size_t bufferSize, size_t maxBuffers)
        : _bufferSize(bufferSize), _maxBuffers(maxBuffers), _allocated(0)
    {
    }

    /* Frees every buffer (all must have been released). */
    CWgBufferPool::~CWgBufferPool() {
        for (uint8_t* b : _free) {
            std::free(b);
        }
    }

    /* Takes a buffer. */
    uint8_t* CWgBufferPool::acquire() noexcept {
        if (!_free.empty()) {
            uint8_t* b = _free.back();
            _free.pop_back();
            return b;
        }

        if (_allocated >= _maxBuffers) {
            return nullptr;
        }

        // --> 16-byte alignment keeps the cipher's word loads aligned.
        void* mem = std::aligned_alloc(16, (_bufferSize + 15) & ~size_t(15));
        if (!mem) {
            return nullptr;
        }

        ++_allocated;
        return static_cast<uint8_t*>(mem);
    }

    /* Returns a buffer. */
    void CWgBufferPool::release(uint8_t* buffer) noexcept {
        if (buffer) {
            try {
                _free.push_back(buffer);
            }
            catch (...) {
                std::free(buffer);
                --_allocated;
            }
        }
    }

    /* Creates an engine. */
    CWgEngine::CWgEngine(IWgOutput* output, SWgEngineOptions options) : _impl(new SImpl(output, std::move(options))) {
    }

    /* Destroys the engine. */
    CWgEngine::~CWgEngine() = default;

    /* Sets the identity. */
    int32_t CWgEngine::privateKey(const SWgKey& key) {
        SImpl& m = *_impl;
        SWgKey pub;
        if (key.valid) {
            int32_t r = DeriveWgPublicKey(key, pub);
            if (r != SBOX_OK) {
                return r;
            }
        }

        if (key.valid && m.privateKey.valid && key == m.privateKey) {
            return SBOX_OK;
        }

        m.privateKey = key;
        m.publicKey = pub;
        if (key.valid) {
            NoiseLabelKey("mac1----", pub, m.mac1KeySelf);
            NoiseLabelKey("cookie--", pub, m.cookieKeySelf);

            Peer* self = m.findPeer(pub);
            if (self) {
                m.erasePeer(self);
            }
        }

        for (Peer* p : m.order) {
            m.zeroKeys(*p);
            m.precompute(*p);
        }

        return SBOX_OK;
    }

    /* Returns the private key. */
    SWgKey CWgEngine::privateKey() const {
        return _impl->privateKey;
    }

    /* Returns the public key. */
    SWgKey CWgEngine::publicKey() const {
        return _impl->publicKey;
    }

    /* Adds/updates/removes a peer. */
    int32_t CWgEngine::setPeer(const SWgPeerConfig& config) {
        SImpl& m = *_impl;
        if (!config.publicKey.valid) {
            return -EINVAL;
        }

        Peer* p = m.findPeer(config.publicKey);
        if (config.remove) {
            if (p) {
                m.erasePeer(p);
            }

            return SBOX_OK;
        }

        if (m.publicKey.valid && config.publicKey == m.publicKey) {
            // --> A device never peers with itself; ignored like the kernel does.
            return SBOX_OK;
        }

        if (!p) {
            if (config.updateOnly) {
                return SBOX_OK;
            }

            std::unique_ptr<Peer> np(new Peer());
            np->publicKey = config.publicKey;
            np->id = uint64_t(uintptr_t(np.get()));
            m.precompute(*np);
            p = np.get();
            m.order.push_back(p);
            m.peers.emplace(keyOf(config.publicKey), std::move(np));
        }

        if (config.presharedKey.valid) {
            std::memcpy(p->psk, config.presharedKey.bytes, 32);
            p->hasPsk = !config.presharedKey.isZero();
        }

        if (config.endpoint.isValid()) {
            p->endpoint = config.endpoint;
        }

        if (config.replaceAllowedIps) {
            m.allowedIps.removeValue(p->id);
        }

        for (const net::SIpPrefix& prefix : config.allowedIps) {
            int32_t r = m.allowedIps.insert(prefix, p->id);
            if (r != SBOX_OK) {
                return r;
            }
        }

        if (config.persistentKeepalive >= 0) {
            bool start = p->keepalive == 0 && config.persistentKeepalive > 0;
            p->keepalive = uint16_t(config.persistentKeepalive);
            if (p->keepalive == 0) {
                p->tPersistent = NONE;
            }

            if (start && p->endpoint.isValid()) {
                m.sendKeepalive(*p);
            }
        }

        return SBOX_OK;
    }

    /* Removes a peer. */
    int32_t CWgEngine::removePeer(const SWgKey& publicKey) {
        Peer* p = _impl->findPeer(publicKey);
        if (!p) {
            return -ENOENT;
        }

        _impl->erasePeer(p);
        return SBOX_OK;
    }

    /* Removes every peer. */
    void CWgEngine::removeAllPeers() {
        while (!_impl->order.empty()) {
            _impl->erasePeer(_impl->order.back());
        }
    }

    namespace {

        /* Fills a status record. */
        void fillStatus(const CWgAllowedIps& table, const Peer& p, SWgPeerStatus& out) {
            out.publicKey = p.publicKey;
            out.hasPresharedKey = p.hasPsk;
            out.presharedKey = p.hasPsk ? SWgKey::fromBytes(p.psk) : SWgKey();
            out.endpoint = p.endpoint;
            out.allowedIps = table.prefixes(p.id);
            out.persistentKeepalive = p.keepalive;
            out.lastHandshakeSec = p.lastHandshakeSec;
            out.lastHandshakeNsec = p.lastHandshakeNsec;
            out.rxBytes = p.rxBytes;
            out.txBytes = p.txBytes;
            out.protocolVersion = 1;
        }

    }

    /* Lists the peers. */
    std::vector<SWgPeerStatus> CWgEngine::peers() const {
        std::vector<SWgPeerStatus> out;
        out.reserve(_impl->order.size());
        for (const Peer* p : _impl->order) {
            SWgPeerStatus s;
            fillStatus(_impl->allowedIps, *p, s);
            out.push_back(std::move(s));
        }

        return out;
    }

    /* Returns one peer. */
    int32_t CWgEngine::peer(const SWgKey& publicKey, SWgPeerStatus& out) const {
        const Peer* p = _impl->findPeer(publicKey);
        if (!p) {
            return -ENOENT;
        }

        fillStatus(_impl->allowedIps, *p, out);
        return SBOX_OK;
    }

    /* Dispatches an underlay datagram. */
    void CWgEngine::receiveDatagram(const SEndpoint& from, uint8_t* data, size_t length) {
        SImpl& m = *_impl;
        if (length < 4) {
            ++m.stats.dropped;
            return;
        }

        int64_t t = m.now();
        // --> The type is one byte followed by three reserved zero bytes.
        uint32_t type = LoadLe32(data);
        switch (type) {
            case MSG_INITIATION:
                m.receiveInitiation(from, data, length, t);
                break;

            case MSG_RESPONSE:
                m.receiveResponse(from, data, length, t);
                break;

            case MSG_COOKIE_REPLY:
                m.receiveCookieReply(data, length, t);
                break;

            case MSG_DATA:
                m.receiveData(from, data, length, t);
                break;

            default:
                ++m.stats.dropped;
                break;
        }
    }

    /* Routes and encrypts a tunnel packet. */
    void CWgEngine::sendPacket(uint8_t* buffer, size_t length, size_t capacity) {
        SImpl& m = *_impl;
        const uint8_t* packet = buffer + WG_DATA_HEADROOM;
        const uint8_t* dest = nullptr;
        uint8_t family = 0;

        if (length >= 20 && (packet[0] >> 4) == 4) {
            dest = packet + 16;
            family = 4;
        }
        else if (length >= 40 && (packet[0] >> 4) == 6) {
            dest = packet + 24;
            family = 6;
        }

        if (!dest) {
            ++m.stats.dropped;
            return;
        }

        Peer* p = m.peerById(m.allowedIps.lookup(dest, family));
        if (!p) {
            ++m.stats.noRoute;
            return;
        }

        if (!p->endpoint.isValid()) {
            ++m.stats.dropped;
            return;
        }

        int64_t t = m.now();
        if (p->staged.empty() && m.canSend(p->current.get(), t)) {
            m.encryptAndSend(*p, *p->current, buffer, length, capacity, true, t);
            m.keepKeyFreshSend(*p, t);
            return;
        }

        m.stage(*p, packet, length);
        m.flushStaged(*p);
    }

    /* Runs due timers. */
    void CWgEngine::runTimers() {
        SImpl& m = *_impl;
        int64_t t = m.now();
        if (t < m.earliest) {
            return;
        }

        // --> Timer handlers may add or remove nothing but timers, so iterating a copy of the
        // order is only defensive.
        std::vector<Peer*> peers = m.order;
        for (Peer* p : peers) {
            m.runPeerTimers(*p, t);
        }

        m.recomputeEarliest();
    }

    /* Returns the next deadline. */
    int64_t CWgEngine::nextDeadline() const noexcept {
        return _impl->earliest;
    }

    /* Starts a handshake. */
    int32_t CWgEngine::initiateHandshake(const SWgKey& publicKey) {
        Peer* p = _impl->findPeer(publicKey);
        if (!p) {
            return -ENOENT;
        }

        if (!p->endpoint.isValid()) {
            return -EDESTADDRREQ;
        }

        _impl->sendInitiation(*p, false);
        return SBOX_OK;
    }

    /* Forces the under-load state. */
    void CWgEngine::forceUnderLoad(bool on) noexcept {
        _impl->forcedUnderLoad = on;
    }

    /* Returns the MTU. */
    uint32_t CWgEngine::mtu() const noexcept {
        return _impl->options.mtu;
    }

    /* Sets the MTU. */
    void CWgEngine::mtu(uint32_t value) noexcept {
        _impl->options.mtu = value;
    }

    /* Returns the counters. */
    const SWgEngineStats& CWgEngine::stats() const noexcept {
        return _impl->stats;
    }

}
}
