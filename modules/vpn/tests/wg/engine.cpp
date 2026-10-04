#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/engine.hpp>

#include <cstring>
#include <deque>
#include <string>
#include <vector>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    /* A datagram in flight on the simulated underlay. */
    struct Datagram {
        SEndpoint from;
        SEndpoint to;
        std::vector<uint8_t> bytes;
    };

    struct World;

    /* One simulated host: an engine, its underlay address and what reached its tunnel. */
    struct Host : IWgOutput {
        World* world = nullptr;
        SEndpoint address;
        std::vector<std::vector<uint8_t>> delivered;
        std::unique_ptr<CWgEngine> engine;
        SWgKey priv;
        SWgKey pub;

        void sendDatagram(const SEndpoint& to, const SReadOnlyByteSpan& bytes, bool stable) override;

        void writePacket(const SReadOnlyByteSpan& packet) override {
            delivered.emplace_back(packet.begin(), packet.end());
        }
    };

    /* The simulated network and clock. */
    struct World {
        int64_t now = 1000000;
        std::deque<Datagram> wire;
        std::vector<Host*> hosts;
        bool drop = false;              // --> Lose everything sent while set.
        std::vector<Datagram> captured; // --> Copy of every datagram sent (even dropped ones), for replays.

        /* Returns the captured datagrams of one message type. */
        std::vector<Datagram> ofType(uint8_t type) const {
            std::vector<Datagram> out;
            for (const Datagram& d : captured) {
                if (!d.bytes.empty() && d.bytes[0] == type) {
                    out.push_back(d);
                }
            }

            return out;
        }

        /* Delivers queued datagrams until the network is quiet. */
        size_t pump(size_t limit = 1000) {
            size_t n = 0;
            while (!wire.empty() && n < limit) {
                Datagram d = std::move(wire.front());
                wire.pop_front();
                ++n;
                for (Host* h : hosts) {
                    if (h->address.toString() == d.to.toString()) {
                        h->engine->receiveDatagram(d.from, d.bytes.data(), d.bytes.size());
                    }
                }
            }

            return n;
        }

        /* Advances the clock in steps, running due timers and the network. */
        void advance(int64_t ms, int64_t step = 100) {
            for (int64_t t = 0; t < ms; t += step) {
                now += step;
                for (Host* h : hosts) {
                    if (h->engine->nextDeadline() <= now) {
                        h->engine->runTimers();
                    }
                }

                pump();
            }
        }
    };

    void Host::sendDatagram(const SEndpoint& to, const SReadOnlyByteSpan& bytes, bool stable) {
        (void)stable;
        Datagram d{ address, to, std::vector<uint8_t>(bytes.begin(), bytes.end()) };
        world->captured.push_back(d);
        if (!world->drop) {
            world->wire.push_back(std::move(d));
        }
    }

    /* Builds an IPv4 packet (with headroom) from `src` to `dst` carrying `payload`. */
    std::vector<uint8_t> ipPacket(const char* src, const char* dst, const std::string& payload) {
        std::vector<uint8_t> buf(WG_DATA_HEADROOM + 20 + payload.size() + WG_DATA_TAILROOM, 0);
        uint8_t* ip = buf.data() + WG_DATA_HEADROOM;
        size_t total = 20 + payload.size();
        ip[0] = 0x45;
        ip[2] = uint8_t(total >> 8);
        ip[3] = uint8_t(total);
        ip[8] = 64;
        ip[9] = 17;
        net::SIpAddress a, b;
        net::SIpAddress::parse(src, a);
        net::SIpAddress::parse(dst, b);
        std::memcpy(ip + 12, a.bytes, 4);
        std::memcpy(ip + 16, b.bytes, 4);
        std::memcpy(ip + 20, payload.data(), payload.size());
        return buf;
    }

    /* Sends a packet from `h`'s tunnel. */
    void send(Host& h, const char* src, const char* dst, const std::string& payload) {
        std::vector<uint8_t> buf = ipPacket(src, dst, payload);
        h.engine->sendPacket(buf.data(), 20 + payload.size(), buf.size());
    }

    /* Returns the payload of a delivered packet. */
    std::string payloadOf(const std::vector<uint8_t>& packet) {
        return std::string(packet.begin() + 20, packet.end());
    }

    net::SIpPrefix prefix(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    SEndpoint endpoint(const char* ip, uint16_t port) {
        SEndpoint ep;
        SEndpoint::fromIp(ip, port, ep);
        return ep;
    }

    /* Two hosts A (10.0.0.1, tunnel 10.9.0.1) and B (10.0.0.2, tunnel 10.9.0.2) peered. */
    struct Pair {
        World world;
        Host a;
        Host b;

        explicit Pair(bool withPsk = true, uint32_t underLoadThreshold = 256) {
            for (Host* h : { &a, &b }) {
                h->world = &world;
                SWgEngineOptions o;
                o.clock = [this]() { return world.now; };
                o.underLoadThreshold = underLoadThreshold;
                h->engine.reset(new CWgEngine(h, o));
                REQUIRE(GenerateWgPrivateKey(h->priv) == SBOX_OK);
                REQUIRE(h->engine->privateKey(h->priv) == SBOX_OK);
                h->pub = h->engine->publicKey();
                world.hosts.push_back(h);
            }

            a.address = endpoint("10.0.0.1", 51820);
            b.address = endpoint("10.0.0.2", 51821);

            SWgKey psk;
            if (withPsk) {
                REQUIRE(GenerateWgPresharedKey(psk) == SBOX_OK);
            }

            SWgPeerConfig pb;
            pb.publicKey = b.pub;
            pb.presharedKey = psk;
            pb.endpoint = b.address;
            pb.allowedIps = { prefix("10.9.0.2/32"), prefix("10.20.0.0/16") };
            REQUIRE(a.engine->setPeer(pb) == SBOX_OK);

            SWgPeerConfig pa;
            pa.publicKey = a.pub;
            pa.presharedKey = psk;
            pa.allowedIps = { prefix("10.9.0.1/32") };
            REQUIRE(b.engine->setPeer(pa) == SBOX_OK);
        }

        /* Exchanges one packet each way, establishing the session. */
        void establish() {
            send(a, "10.9.0.1", "10.9.0.2", "hello");
            world.pump();
            REQUIRE(b.delivered.size() == 1);
            CHECK(payloadOf(b.delivered[0]) == "hello");
            send(b, "10.9.0.2", "10.9.0.1", "world");
            world.pump();
            REQUIRE(a.delivered.size() == 1);
            CHECK(payloadOf(a.delivered[0]) == "world");
        }
    };

}

TEST_CASE("engine: handshake on first packet, data both ways, stats") {
    Pair p;
    p.establish();

    CHECK(p.a.engine->stats().initiationsSent == 1);
    CHECK(p.b.engine->stats().responsesSent == 1);
    CHECK(p.a.engine->stats().sessionsDerived == 1);

    SWgPeerStatus st;
    REQUIRE(p.a.engine->peer(p.b.pub, st) == SBOX_OK);
    CHECK(st.lastHandshakeSec > 0);
    CHECK(st.txBytes > 0);
    CHECK(st.rxBytes > 0);
    CHECK(st.hasPresharedKey);
    CHECK(st.allowedIps.size() == 2);

    // --> B learned A's endpoint from the authenticated initiation.
    REQUIRE(p.b.engine->peer(p.a.pub, st) == SBOX_OK);
    CHECK(st.endpoint.toString() == "10.0.0.1:51820");

    // --> Many packets in a row, larger than one block, padded and trimmed again.
    std::string big(1000, 'x');
    for (int i = 0; i < 50; ++i) {
        send(p.a, "10.9.0.1", "10.20.3.4", big + std::to_string(i));
    }

    p.world.pump();
    REQUIRE(p.b.delivered.size() == 51);
    CHECK(payloadOf(p.b.delivered[50]) == big + "49");
}

TEST_CASE("engine: without a preshared key") {
    Pair p(false);
    p.establish();
}

TEST_CASE("engine: replayed and forged data messages are rejected") {
    Pair p;
    p.establish();
    size_t before = p.b.delivered.size();

    p.world.captured.clear();
    send(p.a, "10.9.0.1", "10.9.0.2", "once");
    REQUIRE(p.world.ofType(4).size() == 1);
    Datagram last = p.world.ofType(4).back();
    p.world.pump();
    CHECK(p.b.delivered.size() == before + 1);

    // --> Replaying the same datagram is refused by the window.
    std::vector<uint8_t> copy = last.bytes;
    p.b.engine->receiveDatagram(last.from, copy.data(), copy.size());
    CHECK(p.b.delivered.size() == before + 1);
    CHECK(p.b.engine->stats().replayed >= 1);

    // --> A flipped ciphertext bit fails authentication.
    copy = last.bytes;
    copy[20] ^= 1;
    p.b.engine->receiveDatagram(last.from, copy.data(), copy.size());
    CHECK(p.b.delivered.size() == before + 1);
    CHECK(p.b.engine->stats().invalidMac >= 1);

    // --> Out-of-order delivery inside the window is fine.
    p.world.captured.clear();
    for (int i = 0; i < 5; ++i) {
        send(p.a, "10.9.0.1", "10.9.0.2", "n" + std::to_string(i));
    }

    p.world.wire.clear();
    std::vector<Datagram> five = p.world.ofType(4);
    REQUIRE(five.size() == 5);
    for (int i = 4; i >= 0; --i) {
        std::vector<uint8_t> d = five[size_t(i)].bytes;
        p.b.engine->receiveDatagram(five[size_t(i)].from, d.data(), d.size());
    }

    CHECK(p.b.delivered.size() == before + 6);
}

TEST_CASE("engine: packets with a source outside the peer's allowed IPs are dropped") {
    Pair p;
    p.establish();
    size_t before = p.b.delivered.size();
    send(p.a, "10.77.0.1", "10.9.0.2", "spoofed");
    p.world.pump();
    CHECK(p.b.delivered.size() == before);
    CHECK(p.b.engine->stats().invalidSource == 1);

    // --> No route on the sender side for an address no peer owns.
    send(p.a, "10.9.0.1", "192.0.2.1", "nowhere");
    CHECK(p.a.engine->stats().noRoute == 1);
}

TEST_CASE("engine: rekey after REKEY_AFTER_TIME and session expiry after REJECT_AFTER_TIME") {
    Pair p;
    p.establish();
    uint64_t sessions = p.a.engine->stats().sessionsDerived;

    // --> Keep traffic flowing past REKEY_AFTER_TIME: the initiator renews the session.
    for (int i = 0; i < 13; ++i) {
        p.world.advance(10000, 1000);
        send(p.a, "10.9.0.1", "10.9.0.2", "tick");
        send(p.b, "10.9.0.2", "10.9.0.1", "tock");
        p.world.pump();
    }

    CHECK(p.a.engine->stats().sessionsDerived > sessions);
    size_t got = p.b.delivered.size();
    send(p.a, "10.9.0.1", "10.9.0.2", "after rekey");
    p.world.pump();
    REQUIRE(p.b.delivered.size() == got + 1);
    CHECK(payloadOf(p.b.delivered.back()) == "after rekey");

    // --> Silence long enough for every session to expire (and the keys to be wiped): the next
    // packet waits for a fresh handshake and is then delivered.
    p.world.drop = true;
    p.world.advance(600000, 5000);
    p.world.drop = false;
    p.world.wire.clear();
    got = p.b.delivered.size();
    uint64_t initiations = p.a.engine->stats().initiationsSent;
    send(p.a, "10.9.0.1", "10.9.0.2", "fresh");
    p.world.pump();
    CHECK(p.a.engine->stats().initiationsSent == initiations + 1);
    REQUIRE(p.b.delivered.size() == got + 1);
    CHECK(payloadOf(p.b.delivered.back()) == "fresh");
}

TEST_CASE("engine: handshake retransmission and giving up") {
    Pair p;
    p.world.drop = true;
    send(p.a, "10.9.0.1", "10.9.0.2", "lost");
    CHECK(p.a.engine->stats().initiationsSent == 1);

    // --> One retry per REKEY_TIMEOUT (+jitter) until REKEY_ATTEMPT_TIME.
    p.world.advance(30000, 100);
    uint64_t sent = p.a.engine->stats().initiationsSent;
    CHECK(sent >= 5);
    CHECK(sent <= 7);

    p.world.advance(90000, 100);
    sent = p.a.engine->stats().initiationsSent;
    CHECK(sent >= 18);
    CHECK(sent <= 20);

    // --> Given up: no more initiations, the staged packet is gone.
    p.world.advance(30000, 100);
    CHECK(p.a.engine->stats().initiationsSent == sent);
    p.world.drop = false;
    p.world.advance(1000);
    CHECK(p.b.delivered.empty());
}

TEST_CASE("engine: cookie reply under load, then the handshake completes with MAC2") {
    Pair p;
    p.b.engine->forceUnderLoad(true);

    send(p.a, "10.9.0.1", "10.9.0.2", "load");
    p.world.pump();
    CHECK(p.b.engine->stats().cookieRepliesSent == 1);
    CHECK(p.a.engine->stats().cookieRepliesReceived == 1);
    CHECK(p.b.engine->stats().responsesSent == 0);
    CHECK(p.b.delivered.empty());

    // --> The retransmission carries a valid MAC2 and is answered.
    p.world.advance(6000, 100);
    CHECK(p.b.engine->stats().responsesSent == 1);
    REQUIRE(p.b.delivered.size() == 1);
    CHECK(payloadOf(p.b.delivered[0]) == "load");

    // --> A forged initiation (bad MAC1) is ignored without a cookie reply.
    std::vector<uint8_t> junk(148, 0);
    junk[0] = 1;
    p.b.engine->receiveDatagram(p.a.address, junk.data(), junk.size());
    CHECK(p.b.engine->stats().cookieRepliesSent == 1);
    CHECK(p.b.engine->stats().invalidMac >= 1);
}

TEST_CASE("engine: load detection by handshake rate") {
    Pair p(true, 3);
    p.world.drop = true;
    send(p.a, "10.9.0.1", "10.9.0.2", "x");
    p.world.drop = false;
    std::vector<Datagram> inits = p.world.ofType(1);
    REQUIRE(inits.size() == 1);

    // --> The first copy is consumed, the next ones are TAI64N replays, and once more than three
    // handshake messages arrived within a second the responder demands cookies.
    for (int i = 0; i < 6; ++i) {
        std::vector<uint8_t> d = inits[0].bytes;
        p.b.engine->receiveDatagram(inits[0].from, d.data(), d.size());
    }

    CHECK(p.b.engine->stats().responsesSent == 1);
    CHECK(p.b.engine->stats().replayed == 2);
    CHECK(p.b.engine->stats().cookieRepliesSent == 3);

    // --> A second later the load is gone again.
    p.world.wire.clear();
    p.world.now += 2500;
    uint64_t cookies = p.b.engine->stats().cookieRepliesSent;
    std::vector<uint8_t> d = inits[0].bytes;
    p.b.engine->receiveDatagram(inits[0].from, d.data(), d.size());
    CHECK(p.b.engine->stats().cookieRepliesSent == cookies);
}

TEST_CASE("engine: roaming follows the authenticated source address") {
    Pair p;
    p.establish();

    // --> A moves to a new underlay address.
    p.a.address = endpoint("10.0.0.99", 40000);
    send(p.a, "10.9.0.1", "10.9.0.2", "moved");
    p.world.pump();

    SWgPeerStatus st;
    REQUIRE(p.b.engine->peer(p.a.pub, st) == SBOX_OK);
    CHECK(st.endpoint.toString() == "10.0.0.99:40000");

    size_t got = p.a.delivered.size();
    send(p.b, "10.9.0.2", "10.9.0.1", "follow");
    p.world.pump();
    REQUIRE(p.a.delivered.size() == got + 1);
    CHECK(payloadOf(p.a.delivered.back()) == "follow");

    // --> A forged packet from yet another address does not move the endpoint.
    std::vector<uint8_t> junk(64, 0);
    junk[0] = 4;
    p.b.engine->receiveDatagram(endpoint("10.0.0.66", 1), junk.data(), junk.size());
    REQUIRE(p.b.engine->peer(p.a.pub, st) == SBOX_OK);
    CHECK(st.endpoint.toString() == "10.0.0.99:40000");
}

TEST_CASE("engine: passive keepalive and persistent keepalive") {
    Pair p;
    p.establish();

    // --> B receives data and has nothing to send: it answers with a keepalive after 10 s.
    uint64_t ka = p.b.engine->stats().keepalivesSent;
    send(p.a, "10.9.0.1", "10.9.0.2", "ping");
    p.world.pump();
    p.world.advance(11000, 500);
    CHECK(p.b.engine->stats().keepalivesSent == ka + 1);

    // --> Persistent keepalive every 2 s from A.
    SWgPeerConfig upd;
    upd.publicKey = p.b.pub;
    upd.persistentKeepalive = 2;
    upd.replaceAllowedIps = false;
    REQUIRE(p.a.engine->setPeer(upd) == SBOX_OK);
    p.world.pump();
    uint64_t before = p.a.engine->stats().keepalivesSent;
    p.world.advance(10000, 250);
    uint64_t after = p.a.engine->stats().keepalivesSent;
    CHECK(after >= before + 4);
    CHECK(after <= before + 6);
}

TEST_CASE("engine: peer management") {
    Pair p;
    p.establish();
    CHECK(p.a.engine->peers().size() == 1);

    // --> Adding allowed IPs without replacing, then replacing.
    SWgPeerConfig upd;
    upd.publicKey = p.b.pub;
    upd.allowedIps = { prefix("172.16.0.0/12") };
    upd.replaceAllowedIps = false;
    REQUIRE(p.a.engine->setPeer(upd) == SBOX_OK);
    SWgPeerStatus st;
    REQUIRE(p.a.engine->peer(p.b.pub, st) == SBOX_OK);
    CHECK(st.allowedIps.size() == 3);

    upd.replaceAllowedIps = true;
    REQUIRE(p.a.engine->setPeer(upd) == SBOX_OK);
    REQUIRE(p.a.engine->peer(p.b.pub, st) == SBOX_OK);
    CHECK(st.allowedIps.size() == 1);

    // --> update_only does not create.
    SWgKey other;
    REQUIRE(GenerateWgPrivateKey(other) == SBOX_OK);
    SWgPeerConfig ghost;
    ghost.publicKey = other;
    ghost.updateOnly = true;
    REQUIRE(p.a.engine->setPeer(ghost) == SBOX_OK);
    CHECK(p.a.engine->peers().size() == 1);

    // --> Our own key is ignored.
    SWgPeerConfig self;
    self.publicKey = p.a.pub;
    REQUIRE(p.a.engine->setPeer(self) == SBOX_OK);
    CHECK(p.a.engine->peers().size() == 1);

    REQUIRE(p.a.engine->removePeer(p.b.pub) == SBOX_OK);
    CHECK(p.a.engine->peers().empty());
    CHECK(p.a.engine->removePeer(p.b.pub) == -ENOENT);

    // --> Traffic now has no route, and B's data finds no session.
    send(p.a, "10.9.0.1", "10.9.0.2", "gone");
    CHECK(p.a.engine->stats().noRoute == 1);
}

TEST_CASE("engine: changing the private key drops sessions") {
    Pair p;
    p.establish();
    SWgKey fresh;
    REQUIRE(GenerateWgPrivateKey(fresh) == SBOX_OK);
    REQUIRE(p.a.engine->privateKey(fresh) == SBOX_OK);
    CHECK(p.a.engine->publicKey() != p.a.pub);

    // --> B does not know the new key, so a new handshake from A fails silently.
    size_t got = p.b.delivered.size();
    send(p.a, "10.9.0.1", "10.9.0.2", "new identity");
    p.world.pump();
    CHECK(p.b.delivered.size() == got);
}
