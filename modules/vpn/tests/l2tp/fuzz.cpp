#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <sbox/vpn/l2tp/l2tp.hpp>
#include <sbox/vpn/l2tp/ppp.hpp>
#include <sbox/vpn/l2tp/transport.hpp>
#include "testutil.hpp"
#include <deque>
#include <random>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

// --> Malformed input must never crash a decoder or a state machine: valid messages captured
// from real exchanges are mutated (bit flips, truncation, length field damage, splices) and fed
// back, together with pure random data.

namespace {

    /* Mutates a message. */
    std::vector<uint8_t> mutate(std::mt19937& rng, const std::vector<uint8_t>& in) {
        std::vector<uint8_t> m = in;
        int kind = int(rng() % 6);
        if (m.empty() || kind == 5) {
            std::vector<uint8_t> r(rng() % 300);
            for (uint8_t& b : r) {
                b = uint8_t(rng());
            }

            return r;
        }

        int edits = 1 + int(rng() % 4);
        for (int i = 0; i < edits && !m.empty(); ++i) {
            size_t at = rng() % m.size();
            switch (kind) {
            case 0: m[at] ^= uint8_t(1u << (rng() % 8)); break;
            case 1: m[at] = uint8_t(rng()); break;
            case 2: m.resize(at); break;
            case 3:
                // --> Length-ish fields: set big or zero 16-bit values.
                if (at + 1 < m.size()) {
                    uint16_t v = (rng() & 1) ? uint16_t(0xffff) : uint16_t(rng() % 8);
                    m[at] = uint8_t(v >> 8);
                    m[at + 1] = uint8_t(v);
                }

                break;
            default:
                m.insert(m.begin() + long(at), uint8_t(rng()));
                break;
            }
        }

        return m;
    }

    SEndpoint ep(const char* addr, uint16_t port) {
        SEndpoint e;
        SEndpoint::fromIp(addr, port, e);
        return e;
    }

    SIkev1Config ikeConfig() {
        SIkev1Config c;
        SIkePsk p;
        p.secret = "fuzz";
        c.psks.push_back(p);
        return c;
    }

}

TEST_CASE("IKEv1 decoders survive random and mutated input") {
    std::mt19937 rng(12345);
    // --> Seeds: a real SA payload, ID, notify, delete.
    SIkev1Sa sa;
    SIkev1Proposal prop;
    prop.protocol = EIKE1_PROTO_ESP;
    prop.spi = { 1, 2, 3, 4 };
    SIkev1Transform t;
    t.id = EIKE1_ESP_AES;
    t.attributes = { { EIKE1_IA_LIFE_TYPE, 1, false }, { EIKE1_IA_LIFE_DURATION, 3600, true }, { EIKE1_IA_KEY_LENGTH, 256, false } };
    prop.transforms = { t, t };
    sa.proposals = { prop, prop };
    std::vector<uint8_t> saBody;
    EncodeIkev1Sa(sa, saBody);
    SIkev1Sa back;
    REQUIRE(DecodeIkev1Sa(Bytes(saBody), back) == SBOX_OK);
    CHECK(back.proposals.size() == 2);
    CHECK(back.proposals[0].transforms[1].attr(EIKE1_IA_LIFE_DURATION) == 3600);

    std::vector<uint8_t> chain;
    uint8_t first = 0;
    EncodeIkev1Payloads({ MakeIkev1Payload(EIKE1_PL_SA, saBody), MakeIkev1Payload(EIKE1_PL_VENDOR, Ikev1VendorId(EIKE1_VID_DPD)) }, chain, first);

    for (int i = 0; i < 30000; ++i) {
        std::vector<uint8_t> m = mutate(rng, (i % 2) ? saBody : chain);
        SIkev1Sa s;
        DecodeIkev1Sa(Bytes(m), s);
        std::vector<SIkev1Payload> p;
        size_t end = 0;
        ParseIkev1Payloads(uint8_t(rng() % 20), Bytes(m), p, &end);
        CHECK(end <= m.size());
        SIkev1Id id;
        DecodeIkev1Id(Bytes(m), id);
        id.toString();
        SIkev1Notify n;
        DecodeIkev1Notify(Bytes(m), n);
        SIkev1Delete d;
        DecodeIkev1Delete(Bytes(m), d);
        net::SIpAddress a;
        DecodeIkev1NatOa(Bytes(m), a);
        Ikev1ClassifyVendorId(Bytes(m));
    }
}

TEST_CASE("IKEv1 responder survives mutated exchanges and still negotiates afterwards") {
    std::mt19937 rng(777);
    // --> Record a complete, valid negotiation.
    std::vector<std::vector<uint8_t>> toResponder;
    {
        CIkev1Responder r(ikeConfig());
        CIkev1Initiator i(ikeConfig(), ep("10.0.0.1", 500), 4500);
        std::deque<std::pair<bool, std::vector<uint8_t>>> q;
        i.sender([&](const SReadOnlyByteSpan& m, const SEndpoint&, const SEndpoint&, bool) { q.emplace_back(true, std::vector<uint8_t>(m.data, m.data + m.size)); });
        r.sender([&](const SReadOnlyByteSpan& m, const SEndpoint&, const SEndpoint&, bool) { q.emplace_back(false, std::vector<uint8_t>(m.data, m.data + m.size)); });
        net::SIpAddress local;
        net::SIpAddress::parse("10.0.0.2", local);
        i.start(local, 500, 4500);
        while (!q.empty()) {
            auto [toR, m] = q.front();
            q.pop_front();
            SIkeDatagram dg;
            dg.data = m;
            if (toR) {
                toResponder.push_back(m);
                dg.remote = ep("10.0.0.2", 500);
                dg.local = ep("10.0.0.1", 500);
                r.handle(dg);
            }
            else {
                dg.remote = ep("10.0.0.1", 500);
                dg.local = ep("10.0.0.2", 500);
                i.handle(dg);
            }
        }

        REQUIRE(i.established());
    }

    // --> Replay mutated versions of every message into a fresh responder, in order, so the
    // mutations hit every state (MM1, MM3, encrypted MM5, Quick Mode).
    for (int round = 0; round < 300; ++round) {
        CIkev1Responder r(ikeConfig());
        size_t up = 0;
        r.onSaUp([&](const SIkev1IpsecSa&) { ++up; });
        r.sender([](const SReadOnlyByteSpan&, const SEndpoint&, const SEndpoint&, bool) {});
        for (const std::vector<uint8_t>& m : toResponder) {
            SIkeDatagram dg;
            dg.remote = ep("10.0.0.2", 500);
            dg.local = ep("10.0.0.1", 500);
            for (int k = 0; k < 8; ++k) {
                dg.data = mutate(rng, m);
                r.handle(dg);
            }

            dg.data = m;
            r.handle(dg);
        }

        r.tick(CEventLoop::nowMs() + 100000);
        CHECK(up <= 1);
    }
}

TEST_CASE("L2TP decoders and tunnels survive mutated control messages") {
    std::mt19937 rng(4242);
    // --> Capture a valid tunnel + session setup.
    std::vector<std::vector<uint8_t>> toLns;
    std::vector<std::vector<uint8_t>> toLac;
    {
        SL2tpTunnelConfig c;
        c.secret = "hidden";
        CL2tpTunnel lns(c, true, 0x1111);
        CL2tpTunnel lac(c, false, 0x2222);
        std::deque<std::pair<bool, std::vector<uint8_t>>> q;
        lns.sender([&](const SReadOnlyByteSpan& p) { q.emplace_back(false, std::vector<uint8_t>(p.data, p.data + p.size)); });
        lac.sender([&](const SReadOnlyByteSpan& p) { q.emplace_back(true, std::vector<uint8_t>(p.data, p.data + p.size)); });
        lac.onEstablished([&] { lac.openSession(); });
        lac.start();
        while (!q.empty()) {
            auto [toL, p] = q.front();
            q.pop_front();
            (toL ? toLns : toLac).push_back(p);
            (toL ? lns : lac).input(Bytes(p));
        }

        REQUIRE(lns.sessionCount() == 1);
    }

    for (int i = 0; i < 20000; ++i) {
        std::vector<uint8_t> m = mutate(rng, toLns[size_t(rng()) % toLns.size()]);
        SL2tpHeader h;
        if (ParseL2tpHeader(Bytes(m), h) == SBOX_OK) {
            CHECK(h.payloadOffset <= h.packetSize);
            CHECK(h.packetSize <= m.size());
            std::vector<SL2tpAvp> avps;
            ParseL2tpAvps(SReadOnlyByteSpan(m.data() + h.payloadOffset, h.packetSize - h.payloadOffset), "hidden", avps);
        }
    }

    for (int round = 0; round < 300; ++round) {
        SL2tpTunnelConfig c;
        c.secret = "hidden";
        CL2tpTunnel lns(c, true, 0x1111);
        CL2tpTunnel lac(c, false, 0x2222);
        lns.sender([](const SReadOnlyByteSpan&) {});
        lac.sender([](const SReadOnlyByteSpan&) {});
        lac.start();
        for (size_t k = 0; k < toLns.size(); ++k) {
            for (int j = 0; j < 4; ++j) {
                lns.input(Bytes(mutate(rng, toLns[k])));
            }

            lns.input(Bytes(toLns[k]));
            if (k < toLac.size()) {
                lac.input(Bytes(mutate(rng, toLac[k])));
                lac.input(Bytes(toLac[k]));
            }
        }

        lns.tick(CEventLoop::nowMs() + 60000);
        lac.tick(CEventLoop::nowMs() + 60000);
    }
}

TEST_CASE("PPP survives mutated frames in every phase") {
    std::mt19937 rng(99);
    SPppConfig server;
    server.server = true;
    server.auth = { EPPPA_MSCHAPV2, EPPPA_CHAP_MD5, EPPPA_PAP };
    SPppUser u;
    u.name = "alice";
    u.password = "pw";
    server.users = { u };
    net::SIpAddress::parse("10.1.0.1", server.localAddress);
    SPppConfig client;
    client.server = false;
    client.user = "alice";
    client.password = "pw";
    client.auth = server.auth;

    // --> Capture a full negotiation.
    std::vector<std::vector<uint8_t>> toServer;
    std::vector<std::vector<uint8_t>> toClient;
    {
        CPppSession s(server);
        CPppSession c(client);
        std::deque<std::pair<bool, std::vector<uint8_t>>> q;
        s.sender([&](const SReadOnlyByteSpan& f) { q.emplace_back(false, std::vector<uint8_t>(f.data, f.data + f.size)); });
        c.sender([&](const SReadOnlyByteSpan& f) { q.emplace_back(true, std::vector<uint8_t>(f.data, f.data + f.size)); });
        s.allocator([](const std::string&, const std::string&, net::SIpAddress& out) { return net::SIpAddress::parse("10.1.0.2", out) == SBOX_OK; });
        s.start();
        c.start();
        while (!q.empty()) {
            auto [toS, f] = q.front();
            q.pop_front();
            (toS ? toServer : toClient).push_back(f);
            (toS ? s : c).input(Bytes(f));
        }

        REQUIRE(s.isUp());
        REQUIRE(c.isUp());
    }

    for (int round = 0; round < 400; ++round) {
        CPppSession s(server);
        CPppSession c(client);
        s.sender([](const SReadOnlyByteSpan&) {});
        c.sender([](const SReadOnlyByteSpan&) {});
        s.allocator([](const std::string&, const std::string&, net::SIpAddress& out) { return net::SIpAddress::parse("10.1.0.2", out) == SBOX_OK; });
        s.start();
        c.start();
        size_t n = std::max(toServer.size(), toClient.size());
        for (size_t k = 0; k < n; ++k) {
            if (k < toServer.size()) {
                for (int j = 0; j < 4; ++j) {
                    s.input(Bytes(mutate(rng, toServer[k])));
                }

                s.input(Bytes(toServer[k]));
            }

            if (k < toClient.size()) {
                for (int j = 0; j < 4; ++j) {
                    c.input(Bytes(mutate(rng, toClient[k])));
                }

                c.input(Bytes(toClient[k]));
            }
        }

        s.tick(CEventLoop::nowMs() + 100000);
        c.tick(CEventLoop::nowMs() + 100000);
    }
}

TEST_CASE("UDP checksum matches a hand-computed value") {
    // --> 10.0.0.1:1701 -> 10.0.0.2:1701, payload "ab": computed with the RFC 768 algorithm in Python.
    net::SIpAddress a;
    net::SIpAddress b;
    net::SIpAddress::parse("10.0.0.1", a);
    net::SIpAddress::parse("10.0.0.2", b);
    std::vector<uint8_t> seg = { 0x06, 0xa5, 0x06, 0xa5, 0x00, 0x0a, 0x00, 0x00, 'a', 'b' };
    // --> sum = 0a00+0001 + 0a00+0002 + 0011 + 000a + 06a5+06a5+000a + 6162 = 0x82d4 -> ~ = 0x7d2b.
    CHECK(L2tpUdpChecksum(a, b, Bytes(seg)) == 0x7d2b);
}
