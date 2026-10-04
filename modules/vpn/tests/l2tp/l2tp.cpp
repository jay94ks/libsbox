#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/l2tp/l2tp.hpp>
#include "testutil.hpp"
#include <deque>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

namespace {

    /**
     * An LNS and a LAC tunnel back to back in memory with an optional loss/reorder filter.
     */
    struct Pair {
        CL2tpTunnel lns;
        CL2tpTunnel lac;
        std::deque<std::pair<bool, std::vector<uint8_t>>> wire;     // --> (toLns, packet).
        std::function<bool(bool toLns, const std::vector<uint8_t>&)> drop;
        bool reorder = false;
        int64_t now = 0;
        std::vector<std::string> lnsData;
        std::vector<std::string> lacData;
        uint16_t lnsSession = 0;
        uint16_t lacSession = 0;
        size_t lnsDown = 0;
        size_t lacDown = 0;
        std::string lnsClosed;
        std::string lacClosed;
        Log log;

        Pair(SL2tpTunnelConfig lnsConfig, SL2tpTunnelConfig lacConfig)
            : lns(lnsConfig, true, 0x1111), lac(lacConfig, false, 0x2222) {
            now = CEventLoop::nowMs();
            lns.sender([this](const SReadOnlyByteSpan& p) { wire.emplace_back(false, std::vector<uint8_t>(p.data, p.data + p.size)); });
            lac.sender([this](const SReadOnlyByteSpan& p) { wire.emplace_back(true, std::vector<uint8_t>(p.data, p.data + p.size)); });
            lns.logger([this](const std::string& m) { log.add(0, "LNS " + m); });
            lac.logger([this](const std::string& m) { log.add(0, "LAC " + m); });
            lns.onSessionUp([this](uint16_t s) { lnsSession = s; });
            lac.onSessionUp([this](uint16_t s) { lacSession = s; });
            lns.onSessionData([this](uint16_t, const SReadOnlyByteSpan& d) { lnsData.emplace_back(reinterpret_cast<const char*>(d.data), d.size); });
            lac.onSessionData([this](uint16_t, const SReadOnlyByteSpan& d) { lacData.emplace_back(reinterpret_cast<const char*>(d.data), d.size); });
            lns.onSessionDown([this](uint16_t, const std::string&) { ++lnsDown; });
            lac.onSessionDown([this](uint16_t, const std::string&) { ++lacDown; });
            lns.onClosed([this](const std::string& r) { lnsClosed = r.empty() ? "closed" : r; });
            lac.onClosed([this](const std::string& r) { lacClosed = r.empty() ? "closed" : r; });
        }

        /* Delivers packets; ticks the clock by `stepMs` when the wire is idle, `rounds` times. */
        void run(int rounds = 1, int64_t stepMs = 0) {
            for (int r = 0; r < rounds; ++r) {
                size_t guard = 0;
                while (!wire.empty() && guard++ < 1000) {
                    if (reorder && wire.size() >= 2 && (guard % 3) == 0) {
                        std::swap(wire[0], wire[1]);
                    }

                    auto [toLns, p] = std::move(wire.front());
                    wire.pop_front();
                    if (drop && drop(toLns, p)) {
                        continue;
                    }

                    (toLns ? lns : lac).input(Bytes(p));
                }

                if (stepMs) {
                    now += stepMs;
                    lns.tick(now);
                    lac.tick(now);
                }
            }
        }

        /* Brings the tunnel and one session up. */
        bool connect() {
            lac.start();
            run(40, 500);
            if (lac.state() != EL2TS_ESTABLISHED || lns.state() != EL2TS_ESTABLISHED) {
                return false;
            }

            lac.openSession();
            run(40, 500);
            return lnsSession != 0 && lacSession != 0;
        }
    };

}

TEST_CASE("Header parsing: control and data forms, offsets, rejection of other versions") {
    std::vector<SL2tpAvp> avps;
    avps.push_back(SL2tpAvp::of16(EL2TP_AVP_MESSAGE_TYPE, EL2TP_HELLO));
    std::vector<uint8_t> c = BuildL2tpControl(7, 9, 3, 4, avps);
    SL2tpHeader h;
    REQUIRE(ParseL2tpHeader(Bytes(c), h) == SBOX_OK);
    CHECK(h.control);
    CHECK(h.tunnelId == 7);
    CHECK(h.sessionId == 9);
    CHECK(h.ns == 3);
    CHECK(h.nr == 4);
    CHECK(h.payloadOffset == 12);
    CHECK(h.packetSize == c.size());

    std::vector<uint8_t> ppp = { 0xff, 0x03, 0xc0, 0x21 };
    std::vector<uint8_t> d = BuildL2tpData(5, 6, Bytes(ppp));
    REQUIRE(ParseL2tpHeader(Bytes(d), h) == SBOX_OK);
    CHECK_FALSE(h.control);
    CHECK(h.payloadOffset == 6);

    // --> Data with L, S and an offset pad of 2.
    std::vector<uint8_t> o = { 0x4a, 0x02, 0x00, 0x12, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0xaa, 0xbb, 0xff, 0x03 };
    REQUIRE(ParseL2tpHeader(Bytes(o), h) == SBOX_OK);
    CHECK(h.hasSequence);
    CHECK(h.payloadOffset == 16);

    std::vector<uint8_t> v3 = { 0xc8, 0x03, 0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(ParseL2tpHeader(Bytes(v3), h) == -EPROTONOSUPPORT);
    std::vector<uint8_t> noSeq = { 0xc0, 0x02, 0x00, 0x08, 0, 1, 0, 0 };
    CHECK(ParseL2tpHeader(Bytes(noSeq), h) == -EBADMSG);
    std::vector<uint8_t> badLen = { 0xc8, 0x02, 0x00, 0x40, 0, 1, 0, 0, 0, 0, 0, 0 };
    CHECK(ParseL2tpHeader(Bytes(badLen), h) == -EBADMSG);
}

TEST_CASE("Hidden AVPs: reveal a vector computed independently, round trip our own") {
    // --> Random Vector a0..af, then Host Name "lac.example.com" hidden with "tunnelsecret"
    // (RFC 2661 4.3, computed with Python's hashlib).
    std::vector<uint8_t> wire = Unhex("801600000024a0a1a2a3a4a5a6a7a8a9aaabacadaeafc026000000074dbc32fe5fb803e2d3b84a1824fb5315faa15ba166681f6f4836d028459b809c");
    std::vector<SL2tpAvp> avps;
    REQUIRE(ParseL2tpAvps(Bytes(wire), "tunnelsecret", avps) == SBOX_OK);
    REQUIRE(avps.size() == 2);
    CHECK(avps[1].hidden);
    CHECK(avps[1].text() == "lac.example.com");
    CHECK(ParseL2tpAvps(Bytes(wire), "", avps) == -EACCES);
    if (ParseL2tpAvps(Bytes(wire), "othersecret", avps) == SBOX_OK) {
        CHECK(avps[1].text() != "lac.example.com");
    }

    std::vector<SL2tpAvp> mine;
    mine.push_back(SL2tpAvp::of16(EL2TP_AVP_MESSAGE_TYPE, EL2TP_SCCRQ));
    SL2tpAvp host = SL2tpAvp::ofBytes(EL2TP_AVP_HOST_NAME, BytesOf(std::string_view("a-rather-long-host-name.example.org")));
    host.hidden = true;
    mine.push_back(host);
    std::vector<uint8_t> enc;
    EncodeL2tpAvps(mine, "s3", enc);
    REQUIRE(ParseL2tpAvps(Bytes(enc), "s3", avps) == SBOX_OK);
    REQUIRE(avps.size() == 3);
    CHECK(avps[1].type == EL2TP_AVP_RANDOM_VECTOR);
    CHECK(avps[2].text() == "a-rather-long-host-name.example.org");
}

TEST_CASE("Tunnel and session setup, data both ways, CDN and StopCCN") {
    Pair p({}, {});
    REQUIRE(p.connect());
    CHECK(p.lns.peerHostName() == "sbox-l2tp");
    CHECK(p.lns.peerId() == 0x2222);
    CHECK(p.lac.peerId() == 0x1111);
    CHECK(p.lns.sessionCount() == 1);

    std::string hello = "\xff\x03\xc0\x21hello";
    REQUIRE(p.lac.sendData(p.lacSession, BytesOf(hello)) == SBOX_OK);
    REQUIRE(p.lns.sendData(p.lnsSession, BytesOf(std::string_view("reply"))) == SBOX_OK);
    p.run();
    REQUIRE(p.lnsData.size() == 1);
    CHECK(p.lnsData[0] == hello);
    REQUIRE(p.lacData.size() == 1);
    CHECK(p.lacData[0] == "reply");

    p.lns.closeSession(p.lnsSession, EL2TP_RES_CDN_ADMIN, "bye");
    p.run(4, 500);
    CHECK(p.lnsDown == 1);
    CHECK(p.lacDown == 1);
    CHECK(p.lac.sessionCount() == 0);

    p.lac.close(EL2TP_RES_STOP_GENERAL, "done");
    p.run(20, 500);
    CHECK(p.lns.state() == EL2TS_CLOSED);
    CHECK(p.lac.state() == EL2TS_CLOSED);
    CHECK(p.lnsClosed.find("StopCCN") != std::string::npos);
}

TEST_CASE("Tunnel authentication with a shared secret and hidden AVPs") {
    SL2tpTunnelConfig c;
    c.secret = "tunnel-secret";
    Pair p(c, c);
    REQUIRE(p.connect());

    SL2tpTunnelConfig other;
    other.secret = "different";
    Pair q(c, other);
    q.lac.start();
    q.run(40, 500);
    CHECK(q.lac.state() != EL2TS_ESTABLISHED);
    CHECK(q.lns.state() != EL2TS_ESTABLISHED);

    // --> A LAC that asks for authentication when the LNS has no secret is refused.
    Pair r({}, c);
    r.lac.start();
    r.run(40, 500);
    CHECK(r.lns.state() != EL2TS_ESTABLISHED);
}

TEST_CASE("Reliable delivery survives loss, duplication and reordering") {
    Pair p({}, {});
    int n = 0;
    p.drop = [&n](bool, const std::vector<uint8_t>& pkt) {
        SL2tpHeader h;
        if (ParseL2tpHeader(Bytes(pkt), h) != SBOX_OK || !h.control) {
            return false;
        }

        return (++n % 3) == 0;
    };
    p.reorder = true;
    REQUIRE(p.connect());

    // --> Duplicate every packet for a while: duplicates are acknowledged and ignored.
    p.drop = nullptr;
    for (int k = 0; k < 3; ++k) {
        p.lac.openSession();
        std::deque<std::pair<bool, std::vector<uint8_t>>> doubled;
        for (auto& w : p.wire) {
            doubled.push_back(w);
            doubled.push_back(w);
        }

        p.wire = doubled;
        p.run(10, 500);
    }

    CHECK(p.lns.sessionCount() == 4);
    CHECK(p.lac.sessionCount() == 4);
}

TEST_CASE("HELLO keepalive and a vanished peer") {
    SL2tpTunnelConfig c;
    c.helloSeconds = 2;
    c.retransmitTries = 3;
    c.retransmitCapMs = 1000;
    Pair p(c, c);
    REQUIRE(p.connect());
    p.run(20, 500);
    CHECK(p.lns.state() == EL2TS_ESTABLISHED);
    CHECK(p.log.contains("received HELLO"));

    // --> The LAC goes silent: the LNS's HELLO is never acknowledged.
    p.drop = [](bool toLns, const std::vector<uint8_t>&) { return toLns; };
    p.run(60, 500);
    CHECK(p.lns.state() == EL2TS_CLOSED);
    CHECK(p.lnsDown == 1);
    CHECK(p.lnsClosed == "peer not responding");
}

TEST_CASE("Unknown mandatory AVP tears the tunnel down, unknown optional ones are ignored") {
    CL2tpTunnel lns({}, true, 0x3333);
    std::vector<std::vector<uint8_t>> out;
    lns.sender([&](const SReadOnlyByteSpan& p) { out.emplace_back(p.data, p.data + p.size); });
    std::vector<SL2tpAvp> avps;
    avps.push_back(SL2tpAvp::of16(EL2TP_AVP_MESSAGE_TYPE, EL2TP_SCCRQ));
    avps.push_back(SL2tpAvp::of16(EL2TP_AVP_PROTOCOL_VERSION, 0x0100));
    avps.push_back(SL2tpAvp::ofBytes(EL2TP_AVP_HOST_NAME, BytesOf(std::string_view("lac"))));
    avps.push_back(SL2tpAvp::of32(EL2TP_AVP_FRAMING_CAPABILITIES, 3));
    avps.push_back(SL2tpAvp::of16(EL2TP_AVP_ASSIGNED_TUNNEL_ID, 77));
    SL2tpAvp vendor = SL2tpAvp::of32(99, 1, false);
    vendor.vendor = 311;    // --> Microsoft, optional: ignored.
    avps.push_back(vendor);
    std::vector<uint8_t> sccrq = BuildL2tpControl(0, 0, 0, 0, avps);
    lns.input(Bytes(sccrq));
    CHECK(lns.state() == EL2TS_WAIT_CONNECT);

    CL2tpTunnel lns2({}, true, 0x4444);
    lns2.sender([&](const SReadOnlyByteSpan&) {});
    vendor.mandatory = true;
    avps.push_back(vendor);
    lns2.input(Bytes(BuildL2tpControl(0, 0, 0, 0, avps)));
    CHECK(lns2.state() == EL2TS_CLOSING);
}
