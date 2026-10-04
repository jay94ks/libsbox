#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/l2tp/ppp.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include "testutil.hpp"
#include <deque>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

namespace {

    net::SIpAddress ip(const char* text) {
        net::SIpAddress a;
        net::SIpAddress::parse(text, a);
        return a;
    }

    SPppConfig serverConfig(std::vector<EPppAuth> auth = { EPPPA_MSCHAPV2 }) {
        SPppConfig c;
        c.server = true;
        c.auth = auth;
        SPppUser alice;
        alice.name = "alice";
        alice.password = "Wonderland!";
        c.users.push_back(alice);
        SPppUser bob;
        bob.name = "bob";
        bob.ntHash.resize(16);
        MsChapNtPasswordHash("builder", SByteSpan(bob.ntHash.data(), 16));
        bob.address = "10.50.0.77";
        c.users.push_back(bob);
        c.localAddress = ip("10.50.0.1");
        c.dns = { ip("10.50.0.53"), ip("1.1.1.1") };
        c.nbns = { ip("10.50.0.54") };
        return c;
    }

    SPppConfig clientConfig(const std::string& user, const std::string& password, std::vector<EPppAuth> auth = { EPPPA_MSCHAPV2, EPPPA_CHAP_MD5, EPPPA_PAP }) {
        SPppConfig c;
        c.server = false;
        c.auth = auth;
        c.user = user;
        c.password = password;
        return c;
    }

    /**
     * Server and client sessions connected in memory.
     */
    struct Link {
        CPppSession server;
        CPppSession client;
        std::deque<std::pair<bool, std::vector<uint8_t>>> wire;     // --> (toServer, frame).
        std::function<bool(bool, const std::vector<uint8_t>&)> drop;
        bool serverUp = false;
        bool clientUp = false;
        std::string serverDown;
        std::string clientDown;
        SPppInfo serverInfo;
        SPppInfo clientInfo;
        std::vector<std::vector<uint8_t>> serverIp;
        std::vector<std::vector<uint8_t>> clientIp;
        int64_t now = CEventLoop::nowMs();
        Log log;

        Link(SPppConfig s, SPppConfig c) : server(s), client(c) {
            server.sender([this](const SReadOnlyByteSpan& f) { wire.emplace_back(false, std::vector<uint8_t>(f.data, f.data + f.size)); });
            client.sender([this](const SReadOnlyByteSpan& f) { wire.emplace_back(true, std::vector<uint8_t>(f.data, f.data + f.size)); });
            server.logger([this](const std::string& m) { log.add(0, m); });
            client.logger([this](const std::string& m) { log.add(0, m); });
            server.allocator([](const std::string&, const std::string& fixed, net::SIpAddress& out) {
                if (!fixed.empty()) {
                    return net::SIpAddress::parse(fixed, out) == SBOX_OK;
                }

                out = ip("10.50.0.2");
                return true;
            });
            server.onUp([this](const SPppInfo& i) {
                serverUp = true;
                serverInfo = i;
            });
            client.onUp([this](const SPppInfo& i) {
                clientUp = true;
                clientInfo = i;
            });
            server.onDown([this](const std::string& r) { serverDown = r; });
            client.onDown([this](const std::string& r) { clientDown = r; });
            server.onIp([this](const SReadOnlyByteSpan& p) { serverIp.emplace_back(p.data, p.data + p.size); });
            client.onIp([this](const SReadOnlyByteSpan& p) { clientIp.emplace_back(p.data, p.data + p.size); });
        }

        void run(int rounds = 1, int64_t stepMs = 0) {
            for (int r = 0; r < rounds; ++r) {
                size_t guard = 0;
                while (!wire.empty() && guard++ < 2000) {
                    auto [toServer, f] = std::move(wire.front());
                    wire.pop_front();
                    if (drop && drop(toServer, f)) {
                        continue;
                    }

                    (toServer ? server : client).input(Bytes(f));
                }

                if (stepMs) {
                    now += stepMs;
                    server.tick(now);
                    client.tick(now);
                }
            }
        }

        void start() {
            server.start();
            client.start();
            run(30, 500);
        }
    };

    /** Builds a minimal IPv4/UDP packet. */
    std::vector<uint8_t> ipPacket(const char* src, const char* dst) {
        std::vector<uint8_t> p(28, 0);
        p[0] = 0x45;
        p[3] = 28;
        p[8] = 64;
        p[9] = 17;
        net::SIpAddress s = ip(src);
        net::SIpAddress d = ip(dst);
        std::memcpy(p.data() + 12, s.bytes, 4);
        std::memcpy(p.data() + 16, d.bytes, 4);
        return p;
    }

}

TEST_CASE("MS-CHAPv2: LCP, mutual authentication, IPCP with address and RFC 1877 DNS") {
    Link l(serverConfig(), clientConfig("alice", "Wonderland!"));
    l.start();
    REQUIRE(l.serverUp);
    REQUIRE(l.clientUp);
    CHECK(l.serverInfo.user == "alice");
    CHECK(l.serverInfo.auth == EPPPA_MSCHAPV2);
    CHECK(l.serverInfo.peerAddress.toString() == "10.50.0.2");
    CHECK(l.clientInfo.localAddress.toString() == "10.50.0.2");
    CHECK(l.clientInfo.peerAddress.toString() == "10.50.0.1");
    REQUIRE(l.clientInfo.dns.size() == 2);
    CHECK(l.clientInfo.dns[0].toString() == "10.50.0.53");
    CHECK(l.clientInfo.dns[1].toString() == "1.1.1.1");
    CHECK(l.clientInfo.peerMru == 1400);

    std::vector<uint8_t> up = ipPacket("10.50.0.2", "10.88.0.5");
    REQUIRE(l.client.sendIp(Bytes(up)) == SBOX_OK);
    std::vector<uint8_t> downPkt = ipPacket("10.88.0.5", "10.50.0.2");
    REQUIRE(l.server.sendIp(Bytes(downPkt)) == SBOX_OK);
    l.run();
    REQUIRE(l.serverIp.size() == 1);
    CHECK(l.serverIp[0] == up);
    REQUIRE(l.clientIp.size() == 1);
    CHECK(l.clientIp[0] == downPkt);

    // --> The server drops packets whose source is not the assigned address.
    std::vector<uint8_t> spoofed = ipPacket("10.50.0.99", "10.88.0.5");
    l.client.sendIp(Bytes(spoofed));
    l.run();
    CHECK(l.serverIp.size() == 1);

    l.client.close("user disconnect");
    l.run(6, 500);
    CHECK(l.serverDown.find("peer terminated") == 0);
    CHECK(l.clientDown == "user disconnect");
}

TEST_CASE("Domain prefix, case-insensitive names and NT-hash accounts with a fixed address") {
    Link l(serverConfig(), clientConfig("CORP\\Bob", "builder"));
    l.start();
    REQUIRE(l.serverUp);
    CHECK(l.serverInfo.user == "bob");
    CHECK(l.clientInfo.localAddress.toString() == "10.50.0.77");
}

TEST_CASE("CHAP-MD5 and PAP when configured") {
    {
        Link l(serverConfig({ EPPPA_CHAP_MD5 }), clientConfig("alice", "Wonderland!"));
        l.start();
        CHECK(l.serverUp);
        CHECK(l.serverInfo.auth == EPPPA_CHAP_MD5);
    }

    {
        Link l(serverConfig({ EPPPA_PAP }), clientConfig("alice", "Wonderland!"));
        l.start();
        CHECK(l.serverUp);
        CHECK(l.serverInfo.auth == EPPPA_PAP);
    }

    {
        // --> PAP against an NT-hash account.
        Link l(serverConfig({ EPPPA_PAP }), clientConfig("bob", "builder"));
        l.start();
        CHECK(l.serverUp);
    }
}

TEST_CASE("Authentication negotiation: the client naks MS-CHAPv2 and the server falls back") {
    Link l(serverConfig({ EPPPA_MSCHAPV2, EPPPA_PAP }), clientConfig("alice", "Wonderland!", { EPPPA_PAP }));
    l.start();
    REQUIRE(l.serverUp);
    CHECK(l.serverInfo.auth == EPPPA_PAP);

    Link refuse(serverConfig({ EPPPA_MSCHAPV2 }), clientConfig("alice", "Wonderland!", { EPPPA_PAP }));
    refuse.start();
    CHECK_FALSE(refuse.serverUp);
    CHECK(refuse.serverDown == "no common authentication protocol");
}

TEST_CASE("Wrong password fails on both ends") {
    for (EPppAuth a : { EPPPA_MSCHAPV2, EPPPA_CHAP_MD5, EPPPA_PAP }) {
        CAPTURE(a);
        Link l(serverConfig({ a }), clientConfig("alice", "wrong"));
        l.start();
        CHECK_FALSE(l.serverUp);
        CHECK_FALSE(l.clientUp);
        CHECK(l.serverDown == "authentication failed");
        CHECK_FALSE(l.clientDown.empty());
    }

    Link unknown(serverConfig(), clientConfig("mallory", "x"));
    unknown.start();
    CHECK_FALSE(unknown.serverUp);
}

TEST_CASE("Negotiation survives lost frames") {
    Link l(serverConfig(), clientConfig("alice", "Wonderland!"));
    int n = 0;
    l.drop = [&n](bool, const std::vector<uint8_t>&) { return (++n % 4) == 0; };
    l.server.start();
    l.client.start();
    l.run(60, 1000);
    CHECK(l.serverUp);
    CHECK(l.clientUp);
}

TEST_CASE("LCP echo detects a dead peer") {
    SPppConfig s = serverConfig();
    s.echoSeconds = 2;
    s.echoFailures = 3;
    Link l(s, clientConfig("alice", "Wonderland!"));
    l.start();
    REQUIRE(l.serverUp);
    l.run(20, 1000);
    CHECK(l.serverDown.empty());
    l.drop = [](bool toServer, const std::vector<uint8_t>&) { return toServer; };
    l.run(40, 1000);
    CHECK(l.serverDown == "peer not responding (LCP echo)");
}

TEST_CASE("Windows-style LCP options are rejected, CCP and IPv6CP get Protocol-Reject") {
    CPppSession s(serverConfig());
    std::vector<std::vector<uint8_t>> out;
    s.sender([&](const SReadOnlyByteSpan& f) { out.emplace_back(f.data, f.data + f.size); });
    s.start();
    REQUIRE(out.size() == 1);
    // --> Our request: MRU 1400, auth MS-CHAPv2, magic.
    CHECK(out[0][4] == 1);
    out.clear();

    // --> Windows: MRU 1400, magic, PFC, ACFC, callback (13), MRRU (17), endpoint discriminator (19).
    std::vector<uint8_t> req = { 0xff, 0x03, 0xc0, 0x21, 1, 7, 0, 0,
                                 1, 4, 0x05, 0x78,
                                 5, 6, 0x12, 0x34, 0x56, 0x78,
                                 7, 2,
                                 8, 2,
                                 13, 3, 6,
                                 17, 4, 0x06, 0x4e,
                                 19, 3, 0 };
    req[7] = uint8_t(req.size() - 4);
    s.input(Bytes(req));
    REQUIRE(out.size() == 1);
    // --> Configure-Reject with the three unsupported options.
    CHECK(out[0][4] == 4);
    CHECK(out[0][5] == 7);
    std::vector<uint8_t> rejected(out[0].begin() + 8, out[0].end());
    CHECK(rejected == std::vector<uint8_t>{ 13, 3, 6, 17, 4, 0x06, 0x4e, 19, 3, 0 });
    out.clear();

    // --> After LCP is open, unknown protocols are rejected.
    std::vector<uint8_t> clean = { 0xff, 0x03, 0xc0, 0x21, 1, 8, 0, 16, 1, 4, 0x05, 0x78, 5, 6, 0x12, 0x34, 0x56, 0x78, 7, 2 };
    s.input(Bytes(clean));
    REQUIRE(out.size() == 1);
    CHECK(out[0][4] == 2);   // --> Configure-Ack.
    out.clear();
    std::vector<uint8_t> ack = { 0xff, 0x03, 0xc0, 0x21, 2, 1 };
    // --> Ack our request id 1 with whatever we sent (the server checks only the id).
    std::vector<uint8_t> ourReq = { 1, 4, 0x05, 0x78, 3, 5, 0xc2, 0x23, 0x81 };
    ack.push_back(0);
    ack.push_back(uint8_t(4 + ourReq.size() + 6));
    ack.insert(ack.end(), ourReq.begin(), ourReq.end());
    ack.insert(ack.end(), { 5, 6, 0, 0, 0, 0 });
    s.input(Bytes(ack));
    // --> LCP open: the server sends its MS-CHAPv2 challenge.
    bool sawChallenge = false;
    for (const auto& f : out) {
        sawChallenge = sawChallenge || (f[2] == 0xc2 && f[3] == 0x23 && f[4] == 1);
    }

    CHECK(sawChallenge);
    out.clear();

    std::vector<uint8_t> ccp = { 0xff, 0x03, 0x80, 0xfd, 1, 1, 0, 10, 18, 6, 0, 0, 0, 1 };
    s.input(Bytes(ccp));
    REQUIRE(out.size() == 1);
    CHECK(out[0][2] == 0xc0);
    CHECK(out[0][4] == 8);   // --> Protocol-Reject.
    CHECK(out[0][8] == 0x80);
    CHECK(out[0][9] == 0xfd);
    out.clear();

    std::vector<uint8_t> v6 = { 0x80, 0x57, 1, 1, 0, 14, 1, 10, 1, 2, 3, 4, 5, 6, 7, 8 };
    s.input(Bytes(v6));
    REQUIRE(out.size() == 1);
    CHECK(out[0][4] == 8);

    // --> Echo request gets a reply with our magic.
    out.clear();
    std::vector<uint8_t> echo = { 0xff, 0x03, 0xc0, 0x21, 9, 42, 0, 8, 0x12, 0x34, 0x56, 0x78 };
    s.input(Bytes(echo));
    REQUIRE(out.size() == 1);
    CHECK(out[0][4] == 10);
    CHECK(out[0][5] == 42);
}
