#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/core/socket.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/l2tp/client.hpp>
#include <sbox/vpn/l2tp/server.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include "testutil.hpp"

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

// --> End to end: a client namespace runs IKEv1 + user-space ESP transport mode + L2TP + PPP
// against the server in another namespace, gets an address and exchanges UDP datagrams through
// the TUN devices on both sides (and through the server into a LAN namespace).

namespace {

    net::SIpPrefix prefix(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    net::SIpAddress ip(const char* text) {
        net::SIpAddress a;
        net::SIpAddress::parse(text, a);
        return a;
    }

    /**
     * srv (10.99.0.1, LAN 10.88.0.1/24 towards "lan" 10.88.0.2) and cli (10.99.0.2).
     */
    struct Topology {
        TempDir dir;
        std::string server;
        std::string client;
        std::string lan;

        TTask<int32_t> build() {
            server = dir.netns("srv");
            client = dir.netns("cli");
            lan = dir.netns("lan");
            if (server.empty() || client.empty() || lan.empty()) {
                co_return -EPERM;
            }

            CFd clientFd;
            CFd lanFd;
            if (net::CNetns::open(client, clientFd) != SBOX_OK || net::CNetns::open(lan, lanFd) != SBOX_OK) {
                co_return -EIO;
            }

            net::CRtnl srv;
            net::CRtnl cli;
            net::CRtnl ln;
            if (srv.open(server) != SBOX_OK || cli.open(client) != SBOX_OK || ln.open(lan) != SBOX_OK) {
                co_return -EIO;
            }

            int32_t r = co_await srv.createVeth("wan0", "wan1", clientFd.get());
            if (r != SBOX_OK) {
                co_return r;
            }

            r = co_await srv.createVeth("lan0", "lan1", lanFd.get());
            if (r != SBOX_OK) {
                co_return r;
            }

            struct Addr { net::CRtnl* rtnl; const char* name; const char* addr; };
            Addr addrs[] = {
                { &srv, "wan0", "10.99.0.1/24" }, { &cli, "wan1", "10.99.0.2/24" }, { &srv, "lan0", "10.88.0.1/24" },
                { &ln, "lan1", "10.88.0.2/24" }, { &srv, "lo", nullptr }, { &cli, "lo", nullptr }, { &ln, "lo", nullptr },
            };

            for (const Addr& a : addrs) {
                int32_t index = co_await a.rtnl->linkIndex(a.name);
                if (index <= 0) {
                    co_return -ENODEV;
                }

                if (a.addr) {
                    r = co_await a.rtnl->addAddress(index, prefix(a.addr));
                    if (r != SBOX_OK) {
                        co_return r;
                    }
                }

                r = co_await a.rtnl->setUp(index);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            // --> The LAN host routes VPN clients back through the server.
            r = co_await ln.addDefaultRoute(ip("10.88.0.1"));
            co_return r;
        }
    };

    SL2tpServerConfig serverConfig(const std::string& netns) {
        SL2tpServerConfig c;
        c.listenAddress = "10.99.0.1";
        c.ikePort = 0;
        c.natPort = 0;
        c.netnsPath = netns;
        c.dataPath = EL2TK_USER;
        SIkePsk psk;
        psk.secret = "shared secret";
        c.ike.psks.push_back(psk);
        c.ike.retransmitMs = 300;
        SPppUser u;
        u.name = "alice";
        u.password = "Wonderland!";
        c.users.push_back(u);
        c.pool = prefix("10.60.0.0/24");
        c.dns = { ip("10.60.0.1") };
        c.echoSeconds = 0;
        return c;
    }

    SL2tpClientConfig clientConfig(const std::string& netns, const CL2tpServer& server) {
        SL2tpClientConfig c;
        c.server = "10.99.0.1";
        c.ikePort = server.ikePort();
        c.natPort = server.natPort();
        c.netnsPath = netns;
        SIkePsk psk;
        psk.secret = "shared secret";
        c.ike.psks.push_back(psk);
        c.ike.retransmitMs = 300;
        c.user = "alice";
        c.password = "Wonderland!";
        c.routes = { prefix("10.88.0.0/24") };
        c.timeoutMs = 15000;
        return c;
    }

    /** UDP socket opened inside a namespace. */
    int32_t udpIn(const std::string& netns, const char* address, uint16_t port, CDatagramSocket& out) {
        net::CNetnsScope scope(netns);
        if (scope.error() != SBOX_OK) {
            return scope.error();
        }

        SEndpoint local;
        SEndpoint::fromIp(address, port, local);
        return out.open(AF_INET, local);
    }

    /** Sends "ping" from the client namespace to `target` and expects the echo. */
    TTask<bool> echoThrough(const std::string& clientNs, const std::string& serverNs, const char* target) {
        CDatagramSocket echo;
        if (udpIn(serverNs, target, 0, echo) != SBOX_OK) {
            co_return false;
        }

        uint16_t port = echo.localEndpoint().port();
        CDatagramSocket sender;
        if (udpIn(clientNs, "0.0.0.0", 0, sender) != SBOX_OK) {
            co_return false;
        }

        SEndpoint dst;
        SEndpoint::fromIp(target, port, dst);
        for (int attempt = 0; attempt < 5; ++attempt) {
            std::string msg = "ping " + std::to_string(attempt);
            sender.sendTo(BytesOf(msg), dst);
            std::vector<uint8_t> buf(2048);
            SEndpoint from;
            SIoResult got = co_await echo.recvFrom(SByteSpan(buf.data(), buf.size()), from, 500);
            if (got.error != SBOX_OK) {
                continue;
            }

            // --> The datagram arrived from the client's tunnel address; answer it.
            echo.sendTo(SReadOnlyByteSpan(buf.data(), got.bytes), from);
            SEndpoint back;
            SIoResult reply = co_await sender.recvFrom(SByteSpan(buf.data(), buf.size()), back, 1000);
            if (reply.error == SBOX_OK && std::string(reinterpret_cast<char*>(buf.data()), reply.bytes) == msg) {
                co_return from.toString().rfind("10.60.0.", 0) == 0;
            }
        }

        co_return false;
    }

    bool rootOrSkip() {
        if (!IsRoot()) {
            MESSAGE("skipped: needs root (network namespaces, TUN)");
            return false;
        }

        return true;
    }

}

TEST_CASE("L2TP/IPsec end to end: raw ESP transport mode, TUN on both sides, UDP through the tunnel") {
    if (!rootOrSkip()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        Topology topo;
        int32_t r = co_await topo.build();
        if (r != SBOX_OK) {
            MESSAGE("skipped: cannot build the topology (" << r << ")");
            co_return;
        }

        Log log;
        CL2tpServer server(serverConfig(topo.server));
        server.logger([&](EIkeLogLevel l, const std::string& m) { log.add(l, "S " + m); });
        r = co_await server.start();
        REQUIRE_MESSAGE(r == SBOX_OK, "server start " << r);
        CHECK(server.dataPath() == "user");

        CL2tpClient client(clientConfig(topo.client, server));
        client.logger([&](EIkeLogLevel l, const std::string& m) { log.add(l, "C " + m); });
        r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "connect " << r << ": " << client.lastError());
        CHECK_FALSE(client.natT());
        CHECK(client.info().localAddress.toString() == "10.60.0.2");
        CHECK(client.info().peerAddress.toString() == "10.60.0.1");
        REQUIRE(client.info().dns.size() == 1);

        auto sessions = server.sessions();
        REQUIRE(sessions.size() == 1);
        CHECK(sessions[0].user == "alice");
        CHECK(sessions[0].address == "10.60.0.2");
        CHECK(sessions[0].identity.rfind("10.99.0.2", 0) == 0);
        CHECK(server.ikeSessions().size() == 1);

        // --> To the server's own tunnel address, then through it into the LAN namespace.
        CHECK(co_await echoThrough(topo.client, topo.server, "10.60.0.1"));
        CHECK(co_await echoThrough(topo.client, topo.lan, "10.88.0.2"));
        CHECK(server.sessions()[0].inPackets >= 2);

        co_await client.disconnect();
        bool gone = co_await WaitFor([&] { return server.sessions().empty(); }, 5000);
        CHECK(gone);
        CHECK(log.contains("down"));
        co_await server.stop();
    }());
}

TEST_CASE("L2TP/IPsec end to end over NAT-T (UDP-encapsulated ESP transport, forced)") {
    if (!rootOrSkip()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        Topology topo;
        if (co_await topo.build() != SBOX_OK) {
            MESSAGE("skipped: cannot build the topology");
            co_return;
        }

        SL2tpServerConfig sc = serverConfig(topo.server);
        sc.ike.forceEncap = true;
        CL2tpServer server(sc);
        REQUIRE(co_await server.start() == SBOX_OK);

        SL2tpClientConfig cc = clientConfig(topo.client, server);
        SIkev1Suite s;
        s.encr = EIKE1_ENCR_3DES;
        s.keyBits = 192;
        s.hash = EIKE1_HASH_SHA1;
        s.group = 2;
        cc.ike.suites = { s };
        cc.ike.esp = { SIkev1EspSuite{ EIKE1_ESP_3DES, 0, EIKE1_AA_HMAC_SHA1 } };
        CL2tpClient client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, client.lastError());
        CHECK(client.natT());
        CHECK(co_await echoThrough(topo.client, topo.server, "10.60.0.1"));

        // --> The administrator disconnects the user.
        CHECK(server.disconnect("alice") == 1);
        bool down = co_await WaitFor([&] { return !client.isUp(); }, 5000);
        CHECK(down);
        co_await client.disconnect();
        co_await server.stop();
    }());
}

TEST_CASE("Failures: wrong PSK, wrong password") {
    if (!rootOrSkip()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        Topology topo;
        if (co_await topo.build() != SBOX_OK) {
            MESSAGE("skipped: cannot build the topology");
            co_return;
        }

        CL2tpServer server(serverConfig(topo.server));
        REQUIRE(co_await server.start() == SBOX_OK);

        SL2tpClientConfig wrongPsk = clientConfig(topo.client, server);
        wrongPsk.ike.psks[0].secret = "nope";
        wrongPsk.timeoutMs = 3000;
        wrongPsk.interfaceName = "l2tpc1";
        CL2tpClient a(wrongPsk);
        CHECK(co_await a.connect() != SBOX_OK);

        SL2tpClientConfig wrongPw = clientConfig(topo.client, server);
        wrongPw.password = "nope";
        wrongPw.interfaceName = "l2tpc2";
        CL2tpClient b(wrongPw);
        int32_t r = co_await b.connect();
        CHECK(r == -EACCES);
        CHECK(server.sessions().empty());
        co_await server.stop();
    }());
}

TEST_CASE("Sharing UDP 500/4500 with the IKEv2 responder") {
    if (!rootOrSkip()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        Topology topo;
        if (co_await topo.build() != SBOX_OK) {
            MESSAGE("skipped: cannot build the topology");
            co_return;
        }

        SIkeServerConfig v2;
        v2.listenAddress = "10.99.0.1";
        v2.port = 0;
        v2.natPort = 0;
        v2.netnsPath = topo.server;
        v2.forwarding = false;
        SIkePsk psk;
        psk.secret = "v2";
        v2.psks.push_back(psk);
        net::SIpPrefix::parse("10.61.0.0/24", v2.pool);
        v2.dataPath.kind = EIDP_USER;
        v2.dataPath.netnsPath = topo.server;
        v2.dataPath.interfaceName = "ipsec0";
        CIkeServer ikev2(v2);
        int32_t r = co_await ikev2.start();
        REQUIRE_MESSAGE(r == SBOX_OK, "IKEv2 start " << r);

        SL2tpServerConfig sc = serverConfig(topo.server);
        sc.dataPath = EL2TK_AUTO;
        sc.ike.forceEncap = true;
        CL2tpServer server(sc);
        REQUIRE(co_await server.start(&ikev2) == SBOX_OK);
        CHECK(server.dataPath() == "user");

        SL2tpClientConfig cc = clientConfig(topo.client, server);
        cc.ikePort = ikev2.port();
        cc.natPort = ikev2.natPort();
        CL2tpClient client(cc);
        r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, client.lastError());
        CHECK(client.natT());
        CHECK(co_await echoThrough(topo.client, topo.server, "10.60.0.1"));
        co_await client.disconnect();
        co_await server.stop();
        co_await ikev2.stop();
    }());
}

TEST_CASE("Plain L2TP without IPsec (dataPath none)") {
    if (!rootOrSkip()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        Topology topo;
        if (co_await topo.build() != SBOX_OK) {
            MESSAGE("skipped: cannot build the topology");
            co_return;
        }

        SL2tpServerConfig sc = serverConfig(topo.server);
        sc.dataPath = EL2TK_PLAIN;
        sc.l2tpPort = 0;
        sc.auth = { EPPPA_CHAP_MD5 };
        CL2tpServer server(sc);
        REQUIRE(co_await server.start() == SBOX_OK);
        CHECK(server.l2tpPort() != 0);

        SL2tpClientConfig cc = clientConfig(topo.client, server);
        cc.ipsec = false;
        cc.l2tpPort = server.l2tpPort();
        CL2tpClient client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, client.lastError());
        CHECK(server.sessions()[0].auth == "CHAP-MD5");
        CHECK(co_await echoThrough(topo.client, topo.server, "10.60.0.1"));

        // --> Stopping the server tears the client's link down.
        co_await server.stop();
        bool down = co_await WaitFor([&] { return !client.isUp(); }, 5000);
        CHECK(down);
        co_await client.disconnect();
    }());
}
