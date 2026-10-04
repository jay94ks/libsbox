#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/initiator.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/ipsec/xfrm.hpp>
#include <sbox/core/fd.hpp>
#include "testutil.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    net::SIpPrefix prefix(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    /**
     * Two namespaces joined by a veth pair: "server" (10.99.0.1, plus a LAN 10.88.0.1/24 on a
     * second veth) and "client" (10.99.0.2).
     */
    struct Topology {
        TempDir dir;
        std::string server;
        std::string client;

        TTask<int32_t> build() {
            server = dir.netns("srv");
            client = dir.netns("cli");
            if (server.empty() || client.empty()) {
                co_return -EPERM;
            }

            CFd clientFd;
            int32_t r = net::CNetns::open(client, clientFd);
            if (r != SBOX_OK) {
                co_return r;
            }

            net::CRtnl srv;
            net::CRtnl cli;
            if (srv.open(server) != SBOX_OK || cli.open(client) != SBOX_OK) {
                co_return -EIO;
            }

            r = co_await srv.createVeth("wan0", "wan1", clientFd.get());
            if (r != SBOX_OK) {
                co_return r;
            }

            r = co_await srv.createVeth("lan0", "lan1");
            if (r != SBOX_OK) {
                co_return r;
            }

            struct Addr { net::CRtnl* rtnl; const char* name; const char* addr; };
            Addr addrs[] = {
                { &srv, "wan0", "10.99.0.1/24" },
                { &cli, "wan1", "10.99.0.2/24" },
                { &srv, "lan0", "10.88.0.1/24" },
                { &srv, "lan1", nullptr },
                { &srv, "lo", nullptr },
                { &cli, "lo", nullptr },
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

            co_return SBOX_OK;
        }
    };

    /** Opens a UDP socket in a namespace, bound to address:port. */
    CFd udpSocket(const std::string& netns, const std::string& address, uint16_t port) {
        CFd fd;
        {
            net::CNetnsScope scope(netns);
            if (scope.error() != SBOX_OK) {
                return fd;
            }

            fd.reset(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        }

        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, address.c_str(), &sa.sin_addr);
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            fd.reset();
        }

        return fd;
    }

    /** Receives one datagram within a timeout. */
    TTask<int32_t> receive(const CFd& fd, std::string& text, sockaddr_in& from, int64_t timeoutMs) {
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        while (true) {
            char buf[2048];
            socklen_t len = sizeof(from);
            ssize_t n = ::recvfrom(fd.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &len);
            if (n >= 0) {
                text.assign(buf, size_t(n));
                co_return SBOX_OK;
            }

            int64_t left = deadline - CEventLoop::nowMs();
            if (left <= 0) {
                co_return -ETIMEDOUT;
            }

            int32_t r = co_await CEventLoop::current()->waitFd(fd.get(), EFDE_READ, left);
            if (r < 0) {
                co_return r;
            }
        }
    }

    /**
     * Brings up a server and a client with user-space ESP and exchanges traffic through the
     * tunnel: client (virtual IP) -> 10.88.0.1 behind the server, and back.
     */
    TTask<void> tunnelTraffic(Topology& topo, bool forceEncap) {
        SIkeServerConfig cfg;
        cfg.listenAddress = "10.99.0.1";
        cfg.netnsPath = topo.server;
        cfg.pool = prefix("10.77.0.0/24");
        cfg.routes.push_back(prefix("10.88.0.0/16"));
        cfg.dataPath.kind = EIDP_USER;
        cfg.dataPath.interfaceName = "ike0";
        cfg.forceEncap = forceEncap;
        SIkePsk psk;
        psk.secret = "tunnel test";
        cfg.psks.push_back(psk);

        CIkeServer server(cfg);
        int32_t r = co_await server.start();
        REQUIRE_MESSAGE(r == SBOX_OK, "server start " << r);
        REQUIRE(server.dataPath());
        CHECK(std::string(server.dataPath()->kind()) == "user");
        CHECK(server.dataPath()->interfaceName() == "ike0");

        SIpsecDataPathOptions dpo;
        dpo.kind = EIDP_USER;
        dpo.netnsPath = topo.client;
        dpo.interfaceName = "ikec0";
        dpo.routes.push_back(prefix("10.88.0.0/16"));
        IIpsecDataPathPtr clientPath;
        REQUIRE(co_await CreateIpsecDataPath(dpo, clientPath) == SBOX_OK);

        SIkeInitiatorConfig cc;
        cc.server = "10.99.0.1";
        cc.netnsPath = topo.client;
        cc.identity = "@client.test";
        cc.psk = psk.secret;
        cc.tsr.push_back(SIkeTrafficSelector::fromPrefix(prefix("10.88.0.0/16")));
        CIkeInitiator client(cc);
        REQUIRE(client.attach(clientPath) == SBOX_OK);
        REQUIRE(co_await clientPath->start() == SBOX_OK);

        r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "connect " << r << " notify " << client.lastNotify());
        CHECK(client.natT() == forceEncap);
        CHECK(client.child().encap == forceEncap);
        std::string vip = client.virtualIp().toString();
        CHECK(vip == "10.77.0.2");

        // --> Give the client's tunnel interface its virtual address.
        net::CRtnl rtnl;
        REQUIRE(rtnl.open(topo.client) == SBOX_OK);
        int32_t index = co_await rtnl.linkIndex("ikec0");
        REQUIRE(index > 0);
        REQUIRE(co_await rtnl.addAddress(index, net::SIpPrefix(client.virtualIp(), 32)) == SBOX_OK);

        CFd lan = udpSocket(topo.server, "10.88.0.1", 7001);
        CFd mobile = udpSocket(topo.client, vip, 7002);
        REQUIRE(lan.isValid());
        REQUIRE(mobile.isValid());

        sockaddr_in to;
        std::memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(7001);
        ::inet_pton(AF_INET, "10.88.0.1", &to.sin_addr);

        for (int32_t i = 0; i < 5; ++i) {
            std::string msg = "hello through ESP " + std::to_string(i);
            REQUIRE(::sendto(mobile.get(), msg.data(), msg.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == ssize_t(msg.size()));

            std::string got;
            sockaddr_in from;
            REQUIRE(co_await receive(lan, got, from, 3000) == SBOX_OK);
            CHECK(got == msg);
            char text[32];
            ::inet_ntop(AF_INET, &from.sin_addr, text, sizeof(text));
            CHECK(std::string(text) == vip);

            std::string reply = "reply " + std::to_string(i);
            REQUIRE(::sendto(lan.get(), reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&from), sizeof(from))
                    == ssize_t(reply.size()));
            REQUIRE(co_await receive(mobile, got, from, 3000) == SBOX_OK);
            CHECK(got == reply);
        }

        SIpsecChildStats stats;
        REQUIRE(co_await clientPath->stats(client.child(), stats) == SBOX_OK);
        CHECK(stats.outPackets == 5);
        CHECK(stats.inPackets == 5);

        // --> Rekey keeps the tunnel working with fresh SAs.
        REQUIRE(co_await client.rekeyChild() == SBOX_OK);
        std::string msg = "after rekey";
        REQUIRE(::sendto(mobile.get(), msg.data(), msg.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == ssize_t(msg.size()));
        std::string got;
        sockaddr_in from;
        REQUIRE(co_await receive(lan, got, from, 3000) == SBOX_OK);
        CHECK(got == msg);
        REQUIRE(co_await clientPath->stats(client.child(), stats) == SBOX_OK);
        CHECK(stats.outPackets == 1);

        CHECK(co_await client.close() == SBOX_OK);
        co_await clientPath->stop();
        co_await server.stop();
    }

}

TEST_CASE("User-space ESP data path carries traffic between namespaces (raw ESP and UDP 4500)") {
    if (!isRoot()) {
        MESSAGE("not root; skipping the namespace data path test");
        return;
    }

    if (::access("/dev/net/tun", R_OK | W_OK) != 0) {
        MESSAGE("/dev/net/tun unavailable; skipping");
        return;
    }

    for (bool encap : { false, true }) {
        Topology topo;
        CEventLoop loop;
        int32_t r = loop.run(topo.build());
        if (r == -EOPNOTSUPP || r == -ENOTSUP) {
            MESSAGE("veth unavailable; skipping");
            return;
        }

        REQUIRE_MESSAGE(r == SBOX_OK, "topology " << r);
        loop.run(tunnelTraffic(topo, encap));
    }
}

TEST_CASE("Kernel XFRM data path between namespaces (needs kernel ESP)") {
    if (!isRoot()) {
        MESSAGE("not root; skipping");
        return;
    }

    Topology topo;
    CEventLoop loop;
    REQUIRE(loop.run(topo.build()) == SBOX_OK);

    bool esp = loop.run([](std::string ns) -> TTask<bool> {
        CXfrm x;
        SXfrmSupport s;
        if (x.open(ns) != SBOX_OK || co_await x.probe(s) != SBOX_OK) {
            co_return false;
        }

        co_return s.esp;
    }(topo.server));

    if (!esp) {
        MESSAGE("kernel ESP (esp4) unavailable; the kernel data path cannot be exercised here");
        return;
    }

    // --> Same scenario with both sides on XFRM.
    loop.run([](Topology& t) -> TTask<void> {
        SIkeServerConfig cfg;
        cfg.listenAddress = "10.99.0.1";
        cfg.netnsPath = t.server;
        cfg.pool = prefix("10.77.0.0/24");
        cfg.routes.push_back(prefix("10.88.0.0/16"));
        cfg.dataPath.kind = EIDP_KERNEL;
        SIkePsk psk;
        psk.secret = "kernel";
        cfg.psks.push_back(psk);
        CIkeServer server(cfg);
        REQUIRE(co_await server.start() == SBOX_OK);
        CHECK(std::string(server.dataPath()->kind()) == "kernel");

        SIpsecDataPathOptions dpo;
        dpo.kind = EIDP_KERNEL;
        dpo.netnsPath = t.client;
        dpo.interfaceName = "ikec0";
        dpo.reqidBase = 0x5c000000u;
        IIpsecDataPathPtr clientPath;
        REQUIRE(co_await CreateIpsecDataPath(dpo, clientPath) == SBOX_OK);

        SIkeInitiatorConfig cc;
        cc.server = "10.99.0.1";
        cc.netnsPath = t.client;
        cc.identity = "@client.test";
        cc.psk = psk.secret;
        cc.tsr.push_back(SIkeTrafficSelector::fromPrefix(prefix("10.88.0.0/16")));
        CIkeInitiator client(cc);
        REQUIRE(client.attach(clientPath) == SBOX_OK);
        REQUIRE(co_await clientPath->start() == SBOX_OK);
        REQUIRE(co_await client.connect() == SBOX_OK);

        SIpsecChildStats stats;
        CHECK(co_await clientPath->stats(client.child(), stats) == SBOX_OK);
        co_await client.close();
        co_await clientPath->stop();
        co_await server.stop();
    }(topo));
}
