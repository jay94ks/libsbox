#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/device.hpp>
#include <sbox/vpn/wg/uapi.hpp>
#include "testutil.hpp"

#include <cstdlib>

using namespace sbox;
using namespace sbox::vpn;
using namespace wgtest;

namespace {

    /* Two namespaces joined by a veth "underlay", each with a user-space WireGuard device. */
    struct STunnel {
        STempDir dir;
        std::string nsA;
        std::string nsB;
        CWgDevice a;
        CWgDevice b;
        SWgKey privA, privB, pubA, pubB;

        /* Builds everything; returns SBOX_OK or the failing step's error. */
        TTask<int32_t> build(bool uapi = false) {
            nsA = dir.netns("a");
            nsB = dir.netns("b");
            if (nsA.empty() || nsB.empty()) {
                co_return -EPERM;
            }

            int32_t r = co_await link(nsA, "ua", "10.0.0.1/24", nsB, "ub", "10.0.0.2/24");
            if (r != SBOX_OK) {
                co_return r;
            }

            GenerateWgPrivateKey(privA);
            GenerateWgPrivateKey(privB);
            DeriveWgPublicKey(privA, pubA);
            DeriveWgPublicKey(privB, pubB);

            SWgDeviceOptions oa;
            oa.name = "wg0";
            oa.netnsPath = nsA;
            oa.mode = EWGM_USERSPACE;
            oa.addresses = { prefix("10.9.0.1/24") };
            oa.uapi = uapi;
            oa.uapiDir = dir.join("uapi");
            SWgDeviceOptions ob = oa;
            ob.netnsPath = nsB;
            ob.addresses = { prefix("10.9.0.2/24") };
            ob.uapiDir = dir.join("uapi-b");     // --> Same interface name, so a separate directory.

            if ((r = co_await a.create(oa)) != SBOX_OK || (r = co_await b.create(ob)) != SBOX_OK) {
                co_return r;
            }

            SWgDeviceConfig ca;
            ca.privateKey = privA;
            ca.listenPort = 51820;
            SWgDeviceConfig cb;
            cb.privateKey = privB;
            if ((r = co_await a.configure(ca)) != SBOX_OK || (r = co_await b.configure(cb)) != SBOX_OK) {
                co_return r;
            }

            SWgPeerConfig pb;
            pb.publicKey = pubB;
            SEndpoint::fromIp("10.0.0.2", b.listenPort(), pb.endpoint);
            pb.allowedIps = { prefix("10.9.0.2/32") };
            SWgPeerConfig pa;
            pa.publicKey = pubA;
            SEndpoint::fromIp("10.0.0.1", a.listenPort(), pa.endpoint);
            pa.allowedIps = { prefix("10.9.0.1/32") };

            if ((r = co_await a.setPeer(pb)) != SBOX_OK || (r = co_await b.setPeer(pa)) != SBOX_OK) {
                co_return r;
            }

            co_return SBOX_OK;
        }

        /* Runs a TCP echo of `size` bytes from a child in A to a listener in B over the tunnel. */
        TTask<int32_t> echo(size_t size, int64_t& echoed) {
            CListener listener;
            int32_t r = listenIn(nsB, "10.9.0.2", listener);
            if (r != SBOX_OK) {
                co_return r;
            }

            uint16_t port = listener.localEndpoint().port();
            std::string payload(size, 'w');
            for (size_t i = 0; i < size; ++i) {
                payload[i] = char('a' + (i * 7) % 26);
            }

            co_return co_await withChild(nsA, [port, payload]() { return blockingEcho("10.9.0.2", port, payload); },
                echoOnce(listener), echoed);
        }
    };

}

TEST_CASE("device: user-space WireGuard between two namespaces carries TCP") {
    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STunnel t;
        int32_t r = co_await t.build();
        REQUIRE(r == SBOX_OK);
        CHECK_FALSE(t.a.isKernel());
        CHECK(t.a.listenPort() == 51820);
        CHECK(t.b.listenPort() != 0);

        int64_t echoed = 0;
        r = co_await t.echo(512 * 1024, echoed);
        CHECK(r == 0);
        CHECK(echoed == 512 * 1024);

        SWgDeviceStatus st;
        REQUIRE(co_await t.a.status(st) == SBOX_OK);
        CHECK(st.name == "wg0");
        CHECK(st.publicKey == t.pubA);
        REQUIRE(st.peers.size() == 1);
        CHECK(st.peers[0].lastHandshakeSec > 0);
        CHECK(st.peers[0].txBytes > 512 * 1024);
        CHECK(st.peers[0].rxBytes > 512 * 1024);

        // --> B learned A's endpoint, and a second connection reuses the session.
        REQUIRE(co_await t.b.status(st) == SBOX_OK);
        CHECK(st.peers[0].endpoint.toString() == "10.0.0.1:51820");
        uint64_t sessions = t.a.engine()->stats().sessionsDerived;
        r = co_await t.echo(1000, echoed);
        CHECK(r == 0);
        CHECK(t.a.engine()->stats().sessionsDerived == sessions);

        // --> Changing A's listen port: B follows A by roaming.
        SWgDeviceConfig move;
        move.listenPort = 51999;
        REQUIRE(co_await t.a.configure(move) == SBOX_OK);
        CHECK(t.a.listenPort() == 51999);
        r = co_await t.echo(4000, echoed);
        CHECK(r == 0);
        REQUIRE(co_await t.b.status(st) == SBOX_OK);
        CHECK(st.peers[0].endpoint.toString() == "10.0.0.1:51999");

        CHECK(co_await t.a.close() == SBOX_OK);
        CHECK(co_await t.b.close() == SBOX_OK);
        CHECK_FALSE(t.a.isOpen());

        // --> The TUN interface disappeared with the device.
        net::CRtnl rt;
        REQUIRE(rt.open(t.nsA) == SBOX_OK);
        CHECK(co_await rt.linkIndex("wg0") == -ENODEV);
    }());
}

TEST_CASE("device: wg-quick configuration applied with routes, then the UAPI") {
    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STunnel t;
        REQUIRE(co_await t.build(true) == SBOX_OK);

        // --> The UAPI socket answers like wireguard-go does.
        std::string sock = WgUapiSocketPath("wg0", t.dir.join("uapi"));
        SWgDeviceStatus st;
        REQUIRE(co_await WgUapiGet(sock, st) == SBOX_OK);
        CHECK(st.privateKey == t.privA);
        CHECK(st.listenPort == 51820);
        REQUIRE(st.peers.size() == 1);
        CHECK(st.peers[0].publicKey == t.pubB);
        CHECK(st.peers[0].allowedIps[0].toString() == "10.9.0.2/32");

        // --> Add an allowed IP through the UAPI (appending, like `wg set`).
        SWgDeviceConfig add;
        SWgPeerConfig p;
        p.publicKey = t.pubB;
        p.replaceAllowedIps = false;
        p.allowedIps = { prefix("10.50.0.0/16") };
        p.persistentKeepalive = 15;
        add.peers.push_back(p);
        REQUIRE(co_await WgUapiSet(sock, add) == SBOX_OK);
        REQUIRE(co_await t.a.status(st) == SBOX_OK);
        CHECK(st.peers[0].allowedIps.size() == 2);
        CHECK(st.peers[0].persistentKeepalive == 15);

        // --> A malformed set is refused with an errno.
        SWgDeviceConfig bad;
        SWgPeerConfig nokey;
        bad.peers.push_back(nokey);
        CHECK(co_await WgUapiSet(sock, bad) != SBOX_OK);

        // --> setConfig from wg-quick text replaces the peers; routeAllowedIps adds routes.
        CHECK(co_await t.a.close() == SBOX_OK);
        CHECK_FALSE(CFile::exists(sock));
        CWgDevice c;
        SWgDeviceOptions oc;
        oc.name = "wgc";
        oc.netnsPath = t.nsA;
        oc.mode = EWGM_USERSPACE;
        oc.addresses = { prefix("10.9.0.1/32") };
        oc.routeAllowedIps = true;
        REQUIRE(co_await c.create(oc) == SBOX_OK);

        std::string text = "[Interface]\nPrivateKey = " + t.privA.toBase64() + "\nListenPort = 51820\n\n[Peer]\nPublicKey = "
            + t.pubB.toBase64() + "\nAllowedIPs = 10.9.0.2/32, 10.60.0.0/16, 0.0.0.0/0\nEndpoint = 10.0.0.2:"
            + std::to_string(t.b.listenPort()) + "\n";
        SWgConfig cfg;
        REQUIRE(ParseWgConfig(text, cfg) == SBOX_OK);
        REQUIRE(co_await c.setConfig(cfg) == SBOX_OK);

        net::CRtnl rt;
        REQUIRE(rt.open(t.nsA) == SBOX_OK);
        std::vector<net::SRouteInfo> routes;
        REQUIRE(co_await rt.listRoutes(routes, AF_INET) == SBOX_OK);
        bool found60 = false, foundDefault = false;
        for (const net::SRouteInfo& route : routes) {
            if (route.oif == c.ifIndex() && route.destination.toString() == "10.60.0.0/16") {
                found60 = true;
            }

            if (route.oif == c.ifIndex() && route.destination.length == 0) {
                foundDefault = true;
            }
        }

        CHECK(found60);
        CHECK_FALSE(foundDefault);

        int64_t echoed = 0;
        int32_t r = co_await t.echo(20000, echoed);
        CHECK(r == 0);

        // --> Removing the peer removes its routes.
        REQUIRE(co_await c.removePeer(t.pubB) == SBOX_OK);
        routes.clear();
        REQUIRE(co_await rt.listRoutes(routes, AF_INET) == SBOX_OK);
        for (const net::SRouteInfo& route : routes) {
            CHECK_FALSE(route.destination.toString() == "10.60.0.0/16");
        }

        CHECK(co_await c.close() == SBOX_OK);
        CHECK(co_await t.b.close() == SBOX_OK);
    }());
}

TEST_CASE("device: kernel module path") {
    if (::geteuid() != 0) {
        MESSAGE("skipped: needs root");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STempDir dir;
        std::string ns = dir.netns("k");
        REQUIRE_FALSE(ns.empty());

        bool kernel = co_await CWgDevice::kernelAvailable(ns);
        if (!kernel) {
            MESSAGE("skipped: no wireguard kernel module (the user-space path is used instead)");

            // --> EWGM_KERNEL refuses, EWGM_AUTO falls back to user space.
            CWgDevice d;
            SWgDeviceOptions o;
            o.name = "wgk";
            o.netnsPath = ns;
            o.mode = EWGM_KERNEL;
            CHECK(co_await d.create(o) == -ENOTSUP);
            o.mode = EWGM_AUTO;
            if (CFile::exists("/dev/net/tun")) {
                REQUIRE(co_await d.create(o) == SBOX_OK);
                CHECK_FALSE(d.isKernel());
                CHECK(co_await d.close() == SBOX_OK);
            }

            co_return;
        }

        CWgDevice d;
        SWgDeviceOptions o;
        o.name = "wgk";
        o.netnsPath = ns;
        o.mode = EWGM_KERNEL;
        REQUIRE(co_await d.create(o) == SBOX_OK);
        CHECK(d.isKernel());

        SWgKey priv, pub, peer;
        GenerateWgPrivateKey(priv);
        DeriveWgPublicKey(priv, pub);
        GenerateWgPrivateKey(peer);
        DeriveWgPublicKey(peer, peer);

        SWgDeviceConfig c;
        c.privateKey = priv;
        c.listenPort = 51820;
        SWgPeerConfig p;
        p.publicKey = peer;
        p.allowedIps = { prefix("10.70.0.0/16"), prefix("fd70::/64") };
        p.persistentKeepalive = 25;
        SEndpoint::fromIp("192.0.2.1", 51820, p.endpoint);
        c.peers.push_back(p);
        REQUIRE(co_await d.configure(c) == SBOX_OK);

        SWgDeviceStatus st;
        REQUIRE(co_await d.status(st) == SBOX_OK);
        CHECK(st.publicKey == pub);
        CHECK(st.listenPort == 51820);
        REQUIRE(st.peers.size() == 1);
        CHECK(st.peers[0].allowedIps.size() == 2);
        CHECK(st.peers[0].persistentKeepalive == 25);
        CHECK(co_await d.close() == SBOX_OK);
    }());
}

TEST_CASE("device: interoperability with the reference tools") {
    const char* paths[] = { "/usr/bin/wg", "/usr/local/bin/wg", "/usr/bin/wireguard-go", "/usr/local/bin/wireguard-go" };
    bool any = false;
    for (const char* p : paths) {
        any = any || ::access(p, X_OK) == 0;
    }

    if (!any) {
        MESSAGE("skipped: neither wg nor wireguard-go is installed");
        return;
    }

    // --> `wg show <if> dump` reads user-space devices through /var/run/wireguard/<if>.sock.
    if (::geteuid() != 0 || !canUseNetns() || ::access("/usr/bin/wg", X_OK) != 0) {
        MESSAGE("skipped: wg interop needs root and /usr/bin/wg");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STempDir dir;
        std::string ns = dir.netns("i");
        CWgDevice d;
        SWgDeviceOptions o;
        o.name = "wgi" + net::RandomHex(4);
        o.netnsPath = ns;
        o.mode = EWGM_USERSPACE;
        o.uapi = true;
        REQUIRE(co_await d.create(o) == SBOX_OK);

        SWgKey priv;
        GenerateWgPrivateKey(priv);
        SWgDeviceConfig c;
        c.privateKey = priv;
        c.listenPort = 51820;
        REQUIRE(co_await d.configure(c) == SBOX_OK);

        int32_t rc = co_await net::CNetns::run(ns, [&o]() {
            std::string cmd = "/usr/bin/wg show " + o.name + " listen-port > /dev/null 2>&1";
            return int32_t(std::system(cmd.c_str()));
        });
        CHECK(rc == 0);
        CHECK(co_await d.close() == SBOX_OK);
    }());
}
