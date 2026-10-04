#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/overlay.hpp>
#include "testutil.hpp"

using namespace sbox;
using namespace sbox::vpn;
using namespace wgtest;

namespace {

    /* One simulated host: its "host" namespace, a network manager and the overlay driver. */
    struct SHost {
        std::string ns;
        std::string stateDir;
        std::shared_ptr<CWgOverlayDriver> driver;
        std::unique_ptr<net::CNetworkManager> manager;
        SWgKey priv;
        SWgKey pub;

        void init(STempDir& dir, const std::string& name) {
            ns = dir.netns(name);
            stateDir = dir.join(name + "-state");
            net::SNetworkManagerOptions o;
            o.stateDir = stateDir;
            o.hostNetns = ns;
            o.firewall = false;
            manager.reset(new net::CNetworkManager(o));

            SWgOverlayDriverOptions d;
            d.uapiDir = dir.join(name + "-uapi");
            driver = std::make_shared<CWgOverlayDriver>(d);
            manager->registerDriver(driver);

            GenerateWgPrivateKey(priv);
            DeriveWgPublicKey(priv, pub);
        }
    };

    /* The other host as seen from one side. */
    SWgOverlayHost hostEntry(const SHost& h, const char* endpoint, const char* subnet) {
        SWgOverlayHost e;
        e.name = h.ns;
        e.publicKey = h.pub;
        e.endpoint = endpoint;
        e.subnet = prefix(subnet);
        return e;
    }

    /* TCP echo from a child in `clientNs` to a listener in `serverNs` on `addr`. */
    TTask<int32_t> echoAcross(const std::string& clientNs, const std::string& serverNs, const char* addr, size_t size, int64_t timeoutMs = 20000) {
        CListener listener;
        int32_t r = listenIn(serverNs, addr, listener);
        if (r != SBOX_OK) {
            co_return r;
        }

        uint16_t port = listener.localEndpoint().port();
        std::string payload(size, 'o');
        std::string target = addr;
        int32_t seconds = int32_t(timeoutMs / 1000);
        int64_t echoed = 0;
        r = co_await withChild(clientNs, [port, payload, target, seconds]() {
            return blockingEcho(target.c_str(), port, payload, seconds);
        }, echoOnce(listener, timeoutMs), echoed);

        if (r == 0 && echoed != int64_t(size)) {
            co_return -EIO;
        }

        co_return r;
    }

}

TEST_CASE("overlay: configuration JSON and the network request") {
    SWgOverlayConfig c;
    GenerateWgPrivateKey(c.privateKey);
    c.hostSubnet = prefix("10.210.1.0/24");
    c.listenPort = 51900;
    c.mode = EWGM_USERSPACE;
    c.nat = false;
    SWgOverlayHost h;
    GenerateWgPrivateKey(h.publicKey);
    h.endpoint = "192.0.2.2:51900";
    h.subnet = prefix("10.210.2.0/24");
    h.persistentKeepalive = 25;
    c.peers.push_back(h);

    SWgOverlayConfig back;
    REQUIRE(SWgOverlayConfig::fromJson(c.toJson(), back) == SBOX_OK);
    CHECK(back.privateKey == c.privateKey);
    CHECK(back.listenPort == 51900);
    CHECK(back.mode == EWGM_USERSPACE);
    CHECK_FALSE(back.nat);
    REQUIRE(back.peers.size() == 1);
    CHECK(back.peers[0].subnet.toString() == "10.210.2.0/24");
    CHECK(back.peers[0].persistentKeepalive == 25);
    CHECK(c.toJson(false).find("privateKey") == nullptr);

    net::SNetworkCreate req;
    REQUIRE(MakeWgOverlayNetwork("ov", prefix("10.210.0.0/16"), c, req) == SBOX_OK);
    CHECK(req.driver == "wg-overlay");
    REQUIRE(req.subnets.size() == 1);
    CHECK(req.subnets[0].subnet.toString() == "10.210.0.0/16");
    CHECK(req.subnets[0].ipRange.toString() == "10.210.1.0/24");
    CHECK(req.subnets[0].gateway.toString() == "10.210.1.1");
    CHECK(req.options["com.docker.network.driver.mtu"] == "1420");

    c.hostSubnet = prefix("10.211.1.0/24");
    CHECK(MakeWgOverlayNetwork("ov", prefix("10.210.0.0/16"), c, req) == -EINVAL);

    CJson bad;
    REQUIRE(CJson::parse("{\"hostSubnet\":\"10.0.0.0/24\",\"mode\":\"warp\"}", bad) == SBOX_OK);
    CHECK(SWgOverlayConfig::fromJson(bad, back) == -EINVAL);
}

TEST_CASE("overlay: containers on two hosts talk over WireGuard") {
    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STempDir dir;
        SHost h1, h2;
        h1.init(dir, "host1");
        h2.init(dir, "host2");
        REQUIRE_FALSE(h1.ns.empty());
        REQUIRE_FALSE(h2.ns.empty());

        // --> The underlay between the two hosts.
        REQUIRE(co_await link(h1.ns, "eth-u", "192.168.77.1/24", h2.ns, "eth-u", "192.168.77.2/24") == SBOX_OK);

        net::SIpPrefix overlay = prefix("10.210.0.0/16");

        // --> Host 1 starts alone; host 2 already knows host 1.
        SWgOverlayConfig c1;
        c1.privateKey = h1.priv;
        c1.hostSubnet = prefix("10.210.1.0/24");
        c1.mode = EWGM_USERSPACE;
        SWgOverlayConfig c2;
        c2.privateKey = h2.priv;
        c2.hostSubnet = prefix("10.210.2.0/24");
        c2.mode = EWGM_USERSPACE;
        c2.peers.push_back(hostEntry(h1, "192.168.77.1:51820", "10.210.1.0/24"));

        net::SNetworkCreate r1, r2;
        REQUIRE(MakeWgOverlayNetwork("ov", overlay, c1, r1) == SBOX_OK);
        REQUIRE(MakeWgOverlayNetwork("ov", overlay, c2, r2) == SBOX_OK);
        net::SNetwork n1, n2;
        int32_t r = co_await h1.manager->createNetwork(r1, n1);
        REQUIRE(r == SBOX_OK);
        r = co_await h2.manager->createNetwork(r2, n2);
        REQUIRE(r == SBOX_OK);

        // --> The private key is not kept in the network object.
        CHECK(n1.option(WG_OVERLAY_OPTION).find("privateKey") == std::string::npos);
        CHECK(n1.driverState.get("bridge").asString().rfind("wgb-", 0) == 0);

        // --> Host 1 learns host 2 at run time.
        r = co_await h1.driver->addHost(*h1.manager, "ov", hostEntry(h2, "192.168.77.2:51820", "10.210.2.0/24"));
        REQUIRE(r == SBOX_OK);
        SWgOverlayConfig stored;
        REQUIRE(co_await h1.driver->config(*h1.manager, "ov", stored) == SBOX_OK);
        CHECK(stored.peers.size() == 1);

        // --> An overlapping subnet is refused.
        CHECK(co_await h1.driver->addHost(*h1.manager, "ov", hostEntry(h2, "192.168.77.9:1", "10.210.1.128/25")) == -EINVAL);

        // -- One container per host.
        std::string c1ns = dir.netns("c1");
        std::string c2ns = dir.netns("c2");
        net::SEndpointCreate e1, e2;
        e1.containerId = "c1";
        e2.containerId = "c2";
        net::SNetworkEndpoint ep1, ep2;
        r = co_await h1.manager->connect("ov", c1ns, e1, ep1);
        REQUIRE(r == SBOX_OK);
        r = co_await h2.manager->connect("ov", c2ns, e2, ep2);
        REQUIRE(r == SBOX_OK);
        CHECK(ep1.address(4).toString() == "10.210.1.2/24");
        CHECK(ep2.address(4).toString() == "10.210.2.2/24");
        CHECK(ep1.mtu == 1420);

        // --> Container to container across the hosts, both directions.
        r = co_await echoAcross(c1ns, c2ns, "10.210.2.2", 300000);
        CHECK(r == 0);
        r = co_await echoAcross(c2ns, c1ns, "10.210.1.2", 1000);
        CHECK(r == 0);

        // --> The host itself reaches a remote container (route with the gateway as source).
        r = co_await echoAcross(h1.ns, c2ns, "10.210.2.2", 1000);
        CHECK(r == 0);

        SWgDeviceStatus st;
        REQUIRE(co_await h1.driver->status(*h1.manager, "ov", st) == SBOX_OK);
        REQUIRE(st.peers.size() == 1);
        CHECK(st.peers[0].lastHandshakeSec > 0);
        CHECK(st.peers[0].rxBytes > 300000);

        // --> After removing host 2, host 1's container cannot reach it any more.
        REQUIRE(co_await h1.driver->removeHost(*h1.manager, "ov", h2.pub) == SBOX_OK);
        REQUIRE(co_await h1.driver->status(*h1.manager, "ov", st) == SBOX_OK);
        CHECK(st.peers.empty());
        r = co_await echoAcross(c1ns, c2ns, "10.210.2.2", 100, 2000);
        CHECK(r != 0);
        CHECK(co_await h1.driver->removeHost(*h1.manager, "ov", h2.pub) == -ENOENT);

        // -- Clean up: endpoints, networks, and nothing left behind on the hosts.
        CHECK(co_await h1.manager->disconnect("ov", "c1") == SBOX_OK);
        CHECK(co_await h2.manager->disconnect("ov", "c2") == SBOX_OK);
        CHECK(co_await h1.manager->deleteNetwork("ov") == SBOX_OK);
        CHECK(co_await h2.manager->deleteNetwork("ov") == SBOX_OK);

        net::CRtnl rt;
        REQUIRE(rt.open(h1.ns) == SBOX_OK);
        CHECK(co_await rt.linkIndex(n1.driverState.get("interface").asString()) == -ENODEV);
        CHECK(co_await rt.linkIndex(n1.driverState.get("bridge").asString()) == -ENODEV);
        CHECK_FALSE(CFile::exists(CFile::join(h1.stateDir, "wg-overlay/" + n1.id + ".json")));
    }());
}

TEST_CASE("overlay: invalid configurations are refused") {
    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STempDir dir;
        SHost h;
        h.init(dir, "host");

        SWgOverlayConfig c;
        c.privateKey = h.priv;
        c.hostSubnet = prefix("10.220.1.0/24");
        c.mode = EWGM_USERSPACE;
        net::SNetworkCreate req;
        REQUIRE(MakeWgOverlayNetwork("bad", prefix("10.220.0.0/16"), c, req) == SBOX_OK);

        // --> A peer subnet overlapping this host's subnet.
        SWgOverlayConfig withBadPeer = c;
        SWgOverlayHost p;
        GenerateWgPrivateKey(p.publicKey);
        p.subnet = prefix("10.220.1.0/25");
        withBadPeer.peers.push_back(p);
        req.options[WG_OVERLAY_OPTION] = withBadPeer.toJson().dump();
        net::SNetwork n;
        CHECK(co_await h.manager->createNetwork(req, n) == -EINVAL);

        // --> No configuration at all.
        req.options.erase(WG_OVERLAY_OPTION);
        CHECK(co_await h.manager->createNetwork(req, n) == -EINVAL);

        // --> The configuration from a file works and the file option is dropped.
        std::string file = dir.join("ov.json");
        REQUIRE(CFile::writeAtomic(file, c.toJson().dump(), 0600) == SBOX_OK);
        req.options[WG_OVERLAY_FILE_OPTION] = file;
        int32_t r = co_await h.manager->createNetwork(req, n);
        REQUIRE(r == SBOX_OK);
        CHECK(n.option(WG_OVERLAY_FILE_OPTION).empty());

        // --> A device restore is a no-op while the device runs here.
        CHECK(co_await h.driver->restore(*h.manager) == 0);
        CHECK(co_await h.manager->deleteNetwork("bad") == SBOX_OK);
    }());
}
