#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/network.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/net/resolv.hpp>
#include "testutil.hpp"
#include "dhcpserver.hpp"
#include <netinet/in.h>

using namespace sbox;
using namespace sbox::net;

namespace {

    SIpPrefix prefix(const char* text) {
        SIpPrefix p;
        SIpPrefix::parse(text, p);
        return p;
    }

    SIpAddress ip(const char* text) {
        SIpAddress a;
        SIpAddress::parse(text, a);
        return a;
    }

    /* Runs a connect from `fromNs` to address:port while a listener in `toNs` accepts. */
    TTask<bool> reachable(const std::string& fromNs, const std::string& toNs, const char* listenAddr,
        const char* connectAddr, uint16_t listenPort, uint16_t connectPort, int32_t timeoutSec = 3)
    {
        CListener listener;
        {
            CNetnsScope scope(toNs);
            sbox::SEndpoint ep;
            sbox::SEndpoint::fromIp(listenAddr, listenPort, ep);
            if (listener.listen(ep) != SBOX_OK) {
                co_return false;
            }
        }

        bool accepted = false;
        CEventLoop::current()->spawn([](CListener* l, bool* flag, int32_t secs) -> TTask<void> {
            CSocket conn;
            *flag = co_await l->accept(conn, secs * 1000 + 500) == SBOX_OK;
        }(&listener, &accepted, timeoutSec));

        std::string target = connectAddr;
        int32_t r = co_await CNetns::run(fromNs, [target, connectPort, timeoutSec]() {
            return nettest::blockingConnect(target.c_str(), connectPort, "x", timeoutSec);
        });

        // --> Let the accept task observe the connection (or time out).
        for (int32_t i = 0; i < (timeoutSec * 1000 + 600) / 10 && !accepted; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        listener.close();
        co_await CEventLoop::current()->sleepFor(1);
        co_return r == 0 && accepted;
    }

}

TEST_CASE("bridge networks: endpoints, port mapping, isolation, persistence and cleanup") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string c1 = dir.netns("c1");
    std::string c2 = dir.netns("c2");
    std::string c3 = dir.netns("c3");
    REQUIRE(!c3.empty());

    SNetworkManagerOptions opts;
    opts.stateDir = dir.join("state");
    opts.hostNetns = host;

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CNetworkManager mgr(opts);

        // --> A real host has its loopback up (published ports are reachable on 127.0.0.1).
        CRtnl hostLo;
        hostLo.open(host);
        co_await hostLo.setUp(1);

        SNetworkCreate req;
        req.name = "front";
        SNetwork front;
        REQUIRE(co_await mgr.createNetwork(req, front) == SBOX_OK);
        REQUIRE(front.subnets.size() == 1);
        CHECK(front.subnets[0].subnet.toString() == "172.17.0.0/16");
        CHECK(front.subnets[0].gateway.toString() == "172.17.0.1");
        std::string bridge = front.driverState.get("bridge").asString();
        CHECK(bridge == "br-" + front.id.substr(0, 12));

        SNetwork dupe;
        CHECK(co_await mgr.createNetwork(req, dupe) == -EEXIST);

        SNetworkCreate req2;
        req2.name = "back";
        SSubnetConfig sc;
        sc.subnet = prefix("10.44.0.0/24");
        sc.gateway = ip("10.44.0.254");
        sc.ipRange = prefix("10.44.0.128/25");
        req2.subnets.push_back(sc);
        req2.options["com.docker.network.bridge.name"] = "sbox-back";
        req2.options["com.docker.network.driver.mtu"] = "1400";
        SNetwork back;
        REQUIRE(co_await mgr.createNetwork(req2, back) == SBOX_OK);

        // --> Endpoints on "front": c1 and c2, explicit address for c2.
        SEndpointCreate e1;
        e1.containerId = "ctr1";
        SNetworkEndpoint ep1;
        REQUIRE(co_await mgr.connect("front", c1, e1, ep1) == SBOX_OK);
        CHECK(ep1.sandboxIfName == "eth0");
        CHECK(ep1.address(4).toString() == "172.17.0.2/16");
        CHECK(ep1.mac.toString() == "02:42:ac:11:00:02");

        SEndpointCreate e2;
        e2.containerId = "ctr2";
        SIpPrefix::parse("172.17.3.3", e2.ipv4);
        SNetworkEndpoint ep2;
        REQUIRE(co_await mgr.connect(front.id.substr(0, 10), c2, e2, ep2) == SBOX_OK);
        CHECK(ep2.address(4).toString() == "172.17.3.3/16");

        // --> c3 on "back": address from the ip range, gateway as configured, MTU applied.
        SEndpointCreate e3;
        e3.containerId = "ctr3";
        SNetworkEndpoint ep3;
        REQUIRE(co_await mgr.connect("back", c3, e3, ep3) == SBOX_OK);
        CHECK(ep3.address(4).toString() == "10.44.0.128/24");
        REQUIRE(ep3.gateways.size() == 1);
        CHECK(ep3.gateways[0].toString() == "10.44.0.254");

        CRtnl rt3;
        rt3.open(c3);
        SLinkInfo eth;
        CHECK(co_await rt3.getLink("eth0", eth) == SBOX_OK);
        CHECK(eth.mtu == 1400);
        std::vector<SRouteInfo> routes;
        co_await rt3.listRoutes(routes, AF_INET);
        bool sawDefault = false;
        for (const SRouteInfo& r : routes) {
            sawDefault = sawDefault || (r.destination.length == 0 && r.gateway == ip("10.44.0.254"));
        }

        CHECK(sawDefault);

        // --> Same bridge reachable, other network isolated.
        CHECK(co_await reachable(c2, c1, "172.17.0.2", "172.17.0.2", 7001, 7001));
        CHECK_FALSE(co_await reachable(c3, c1, "172.17.0.2", "172.17.0.2", 7002, 7002, 1));

        // --> Publish c1:80 on the host; loopback and the gateway address both reach it.
        SPortMapping pm;
        REQUIRE(SPortMapping::parse("18081:80/tcp", pm) == SBOX_OK);
        SPortMapping eph;
        REQUIRE(SPortMapping::parse("81", eph) == SBOX_OK);
        CHECK(co_await mgr.setPortMappings(ep1.id, { pm, eph }) == SBOX_OK);
        CHECK(co_await reachable(host, c1, "172.17.0.2", "127.0.0.1", 80, 18081));
        CHECK(co_await reachable(host, c1, "172.17.0.2", "10.44.0.254", 80, 18081));

        SNetworkEndpoint reread;
        REQUIRE(co_await mgr.getEndpoint(ep1.id, reread) == SBOX_OK);
        REQUIRE(reread.ports.size() == 2);
        CHECK(reread.ports[1].hostPort >= 32768);
        CHECK(reread.ports[1].hostPort <= 60999);

        // --> The same host port cannot be published twice.
        CHECK(co_await mgr.setPortMappings(ep2.id, { pm }) == -EADDRINUSE);

        // --> A second manager instance sees the persisted state.
        {
            CNetworkManager other(opts);
            std::vector<SNetwork> nets;
            CHECK(co_await other.listNetworks(nets) == SBOX_OK);
            CHECK(nets.size() == 2);
            std::vector<SNetworkEndpoint> eps;
            CHECK(co_await other.listEndpoints("front", eps) == SBOX_OK);
            CHECK(eps.size() == 2);
            SNetwork got;
            CHECK(co_await other.getNetwork("back", got) == SBOX_OK);
            CHECK(got.option("com.docker.network.driver.mtu") == "1400");
        }

        // --> Leave and join again.
        CHECK(co_await mgr.leave(ep2.id) == SBOX_OK);
        CRtnl rt2;
        rt2.open(c2);
        CHECK(co_await rt2.linkIndex("eth0") == -ENODEV);
        SNetworkEndpoint rejoined;
        CHECK(co_await mgr.join(ep2.id, c2, "eth5", rejoined) == SBOX_OK);
        CHECK(co_await rt2.linkIndex("eth5") > 0);

        // --> Cleanup order: networks with endpoints are busy.
        CHECK(co_await mgr.deleteNetwork("front") == -EBUSY);
        CHECK(co_await mgr.disconnect("front", "ctr1") == SBOX_OK);
        CHECK(co_await mgr.disconnect("front", "ctr2") == SBOX_OK);
        CHECK(co_await mgr.disconnect("front", "ctr2") == -ENOENT);
        CHECK(co_await mgr.disconnect("", "ctr3") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("front") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("back") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("back") == -ENOENT);

        CRtnl hrt;
        hrt.open(host);
        CHECK(co_await hrt.linkIndex(bridge) == -ENODEV);
        CHECK(co_await hrt.linkIndex("sbox-back") == -ENODEV);

        std::vector<SLinkInfo> links;
        co_await hrt.listLinks(links);
        for (const SLinkInfo& l : links) {
            CHECK(l.kind != "veth");
        }

        CFirewall fw;
        if (fw.open(host) == SBOX_OK) {
            CHECK(co_await fw.exists() == 0);
        }

        SIpamPool pool;
        CHECK(co_await mgr.ipam().getPool(front.subnets[0].poolId, pool) == -ENOENT);
    };

    loop.run(body());
}

TEST_CASE("internal networks, ICC off and none/host drivers") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string a = dir.netns("a");
    std::string b = dir.netns("b");
    std::string n = dir.netns("n");
    REQUIRE(!n.empty());

    SNetworkManagerOptions opts;
    opts.stateDir = dir.join("state");
    opts.hostNetns = host;

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CNetworkManager mgr(opts);

        SNetworkCreate req;
        req.name = "quiet";
        req.internal = true;
        req.options["com.docker.network.bridge.enable_icc"] = "false";
        SSubnetConfig sc;
        sc.subnet = prefix("10.55.0.0/24");
        req.subnets.push_back(sc);
        SNetwork net;
        REQUIRE(co_await mgr.createNetwork(req, net) == SBOX_OK);

        SNetworkEndpoint ea, eb;
        SEndpointCreate ca;
        ca.containerId = "a";
        REQUIRE(co_await mgr.connect("quiet", a, ca, ea) == SBOX_OK);
        SEndpointCreate cb;
        cb.containerId = "b";
        REQUIRE(co_await mgr.connect("quiet", b, cb, eb) == SBOX_OK);

        // --> Internal networks have no gateway route.
        CHECK(ea.gateways.empty());

        // --> ICC disabled: a cannot reach b (needs bridge netfilter; report when missing).
        bool icc = co_await reachable(a, b, "10.55.0.3", "10.55.0.3", 7100, 7100, 1);
        if (CFile::exists("/proc/sys/net/bridge/bridge-nf-call-iptables")) {
            CHECK_FALSE(icc);
        }
        else {
            MESSAGE("bridge netfilter unavailable, ICC filtering not enforced");
        }

        // --> none: loopback only.
        SNetworkCreate nreq;
        nreq.name = "nonet";
        nreq.driver = "null";
        SNetwork none;
        REQUIRE(co_await mgr.createNetwork(nreq, none) == SBOX_OK);
        CHECK(none.subnets.empty());
        SNetworkEndpoint en;
        SEndpointCreate cn;
        cn.containerId = "n";
        REQUIRE(co_await mgr.connect("nonet", n, cn, en) == SBOX_OK);
        CRtnl rn;
        rn.open(n);
        SLinkInfo lo;
        CHECK(co_await rn.getLink("lo", lo) == SBOX_OK);
        CHECK(lo.isUp());

        SNetworkCreate hreq;
        hreq.name = "hostnet";
        hreq.driver = "host";
        SNetwork hn;
        REQUIRE(co_await mgr.createNetwork(hreq, hn) == SBOX_OK);

        SNetworkCreate bad;
        bad.name = "bad name";
        CHECK(co_await mgr.createNetwork(bad, hn) == -EINVAL);
        bad.name = "x";
        bad.driver = "nope";
        CHECK(co_await mgr.createNetwork(bad, hn) == -ENOTSUP);

        CHECK(co_await mgr.disconnect("", "a") == SBOX_OK);
        CHECK(co_await mgr.disconnect("", "b") == SBOX_OK);
        CHECK(co_await mgr.disconnect("", "n") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("quiet") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("nonet") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("hostnet") == SBOX_OK);
    };

    loop.run(body());
}

TEST_CASE("macvlan networks with static and DHCP physical addresses") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string lan = dir.netns("lan");
    std::string c1 = dir.netns("c1");
    std::string c2 = dir.netns("c2");
    REQUIRE(!c2.empty());

    SNetworkManagerOptions opts;
    opts.stateDir = dir.join("state");
    opts.hostNetns = host;

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        // --> The host's "physical" uplink lan0 leads to the LAN namespace (router + DHCP).
        CRtnl hrt;
        hrt.open(host);
        CFd lanFd;
        CNetns::open(lan, lanFd);
        REQUIRE(co_await hrt.createVeth("lan0", "srv0", lanFd.get()) == SBOX_OK);
        co_await hrt.setUp(co_await hrt.linkIndex("lan0"));

        CRtnl lrt;
        lrt.open(lan);
        int32_t srv = co_await lrt.linkIndex("srv0");
        co_await lrt.addAddress(srv, prefix("10.123.0.1/24"));
        co_await lrt.setUp(srv);
        co_await lrt.setUp(1);

        CNetworkManager mgr(opts);

        // --> Static physical addresses from a configured range.
        SNetworkCreate req;
        req.name = "phys";
        req.driver = "macvlan";
        req.options["parent"] = "lan0";
        SSubnetConfig sc;
        sc.subnet = prefix("10.123.0.0/24");
        sc.gateway = ip("10.123.0.1");
        sc.rangeStart = ip("10.123.0.100");
        sc.rangeEnd = ip("10.123.0.110");
        req.subnets.push_back(sc);
        SNetwork phys;
        REQUIRE(co_await mgr.createNetwork(req, phys) == SBOX_OK);

        SEndpointCreate e1;
        e1.containerId = "m1";
        SNetworkEndpoint ep1;
        REQUIRE(co_await mgr.connect("phys", c1, e1, ep1) == SBOX_OK);
        CHECK(ep1.address(4).toString() == "10.123.0.100/24");

        CRtnl r1;
        r1.open(c1);
        SLinkInfo eth;
        CHECK(co_await r1.getLink("eth0", eth) == SBOX_OK);
        CHECK(eth.kind == "macvlan");

        // --> The container reaches the LAN router directly.
        CHECK(co_await reachable(c1, lan, "10.123.0.1", "10.123.0.1", 7200, 7200));

        // --> DHCP-assigned address on a second macvlan network.
        nettest::SMiniServer server;
        REQUIRE(server.open(lan, "srv0") == SBOX_OK);
        bool served = false;
        CEventLoop::current()->spawn([](nettest::SMiniServer* sv, bool* flag) -> TTask<void> {
            co_await sv->serve();
            *flag = true;
        }(&server, &served));

        CHECK(co_await mgr.disconnect("phys", "m1") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("phys") == SBOX_OK);

        SNetworkCreate dreq;
        dreq.name = "dhcpnet";
        dreq.driver = "macvlan";
        dreq.options["parent"] = "lan0";
        dreq.options["sbox.dhcp"] = "true";
        SNetwork dnet;
        REQUIRE(co_await mgr.createNetwork(dreq, dnet) == SBOX_OK);

        SEndpointCreate e2;
        e2.containerId = "m2";
        e2.hostname = "box2";
        SNetworkEndpoint ep2;
        int32_t r = co_await mgr.connect("dhcpnet", c2, e2, ep2);
        REQUIRE(r == SBOX_OK);
        CHECK(ep2.address(4).toString() == "10.123.0.50/24");
        REQUIRE(ep2.gateways.size() == 1);
        CHECK(ep2.gateways[0].toString() == "10.123.0.1");
        CHECK(ep2.driverState.get("lease").get("server").asString() == "10.123.0.1");

        CRtnl r2;
        r2.open(c2);
        std::vector<SAddressInfo> addrs;
        co_await r2.listAddresses(addrs, AF_INET, co_await r2.linkIndex("eth0"));
        REQUIRE(addrs.size() == 1);
        CHECK(addrs[0].prefix.toString() == "10.123.0.50/24");

        CHECK(co_await mgr.disconnect("dhcpnet", "m2") == SBOX_OK);
        for (int32_t i = 0; i < 100 && server.releases == 0; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.releases == 1);
        CHECK(co_await mgr.deleteNetwork("dhcpnet") == SBOX_OK);

        // --> Bad parents and modes are rejected.
        SNetworkCreate bad;
        bad.name = "badvlan";
        bad.driver = "macvlan";
        SNetwork tmp;
        CHECK(co_await mgr.createNetwork(bad, tmp) == -EINVAL);
        bad.options["parent"] = "nosuch0";
        CHECK(co_await mgr.createNetwork(bad, tmp) == -ENODEV);
        bad.options["parent"] = "lan0";
        bad.options["macvlan_mode"] = "weird";
        CHECK(co_await mgr.createNetwork(bad, tmp) == -EINVAL);

        SNetworkCreate iv;
        iv.name = "ipv";
        iv.driver = "ipvlan";
        iv.options["parent"] = "lan0";
        SSubnetConfig isc;
        isc.subnet = prefix("10.124.0.0/24");
        iv.subnets.push_back(isc);
        SNetwork ivn;
        REQUIRE(co_await mgr.createNetwork(iv, ivn) == SBOX_OK);
        SEndpointCreate ie;
        ie.containerId = "i1";
        SNetworkEndpoint iep;
        int32_t ir = co_await mgr.connect("ipv", c1, ie, iep);
        if (ir == -EOPNOTSUPP || ir == -ENOTSUP) {
            MESSAGE("ipvlan not available in this kernel");
        }
        else {
            CHECK(ir == SBOX_OK);
            CHECK(co_await mgr.disconnect("ipv", "i1") == SBOX_OK);
        }

        CHECK(co_await mgr.deleteNetwork("ipv") == SBOX_OK);

        server.stop = true;
        while (!served) {
            co_await CEventLoop::current()->sleepFor(10);
        }
    };

    loop.run(body());
}

TEST_CASE("rootless helpers") {
    MESSAGE("can manage host network: " << CanManageHostNetwork());
    CHECK(DefaultNetworkStateDir().size() > 4);

    if (!nettest::canCreateNetns()) {
        return;
    }

    nettest::STempDir dir;
    std::string ns = dir.netns("lo");
    CEventLoop loop;
    CHECK(loop.run(BringUpLoopback(ns)) == SBOX_OK);
}

TEST_CASE("port mapping parser") {
    SPortMapping p;
    REQUIRE(SPortMapping::parse("127.0.0.1:8080:80/udp", p) == SBOX_OK);
    CHECK(p.hostIp.toString() == "127.0.0.1");
    CHECK(p.hostPort == 8080);
    CHECK(p.containerPort == 80);
    CHECK(p.protocolName() == "udp");

    REQUIRE(SPortMapping::parse("[::1]:9000:90", p) == SBOX_OK);
    CHECK(p.hostIp.toString() == "::1");
    CHECK(p.protocol == IPPROTO_TCP);

    REQUIRE(SPortMapping::parse("0.0.0.0::53/sctp", p) == SBOX_OK);
    CHECK(p.hostPort == 0);
    CHECK(p.containerPort == 53);
    CHECK(p.protocolName() == "sctp");

    CHECK(SPortMapping::parse("80/xyz", p) == -EINVAL);
    CHECK(SPortMapping::parse("70000:80", p) == -EINVAL);
    CHECK(SPortMapping::parse("a:b:c:80", p) == -EINVAL);

    SPortMapping back;
    REQUIRE(SPortMapping::fromJson(p.toJson(), back) == SBOX_OK);
    CHECK(back.containerPort == 53);
}

TEST_CASE("hosts and resolv.conf generation") {
    std::string hosts = GenerateHosts("web", { ip("172.17.0.2") }, { { ip("10.0.0.9"), { "db", "db.local" } } }, { "www" }, false);
    CHECK(hosts == "127.0.0.1\tlocalhost\n10.0.0.9\tdb db.local\n172.17.0.2\tweb www\n");

    std::string withV6 = GenerateHosts("web", { ip("fd00::2") });
    CHECK(withV6.find("::1\tlocalhost ip6-localhost ip6-loopback\n") != std::string::npos);
    CHECK(withV6.find("fd00::2\tweb\n") != std::string::npos);

    std::string host = "# managed\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nsearch lan example.com\noptions edns0 trust-ad\n";
    CHECK(ContainerResolvConf(host, false) == "nameserver 192.168.1.1\nsearch lan example.com\noptions edns0 trust-ad\n");
    CHECK(ContainerResolvConf(host, true) == host);

    std::string local = "nameserver 127.0.0.53\noptions edns0\n";
    CHECK(ContainerResolvConf(local, false) == "nameserver 8.8.8.8\nnameserver 8.8.4.4\noptions edns0\n");
    CHECK(ContainerResolvConf(local, false, false, { ip("1.1.1.1") }, { "corp" }, { "ndots:2" })
        == "nameserver 1.1.1.1\nsearch corp\noptions ndots:2\n");

    SResolvConf parsed = ParseResolvConf("domain a.b\nsearch c.d e.f\nnameserver fe80::1%eth0\nnameserver ::1\n");
    CHECK(parsed.search.size() == 2);
    CHECK(parsed.nameservers.size() == 1);
}
