#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/net/sysctl.hpp>
#include "testutil.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace sbox;
using namespace sbox::net;

namespace {

    SIpPrefix prefix(const char* text) {
        SIpPrefix p;
        REQUIRE(SIpPrefix::parse(text, p) == SBOX_OK);
        return p;
    }

    SIpAddress ip(const char* text) {
        SIpAddress a;
        REQUIRE(SIpAddress::parse(text, a) == SBOX_OK);
        return a;
    }

    /* Blocking TCP connect + send used inside a forked child (CNetns::run). */
    int32_t blockingConnect(const char* address, uint16_t port, const char* payload) {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return -errno;
        }

        timeval tv{ 5, 0 };
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, address, &sa.sin_addr);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            int32_t err = -errno;
            ::close(fd);
            return err;
        }

        ssize_t n = ::send(fd, payload, std::strlen(payload), MSG_NOSIGNAL);
        ::close(fd);
        return n == ssize_t(std::strlen(payload)) ? 0 : -EIO;
    }

}

TEST_CASE("bridge, veth, addresses, routes and TCP across the veth inside test namespaces") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string hostNs = dir.netns("host");
    std::string ctrNs = dir.netns("ctr");
    REQUIRE(!hostNs.empty());
    REQUIRE(!ctrNs.empty());

    CEventLoop loop;

    auto body = [&]() -> TTask<void> {
        CRtnl host, ctr;
        REQUIRE(host.open(hostNs) == SBOX_OK);
        REQUIRE(ctr.open(ctrNs) == SBOX_OK);

        // --> Unknown kinds fail with the kernel's extended ACK text.
        SLinkSpec bad;
        bad.name = "bad0";
        bad.kind = "no-such-kind";
        int32_t r = co_await host.createLink(bad);
        CHECK(r < 0);
        CHECK(!host.lastError().empty());
        MESSAGE("extended ACK: " << host.lastError());

        REQUIRE(co_await host.createBridge("br-test", 1400) == SBOX_OK);
        int32_t br = co_await host.linkIndex("br-test");
        REQUIRE(br > 0);

        CFd ctrFd;
        REQUIRE(CNetns::open(ctrNs, ctrFd) == SBOX_OK);
        REQUIRE(co_await host.createVeth("veth-h", "veth-c", ctrFd.get(), 1400) == SBOX_OK);

        int32_t vh = co_await host.linkIndex("veth-h");
        REQUIRE(vh > 0);
        CHECK(co_await host.setMaster(vh, br) == SBOX_OK);
        CHECK(co_await host.setUp(vh) == SBOX_OK);
        CHECK(co_await host.setUp(br) == SBOX_OK);
        CHECK(co_await host.addAddress(br, prefix("10.200.0.1/24")) == SBOX_OK);
        CHECK(co_await host.addAddress(br, prefix("10.200.0.1/24")) == -EEXIST);
        if (nettest::haveIpv6()) {
            CHECK(co_await host.addAddress(br, prefix("fd77::1/64")) == SBOX_OK);
        }
        else {
            MESSAGE("IPv6 disabled in this kernel");
        }

        SLinkInfo hostSide;
        REQUIRE(co_await host.getLinkByIndex(vh, hostSide) == SBOX_OK);
        CHECK(hostSide.master == br);
        CHECK(hostSide.kind == "veth");
        CHECK(hostSide.mtu == 1400);

        // --> The peer was created directly in the container namespace.
        int32_t vc = co_await ctr.linkIndex("veth-c");
        REQUIRE(vc > 0);
        CHECK(co_await host.linkIndex("veth-c") == -ENODEV);
        CHECK(co_await ctr.rename(vc, "eth0") == SBOX_OK);

        SMacAddress mac;
        SMacAddress::parse("02:42:0a:c8:00:02", mac);
        CHECK(co_await ctr.setMac(vc, mac) == SBOX_OK);
        CHECK(co_await ctr.setMtu(vc, 1300) == SBOX_OK);
        CHECK(co_await ctr.addAddress(vc, prefix("10.200.0.2/24")) == SBOX_OK);
        CHECK(co_await ctr.setUp(vc) == SBOX_OK);
        CHECK(co_await ctr.setUp(1) == SBOX_OK);
        CHECK(co_await ctr.addDefaultRoute(ip("10.200.0.1")) == SBOX_OK);

        SLinkInfo eth0;
        REQUIRE(co_await ctr.getLink("eth0", eth0) == SBOX_OK);
        CHECK(eth0.mac == mac);
        CHECK(eth0.mtu == 1300);
        CHECK(eth0.isUp());

        std::vector<SAddressInfo> addrs;
        CHECK(co_await ctr.listAddresses(addrs, AF_INET, vc) == SBOX_OK);
        REQUIRE(addrs.size() == 1);
        CHECK(addrs[0].prefix.toString() == "10.200.0.2/24");

        std::vector<SRouteInfo> routes;
        CHECK(co_await ctr.listRoutes(routes, AF_INET) == SBOX_OK);
        bool sawDefault = false;
        for (const SRouteInfo& rt : routes) {
            if (rt.destination.length == 0 && rt.gateway == ip("10.200.0.1")) {
                sawDefault = true;
                CHECK(rt.oif == vc);
            }
        }

        CHECK(sawDefault);

        // --> Prefix route through the gateway, then removal.
        SRouteInfo extra;
        extra.destination = prefix("192.0.2.0/24");
        extra.gateway = ip("10.200.0.1");
        CHECK(co_await ctr.addRoute(extra) == SBOX_OK);
        CHECK(co_await ctr.delRoute(extra) == SBOX_OK);
        CHECK(co_await ctr.delRoute(extra) == -ESRCH);

        // --> Neighbour entries.
        CHECK(co_await ctr.setNeighbour(vc, ip("10.200.0.9"), SMacAddress::random()) == SBOX_OK);
        std::vector<SNeighbourInfo> neigh;
        CHECK(co_await ctr.listNeighbours(neigh, AF_INET) == SBOX_OK);
        bool sawNeigh = false;
        for (const SNeighbourInfo& n : neigh) {
            sawNeigh = sawNeigh || n.address == ip("10.200.0.9");
        }

        CHECK(sawNeigh);

        // --> TCP from the container namespace to a listener on the bridge address.
        CListener listener;
        {
            CNetnsScope scope(hostNs);
            REQUIRE(scope.error() == SBOX_OK);
            SEndpoint ep;
            SEndpoint::fromIp("10.200.0.1", 0, ep);
            REQUIRE(listener.listen(ep) == SBOX_OK);
        }

        uint16_t port = listener.localEndpoint().port();
        std::string received;
        bool accepted = false;

        CEventLoop::current()->spawn([](CListener* l, std::string* out, bool* flag) -> TTask<void> {
            CSocket conn;
            int32_t a = co_await l->accept(conn, 10000);
            CHECK(a == SBOX_OK);
            if (a == SBOX_OK) {
                std::vector<uint8_t> all;
                co_await conn.recvAll(all, 1024, 5000);
                out->assign(all.begin(), all.end());
                CHECK(conn.remoteEndpoint().toString().rfind("10.200.0.2:", 0) == 0);
            }

            *flag = true;
        }(&listener, &received, &accepted));

        int32_t child = co_await CNetns::run(ctrNs, [port]() {
            return blockingConnect("10.200.0.1", port, "hello-veth");
        });

        CHECK(child == 0);

        while (!accepted) {
            co_await CEventLoop::current()->sleepFor(2);
        }

        CHECK(received == "hello-veth");

        // --> Detach and delete; deleting one end of the pair removes the peer.
        CHECK(co_await host.setMaster(vh, 0) == SBOX_OK);
        CHECK(co_await host.deleteLink(vh) == SBOX_OK);
        CHECK(co_await ctr.linkIndex("eth0") == -ENODEV);
        CHECK(co_await host.delAddress(br, prefix("10.200.0.1/24")) == SBOX_OK);
    };

    loop.run(body());
}

TEST_CASE("macvlan, ipvlan, vxlan, dummy and tun/tap devices in a test namespace") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string hostNs = dir.netns("host");
    std::string ctrNs = dir.netns("ctr");
    REQUIRE(!hostNs.empty());

    CEventLoop loop;

    auto body = [&]() -> TTask<void> {
        CRtnl host, ctr;
        REQUIRE(host.open(hostNs) == SBOX_OK);
        REQUIRE(ctr.open(ctrNs) == SBOX_OK);

        // --> A dummy device is the natural parent; fall back to a veth end when the kernel
        // has no dummy driver.
        std::string parentName = "parent0";
        int32_t d = co_await host.createDummy(parentName);
        if (d != SBOX_OK) {
            MESSAGE("dummy unavailable (" << d << "), using a veth end as macvlan parent");
            REQUIRE(co_await host.createVeth(parentName, "parent0p") == SBOX_OK);
        }

        int32_t parent = co_await host.linkIndex(parentName);
        REQUIRE(parent > 0);
        CHECK(co_await host.setUp(parent) == SBOX_OK);

        CFd ctrFd;
        REQUIRE(CNetns::open(ctrNs, ctrFd) == SBOX_OK);

        static const EMacvlanMode MODES[] = { EMVM_BRIDGE, EMVM_PRIVATE, EMVM_VEPA };
        int32_t made = 0;
        for (EMacvlanMode mode : MODES) {
            std::string name = "mv" + std::to_string(made);
            CHECK(co_await host.createMacvlan(name, parent, mode, ctrFd.get()) == SBOX_OK);
            SLinkInfo info;
            CHECK(co_await ctr.getLink(name, info) == SBOX_OK);
            CHECK(info.kind == "macvlan");
            ++made;
        }

        // --> passthru allows a single macvlan on the parent.
        CHECK(co_await host.createMacvlan("mvpt", parent, EMVM_PASSTHRU) < 0);

        int32_t iv = co_await host.createIpvlan("ipv0", parent, EIVM_L2, ctrFd.get());
        if (iv == -EOPNOTSUPP || iv == -ENOTSUP) {
            MESSAGE("ipvlan not available in this kernel");
        }
        else {
            CHECK(iv == SBOX_OK);
            SLinkInfo info;
            CHECK(co_await ctr.getLink("ipv0", info) == SBOX_OK);
            CHECK(info.kind == "ipvlan");
        }

        SVxlanConfig vx;
        vx.vni = 4242;
        vx.port = 4789;
        SIpAddress::parse("239.1.1.1", vx.remote);
        vx.parentIndex = parent;
        int32_t vr = co_await host.createVxlan("vx0", vx);
        if (vr == -EOPNOTSUPP) {
            MESSAGE("vxlan not available");
        }
        else {
            CHECK(vr == SBOX_OK);
            SLinkInfo info;
            CHECK(co_await host.getLink("vx0", info) == SBOX_OK);
            CHECK(info.kind == "vxlan");
        }

        // --> TUN and TAP devices created inside the namespace.
        CFd tun;
        std::string tunName;
        STunTapOptions opts;
        opts.netnsPath = hostNs;
        CHECK(CreateTunTap("sboxtun%d", opts, tun, &tunName) == SBOX_OK);
        CHECK(tunName == "sboxtun0");

        CFd tap;
        opts.tap = true;
        opts.persistent = true;
        CHECK(CreateTunTap("sboxtap0", opts, tap) == SBOX_OK);
        tap.reset();

        SLinkInfo tapInfo;
        CHECK(co_await host.getLink("sboxtap0", tapInfo) == SBOX_OK);
        CHECK(tapInfo.kind == "tun");
        CHECK(co_await host.deleteLink(tapInfo.index) == SBOX_OK);

        SLinkInfo tunInfo;
        CHECK(co_await host.getLink("sboxtun0", tunInfo) == SBOX_OK);
        tun.reset();

        // --> Bridges are namespace-local and refuse to move.
        REQUIRE(co_await host.createBridge("brstay") == SBOX_OK);
        int32_t bs = co_await host.linkIndex("brstay");
        CHECK(co_await host.moveToNetnsFd(bs, ctrFd.get()) == -EINVAL);

        // --> Move a link between namespaces by descriptor and rename it on the way.
        REQUIRE(co_await host.createVeth("mvmove", "mvmovep") == SBOX_OK);
        int32_t bm = co_await host.linkIndex("mvmove");
        CHECK(co_await host.moveToNetnsFd(bm, ctrFd.get(), "moved0") == SBOX_OK);
        CHECK(co_await host.linkIndex("mvmove") == -ENODEV);
        CHECK(co_await ctr.linkIndex("moved0") > 0);

        // --> Sysctl in a namespace.
        CHECK(SetIpForward(true, hostNs) == SBOX_OK);
        std::string value;
        CHECK(ReadSysctl("net.ipv4.ip_forward", value, hostNs) == SBOX_OK);
        CHECK(value == "1");
        CHECK(ReadSysctl("net.ipv4.ip_forward", value, ctrNs) == SBOX_OK);
        CHECK(value == "0");
        CHECK(SetRouteLocalnet(parentName, true, hostNs) == SBOX_OK);
        if (nettest::haveIpv6()) {
            CHECK(SetAcceptRa(parentName, 0, hostNs) == SBOX_OK);
            CHECK(SetIpv6Disabled(parentName, true, hostNs) == SBOX_OK);
        }
        else {
            MESSAGE("no IPv6 sysctls on this kernel");
        }
        CHECK(WriteSysctl("net/../../etc", "x", hostNs) == -EINVAL);
    };

    loop.run(body());
}

TEST_CASE("persistent namespaces are created, identified and removed") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string path = dir.join("pinned");
    REQUIRE(CNetns::create(path) == SBOX_OK);
    CHECK(CNetns::create(path) == -EEXIST);
    CHECK(CNetns::isNetns(path));
    CHECK_FALSE(CNetns::isNetns(dir.path));

    uint64_t a = 0, b = 0;
    CHECK(CNetns::inode(path, a) == SBOX_OK);
    CHECK(CNetns::inode("/proc/self/ns/net", b) == SBOX_OK);
    CHECK(a != b);

    CFd anon;
    CHECK(CNetns::createAnonymous(anon) == SBOX_OK);
    CHECK(anon.isValid());

    CEventLoop loop;
    int32_t inside = loop.run(CNetns::run(path, []() -> int32_t {
        // --> A fresh namespace only has a loopback device.
        return ::if_nametoindex("lo") == 1 && ::if_nametoindex("eth0") == 0 ? 7 : -1;
    }));
    CHECK(inside == 7);

    CHECK(CNetns::remove(path) == SBOX_OK);
    CHECK_FALSE(CFile::exists(path));
    CHECK(CNetns::remove(path) == SBOX_OK);
}
