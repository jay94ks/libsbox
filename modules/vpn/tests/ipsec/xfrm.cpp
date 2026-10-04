#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/ipsec/xfrm.hpp>
#include <sbox/net/rtnl.hpp>
#include "ipsec/datapaths.hpp"
#include "testutil.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    net::SIpAddress ip(const char* text) {
        net::SIpAddress a;
        net::SIpAddress::parse(text, a);
        return a;
    }

    net::SIpPrefix prefix(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    /** Policy with one tunnel template. */
    SXfrmPolicy tunnelPolicy(EXfrmDir dir, const char* src, const char* dst, uint32_t reqid) {
        SXfrmPolicy p;
        p.dir = dir;
        p.selector.src = prefix(src);
        p.selector.dst = prefix(dst);
        SXfrmTemplate t;
        t.src = ip(dir == EXDIR_OUT ? "10.123.0.1" : "10.123.0.2");
        t.dst = ip(dir == EXDIR_OUT ? "10.123.0.2" : "10.123.0.1");
        t.reqid = reqid;
        p.templates.push_back(t);
        return p;
    }

    bool needRoot() {
        if (!isRoot()) {
            MESSAGE("not root; skipping XFRM test");
            return false;
        }

        return true;
    }

}

TEST_CASE("XFRM probe reports what this kernel can do") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("probe");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        int32_t r = x.open(netns);
        if (r == -ENOTSUP) {
            MESSAGE("kernel without NETLINK_XFRM");
            co_return;
        }

        REQUIRE(r == SBOX_OK);
        SXfrmSupport s;
        REQUIRE(co_await x.probe(s) == SBOX_OK);
        CHECK(s.netlink);
        MESSAGE("XFRM support: esp=" << s.esp << " gcm=" << s.gcm << " chacha=" << s.chacha << " 3des=" << s.des3
                << " interfaces=" << s.interfaces);

        // --> The probe leaves nothing behind.
        std::vector<SXfrmSa> sas;
        REQUIRE(co_await x.listSas(sas) == SBOX_OK);
        CHECK(sas.empty());
    }(ns));
}

TEST_CASE("XFRM policies: add, list, delete and owner-scoped flush") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("policies");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        if (x.open(netns) != SBOX_OK) {
            MESSAGE("no NETLINK_XFRM");
            co_return;
        }

        const uint32_t base = 0x5b000000u;
        for (EXfrmDir d : { EXDIR_OUT, EXDIR_IN, EXDIR_FWD }) {
            bool out = d == EXDIR_OUT;
            SXfrmPolicy p = tunnelPolicy(d, out ? "10.77.0.0/24" : "10.88.0.0/16", out ? "10.88.0.0/16" : "10.77.0.0/24", base + 1);
            p.priority = 100;
            REQUIRE(co_await x.addPolicy(p) == SBOX_OK);
        }

        // --> Someone else's policy, with a mark and a port selector.
        SXfrmPolicy foreign = tunnelPolicy(EXDIR_OUT, "192.168.1.0/24", "192.168.2.0/24", 77);
        foreign.mark.value = 0x42;
        foreign.mark.mask = 0xff;
        foreign.selector.protocol = 17;
        foreign.selector.dstPort = 53;
        foreign.selector.dstPortMask = 0xffff;
        REQUIRE(co_await x.addPolicy(foreign) == SBOX_OK);
        CHECK(co_await x.addPolicy(foreign) == -EEXIST);
        CHECK(co_await x.addPolicy(foreign, true) == SBOX_OK);

        std::vector<SXfrmPolicy> list;
        REQUIRE(co_await x.listPolicies(list) == SBOX_OK);
        REQUIRE(list.size() == 4);

        bool sawForeign = false;
        for (const SXfrmPolicy& p : list) {
            REQUIRE(p.templates.size() == 1);
            if (p.templates[0].reqid == 77) {
                sawForeign = true;
                CHECK(p.mark.value == 0x42);
                CHECK(p.mark.mask == 0xff);
                CHECK(p.selector.protocol == 17);
                CHECK(p.selector.dstPort == 53);
                CHECK(p.selector.src.toString() == "192.168.1.0/24");
                CHECK(p.templates[0].mode == EXMODE_TUNNEL);
                CHECK(p.templates[0].dst.toString() == "10.123.0.2");
            }
            else {
                CHECK(p.templates[0].reqid == base + 1);
                CHECK(p.priority == 100);
            }
        }

        CHECK(sawForeign);

        SXfrmOwner owner;
        owner.reqidMin = base;
        owner.reqidMax = base + 0xffffff;
        CHECK(co_await x.flushOwned(owner) == 3);
        REQUIRE(co_await x.listPolicies(list) == SBOX_OK);
        REQUIRE(list.size() == 1);
        CHECK(list[0].templates[0].reqid == 77);

        CHECK(co_await x.deletePolicy(foreign.selector, EXDIR_OUT, foreign.mark) == SBOX_OK);
        CHECK(co_await x.deletePolicy(foreign.selector, EXDIR_OUT, foreign.mark) == -ENOENT);
        REQUIRE(co_await x.listPolicies(list) == SBOX_OK);
        CHECK(list.empty());
    }(ns));
}

TEST_CASE("XFRM SAs: allocate, add, read back, delete (needs kernel ESP)") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("sas");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        if (x.open(netns) != SBOX_OK) {
            MESSAGE("no NETLINK_XFRM");
            co_return;
        }

        SXfrmSupport support;
        REQUIRE(co_await x.probe(support) == SBOX_OK);

        SXfrmSa sa;
        sa.src = ip("10.123.0.2");
        sa.dst = ip("10.123.0.1");
        sa.reqid = 0x5b000009u;
        sa.crypt.name = "cbc(aes)";
        sa.crypt.key.assign(32, 1);
        sa.auth.name = "hmac(sha256)";
        sa.auth.key.assign(32, 2);
        sa.auth.bits = 128;
        sa.encap = true;
        sa.encapSport = 4500;
        sa.encapDport = 4500;
        sa.replayWindow = 64;
        sa.spi = 0xabc001;

        if (!support.esp) {
            // --> Without esp4 the kernel refuses ESP states: the data path falls back to user space.
            CHECK(co_await x.addSa(sa) == -EPROTONOSUPPORT);
            MESSAGE("kernel ESP unavailable; SA install skipped (user-space ESP is used instead)");
            co_return;
        }

        uint32_t spi = 0;
        REQUIRE(co_await x.allocSpi(sa.src, sa.dst, 50, sa.reqid, SXfrmMark(), spi) == SBOX_OK);
        CHECK(spi >= 0x100);
        sa.spi = spi;
        REQUIRE(co_await x.addSa(sa, true) == SBOX_OK);

        SXfrmSa back;
        REQUIRE(co_await x.getSa(sa.dst, spi, 50, back) == SBOX_OK);
        CHECK(back.reqid == sa.reqid);
        CHECK(back.crypt.name == "cbc(aes)");
        CHECK(back.auth.bits == 128);
        CHECK(back.encap);
        CHECK(back.encapDport == 4500);
        CHECK(back.replayWindow == 64);

        if (support.gcm) {
            SXfrmSa gcm = sa;
            gcm.spi = spi + 1;
            gcm.crypt = SXfrmAlgorithm();
            gcm.auth = SXfrmAlgorithm();
            gcm.aead.name = "rfc4106(gcm(aes))";
            gcm.aead.key.assign(20, 3);
            gcm.aead.bits = 128;
            CHECK(co_await x.addSa(gcm) == SBOX_OK);
        }

        SXfrmOwner owner;
        owner.reqidMin = 0x5b000000u;
        owner.reqidMax = 0x5bffffffu;
        CHECK(co_await x.flushOwned(owner) >= 1);
        CHECK(co_await x.getSa(sa.dst, spi, 50, back) == -ESRCH);
    }(ns));
}

TEST_CASE("XFRM interfaces (needs CONFIG_XFRM_INTERFACE)") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("ifaces");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        if (x.open(netns) != SBOX_OK) {
            MESSAGE("no NETLINK_XFRM");
            co_return;
        }

        int32_t r = co_await x.createInterface("xfrmt0", 42);
        if (r == -ENOTSUP) {
            MESSAGE("kernel without xfrm interfaces; skipped");
            co_return;
        }

        REQUIRE(r == SBOX_OK);
        net::CRtnl rtnl;
        REQUIRE(rtnl.open(netns) == SBOX_OK);
        CHECK(co_await rtnl.linkIndex("xfrmt0") > 0);
    }(ns));
}

TEST_CASE("XFRM notifications: policy expiry and acquire") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("events");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        CXfrmMonitor mon;
        if (x.open(netns) != SBOX_OK || mon.open(netns) != SBOX_OK) {
            MESSAGE("no NETLINK_XFRM");
            co_return;
        }

        // --> A policy with a one-second hard lifetime expires on its own.
        SXfrmPolicy p = tunnelPolicy(EXDIR_OUT, "10.200.0.0/24", "10.201.0.0/24", 5);
        p.lifetime.hardAddSeconds = 1;
        REQUIRE(co_await x.addPolicy(p) == SBOX_OK);

        SXfrmEvent ev;
        bool expired = false;
        while (!expired && co_await mon.next(ev, 5000) == SBOX_OK) {
            expired = ev.type == EXEV_POLICY_EXPIRE && ev.hard && ev.policy.selector.dst.toString() == "10.201.0.0/24";
        }

        CHECK(expired);

        // --> Traffic matching an IPsec policy without an SA makes the kernel ask for one.
        net::CRtnl rtnl;
        REQUIRE(rtnl.open(netns) == SBOX_OK);
        REQUIRE(co_await rtnl.createVeth("xva0", "xvb0") == SBOX_OK);
        int32_t index = co_await rtnl.linkIndex("xva0");
        REQUIRE(index > 0);
        REQUIRE(co_await rtnl.setUp(co_await rtnl.linkIndex("xvb0")) == SBOX_OK);
        REQUIRE(co_await rtnl.addAddress(index, prefix("10.123.0.1/24")) == SBOX_OK);
        REQUIRE(co_await rtnl.setUp(index) == SBOX_OK);
        net::SRouteInfo route;
        route.destination = prefix("10.124.0.0/24");
        route.oif = index;
        REQUIRE(co_await rtnl.addRoute(route) == SBOX_OK);

        SXfrmPolicy out = tunnelPolicy(EXDIR_OUT, "10.123.0.0/24", "10.124.0.0/24", 0x5b000077u);
        REQUIRE(co_await x.addPolicy(out) == SBOX_OK);

        int fd = -1;
        {
            net::CNetnsScope scope(netns);
            REQUIRE(scope.error() == SBOX_OK);
            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        }

        REQUIRE(fd >= 0);
        sockaddr_in to;
        std::memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(9);
        ::inet_pton(AF_INET, "10.124.0.5", &to.sin_addr);
        const char data[] = "acquire me";
        ::sendto(fd, data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));

        bool acquired = false;
        while (!acquired && co_await mon.next(ev, 5000) == SBOX_OK) {
            acquired = ev.type == EXEV_ACQUIRE && ev.sa.dst.toString() == "10.123.0.2" && ev.sa.reqid == 0x5b000077u;
        }

        ::close(fd);
        CHECK(acquired);
        mon.close();
    }(ns));
}

TEST_CASE("Kernel data path: SPI allocation, install (or refusal without esp4) and cleanup") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("kdp");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        CXfrm x;
        SXfrmSupport support;
        if (x.open(netns) != SBOX_OK || co_await x.probe(support) != SBOX_OK) {
            MESSAGE("no NETLINK_XFRM");
            co_return;
        }

        // --> Force the kernel path even where esp4 is missing to exercise everything up to
        // the SA install.
        SXfrmSupport forced = support;
        forced.esp = true;
        SIpsecDataPathOptions o;
        o.netnsPath = netns;
        o.reqidBase = 0x5d000000u;
        IIpsecDataPathPtr path = ipsec::MakeKernelDataPath(o, forced);
        REQUIRE(co_await path->start() == SBOX_OK);
        CHECK(std::string(path->kind()) == "kernel");

        SIpsecChildSa c;
        c.reqid = 0x5d000001u;
        c.local = ip("10.123.0.1");
        c.remote = ip("10.123.0.2");
        c.encr = EIKE_ENCR_AES_CBC;
        c.keyBits = 128;
        c.integ = EIKE_INTEG_HMAC_SHA2_256_128;
        c.inEncKey.assign(16, 1);
        c.outEncKey.assign(16, 2);
        c.inIntegKey.assign(32, 3);
        c.outIntegKey.assign(32, 4);
        c.outboundSpi = 0xc0ffee;
        c.localTs.push_back(SIkeTrafficSelector::fromPrefix(prefix("10.88.0.0/16")));
        SIkeTrafficSelector odd;
        odd.start = ip("10.77.0.1");
        odd.end = ip("10.77.0.6");
        c.remoteTs.push_back(odd);

        REQUIRE(co_await path->allocateSpi(c.local, c.remote, c.reqid, c.inboundSpi) == SBOX_OK);
        CHECK(c.inboundSpi >= 0x100);

        int32_t r = co_await path->installChild(c);
        if (!support.esp) {
            CHECK(r == -EPROTONOSUPPORT);
        }
        else {
            REQUIRE(r == SBOX_OK);
            std::vector<SXfrmPolicy> policies;
            REQUIRE(co_await x.listPolicies(policies) == SBOX_OK);
            // --> 10.77.0.1-10.77.0.6 is three prefixes; out/in/fwd for each.
            CHECK(policies.size() == 9);
        }

        co_await path->stop();
        std::vector<SXfrmSa> sas;
        REQUIRE(co_await x.listSas(sas) == SBOX_OK);
        CHECK(sas.empty());
        std::vector<SXfrmPolicy> policies;
        REQUIRE(co_await x.listPolicies(policies) == SBOX_OK);
        CHECK(policies.empty());
    }(ns));
}

TEST_CASE("Kernel-mode IKE sockets: bypass policies and UDP_ENCAP still deliver IKE messages") {
    if (!needRoot()) {
        return;
    }

    TempDir dir;
    std::string ns = dir.netns("encap");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    loop.run([](std::string netns) -> TTask<void> {
        net::CRtnl rtnl;
        REQUIRE(rtnl.open(netns) == SBOX_OK);
        REQUIRE(co_await rtnl.setUp(co_await rtnl.linkIndex("lo")) == SBOX_OK);

        CIkeSocket server;
        SIkeSocketOptions so;
        so.address = "127.0.0.1";
        so.port = 0;
        so.natPort = 0;
        so.netnsPath = netns;
        REQUIRE(server.open(so) == SBOX_OK);
        REQUIRE(server.enableKernelEncap() == SBOX_OK);

        std::vector<SIkeDatagram> got;
        server.start([&got](SIkeDatagram& dg) { got.push_back(std::move(dg)); });

        CIkeSocket client;
        REQUIRE(client.open(so) == SBOX_OK);
        client.start([](SIkeDatagram&) {});

        SEndpoint to;
        REQUIRE(SEndpoint::fromIp("127.0.0.1", server.natPort(), to) == SBOX_OK);
        std::vector<uint8_t> message(40, 0x2a);
        REQUIRE(client.send(BytesOf(message), SEndpoint(), to, true) == SBOX_OK);
        REQUIRE(client.sendKeepalive(SEndpoint(), to) == SBOX_OK);

        for (int32_t i = 0; i < 100 && got.empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        REQUIRE(got.size() == 1);
        CHECK(got[0].natT);
        CHECK(got[0].data == message);
        CHECK(got[0].local.toString() == "127.0.0.1:" + std::to_string(server.natPort()));
        client.close();
        server.close();
    }(ns));
}
