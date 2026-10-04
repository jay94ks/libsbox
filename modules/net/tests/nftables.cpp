#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/net/sysctl.hpp>
#include "testutil.hpp"
#include <cstring>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
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

    /* Returns the expression names of a NEWRULE message. */
    std::vector<std::string> exprNames(const CNlMessage& msg) {
        const std::vector<uint8_t>& b = msg.bytes();
        CNlAttrs attrs(b.data() + NLMSG_HDRLEN + 4, b.size() - NLMSG_HDRLEN - 4);
        std::vector<std::string> out;
        const SNlAttr* e = attrs.find(NFTA_RULE_EXPRESSIONS);
        if (!e) {
            return out;
        }

        CNlAttrs list = CNlAttrs::nested(*e);
        for (const SNlAttr& elem : list.items()) {
            out.push_back(CNlAttrs::nested(elem).str(NFTA_EXPR_NAME));
        }

        return out;
    }

    /* A one-shot TCP server living in a namespace. */
    struct SServer {
        CListener listener;
        std::string peer;
        std::string data;
        bool done = false;

        int32_t listen(const std::string& ns, const char* address, uint16_t port) {
            CNetnsScope scope(ns);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            SEndpoint ep;
            SEndpoint::fromIp(address, port, ep);
            return listener.listen(ep);
        }

        void start() {
            CEventLoop::current()->spawn([](SServer* self) -> TTask<void> {
                CSocket conn;
                if (co_await self->listener.accept(conn, 8000) == SBOX_OK) {
                    std::string p = conn.remoteEndpoint().toString();
                    self->peer = p.substr(0, p.rfind(':'));
                    std::vector<uint8_t> all;
                    co_await conn.recvAll(all, 1024, 3000);
                    self->data.assign(all.begin(), all.end());
                }

                self->done = true;
            }(this));
        }

        TTask<void> wait() {
            while (!done) {
                co_await CEventLoop::current()->sleepFor(2);
            }
        }
    };

    /* Connects a container namespace to a bridge in the host namespace. */
    TTask<int32_t> plug(CRtnl& host, int32_t bridge, const std::string& ctrNs, const std::string& veth,
        const char* address, const char* gateway)
    {
        CFd fd;
        int32_t r = CNetns::open(ctrNs, fd);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = co_await host.createVeth(veth, "eth0", fd.get());
        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t idx = co_await host.linkIndex(veth);
        co_await host.setMaster(idx, bridge);
        co_await host.setUp(idx);

        CRtnl ctr;
        ctr.open(ctrNs);
        int32_t eth = co_await ctr.linkIndex("eth0");
        co_await ctr.addAddress(eth, prefix(address));
        co_await ctr.setUp(eth);
        co_await ctr.setUp(1);
        co_return co_await ctr.addDefaultRoute(ip(gateway));
    }

}

TEST_CASE("ruleset batch has the expected structure") {
    SFirewallState state;
    SFirewallNetwork a;
    a.bridge = "br-a";
    a.subnets.push_back(prefix("172.18.0.0/16"));
    a.subnets.push_back(prefix("fd00:18::/64"));
    SFirewallNetwork b;
    b.bridge = "br-b";
    b.subnets.push_back(prefix("172.19.0.0/16"));
    b.icc = false;
    state.networks = { a, b };

    SFirewallPortMap pm;
    pm.bridge = "br-a";
    pm.protocol = IPPROTO_TCP;
    pm.hostPort = 8080;
    pm.containerIp = ip("172.18.0.2");
    pm.containerPort = 80;
    state.portMaps.push_back(pm);

    std::vector<CNlMessage> msgs = CFirewall::build(state, "sbox-test");

    // --> 3 table messages, 5 chains, 2 jump rules, 3 masquerade + 2 localhost rules,
    // 1 port map, 1 established, 1 icc drop, 2 isolation drops.
    REQUIRE(msgs.size() == 3 + 5 + 2 + 5 + 1 + 1 + 1 + 2);

    auto cmd = [](const CNlMessage& m) { return m.type() & 0xff; };
    CHECK((msgs[0].type() >> 8) == NFNL_SUBSYS_NFTABLES);
    CHECK(cmd(msgs[0]) == NFT_MSG_NEWTABLE);
    CHECK(cmd(msgs[1]) == NFT_MSG_DELTABLE);
    CHECK(cmd(msgs[2]) == NFT_MSG_NEWTABLE);
    CHECK(cmd(msgs[3]) == NFT_MSG_NEWCHAIN);

    for (const CNlMessage& m : msgs) {
        CHECK((m.flags() & NLM_F_ACK) != 0);
    }

    // --> The DNAT rule: nfproto, iifname !=, l4proto, dport, immediate x2, nat.
    bool sawDnat = false;
    for (const CNlMessage& m : msgs) {
        if (cmd(m) != NFT_MSG_NEWRULE) {
            continue;
        }

        std::vector<std::string> names = exprNames(m);
        if (!names.empty() && names.back() == "nat") {
            sawDnat = true;
            std::vector<std::string> expect = { "meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "cmp",
                "immediate", "immediate", "nat" };
            CHECK(names == expect);
        }
    }

    CHECK(sawDnat);

    std::vector<CNlMessage> rm = CFirewall::buildRemove("sbox-test");
    REQUIRE(rm.size() == 2);
    CHECK(cmd(rm[1]) == NFT_MSG_DELTABLE);
}

TEST_CASE("ruleset applies atomically and idempotently in a throwaway namespace") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string ns = dir.netns("fw");
    REQUIRE(!ns.empty());

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CFirewall fw;
        int32_t r = fw.open(ns);
        if (r == -ENOTSUP) {
            MESSAGE("skipped: nfnetlink unavailable");
            co_return;
        }

        REQUIRE(r == SBOX_OK);
        CHECK(co_await fw.exists() == 0);
        CHECK(co_await fw.remove() == SBOX_OK);

        SFirewallState state;
        SFirewallNetwork n;
        n.bridge = "br-x";
        n.subnets.push_back(prefix("10.88.0.0/16"));
        state.networks.push_back(n);

        SFirewallPortMap pm;
        pm.bridge = "br-x";
        pm.protocol = IPPROTO_UDP;
        pm.hostIp = ip("192.0.2.10");
        pm.hostPort = 5353;
        pm.containerIp = ip("10.88.0.5");
        pm.containerPort = 53;
        state.portMaps.push_back(pm);

        r = co_await fw.apply(state);
        if (r == -ENOTSUP) {
            MESSAGE("skipped: nf_tables unavailable: " << fw.lastError());
            co_return;
        }

        REQUIRE_MESSAGE(r == SBOX_OK, fw.lastError());
        CHECK(co_await fw.exists() == 1);

        std::vector<SNftRuleInfo> rules;
        CHECK(co_await fw.listRules(rules) == SBOX_OK);
        size_t first = rules.size();
        CHECK(first == 6);

        size_t portmaps = 0;
        for (const SNftRuleInfo& info : rules) {
            portmaps += info.chain == "portmap" ? 1 : 0;
        }

        CHECK(portmaps == 1);

        // --> Applying again replaces instead of appending.
        CHECK(co_await fw.apply(state) == SBOX_OK);
        CHECK(co_await fw.listRules(rules) == SBOX_OK);
        CHECK(rules.size() == first);

        // --> A failing batch (jump to a missing chain) leaves the previous ruleset intact.
        std::vector<CNlMessage> broken = CFirewall::build(state, fw.table());
        CNftRule bad;
        bad.verdict(ENFV_JUMP, "no-such-chain");
        CNlMessage extra(uint16_t((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE), NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
        nfgenmsg g{};
        g.nfgen_family = NFPROTO_INET;
        extra.putHeader(&g, sizeof(g));
        extra.putString(NFTA_RULE_TABLE, fw.table());
        extra.putString(NFTA_RULE_CHAIN, "forward");
        std::vector<uint8_t> e = bad.expressions();
        extra.put(uint16_t(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED), e.data(), e.size());
        broken.push_back(std::move(extra));

        CHECK(co_await fw.send(std::move(broken)) < 0);
        CHECK(co_await fw.listRules(rules) == SBOX_OK);
        CHECK(rules.size() == first);

        CHECK(co_await fw.remove() == SBOX_OK);
        CHECK(co_await fw.exists() == 0);
        CHECK(co_await fw.remove() == SBOX_OK);
    };

    loop.run(body());
}

TEST_CASE("port mapping, masquerade and isolation work end to end") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string c1 = dir.netns("c1");
    std::string c2 = dir.netns("c2");
    std::string outside = dir.netns("outside");
    REQUIRE(!outside.empty());

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CFirewall fw;
        if (fw.open(host) != SBOX_OK) {
            MESSAGE("skipped: nfnetlink unavailable");
            co_return;
        }

        CRtnl rt;
        REQUIRE(rt.open(host) == SBOX_OK);
        REQUIRE(co_await rt.createBridge("br-one") == SBOX_OK);
        REQUIRE(co_await rt.createBridge("br-two") == SBOX_OK);
        int32_t b1 = co_await rt.linkIndex("br-one");
        int32_t b2 = co_await rt.linkIndex("br-two");
        co_await rt.addAddress(b1, prefix("10.31.0.1/24"));
        co_await rt.addAddress(b2, prefix("10.32.0.1/24"));
        co_await rt.setUp(b1);
        co_await rt.setUp(b2);
        co_await rt.setUp(1);

        REQUIRE(co_await plug(rt, b1, c1, "vc1", "10.31.0.2/24", "10.31.0.1") == SBOX_OK);
        REQUIRE(co_await plug(rt, b2, c2, "vc2", "10.32.0.2/24", "10.32.0.1") == SBOX_OK);

        // --> "outside" is a network beyond the host's uplink.
        CFd outFd;
        CNetns::open(outside, outFd);
        REQUIRE(co_await rt.createVeth("uplink", "eth0", outFd.get()) == SBOX_OK);
        int32_t up = co_await rt.linkIndex("uplink");
        co_await rt.addAddress(up, prefix("10.33.0.1/24"));
        co_await rt.setUp(up);
        CRtnl out;
        out.open(outside);
        int32_t oe = co_await out.linkIndex("eth0");
        co_await out.addAddress(oe, prefix("10.33.0.2/24"));
        co_await out.setUp(oe);
        co_await out.setUp(1);

        REQUIRE(SetIpForward(true, host) == SBOX_OK);
        REQUIRE(SetRouteLocalnet("br-one", true, host) == SBOX_OK);

        SFirewallState state;
        SFirewallNetwork n1;
        n1.bridge = "br-one";
        n1.subnets.push_back(prefix("10.31.0.0/24"));
        SFirewallNetwork n2;
        n2.bridge = "br-two";
        n2.subnets.push_back(prefix("10.32.0.0/24"));
        state.networks = { n1, n2 };

        SFirewallPortMap pm;
        pm.bridge = "br-one";
        pm.protocol = IPPROTO_TCP;
        pm.hostPort = 18080;
        pm.containerIp = ip("10.31.0.2");
        pm.containerPort = 8080;
        state.portMaps.push_back(pm);

        int32_t r = co_await fw.apply(state);
        if (r == -ENOTSUP) {
            MESSAGE("skipped: nf_tables unavailable");
            co_return;
        }

        REQUIRE_MESSAGE(r == SBOX_OK, fw.lastError());

        // 1. outside -> host:18080 is DNATed into c1:8080 (prerouting).
        {
            SServer srv;
            REQUIRE(srv.listen(c1, "10.31.0.2", 8080) == SBOX_OK);
            srv.start();
            int32_t c = co_await CNetns::run(outside, []() {
                return nettest::blockingConnect("10.33.0.1", 18080, "from-outside");
            });
            CHECK(c == 0);
            co_await srv.wait();
            CHECK(srv.data == "from-outside");
            CHECK(srv.peer == "10.33.0.2");
        }

        // 2. host loopback -> 127.0.0.1:18080 (output chain + 127/8 masquerade).
        {
            SServer srv;
            REQUIRE(srv.listen(c1, "10.31.0.2", 8080) == SBOX_OK);
            srv.start();
            int32_t c = co_await CNetns::run(host, []() {
                return nettest::blockingConnect("127.0.0.1", 18080, "from-loopback");
            });
            CHECK(c == 0);
            co_await srv.wait();
            CHECK(srv.data == "from-loopback");
            CHECK(srv.peer == "10.31.0.1");
        }

        // 3. c2 -> outside is masqueraded behind the uplink address.
        {
            SServer srv;
            REQUIRE(srv.listen(outside, "10.33.0.2", 9090) == SBOX_OK);
            srv.start();
            int32_t c = co_await CNetns::run(c2, []() {
                return nettest::blockingConnect("10.33.0.2", 9090, "masq");
            });
            CHECK(c == 0);
            co_await srv.wait();
            CHECK(srv.data == "masq");
            CHECK(srv.peer == "10.33.0.1");
        }

        // 4. c2 -> c1 is dropped by the isolation rules.
        {
            SServer srv;
            REQUIRE(srv.listen(c1, "10.31.0.2", 8081) == SBOX_OK);
            int32_t c = co_await CNetns::run(c2, []() {
                return nettest::blockingConnect("10.31.0.2", 8081, "blocked", 1);
            });
            CHECK(c < 0);
        }

        CHECK(co_await fw.remove() == SBOX_OK);
    };

    loop.run(body());
}
