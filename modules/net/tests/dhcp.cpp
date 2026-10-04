#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/dhcp.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include "testutil.hpp"
#include "dhcpserver.hpp"
#include <cstring>
#include <net/if.h>
#include <sys/socket.h>

using namespace sbox;
using namespace sbox::net;

namespace {

    SIpAddress ip(const char* text) {
        SIpAddress a;
        SIpAddress::parse(text, a);
        return a;
    }

}

TEST_CASE("DHCP messages encode and decode") {
    SDhcpMessage m;
    m.op = 1;
    m.xid = 0x12345678;
    m.flags = 0x8000;
    SMacAddress::parse("02:00:00:aa:bb:cc", m.chaddr);
    m.type(EDHCP_REQUEST);
    m.setAddress(50, ip("192.168.1.20"));
    m.setU32(51, 7200);
    std::string longHost(300, 'h');
    m.setOption(12, longHost.data(), longHost.size());

    std::vector<uint8_t> bytes = m.encode();
    CHECK(bytes.size() >= 300);
    CHECK(bytes[236] == 0x63);
    CHECK(bytes[240] == 53);    // --> Message type is the first option.

    SDhcpMessage d;
    REQUIRE(SDhcpMessage::decode(bytes.data(), bytes.size(), d) == SBOX_OK);
    CHECK(d.xid == 0x12345678);
    CHECK(d.flags == 0x8000);
    CHECK(d.chaddr == m.chaddr);
    CHECK(d.type() == EDHCP_REQUEST);
    CHECK(d.address(50).toString() == "192.168.1.20");
    CHECK(d.u32(51) == 7200);
    CHECK(d.text(12) == longHost);     // --> Split into two option instances and concatenated.

    CHECK(SDhcpMessage::decode(bytes.data(), 100, d) == -EBADMSG);
    bytes[236] = 0;
    CHECK(SDhcpMessage::decode(bytes.data(), bytes.size(), d) == -EBADMSG);

    SDhcpLease lease;
    lease.address = ip("10.0.0.5");
    lease.prefixLength = 16;
    lease.dns.push_back(ip("1.1.1.1"));
    lease.leaseTime = 100;
    SDhcpLease back;
    REQUIRE(SDhcpLease::fromJson(lease.toJson(), back) == SBOX_OK);
    CHECK(back.prefix().toString() == "10.0.0.5/16");
    CHECK(back.dns.size() == 1);
    CHECK(back.leaseTime == 100);
}

TEST_CASE("DHCP client acquires, renews and releases against a test server over a veth pair") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string srvNs = dir.netns("srv");
    std::string cliNs = dir.netns("cli");
    REQUIRE(!cliNs.empty());

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CRtnl srv, cli;
        REQUIRE(srv.open(srvNs) == SBOX_OK);
        REQUIRE(cli.open(cliNs) == SBOX_OK);

        CFd cliFd;
        CNetns::open(cliNs, cliFd);
        REQUIRE(co_await srv.createVeth("srv0", "cli0", cliFd.get()) == SBOX_OK);
        int32_t s = co_await srv.linkIndex("srv0");
        SIpPrefix sp;
        SIpPrefix::parse("10.123.0.1/24", sp);
        co_await srv.addAddress(s, sp);
        co_await srv.setUp(s);

        int32_t c = co_await cli.linkIndex("cli0");
        co_await cli.setUp(c);

        nettest::SMiniServer server;
        REQUIRE(server.open(srvNs, "srv0") == SBOX_OK);
        server.naksLeft = 1;

        bool served = false;
        CEventLoop::current()->spawn([](nettest::SMiniServer* sv, bool* flag) -> TTask<void> {
            co_await sv->serve();
            *flag = true;
        }(&server, &served));

        CDhcpClient client;
        REQUIRE(client.open("cli0", cliNs) == SBOX_OK);
        client.hostname("sbox-test");

        SDhcpLease lease;
        int32_t r = co_await client.acquire(lease, 15000);
        REQUIRE(r == SBOX_OK);
        CHECK(lease.address.toString() == "10.123.0.50");
        CHECK(lease.prefixLength == 24);
        CHECK(lease.router.toString() == "10.123.0.1");
        CHECK(lease.server.toString() == "10.123.0.1");
        REQUIRE(lease.dns.size() == 2);
        CHECK(lease.dns[1].toString() == "9.9.9.9");
        CHECK(lease.domain == "example.test");
        CHECK(lease.leaseTime == 600);
        CHECK(lease.renewTime == 300);
        CHECK(lease.rebindTime == 525);
        CHECK(lease.serverMac.isValid());

        // --> The first REQUEST was NAKed, so discovery ran twice.
        CHECK(server.discovers >= 2);

        // --> Configure the lease, then renew by unicast.
        CHECK(co_await cli.addAddress(c, lease.prefix()) == SBOX_OK);
        lease.leaseTime = 1;
        CHECK(co_await client.renew(lease, 5000) == SBOX_OK);
        CHECK(lease.leaseTime == 600);
        CHECK(server.renewals == 1);

        CHECK(co_await client.rebind(lease, 5000) == SBOX_OK);
        CHECK(server.renewals == 2);

        CHECK(client.release(lease) == SBOX_OK);
        for (int32_t i = 0; i < 100 && server.releases == 0; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.releases == 1);

        server.stop = true;
        while (!served) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        client.close();
    };

    loop.run(body());
}

TEST_CASE("DHCP client times out without a server") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string ns = dir.netns("lonely");

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CRtnl rt;
        rt.open(ns);
        REQUIRE(co_await rt.createVeth("a0", "b0") == SBOX_OK);
        co_await rt.setUp(co_await rt.linkIndex("a0"));
        co_await rt.setUp(co_await rt.linkIndex("b0"));

        CDhcpClient client;
        REQUIRE(client.open("a0", ns) == SBOX_OK);
        SDhcpLease lease;
        CHECK(co_await client.acquire(lease, 300) == -ETIMEDOUT);
        CHECK(client.open("nosuch0", ns) == -ENODEV);
    };

    loop.run(body());
}
