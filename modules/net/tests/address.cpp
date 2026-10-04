#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/net/address.hpp>

using namespace sbox;
using namespace sbox::net;

TEST_CASE("IPv4 and IPv6 addresses parse and format") {
    SIpAddress a;
    REQUIRE(SIpAddress::parse("172.17.0.1", a) == SBOX_OK);
    CHECK(a.isV4());
    CHECK(a.v4() == 0xac110001u);
    CHECK(a.toString() == "172.17.0.1");

    SIpAddress b;
    REQUIRE(SIpAddress::parse("fd00:0:0:0::1", b) == SBOX_OK);
    CHECK(b.isV6());
    CHECK(b.toString() == "fd00::1");

    CHECK(SIpAddress::parse("1.2.3", a) == -EINVAL);
    CHECK(SIpAddress::parse("", a) == -EINVAL);
    CHECK(SIpAddress::parse("10.0.0.1/24", a) == -EINVAL);
}

TEST_CASE("address arithmetic carries across bytes") {
    SIpAddress a;
    REQUIRE(SIpAddress::parse("10.0.0.255", a) == SBOX_OK);
    CHECK(a.add(1).toString() == "10.0.1.0");
    CHECK(a.add(257).toString() == "10.0.2.0");

    SIpAddress base;
    REQUIRE(SIpAddress::parse("10.0.0.0", base) == SBOX_OK);
    CHECK(a.distanceFrom(base) == 255);
    CHECK(base.distanceFrom(a) == UINT64_MAX);

    SIpAddress v6;
    REQUIRE(SIpAddress::parse("fd00::ffff:ffff", v6) == SBOX_OK);
    CHECK(v6.add(1).toString() == "fd00::1:0:0");
}

TEST_CASE("prefixes compute networks, containment and overlap") {
    SIpPrefix p;
    REQUIRE(SIpPrefix::parse("172.18.5.7/16", p) == SBOX_OK);
    CHECK(p.length == 16);
    CHECK(p.network().toString() == "172.18.0.0/16");
    CHECK_FALSE(p.isNetwork());
    CHECK(p.last().toString() == "172.18.255.255");
    CHECK(p.mask().toString() == "255.255.0.0");
    CHECK(p.size() == 65536);
    CHECK(p.at(2).toString() == "172.18.0.2");

    SIpAddress inside, outside;
    SIpAddress::parse("172.18.200.1", inside);
    SIpAddress::parse("172.19.0.1", outside);
    CHECK(p.contains(inside));
    CHECK_FALSE(p.contains(outside));

    SIpPrefix q, r;
    SIpPrefix::parse("172.18.3.0/24", q);
    SIpPrefix::parse("172.19.0.0/16", r);
    CHECK(p.overlaps(q));
    CHECK(q.overlaps(p));
    CHECK_FALSE(p.overlaps(r));

    SIpPrefix host;
    REQUIRE(SIpPrefix::parse("10.1.2.3", host) == SBOX_OK);
    CHECK(host.length == 32);

    SIpPrefix v6;
    REQUIRE(SIpPrefix::parse("fd12:3456::/64", v6) == SBOX_OK);
    CHECK(v6.size() == UINT64_MAX);
    CHECK(v6.at(1).toString() == "fd12:3456::1");

    CHECK(SIpPrefix::parse("10.0.0.0/33", p) == -EINVAL);
    CHECK(SIpPrefix::parse("10.0.0.0/x", p) == -EINVAL);
}

TEST_CASE("MAC addresses parse, format and derive from IPv4") {
    SMacAddress m;
    REQUIRE(SMacAddress::parse("02:42:AC:11:00:02", m) == SBOX_OK);
    CHECK(m.toString() == "02:42:ac:11:00:02");
    CHECK(SMacAddress::parse("02:42:ac:11:00", m) == -EINVAL);

    SIpAddress a;
    SIpAddress::parse("172.17.0.2", a);
    CHECK(SMacAddress::fromIpv4(a).toString() == "02:42:ac:11:00:02");

    SMacAddress r = SMacAddress::random();
    CHECK(r.isValid());
    CHECK((r.bytes[0] & 1) == 0);
    CHECK((r.bytes[0] & 2) == 2);

    CHECK(RandomHex(12).size() == 12);
}
