#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/allowedips.hpp>

#include <cstdlib>
#include <string>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    net::SIpPrefix pfx(const char* text) {
        net::SIpPrefix p;
        REQUIRE(net::SIpPrefix::parse(text, p) == SBOX_OK);
        return p;
    }

    net::SIpAddress ip(const char* text) {
        net::SIpAddress a;
        REQUIRE(net::SIpAddress::parse(text, a) == SBOX_OK);
        return a;
    }

}

TEST_CASE("allowed IPs: longest prefix match for IPv4") {
    CWgAllowedIps t;
    REQUIRE(t.insert(pfx("10.0.0.0/8"), 1) == SBOX_OK);
    REQUIRE(t.insert(pfx("10.1.0.0/16"), 2) == SBOX_OK);
    REQUIRE(t.insert(pfx("10.1.2.3/32"), 3) == SBOX_OK);
    REQUIRE(t.insert(pfx("0.0.0.0/0"), 4) == SBOX_OK);
    CHECK(t.size() == 4);

    CHECK(t.lookup(ip("10.2.3.4")) == 1);
    CHECK(t.lookup(ip("10.1.9.9")) == 2);
    CHECK(t.lookup(ip("10.1.2.3")) == 3);
    CHECK(t.lookup(ip("10.1.2.4")) == 2);
    CHECK(t.lookup(ip("192.0.2.1")) == 4);

    // --> Host bits are ignored on insert.
    REQUIRE(t.insert(pfx("172.16.5.5/12"), 5) == SBOX_OK);
    CHECK(t.lookup(ip("172.31.255.255")) == 5);
    CHECK(t.prefixes(5)[0].toString() == "172.16.0.0/12");

    CHECK(t.remove(pfx("10.1.0.0/16")));
    CHECK_FALSE(t.remove(pfx("10.1.0.0/16")));
    CHECK(t.lookup(ip("10.1.9.9")) == 1);
    CHECK(t.lookup(ip("10.1.2.3")) == 3);

    CHECK(t.insert(pfx("10.0.0.0/8"), 0) == -EINVAL);
}

TEST_CASE("allowed IPs: IPv6, ownership moves, removal by owner") {
    CWgAllowedIps t;
    REQUIRE(t.insert(pfx("fd00::/8"), 1) == SBOX_OK);
    REQUIRE(t.insert(pfx("fd00:1::/32"), 2) == SBOX_OK);
    REQUIRE(t.insert(pfx("fd00:1::5/128"), 2) == SBOX_OK);
    REQUIRE(t.insert(pfx("10.0.0.0/24"), 2) == SBOX_OK);

    CHECK(t.lookup(ip("fd00:1::5")) == 2);
    CHECK(t.lookup(ip("fd00:2::5")) == 1);
    CHECK(t.lookup(ip("fe80::1")) == 0);

    // --> A prefix has one owner: inserting moves it.
    REQUIRE(t.insert(pfx("fd00:1::/32"), 1) == SBOX_OK);
    CHECK(t.lookup(ip("fd00:1::7")) == 1);
    CHECK(t.size() == 4);

    std::vector<net::SIpPrefix> two = t.prefixes(2);
    REQUIRE(two.size() == 2);
    CHECK(two[0].toString() == "10.0.0.0/24");
    CHECK(two[1].toString() == "fd00:1::5/128");

    CHECK(t.removeValue(2) == 2);
    CHECK(t.lookup(ip("fd00:1::5")) == 1);
    CHECK(t.lookup(ip("10.0.0.1")) == 0);
    CHECK(t.size() == 2);

    t.clear();
    CHECK(t.size() == 0);
    CHECK(t.lookup(ip("fd00::1")) == 0);
}

TEST_CASE("allowed IPs: randomized comparison with a linear scan") {
    CWgAllowedIps t;
    struct Entry {
        uint32_t net;
        uint8_t len;
        uint64_t value;
    };
    std::vector<Entry> entries;

    std::srand(7);
    for (int i = 0; i < 400; ++i) {
        uint32_t a = uint32_t(std::rand()) ^ (uint32_t(std::rand()) << 16);
        uint8_t len = uint8_t(std::rand() % 33);
        uint32_t mask = len == 0 ? 0 : ~uint32_t(0) << (32 - len);
        a &= mask;
        uint64_t v = uint64_t(1 + std::rand() % 20);
        REQUIRE(t.insert(net::SIpPrefix(net::SIpAddress::fromV4(a), len), v) == SBOX_OK);

        bool replaced = false;
        for (Entry& e : entries) {
            if (e.net == a && e.len == len) {
                e.value = v;
                replaced = true;
            }
        }

        if (!replaced) {
            entries.push_back(Entry{ a, len, v });
        }
    }

    CHECK(t.size() == entries.size());

    for (int i = 0; i < 2000; ++i) {
        uint32_t a = uint32_t(std::rand()) ^ (uint32_t(std::rand()) << 16);
        int best = -1;
        uint64_t expect = 0;
        for (const Entry& e : entries) {
            uint32_t mask = e.len == 0 ? 0 : ~uint32_t(0) << (32 - e.len);
            if ((a & mask) == e.net && int(e.len) > best) {
                best = e.len;
                expect = e.value;
            }
        }

        CHECK(t.lookup(net::SIpAddress::fromV4(a)) == expect);
    }
}

TEST_CASE("replay window: fresh, duplicate, out of order, too old") {
    CWgReplayWindow w;
    CHECK(w.accept(0));
    CHECK_FALSE(w.accept(0));
    CHECK(w.accept(2));
    CHECK(w.accept(1));
    CHECK_FALSE(w.accept(1));

    // --> Jump ahead; counters inside the window stay acceptable once.
    CHECK(w.accept(5000));
    CHECK(w.accept(4000));
    CHECK_FALSE(w.accept(4000));
    CHECK(w.accept(5000 - 2047));

    // --> Far ahead: everything older than the window is refused.
    CHECK(w.accept(100000));
    CHECK_FALSE(w.accept(100000 - CWgReplayWindow::WINDOW - 1));
    CHECK(w.accept(100000 - CWgReplayWindow::WINDOW + 1));
    CHECK_FALSE(w.accept(5000));

    // --> The limit (REJECT_AFTER_MESSAGES) is enforced.
    CHECK_FALSE(w.accept(200, 100));
    CHECK_FALSE(w.accept(~uint64_t(0)));

    // --> Sequential run across many words with a reordered tail.
    w.reset();
    for (uint64_t i = 0; i < 20000; ++i) {
        REQUIRE(w.accept(i));
    }

    for (uint64_t i = 20000 - 100; i < 20000; ++i) {
        CHECK_FALSE(w.accept(i));
    }

    CHECK(w.accept(20100));
    CHECK(w.accept(20050));
    CHECK_FALSE(w.accept(20050));
}
