#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/net/netlink.hpp>
#include <sbox/net/rtnl.hpp>
#include "testutil.hpp"
#include <cstring>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

using namespace sbox;
using namespace sbox::net;

TEST_CASE("message builder encodes aligned and nested attributes") {
    CNlMessage msg(RTM_NEWLINK, NLM_F_CREATE);
    ifinfomsg ifi;
    std::memset(&ifi, 0, sizeof(ifi));
    ifi.ifi_index = 7;
    msg.putHeader(&ifi, sizeof(ifi));

    msg.putString(IFLA_IFNAME, "br0");          // 4 + 4 -> 8 bytes
    msg.putU32(IFLA_MTU, 1400);                  // 8 bytes
    size_t nest = msg.beginNested(IFLA_LINKINFO);
    msg.putString(IFLA_INFO_KIND, "bridge");     // 4 + 7 -> 12 bytes
    msg.endNested(nest);
    msg.putU8(IFLA_OPERSTATE, 6);                // 5 -> 8 bytes

    const std::vector<uint8_t>& b = msg.bytes();
    REQUIRE(b.size() == 16 + 16 + 8 + 8 + 4 + 12 + 8);

    nlmsghdr h;
    std::memcpy(&h, b.data(), sizeof(h));
    CHECK(h.nlmsg_len == b.size());
    CHECK(h.nlmsg_type == RTM_NEWLINK);
    CHECK(h.nlmsg_flags == NLM_F_CREATE);

    // --> Parse back what was written.
    CNlAttrs attrs(b.data() + 32, b.size() - 32);
    REQUIRE(attrs.items().size() == 4);
    CHECK(attrs.str(IFLA_IFNAME) == "br0");
    CHECK(attrs.u32(IFLA_MTU) == 1400);

    const SNlAttr* info = attrs.find(IFLA_LINKINFO);
    REQUIRE(info != nullptr);
    CHECK(info->length == 12);
    CHECK(CNlAttrs::nested(*info).str(IFLA_INFO_KIND) == "bridge");

    // --> The nested flag is set on the wire but stripped by the parser.
    nlattr raw;
    std::memcpy(&raw, b.data() + 48, sizeof(raw));
    CHECK((raw.nla_type & NLA_F_NESTED) != 0);
    CHECK(raw.nla_len == 16);

    const SNlAttr* oper = attrs.find(IFLA_OPERSTATE);
    REQUIRE(oper != nullptr);
    CHECK(oper->u8() == 6);
}

TEST_CASE("big-endian helpers and truncated input") {
    CNlMessage msg(1, 0);
    msg.putBe16(1, 0x1234);
    msg.putBe32(2, 0xdeadbeef);
    msg.putBe64(3, 0x0102030405060708ull);

    const std::vector<uint8_t>& b = msg.bytes();
    CNlAttrs attrs(b.data() + 16, b.size() - 16);
    CHECK(attrs.find(1)->be16() == 0x1234);
    CHECK(attrs.find(2)->be32() == 0xdeadbeef);
    CHECK(attrs.find(3)->data[0] == 1);
    CHECK(attrs.find(3)->data[7] == 8);

    // --> A cut-off attribute stream yields what parsed cleanly.
    CNlAttrs cut(b.data() + 16, 10);
    CHECK(cut.items().size() == 1);
}

TEST_CASE("generic netlink resolves the nlctrl family") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CNetlinkSocket s;
        REQUIRE(s.open(NETLINK_GENERIC) == SBOX_OK);

        SGenlFamily family;
        CHECK(co_await ResolveGenlFamily(s, "nlctrl", family) == SBOX_OK);
        CHECK(family.id == GENL_ID_CTRL);

        SGenlFamily missing;
        int32_t r = co_await ResolveGenlFamily(s, "no-such-family-x", missing);
        CHECK(r == -ENOENT);
    };

    loop.run(body());
}

TEST_CASE("rtnetlink reports errors with extended ACK and serializes concurrent requests") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CRtnl rt;
        REQUIRE(rt.open() == SBOX_OK);

        SLinkInfo lo;
        CHECK(co_await rt.getLink("lo", lo) == SBOX_OK);
        CHECK(lo.index == 1);

        SLinkInfo none;
        int32_t r = co_await rt.getLink("nosuchdev0", none);
        CHECK(r == -ENODEV);

        // --> Several tasks share the socket at once.
        int32_t done = 0;
        for (int32_t i = 0; i < 5; ++i) {
            CEventLoop::current()->spawn([](CRtnl* rtnl, int32_t* counter) -> TTask<void> {
                std::vector<SLinkInfo> links;
                CHECK(co_await rtnl->listLinks(links) == SBOX_OK);
                CHECK(!links.empty());
                ++*counter;
            }(&rt, &done));
        }

        while (done < 5) {
            co_await CEventLoop::current()->sleepFor(1);
        }
    };

    loop.run(body());
}
