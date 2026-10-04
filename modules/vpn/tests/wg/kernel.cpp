#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/kernel.hpp>
#include <sbox/vpn/wg/uapi.hpp>

#include <linux/netlink.h>
#include <netinet/in.h>
#include <cstring>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    constexpr uint16_t FAMILY = 0x1b;

    net::SIpPrefix pfx(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    SWgKey newKey() {
        SWgKey k;
        GenerateWgPrivateKey(k);
        return k;
    }

    /* Returns the attributes after nlmsghdr + genlmsghdr. */
    net::CNlAttrs attrsOf(const net::CNlMessage& m) {
        const std::vector<uint8_t>& b = m.bytes();
        return net::CNlAttrs(b.data() + NLMSG_HDRLEN + 4, b.size() - NLMSG_HDRLEN - 4);
    }

    /* Converts a built message into what CNetlinkSocket hands back. */
    net::SNlReply replyOf(const net::CNlMessage& m) {
        net::SNlReply r;
        r.type = m.type();
        r.flags = 0;
        r.payload.assign(m.bytes().begin() + NLMSG_HDRLEN, m.bytes().end());
        return r;
    }

    /* Counts the peers of a SET_DEVICE message. */
    size_t peerCount(const net::CNlMessage& m) {
        const net::SNlAttr* peers = attrsOf(m).find(EWGDA_PEERS);
        return peers ? net::CNlAttrs::nested(*peers).items().size() : 0;
    }

}

TEST_CASE("kernel: SET_DEVICE encoding") {
    SWgKey priv = newKey();
    SWgKey peer = newKey();
    SWgKey psk = newKey();
    SWgKey gone = newKey();

    SWgDeviceConfig c;
    c.privateKey = priv;
    c.listenPort = 51820;
    c.fwmark = 0x51;
    c.replacePeers = true;

    SWgPeerConfig p;
    p.publicKey = peer;
    p.presharedKey = psk;
    SEndpoint::fromIp("192.0.2.7", 4500, p.endpoint);
    p.allowedIps = { pfx("10.1.0.0/16"), pfx("fd00:1::5/64") };
    p.persistentKeepalive = 25;
    c.peers.push_back(p);

    SWgPeerConfig r;
    r.publicKey = gone;
    r.remove = true;
    c.peers.push_back(r);

    std::vector<net::CNlMessage> msgs = BuildWgSetDevice(FAMILY, "wg7", c);
    REQUIRE(msgs.size() == 1);
    const net::CNlMessage& m = msgs[0];
    CHECK(m.type() == FAMILY);
    CHECK(m.bytes()[NLMSG_HDRLEN] == EWGC_SET_DEVICE);
    CHECK(m.bytes()[NLMSG_HDRLEN + 1] == WG_GENL_VERSION);

    net::CNlAttrs a = attrsOf(m);
    CHECK(a.str(EWGDA_IFNAME) == "wg7");
    REQUIRE(a.find(EWGDA_PRIVATE_KEY));
    CHECK(std::memcmp(a.find(EWGDA_PRIVATE_KEY)->data, priv.bytes, 32) == 0);
    CHECK(a.find(EWGDA_LISTEN_PORT)->u16() == 51820);
    CHECK(a.u32(EWGDA_FWMARK) == 0x51);
    CHECK(a.u32(EWGDA_FLAGS) == EWGDF_REPLACE_PEERS);

    const net::SNlAttr* peersAttr = a.find(EWGDA_PEERS);
    REQUIRE(peersAttr);
    // --> Nested attributes carry NLA_F_NESTED on the wire.
    uint16_t rawType = 0;
    std::memcpy(&rawType, peersAttr->data - 2, 2);
    CHECK((rawType & NLA_F_NESTED) != 0);

    net::CNlAttrs peers = net::CNlAttrs::nested(*peersAttr);
    REQUIRE(peers.items().size() == 2);

    net::CNlAttrs p0 = net::CNlAttrs::nested(peers.items()[0]);
    CHECK(std::memcmp(p0.find(EWGPA_PUBLIC_KEY)->data, peer.bytes, 32) == 0);
    CHECK(std::memcmp(p0.find(EWGPA_PRESHARED_KEY)->data, psk.bytes, 32) == 0);
    CHECK(p0.u32(EWGPA_FLAGS) == EWGPF_REPLACE_ALLOWEDIPS);
    CHECK(p0.find(EWGPA_PERSISTENT_KEEPALIVE_INTERVAL)->u16() == 25);
    const net::SNlAttr* ep = p0.find(EWGPA_ENDPOINT);
    REQUIRE(ep);
    REQUIRE(ep->length == sizeof(sockaddr_in));
    const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(ep->data);
    CHECK(sin->sin_family == AF_INET);
    CHECK(ntohs(sin->sin_port) == 4500);

    net::CNlAttrs ips = net::CNlAttrs::nested(*p0.find(EWGPA_ALLOWEDIPS));
    REQUIRE(ips.items().size() == 2);
    net::CNlAttrs ip0 = net::CNlAttrs::nested(ips.items()[0]);
    CHECK(ip0.find(EWGAA_FAMILY)->u16() == AF_INET);
    CHECK(ip0.find(EWGAA_IPADDR)->address().toString() == "10.1.0.0");
    CHECK(ip0.find(EWGAA_CIDR_MASK)->u8() == 16);
    net::CNlAttrs ip1 = net::CNlAttrs::nested(ips.items()[1]);
    CHECK(ip1.find(EWGAA_FAMILY)->u16() == AF_INET6);
    CHECK(ip1.find(EWGAA_IPADDR)->address().toString() == "fd00:1::");
    CHECK(ip1.find(EWGAA_CIDR_MASK)->u8() == 64);

    net::CNlAttrs p1 = net::CNlAttrs::nested(peers.items()[1]);
    CHECK(p1.u32(EWGPA_FLAGS) == EWGPF_REMOVE_ME);
    CHECK(p1.find(EWGPA_ALLOWEDIPS) == nullptr);

    // --> Unset fields are not sent.
    SWgDeviceConfig empty;
    std::vector<net::CNlMessage> e = BuildWgSetDevice(FAMILY, "wg7", empty);
    REQUIRE(e.size() == 1);
    net::CNlAttrs ea = attrsOf(e[0]);
    CHECK(ea.find(EWGDA_PRIVATE_KEY) == nullptr);
    CHECK(ea.find(EWGDA_LISTEN_PORT) == nullptr);
    CHECK(ea.find(EWGDA_FWMARK) == nullptr);
    CHECK(ea.find(EWGDA_FLAGS) == nullptr);
    CHECK(ea.find(EWGDA_PEERS) == nullptr);
}

TEST_CASE("kernel: large changes are split across messages") {
    SWgDeviceConfig c;
    c.privateKey = newKey();
    c.replacePeers = true;
    for (int i = 0; i < 300; ++i) {
        SWgPeerConfig p;
        p.publicKey = newKey();
        p.allowedIps = { pfx(("10.2." + std::to_string(i % 250) + ".0/24").c_str()) };
        c.peers.push_back(p);
    }

    SWgPeerConfig big;
    big.publicKey = newKey();
    for (int i = 0; i < 500; ++i) {
        big.allowedIps.push_back(pfx(("10.3." + std::to_string(i / 250) + "." + std::to_string(i % 250) + "/32").c_str()));
    }

    c.peers.push_back(big);

    std::vector<net::CNlMessage> msgs = BuildWgSetDevice(FAMILY, "wg7", c, 4096);
    REQUIRE(msgs.size() > 3);

    size_t peers = 0;
    size_t bigIps = 0;
    size_t bigParts = 0;
    for (size_t i = 0; i < msgs.size(); ++i) {
        CHECK(msgs[i].size() <= 4096);
        net::CNlAttrs a = attrsOf(msgs[i]);
        CHECK(a.str(EWGDA_IFNAME) == "wg7");
        // --> Only the first message carries device attributes (REPLACE_PEERS must not repeat).
        CHECK((a.find(EWGDA_PRIVATE_KEY) != nullptr) == (i == 0));
        CHECK((a.find(EWGDA_FLAGS) != nullptr) == (i == 0));

        const net::SNlAttr* list = a.find(EWGDA_PEERS);
        REQUIRE(list);
        net::CNlAttrs items = net::CNlAttrs::nested(*list);
        for (const net::SNlAttr& item : items.items()) {
            net::CNlAttrs pa = net::CNlAttrs::nested(item);
            if (std::memcmp(pa.find(EWGPA_PUBLIC_KEY)->data, big.publicKey.bytes, 32) == 0) {
                ++bigParts;
                uint32_t flags = pa.u32(EWGPA_FLAGS);
                CHECK(flags == (bigParts == 1 ? uint32_t(EWGPF_REPLACE_ALLOWEDIPS) : uint32_t(EWGPF_UPDATE_ONLY)));
                bigIps += net::CNlAttrs::nested(*pa.find(EWGPA_ALLOWEDIPS)).items().size();
            }
            else {
                ++peers;
            }
        }
    }

    CHECK(peers == 300);
    CHECK(bigParts > 1);
    CHECK(bigIps == 500);
    CHECK(peerCount(msgs[0]) > 0);
}

TEST_CASE("kernel: GET_DEVICE request and multi-part reply decoding") {
    net::CNlMessage get = BuildWgGetDevice(FAMILY, "wg7");
    CHECK(get.bytes()[NLMSG_HDRLEN] == EWGC_GET_DEVICE);
    CHECK(attrsOf(get).str(EWGDA_IFNAME) == "wg7");

    SWgKey priv = newKey(), pub, peer = newKey(), psk = newKey();
    DeriveWgPublicKey(priv, pub);

    // --> First part: device attributes and the start of the peer.
    net::CNlMessage m1 = net::CNlMessage::genl(FAMILY, EWGC_GET_DEVICE, 1, 0);
    m1.putU32(EWGDA_IFINDEX, 7);
    m1.putString(EWGDA_IFNAME, "wg7");
    m1.put(EWGDA_PRIVATE_KEY, priv.bytes, 32);
    m1.put(EWGDA_PUBLIC_KEY, pub.bytes, 32);
    m1.putU16(EWGDA_LISTEN_PORT, 51820);
    m1.putU32(EWGDA_FWMARK, 9);
    size_t list = m1.beginNested(EWGDA_PEERS);
    size_t pe = m1.beginNested(0);
    m1.put(EWGPA_PUBLIC_KEY, peer.bytes, 32);
    m1.put(EWGPA_PRESHARED_KEY, psk.bytes, 32);
    sockaddr_in sin;
    std::memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = htonl(0xc0000201);
    m1.put(EWGPA_ENDPOINT, &sin, sizeof(sin));
    int64_t ts[2] = { 1700000000, 42 };
    m1.put(EWGPA_LAST_HANDSHAKE_TIME, ts, sizeof(ts));
    m1.putU64(EWGPA_RX_BYTES, 1000);
    m1.putU64(EWGPA_TX_BYTES, 2000);
    m1.putU16(EWGPA_PERSISTENT_KEEPALIVE_INTERVAL, 25);
    m1.putU32(EWGPA_PROTOCOL_VERSION, 1);
    size_t ips = m1.beginNested(EWGPA_ALLOWEDIPS);
    size_t ip = m1.beginNested(0);
    m1.putU16(EWGAA_FAMILY, AF_INET);
    net::SIpAddress a;
    net::SIpAddress::parse("10.5.0.0", a);
    m1.putAddress(EWGAA_IPADDR, a);
    m1.putU8(EWGAA_CIDR_MASK, 16);
    m1.endNested(ip);
    m1.endNested(ips);
    m1.endNested(pe);
    m1.endNested(list);

    // --> Second part: the same peer continues with one more allowed IP.
    net::CNlMessage m2 = net::CNlMessage::genl(FAMILY, EWGC_GET_DEVICE, 1, 0);
    m2.putString(EWGDA_IFNAME, "wg7");
    list = m2.beginNested(EWGDA_PEERS);
    pe = m2.beginNested(0);
    m2.put(EWGPA_PUBLIC_KEY, peer.bytes, 32);
    ips = m2.beginNested(EWGPA_ALLOWEDIPS);
    ip = m2.beginNested(0);
    m2.putU16(EWGAA_FAMILY, AF_INET);
    net::SIpAddress::parse("10.6.0.1", a);
    m2.putAddress(EWGAA_IPADDR, a);
    m2.putU8(EWGAA_CIDR_MASK, 32);
    m2.endNested(ip);
    m2.endNested(ips);
    m2.endNested(pe);
    m2.endNested(list);

    SWgDeviceStatus st;
    REQUIRE(ParseWgGetDevice({ replyOf(m1), replyOf(m2) }, st) == SBOX_OK);
    CHECK(st.kernel);
    CHECK(st.ifIndex == 7);
    CHECK(st.name == "wg7");
    CHECK(st.privateKey == priv);
    CHECK(st.publicKey == pub);
    CHECK(st.listenPort == 51820);
    CHECK(st.fwmark == 9);
    REQUIRE(st.peers.size() == 1);
    const SWgPeerStatus& p = st.peers[0];
    CHECK(p.publicKey == peer);
    CHECK(p.hasPresharedKey);
    CHECK(p.presharedKey == psk);
    CHECK(p.endpoint.toString() == "192.0.2.1:1234");
    CHECK(p.lastHandshakeSec == 1700000000);
    CHECK(p.lastHandshakeNsec == 42);
    CHECK(p.rxBytes == 1000);
    CHECK(p.txBytes == 2000);
    CHECK(p.persistentKeepalive == 25);
    REQUIRE(p.allowedIps.size() == 2);
    CHECK(p.allowedIps[1].toString() == "10.6.0.1/32");

    CHECK(ParseWgGetDevice({}, st) == -EBADMSG);
}

TEST_CASE("uapi: get and set texts round-trip") {
    SWgDeviceStatus s;
    s.privateKey = newKey();
    s.listenPort = 51820;
    s.fwmark = 3;
    SWgPeerStatus p;
    p.publicKey = newKey();
    p.presharedKey = newKey();
    p.hasPresharedKey = true;
    SEndpoint::fromIp("192.0.2.9", 777, p.endpoint);
    p.allowedIps = { pfx("10.0.0.0/8"), pfx("fd00::/8") };
    p.lastHandshakeSec = 5;
    p.lastHandshakeNsec = 6;
    p.rxBytes = 7;
    p.txBytes = 8;
    p.persistentKeepalive = 9;
    s.peers.push_back(p);
    SWgPeerStatus q;
    q.publicKey = newKey();
    s.peers.push_back(q);

    std::string text = FormatWgUapiGet(s) + "errno=0\n\n";
    SWgDeviceStatus back;
    REQUIRE(ParseWgUapiGet(text, back) == SBOX_OK);
    CHECK(back.privateKey == s.privateKey);
    CHECK(back.listenPort == 51820);
    CHECK(back.fwmark == 3);
    REQUIRE(back.peers.size() == 2);
    CHECK(back.peers[0].presharedKey == p.presharedKey);
    CHECK(back.peers[0].endpoint.toString() == "192.0.2.9:777");
    CHECK(back.peers[0].allowedIps.size() == 2);
    CHECK(back.peers[0].rxBytes == 7);
    CHECK(back.peers[0].persistentKeepalive == 9);
    CHECK_FALSE(back.peers[1].hasPresharedKey);
    CHECK(FormatWgUapiGet(back) == FormatWgUapiGet(s));

    CHECK(ParseWgUapiGet("errno=22\n\n", back) == -22);
    CHECK(ParseWgUapiGet("listen_port=1\n", back) == -EBADMSG);

    SWgDeviceConfig c;
    c.privateKey = newKey();
    c.listenPort = 1;
    c.fwmark = 0;
    c.replacePeers = true;
    SWgPeerConfig pc;
    pc.publicKey = newKey();
    pc.persistentKeepalive = 0;
    pc.replaceAllowedIps = true;
    pc.allowedIps = { pfx("10.1.0.0/16") };
    SEndpoint::fromIp("192.0.2.1", 5, pc.endpoint);
    c.peers.push_back(pc);
    SWgPeerConfig rm;
    rm.publicKey = newKey();
    rm.remove = true;
    c.peers.push_back(rm);

    std::string set = FormatWgUapiSet(c);
    SWgDeviceConfig parsed;
    REQUIRE(ParseWgUapiSet(set, parsed) == SBOX_OK);
    CHECK(FormatWgUapiSet(parsed) == set);
    CHECK(parsed.replacePeers);
    REQUIRE(parsed.peers.size() == 2);
    CHECK(parsed.peers[0].replaceAllowedIps);
    CHECK(parsed.peers[1].remove);

    CHECK(ParseWgUapiSet("allowed_ip=10.0.0.0/8\n", parsed) == -EINVAL);
    CHECK(ParseWgUapiSet("bogus=1\n", parsed) == -EINVAL);
    CHECK(WgUapiSocketPath("wg0") == "/var/run/wireguard/wg0.sock");
}
