#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/config.hpp>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    const char* SAMPLE =
        "# Server configuration\n"
        "[Interface]\n"
        "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"
        "ListenPort = 51820\n"
        "fwmark = 0x1234\n"
        "Address = 10.200.0.1/24, fd00:200::1/64\n"
        "Address = 10.201.0.1/24   # second line\n"
        "DNS = 1.1.1.1, example.internal\n"
        "MTU = 1380\n"
        "PostUp = echo up\n"
        "\n"
        "[Peer]\n"
        "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n"
        "PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=\n"
        "AllowedIPs = 10.200.0.2/32,fd00:200::2/128\n"
        "Endpoint = 192.0.2.10:51821\n"
        "PersistentKeepalive = 25\n"
        "\n"
        "[peer]\n"
        "publickey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\n"
        "allowedips = 10.200.0.3/32\n"
        "endpoint = [2001:db8::5]:51820\n"
        "\n"
        "[Peer]\n"
        "PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = vpn.example.com:443\n"
        "PersistentKeepalive = off\n";

}

TEST_CASE("config: parse the wg-quick format") {
    SWgConfig c;
    std::string err;
    REQUIRE_MESSAGE(ParseWgConfig(SAMPLE, c, &err) == SBOX_OK, err);

    CHECK(c.privateKey.toBase64() == "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    CHECK(c.listenPort == 51820);
    CHECK(c.fwmark == 0x1234);
    REQUIRE(c.addresses.size() == 3);
    CHECK(c.addresses[1].toString() == "fd00:200::1/64");
    CHECK(c.dns.size() == 2);
    CHECK(c.mtu == 1380);
    REQUIRE(c.postUp.size() == 1);

    REQUIRE(c.peers.size() == 3);
    CHECK(c.peers[0].presharedKey.valid);
    CHECK(c.peers[0].allowedIps.size() == 2);
    CHECK(c.peers[0].endpoint.toString() == "192.0.2.10:51821");
    CHECK(c.peers[0].persistentKeepalive == 25);
    CHECK(c.peers[1].endpoint.toString() == "[2001:db8::5]:51820");
    CHECK(c.peers[1].persistentKeepalive == 0);
    CHECK_FALSE(c.peers[2].endpoint.isValid());
    CHECK(c.peers[2].endpointHost == "vpn.example.com:443");
}

TEST_CASE("config: write and parse again round-trips") {
    SWgConfig c;
    REQUIRE(ParseWgConfig(SAMPLE, c) == SBOX_OK);
    std::string text = WriteWgConfig(c);

    SWgConfig d;
    std::string err;
    REQUIRE_MESSAGE(ParseWgConfig(text, d, &err) == SBOX_OK, err);
    CHECK(WriteWgConfig(d) == text);
    CHECK(d.privateKey == c.privateKey);
    CHECK(d.addresses.size() == c.addresses.size());
    REQUIRE(d.peers.size() == c.peers.size());
    for (size_t i = 0; i < d.peers.size(); ++i) {
        CHECK(d.peers[i].publicKey == c.peers[i].publicKey);
        CHECK(d.peers[i].allowedIps.size() == c.peers[i].allowedIps.size());
        CHECK(d.peers[i].endpoint.toString() == c.peers[i].endpoint.toString());
        CHECK(d.peers[i].endpointHost == c.peers[i].endpointHost);
        CHECK(d.peers[i].persistentKeepalive == c.peers[i].persistentKeepalive);
    }

    // --> The `wg setconf` flavour leaves the wg-quick keys out.
    std::string plain = WriteWgConfig(c, false);
    CHECK(plain.find("Address") == std::string::npos);
    CHECK(plain.find("DNS") == std::string::npos);
    CHECK(plain.find("ListenPort = 51820") != std::string::npos);
}

TEST_CASE("config: errors name the line") {
    SWgConfig c;
    std::string err;
    CHECK(ParseWgConfig("[Interface]\nPrivateKey = nope\n", c, &err) == -EINVAL);
    CHECK(err == "line 2: invalid PrivateKey");
    CHECK(ParseWgConfig("[Peer]\nAllowedIPs = 10.0.0.0/8\n", c, &err) == -EINVAL);
    CHECK(err.find("no PublicKey") != std::string::npos);
    CHECK(ParseWgConfig("[Interface]\nBogus = 1\n", c, &err) == -EINVAL);
    CHECK(ParseWgConfig("[Wat]\n", c, &err) == -EINVAL);
    CHECK(ParseWgConfig("ListenPort = 1\n", c, &err) == -EINVAL);
    CHECK(ParseWgConfig("[Interface]\nListenPort = 70000\n", c, &err) == -EINVAL);
    CHECK(ParseWgConfig("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = fd00::1:5\n", c, &err) == -EINVAL);
}

TEST_CASE("config: client configuration for the official apps") {
    SWgKey serverPriv, serverPub;
    REQUIRE(GenerateWgPrivateKey(serverPriv) == SBOX_OK);
    REQUIRE(DeriveWgPublicKey(serverPriv, serverPub) == SBOX_OK);

    SWgClientRequest req;
    req.serverPublicKey = serverPub;
    req.serverEndpoint = "vpn.example.com:51820";
    net::SIpPrefix a;
    REQUIRE(net::SIpPrefix::parse("10.200.0.7/32", a) == SBOX_OK);
    req.clientAddresses = { a };
    req.dns = { "10.200.0.1" };

    SWgClientBundle b;
    REQUIRE(GenerateWgClientConfig(req, b) == SBOX_OK);

    SWgConfig parsed;
    REQUIRE(ParseWgConfig(b.text, parsed) == SBOX_OK);
    REQUIRE(parsed.peers.size() == 1);
    CHECK(parsed.peers[0].publicKey == serverPub);
    CHECK(parsed.peers[0].endpointHost == "vpn.example.com:51820");
    CHECK(parsed.peers[0].allowedIps.size() == 2);
    CHECK(parsed.peers[0].persistentKeepalive == 25);
    CHECK(parsed.peers[0].presharedKey.valid);
    CHECK(parsed.addresses[0].toString() == "10.200.0.7/32");
    CHECK(parsed.dns[0] == "10.200.0.1");

    // --> The server-side peer matches the client's key and address.
    SWgKey clientPub;
    REQUIRE(DeriveWgPublicKey(parsed.privateKey, clientPub) == SBOX_OK);
    CHECK(b.serverPeer.publicKey == clientPub);
    CHECK(b.serverPeer.presharedKey == parsed.peers[0].presharedKey);
    REQUIRE(b.serverPeer.allowedIps.size() == 1);
    CHECK(b.serverPeer.allowedIps[0].toString() == "10.200.0.7/32");

    // --> Compact enough for a QR code (version 40 holds 2953 bytes).
    CHECK(b.text.size() < 600);

    req.clientAddresses.clear();
    CHECK(GenerateWgClientConfig(req, b) == -EINVAL);
}
