#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/core/file.hpp>
#include <sbox/vpn/l2tp/profiles.hpp>
#include <sbox/vpn/l2tp/server.hpp>
#include "testutil.hpp"
#include <climits>
#include <cstdio>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

namespace {

    /* Parses JSON text into a configuration. */
    int32_t parse(const std::string& text, SL2tpServerConfig& out, std::string& error) {
        CJson json;
        if (CJson::parse(text, json) != SBOX_OK) {
            error = "json";
            return -EINVAL;
        }

        error.clear();
        return ParseL2tpServerConfig(json, out, &error);
    }

    /* The sbox-l2tp binary next to the build's test executables (build/bin). */
    std::string tool() {
        char self[PATH_MAX];
        ssize_t n = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n <= 0) {
            return std::string();
        }

        std::string path(self, size_t(n));
        path = path.substr(0, path.rfind('/'));         // --> build/modules/vpn
        path = path.substr(0, path.rfind('/'));         // --> build/modules
        path = path.substr(0, path.rfind('/'));         // --> build
        return path + "/bin/sbox-l2tp";
    }

    /* Runs a command and returns stdout. */
    std::string capture(const std::string& cmd, int* status = nullptr) {
        std::string out;
        FILE* f = ::popen(cmd.c_str(), "r");
        if (!f) {
            return out;
        }

        char buf[4096];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
            out.append(buf, n);
        }

        int st = ::pclose(f);
        if (status) {
            *status = st;
        }

        return out;
    }

    const char* GOOD = R"({
        "listen": "203.0.113.5",
        "psk": "a long pre-shared key",
        "ike": ["aes256-sha1-modp1024", "3des-sha1-modp1024-modp2048"],
        "esp": ["aes256-aes128-sha1", "aes128gcm16"],
        "users": [ { "name": "alice", "password": "s3cret" },
                   { "name": "bob", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c", "address": "10.60.0.50" } ],
        "auth": ["mschapv2", "pap"],
        "pool": "10.60.0.0/24",
        "dns": ["10.60.0.1", "1.1.1.1"],
        "interface": "l2tp7",
        "dataPath": "user",
        "forceEncap": true,
        "dpd": 20,
        "hello": 30,
        "idleTimeout": 600,
        "bridge": "br-test"
    })";

}

TEST_CASE("Configuration parsing") {
    SL2tpServerConfig c;
    std::string error;
    REQUIRE_MESSAGE(parse(GOOD, c, error) == SBOX_OK, error);
    CHECK(c.listenAddress == "203.0.113.5");
    REQUIRE(c.ike.psks.size() == 1);
    CHECK(c.ike.psks[0].secret == "a long pre-shared key");
    CHECK(c.ike.suites.size() == 3);
    CHECK(c.ike.esp.size() == 3);
    CHECK(c.users.size() == 2);
    CHECK(c.users[1].ntHash.size() == 16);
    CHECK(c.auth == std::vector<EPppAuth>{ EPPPA_MSCHAPV2, EPPPA_PAP });
    CHECK(c.pool.toString() == "10.60.0.0/24");
    CHECK(c.dns.size() == 2);
    CHECK(c.interfaceName == "l2tp7");
    CHECK(c.dataPath == EL2TK_USER);
    CHECK(c.ike.forceEncap);
    CHECK(c.ike.dpdSeconds == 20);
    CHECK(c.tunnel.helloSeconds == 30);
    CHECK(c.idleSeconds == 600);
    CHECK(c.bridge == "br-test");

    struct Bad { const char* json; const char* message; };
    const Bad bad[] = {
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24","bogus":1})", "unknown key" },
        { R"({"users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24"})", "psk is required" },
        { R"({"psk":"k","pool":"10.0.0.0/24"})", "at least one user" },
        { R"({"psk":"k","users":[{"name":"a"}],"pool":"10.0.0.0/24"})", "needs a name and a password" },
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"fd00::/64"})", "pool" },
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24","ike":["aes256-whirlpool-modp1024"]})", "bad IKE proposal" },
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24","esp":["aes256"]})", "bad ESP proposal" },
        { R"({"psk":"k","users":[{"name":"a","ntHash":"8846f7eaee8fb117ad06bdd830b7586c"}],"pool":"10.0.0.0/24","auth":"chap"})", "CHAP-MD5" },
        { R"({"psk":"k","users":[{"name":"a","password":"b","address":"10.9.9.9"}],"pool":"10.0.0.0/24"})", "outside the pool" },
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24","dataPath":"magic"})", "dataPath" },
        { R"({"psk":"k","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24","mtu":20})", "mtu" },
    };

    for (const Bad& b : bad) {
        CAPTURE(b.json);
        SL2tpServerConfig x;
        CHECK(parse(b.json, x, error) == -EINVAL);
        CHECK(error.find(b.message) != std::string::npos);
    }

    // --> Without IPsec no PSK is needed.
    SL2tpServerConfig plain;
    CHECK(parse(R"({"dataPath":"none","users":[{"name":"a","password":"b"}],"pool":"10.0.0.0/24"})", plain, error) == SBOX_OK);
}

TEST_CASE("Proposal strings") {
    std::vector<SIkev1Suite> s;
    REQUIRE(ParseIkev1Proposal("aes256-aes128-sha256-sha1-modp2048-ecp256", s) == SBOX_OK);
    CHECK(s.size() == 8);
    CHECK(s[0].toString() == "AES_CBC_256/SHA2_256/MODP_2048");
    CHECK(ParseIkev1Proposal("aes256-sha1", s) == -EINVAL);
    std::vector<SIkev1EspSuite> e;
    REQUIRE(ParseIkev1EspProposal("3des-aes256-sha1", e) == SBOX_OK);
    CHECK(e.size() == 2);
    CHECK(Ikev1EspSuiteName(e[0]) == "3des-sha1");
    CHECK(Ikev1EspSuiteName(e[1]) == "aes256-sha1");
    CHECK(ParseIkev1EspProposal("aes256gcm16-chacha", e) == -EINVAL);
}

TEST_CASE("Client profiles") {
    SL2tpClientProfile p;
    p.name = "Office VPN";
    p.server = "vpn.example.com";
    p.psk = "it's secret";
    p.user = "alice";
    p.routes = { "10.88.0.0/16" };
    p.serverBehindNat = true;

    std::string w = WindowsL2tpSetup(p);
    CHECK(w.find("-TunnelType L2tp") != std::string::npos);
    CHECK(w.find("-L2tpPsk 'it''s secret'") != std::string::npos);
    CHECK(w.find("-AuthenticationMethod MSChapv2") != std::string::npos);
    CHECK(w.find("AssumeUDPEncapsulationContextOnSendRule") != std::string::npos);
    CHECK(w.find("Add-VpnConnectionRoute -ConnectionName 'Office VPN' -DestinationPrefix '10.88.0.0/16'") != std::string::npos);
    CHECK(w.find("-SplitTunneling") != std::string::npos);

    std::string a = AppleL2tpMobileConfig(p);
    CHECK(a.find("<string>L2TP</string>") != std::string::npos);
    CHECK(a.find("<string>SharedSecret</string>") != std::string::npos);
    CHECK(a.find("<data>aXQncyBzZWNyZXQ=</data>") != std::string::npos);
    CHECK(a.find("<key>AuthName</key><string>alice</string>") != std::string::npos);
    CHECK(a.find("it&apos;s") == std::string::npos);

    std::string d = AndroidL2tpSetup(p);
    CHECK(d.find("L2TP/IPSec PSK") != std::string::npos);
    CHECK(d.find("it's secret") != std::string::npos);
}

TEST_CASE("sbox-l2tp: check, profile, nthash") {
    std::string bin = tool();
    if (::access(bin.c_str(), X_OK) != 0) {
        MESSAGE("skipped: " << bin << " not built");
        return;
    }

    TempDir dir;
    std::string cfg = dir.join("l2tp.json");
    REQUIRE(CFile::writeAtomic(cfg, GOOD) == SBOX_OK);
    int status = -1;
    std::string out = capture(bin + " check -c " + cfg + " 2>&1", &status);
    CHECK(status == 0);
    CHECK(out.find("configuration OK: 2 user(s)") != std::string::npos);

    out = capture(bin + " profile --server vpn.example.com -c " + cfg + " --format windows", &status);
    CHECK(status == 0);
    CHECK(out.find("-L2tpPsk 'a long pre-shared key'") != std::string::npos);

    out = capture(bin + " profile --server vpn.example.com --psk k --format apple", &status);
    CHECK(status == 0);
    CHECK(out.find("com.apple.vpn.managed") != std::string::npos);

    out = capture(bin + " nthash password", &status);
    CHECK(out == "8846f7eaee8fb117ad06bdd830b7586c\n");

    capture(bin + " frobnicate 2>/dev/null", &status);
    CHECK(status != 0);
}
