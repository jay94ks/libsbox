#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/http/auth.hpp>
#include <sbox/http/headers.hpp>
#include <sbox/http/proxy.hpp>
#include <cerrno>

using namespace sbox;
using namespace sbox::http;

TEST_CASE("header collection is case-insensitive and keeps order and duplicates") {
    CHeaders h;
    h.add("Content-Type", "text/plain");
    h.add("Set-Cookie", "a=1");
    h.add("set-cookie", " b=2 ");
    h.add("X-Empty", "");

    CHECK(h.size() == 4);
    CHECK(h.has("CONTENT-TYPE"));
    CHECK(h.get("content-type") == "text/plain");
    CHECK(h.get("missing", "dflt") == "dflt");
    CHECK(h.find("missing") == nullptr);

    auto cookies = h.getAll("SET-COOKIE");
    REQUIRE(cookies.size() == 2);
    CHECK(cookies[0] == "a=1");
    CHECK(cookies[1] == "b=2");
    CHECK(h.combined("set-cookie") == "a=1, b=2");

    h.set("SET-COOKIE", "c=3");
    CHECK(h.getAll("set-cookie").size() == 1);
    CHECK(h.at(1).value == "c=3");
    CHECK(h.at(1).name == "Set-Cookie");

    CHECK(h.remove("x-empty") == 1);
    CHECK(h.size() == 2);

    std::string wire;
    h.serializeTo(wire);
    CHECK(wire == "Content-Type: text/plain\r\nSet-Cookie: c=3\r\n");
}

TEST_CASE("token lists") {
    CHeaders h;
    h.add("Connection", "keep-alive, Upgrade");
    h.add("Connection", "close");
    CHECK(h.hasToken("connection", "upgrade"));
    CHECK(h.hasToken("connection", "CLOSE"));
    CHECK_FALSE(h.hasToken("connection", "keep"));

    auto items = SplitHeaderList(" a , \"b,c\" ,, d ");
    REQUIRE(items.size() == 3);
    CHECK(items[0] == "a");
    CHECK(items[1] == "\"b,c\"");
    CHECK(items[2] == "d");

    CHECK(IsToken("X-Registry-Auth"));
    CHECK_FALSE(IsToken("Bad Name"));
    CHECK_FALSE(IsToken(""));
}

TEST_CASE("media types") {
    SMediaType mt;
    REQUIRE(SMediaType::parse("Application/VND.Docker.Plugins.v1.2+JSON; charset=\"UTF-8\"; q=0.5", mt) == SBOX_OK);
    CHECK(mt.type == "application");
    CHECK(mt.subtype == "vnd.docker.plugins.v1.2+json");
    CHECK(mt.essence() == "application/vnd.docker.plugins.v1.2+json");
    CHECK(mt.param("CHARSET") == "UTF-8");
    CHECK(mt.param("q") == "0.5");
    CHECK(mt.toString() == "application/vnd.docker.plugins.v1.2+json; charset=UTF-8; q=0.5");

    CHECK(SMediaType::parse("text", mt) == -EINVAL);
    CHECK(SMediaType::parse("text/", mt) == -EINVAL);
    CHECK(SMediaType::parse("text/plain; x=\"unterminated", mt) == -EINVAL);
}

TEST_CASE("Link headers for registry pagination") {
    std::vector<SLink> links;
    REQUIRE(ParseLinkHeader("</v2/_catalog?last=b&n=2>; rel=\"next\", <https://x/y,z>; rel=\"prev first\"; title=t", links) == SBOX_OK);
    REQUIRE(links.size() == 2);
    CHECK(links[0].target == "/v2/_catalog?last=b&n=2");
    CHECK(links[0].hasRel("next"));
    CHECK(links[1].target == "https://x/y,z");
    CHECK(links[1].hasRel("FIRST"));
    CHECK_FALSE(links[1].hasRel("next"));
    CHECK(links[1].param("title") == "t");

    std::vector<SLink> bad;
    CHECK(ParseLinkHeader("no-brackets; rel=next", bad) == -EINVAL);
    CHECK(ParseLinkHeader("<unterminated; rel=next", bad) == -EINVAL);
}

TEST_CASE("Content-Range and Range") {
    SContentRange cr;
    REQUIRE(SContentRange::parse("bytes 0-499/1234", cr) == SBOX_OK);
    CHECK(cr.first == 0);
    CHECK(cr.last == 499);
    CHECK(cr.completeLength == 1234);
    CHECK(cr.length() == 500);
    CHECK(cr.toString() == "bytes 0-499/1234");

    REQUIRE(SContentRange::parse("bytes 10-19/*", cr) == SBOX_OK);
    CHECK(cr.completeLength == -1);

    REQUIRE(SContentRange::parse("bytes */1234", cr) == SBOX_OK);
    CHECK(cr.unsatisfied);
    CHECK(cr.toString() == "bytes */1234");

    CHECK(SContentRange::parse("bytes 5-4/10", cr) == -EINVAL);
    CHECK(SContentRange::parse("bytes 0-10/10", cr) == -EINVAL);
    CHECK(SContentRange::parse("items 0-1/2", cr) == -EINVAL);
    CHECK(SContentRange::parse("bytes */*", cr) == -EINVAL);

    CHECK(FormatRange(100) == "bytes=100-");
    CHECK(FormatRange(0, 99) == "bytes=0-99");

    uint64_t a = 0, b = 0;
    REQUIRE(ParseRange("bytes=100-", 1000, a, b) == SBOX_OK);
    CHECK(a == 100);
    CHECK(b == 999);
    REQUIRE(ParseRange("bytes=0-5000", 1000, a, b) == SBOX_OK);
    CHECK(b == 999);
    REQUIRE(ParseRange("bytes=-10", 1000, a, b) == SBOX_OK);
    CHECK(a == 990);
    CHECK(ParseRange("bytes=1000-", 1000, a, b) == -ERANGE);
    CHECK(ParseRange("bytes=0-1,5-6", 1000, a, b) == -EINVAL);
    CHECK(ParseRange("bytes=5-1", 1000, a, b) == -EINVAL);
}

TEST_CASE("HTTP dates") {
    CHECK(FormatHttpDate(784111777) == "Sun, 06 Nov 1994 08:49:37 GMT");
}

TEST_CASE("base64 and Basic auth") {
    CHECK(Base64Encode(BytesOf("")) == "");
    CHECK(Base64Encode(BytesOf("f")) == "Zg==");
    CHECK(Base64Encode(BytesOf("fo")) == "Zm8=");
    CHECK(Base64Encode(BytesOf("foo")) == "Zm9v");
    CHECK(Base64Encode(BytesOf("foobar")) == "Zm9vYmFy");

    std::vector<uint8_t> out;
    REQUIRE(Base64Decode("Zm9vYmE=", out) == SBOX_OK);
    CHECK(std::string(out.begin(), out.end()) == "fooba");
    REQUIRE(Base64Decode("Zm9vYmE", out) == SBOX_OK);
    CHECK(std::string(out.begin(), out.end()) == "fooba");
    CHECK(Base64Decode("Zm9v YmE=", out) == -EINVAL);
    CHECK(Base64Decode("Z", out) == -EINVAL);
    CHECK(Base64Decode("Zh==", out) == -EINVAL);
    CHECK(Base64Decode("Zm9=v", out) == -EINVAL);

    CHECK(EncodeBasicAuth("Aladdin", "open sesame") == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

    std::string user, pass;
    REQUIRE(DecodeBasicAuth("basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", user, pass) == SBOX_OK);
    CHECK(user == "Aladdin");
    CHECK(pass == "open sesame");
    CHECK(DecodeBasicAuth("Bearer abc", user, pass) == -ENOENT);
    CHECK(DecodeBasicAuth("Basic !!!", user, pass) == -EINVAL);
}

TEST_CASE("Docker Hub Bearer challenge") {
    std::vector<SAuthChallenge> ch;
    REQUIRE(ParseAuthChallenges("Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"", ch) == SBOX_OK);
    REQUIRE(ch.size() == 1);
    CHECK(ch[0].isScheme("bearer"));
    CHECK(ch[0].param("realm") == "https://auth.docker.io/token");
    CHECK(ch[0].param("Service") == "registry.docker.io");
    CHECK(ch[0].param("scope") == "repository:library/alpine:pull");
    CHECK(ch[0].token68.empty());
    CHECK_FALSE(ch[0].hasParam("error"));
}

TEST_CASE("several challenges, token68 and quoting") {
    std::vector<SAuthChallenge> ch;
    REQUIRE(ParseAuthChallenges("Basic realm=\"Registry Realm\", charset=UTF-8, Bearer realm=\"https://a/t\", scope=\"a,b\" , Negotiate, NTLM abc+/==", ch) == SBOX_OK);
    REQUIRE(ch.size() == 4);
    CHECK(ch[0].isScheme("Basic"));
    CHECK(ch[0].param("realm") == "Registry Realm");
    CHECK(ch[0].param("charset") == "UTF-8");
    CHECK(ch[1].isScheme("Bearer"));
    CHECK(ch[1].param("scope") == "a,b");
    CHECK(ch[2].isScheme("Negotiate"));
    CHECK(ch[2].params.empty());
    CHECK(ch[3].token68 == "abc+/==");

    std::vector<SAuthChallenge> esc;
    REQUIRE(ParseAuthChallenges("Bearer realm = \"a\\\"b\", error=\"insufficient_scope\"", esc) == SBOX_OK);
    REQUIRE(esc.size() == 1);
    CHECK(esc[0].param("realm") == "a\"b");
    CHECK(esc[0].param("error") == "insufficient_scope");

    std::vector<SAuthChallenge> t68;
    REQUIRE(ParseAuthChallenges("Custom dG9rZW4=", t68) == SBOX_OK);
    CHECK(t68[0].token68 == "dG9rZW4=");

    std::vector<SAuthChallenge> bad;
    CHECK(ParseAuthChallenges("Bearer realm=\"unterminated", bad) == -EINVAL);
    CHECK(ParseAuthChallenges("=x", bad) == -EINVAL);
    CHECK(ParseAuthChallenges("Bearer a=b c", bad) == -EINVAL);
}

TEST_CASE("NO_PROXY matching") {
    SProxyConfig cfg;
    cfg.httpProxy = "http://proxy:3128";
    cfg.httpsProxy = "http://proxy:3128";
    cfg.noProxy = "localhost,127.0.0.0/8, ::1 .internal.example *.svc.cluster.local,example.org:8443,10.0.0.0/8,fd00::/8";

    CHECK(cfg.bypasses("localhost", 80));
    CHECK(cfg.bypasses("127.0.0.5", 80));
    CHECK(cfg.bypasses("::1", 80));
    CHECK(cfg.bypasses("a.internal.example", 80));
    CHECK(cfg.bypasses("internal.example", 80));
    CHECK(cfg.bypasses("x.svc.cluster.local", 443));
    CHECK(cfg.bypasses("example.org", 8443));
    CHECK_FALSE(cfg.bypasses("example.org", 443));
    CHECK(cfg.bypasses("10.1.2.3", 80));
    CHECK(cfg.bypasses("fd12::1", 80));
    CHECK_FALSE(cfg.bypasses("registry-1.docker.io", 443));
    CHECK_FALSE(cfg.bypasses("notinternal.example", 80));
    CHECK_FALSE(cfg.bypasses("11.0.0.1", 80));

    SUrl u;
    REQUIRE(SUrl::parse("https://registry-1.docker.io/v2/", u) == SBOX_OK);
    CHECK(cfg.select(u) == "http://proxy:3128");
    REQUIRE(SUrl::parse("http://127.0.0.1:5000/v2/", u) == SBOX_OK);
    CHECK(cfg.select(u).empty());

    SProxyConfig all;
    all.httpsProxy = "http://p:1";
    all.noProxy = "*";
    CHECK(all.bypasses("anything", 1));
}

TEST_CASE("proxy settings from the environment") {
    ::setenv("https_proxy", "http://lower:1", 1);
    ::setenv("HTTPS_PROXY", "http://upper:1", 1);
    ::unsetenv("http_proxy");
    ::unsetenv("HTTP_PROXY");
    ::setenv("ALL_PROXY", "http://all:2", 1);
    ::unsetenv("all_proxy");
    ::setenv("no_proxy", "a,b", 1);

    SProxyConfig cfg = SProxyConfig::fromEnvironment();
    CHECK(cfg.httpsProxy == "http://lower:1");
    CHECK(cfg.httpProxy == "http://all:2");
    CHECK(cfg.noProxy == "a,b");
}
