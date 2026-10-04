#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/http/url.hpp>
#include <cerrno>

using namespace sbox;
using namespace sbox::http;

namespace {

    std::string resolved(const char* base, const char* ref) {
        SUrl b;
        REQUIRE(SUrl::parse(base, b) == SBOX_OK);

        SUrl out;
        REQUIRE(SUrl::resolve(b, ref, out) == SBOX_OK);
        return out.toString();
    }

}

TEST_CASE("RFC 3986 5.4.1 normal examples") {
    const char* base = "http://a/b/c/d;p?q";
    const char* cases[][2] = {
        { "g:h", "g:h" },
        { "g", "http://a/b/c/g" },
        { "./g", "http://a/b/c/g" },
        { "g/", "http://a/b/c/g/" },
        { "/g", "http://a/g" },
        { "//g", "http://g" },
        { "?y", "http://a/b/c/d;p?y" },
        { "g?y", "http://a/b/c/g?y" },
        { "#s", "http://a/b/c/d;p?q#s" },
        { "g#s", "http://a/b/c/g#s" },
        { "g?y#s", "http://a/b/c/g?y#s" },
        { ";x", "http://a/b/c/;x" },
        { "g;x", "http://a/b/c/g;x" },
        { "g;x?y#s", "http://a/b/c/g;x?y#s" },
        { "", "http://a/b/c/d;p?q" },
        { ".", "http://a/b/c/" },
        { "./", "http://a/b/c/" },
        { "..", "http://a/b/" },
        { "../", "http://a/b/" },
        { "../g", "http://a/b/g" },
        { "../..", "http://a/" },
        { "../../", "http://a/" },
        { "../../g", "http://a/g" },
    };

    for (const auto& c : cases) {
        CAPTURE(c[0]);
        CHECK(resolved(base, c[0]) == c[1]);
    }
}

TEST_CASE("RFC 3986 5.4.2 abnormal examples") {
    const char* base = "http://a/b/c/d;p?q";
    const char* cases[][2] = {
        { "../../../g", "http://a/g" },
        { "../../../../g", "http://a/g" },
        { "/./g", "http://a/g" },
        { "/../g", "http://a/g" },
        { "g.", "http://a/b/c/g." },
        { ".g", "http://a/b/c/.g" },
        { "g..", "http://a/b/c/g.." },
        { "..g", "http://a/b/c/..g" },
        { "./../g", "http://a/b/g" },
        { "./g/.", "http://a/b/c/g/" },
        { "g/./h", "http://a/b/c/g/h" },
        { "g/../h", "http://a/b/c/h" },
        { "g;x=1/./y", "http://a/b/c/g;x=1/y" },
        { "g;x=1/../y", "http://a/b/c/y" },
        { "g?y/./x", "http://a/b/c/g?y/./x" },
        { "g?y/../x", "http://a/b/c/g?y/../x" },
        { "g#s/./x", "http://a/b/c/g#s/./x" },
        { "g#s/../x", "http://a/b/c/g#s/../x" },
        { "http:g", "http:g" },
    };

    for (const auto& c : cases) {
        CAPTURE(c[0]);
        CHECK(resolved(base, c[0]) == c[1]);
    }
}

TEST_CASE("remove dot segments (5.2.4 examples)") {
    CHECK(RemoveDotSegments("/a/b/c/./../../g") == "/a/g");
    CHECK(RemoveDotSegments("mid/content=5/../6") == "mid/6");
    CHECK(RemoveDotSegments("/..") == "/");
    CHECK(RemoveDotSegments("") == "");
}

TEST_CASE("parse splits every component") {
    SUrl u;
    REQUIRE(SUrl::parse("HTTPS://user:p%40ss@Registry-1.Docker.IO:8443/v2/library/alpine/manifests/latest?n=1&last=a#frag", u) == SBOX_OK);
    CHECK(u.scheme == "https");
    CHECK(u.hasUserinfo);
    CHECK(u.userinfo == "user:p%40ss");
    CHECK(u.host == "registry-1.docker.io");
    CHECK(u.port == 8443);
    CHECK(u.path == "/v2/library/alpine/manifests/latest");
    CHECK(u.hasQuery);
    CHECK(u.query == "n=1&last=a");
    CHECK(u.fragment == "frag");
    CHECK(u.effectivePort() == 8443);
    CHECK(u.hostPort() == "registry-1.docker.io:8443");
    CHECK(u.requestTarget() == "/v2/library/alpine/manifests/latest?n=1&last=a");

    std::string user, pass;
    REQUIRE(u.credentials(user, pass) == SBOX_OK);
    CHECK(user == "user");
    CHECK(pass == "p@ss");

    CHECK(u.toString() == "https://user:p%40ss@registry-1.docker.io:8443/v2/library/alpine/manifests/latest?n=1&last=a#frag");
}

TEST_CASE("default ports, empty paths and empty components") {
    SUrl u;
    REQUIRE(SUrl::parse("http://example.com", u) == SBOX_OK);
    CHECK(u.port == -1);
    CHECK(u.effectivePort() == 80);
    CHECK(u.requestTarget() == "/");
    CHECK(u.hostPort() == "example.com");

    REQUIRE(SUrl::parse("https://example.com:443/?", u) == SBOX_OK);
    CHECK(u.hostPort() == "example.com");
    CHECK(u.hasQuery);
    CHECK(u.query.empty());
    CHECK(u.toString() == "https://example.com:443/?");

    REQUIRE(SUrl::parse("http://example.com:/x", u) == SBOX_OK);
    CHECK(u.port == -1);
}

TEST_CASE("IPv6 literals") {
    SUrl u;
    REQUIRE(SUrl::parse("http://[::1]:8080/a", u) == SBOX_OK);
    CHECK(u.host == "::1");
    CHECK(u.isIpv6Host());
    CHECK(u.port == 8080);
    CHECK(u.hostPort() == "[::1]:8080");
    CHECK(u.toString() == "http://[::1]:8080/a");

    REQUIRE(SUrl::parse("http://[FE80::1%25eth0]/", u) == SBOX_OK);
    CHECK(u.host == "fe80::1%25eth0");

    CHECK(SUrl::parse("http://[::1/a", u) == -EINVAL);
    CHECK(SUrl::parse("http://[zz::1]/", u) == -EINVAL);
    CHECK(SUrl::parse("http://[::1]x/", u) == -EINVAL);
}

TEST_CASE("malformed URLs are rejected") {
    SUrl u;
    CHECK(SUrl::parse("http://a b/", u) == -EINVAL);
    CHECK(SUrl::parse("http://a/\x01", u) == -EINVAL);
    CHECK(SUrl::parse("http://a/%zz", u) == -EINVAL);
    CHECK(SUrl::parse("http://a/%4", u) == -EINVAL);
    CHECK(SUrl::parse("http://a:99999/", u) == -EINVAL);
    CHECK(SUrl::parse("http://a:12x/", u) == -EINVAL);
    CHECK(SUrl::parse("http://a/\xc3\xa9", u) == -EINVAL);
    CHECK(SUrl::parse("http://a/[x]", u) == -EINVAL);

    SUrl rel;
    REQUIRE(SUrl::parse("/relative", rel) == SBOX_OK);
    SUrl out;
    CHECK(SUrl::resolve(rel, "x", out) == -EINVAL);
}

TEST_CASE("relative references and colon paths") {
    SUrl u;
    REQUIRE(SUrl::parse("./a:b", u) == SBOX_OK);
    CHECK(u.scheme.empty());
    CHECK(u.path == "./a:b");

    REQUIRE(SUrl::parse("1a:b", u) == SBOX_OK);
    CHECK(u.scheme.empty());

    REQUIRE(SUrl::parse("//host/p", u) == SBOX_OK);
    CHECK(u.hasAuthority);
    CHECK(u.host == "host");
}

TEST_CASE("realm and Location style resolution") {
    CHECK(resolved("https://registry.example.com/v2/x/blobs/sha256:ab", "https://cdn.example.net/blob?sig=1")
        == "https://cdn.example.net/blob?sig=1");
    CHECK(resolved("https://registry.example.com/v2/x/blobs/sha256:ab", "/v2/x/blobs/uploads/123?_state=z")
        == "https://registry.example.com/v2/x/blobs/uploads/123?_state=z");
    CHECK(resolved("http://h/a/b", "//other:81/c") == "http://other:81/c");
}

TEST_CASE("percent encoding round trips") {
    CHECK(PercentEncode("repository:library/alpine:pull") == "repository%3Alibrary%2Falpine%3Apull");
    CHECK(PercentEncode("a b/c", EPCT_PATH) == "a%20b/c");
    CHECK(PercentEncode("a b&c", EPCT_FORM) == "a+b%26c");
    CHECK(PercentEncode("x=y&z?", EPCT_QUERY) == "x%3Dy%26z?");
    CHECK(PercentEncode("\xff~-._") == "%FF~-._");

    std::string out;
    CHECK(PercentDecode("a%20b%2Fc", out) == SBOX_OK);
    CHECK(out == "a b/c");
    CHECK(PercentDecode("a+b", out, true) == SBOX_OK);
    CHECK(out == "a b");
    CHECK(PercentDecode("a+b", out) == SBOX_OK);
    CHECK(out == "a+b");
    CHECK(PercentDecode("%G1", out) == -EINVAL);
    CHECK(PercentDecode("%1", out) == -EINVAL);
}

TEST_CASE("query building and parsing") {
    SQueryParams params = { { "service", "registry.docker.io" }, { "scope", "repository:library/alpine:pull" }, { "e", "" } };
    std::string q = BuildQuery(params);
    CHECK(q == "service=registry.docker.io&scope=repository%3Alibrary%2Falpine%3Apull&e=");

    SQueryParams back;
    REQUIRE(ParseQuery(q, back) == SBOX_OK);
    CHECK(back == params);

    SQueryParams more;
    REQUIRE(ParseQuery("a=1&&b&c=x+y&a=2", more) == SBOX_OK);
    REQUIRE(more.size() == 4);
    CHECK(more[1].first == "b");
    CHECK(more[1].second.empty());
    CHECK(more[2].second == "x y");
    CHECK(more[3].second == "2");
    CHECK(ParseQuery("a=%zz", more) == -EINVAL);
}
