#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/image/reference.hpp>
#include <sbox/image/digest.hpp>
#include <sbox/image/spec.hpp>
#include <cerrno>

using namespace sbox;
using namespace sbox::image;

namespace {

    const std::string HEX64 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

}

TEST_CASE("strict parse follows distribution/reference") {
    struct Case {
        const char* input;
        bool ok;
        const char* domain;
        const char* path;
        const char* tag;
        const char* digest;
    };

    std::string dg = "sha256:" + HEX64;
    std::string withDigest1 = "test:5000/repo@" + dg;
    std::string withDigest2 = "test:5000/repo:tag@" + dg;
    std::string longTag(128, 'a');
    std::string tooLongTag(129, 'a');
    std::string tagged = "repo:" + longTag;
    std::string tagged2 = "repo:" + tooLongTag;
    std::string longName = "a/" + std::string(253, 'a');
    std::string tooLongName = "a/" + std::string(254, 'a');

    const Case cases[] = {
        { "test_com", true, "", "test_com", "", "" },
        { "test.com:tag", true, "", "test.com", "tag", "" },
        { "test.com:5000", true, "", "test.com", "5000", "" },
        { "test.com/repo:tag", true, "test.com", "repo", "tag", "" },
        { "test:5000/repo", true, "test:5000", "repo", "", "" },
        { "test:5000/repo:tag", true, "test:5000", "repo", "tag", "" },
        { withDigest1.c_str(), true, "test:5000", "repo", "", dg.c_str() },
        { withDigest2.c_str(), true, "test:5000", "repo", "tag", dg.c_str() },
        { "test:5000/repo", true, "test:5000", "repo", "", "" },
        { "", false, "", "", "", "" },
        { ":justtag", false, "", "", "", "" },
        { "@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false, "", "", "", "" },
        { "repo@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false, "", "", "", "" },
        { "validname@invaliddigest:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false, "", "", "", "" },
        { "Uppercase:tag", false, "", "", "", "" },
        { "test:5000/Uppercase/lowercase:tag", false, "", "", "", "" },
        { "lowercase:Uppercase", true, "", "lowercase", "Uppercase", "" },
        { tagged.c_str(), true, "", "repo", longTag.c_str(), "" },
        { tagged2.c_str(), false, "", "", "", "" },
        { longName.c_str(), true, "a", longName.c_str() + 2, "", "" },
        { tooLongName.c_str(), false, "", "", "", "" },
        { "-foo", false, "", "", "", "" },
        { "foo-", false, "", "", "", "" },
        { "foo..bar", false, "", "", "", "" },
        { "foo___bar", false, "", "", "", "" },
        { "foo__bar", true, "", "foo__bar", "", "" },
        { "foo--bar", true, "", "foo--bar", "", "" },
        { "docker///docker", false, "", "", "", "" },
        { "sub-dom1.foo.com/bar/baz/quux", true, "sub-dom1.foo.com", "bar/baz/quux", "", "" },
        { "sub-dom1.foo.com/bar/baz/quux:some-long-tag", true, "sub-dom1.foo.com", "bar/baz/quux", "some-long-tag", "" },
        { "b.gcr.io/test.example.com/my-app:test.example.com", true, "b.gcr.io", "test.example.com/my-app", "test.example.com", "" },
        { "xn--n3h.com/myimage:xn--n3h.com", true, "xn--n3h.com", "myimage", "xn--n3h.com", "" },
        { "foo_bar.com:8080", true, "", "foo_bar.com", "8080", "" },
        { "foo/foo_bar.com:8080", true, "foo", "foo_bar.com", "8080", "" },
        { "[2001:db8::1]:5000/repo", true, "[2001:db8::1]:5000", "repo", "", "" },
        { "[2001:db8::1]/repo:tag", true, "[2001:db8::1]", "repo", "tag", "" },
        { "[2001:db8::1]", false, "", "", "", "" },
        { "localhost/foo", true, "localhost", "foo", "", "" },
        { "localhost:5000/foo:bar", true, "localhost:5000", "foo", "bar", "" },
    };

    for (const Case& c : cases) {
        std::string input = c.input;
        CAPTURE(input);
        SReference r;
        int32_t rc = SReference::parse(c.input, r);
        if (!c.ok) {
            CHECK(rc == -EINVAL);
            continue;
        }

        REQUIRE(rc == SBOX_OK);
        CHECK(r.domain == c.domain);
        CHECK(r.path == c.path);
        CHECK(r.tag == c.tag);
        CHECK(r.digest == c.digest);
    }
}

TEST_CASE("normalization like ParseNormalizedNamed") {
    struct Case {
        const char* input;
        const char* full;       // --> nullptr: must fail.
        const char* familiar;
    };

    const Case cases[] = {
        { "docker/docker", "docker.io/docker/docker", "docker/docker" },
        { "library/debian", "docker.io/library/debian", "debian" },
        { "debian", "docker.io/library/debian", "debian" },
        { "docker.io/docker/docker", "docker.io/docker/docker", "docker/docker" },
        { "docker.io/library/debian", "docker.io/library/debian", "debian" },
        { "docker.io/debian", "docker.io/library/debian", "debian" },
        { "index.docker.io/docker/docker", "docker.io/docker/docker", "docker/docker" },
        { "index.docker.io/library/debian", "docker.io/library/debian", "debian" },
        { "index.docker.io/debian", "docker.io/library/debian", "debian" },
        { "localhost/library/debian", "localhost/library/debian", "localhost/library/debian" },
        { "localhost/debian", "localhost/debian", "localhost/debian" },
        { "registry.com/docker/docker", "registry.com/docker/docker", "registry.com/docker/docker" },
        { "127.0.0.1:5000/foo/bar", "127.0.0.1:5000/foo/bar", "127.0.0.1:5000/foo/bar" },
        { "localhost:5000/foo", "localhost:5000/foo", "localhost:5000/foo" },
        { "foo/bar/baz", "docker.io/foo/bar/baz", "foo/bar/baz" },
        { "docker.io/library/foo/bar", "docker.io/library/foo/bar", "library/foo/bar" },
        { "ubuntu:22.04", "docker.io/library/ubuntu:22.04", "ubuntu:22.04" },
        { "docker/Docker", nullptr, nullptr },
        { "docker///docker", nullptr, nullptr },
        { "docker.io/docker/Docker", nullptr, nullptr },
        { "docker.io/docker///docker", nullptr, nullptr },
        { "1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a", nullptr, nullptr },
        { "Foo/bar", "Foo/bar", "Foo/bar" },
        { "", nullptr, nullptr },
        { "alpine:", nullptr, nullptr },
    };

    for (const Case& c : cases) {
        std::string input = c.input;
        CAPTURE(input);
        SReference r;
        int32_t rc = ParseNormalizedReference(c.input, r);
        if (!c.full) {
            CHECK(rc == -EINVAL);
            continue;
        }

        REQUIRE(rc == SBOX_OK);
        CHECK(r.toString() == c.full);
        CHECK(r.familiarString() == c.familiar);
    }

    // --> Upper-case domain ("Foo/bar") counts as a domain, the path is fine.
    SReference up;
    CHECK(ParseNormalizedReference("Foo.com/bar", up) == SBOX_OK);
    CHECK(up.domain == "Foo.com");
}

TEST_CASE("ParseDockerRef adds :latest and drops the tag of tag+digest") {
    SReference r;
    REQUIRE(ParseDockerReference("alpine", r) == SBOX_OK);
    CHECK(r.toString() == "docker.io/library/alpine:latest");
    CHECK(r.familiarString() == "alpine:latest");

    std::string dg = "sha256:" + HEX64;
    REQUIRE(ParseDockerReference("alpine:3.20@" + dg, r) == SBOX_OK);
    CHECK(r.toString() == "docker.io/library/alpine@" + dg);

    REQUIRE(ParseDockerReference("gcr.io/proj/app@" + dg, r) == SBOX_OK);
    CHECK(r.toString() == "gcr.io/proj/app@" + dg);
    CHECK(!r.hasTag());
}

TEST_CASE("registry hosts") {
    CHECK(RegistryHost("docker.io") == "registry-1.docker.io");
    CHECK(RegistryHost("ghcr.io") == "ghcr.io");
    CHECK(RegistryHost("localhost:5000") == "localhost:5000");
    CHECK(IsLoopbackRegistry("localhost:5000"));
    CHECK(IsLoopbackRegistry("127.0.0.1:5000"));
    CHECK(IsLoopbackRegistry("[::1]:5000"));
    CHECK(!IsLoopbackRegistry("example.com"));
    CHECK(IsValidTag("v1.0_rc-1"));
    CHECK(!IsValidTag(".hidden"));
    CHECK(!IsValidTag("-x"));
}

TEST_CASE("digests and chain IDs") {
    CHECK(DigestOf(std::string_view("")) == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(DigestOf(std::string_view("abc")) == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(DigestOf(std::string_view("abc"), EDIGEST_SHA512) ==
          "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    CHECK(ValidateDigest("sha256:" + HEX64) == SBOX_OK);
    CHECK(ValidateDigest("sha256:" + HEX64.substr(1)) == -EINVAL);
    CHECK(ValidateDigest("sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == -EINVAL);
    CHECK(ValidateDigest("md5:abc") == -ENOTSUP);
    CHECK(ValidateDigest("sha256") == -EINVAL);
    CHECK(ValidateDigest(":abc") == -EINVAL);
    CHECK(ValidateDigest("sha+256:abc") == -ENOTSUP);
    CHECK(ValidateDigest("sha++256:abc") == -EINVAL);

    // --> Chain IDs (image-spec config.md): ChainID(L0) = DiffID(L0),
    // ChainID(L0|L1) = sha256(ChainID(L0) + " " + DiffID(L1)).
    std::string d0 = DigestOf(std::string_view("layer0"));
    std::string d1 = DigestOf(std::string_view("layer1"));
    std::string d2 = DigestOf(std::string_view("layer2"));
    std::vector<std::string> ids = ChainIds({ d0, d1, d2 });
    REQUIRE(ids.size() == 3);
    CHECK(ids[0] == d0);
    CHECK(ids[1] == DigestOf(d0 + " " + d1));
    CHECK(ids[2] == DigestOf(ids[1] + " " + d2));
    CHECK(ChainId("", d0) == d0);

    // --> Known vector: the chain ID of the alpine:3.x style two-layer case computed with
    // sha256sum: printf 'sha256:aaa... sha256:bbb...' | sha256sum.
    std::string a = "sha256:" + std::string(64, 'a');
    std::string b = "sha256:" + std::string(64, 'b');
    CHECK(ChainId(a, b) == "sha256:" + std::string(DigestHex(DigestOf(a + " " + b))));
}

TEST_CASE("platforms") {
    SPlatform p;
    REQUIRE(SPlatform::parse("linux/aarch64", p) == SBOX_OK);
    CHECK(p.toString() == "linux/arm64");
    REQUIRE(SPlatform::parse("linux/arm64/v8", p) == SBOX_OK);
    CHECK(p.toString() == "linux/arm64");
    REQUIRE(SPlatform::parse("linux/arm", p) == SBOX_OK);
    CHECK(p.toString() == "linux/arm/v7");
    REQUIRE(SPlatform::parse("x86_64", p) == SBOX_OK);
    CHECK(p.toString() == "linux/amd64");
    CHECK(SPlatform::parse("linux//x", p) == -EINVAL);

    SPlatform host = HostPlatform();
    CHECK(host.os == "linux");
    CHECK(!host.architecture.empty());

    SPlatform want;
    SPlatform::parse("linux/arm/v7", want);
    SPlatform v6;
    SPlatform::parse("linux/arm/v6", v6);
    SPlatform v7;
    SPlatform::parse("linux/arm/v7", v7);
    SPlatform amd;
    SPlatform::parse("linux/amd64", amd);
    CHECK(PlatformScore(want, v7) > PlatformScore(want, v6));
    CHECK(PlatformScore(want, v6) > 0);
    CHECK(PlatformScore(v6, v7) == 0);
    CHECK(PlatformScore(want, amd) == 0);

    SIndex idx;
    auto add = [&](const char* plat, const char* digestChar) {
        SDescriptor d;
        d.mediaType = MT_OCI_MANIFEST;
        d.digest = "sha256:" + std::string(64, digestChar[0]);
        d.size = 10;
        SPlatform::parse(plat, d.platform);
        d.hasPlatform = true;
        idx.manifests.push_back(d);
    };

    add("linux/amd64", "1");
    add("linux/arm/v6", "2");
    add("linux/arm/v7", "3");
    add("linux/arm64/v8", "4");
    SDescriptor att;
    att.mediaType = MT_OCI_MANIFEST;
    att.digest = "sha256:" + std::string(64, '5');
    att.size = 1;
    att.platform.os = "unknown";
    att.platform.architecture = "unknown";
    att.hasPlatform = true;
    idx.manifests.push_back(att);

    CHECK(idx.select(want) == 2);
    CHECK(idx.select(amd) == 0);
    SPlatform arm64;
    SPlatform::parse("linux/arm64", arm64);
    CHECK(idx.select(arm64) == 3);
    SPlatform s390;
    SPlatform::parse("linux/s390x", s390);
    CHECK(idx.select(s390) == -ENOENT);
}

TEST_CASE("manifest documents round trip and classify") {
    std::string text = R"({"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json",
        "config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":1469,
        "digest":"sha256:9c6f0724472873bb50a2ae67a9e7adcb57673a183cea8b06eb778dca859181b5"},
        "layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":2818413,
        "digest":"sha256:31e352740f534f9ad170f75378a84fe453d6156e40700b882d737a8f4a6988a3"}]})";
    CJson j;
    REQUIRE(CJson::parse(text, j) == SBOX_OK);
    CHECK(ClassifyManifest(j) == EMK_MANIFEST);
    SManifest m;
    REQUIRE(SManifest::fromJson(j, m) == SBOX_OK);
    CHECK(m.layers.size() == 1);
    CHECK(m.config.size == 1469);
    SManifest m2;
    REQUIRE(SManifest::fromJson(m.toJson(), m2) == SBOX_OK);
    CHECK(m2.toJson().dump() == m.toJson().dump());

    CJson s1;
    REQUIRE(CJson::parse(R"({"schemaVersion":1,"name":"x","fsLayers":[]})", s1) == SBOX_OK);
    CHECK(ClassifyManifest(s1) == EMK_SCHEMA1);
    CJson idx;
    REQUIRE(CJson::parse(R"({"schemaVersion":2,"manifests":[]})", idx) == SBOX_OK);
    CHECK(ClassifyManifest(idx) == EMK_INDEX);
    CHECK(ClassifyManifest(idx, "application/vnd.docker.distribution.manifest.v1+prettyjws") == EMK_INDEX);

    CJson cfg;
    REQUIRE(CJson::parse(R"({"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["/bin/sh"],
        "ExposedPorts":{"80/tcp":{}},"Labels":{"a":"b"}},"rootfs":{"type":"layers","diff_ids":
        ["sha256:94e5f06ff8e3d4441dc3cd8b090ff38dc911bfa8ebdb0dc28395bc98f82f983f"]},"history":[{"created_by":"x"}]})", cfg) == SBOX_OK);
    SImageConfig c;
    REQUIRE(SImageConfig::fromJson(cfg, c) == SBOX_OK);
    CHECK(c.cmd == std::vector<std::string>{ "/bin/sh" });
    CHECK(c.exposedPorts == std::vector<std::string>{ "80/tcp" });
    CHECK(c.label("a") == "b");
    CHECK(c.diffIds.size() == 1);
    CJson back = c.toJson();
    CHECK(back.get("history").size() == 1);
    CHECK(back.get("config").get("Labels").get("a").asString() == "b");
}
