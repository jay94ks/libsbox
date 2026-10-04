#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/image/registry.hpp>

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

namespace {

    /* Options for talking to the in-test registry quickly. */
    SRegistryOptions testOptions() {
        SRegistryOptions o;
        o.unpack = false;
        o.retryDelayMs = 10;
        o.certsDir.clear();
        o.dockerConfig = "/nonexistent/config.json";
        return o;
    }

    /* A two layer test image. */
    TestImage sampleImage(const std::string& arch = "", bool docker = false) {
        std::string big(300000, 'x');
        for (size_t i = 0; i < big.size(); ++i) {
            big[i] = char('a' + (i * 7919 % 26));
        }

        return BuildImage({ { Dir("etc"), File("etc/hostname", "test\n"), File("big.bin", big), Dir("data"),
                              File("data/a", "A"), File("data/b", "B") },
                            { File(".wh.big.bin", ""), File("data/c", "C") } },
                          arch, docker);
    }

}

TEST_CASE("pull with Bearer auth, CDN redirect and http fallback") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        REQUIRE(reg.start() == SBOX_OK);
        TestImage img = sampleImage();
        reg.add("library/app", "v1", img);

        std::vector<SProgress> events;
        SRegistryOptions o = testOptions();
        o.progress = [&events](const SProgress& p) { events.push_back(p); };
        CRegistryClient client(o);
        SPullResult res;
        int32_t r = co_await client.pull(*store, reg.domain() + "/library/app:v1", res);
        CAPTURE(client.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(res.reference == reg.domain() + "/library/app:v1");
        CHECK(res.manifestDigest == img.manifestDigest);
        CHECK(res.imageId == img.configDigest);
        CHECK(res.endpoint == "http://" + reg.domain());
        CHECK(reg.cdnAuthLeaks == 0);
        CHECK(reg.tokenRequests >= 1);
        CHECK(reg.blobGets == 3);
        for (const auto& [d, b] : img.blobs) {
            CHECK(store->hasBlob(d));
        }

        bool sawVerified = false;
        bool sawDone = false;
        for (const SProgress& p : events) {
            sawVerified = sawVerified || p.phase == EPP_VERIFIED;
            sawDone = sawDone || p.phase == EPP_DONE;
        }

        CHECK(sawVerified);
        CHECK(sawDone);

        SImageInfo info;
        REQUIRE(store->resolve(reg.domain() + "/library/app:v1", info) == SBOX_OK);
        CHECK(info.id == img.configDigest);
        REQUIRE(info.repoDigests.size() == 1);
        CHECK(info.repoDigests[0] == reg.domain() + "/library/app@" + img.manifestDigest);
        REQUIRE(store->resolve(std::string(DigestHex(img.configDigest)).substr(0, 12), info) == SBOX_OK);

        // --> A second pull finds everything in the store and downloads nothing.
        int32_t before = reg.blobGets;
        SPullResult again;
        REQUIRE(co_await client.pull(*store, reg.domain() + "/library/app:v1", again) == SBOX_OK);
        CHECK(reg.blobGets == before);
        CHECK(again.downloadedBytes == 0);

        // --> By digest.
        TempDir tmp2;
        CContentStorePtr store2;
        REQUIRE(CContentStore::open(tmp2.sub("store"), store2) == SBOX_OK);
        SPullResult byDigest;
        REQUIRE(co_await client.pull(*store2, reg.domain() + "/library/app@" + img.manifestDigest, byDigest) == SBOX_OK);
        REQUIRE(store2->resolve(reg.domain() + "/library/app@" + img.manifestDigest, info) == SBOX_OK);
        CHECK(info.repoTags.empty());

        // --> Unknown tag and unknown repository.
        SPullResult missing;
        CHECK(co_await client.pull(*store, reg.domain() + "/library/app:nope", missing) == -ENOENT);
        CHECK(client.lastError().find("MANIFEST_UNKNOWN") != std::string::npos);
        co_await reg.stop();
    }());
}

TEST_CASE("platform selection from an index, schema 1 rejection") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        REQUIRE(reg.start() == SBOX_OK);
        TestImage amd = sampleImage("amd64");
        TestImage arm = BuildImage({ { File("arm", "64") } }, "arm64");
        TestImage armv7 = BuildImage({ { File("arm", "32") } }, "arm");
        reg.add("multi", "", amd);
        reg.add("multi", "", arm);
        reg.add("multi", "", armv7);
        std::string index = BuildIndex({ { &amd, "linux/amd64" }, { &arm, "linux/arm64/v8" }, { &armv7, "linux/arm/v7" } }, true);
        reg.addManifest("multi", "latest", MT_DOCKER_MANIFEST_LIST, index);

        SRegistryOptions o = testOptions();
        SPlatform::parse("linux/arm64", o.platform);
        {
            CRegistryClient client(o);
            SPullResult res;
            REQUIRE(co_await client.pull(*store, reg.domain() + "/multi", res) == SBOX_OK);
            CHECK(res.imageId == arm.configDigest);
            CHECK(res.resolvedDigest == DigestOf(index));
            CHECK(res.manifestDigest == arm.manifestDigest);
            SImageInfo info;
            REQUIRE(store->resolve(reg.domain() + "/multi:latest", info) == SBOX_OK);
            CHECK(info.repoDigests.size() == 1);
            CHECK(info.repoDigests[0] == reg.domain() + "/multi@" + DigestOf(index));
            CHECK(store->hasBlob(DigestOf(index)));
        }

        {
            SPlatform::parse("linux/arm/v7", o.platform);
            CRegistryClient client(o);
            SPullResult res;
            REQUIRE(co_await client.pull(*store, reg.domain() + "/multi", res) == SBOX_OK);
            CHECK(res.imageId == armv7.configDigest);
        }

        {
            SPlatform::parse("linux/s390x", o.platform);
            CRegistryClient client(o);
            SPullResult res;
            CHECK(co_await client.pull(*store, reg.domain() + "/multi", res) == -ENOEXEC);
            CHECK(client.lastError().find("linux/s390x") != std::string::npos);
        }

        reg.addManifest("old", "v1", MT_DOCKER_SCHEMA1_SIGNED,
                        R"({"schemaVersion":1,"name":"old","tag":"v1","architecture":"amd64","fsLayers":[],"history":[]})");
        {
            CRegistryClient client(testOptions());
            SPullResult res;
            CHECK(co_await client.pull(*store, reg.domain() + "/old:v1", res) == -EPROTONOSUPPORT);
            CHECK(client.lastError().find("schema 1") != std::string::npos);
        }

        co_await reg.stop();
    }());
}

TEST_CASE("interrupted downloads resume with Range; corrupt blobs are rejected") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        REQUIRE(reg.start() == SBOX_OK);
        TestImage img = sampleImage();
        reg.add("resume/me", "v1", img);
        // --> The big layer's first response dies half way through.
        std::string bigLayer = img.layerDigests[0];
        reg.cutOnce[bigLayer] = img.blobs[bigLayer].size() / 2;

        std::vector<std::string> retries;
        SRegistryOptions o = testOptions();
        o.progress = [&retries](const SProgress& p) {
            if (p.phase == EPP_RETRYING) {
                retries.push_back(p.digest);
            }
        };

        CRegistryClient client(o);
        SPullResult res;
        int32_t r = co_await client.pull(*store, reg.domain() + "/resume/me:v1", res);
        CAPTURE(client.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(reg.rangeRequests >= 1);
        CHECK(!retries.empty());
        CHECK(store->hasBlob(bigLayer));
        std::string content;
        CHECK(store->readBlob(bigLayer, content, size_t(64) << 20) == SBOX_OK);

        // --> Same size, different bytes: every attempt fails verification.
        TestImage bad = BuildImage({ { File("x", "good") } });
        reg.add("bad/img", "v1", bad);
        std::string& blob = reg.blobs[bad.layerDigests[0]];
        blob[blob.size() / 2] ^= 0x55;
        SRegistryOptions o2 = testOptions();
        o2.maxAttempts = 2;
        CRegistryClient client2(o2);
        SPullResult res2;
        CHECK(co_await client2.pull(*store, reg.domain() + "/bad/img:v1", res2) == -EBADMSG);
        CHECK(!store->hasBlob(bad.layerDigests[0]));
        SImageInfo info;
        CHECK(store->resolve(reg.domain() + "/bad/img:v1", info) == -ENOENT);
        co_await reg.stop();
    }());
}

TEST_CASE("Basic credentials from config.json for the token endpoint") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        REQUIRE(reg.start() == SBOX_OK);
        reg.basicUser = "alice";
        reg.basicPassword = "s3cret:pw";
        TestImage img = BuildImage({ { File("private", "1") } });
        reg.add("private/app", "v1", img);

        std::string cfg = R"({"auths":{")" + reg.domain() + R"(":{"auth":")" + http::EncodeBasicAuth("alice", "s3cret:pw").substr(6) +
                          R"("}}})";
        REQUIRE(CFile::writeAtomic(tmp.sub("config.json"), cfg) == SBOX_OK);

        SRegistryOptions o = testOptions();
        {
            CRegistryClient anon(o);
            SPullResult res;
            CHECK(co_await anon.pull(*store, reg.domain() + "/private/app:v1", res) == -EACCES);
            CHECK(anon.lastError().find("incorrect username") != std::string::npos);
        }

        o.dockerConfig = tmp.sub("config.json");
        CRegistryClient client(o);
        SPullResult res;
        int32_t r = co_await client.pull(*store, reg.domain() + "/private/app:v1", res);
        CAPTURE(client.lastError());
        CHECK(r == SBOX_OK);

        // --> Explicit credentials win over config.json.
        SRegistryOptions o2 = testOptions();
        SRegistryAuth wrong;
        wrong.username = "alice";
        wrong.password = "nope";
        o2.credentials.emplace_back(reg.domain(), wrong);
        o2.dockerConfig = tmp.sub("config.json");
        CRegistryClient client2(o2);
        TempDir tmp2;
        CContentStorePtr store2;
        REQUIRE(CContentStore::open(tmp2.sub("store"), store2) == SBOX_OK);
        CHECK(co_await client2.pull(*store2, reg.domain() + "/private/app:v1", res) == -EACCES);
        co_await reg.stop();
    }());
}

TEST_CASE("mirrors are tried first and fall back to the registry") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        TestRegistry mirror;
        REQUIRE(reg.start() == SBOX_OK);
        REQUIRE(mirror.start() == SBOX_OK);
        TestImage a = BuildImage({ { File("a", "1") } });
        TestImage b = BuildImage({ { File("b", "2") } });
        reg.add("lib/a", "v1", a);
        reg.add("lib/b", "v1", b);
        mirror.add("lib/b", "v1", b);

        SRegistryOptions o = testOptions();
        o.mirrors.push_back(reg.domain() + "=" + mirror.base());
        CRegistryClient client(o);
        SPullResult ra;
        REQUIRE(co_await client.pull(*store, reg.domain() + "/lib/a:v1", ra) == SBOX_OK);
        CHECK(ra.endpoint == "http://" + reg.domain());
        SPullResult rb;
        REQUIRE(co_await client.pull(*store, reg.domain() + "/lib/b:v1", rb) == SBOX_OK);
        CHECK(rb.endpoint == mirror.base());
        CHECK(mirror.blobGets == 2);
        co_await mirror.stop();
        co_await reg.stop();
    }());
}

TEST_CASE("push: monolithic, chunked and cross-repository mount; tag listing") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        TestRegistry reg;
        REQUIRE(reg.start() == SBOX_OK);
        TestImage img = sampleImage();
        reg.add("src/app", "v1", img);

        CRegistryClient client(testOptions());
        SPullResult pulled;
        REQUIRE(co_await client.pull(*store, reg.domain() + "/src/app:v1", pulled) == SBOX_OK);

        // --> Layers came from src/app on the same registry: they are mounted, the config uploaded.
        SPushResult pushed;
        int32_t r = co_await client.push(*store, reg.domain() + "/src/app:v1", reg.domain() + "/dst/app:v2", pushed);
        CAPTURE(client.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(pushed.manifestDigest == img.manifestDigest);
        CHECK(pushed.blobsMounted == 2);
        CHECK(pushed.blobsUploaded == 1);
        CHECK(reg.mounts == 2);
        CHECK(reg.manifests["dst/app"]["v2"].second == img.manifest);

        // --> Pushing again: everything exists.
        SPushResult again;
        REQUIRE(co_await client.push(*store, reg.domain() + "/src/app:v1", reg.domain() + "/dst/app:v2", again) == SBOX_OK);
        CHECK(again.blobsExisting == 3);

        // --> A fresh image uploaded in 1000 byte chunks.
        TestImage fresh = BuildImage({ { File("payload", std::string(5000, 'p')) }, { File("more", std::string(2500, 'q')) } });
        for (const auto& [d, b] : fresh.blobs) {
            std::string stored;
            REQUIRE(store->writeBlob(BytesOf(b), stored, d) == SBOX_OK);
        }

        SDescriptor md;
        md.mediaType = fresh.manifestType;
        REQUIRE(store->writeBlob(BytesOf(fresh.manifest), md.digest, fresh.manifestDigest) == SBOX_OK);
        md.size = int64_t(fresh.manifest.size());
        REQUIRE(store->setRecord(reg.domain() + "/fresh/img:1", md) == SBOX_OK);

        SRegistryOptions chunked = testOptions();
        chunked.uploadChunkSize = 1000;
        CRegistryClient client2(chunked);
        SPushResult pr;
        r = co_await client2.push(*store, reg.domain() + "/fresh/img:1", "", pr);
        CAPTURE(client2.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(pr.blobsUploaded == 3);
        CHECK(reg.patches >= 3);
        for (const auto& [d, b] : fresh.blobs) {
            CHECK(reg.blobs[d] == b);
        }

        // --> Pull it back into another store.
        TempDir tmp2;
        CContentStorePtr store2;
        REQUIRE(CContentStore::open(tmp2.sub("store"), store2) == SBOX_OK);
        SPullResult back;
        REQUIRE(co_await client2.pull(*store2, reg.domain() + "/fresh/img:1", back) == SBOX_OK);
        CHECK(back.imageId == fresh.configDigest);

        std::vector<std::string> tags;
        reg.add("src/app", "v3", img);
        reg.add("src/app", "v2", img);
        REQUIRE(co_await client.listTags(reg.domain() + "/src/app", tags) == SBOX_OK);
        CHECK(tags == std::vector<std::string>{ "v1", "v2", "v3" });
        co_await reg.stop();
    }());
}

TEST_CASE("Docker config.json credentials") {
    TempDir tmp;
    std::string path = tmp.sub("config.json");
    std::string cfg = R"({
        "auths": {
            "https://index.docker.io/v1/": { "auth": ")" + http::EncodeBasicAuth("hubuser", "hubpass").substr(6) + R"(" },
            "registry.example.com:5000": { "username": "u2", "password": "p2" },
            "https://ghcr.io": { "auth": ")" + http::EncodeBasicAuth("gh", "tok").substr(6) + R"(", "identitytoken": "refresh" }
        },
        "credsStore": "desktop"
    })";
    REQUIRE(CFile::writeAtomic(path, cfg) == SBOX_OK);
    SRegistryAuth a;
    REQUIRE(LoadDockerCredentials(path, "docker.io", a) == SBOX_OK);
    CHECK(a.username == "hubuser");
    CHECK(a.password == "hubpass");
    REQUIRE(LoadDockerCredentials(path, "registry.example.com:5000", a) == SBOX_OK);
    CHECK(a.username == "u2");
    REQUIRE(LoadDockerCredentials(path, "ghcr.io", a) == SBOX_OK);
    CHECK(a.identityToken == "refresh");
    CHECK(LoadDockerCredentials(path, "quay.io", a) == -ENOENT);
    CHECK(LoadDockerCredentials(tmp.sub("missing.json"), "quay.io", a) == -ENOENT);
}
