#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/image/registry.hpp>
#include <sbox/image/snapshot.hpp>

// Live pulls from Docker Hub. Only run with SBOX_TEST_NETWORK=1 (HTTPS_PROXY and SSL_CERT_FILE
// from the environment are honoured).

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

namespace {

    bool networkEnabled() {
        const char* v = std::getenv("SBOX_TEST_NETWORK");
        return v && std::string(v) == "1";
    }

    TTask<void> pullAndCheck(const std::string& reference, const std::string& expectFile) {
        TempDir tmp;
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        SRegistryOptions o;
        o.proxy = http::SProxyConfig::fromEnvironment();
        o.unpack = true;
        uint64_t layers = 0;
        o.progress = [&layers](const SProgress& p) {
            if (p.phase == EPP_VERIFIED) {
                ++layers;
            }
        };

        CRegistryClient client(o);
        SPullResult res;
        int64_t start = CEventLoop::nowMs();
        int32_t r = co_await client.pull(*store, reference, res);
        CAPTURE(client.lastError());
        REQUIRE(r == SBOX_OK);
        MESSAGE("pulled " << res.reference << " (" << res.resolvedDigest << ") -> manifest " << res.manifestDigest << ", image "
                          << res.imageId << ", " << res.downloadedBytes << " bytes in " << (CEventLoop::nowMs() - start) << " ms");
        CHECK(res.image.config.os == "linux");
        CHECK(res.image.config.architecture == HostPlatform().architecture);

        CSnapshotter snap(store);
        std::vector<SSnapshotInfo> snaps;
        REQUIRE(snap.listSnapshots(snaps) == SBOX_OK);
        CHECK(snaps.size() == res.image.manifest.layers.size());

        std::string flat = tmp.sub("flat");
        REQUIRE(snap.flatten(res.image, flat) == SBOX_OK);
        CHECK(CFile::exists(CFile::join(flat, expectFile)));
    }

}

TEST_CASE("live pull of docker.io/library/alpine:latest") {
    if (!networkEnabled()) {
        MESSAGE("skipped: set SBOX_TEST_NETWORK=1 to pull from Docker Hub");
        return;
    }

    CEventLoop loop;
    loop.run(pullAndCheck("alpine:latest", "etc/alpine-release"));
}

TEST_CASE("live pull of docker.io/library/busybox") {
    if (!networkEnabled()) {
        MESSAGE("skipped: set SBOX_TEST_NETWORK=1 to pull from Docker Hub");
        return;
    }

    CEventLoop loop;
    loop.run(pullAndCheck("busybox", "bin/busybox"));
}
