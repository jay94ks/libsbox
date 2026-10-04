#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/image/gc.hpp>
#include <sbox/image/snapshot.hpp>

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

TEST_CASE("rmi semantics: untag, delete, conflicts") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    TestImage shared = BuildImage({ { File("base", "1") } });
    TestImage app = BuildImage({ { File("base", "1") }, { File("app", "2") } });
    REQUIRE(ImportImage(*store, shared, "base:1") == SBOX_OK);
    REQUIRE(ImportImage(*store, shared, "base:latest") == SBOX_OK);
    REQUIRE(ImportImage(*store, app, "app:1") == SBOX_OK);

    // --> By ID with two tags: needs force.
    SRemoveResult res;
    std::string error;
    CHECK(RemoveImage(*store, std::string(DigestHex(shared.configDigest)).substr(0, 12), false, res, &error) == -EEXIST);
    CHECK(error.find("multiple repositories") != std::string::npos);

    // --> Untag one of two names: the image stays.
    REQUIRE(RemoveImage(*store, "base:1", false, res) == SBOX_OK);
    CHECK(res.untagged == std::vector<std::string>{ "docker.io/library/base:1" });
    CHECK(res.deleted.empty());
    SImageInfo info;
    REQUIRE(store->resolve("base", info) == SBOX_OK);

    // --> The last tag deletes the image; the layer shared with app:1 stays.
    REQUIRE(RemoveImage(*store, "base", false, res) == SBOX_OK);
    REQUIRE(!res.deleted.empty());
    CHECK(res.deleted[0] == shared.configDigest);
    CHECK(store->resolve("base", info) == -ENOENT);
    CHECK(!store->hasBlob(shared.configDigest));
    CHECK(!store->hasBlob(shared.manifestDigest));
    CHECK(store->hasBlob(shared.layerDigests[0]));
    CHECK(store->hasBlob(app.layerDigests[1]));

    // --> An image used by a container root needs force.
    REQUIRE(store->resolve("app:1", info) == SBOX_OK);
    CSnapshotter snap(store);
    SContainerInfo c;
    REQUIRE(snap.prepare("user1", info, ESNAP_COPY, c) == SBOX_OK);
    CHECK(RemoveImage(*store, "app:1", false, res, &error) == -EBUSY);
    CHECK(error.find("user1") != std::string::npos);
    REQUIRE(RemoveImage(*store, "app:1", true, res) == SBOX_OK);
    CHECK(store->resolve("app:1", info) == -ENOENT);
    // --> The container still holds its blobs.
    CHECK(store->hasBlob(app.manifestDigest));
    CHECK(store->hasBlob(app.layerDigests[1]));
    REQUIRE(snap.remove("user1") == SBOX_OK);
    SGcResult gc;
    REQUIRE(CollectGarbage(*store, SGcOptions(), gc) == SBOX_OK);
    CHECK(store->listBlobs().empty());
    CHECK(RemoveImage(*store, "nothing:here", false, res) == -ENOENT);
}

TEST_CASE("garbage collection keeps referenced content and leases") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    TestImage keep = BuildImage({ { File("k", "1") } });
    TestImage dangling = BuildImage({ { File("d", "1") } });
    TestImage leased = BuildImage({ { File("l", "1") } });
    REQUIRE(ImportImage(*store, keep, "keep:1") == SBOX_OK);
    REQUIRE(ImportImage(*store, dangling, "") == SBOX_OK);
    std::string orphan;
    REQUIRE(store->writeBlob(BytesOf(std::string_view("orphan")), orphan) == SBOX_OK);
    for (const auto& [d, b] : leased.blobs) {
        std::string s;
        REQUIRE(store->writeBlob(BytesOf(b), s, d) == SBOX_OK);
    }

    // --> Snapshots of kept and of removed images.
    SSnapshotterOptions so;
    so.rootless = IsRoot() ? 0 : 1;
    CSnapshotter snap(store, so);
    SImageInfo keepInfo;
    REQUIRE(store->resolve("keep:1", keepInfo) == SBOX_OK);
    REQUIRE(snap.unpack(keepInfo) == SBOX_OK);
    SImageInfo dangInfo;
    REQUIRE(store->resolve(dangling.configDigest, dangInfo) == SBOX_OK);
    REQUIRE(snap.unpack(dangInfo) == SBOX_OK);

    CLease lease;
    REQUIRE(lease.open(*store) == SBOX_OK);
    for (const auto& [d, b] : leased.blobs) {
        lease.addBlob(d);
    }

    // --> Dry run changes nothing.
    SGcOptions dry;
    dry.dryRun = true;
    dry.pruneDangling = true;
    SGcResult res;
    REQUIRE(CollectGarbage(*store, dry, res) == SBOX_OK);
    CHECK(res.removedImages == std::vector<std::string>{ dangling.configDigest });
    CHECK(std::find(res.removedBlobs.begin(), res.removedBlobs.end(), orphan) != res.removedBlobs.end());
    CHECK(res.removedSnapshots.size() == 1);
    CHECK(store->hasBlob(orphan));

    // --> Without pruning, the dangling image survives; the orphan goes.
    REQUIRE(CollectGarbage(*store, SGcOptions(), res) == SBOX_OK);
    CHECK(res.removedBlobs == std::vector<std::string>{ orphan });
    CHECK(res.removedSnapshots.empty());
    CHECK(store->hasBlob(dangling.manifestDigest));
    for (const auto& [d, b] : leased.blobs) {
        CHECK(store->hasBlob(d));
    }

    // --> Pruning dangling images removes them and their snapshots.
    SGcOptions prune;
    prune.pruneDangling = true;
    REQUIRE(CollectGarbage(*store, prune, res) == SBOX_OK);
    CHECK(res.removedImages == std::vector<std::string>{ dangling.configDigest });
    CHECK(!store->hasBlob(dangling.manifestDigest));
    CHECK(!snap.hasSnapshot(ChainIds(dangling.diffIds)[0]));
    CHECK(snap.hasSnapshot(ChainIds(keep.diffIds)[0]));
    CHECK(store->hasBlob(keep.layerDigests[0]));

    // --> Once the lease is gone its blobs are collected.
    lease.release();
    REQUIRE(CollectGarbage(*store, SGcOptions(), res) == SBOX_OK);
    for (const auto& [d, b] : leased.blobs) {
        CHECK(!store->hasBlob(d));
    }

    // --> prune -a removes every image without a container.
    SGcOptions all;
    all.pruneUnused = true;
    REQUIRE(CollectGarbage(*store, all, res) == SBOX_OK);
    CHECK(res.removedImages == std::vector<std::string>{ keep.configDigest });
    CHECK(store->listBlobs().empty());
    std::vector<SSnapshotInfo> snaps;
    snap.listSnapshots(snaps);
    CHECK(snaps.empty());
}
