#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

TEST_CASE("the store is an OCI image layout") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    CJson layout;
    REQUIRE(CJson::parse(ReadText(tmp.sub("store/oci-layout")), layout) == SBOX_OK);
    CHECK(layout.get("imageLayoutVersion").asString() == "1.0.0");

    TestImage img = BuildImage({ { File("a", "1") } });
    REQUIRE(ImportImage(*store, img, "alpine") == SBOX_OK);
    CHECK(CFile::exists(tmp.sub("store/blobs/sha256/" + std::string(DigestHex(img.manifestDigest)))));

    CJson index;
    REQUIRE(CJson::parse(ReadText(tmp.sub("store/index.json")), index) == SBOX_OK);
    CHECK(index.get("schemaVersion").asInt() == 2);
    CHECK(index.get("mediaType").asString() == MT_OCI_INDEX);
    REQUIRE(index.get("manifests").size() == 1);
    const CJson& entry = index.get("manifests").at(0);
    CHECK(entry.get("digest").asString() == img.manifestDigest);
    CHECK(entry.get("size").asInt() == int64_t(img.manifest.size()));
    CHECK(entry.get("annotations").get(ANNOTATION_IMAGE_NAME).asString() == "docker.io/library/alpine:latest");
    CHECK(entry.get("annotations").get(ANNOTATION_REF_NAME).asString() == "latest");

    // --> A second store object over the same root sees the same content.
    CContentStorePtr again;
    REQUIRE(CContentStore::open(tmp.sub("store"), again) == SBOX_OK);
    SImageInfo info;
    REQUIRE(again->resolve("alpine:latest", info) == SBOX_OK);
    CHECK(info.id == img.configDigest);
    REQUIRE(again->resolve("docker.io/library/alpine", info) == SBOX_OK);
    REQUIRE(again->resolve(img.configDigest, info) == SBOX_OK);
    REQUIRE(again->resolve(std::string(DigestHex(img.configDigest)), info) == SBOX_OK);
    REQUIRE(again->resolve(std::string(DigestHex(img.configDigest)).substr(0, 6), info) == SBOX_OK);
    CHECK(again->resolve("busybox", info) == -ENOENT);
    CHECK(again->resolve("ffffffffffff", info) == -ENOENT);

    // --> Moving a tag leaves the old image dangling; tagging an image again names it.
    TestImage newer = BuildImage({ { File("a", "2") } });
    REQUIRE(ImportImage(*store, newer, "alpine:latest") == SBOX_OK);
    std::vector<SImageInfo> images;
    REQUIRE(store->listImages(images) == SBOX_OK);
    REQUIRE(images.size() == 2);
    int dangling = 0;
    for (const SImageInfo& i : images) {
        dangling += i.repoTags.empty();
        if (i.id == newer.configDigest) {
            CHECK(i.repoTags == std::vector<std::string>{ "docker.io/library/alpine:latest" });
        }
    }

    CHECK(dangling == 1);
    REQUIRE(store->setRecord("old/alpine:keep", info.manifestDescriptor) == SBOX_OK);
    REQUIRE(store->listImages(images) == SBOX_OK);
    for (const SImageInfo& i : images) {
        CHECK(!i.repoTags.empty());
    }

    CHECK(store->setRecord("Bad Name", info.manifestDescriptor) == -EINVAL);
    CHECK(store->removeRecord("nope:1") == -ENOENT);
    REQUIRE(store->removeRecord("old/alpine:keep") == SBOX_OK);

    // --> Ambiguous short IDs.
    std::vector<TestImage> many;
    for (int i = 0; i < 40; ++i) {
        many.push_back(BuildImage({ { File("n", std::to_string(i)) } }));
        REQUIRE(ImportImage(*store, many.back(), "many:" + std::to_string(i)) == SBOX_OK);
    }

    bool ambiguous = false;
    for (char c : std::string("0123456789abcdef")) {
        int count = 0;
        for (const TestImage& t : many) {
            count += DigestHex(t.configDigest)[0] == c;
        }

        if (count > 1) {
            CHECK(store->resolve(std::string(1, c), info) == -EEXIST);
            ambiguous = true;
            break;
        }
    }

    CHECK(ambiguous);
}

TEST_CASE("blob ingestion is verified, atomic and resumable") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    std::string data = "hello blob";
    std::string digest;
    REQUIRE(store->writeBlob(BytesOf(data), digest) == SBOX_OK);
    CHECK(digest == DigestOf(data));
    CHECK(store->blobSize(digest) == int64_t(data.size()));
    std::string back;
    REQUIRE(store->readBlob(digest, back) == SBOX_OK);
    CHECK(back == data);
    CHECK(store->writeBlob(BytesOf(data), digest, "sha256:" + std::string(64, '0')) == -EBADMSG);
    CHECK(store->listBlobs() == std::vector<std::string>{ DigestOf(data) });

    // --> A corrupted blob on disk is detected when read.
    REQUIRE(CFile::writeAtomic(store->blobPath(DigestOf(data)), "hello BLOB") == SBOX_OK);
    CHECK(store->readBlob(DigestOf(data), back) == -EBADMSG);

    // --> Named ingests: a second writer is refused, a later one resumes.
    std::string payload(100000, 'z');
    std::string pd = DigestOf(payload);
    {
        CBlobWriter w;
        REQUIRE(w.open(*store, "x.partial", true) == SBOX_OK);
        REQUIRE(w.write(SReadOnlyByteSpan(BytesOf(payload).data, 40000)) == SBOX_OK);
        CBlobWriter other;
        CHECK(other.open(*store, "x.partial", true) == -EBUSY);
    }

    CHECK(CFile::exists(store->path("ingest/x.partial")));
    {
        CBlobWriter w;
        REQUIRE(w.open(*store, "x.partial", true) == SBOX_OK);
        CHECK(w.offset() == 40000);
        REQUIRE(w.write(BytesOf(payload).slice(40000)) == SBOX_OK);
        REQUIRE(w.commit(pd, int64_t(payload.size())) == SBOX_OK);
    }

    CHECK(store->hasBlob(pd));
    CHECK(!CFile::exists(store->path("ingest/x.partial")));

    // --> Wrong size or digest discards the ingest.
    {
        CBlobWriter w;
        REQUIRE(w.open(*store) == SBOX_OK);
        REQUIRE(w.write(BytesOf(std::string_view("abc"))) == SBOX_OK);
        std::string path = w.path();
        CHECK(w.commit(DigestOf(std::string_view("abc")), 4) == -EBADMSG);
        CHECK(!CFile::exists(path));
    }

    // --> Unnamed ingests vanish when abandoned.
    std::string abandoned;
    {
        CBlobWriter w;
        REQUIRE(w.open(*store) == SBOX_OK);
        abandoned = w.path();
        CHECK(CFile::exists(abandoned));
    }

    CHECK(!CFile::exists(abandoned));
}

TEST_CASE("leases are visible while held") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    std::vector<std::string> blobs;
    std::vector<std::string> snaps;
    {
        CLease lease;
        REQUIRE(lease.open(*store) == SBOX_OK);
        REQUIRE(lease.addBlob("sha256:" + std::string(64, '1')) == SBOX_OK);
        REQUIRE(lease.addSnapshot("sha256:" + std::string(64, '2')) == SBOX_OK);
        REQUIRE(CLease::collect(*store, blobs, snaps) == SBOX_OK);
        CHECK(blobs == std::vector<std::string>{ "sha256:" + std::string(64, '1') });
        CHECK(snaps == std::vector<std::string>{ "sha256:" + std::string(64, '2') });
    }

    blobs.clear();
    snaps.clear();
    REQUIRE(CLease::collect(*store, blobs, snaps) == SBOX_OK);
    CHECK(blobs.empty());

    // --> A stale lease file (its process died) is removed.
    REQUIRE(CFile::writeAtomic(store->path("leases/dead.json"), "{\"blobs\":[\"x\"]}") == SBOX_OK);
    REQUIRE(CLease::collect(*store, blobs, snaps) == SBOX_OK);
    CHECK(blobs.empty());
    CHECK(!CFile::exists(store->path("leases/dead.json")));
}
