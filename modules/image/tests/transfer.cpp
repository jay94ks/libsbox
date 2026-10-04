#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/image/snapshot.hpp>
#include <sbox/image/transfer.hpp>

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

namespace {

    /* Reads every member of a tar held in memory. */
    std::map<std::string, std::string> readTar(const std::vector<uint8_t>& bytes) {
        std::map<std::string, std::string> out;
        archive::CMemorySource src(SReadOnlyByteSpan(bytes.data(), bytes.size()));
        archive::CTarReader reader(src);
        archive::STarEntry e;
        while (reader.next(e) == 1) {
            std::string data;
            std::vector<uint8_t> buf(65536);
            while (true) {
                SIoResult io = reader.read(SByteSpan(buf.data(), buf.size()));
                if (!io.ok() || io.bytes == 0) {
                    break;
                }

                data.append(reinterpret_cast<const char*>(buf.data()), io.bytes);
            }

            out[e.path] = data;
        }

        return out;
    }

    /* Builds a tar from (path, data) pairs. */
    std::vector<uint8_t> writeTar(const std::vector<std::pair<std::string, std::string>>& files) {
        std::vector<uint8_t> out;
        archive::CVectorSink sink(out);
        archive::CTarWriter w(sink);
        for (const auto& [path, data] : files) {
            archive::STarEntry e;
            e.path = path;
            e.size = data.size();
            w.writeEntry(e, BytesOf(data));
        }

        w.finish();
        return out;
    }

    /* Loads an in-memory archive into a store. */
    int32_t loadBytes(CContentStore& store, const std::vector<uint8_t>& bytes, SLoadResult& res, std::string* error = nullptr,
                      const SLoadOptions& options = SLoadOptions()) {
        archive::CMemorySource src(SReadOnlyByteSpan(bytes.data(), bytes.size()));
        return LoadImageArchive(store, src, options, res, error);
    }

    TestImage appImage() {
        return BuildImage({ { Dir("app"), File("app/main", "#!/bin/sh\necho hi\n", 0755), File("app/remove-me", "x") },
                            { File("app/.wh.remove-me", ""), File("app/config", "cfg") } });
    }

}

TEST_CASE("docker save / docker load round trip") {
    TempDir tmp;
    CContentStorePtr a;
    REQUIRE(CContentStore::open(tmp.sub("a"), a) == SBOX_OK);
    TestImage app = appImage();
    TestImage other = BuildImage({ { File("other", "1") } }, "", true);
    REQUIRE(ImportImage(*a, app, "example/app:v1") == SBOX_OK);
    REQUIRE(ImportImage(*a, app, "example/app:v2") == SBOX_OK);
    REQUIRE(ImportImage(*a, other, "other:1") == SBOX_OK);

    std::vector<uint8_t> tarBytes;
    archive::CVectorSink sink(tarBytes);
    std::string error;
    REQUIRE(SaveDockerArchive(*a, { "example/app:v1", "other:1" }, sink, &error) == SBOX_OK);
    std::map<std::string, std::string> files = readTar(tarBytes);
    REQUIRE(files.count("manifest.json"));
    REQUIRE(files.count("oci-layout"));
    REQUIRE(files.count("index.json"));
    REQUIRE(files.count("repositories"));

    CJson manifest;
    REQUIRE(CJson::parse(files["manifest.json"], manifest) == SBOX_OK);
    REQUIRE(manifest.size() == 2);
    const CJson& first = manifest.at(0);
    CHECK(first.get("RepoTags").asStrings() == std::vector<std::string>{ "example/app:v1" });
    CHECK(first.get("Config").asString() == "blobs/sha256/" + std::string(DigestHex(app.configDigest)));
    std::vector<std::string> layers = first.get("Layers").asStrings();
    REQUIRE(layers.size() == 2);
    // --> Layers are uncompressed: the file digest is the diffID.
    CHECK(DigestOf(files[layers[0]]) == app.diffIds[0]);
    CHECK(DigestOf(files[layers[1]]) == app.diffIds[1]);
    CHECK(DigestOf(files[first.get("Config").asString()]) == app.configDigest);
    CJson repos;
    REQUIRE(CJson::parse(files["repositories"], repos) == SBOX_OK);
    CHECK(repos.get("example/app").get("v1").isString());
    CHECK(manifest.at(1).get("RepoTags").asStrings() == std::vector<std::string>{ "other:1" });

    // --> A bare repository name exports every tag of it.
    std::vector<uint8_t> both;
    archive::CVectorSink sink2(both);
    REQUIRE(SaveDockerArchive(*a, { "example/app" }, sink2) == SBOX_OK);
    CJson m2;
    REQUIRE(CJson::parse(readTar(both)["manifest.json"], m2) == SBOX_OK);
    CHECK(m2.at(0).get("RepoTags").size() == 2);

    // --> By image ID: no tags.
    std::vector<uint8_t> byId;
    archive::CVectorSink sink3(byId);
    REQUIRE(SaveDockerArchive(*a, { std::string(DigestHex(app.configDigest)).substr(0, 12) }, sink3) == SBOX_OK);
    CJson m3;
    REQUIRE(CJson::parse(readTar(byId)["manifest.json"], m3) == SBOX_OK);
    CHECK(m3.at(0).get("RepoTags").isNull());

    CContentStorePtr b;
    REQUIRE(CContentStore::open(tmp.sub("b"), b) == SBOX_OK);
    SLoadResult res;
    REQUIRE(loadBytes(*b, tarBytes, res, &error) == SBOX_OK);
    CHECK(res.format == "docker");
    CHECK(res.tags == std::vector<std::string>{ "docker.io/example/app:v1", "docker.io/library/other:1" });
    CHECK(res.imageIds == std::vector<std::string>{ app.configDigest, other.configDigest });
    SImageInfo loaded;
    REQUIRE(b->resolve("example/app:v1", loaded) == SBOX_OK);
    CHECK(loaded.id == app.configDigest);
    CHECK(loaded.manifest.layers[0].mediaType == MT_OCI_LAYER);
    CHECK(loaded.manifest.layers[0].digest == app.diffIds[0]);

    // --> The archive's own manifest was reused: saving again yields the same manifest digest.
    CJson index;
    REQUIRE(CJson::parse(readTar(tarBytes)["index.json"], index) == SBOX_OK);
    CHECK(index.get("manifests").at(0).get("digest").asString() == loaded.manifestDigest);
    CHECK(index.get("manifests").at(0).get("annotations").get(ANNOTATION_IMAGE_NAME).asString() == "docker.io/example/app:v1");
    CHECK(index.get("manifests").at(0).get("annotations").get(ANNOTATION_REF_NAME).asString() == "v1");

    CSnapshotter snap(b);
    std::string flat = tmp.sub("flat");
    REQUIRE(snap.flatten(loaded, flat) == SBOX_OK);
    CHECK(ReadText(CFile::join(flat, "app/config")) == "cfg");
    CHECK(!CFile::exists(CFile::join(flat, "app/remove-me")));

    // --> Loading the same archive gzip-compressed is the same.
    std::string gz = Gzip(std::string(tarBytes.begin(), tarBytes.end()));
    CContentStorePtr c;
    REQUIRE(CContentStore::open(tmp.sub("c"), c) == SBOX_OK);
    SLoadResult res2;
    REQUIRE(loadBytes(*c, std::vector<uint8_t>(gz.begin(), gz.end()), res2) == SBOX_OK);
    CHECK(res2.imageIds == res.imageIds);
}

TEST_CASE("load a hand-built docker save archive (classic layout)") {
    TempDir tmp;
    std::string tar1 = BuildTar({ Dir("etc"), File("etc/os-release", "ID=test\n"), File("bin-sh", "binary", 0755) });
    std::string tar2 = BuildTar({ File(".wh.bin-sh", ""), File("etc/motd", "hello\n") });
    std::string diff1 = DigestOf(tar1);
    std::string diff2 = DigestOf(tar2);
    CJson cfg;
    REQUIRE(CJson::parse(R"({"architecture":"amd64","os":"linux","config":{"Cmd":["/bin-sh"],"Env":["A=1"]},
        "rootfs":{"type":"layers","diff_ids":[")" + diff1 + R"(",")" + diff2 + R"("]},"history":[{},{}]})", cfg) == SBOX_OK);
    std::string config = cfg.dump();
    std::string configHex(DigestHex(DigestOf(config)));
    std::string v1a(64, 'a');
    std::string v1b(64, 'b');
    std::string manifest = R"([{"Config":")" + configHex + R"(.json","RepoTags":["legacy/img:latest","legacy/img:1.0"],"Layers":[")" +
                           v1a + R"(/layer.tar",")" + v1b + R"(/layer.tar"]}])";
    std::vector<uint8_t> bytes = writeTar({
        { v1a + "/VERSION", "1.0" },
        { v1a + "/json", "{\"id\":\"" + v1a + "\"}" },
        { v1a + "/layer.tar", tar1 },
        { v1b + "/VERSION", "1.0" },
        { v1b + "/json", "{\"id\":\"" + v1b + "\",\"parent\":\"" + v1a + "\"}" },
        { v1b + "/layer.tar", Gzip(tar2) },
        { configHex + ".json", config },
        { "repositories", "{\"legacy/img\":{\"latest\":\"" + v1b + "\"}}" },
        { "manifest.json", manifest },
    });

    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("s"), store) == SBOX_OK);
    SLoadResult res;
    std::string error;
    int32_t r = loadBytes(*store, bytes, res, &error);
    CAPTURE(error);
    REQUIRE(r == SBOX_OK);
    CHECK(res.tags.size() == 2);
    SImageInfo info;
    REQUIRE(store->resolve("legacy/img", info) == SBOX_OK);
    CHECK(info.id == "sha256:" + configHex);
    CHECK(info.repoTags.size() == 2);
    CHECK(info.manifest.layers[1].mediaType == MT_OCI_LAYER_GZIP);
    CHECK(store->diffIdOf(info.manifest.layers[1].digest) == diff2);
    CSnapshotter snap(store);
    std::string flat = tmp.sub("flat");
    REQUIRE(snap.flatten(info, flat) == SBOX_OK);
    CHECK(ReadText(CFile::join(flat, "etc/os-release")) == "ID=test\n");
    CHECK(ReadText(CFile::join(flat, "etc/motd")) == "hello\n");
    CHECK(!CFile::exists(CFile::join(flat, "bin-sh")));

    // --> A layer that does not match the config's diffID is refused.
    std::string badManifest = R"([{"Config":")" + configHex + R"(.json","RepoTags":["bad/img:1"],"Layers":[")" + v1b +
                              R"(/layer.tar",")" + v1a + R"(/layer.tar"]}])";
    std::vector<uint8_t> bad = writeTar({ { v1a + "/layer.tar", tar1 }, { v1b + "/layer.tar", tar2 }, { configHex + ".json", config },
                                          { "manifest.json", badManifest } });
    SLoadResult badRes;
    CHECK(loadBytes(*store, bad, badRes, &error) == -EBADMSG);
    CHECK(error.find("diffID") != std::string::npos);
    CHECK(store->resolve("bad/img:1", info) == -ENOENT);

    // --> Members escaping the archive root are not followed.
    std::vector<uint8_t> escape = writeTar({ { "manifest.json", R"([{"Config":"../../etc/passwd","RepoTags":[],"Layers":[]}])" } });
    CHECK(loadBytes(*store, escape, badRes, &error) != SBOX_OK);

    std::vector<uint8_t> junk = writeTar({ { "hello.txt", "hi" } });
    CHECK(loadBytes(*store, junk, badRes, &error) == -EINVAL);
}

TEST_CASE("OCI archive export and import") {
    TempDir tmp;
    CContentStorePtr a;
    REQUIRE(CContentStore::open(tmp.sub("a"), a) == SBOX_OK);
    TestImage app = appImage();
    REQUIRE(ImportImage(*a, app, "ghcr.io/example/app:2.0") == SBOX_OK);
    std::vector<uint8_t> bytes;
    archive::CVectorSink sink(bytes);
    REQUIRE(SaveOciArchive(*a, { "ghcr.io/example/app:2.0" }, sink) == SBOX_OK);
    std::map<std::string, std::string> files = readTar(bytes);
    CHECK(files.count("oci-layout"));
    CHECK(files.count("blobs/sha256/" + std::string(DigestHex(app.layerDigests[0]))));
    CJson index;
    REQUIRE(CJson::parse(files["index.json"], index) == SBOX_OK);
    CHECK(index.get("manifests").at(0).get("digest").asString() == app.manifestDigest);

    CContentStorePtr b;
    REQUIRE(CContentStore::open(tmp.sub("b"), b) == SBOX_OK);
    SLoadResult res;
    REQUIRE(loadBytes(*b, bytes, res) == SBOX_OK);
    CHECK(res.format == "oci");
    CHECK(res.tags == std::vector<std::string>{ "ghcr.io/example/app:2.0" });
    SImageInfo info;
    REQUIRE(b->resolve("ghcr.io/example/app:2.0", info) == SBOX_OK);
    CHECK(info.manifestDigest == app.manifestDigest);

    // --> An OCI layout with only a tag in ref.name and a nested multi-platform index.
    TestImage other = BuildImage({ { File("arm", "1") } }, "arm64");
    std::string idxText = BuildIndex({ { &app, HostPlatform().toString() }, { &other, "linux/arm64" } });
    SIndex top;
    top.mediaType = MT_OCI_INDEX;
    SDescriptor d;
    d.mediaType = MT_OCI_INDEX;
    d.digest = DigestOf(idxText);
    d.size = int64_t(idxText.size());
    d.annotation(ANNOTATION_REF_NAME, "v9");
    top.manifests.push_back(d);
    std::vector<std::pair<std::string, std::string>> members = { { "oci-layout", "{\"imageLayoutVersion\":\"1.0.0\"}" },
                                                                 { "index.json", top.toJson().dump() },
                                                                 { "blobs/sha256/" + std::string(DigestHex(d.digest)), idxText },
                                                                 { "blobs/sha256/" + std::string(DigestHex(app.manifestDigest)), app.manifest },
                                                                 { "blobs/sha256/" + std::string(DigestHex(other.manifestDigest)), other.manifest } };
    for (const TestImage* img : { &app, &other }) {
        for (const auto& [dg, blob] : img->blobs) {
            members.emplace_back("blobs/sha256/" + std::string(DigestHex(dg)), blob);
        }
    }

    CContentStorePtr c;
    REQUIRE(CContentStore::open(tmp.sub("c"), c) == SBOX_OK);
    SLoadOptions lo;
    lo.name = "imported/thing";
    SLoadResult res2;
    std::string error;
    int32_t r = loadBytes(*c, writeTar(members), res2, &error, lo);
    CAPTURE(error);
    REQUIRE(r == SBOX_OK);
    CHECK(res2.tags == std::vector<std::string>{ "docker.io/imported/thing:v9" });
    REQUIRE(c->resolve("imported/thing:v9", info) == SBOX_OK);
    CHECK(info.id == app.configDigest);

    // --> A corrupted blob is refused.
    members[3].second[10] ^= 1;
    CContentStorePtr e;
    REQUIRE(CContentStore::open(tmp.sub("e"), e) == SBOX_OK);
    CHECK(loadBytes(*e, writeTar(members), res2, &error, lo) == -EBADMSG);
}
