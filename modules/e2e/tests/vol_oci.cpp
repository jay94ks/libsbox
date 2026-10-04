// vol -> oci: `-v name:/data`, a read-only bind and a tmpfs are turned into config.json mounts by
// PrepareContainerMounts; data a container writes stays in the volume for the next container;
// the volume survives a backup / remove / restore round trip (library and sboxvol CLI).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
#include <sbox/vol/backup.hpp>
#include <sbox/vol/mount.hpp>
#include <sbox/vol/store.hpp>

using namespace sbox;
using namespace e2e;

namespace {

    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root (or no private mount namespace); skipping");
            return false;
        }

        if (!haveTools()) {
            MESSAGE("CLI tools were not built; skipping");
            return false;
        }

        return true;
    }

    /**
     * Parses the Docker flags of one container into mount requests.
     */
    std::vector<vol::SMountRequest> parseFlags(const std::vector<std::string>& volumes, const std::vector<std::string>& mounts,
                                               const std::vector<std::string>& tmpfs) {
        std::vector<vol::SMountRequest> out;
        for (const std::string& v : volumes) {
            vol::SMountRequest r;
            std::string error;
            REQUIRE_MESSAGE(vol::ParseVolumeFlag(v, r, &error) == SBOX_OK, error);
            out.push_back(r);
        }

        for (const std::string& m : mounts) {
            vol::SMountRequest r;
            std::string error;
            REQUIRE_MESSAGE(vol::ParseMountFlag(m, r, &error) == SBOX_OK, error);
            out.push_back(r);
        }

        for (const std::string& t : tmpfs) {
            vol::SMountRequest r;
            std::string error;
            REQUIRE_MESSAGE(vol::ParseTmpfsFlag(t, r, &error) == SBOX_OK, error);
            out.push_back(r);
        }

        return out;
    }

    /**
     * Prepares the mounts of container `id` and writes a bundle running `script`.
     */
    TTask<void> prepareBundle(vol::CVolumeStore& store, std::string bundle, std::string id, std::vector<vol::SMountRequest> requests,
                              std::string script) {
        std::vector<CJson> mounts;
        std::string error;
        int32_t r = co_await vol::PrepareContainerMounts(store, std::move(requests), id, bundle + "/rootfs", mounts, &error);
        REQUIRE_MESSAGE(r == SBOX_OK, error);

        std::vector<std::string> args;
        args.push_back("/bin/sh");
        args.push_back("-c");
        args.push_back(std::move(script));
        CJson config = defaultConfig(std::move(args));
        for (CJson& m : mounts) {
            config["mounts"].push(std::move(m));
        }

        REQUIRE(writeConfig(bundle, config));
    }

}

TEST_CASE("a named volume, a read-only bind and a tmpfs reach the container; data persists and survives backup and restore") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    REQUIRE(makeRootfs(bundle + "/rootfs"));
    // --> Image content at the volume's target: copied up into the empty volume on first use.
    CFile::makeDirs(bundle + "/rootfs/data", 0755);
    CFile::writeAtomic(bundle + "/rootfs/data/seed.txt", "from the image\n", 0644);

    std::string hostDir = tmp / "host";
    CFile::makeDirs(hostDir, 0755);
    CFile::writeAtomic(hostDir + "/hello.txt", "host file\n", 0644);

    CEventLoop loop;
    loop.run([](const TempDir& t, std::string bundleDir, std::string host) -> TTask<void> {
        vol::SVolumeStoreOptions so;
        so.root = t / "volumes";
        vol::CVolumeStore store(so);
        std::string state = t / "state";

        // --> First container: sees the copied-up seed, writes into the volume, reads the bind,
        // cannot write it, and has a size-limited tmpfs.
        std::string id1 = "e2e-vol1-" + randomSuffix();
        std::vector<vol::SMountRequest> req1 = parseFlags({ "e2edata:/data" }, { "type=bind,src=" + host + ",dst=/host,readonly" }, { "/scratch:size=1m" });
        co_await prepareBundle(store, bundleDir, id1, req1,
            "cat /data/seed.txt; echo persisted > /data/out.txt; cat /host/hello.txt; "
            "if touch /host/x 2>/dev/null; then echo bind-writable; else echo bind-ro; fi; "
            "echo t > /scratch/t && cat /scratch/t; "
            "if head -c 2000000 /dev/zero > /scratch/big 2>/dev/null; then echo tmpfs-unbounded; else echo tmpfs-full; fi");
        ContainerRun r1 = co_await runContainer(state, bundleDir, id1);
        REQUIRE_MESSAGE(r1.error == SBOX_OK, r1.message);
        CHECK(r1.code == 0);
        CHECK(r1.out == "from the image\nhost file\nbind-ro\nt\ntmpfs-full\n");
        CHECK_FALSE(CFile::exists(host + "/x"));

        vol::SVolume v;
        REQUIRE(store.inspect("e2edata", v) == SBOX_OK);
        CHECK(v.users.size() == 1);
        std::string onHost;
        CHECK(CFile::readAll(v.mountpoint + "/out.txt", onHost) == SBOX_OK);
        CHECK(onHost == "persisted\n");

        // --> Removing the container releases the volume; the data stays.
        CHECK(co_await store.releaseUser(id1, true) == SBOX_OK);
        REQUIRE(store.inspect("e2edata", v) == SBOX_OK);
        CHECK(v.users.empty());

        // --> Second container (run with the CLI) reads what the first one wrote.
        std::string id2 = "e2e-vol2-" + randomSuffix();
        std::vector<vol::SMountRequest> req2 = parseFlags({ "e2edata:/data:ro" }, {}, {});
        co_await prepareBundle(store, bundleDir, id2, req2,
            "cat /data/out.txt; if echo x > /data/y 2>/dev/null; then echo vol-writable; else echo vol-ro; fi");
        ToolResult r2 = co_await runTool(t.path, tool("sbox"), Args("--root", state, "run", "--bundle", bundleDir, id2));
        CHECK_MESSAGE(r2.code == 0, r2.err);
        CHECK(r2.out == "persisted\nvol-ro\n");
        CHECK(co_await store.releaseUser(id2, true) == SBOX_OK);

        // --> Library backup, remove, restore under a new name, and a container on the restored volume.
        std::string backup = t / "e2edata.tgz";
        REQUIRE(co_await vol::BackupVolumeToFile(store, "e2edata", backup) == SBOX_OK);
        REQUIRE(co_await store.remove("e2edata") == SBOX_OK);
        CHECK(store.inspect("e2edata", v) != SBOX_OK);
        REQUIRE(co_await vol::RestoreVolumeFromFile(store, "restored", backup) == SBOX_OK);

        std::string id3 = "e2e-vol3-" + randomSuffix();
        std::vector<vol::SMountRequest> req3 = parseFlags({ "restored:/data" }, {}, {});
        co_await prepareBundle(store, bundleDir, id3, req3, "cat /data/out.txt /data/seed.txt");
        ContainerRun r3 = co_await runContainer(state, bundleDir, id3);
        REQUIRE_MESSAGE(r3.error == SBOX_OK, r3.message);
        CHECK(r3.out == "persisted\nfrom the image\n");
        CHECK(co_await store.releaseUser(id3, true) == SBOX_OK);

        // --> The same through sboxvol: backup to stdout, restore from stdin into another volume.
        ToolResult bk = co_await runTool(t.path, tool("sboxvol"), Args("--root", so.root, "backup", "restored", t / "cli.tgz"));
        REQUIRE_MESSAGE(bk.code == 0, bk.err);
        std::string archiveBytes;
        REQUIRE(CFile::readAll(t / "cli.tgz", archiveBytes) == SBOX_OK);
        RunOptions ro;
        ro.input = archiveBytes;
        ToolResult rs = co_await runTool(t.path, tool("sboxvol"), Args("--root", so.root, "restore", "--label", "from=cli", "viacli", "-"), ro);
        REQUIRE_MESSAGE(rs.code == 0, rs.err);
        REQUIRE(store.inspect("viacli", v) == SBOX_OK);
        CHECK(v.labels["from"] == "cli");
        CHECK(CFile::readAll(v.mountpoint + "/out.txt", onHost) == SBOX_OK);
        CHECK(onHost == "persisted\n");

        // --> An anonymous volume is removed with its container (docker run --rm).
        std::string id4 = "e2e-vol4-" + randomSuffix();
        std::vector<vol::SMountRequest> req4 = parseFlags({ "/anon" }, {}, {});
        co_await prepareBundle(store, bundleDir, id4, req4, "echo a > /anon/a; cat /anon/a");
        ContainerRun r4 = co_await runContainer(state, bundleDir, id4);
        CHECK(r4.out == "a\n");
        std::vector<vol::SVolume> all;
        REQUIRE(store.list(all) == SBOX_OK);
        CHECK(all.size() == 3);
        CHECK(co_await store.releaseUser(id4, true) == SBOX_OK);
        all.clear();
        REQUIRE(store.list(all) == SBOX_OK);
        CHECK(all.size() == 2);

        CHECK(co_await store.remove("restored") == SBOX_OK);
        CHECK(co_await store.remove("viacli") == SBOX_OK);
    }(tmp, bundle, hostDir));
}
