#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/core/fd.hpp>
#include <sbox/image/snapshot.hpp>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

namespace {

    /* The layered test image: whiteouts and an opaque directory in the second layer. */
    TestImage layeredImage() {
        return BuildImage({ { Dir("etc"), File("etc/hostname", "base\n"), File("big.bin", std::string(5000, 'b')), Dir("data"),
                              File("data/a", "A"), File("data/b", "B"), Dir("dir"), Dir("dir/sub"), File("dir/sub/file", "old"),
                              Link("link", "etc/hostname") },
                            { File(".wh.big.bin", ""), File("data/c", "C"), File("data/.wh.a", ""), Dir("dir"),
                              File("dir/.wh..wh..opq", ""), File("dir/new", "new"), File("etc/hostname", "top\n") } });
    }

    /* Checks the merged view of layeredImage() under `root`. */
    void checkMerged(const std::string& root) {
        CHECK(ReadText(CFile::join(root, "etc/hostname")) == "top\n");
        CHECK(!CFile::exists(CFile::join(root, "big.bin")));
        CHECK(!CFile::exists(CFile::join(root, "data/a")));
        CHECK(ReadText(CFile::join(root, "data/b")) == "B");
        CHECK(ReadText(CFile::join(root, "data/c")) == "C");
        CHECK(!CFile::exists(CFile::join(root, "dir/sub")));
        CHECK(ReadText(CFile::join(root, "dir/new")) == "new");
        CHECK(ReadText(CFile::join(root, "link")) == "top\n");
    }

    /* Returns true when overlay can be mounted here (root and the module). */
    bool overlayUsable(CSnapshotter& snap) {
        if (!IsRoot()) {
            MESSAGE("skipped: needs root for overlay mounts");
            return false;
        }

        if (!snap.overlaySupported()) {
            MESSAGE("skipped: overlayfs is not available");
            return false;
        }

        return true;
    }

    /* Opens a store and imports the test image. */
    CContentStorePtr storeWith(const TempDir& tmp, const TestImage& img, const std::string& name, SImageInfo& info) {
        CContentStorePtr store;
        REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
        REQUIRE(ImportImage(*store, img, name) == SBOX_OK);
        REQUIRE(store->resolve(name, info) == SBOX_OK);
        return store;
    }

}

TEST_CASE("layers unpack once into chain ID snapshots with overlay whiteouts") {
    if (!IsRoot()) {
        MESSAGE("skipped: overlay whiteouts (0/0 devices, trusted xattrs) need root");
        return;
    }

    TempDir tmp;
    TestImage img = layeredImage();
    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/layers:1", info);
    std::vector<SProgress> events;
    SSnapshotterOptions so;
    so.rootless = 0;
    so.progress = [&events](const SProgress& p) { events.push_back(p); };
    CSnapshotter snap(store, so);
    REQUIRE(snap.unpack(info) == SBOX_OK);

    std::vector<std::string> chains = ChainIds(img.diffIds);
    REQUIRE(chains.size() == 2);
    CHECK(chains[1] == DigestOf(img.diffIds[0] + " " + img.diffIds[1]));
    SSnapshotInfo s0;
    SSnapshotInfo s1;
    REQUIRE(snap.snapshot(chains[0], s0) == SBOX_OK);
    REQUIRE(snap.snapshot(chains[1], s1) == SBOX_OK);
    CHECK(s1.parent == chains[0]);
    CHECK(s1.diffId == img.diffIds[1]);
    CHECK(store->diffIdOf(img.layerDigests[1]) == img.diffIds[1]);

    struct stat st{};
    REQUIRE(::lstat(CFile::join(s1.path, "big.bin").c_str(), &st) == 0);
    CHECK(S_ISCHR(st.st_mode));
    CHECK(st.st_rdev == 0);
    char value[8] = {};
    CHECK(::lgetxattr(CFile::join(s1.path, "dir").c_str(), "trusted.overlay.opaque", value, sizeof(value)) == 1);
    CHECK(value[0] == 'y');
    CHECK(CFile::exists(CFile::join(s0.path, "dir/sub/file")));

    // --> Unpacking again is a no-op.
    size_t extracted = 0;
    for (const SProgress& p : events) {
        extracted += p.phase == EPP_EXTRACTED;
    }

    CHECK(extracted == 2);
    REQUIRE(snap.unpack(info) == SBOX_OK);
    size_t again = 0;
    for (const SProgress& p : events) {
        again += p.phase == EPP_EXTRACTED;
    }

    CHECK(again == 2);
    std::vector<SSnapshotInfo> all;
    REQUIRE(snap.listSnapshots(all) == SBOX_OK);
    CHECK(all.size() == 2);
}

TEST_CASE("a diffID that does not match the config is rejected") {
    TempDir tmp;
    TestImage img = BuildImage({ { File("x", "1") } });
    // --> Rewrite the config with a wrong diffID (and a new manifest pointing at it).
    CJson cfg;
    CJson::parse(img.config, cfg);
    cfg["rootfs"]["diff_ids"] = CJson::fromStrings({ "sha256:" + std::string(64, '0') });
    std::string config = cfg.dump();
    img.blobs.erase(img.configDigest);
    img.configDigest = DigestOf(config);
    img.blobs[img.configDigest] = config;
    CJson man;
    CJson::parse(img.manifest, man);
    man["config"].set("digest", img.configDigest);
    man["config"].set("size", int64_t(config.size()));
    img.manifest = man.dump();
    img.manifestDigest = DigestOf(img.manifest);

    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/bad:1", info);
    SSnapshotterOptions so;
    so.rootless = IsRoot() ? 0 : 1;
    CSnapshotter snap(store, so);
    CHECK(snap.unpack(info) == -EBADMSG);
    CHECK(snap.lastError().find("diffID") != std::string::npos);
    std::vector<SSnapshotInfo> all;
    snap.listSnapshots(all);
    CHECK(all.empty());
    CHECK(snap.flatten(info, tmp.sub("flat")) == -EBADMSG);
}

TEST_CASE("copy snapshotter flattens layers with whiteouts applied") {
    TempDir tmp;
    TestImage img = layeredImage();
    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/copy:1", info);
    CSnapshotter snap(store);
    SContainerInfo c;
    int32_t r = snap.prepare("c1", info, ESNAP_COPY, c);
    CAPTURE(snap.lastError());
    REQUIRE(r == SBOX_OK);
    CHECK(c.mode == ESNAP_COPY);
    CHECK(c.rootfs == store->path("containers/c1/rootfs"));
    checkMerged(c.rootfs);
    CHECK(snap.prepare("c1", info, ESNAP_COPY, c) == -EEXIST);
    CHECK(snap.prepare("bad/id", info, ESNAP_COPY, c) == -EINVAL);

    std::vector<SContainerInfo> list;
    REQUIRE(snap.listContainers(list) == SBOX_OK);
    REQUIRE(list.size() == 1);
    CHECK(list[0].imageId == info.id);
    SImageInfo committed;
    CHECK(snap.commit("c1", SCommitOptions(), committed) == -ENOTSUP);
    REQUIRE(snap.remove("c1") == SBOX_OK);
    CHECK(!CFile::exists(store->path("containers/c1")));
}

TEST_CASE("overlay container root, changes, commit") {
    TempDir tmp;
    TestImage img = layeredImage();
    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/overlay:1", info);
    SSnapshotterOptions so;
    so.rootless = 0;
    CSnapshotter snap(store, so);
    if (!overlayUsable(snap)) {
        return;
    }

    for (bool legacy : { false, true }) {
        CAPTURE(legacy);
        SSnapshotterOptions lo = so;
        lo.legacyMount = legacy;
        CSnapshotter s(store, lo);
        std::string id = legacy ? "legacy" : "newapi";
        SContainerInfo c;
        int32_t r = s.prepare(id, info, ESNAP_OVERLAY, c);
        CAPTURE(s.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(c.plan.lowerDirs.size() == 2);
        CHECK(c.plan.lowerDirs[0] == CFile::join(s.snapshotDir(ChainIds(img.diffIds)[1]), "fs"));
        checkMerged(c.rootfs);

        // --> Changes: a new file, a deleted file, a replaced directory.
        REQUIRE(CFile::writeAtomic(CFile::join(c.rootfs, "data/added"), "added") == SBOX_OK);
        REQUIRE(::unlink(CFile::join(c.rootfs, "data/b").c_str()) == 0);
        REQUIRE(::rmdir(CFile::join(c.rootfs, "etc").c_str()) != 0);
        REQUIRE(CFile::removeTree(CFile::join(c.rootfs, "dir")) == SBOX_OK);
        REQUIRE(::mkdir(CFile::join(c.rootfs, "dir").c_str(), 0700) == 0);
        REQUIRE(CFile::writeAtomic(CFile::join(c.rootfs, "dir/only"), "only") == SBOX_OK);

        SCommitOptions co;
        co.reference = "test/committed:" + id;
        co.author = "tester";
        co.comment = "from test";
        co.hasConfigOverride = true;
        co.config = info.config;
        co.config.cmd = { "/bin/true" };
        SImageInfo out;
        r = s.commit(id, co, out);
        CAPTURE(s.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(out.manifest.layers.size() == 3);
        CHECK(out.config.diffIds.size() == 3);
        CHECK(out.config.cmd == std::vector<std::string>{ "/bin/true" });
        CHECK(out.config.author == "tester");
        CHECK(out.config.raw.get("history").size() == 2);
        SImageInfo byName;
        REQUIRE(store->resolve("test/committed:" + id, byName) == SBOX_OK);
        CHECK(byName.id == out.id);

        // --> The committed image flattened elsewhere shows the changes.
        std::string flat = tmp.sub("flat-" + id);
        REQUIRE(s.flatten(out, flat) == SBOX_OK);
        CHECK(ReadText(CFile::join(flat, "data/added")) == "added");
        CHECK(!CFile::exists(CFile::join(flat, "data/b")));
        CHECK(ReadText(CFile::join(flat, "data/c")) == "C");
        CHECK(!CFile::exists(CFile::join(flat, "dir/new")));
        CHECK(ReadText(CFile::join(flat, "dir/only")) == "only");

        REQUIRE(s.unmount(id) == SBOX_OK);
        CHECK(!CFile::exists(CFile::join(c.rootfs, "etc/hostname")));
        REQUIRE(s.mount(id) == SBOX_OK);
        CHECK(ReadText(CFile::join(c.rootfs, "data/added")) == "added");
        REQUIRE(s.remove(id) == SBOX_OK);
        CHECK(!CFile::exists(store->path("containers/" + id)));
    }
}

TEST_CASE("many layers: the legacy mount data limit is handled with relative paths") {
    TempDir tmp;
    std::vector<std::vector<LayerEntry>> layers;
    for (int i = 0; i < 70; ++i) {
        layers.push_back({ File("f" + std::to_string(i), std::to_string(i)), File("top", std::to_string(i)) });
    }

    TestImage img = BuildImage(layers);
    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/many:1", info);
    SSnapshotterOptions so;
    so.rootless = 0;
    CSnapshotter probe(store, so);
    if (!overlayUsable(probe)) {
        return;
    }

    for (bool legacy : { false, true }) {
        CAPTURE(legacy);
        SSnapshotterOptions lo = so;
        lo.legacyMount = legacy;
        CSnapshotter s(store, lo);
        SContainerInfo c;
        std::string id = legacy ? "many-legacy" : "many-new";
        int32_t r = s.prepare(id, info, ESNAP_OVERLAY, c);
        CAPTURE(s.lastError());
        REQUIRE(r == SBOX_OK);
        CHECK(c.plan.toMountData().size() > 4096);
        CHECK(ReadText(CFile::join(c.rootfs, "top")) == "69");
        CHECK(ReadText(CFile::join(c.rootfs, "f0")) == "0");
        CHECK(ReadText(CFile::join(c.rootfs, "f42")) == "42");
        REQUIRE(s.remove(id) == SBOX_OK);
    }
}

TEST_CASE("rootless format: userxattr overlay inside a user namespace") {
    if (!IsRoot()) {
        MESSAGE("skipped: the test creates the user namespace from root to control the mapping");
        return;
    }

    TempDir tmp;
    TestImage img = layeredImage();
    SImageInfo info;
    CContentStorePtr store = storeWith(tmp, img, "test/rootless:1", info);
    SSnapshotterOptions so;
    so.rootless = 1;
    CSnapshotter snap(store, so);
    SContainerInfo c;
    int32_t r = snap.prepare("rl", info, ESNAP_OVERLAY, c, false);
    CAPTURE(snap.lastError());
    REQUIRE(r == SBOX_OK);
    REQUIRE(c.plan.options == std::vector<std::string>{ "userxattr" });

    // --> The whiteout is an xwhiteout (empty file with user.overlay.whiteout).
    std::string big = CFile::join(snap.snapshotDir(ChainIds(img.diffIds)[1]), "fs/big.bin");
    struct stat st{};
    REQUIRE(::lstat(big.c_str(), &st) == 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK(::lgetxattr(big.c_str(), "user.overlay.whiteout", nullptr, 0) >= 0);

    // --> Mount it in a child that owns a fresh user + mount namespace.
    int ready[2];
    REQUIRE(::pipe2(ready, O_CLOEXEC) == 0);
    pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        ::close(ready[1]);
        if (::unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
            ::_exit(10);
        }

        int fd = ::open("/proc/self/setgroups", O_WRONLY);
        if (fd >= 0) {
            (void)::write(fd, "deny", 4);
            ::close(fd);
        }

        fd = ::open("/proc/self/uid_map", O_WRONLY);
        if (fd < 0 || ::write(fd, "0 0 1", 5) != 5) {
            ::_exit(11);
        }

        ::close(fd);
        fd = ::open("/proc/self/gid_map", O_WRONLY);
        if (fd < 0 || ::write(fd, "0 0 1", 5) != 5) {
            ::_exit(12);
        }

        ::close(fd);
        if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
            ::_exit(13);
        }

        if (snap.mountPlan(c.plan) != SBOX_OK) {
            ::_exit(14);
        }

        std::string root = c.rootfs;
        bool ok = !CFile::exists(CFile::join(root, "big.bin")) && !CFile::exists(CFile::join(root, "data/a")) &&
                  CFile::exists(CFile::join(root, "data/c")) && !CFile::exists(CFile::join(root, "dir/sub")) &&
                  CFile::exists(CFile::join(root, "dir/new"));
        ::_exit(ok ? 0 : 15);
    }

    ::close(ready[0]);
    ::close(ready[1]);
    int pidfd = int(::syscall(SYS_pidfd_open, pid, 0));
    REQUIRE(pidfd >= 0);
    CEventLoop loop;
    int32_t status = loop.run([](int fd) -> TTask<int32_t> {
        co_await CEventLoop::current()->waitFd(fd, EFDE_READ, 30000);
        siginfo_t si{};
        ::waitid(P_PIDFD, id_t(fd), &si, WEXITED);
        co_return si.si_code == CLD_EXITED ? si.si_status : 100 + si.si_status;
    }(pidfd));
    ::close(pidfd);
    if (status == 10 || status == 13 || status == 14) {
        MESSAGE("skipped: rootless overlay is not available here (child status " << status << ")");
    } else {
        CHECK(status == 0);
    }

    REQUIRE(snap.remove("rl") == SBOX_OK);
}
