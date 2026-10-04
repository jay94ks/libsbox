#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "testutil.hpp"

#include <sbox/archive/stream.hpp>
#include <sbox/archive/tar.hpp>
#include <sbox/vol/backup.hpp>
#include <sys/xattr.h>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

namespace {

    SVolumeStoreOptions storeAt(const std::string& root) {
        SVolumeStoreOptions o;
        o.root = root;
        return o;
    }

    /* Populates a volume with every kind of entry the backup must keep. */
    bool populate(const std::string& mp, bool root, bool& xattrs) {
        if (CFile::makeDirs(mp + "/dir/nested", 0750) != SBOX_OK) {
            return false;
        }

        bool ok = writeFile(mp + "/file.txt", "hello volume", 0640) &&
                  writeFile(mp + "/dir/nested/deep.bin", std::string(200000, 'z')) &&
                  ::symlink("dir/nested/deep.bin", (mp + "/link").c_str()) == 0 &&
                  ::symlink("/etc/passwd", (mp + "/abs-link").c_str()) == 0 &&
                  ::link((mp + "/file.txt").c_str(), (mp + "/hardlink").c_str()) == 0 &&
                  ::mkfifo((mp + "/fifo").c_str(), 0600) == 0 &&
                  ::chmod((mp + "/dir").c_str(), 0705) == 0;
        if (!ok) {
            return false;
        }

        if (root) {
            ok = ::chown((mp + "/file.txt").c_str(), 1500, 1600) == 0 && ::lchown((mp + "/link").c_str(), 1501, 1601) == 0 &&
                 ::chown((mp + "/dir").c_str(), 1502, 1602) == 0 && ::chown(mp.c_str(), 1503, 1603) == 0;
        }

        xattrs = ::setxattr((mp + "/file.txt").c_str(), "user.origin", "backup-test", 11, 0) == 0;
        if (root && ::setxattr((mp + "/dir").c_str(), "trusted.sbox", "t", 1, 0) != 0) {
            xattrs = false;
        }

        return ok;
    }

    /* Verifies the restored copy. */
    void verify(const std::string& mp, bool root, bool xattrs) {
        CHECK(readFile(mp + "/file.txt") == "hello volume");
        CHECK(readFile(mp + "/dir/nested/deep.bin") == std::string(200000, 'z'));
        char buffer[256] = {};
        CHECK(::readlink((mp + "/link").c_str(), buffer, sizeof(buffer)) == 19);
        CHECK(std::string(buffer) == "dir/nested/deep.bin");
        std::memset(buffer, 0, sizeof(buffer));
        CHECK(::readlink((mp + "/abs-link").c_str(), buffer, sizeof(buffer)) == 11);
        CHECK(std::string(buffer) == "/etc/passwd");

        struct stat f{}, h{}, d{}, l{}, r{}, p{};
        REQUIRE(::stat((mp + "/file.txt").c_str(), &f) == 0);
        REQUIRE(::stat((mp + "/hardlink").c_str(), &h) == 0);
        REQUIRE(::stat((mp + "/dir").c_str(), &d) == 0);
        REQUIRE(::lstat((mp + "/link").c_str(), &l) == 0);
        REQUIRE(::stat(mp.c_str(), &r) == 0);
        REQUIRE(::lstat((mp + "/fifo").c_str(), &p) == 0);
        CHECK(f.st_ino == h.st_ino);
        CHECK((f.st_mode & 07777) == 0640);
        CHECK((d.st_mode & 07777) == 0705);
        CHECK(S_ISFIFO(p.st_mode));
        if (root) {
            CHECK(f.st_uid == 1500);
            CHECK(f.st_gid == 1600);
            CHECK(l.st_uid == 1501);
            CHECK(l.st_gid == 1601);
            CHECK(d.st_uid == 1502);
            CHECK(r.st_uid == 1503);
            CHECK(r.st_gid == 1603);
        }

        if (xattrs) {
            char value[32] = {};
            CHECK(::getxattr((mp + "/file.txt").c_str(), "user.origin", value, sizeof(value)) == 11);
            CHECK(std::string(value) == "backup-test");
            if (root) {
                CHECK(::getxattr((mp + "/dir").c_str(), "trusted.sbox", value, sizeof(value)) == 1);
            }
        }
    }

}

TEST_CASE("backup and restore round trip keeps ownership, xattrs, links and modes") {
    TempDir dir("backup");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));
    bool root = isRoot();
    SVolume src;
    SVolumeCreate c;
    c.name = "source";
    REQUIRE(loop.run(store.create(c, src)) == SBOX_OK);
    bool xattrs = false;
    REQUIRE(populate(src.mountpoint, root, xattrs));
    if (!xattrs) {
        MESSAGE("xattrs unsupported here; xattr round trip not checked");
    }

    // --> File backup (atomic) and restore into a new volume.
    std::string file = dir / "source.tar.gz";
    REQUIRE(loop.run(BackupVolumeToFile(store, "source", file)) == SBOX_OK);
    std::string bytes = readFile(file);
    REQUIRE(bytes.size() > 20);
    CHECK(uint8_t(bytes[0]) == 0x1f);
    CHECK(uint8_t(bytes[1]) == 0x8b);
    REQUIRE(store.inspect("source", src) == SBOX_OK);
    CHECK(src.users.empty());

    REQUIRE(loop.run(RestoreVolumeFromFile(store, "copy", file)) == SBOX_OK);
    SVolume copy;
    REQUIRE(store.inspect("copy", copy) == SBOX_OK);
    CHECK(copy.users.empty());
    verify(copy.mountpoint, root, xattrs);

    // --> The system tar reads our backups.
    std::string tar = findTool("tar");
    if (!tar.empty()) {
        std::string listing;
        CHECK(loop.run(runProgram({ tar, "-tzf", file }, &listing)) == 0);
        CHECK(listing.find("file.txt") != std::string::npos);
        CHECK(listing.find("dir/nested/deep.bin") != std::string::npos);
    }

    // --> A non-empty volume needs overwrite; overwrite replaces the content.
    REQUIRE(writeFile(copy.mountpoint + "/extra", "stale"));
    SRestoreOptions ro;
    CHECK(loop.run(RestoreVolumeFromFile(store, "copy", file, ro)) == -ENOTEMPTY);
    ro.overwrite = true;
    REQUIRE(loop.run(RestoreVolumeFromFile(store, "copy", file, ro)) == SBOX_OK);
    CHECK(!CFile::exists(copy.mountpoint + "/extra"));
    verify(copy.mountpoint, root, xattrs);

    // --> Missing volume without create.
    SRestoreOptions nocreate;
    nocreate.create = false;
    CHECK(loop.run(RestoreVolumeFromFile(store, "absent", file, nocreate)) == -ENOENT);

    // --> Restore creates with the requested labels.
    SRestoreOptions labelled;
    labelled.createOptions.labels["restored"] = "yes";
    REQUIRE(loop.run(RestoreVolumeFromFile(store, "labelled", file, labelled)) == SBOX_OK);
    SVolume lv;
    REQUIRE(store.inspect("labelled", lv) == SBOX_OK);
    CHECK(lv.labels["restored"] == "yes");

    // --> Backups of missing volumes fail and leave no temporary file.
    CHECK(loop.run(BackupVolumeToFile(store, "nope", dir / "nope.tgz")) == -ENOENT);
    CHECK(!CFile::exists(dir / "nope.tgz"));

    // --> Freeze needs the volume's own filesystem.
    SBackupOptions fz;
    fz.freeze = true;
    std::vector<uint8_t> sinkBytes;
    archive::CVectorSink sink(sinkBytes);
    CHECK(loop.run(BackupVolume(store, "source", sink, fz)) == -ENOTSUP);
    REQUIRE(store.inspect("source", src) == SBOX_OK);
    CHECK(src.users.empty());
}

TEST_CASE("backup streams through a pipe into a restore") {
    TempDir dir("stream");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));
    SVolume src;
    SVolumeCreate c;
    c.name = "piped";
    REQUIRE(loop.run(store.create(c, src)) == SBOX_OK);
    bool xattrs = false;
    bool root = isRoot();
    REQUIRE(populate(src.mountpoint, root, xattrs));

    CStream readEnd, writeEnd;
    REQUIRE(CPipe::create(readEnd, writeEnd) == SBOX_OK);

    auto producer = [&]() -> TTask<int32_t> {
        int32_t rc = co_await BackupVolumeToStream(store, "piped", writeEnd);
        writeEnd.close();
        co_return rc;
    };

    auto both = [&]() -> TTask<int32_t> {
        int32_t prc = -1;
        auto runProducer = [&]() -> TTask<void> {
            prc = co_await producer();
        };

        CEventLoop::current()->spawn(runProducer());
        int32_t crc = co_await RestoreVolumeFromStream(store, "landed", readEnd);
        co_await CEventLoop::current()->sleepFor(1);
        co_return crc < 0 ? crc : prc;
    };

    REQUIRE(loop.run(both()) == SBOX_OK);
    SVolume landed;
    REQUIRE(store.inspect("landed", landed) == SBOX_OK);
    verify(landed.mountpoint, root, xattrs);
}

TEST_CASE("restore never writes outside the volume") {
    TempDir dir("evil");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));

    // --> A tar with a symlink to the outside followed by a file written through it.
    std::vector<uint8_t> tar;
    {
        archive::CVectorSink sink(tar);
        archive::CTarWriter w(sink);
        archive::STarEntry link;
        link.path = "escape";
        link.type = archive::ETAR_SYMLINK;
        link.linkPath = dir.path;
        link.mode = 0777;
        REQUIRE(w.writeHeader(link) == SBOX_OK);
        archive::STarEntry file;
        file.path = "escape/pwned";
        file.type = archive::ETAR_FILE;
        file.mode = 0644;
        file.size = 4;
        REQUIRE(w.writeHeader(file) == SBOX_OK);
        REQUIRE(w.writeData(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("evil"), 4)) == SBOX_OK);
        REQUIRE(w.finish() == SBOX_OK);
    }

    archive::CMemorySource source(SReadOnlyByteSpan(tar.data(), tar.size()));
    loop.run(RestoreVolume(store, "target", source));
    CHECK(!CFile::exists(dir / "pwned"));
}

TEST_CASE("freeze backup of a device volume") {
    std::string mkfs = findTool("mkfs.ext4");
    if (!isRoot() || mkfs.empty()) {
        MESSAGE("skipped: needs root and mkfs.ext4");
        return;
    }

    TempDir dir("freeze");
    std::string image = dir / "disk.img";
    REQUIRE(writeFile(image, ""));
    REQUIRE(::truncate(image.c_str(), 32 << 20) == 0);
    {
        CEventLoop loop;
        REQUIRE(loop.run(runProgram({ mkfs, "-q", "-F", image })) == 0);
    }

    LoopDevice dev;
    if (!dev.attach(image)) {
        MESSAGE("skipped: no loop devices");
        return;
    }

    std::string root = dir / "v";
    std::string file = dir / "frozen.tgz";
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        CVolumeStore store(storeAt(root));
        SVolume v;
        SVolumeCreate c;
        c.name = "blockvol";
        c.options = { { "type", "ext4" }, { "device", dev.path } };
        CHILD_CHECK(loop.run(store.create(c, v)) == SBOX_OK);
        std::string mp;
        CHILD_CHECK(loop.run(store.acquire("blockvol", "writer", mp)) == SBOX_OK);
        CHILD_CHECK(writeFile(mp + "/db", "consistent"));
        SBackupOptions fz;
        fz.freeze = true;
        CHILD_CHECK(loop.run(BackupVolumeToFile(store, "blockvol", file, fz)) == SBOX_OK);
        // --> Thawed again: writes work.
        CHILD_CHECK(writeFile(mp + "/after", "x"));
        CHILD_CHECK(loop.run(store.release("blockvol", "writer")) == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(mp));

        // --> Backup of an unused device volume mounts it temporarily.
        CHILD_CHECK(loop.run(BackupVolumeToFile(store, "blockvol", file + ".2")) == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(mp));
        CHILD_CHECK(loop.run(RestoreVolumeFromFile(store, "plain", file)) == SBOX_OK);
        CHILD_CHECK(store.inspect("plain", v) == SBOX_OK);
        CHILD_CHECK(readFile(v.mountpoint + "/db") == "consistent");
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}
