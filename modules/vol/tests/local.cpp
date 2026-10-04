#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "testutil.hpp"

#include <sbox/vol/local.hpp>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <linux/magic.h>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

TEST_CASE("ParseSize follows go-units RAMInBytes") {
    struct Case {
        const char* text;
        int32_t rc;
        uint64_t value;
    };

    const Case cases[] = {
        { "0", SBOX_OK, 0 },
        { "4096", SBOX_OK, 4096 },
        { "10k", SBOX_OK, 10240 },
        { "10K", SBOX_OK, 10240 },
        { "10kb", SBOX_OK, 10240 },
        { "10KiB", SBOX_OK, 10240 },
        { "512m", SBOX_OK, uint64_t(512) << 20 },
        { "10G", SBOX_OK, uint64_t(10) << 30 },
        { "10 GB", SBOX_OK, uint64_t(10) << 30 },
        { "1.5g", SBOX_OK, uint64_t(3) << 29 },
        { "2t", SBOX_OK, uint64_t(2) << 40 },
        { "1p", SBOX_OK, uint64_t(1) << 50 },
        { "100b", SBOX_OK, 100 },
        { "", -EINVAL, 0 },
        { "g", -EINVAL, 0 },
        { "10x", -EINVAL, 0 },
        { "10gg", -EINVAL, 0 },
        { "-1", -EINVAL, 0 },
        { "99999999999999999999", -ERANGE, 0 },
        { "20000000p", -ERANGE, 0 },
    };

    for (const Case& c : cases) {
        CAPTURE(c.text);
        uint64_t v = 12345;
        CHECK(ParseSize(c.text, v) == c.rc);
        if (c.rc == SBOX_OK) {
            CHECK(v == c.value);
        }
    }

    CHECK(FormatSize(uint64_t(10) << 30) == "10g");
    CHECK(FormatSize(uint64_t(3) << 20) == "3m");
    CHECK(FormatSize(1536) == "1536");
    CHECK(FormatSize(2048) == "2k");
    CHECK(FormatSize(1000) == "1000");
    CHECK(FormatSize(0) == "0");
}

TEST_CASE("ParseMountOptions splits flags and data like Docker") {
    uint64_t flags = 0;
    std::string data;
    REQUIRE(ParseMountOptions("ro,nosuid,size=10m,mode=1777,uid=1000", flags, data) == SBOX_OK);
    CHECK(flags == (MS_RDONLY | MS_NOSUID));
    CHECK(data == "size=10m,mode=1777,uid=1000");

    REQUIRE(ParseMountOptions("ro,rw,bind", flags, data) == SBOX_OK);
    CHECK(flags == MS_BIND);
    CHECK(data.empty());

    REQUIRE(ParseMountOptions("rbind,rslave,noexec", flags, data) == SBOX_OK);
    CHECK(flags == (MS_BIND | MS_REC | MS_SLAVE | MS_NOEXEC));

    REQUIRE(ParseMountOptions("addr=10.0.0.1,rw,nfsvers=4", flags, data) == SBOX_OK);
    CHECK(flags == 0);
    CHECK(data == "addr=10.0.0.1,nfsvers=4");

    REQUIRE(ParseMountOptions("", flags, data) == SBOX_OK);
    CHECK(flags == 0);
    CHECK(ParseMountOptions("ro,,nodev", flags, data) == -EINVAL);
}

TEST_CASE("ParseLocalOptions table") {
    struct Case {
        TStringMap options;
        int32_t rc;
        ELocalKind kind;
        const char* errorPart;
    };

    const std::vector<Case> cases = {
        { {}, SBOX_OK, ELK_DIRECTORY, "" },
        { { { "size", "10G" } }, SBOX_OK, ELK_DIRECTORY, "" },
        { { { "type", "tmpfs" }, { "device", "tmpfs" } }, SBOX_OK, ELK_TMPFS, "" },
        { { { "type", "tmpfs" }, { "device", "tmpfs" }, { "o", "size=100m,uid=1000" } }, SBOX_OK, ELK_TMPFS, "" },
        { { { "type", "nfs" }, { "device", ":/export" }, { "o", "addr=10.0.0.1,rw,nfsvers=4" } }, SBOX_OK, ELK_NFS, "" },
        { { { "type", "nfs4" }, { "device", "nas.local:/vol" } }, SBOX_OK, ELK_NFS, "" },
        { { { "type", "none" }, { "device", "/srv/data" }, { "o", "bind" } }, SBOX_OK, ELK_BIND, "" },
        { { { "type", "none" }, { "device", "/srv/data" }, { "o", "rbind,ro" } }, SBOX_OK, ELK_BIND, "" },
        { { { "type", "ext4" }, { "device", "/dev/sdb1" } }, SBOX_OK, ELK_DEVICE, "" },
        { { { "type", "xfs" }, { "device", "/dev/sdc" }, { "o", "noatime" } }, SBOX_OK, ELK_DEVICE, "" },
        { { { "type", "tmpfs" } }, -EINVAL, ELK_INVALID, "missing required option: \"device\"" },
        { { { "device", "/dev/sdb1" } }, -EINVAL, ELK_INVALID, "missing required option: \"type\"" },
        { { { "o", "size=1m" } }, -EINVAL, ELK_INVALID, "missing required option" },
        { { { "o", "size=1m" }, { "type", "tmpfs" } }, -EINVAL, ELK_INVALID, "missing required option: \"device\"" },
        { { { "bogus", "1" } }, -EINVAL, ELK_INVALID, "invalid option: \"bogus\"" },
        { { { "size", "lots" } }, -EINVAL, ELK_INVALID, "invalid size" },
        { { { "size", "1g" }, { "type", "tmpfs" }, { "device", "tmpfs" } }, -EINVAL, ELK_INVALID, "size option" },
        { { { "type", "none" }, { "device", "/srv" } }, -EINVAL, ELK_INVALID, "o=bind" },
        { { { "type", "none" }, { "device", "relative" }, { "o", "bind" } }, -EINVAL, ELK_INVALID, "absolute" },
        { { { "type", "nfs" }, { "device", "noexport" } }, -EINVAL, ELK_INVALID, "nfs device" },
        { { { "type", "ext4" }, { "device", "/dev/x" }, { "o", "remount" } }, -EINVAL, ELK_INVALID, "remount" },
    };

    for (const Case& c : cases) {
        SLocalOptions out;
        std::string error;
        int32_t rc = ParseLocalOptions(c.options, out, &error);
        CAPTURE(error);
        CHECK(rc == c.rc);
        if (rc == SBOX_OK) {
            CHECK(out.kind == c.kind);
        } else {
            CHECK(error.find(c.errorPart) != std::string::npos);
        }
    }

    SLocalOptions out;
    REQUIRE(ParseLocalOptions({ { "type", "tmpfs" }, { "device", "tmpfs" }, { "o", "ro,size=1m,mode=0700" } }, out) == SBOX_OK);
    CHECK(out.flags == MS_RDONLY);
    CHECK(out.data == "size=1m,mode=0700");
    CHECK(out.needsMount());

    REQUIRE(ParseLocalOptions({ { "size", "512m" } }, out) == SBOX_OK);
    CHECK(out.quotaBytes == (uint64_t(512) << 20));
    CHECK(!out.needsMount());
}

TEST_CASE("tmpfs, bind and device volumes mount and unmount in a private mount namespace") {
    if (!isRoot()) {
        MESSAGE("skipped: needs root for mount(2)");
        return;
    }

    TempDir dir("local");
    REQUIRE(CFile::makeDirs(dir / "tmpfs", 0755) == SBOX_OK);
    REQUIRE(CFile::makeDirs(dir / "bind", 0755) == SBOX_OK);
    REQUIRE(CFile::makeDirs(dir / "host", 0755) == SBOX_OK);
    REQUIRE(writeFile(dir / "host/hello", "from host"));

    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        // --> tmpfs with size, mode, uid, gid.
        SLocalOptions t;
        CHILD_CHECK(ParseLocalOptions({ { "type", "tmpfs" }, { "device", "tmpfs" }, { "o", "size=4m,mode=0750,uid=1234,gid=4321" } }, t) == SBOX_OK);
        CHILD_CHECK(loop.run(MountLocalVolume(t, dir / "tmpfs")) == SBOX_OK);
        CHILD_CHECK(IsMountPoint(dir / "tmpfs"));
        struct statfs sf{};
        CHILD_CHECK(::statfs((dir / "tmpfs").c_str(), &sf) == 0);
        CHILD_CHECK(uint64_t(sf.f_type) == uint64_t(TMPFS_MAGIC));
        CHILD_CHECK(uint64_t(sf.f_blocks) * uint64_t(sf.f_bsize) == (uint64_t(4) << 20));
        struct stat st{};
        CHILD_CHECK(::stat((dir / "tmpfs").c_str(), &st) == 0);
        CHILD_CHECK((st.st_mode & 07777) == 0750);
        CHILD_CHECK(st.st_uid == 1234 && st.st_gid == 4321);
        CHILD_CHECK(UnmountLocalVolume(dir / "tmpfs") == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(dir / "tmpfs"));
        CHILD_CHECK(UnmountLocalVolume(dir / "tmpfs") == SBOX_OK);

        // --> Read-only bind: content visible, writes refused, flags applied by the remount.
        SLocalOptions b;
        CHILD_CHECK(ParseLocalOptions({ { "type", "none" }, { "device", dir / "host" }, { "o", "bind,ro,nosuid" } }, b) == SBOX_OK);
        CHILD_CHECK(loop.run(MountLocalVolume(b, dir / "bind")) == SBOX_OK);
        CHILD_CHECK(IsMountPoint(dir / "bind"));
        CHILD_CHECK(readFile(dir / "bind/hello") == "from host");
        CHILD_CHECK(!writeFile(dir / "bind/new", "x"));
        CHILD_CHECK(errno == EROFS);
        struct statfs bf{};
        CHILD_CHECK(::statfs((dir / "bind").c_str(), &bf) == 0);
        CHILD_CHECK((bf.f_flags & ST_RDONLY) && (bf.f_flags & ST_NOSUID));
        CHILD_CHECK(UnmountLocalVolume(dir / "bind") == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(dir / "bind"));

        // --> A busy mount (open directory) is detached lazily.
        CHILD_CHECK(loop.run(MountLocalVolume(t, dir / "tmpfs")) == SBOX_OK);
        int busy = ::open((dir / "tmpfs").c_str(), O_RDONLY | O_DIRECTORY);
        CHILD_CHECK(busy >= 0);
        CHILD_CHECK(::fchdir(busy) == 0);
        CHILD_CHECK(UnmountLocalVolume(dir / "tmpfs", true) == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(dir / "tmpfs"));
        CHILD_CHECK(::chdir("/") == 0);
        ::close(busy);

        // --> Bad device type fails cleanly.
        SLocalOptions bad;
        CHILD_CHECK(ParseLocalOptions({ { "type", "nosuchfs" }, { "device", "/dev/null" } }, bad) == SBOX_OK);
        CHILD_CHECK(loop.run(MountLocalVolume(bad, dir / "tmpfs")) < 0);
        CHILD_CHECK(!IsMountPoint(dir / "tmpfs"));
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("block device volume on a loop-mounted ext4 image") {
    std::string mkfs = findTool("mkfs.ext4");
    if (!isRoot() || mkfs.empty()) {
        MESSAGE("skipped: needs root and mkfs.ext4");
        return;
    }

    TempDir dir("blk");
    std::string image = dir / "disk.img";
    REQUIRE(writeFile(image, ""));
    REQUIRE(::truncate(image.c_str(), 32 << 20) == 0);
    CEventLoop loop;
    REQUIRE(loop.run(runProgram({ mkfs, "-q", "-F", image })) == 0);

    LoopDevice dev;
    if (!dev.attach(image)) {
        MESSAGE("skipped: no loop devices");
        return;
    }

    REQUIRE(CFile::makeDirs(dir / "mnt", 0755) == SBOX_OK);
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop child;
        SLocalOptions o;
        CHILD_CHECK(ParseLocalOptions({ { "type", "ext4" }, { "device", dev.path }, { "o", "noatime" } }, o) == SBOX_OK);
        CHILD_CHECK(o.kind == ELK_DEVICE);
        CHILD_CHECK(child.run(MountLocalVolume(o, dir / "mnt")) == SBOX_OK);
        struct statfs sf{};
        CHILD_CHECK(::statfs((dir / "mnt").c_str(), &sf) == 0);
        CHILD_CHECK(uint64_t(sf.f_type) == uint64_t(EXT4_SUPER_MAGIC));
        CHILD_CHECK(sf.f_flags & ST_NOATIME);
        CHILD_CHECK(writeFile(dir / "mnt/data", "persisted"));
        CHILD_CHECK(UnmountLocalVolume(dir / "mnt") == SBOX_OK);
        CHILD_CHECK(!CFile::exists(dir / "mnt/data"));
        CHILD_CHECK(child.run(MountLocalVolume(o, dir / "mnt")) == SBOX_OK);
        CHILD_CHECK(readFile(dir / "mnt/data") == "persisted");
        CHILD_CHECK(UnmountLocalVolume(dir / "mnt") == SBOX_OK);
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("NFS volumes need a server") {
    const char* server = std::getenv("SBOX_TEST_NFS");
    if (server == nullptr || !isRoot()) {
        MESSAGE("skipped: set SBOX_TEST_NFS=host:/export (as root) to test NFS volumes");
        return;
    }

    TempDir dir("nfs");
    REQUIRE(CFile::makeDirs(dir / "mnt", 0755) == SBOX_OK);
    std::string device = server;
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        SLocalOptions o;
        CHILD_CHECK(ParseLocalOptions({ { "type", "nfs" }, { "device", device }, { "o", "rw,nfsvers=4" } }, o) == SBOX_OK);
        CHILD_CHECK(loop.run(MountLocalVolume(o, dir / "mnt")) == SBOX_OK);
        CHILD_CHECK(IsMountPoint(dir / "mnt"));
        CHILD_CHECK(UnmountLocalVolume(dir / "mnt") == SBOX_OK);
        return 0;
    });

    CHECK(code == 0);
}

TEST_CASE("NFS mount resolves names before the kernel sees them") {
    if (!isRoot()) {
        MESSAGE("skipped: needs root");
        return;
    }

    // --> A name that cannot resolve fails in user space (the kernel would only say EINVAL).
    TempDir dir("nfsres");
    REQUIRE(CFile::makeDirs(dir / "mnt", 0755) == SBOX_OK);
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        SLocalOptions o;
        CHILD_CHECK(ParseLocalOptions({ { "type", "nfs" }, { "device", ":/export" }, { "o", "addr=no-such-host.invalid" } }, o) == SBOX_OK);
        int32_t rc = loop.run(MountLocalVolume(o, dir / "mnt"));
        CHILD_CHECK(rc < 0);
        CHILD_CHECK(!IsMountPoint(dir / "mnt"));
        SLocalOptions none;
        CHILD_CHECK(ParseLocalOptions({ { "type", "nfs" }, { "device", ":/export" } }, none) == SBOX_OK);
        CHILD_CHECK(loop.run(MountLocalVolume(none, dir / "mnt")) == -EDESTADDRREQ);
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("CopyUpIfEmpty copies image content with metadata") {
    TempDir dir("copyup");
    std::string src = dir / "image/data";
    std::string dst = dir / "vol";
    REQUIRE(CFile::makeDirs(src + "/sub", 0755) == SBOX_OK);
    REQUIRE(CFile::makeDirs(dst, 0755) == SBOX_OK);
    REQUIRE(writeFile(src + "/a.txt", "alpha", 0640));
    REQUIRE(writeFile(src + "/sub/b.txt", "beta"));
    REQUIRE(::symlink("../a.txt", (src + "/sub/link").c_str()) == 0);
    REQUIRE(::link((src + "/a.txt").c_str(), (src + "/hard").c_str()) == 0);
    REQUIRE(::chmod(src.c_str(), 0711) == 0);
    bool root = isRoot();
    if (root) {
        REQUIRE(::chown((src + "/a.txt").c_str(), 1001, 1002) == 0);
        REQUIRE(::chown(src.c_str(), 33, 33) == 0);
    }

    bool xattr = ::setxattr((src + "/sub/b.txt").c_str(), "user.test", "v1", 2, 0) == 0;

    CHECK(CopyUpIfEmpty(src, dst) == 1);
    CHECK(readFile(dst + "/a.txt") == "alpha");
    CHECK(readFile(dst + "/sub/b.txt") == "beta");
    char link[64] = {};
    CHECK(::readlink((dst + "/sub/link").c_str(), link, sizeof(link)) == 8);
    CHECK(std::string(link) == "../a.txt");
    struct stat a{}, h{}, d{};
    REQUIRE(::stat((dst + "/a.txt").c_str(), &a) == 0);
    REQUIRE(::stat((dst + "/hard").c_str(), &h) == 0);
    REQUIRE(::stat(dst.c_str(), &d) == 0);
    CHECK(a.st_ino == h.st_ino);
    CHECK((a.st_mode & 07777) == 0640);
    CHECK((d.st_mode & 07777) == 0711);
    if (root) {
        CHECK(a.st_uid == 1001);
        CHECK(a.st_gid == 1002);
        CHECK(d.st_uid == 33);
    }

    if (xattr) {
        char value[8] = {};
        CHECK(::getxattr((dst + "/sub/b.txt").c_str(), "user.test", value, sizeof(value)) == 2);
        CHECK(std::string(value) == "v1");
    } else {
        MESSAGE("user xattrs unsupported here; xattr copy not checked");
    }

    // --> Not empty any more: nothing happens.
    REQUIRE(writeFile(src + "/late", "x"));
    CHECK(CopyUpIfEmpty(src, dst) == 0);
    CHECK(!CFile::exists(dst + "/late"));

    // --> Missing source: nothing to do.
    CHECK(CopyUpIfEmpty(dir / "missing", dir / "vol2") == 0);
}

TEST_CASE("OpenInRoot keeps symlinks inside the root") {
    TempDir dir("inroot");
    std::string rootfs = dir / "rootfs";
    REQUIRE(CFile::makeDirs(rootfs + "/var/lib/app", 0755) == SBOX_OK);
    REQUIRE(CFile::makeDirs(dir / "outside", 0755) == SBOX_OK);
    REQUIRE(writeFile(dir / "outside/secret", "s"));
    REQUIRE(writeFile(rootfs + "/var/lib/app/inside", "i"));
    REQUIRE(::symlink("/var/lib/app", (rootfs + "/data").c_str()) == 0);
    REQUIRE(::symlink("../../../../outside", (rootfs + "/escape").c_str()) == 0);

    int32_t fd = OpenInRoot(rootfs, "/data");
    REQUIRE(fd >= 0);
    CHECK(readFile("/proc/self/fd/" + std::to_string(fd) + "/inside") == "i");
    ::close(fd);

    // --> "../../../../outside" is clamped at the root: it names <root>/outside, which is missing.
    CHECK(OpenInRoot(rootfs, "/escape") == -ENOENT);
    CHECK(OpenInRoot(rootfs, "/nope") == -ENOENT);
}

TEST_CASE("IsDirectoryEmpty and IsMountPoint basics") {
    TempDir dir("basics");
    CHECK(IsDirectoryEmpty(dir.path));
    CHECK(IsDirectoryEmpty(dir / "missing"));
    REQUIRE(writeFile(dir / "f", ""));
    CHECK(!IsDirectoryEmpty(dir.path));
    CHECK(IsMountPoint("/"));
    CHECK(!IsMountPoint(dir.path));
}
