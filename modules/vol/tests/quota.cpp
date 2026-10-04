#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "testutil.hpp"

#include <sbox/vol/quota.hpp>
#include <sbox/vol/store.hpp>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

namespace {

    /* Writes `size` bytes into a new file; returns 0 or the errno that stopped it. */
    int fillFile(const std::string& path, size_t size) {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) {
            return errno;
        }

        std::vector<char> chunk(65536, 'q');
        size_t done = 0;
        int err = 0;
        while (done < size) {
            ssize_t n = ::write(fd, chunk.data(), std::min(chunk.size(), size - done));
            if (n < 0) {
                err = errno;
                break;
            }

            done += size_t(n);
        }

        if (err == 0 && ::fsync(fd) != 0) {
            err = errno;
        }

        ::close(fd);
        return err;
    }

    /**
     * Exercises a store on a filesystem with project quotas enforced (inside the forked child).
     */
    int quotaScenario(const std::string& mnt) {
        CEventLoop loop;
        CHILD_CHECK(ProbeProjectQuota(mnt) == SBOX_OK);
        SVolumeStoreOptions o;
        o.root = mnt + "/volumes";
        o.projectIdBase = 500;
        CVolumeStore store(o);

        SVolumeCreate req;
        req.name = "limited";
        req.options["size"] = "1m";
        SVolume v;
        CHILD_CHECK(loop.run(store.create(req, v)) == SBOX_OK);
        CHILD_CHECK(v.projectId == 500);
        CHILD_CHECK(v.sizeLimit == (uint64_t(1) << 20));
        uint32_t id = 0;
        CHILD_CHECK(GetProjectId(v.mountpoint, id) == SBOX_OK && id == 500);

        // --> Writing past the limit fails with EDQUOT; files inherit the project id.
        CHILD_CHECK(fillFile(v.mountpoint + "/small", 256 << 10) == 0);
        CHILD_CHECK(GetProjectId(v.mountpoint + "/small", id) == SBOX_OK && id == 500);
        CHILD_CHECK(fillFile(v.mountpoint + "/big", 4 << 20) == EDQUOT);

        SVolumeUsage u;
        CHILD_CHECK(store.usage("limited", u) == SBOX_OK);
        CHILD_CHECK(u.limit == (uint64_t(1) << 20));
        CHILD_CHECK(u.bytes >= (uint64_t(256) << 10));
        CHILD_CHECK(u.bytes <= (uint64_t(1) << 20) + 65536);

        // --> A second volume gets the next id; the allocation survives a new store instance.
        req.name = "second";
        CHILD_CHECK(loop.run(store.create(req, v)) == SBOX_OK);
        CHILD_CHECK(v.projectId == 501);
        CHILD_CHECK(loop.run(store.remove("second")) == SBOX_OK);
        CVolumeStore again(o);
        req.name = "third";
        CHILD_CHECK(loop.run(again.create(req, v)) == SBOX_OK);
        CHILD_CHECK(v.projectId == 502);
        return 0;
    }

    /**
     * Makes a filesystem image, attaches it and runs `body` with it mounted (private namespace).
     * @return The child's code, 77 when the environment cannot do it.
     */
    int withImage(const std::vector<std::string>& mkfsArgs, const std::string& fsType, const std::string& mountData,
                  const std::function<int(const std::string&)>& body) {
        TempDir dir("quota");
        std::string image = dir / "fs.img";
        if (!writeFile(image, "") || ::truncate(image.c_str(), 300 << 20) != 0) {
            return 77;
        }

        std::vector<std::string> args = mkfsArgs;
        args.push_back(image);
        {
            CEventLoop loop;
            if (loop.run(runProgram(args)) != 0) {
                return 77;
            }
        }

        LoopDevice dev;
        if (!dev.attach(image)) {
            return 77;
        }

        std::string mnt = dir / "mnt";
        CFile::makeDirs(mnt, 0755);
        return runInPrivateMountNs([&]() -> int {
            if (::mount(dev.path.c_str(), mnt.c_str(), fsType.c_str(), 0, mountData.empty() ? nullptr : mountData.c_str()) != 0) {
                std::fprintf(stderr, "mount %s (%s) failed: %s\n", fsType.c_str(), mountData.c_str(), std::strerror(errno));
                return 77;
            }

            return body(mnt);
        });
    }

}

TEST_CASE("ProbeProjectQuota reports -ENOTSUP where project quotas are off") {
    TempDir dir("probe");
    int32_t rc = ProbeProjectQuota(dir.path);
    CHECK((rc == SBOX_OK || rc == -ENOTSUP));
    CHECK(ProbeProjectQuota(dir / "missing") == -ENOENT);
    if (rc == -ENOTSUP) {
        CHECK(SetProjectLimit(dir.path, 1234, 1 << 20) == -ENOTSUP);
        SQuotaUsage u;
        CHECK(GetProjectUsage(dir.path, 1234, u) == -ENOTSUP);
    }

    // --> /tmp's filesystem decides whether project ids exist at all; both answers are valid.
    uint32_t id = 99;
    int32_t g = GetProjectId(dir.path, id);
    CHECK((g == SBOX_OK || g == -ENOTSUP));
}

TEST_CASE("BlockDeviceOf reads mountinfo") {
    std::string dev = BlockDeviceOf("/proc/self");
    CHECK(dev == "proc");
    CHECK(BlockDeviceOf("/nonexistent/path").empty());
}

TEST_CASE("store refuses size= without project quota support") {
    TempDir dir("noquota");
    if (ProbeProjectQuota(dir.path) == SBOX_OK) {
        MESSAGE("skipped: /tmp has project quotas enabled");
        return;
    }

    CEventLoop loop;
    CVolumeStore store(SVolumeStoreOptions{ dir / "vols" });
    SVolumeCreate req;
    req.name = "sized";
    req.options["size"] = "10G";
    SVolume v;
    CHECK(loop.run(store.create(req, v)) == -ENOTSUP);
    CHECK(store.lastError().find("quota") != std::string::npos);
    CHECK(!CFile::exists(dir / "vols/sized"));
}

TEST_CASE("project ids on ext4 with the project feature") {
    std::string mkfs = findTool("mkfs.ext4");
    if (!isRoot() || mkfs.empty()) {
        MESSAGE("skipped: needs root and mkfs.ext4");
        return;
    }

    int code = withImage({ mkfs, "-q", "-F", "-O", "project" }, "ext4", "", [](const std::string& mnt) -> int {
        std::string d = mnt + "/proj";
        CHILD_CHECK(::mkdir(d.c_str(), 0755) == 0);
        CHILD_CHECK(SetProjectId(d, 4242, true) == SBOX_OK);
        uint32_t id = 0;
        CHILD_CHECK(GetProjectId(d, id) == SBOX_OK && id == 4242);
        CHILD_CHECK(writeFile(d + "/child", "x"));
        CHILD_CHECK(GetProjectId(d + "/child", id) == SBOX_OK && id == 4242);
        CHILD_CHECK(QuotaFsOf(mnt) == EQFS_EXT4);
        // --> Project ids without the quota feature/prjquota: limits are not available.
        int32_t probe = ProbeProjectQuota(mnt);
        CHILD_CHECK(probe == -ENOTSUP || probe == SBOX_OK);
        if (probe == -ENOTSUP) {
            CHILD_CHECK(SetProjectLimit(d, 4242, 1 << 20) == -ENOTSUP);
        }

        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: ext4 project feature unavailable (mkfs, loop device or kernel)");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("project quota limits on ext4 (prjquota)") {
    std::string mkfs = findTool("mkfs.ext4");
    if (!isRoot() || mkfs.empty()) {
        MESSAGE("skipped: needs root and mkfs.ext4");
        return;
    }

    int code = withImage({ mkfs, "-q", "-F", "-O", "quota,project" }, "ext4", "prjquota", quotaScenario);
    if (code == 77) {
        MESSAGE("skipped: ext4 project quotas unavailable (the kernel needs CONFIG_QUOTA and CONFIG_QFMT_V2)");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("project quota limits on XFS (prjquota)") {
    std::string mkfs = findTool("mkfs.xfs");
    if (!isRoot() || mkfs.empty()) {
        MESSAGE("skipped: needs root and mkfs.xfs");
        return;
    }

    int code = withImage({ mkfs, "-q", "-f" }, "xfs", "prjquota", quotaScenario);
    if (code == 77) {
        MESSAGE("skipped: XFS with project quotas unavailable (kernel xfs/quota support)");
        return;
    }

    CHECK(code == 0);
}
