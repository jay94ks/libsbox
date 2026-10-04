#include <sbox/vol/quota.hpp>

#include "util.hpp"

#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/dqblk_xfs.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef PRJQUOTA
#define PRJQUOTA 2
#endif

#ifndef SYS_quotactl_fd
#define SYS_quotactl_fd 443
#endif

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

namespace sbox {
namespace vol {

    namespace {

        /* Maps the errnos meaning "no project quota here" to -ENOTSUP. */
        int32_t mapQuotaError(int e) noexcept {
            switch (e) {
                case ENOSYS:
                case ENOTTY:
                case EOPNOTSUPP:
                case ESRCH:         // --> Quota accounting is off for this type.
                case ENOTBLK:
                case EINVAL:
                    return -ENOTSUP;
                default:
                    return -e;
            }
        }

        /*
         * Runs one quotactl command for the project quota type on the filesystem holding `path`:
         * quotactl_fd(2) (5.14+) on a descriptor of the path, else quotactl(2) on its block device.
         */
        int32_t quotaCall(const std::string& path, int cmd, uint32_t id, void* addr) noexcept {
            int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0) {
                return -errno;
            }

            CFd held(fd);
            long rc = ::syscall(SYS_quotactl_fd, held.get(), (unsigned int)QCMD(cmd, PRJQUOTA), id, addr);
            if (rc == 0) {
                return SBOX_OK;
            }

            if (errno != ENOSYS) {
                return -errno;
            }

            std::string device = BlockDeviceOf(path);
            if (device.empty() || device[0] != '/') {
                return -ENOTSUP;
            }

            if (::quotactl(QCMD(cmd, PRJQUOTA), device.c_str(), int(id), reinterpret_cast<caddr_t>(addr)) == 0) {
                return SBOX_OK;
            }

            return -errno;
        }

    }

    /* Returns the quota family of the filesystem holding `path`. */
    EQuotaFs QuotaFsOf(const std::string& path) noexcept {
        struct statfs sf{};
        if (::statfs(path.c_str(), &sf) != 0) {
            return EQFS_OTHER;
        }

        if (uint64_t(sf.f_type) == uint64_t(XFS_SUPER_MAGIC)) {
            return EQFS_XFS;
        }

        if (uint64_t(sf.f_type) == uint64_t(EXT4_SUPER_MAGIC)) {
            return EQFS_EXT4;
        }

        return EQFS_OTHER;
    }

    /* Checks that project quotas are enforced on the filesystem holding `path`. */
    int32_t ProbeProjectQuota(const std::string& path) noexcept {
        struct stat st{};
        if (::stat(path.c_str(), &st) != 0) {
            return -errno;
        }

        if (QuotaFsOf(path) == EQFS_XFS) {
            fs_quota_stat qs{};
            int32_t rc = quotaCall(path, Q_XGETQSTAT, 0, &qs);
            if (rc < 0) {
                return mapQuotaError(-rc);
            }

            return (qs.qs_flags & FS_QUOTA_PDQ_ENFD) ? SBOX_OK : -ENOTSUP;
        }

        struct dqblk dq{};
        int32_t rc = quotaCall(path, Q_GETQUOTA, 0, &dq);
        return rc < 0 ? mapQuotaError(-rc) : SBOX_OK;
    }

    /* Reads the project id of a file or directory. */
    int32_t GetProjectId(const std::string& path, uint32_t& id) noexcept {
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            return -errno;
        }

        CFd held(fd);
        fsxattr fsx{};
        if (::ioctl(held.get(), FS_IOC_FSGETXATTR, &fsx) != 0) {
            return errno == ENOTTY || errno == EOPNOTSUPP ? -ENOTSUP : -errno;
        }

        id = fsx.fsx_projid;
        return SBOX_OK;
    }

    /* Sets the project id (and inherit flag) of a directory. */
    int32_t SetProjectId(const std::string& dir, uint32_t id, bool inherit) noexcept {
        int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            return -errno;
        }

        CFd held(fd);
        fsxattr fsx{};
        if (::ioctl(held.get(), FS_IOC_FSGETXATTR, &fsx) != 0) {
            return errno == ENOTTY || errno == EOPNOTSUPP ? -ENOTSUP : -errno;
        }

        fsx.fsx_projid = id;
        if (inherit) {
            fsx.fsx_xflags |= FS_XFLAG_PROJINHERIT;
        } else {
            fsx.fsx_xflags &= ~uint32_t(FS_XFLAG_PROJINHERIT);
        }

        if (::ioctl(held.get(), FS_IOC_FSSETXATTR, &fsx) != 0) {
            return errno == ENOTTY || errno == EOPNOTSUPP ? -ENOTSUP : -errno;
        }

        return SBOX_OK;
    }

    /* Sets the block limit of a project. */
    int32_t SetProjectLimit(const std::string& path, uint32_t id, uint64_t bytes) noexcept {
        if (QuotaFsOf(path) == EQFS_XFS) {
            fs_disk_quota d{};
            d.d_version = FS_DQUOT_VERSION;
            d.d_id = id;
            d.d_flags = FS_PROJ_QUOTA;
            d.d_fieldmask = FS_DQ_BSOFT | FS_DQ_BHARD;
            // --> XFS counts in 512-byte basic blocks.
            d.d_blk_hardlimit = (bytes + 511) / 512;
            d.d_blk_softlimit = d.d_blk_hardlimit;
            int32_t rc = quotaCall(path, Q_XSETQLIM, id, &d);
            return rc < 0 ? mapQuotaError(-rc) : SBOX_OK;
        }

        struct dqblk dq{};
        // --> The generic interface counts block limits in QIF_DQBLKSIZE (1 KiB) units.
        dq.dqb_bhardlimit = (bytes + 1023) / 1024;
        dq.dqb_bsoftlimit = dq.dqb_bhardlimit;
        dq.dqb_valid = QIF_BLIMITS;
        int32_t rc = quotaCall(path, Q_SETQUOTA, id, &dq);
        return rc < 0 ? mapQuotaError(-rc) : SBOX_OK;
    }

    /* Reads usage and limit of a project. */
    int32_t GetProjectUsage(const std::string& path, uint32_t id, SQuotaUsage& out) noexcept {
        out = SQuotaUsage();
        if (QuotaFsOf(path) == EQFS_XFS) {
            fs_disk_quota d{};
            int32_t rc = quotaCall(path, Q_XGETQUOTA, id, &d);
            if (rc < 0) {
                return mapQuotaError(-rc);
            }

            out.usedBytes = uint64_t(d.d_bcount) * 512;
            out.limitBytes = uint64_t(d.d_blk_hardlimit) * 512;
            out.usedInodes = d.d_icount;
            return SBOX_OK;
        }

        struct dqblk dq{};
        int32_t rc = quotaCall(path, Q_GETQUOTA, id, &dq);
        if (rc < 0) {
            return mapQuotaError(-rc);
        }

        out.usedBytes = dq.dqb_curspace;
        out.limitBytes = uint64_t(dq.dqb_bhardlimit) * 1024;
        out.usedInodes = dq.dqb_curinodes;
        return SBOX_OK;
    }

    /* Returns the block device of the mount containing `path`. */
    std::string BlockDeviceOf(const std::string& path) {
        struct stat st{};
        if (::stat(path.c_str(), &st) != 0) {
            return std::string();
        }

        std::string text;
        if (CFile::readAll("/proc/self/mountinfo", text) != SBOX_OK) {
            return std::string();
        }

        std::string want = std::to_string(major(st.st_dev)) + ":" + std::to_string(minor(st.st_dev));
        std::string found;
        for (std::string_view line : CFile::splitLines(text)) {
            // --> "<id> <parent> <major:minor> <root> <mountpoint> <opts> [optional...] - <fstype> <source> <super opts>"
            size_t p1 = line.find(' ');
            size_t p2 = p1 == std::string_view::npos ? p1 : line.find(' ', p1 + 1);
            size_t p3 = p2 == std::string_view::npos ? p2 : line.find(' ', p2 + 1);
            if (p3 == std::string_view::npos || line.substr(p2 + 1, p3 - p2 - 1) != want) {
                continue;
            }

            size_t sep = line.find(" - ");
            if (sep == std::string_view::npos) {
                continue;
            }

            std::string_view rest = line.substr(sep + 3);
            size_t a = rest.find(' ');
            if (a == std::string_view::npos) {
                continue;
            }

            size_t b = rest.find(' ', a + 1);
            found = std::string(rest.substr(a + 1, b == std::string_view::npos ? std::string_view::npos : b - a - 1));
        }

        return found;
    }

    /* Freezes the filesystem mounted at `path`. */
    int32_t FreezeFs(const std::string& path) noexcept {
        int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        CFd held(fd);
        if (::ioctl(held.get(), FIFREEZE, 0) != 0) {
            return errno == EOPNOTSUPP || errno == ENOTTY ? -ENOTSUP : -errno;
        }

        return SBOX_OK;
    }

    /* Thaws the filesystem mounted at `path`. */
    int32_t ThawFs(const std::string& path) noexcept {
        int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        CFd held(fd);
        return ::ioctl(held.get(), FITHAW, 0) == 0 ? SBOX_OK : -errno;
    }

}
}
