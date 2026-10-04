#ifndef __INCLUDE_SBOX_VOL_QUOTA_HPP__
#define __INCLUDE_SBOX_VOL_QUOTA_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace vol {

    /**
     * Filesystem family as far as project quotas are concerned.
     */
    enum EQuotaFs {
        EQFS_OTHER = 0,     // --> Generic quota interface (Q_GETQUOTA / Q_SETQUOTA) is tried.
        EQFS_XFS,           // --> XFS: Q_XGETQSTAT / Q_XSETQLIM / Q_XGETQUOTA.
        EQFS_EXT4,          // --> ext4 (feature "project" + "quota", mounted with prjquota).
    };

    /**
     * Usage and limits of one project id.
     */
    struct SQuotaUsage {
        uint64_t usedBytes = 0;
        uint64_t limitBytes = 0;        // --> Hard block limit, 0 for none.
        uint64_t usedInodes = 0;
    };

    /**
     * Returns the quota family of the filesystem holding `path` (statfs magic).
     */
    SBOX_API EQuotaFs QuotaFsOf(const std::string& path) noexcept;

    /**
     * Checks that project quotas are enforced on the filesystem holding `path`.
     *
     * XFS must be mounted with pquota/prjquota (enforcement on), ext4 needs the "project" and
     * "quota" features and the prjquota mount option, and the kernel needs CONFIG_QUOTA.
     * @return SBOX_OK, or -ENOTSUP when project quotas are unavailable there (any other
     *         negated errno means the check itself failed, e.g. -ENOENT).
     */
    SBOX_API int32_t ProbeProjectQuota(const std::string& path) noexcept;

    /**
     * Reads the project id of a file or directory (FS_IOC_FSGETXATTR).
     */
    SBOX_API int32_t GetProjectId(const std::string& path, uint32_t& id) noexcept;

    /**
     * Sets the project id of a directory (FS_IOC_FSSETXATTR) and, with `inherit`, the
     * FS_XFLAG_PROJINHERIT flag so everything created below gets the same id.
     * @return SBOX_OK, -ENOTSUP when the filesystem has no project ids, or another errno.
     */
    SBOX_API int32_t SetProjectId(const std::string& dir, uint32_t id, bool inherit = true) noexcept;

    /**
     * Sets the hard (and soft) block limit of project `id` on the filesystem holding `path`:
     * quotactl(Q_XSETQLIM) on XFS, quotactl(Q_SETQUOTA, PRJQUOTA) elsewhere. quotactl_fd(2) is
     * used when the kernel has it, otherwise the block device is taken from mountinfo.
     * @param bytes Limit in bytes (rounded up to the filesystem's quota unit), 0 removes it.
     * @return SBOX_OK, -ENOTSUP when project quotas are unavailable, or another errno.
     */
    SBOX_API int32_t SetProjectLimit(const std::string& path, uint32_t id, uint64_t bytes) noexcept;

    /**
     * Reads usage and limit of project `id` on the filesystem holding `path`.
     */
    SBOX_API int32_t GetProjectUsage(const std::string& path, uint32_t id, SQuotaUsage& out) noexcept;

    /**
     * Returns the block device mounted at the mount that contains `path` (mountinfo source of
     * the mount whose st_dev matches), or an empty string.
     */
    SBOX_API std::string BlockDeviceOf(const std::string& path);

}
}

#endif
