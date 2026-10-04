#ifndef __INCLUDE_SBOX_VOL_LOCAL_HPP__
#define __INCLUDE_SBOX_VOL_LOCAL_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <map>

namespace sbox {
namespace vol {

    /**
     * String map used for volume labels and driver options (sorted, like Go maps in Docker's JSON).
     */
    using TStringMap = std::map<std::string, std::string>;

    /**
     * What a `local` driver volume is backed by, derived from its options.
     */
    enum ELocalKind {
        ELK_DIRECTORY = 0,      // --> No options: a plain directory under the store (optionally quota limited).
        ELK_TMPFS,              // --> type=tmpfs: memory backed, mounted on first use.
        ELK_NFS,                // --> type=nfs / nfs4: kernel NFS client, addr= resolved by us.
        ELK_BIND,               // --> o=bind / rbind: a host path bound onto the volume.
        ELK_DEVICE,             // --> Any other type=<fs> with device= (ext4/xfs block devices, cifs ...).
        ELK_INVALID,
    };

    /**
     * Parsed options of Docker's `local` volume driver (`--opt type=... --opt device=... --opt o=...`,
     * plus `--opt size=...` for a project-quota limit of a directory volume).
     */
    struct SLocalOptions {
        ELocalKind kind = ELK_DIRECTORY;
        std::string type;               // --> Filesystem type as given ("tmpfs", "nfs4", "ext4", "none").
        std::string device;             // --> Mount source ("tmpfs", ":/export", "/dev/sdb1", "/host/path").
        std::string o;                  // --> Raw comma separated mount options.
        uint64_t flags = 0;             // --> MS_* flags taken from `o`.
        std::string data;               // --> Filesystem specific part of `o` (passed to mount(2) as data).
        uint64_t quotaBytes = 0;        // --> size=: project quota limit (directory volumes only), 0 for none.

        /** Returns true when the volume needs a mount(2) on first use. */
        inline bool needsMount() const noexcept { return kind != ELK_DIRECTORY && kind != ELK_INVALID; }
    };

    /**
     * Parses a size the way Docker does (go-units RAMInBytes): a decimal number with an optional
     * binary unit k, m, g, t, p (optionally followed by "b" or "ib"), case-insensitive:
     * "10G" = 10 GiB, "512m", "1.5g", "4096".
     * @return SBOX_OK, -EINVAL for malformed text or -ERANGE on overflow.
     */
    SBOX_API int32_t ParseSize(std::string_view text, uint64_t& out);

    /**
     * Formats a byte count with the largest exact binary unit ("10g", "512m", "3k", "1000").
     */
    SBOX_API std::string FormatSize(uint64_t bytes);

    /**
     * Splits a mount option string ("ro,nosuid,size=10m,mode=1777") into MS_* flags and the
     * filesystem data string, like Docker's mount.ParseOptions. Unknown words go to the data part.
     * @return SBOX_OK or -EINVAL for an empty component.
     */
    SBOX_API int32_t ParseMountOptions(std::string_view options, uint64_t& flags, std::string& data);

    /**
     * Validates and parses `local` driver options with Docker's rules: only type, device, o and
     * size are accepted; type and device require each other; o requires both; size is a project
     * quota for directory volumes. `bind` needs an absolute device path.
     * @param error Receives a human readable reason on failure (optional).
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseLocalOptions(const TStringMap& options, SLocalOptions& out, std::string* error = nullptr);

    /**
     * Mounts a volume's backing filesystem onto `target` (the volume's _data directory).
     *
     * NFS: the kernel client needs a numeric server address, so a host name in `addr=` (or, when
     * there is no addr=, the host part of "host:/export") is resolved here and passed as addr=.
     * Bind volumes apply ro/nosuid/nodev/noexec with a second MS_REMOUNT|MS_BIND call.
     * @return SBOX_OK or a negated errno.
     */
    SBOX_API TTask<int32_t> MountLocalVolume(SLocalOptions options, std::string target);

    /**
     * Unmounts a volume mount (umount2, retried with MNT_DETACH when busy and `lazy`).
     * A target that is not a mount point is not an error.
     */
    SBOX_API int32_t UnmountLocalVolume(const std::string& target, bool lazy = true) noexcept;

    /**
     * Returns true when `path` is the root of a mount.
     */
    SBOX_API bool IsMountPoint(const std::string& path) noexcept;

    /**
     * Copies the contents of `source` (and the ownership and mode of `source` itself) into
     * `target` when `target` is empty -- Docker's copy-up of image content into a fresh volume.
     * Ownership, modes, times, xattrs, symlinks, hardlinks and devices are preserved; symlinks
     * are never followed.
     * @return 1 when content was copied, 0 when nothing was done (target not empty, source
     *         missing or not a directory), or a negated errno.
     */
    SBOX_API int32_t CopyUpIfEmpty(const std::string& source, const std::string& target);

    /**
     * Resolves `path` inside `rootfs` the way a container would see it (symlinks are resolved
     * with rootfs as "/", never leaving it) and returns an O_PATH descriptor for it.
     * @return The descriptor (>= 0) or a negated errno (-ENOENT when missing).
     */
    SBOX_API int32_t OpenInRoot(const std::string& rootfs, const std::string& path) noexcept;

    /**
     * Returns true when the directory `path` has no entries (missing counts as empty).
     */
    SBOX_API bool IsDirectoryEmpty(const std::string& path) noexcept;

}
}

#endif
