#ifndef __INCLUDE_SBOX_VOL_MOUNT_HPP__
#define __INCLUDE_SBOX_VOL_MOUNT_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vol/store.hpp>

namespace sbox {
namespace vol {

    /**
     * Kind of a container mount request.
     */
    enum EMountType {
        EMT_VOLUME = 0,     // --> Named or anonymous volume from the store.
        EMT_BIND,           // --> Host path.
        EMT_TMPFS,          // --> Private tmpfs.
        EMT_INVALID,
    };

    /**
     * A Docker style mount request (`-v`, `--mount`, `--tmpfs`) before it is resolved.
     */
    struct SMountRequest {
        EMountType type = EMT_VOLUME;
        std::string source;             // --> Volume name (empty: anonymous) or host path.
        std::string target;             // --> Absolute, cleaned path inside the container.
        bool readOnly = false;
        // --
        std::string propagation;        // --> Bind propagation ("rprivate" ... ), empty for the default.
        bool nonRecursive = false;      // --> "bind" instead of "rbind".
        bool createHostPath = false;    // --> -v creates a missing host directory, --mount does not.
        std::string selinuxLabel;       // --> "z" or "Z" as given (no relabeling is done).
        std::string consistency;        // --> consistent / cached / delegated (accepted and ignored).
        // --
        bool noCopy = false;            // --> Do not copy image content into an empty volume.
        std::string volumeDriver;       // --> Empty or "local".
        std::string volumeSubpath;      // --> Mount only this relative path of the volume.
        TStringMap volumeLabels;
        TStringMap volumeOptions;
        // --
        uint64_t tmpfsSize = 0;         // --> Bytes, 0 for the kernel default.
        uint32_t tmpfsMode = 0;         // --> Permission bits, 0 for the default (1777).
        std::vector<std::string> tmpfsOptions;  // --> Extra options of --tmpfs (verbatim).
    };

    /**
     * Parses `-v` / `--volume`: `[source:]target[:mode]` with modes ro, rw, z, Z, nocopy,
     * a propagation (shared, rshared, slave, rslave, private, rprivate) and a consistency
     * (consistent, cached, delegated), each at most once. A source starting with '/' is a bind
     * (created when missing), any other source a volume name, no source an anonymous volume.
     * @param error Receives a reason on failure (optional).
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseVolumeFlag(std::string_view spec, SMountRequest& out, std::string* error = nullptr);

    /**
     * Parses `--mount` (CSV of key=value with double-quote quoting): type (volume, bind,
     * tmpfs), source|src, target|destination|dst, readonly|ro, consistency, bind-propagation,
     * bind-nonrecursive, volume-driver, volume-label, volume-nocopy, volume-subpath, volume-opt,
     * tmpfs-size, tmpfs-mode. Options of another mount type are rejected.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseMountFlag(std::string_view spec, SMountRequest& out, std::string* error = nullptr);

    /**
     * Parses `--tmpfs target[:options]` (options verbatim, Docker's noexec,nosuid,nodev
     * defaults unless overridden by exec / suid / dev).
     */
    SBOX_API int32_t ParseTmpfsFlag(std::string_view spec, SMountRequest& out, std::string* error = nullptr);

    /**
     * Cleans an absolute path lexically ("//a/./b/../c" -> "/a/c").
     * @return SBOX_OK, or -EINVAL for a relative path, an embedded NUL or ".." above "/".
     */
    SBOX_API int32_t CleanAbsolutePath(std::string_view path, std::string& out);

    /**
     * Validates a bind source: absolute, cleaned, existing (or created as a 0755 directory with
     * `create`), and not inside the volume store (bind the volume instead).
     * @param cleaned Receives the cleaned path.
     * @return SBOX_OK, -EINVAL, -ENOENT, or another errno.
     */
    SBOX_API int32_t ValidateHostPath(const std::string& path, bool create, std::string& cleaned,
                                      const std::string& storeRoot = std::string());

    /**
     * Builds the OCI runtime-spec mount object {destination, type, source, options} of a
     * request whose source is already resolved to a host path (a volume's mountpoint for
     * volumes). Binds and volumes: ["rbind"|"bind", "ro"|"rw", <propagation, default rprivate>];
     * tmpfs: ["nosuid","nodev","noexec", ("ro"), "size=..", "mode=.."].
     */
    SBOX_API int32_t BuildOciMount(const SMountRequest& request, const std::string& hostSource, CJson& out);

    /**
     * Turns mount requests into OCI mounts for one container: volumes are created when missing
     * (anonymous ones get a random name and the anonymous label), acquired for `containerId`,
     * and, unless nocopy, filled with the image content found at the target inside `rootfs`
     * when they are empty; bind sources are validated. Duplicate targets are -EINVAL.
     * On failure every volume acquired here is released again.
     * @param rootfs Container root filesystem for copy-up, empty to skip copy-up.
     * @param out Receives one OCI mount object per request, in order.
     * @param error Receives a reason on failure (optional).
     */
    SBOX_API TTask<int32_t> PrepareContainerMounts(CVolumeStore& store, std::vector<SMountRequest> requests,
                                                   std::string containerId, std::string rootfs,
                                                   std::vector<CJson>& out, std::string* error = nullptr);

}
}

#endif
