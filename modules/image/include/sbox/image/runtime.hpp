#ifndef __INCLUDE_SBOX_IMAGE_RUNTIME_HPP__
#define __INCLUDE_SBOX_IMAGE_RUNTIME_HPP__

#include <sbox/core/json.hpp>
#include <sbox/image/snapshot.hpp>
#include <sbox/image/spec.hpp>

namespace sbox {
namespace image {

    /**
     * A user resolved against a root filesystem (runc's GetExecUser semantics).
     */
    struct SBOX_API SResolvedUser {
        uint32_t uid = 0;
        uint32_t gid = 0;
        std::vector<uint32_t> additionalGids;   // --> Groups of /etc/group that list the user.
        std::string home = "/";
        std::string name;
    };

    /**
     * Resolves an image "User" value ("", "name", "uid", "name:group", "uid:gid", ...) through
     * the rootfs /etc/passwd and /etc/group (opened without leaving the rootfs). A numeric uid
     * that is not in /etc/passwd is accepted with gid 0; a name that is not found is an error.
     * @return SBOX_OK, -ENOENT (unknown user or group name), -EINVAL (malformed).
     */
    SBOX_API int32_t ResolveUser(const std::string& rootfs, std::string_view spec, SResolvedUser& out, std::string* error = nullptr);

    /**
     * Returns the capabilities Docker grants a container by default (CAP_CHOWN,
     * CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER, CAP_MKNOD, CAP_NET_RAW, CAP_SETGID,
     * CAP_SETUID, CAP_SETFCAP, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_KILL,
     * CAP_AUDIT_WRITE).
     */
    SBOX_API std::vector<std::string> DefaultCapabilities();

    /**
     * Returns Docker's default seccomp profile (moby profiles/seccomp/default.json format,
     * with archMap, includes/excludes by capability and architecture) as JSON text.
     */
    SBOX_API const char* DockerDefaultSeccompProfile() noexcept;

    /**
     * Converts a Docker-format seccomp profile into the OCI runtime-spec "linux.seccomp"
     * object for an architecture and capability set, as dockerd does: rules whose includes
     * (all listed capabilities present, architecture listed, minimum kernel) or excludes do
     * not fit are dropped, archMap selects the native and secondary architectures.
     * @param goArch Architecture in Go/OCI image spelling ("amd64", "arm64", ...).
     * @param capabilities Bounding set ("CAP_SYS_ADMIN", ...).
     * @return SBOX_OK or -EINVAL for a malformed profile.
     */
    SBOX_API int32_t SeccompProfileToOci(const CJson& profile, std::string_view goArch,
                                         const std::vector<std::string>& capabilities, CJson& out);

    /**
     * Options for turning an image config into an OCI runtime spec (`docker run` knobs).
     */
    struct SBOX_API SBundleOptions {
        std::vector<std::string> args;          // --> Replaces Cmd (like arguments after the image name).
        std::vector<std::string> entrypoint;    // --> Replaces Entrypoint when hasEntrypoint.
        bool hasEntrypoint = false;
        std::vector<std::string> env;           // --> Added/overriding "NAME=value".
        std::string user;                       // --> Overrides the image User.
        std::string workingDir;                 // --> Overrides the image WorkingDir.
        std::string hostname;                   // --> Default: 12 random hex characters.
        std::string rootPath = "rootfs";        // --> root.path in config.json.
        bool terminal = false;
        bool readOnlyRoot = false;
        bool rootless = false;                  // --> Like `runc spec --rootless`: user namespace mapping the
                                                //     caller to 0, no network namespace, /sys bind mount.
        bool seccomp = true;                    // --> Embed the converted Docker default profile.
        bool noNewPrivileges = false;
        std::vector<std::string> capAdd;        // --> "NET_ADMIN" or "CAP_NET_ADMIN"; "ALL" for every capability.
        std::vector<std::string> capDrop;
        std::vector<std::pair<std::string, std::string>> annotations;
    };

    /**
     * Builds an OCI runtime spec (config.json content) from an image config.
     *
     * process: Entrypoint + Cmd (or the overrides), Env (PATH added when missing, HOSTNAME,
     * HOME from /etc/passwd, TERM with a terminal), cwd, user resolved in `rootfs`, Docker's
     * default capabilities, no rlimits. Mounts like Docker's defaults (proc, /dev tmpfs, devpts,
     * shm, mqueue, sysfs, cgroup). linux: pid/ipc/uts/mount/network/cgroup namespaces, Docker's
     * masked and read-only paths, device cgroup rules, the default seccomp profile.
     * Annotations: image labels, then org.opencontainers.image.* from the config (os,
     * architecture, exposedPorts, stopSignal, ...) and the volumes list.
     * @param rootfs Root filesystem used to resolve user and group names ("" skips names).
     */
    SBOX_API int32_t GenerateRuntimeSpec(const SImageConfig& config, const std::string& rootfs, const SBundleOptions& options,
                                         CJson& out, std::string* error = nullptr);

    /**
     * Writes an OCI bundle for an image: `<dir>/<rootPath>` (flattened copy, or an overlay
     * container root mounted there) and `<dir>/config.json`.
     * @param mode ESNAP_COPY flattens the layers into the bundle; ESNAP_OVERLAY prepares a
     *        container root (ID in `containerId`) and mounts it on the bundle's rootfs;
     *        ESNAP_AUTO picks overlay when supported.
     */
    SBOX_API int32_t CreateBundle(CSnapshotter& snapshotter, const SImageInfo& image, const std::string& dir,
                                  const SBundleOptions& options, ESnapshotMode mode, std::string* containerId = nullptr,
                                  std::string* error = nullptr);

}
}

#endif
