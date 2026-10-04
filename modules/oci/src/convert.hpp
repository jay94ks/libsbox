#ifndef __SRC_OCI_CONVERT_HPP__
#define __SRC_OCI_CONVERT_HPP__

#include <sbox/box/cgroup.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/oci/spec.hpp>

namespace sbox {
namespace oci {

    /**
     * Inputs of the container init translation besides the configuration.
     */
    struct InitContext {
        std::string bundle;                     // --> Absolute bundle directory.
        std::string rootfs;                     // --> Absolute rootfs directory.
        CCgroup* cgroup = nullptr;              // --> The container cgroup, or null.
        bool noPivot = false;
    };

    /**
     * Fills the process part of a launch spec (args, env, cwd, identity, capabilities, rlimits,
     * no_new_privs, terminal size) from an OCI process.
     */
    int32_t ApplyProcess(const SProcessSpec& process, SLaunchSpec& out, std::string& error, std::vector<std::string>& warnings);

    /**
     * Translates a configuration into the launch spec of the container init (namespaces, id
     * maps, rootfs, mounts, devices, masked/read-only paths, sysctls, process). Seccomp,
     * descriptors, the start gate and the console are added by the caller.
     */
    int32_t BuildInitSpec(const SSpec& spec, const InitContext& context, SLaunchSpec& out, std::string& error, std::vector<std::string>& warnings);

    /**
     * Converts OCI resources to box cgroup resources (unsupported knobs become warnings).
     */
    void ToCgroupResources(const SResourcesSpec& res, SCgroupResources& out, std::vector<std::string>& warnings);

    /**
     * Returns the device rules runc always allows (null, zero, full, random, urandom, tty,
     * console, ptmx, pts, tun, mknod of anything) plus one rule per configured device node.
     */
    std::vector<SCgroupDeviceRule> DefaultDeviceRules(const SSpec& spec);

    /**
     * Expands a systemd cgroupsPath "slice:prefix:name" into a cgroupfs path
     * ("system.slice:docker:abc" -> "system.slice/docker-abc.scope").
     * @return SBOX_OK or -EINVAL.
     */
    int32_t ExpandSystemdCgroupPath(const std::string& path, bool rootless, std::string& out);

    /**
     * Converts an OCI propagation name ("rslave") to MS_* flags (0 for "").
     */
    uint64_t PropagationFlags(const std::string& name) noexcept;

}
}

#endif
