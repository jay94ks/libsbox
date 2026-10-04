#ifndef __INCLUDE_SBOX_OCI_SECCOMP_HPP__
#define __INCLUDE_SBOX_OCI_SECCOMP_HPP__

#include <sbox/common.hpp>
#include <sbox/box/seccomp.hpp>
#include <sbox/core/json.hpp>
#include <sbox/oci/spec.hpp>

namespace sbox {
namespace oci {

    /**
     * Converts an OCI `linux.seccomp` section to a box seccomp profile with runc's semantics:
     * SCMP_ACT_KILL is KILL_THREAD, ERRNO and TRACE without errnoRet use EPERM, the native
     * architecture is always part of the filter (as libseccomp does), architectures the box
     * compiler has no table for are skipped with a warning, SECCOMP_FILTER_FLAG_TSYNC is
     * implied (the process is single-threaded when the filter is installed).
     * @param error Receives the reason on failure (SCMP_ACT_NOTIFY, unknown flags ...).
     * @return SBOX_OK, -EINVAL or -ENOTSUP.
     */
    SBOX_API int32_t SeccompProfileFromSpec(const SSeccompSpec& spec, SSeccompProfile& out, std::string& error, std::vector<std::string>* warnings = nullptr);

    /**
     * Compiles an OCI `linux.seccomp` section into a BPF filter.
     * @param unknown When not null, receives system call names no architecture knows (they are
     *        skipped, as runc does).
     */
    SBOX_API int32_t CompileSeccompSpec(const SSeccompSpec& spec, CSeccompFilter& out, std::string& error, std::vector<std::string>* warnings = nullptr, std::vector<std::string>* unknown = nullptr);

    /**
     * What a Docker seccomp profile (profiles/seccomp/default.json format) is resolved against.
     */
    struct SDockerSeccompContext {
        std::vector<std::string> capabilities;  // --> The container's bounding set ("CAP_SYS_ADMIN").
        std::string goArch;                     // --> Go architecture name ("amd64", "arm64").
        uint32_t kernelMajor = 0;
        uint32_t kernelMinor = 0;

        /**
         * Returns the context of this host (native architecture, running kernel) for `caps`.
         */
        static SDockerSeccompContext host(std::vector<std::string> caps);
    };

    /**
     * Resolves a Docker seccomp profile into the OCI section dockerd would write to config.json:
     * `archMap` entries of the native architecture (with their sub-architectures), and only the
     * rules whose `includes`/`excludes` (capabilities, architectures, minimum kernel) match.
     * @return SBOX_OK or -EINVAL (with `error`).
     */
    SBOX_API int32_t SeccompSpecFromDockerProfile(const CJson& profile, const SDockerSeccompContext& context, SSeccompSpec& out, std::string& error);

    /**
     * Returns Docker's default capability set (the bounding set of `docker run` without
     * --cap-add/--cap-drop).
     */
    SBOX_API std::vector<std::string> DockerDefaultCapabilities();

}
}

#endif
