#include <sbox/oci/seccomp.hpp>
#include "jsonread.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <sys/utsname.h>

namespace sbox {
namespace oci {

    namespace {

        /**
         * Maps an OCI action name to the box action.
         */
        int32_t actionOf(const std::string& name, ESeccompAction& out, std::string& error) {
            static const std::pair<const char*, ESeccompAction> ACTIONS[] = {
                { "SCMP_ACT_KILL", ESACT_KILL_THREAD }, { "SCMP_ACT_KILL_THREAD", ESACT_KILL_THREAD },
                { "SCMP_ACT_KILL_PROCESS", ESACT_KILL_PROCESS }, { "SCMP_ACT_TRAP", ESACT_TRAP },
                { "SCMP_ACT_ERRNO", ESACT_ERRNO }, { "SCMP_ACT_TRACE", ESACT_TRACE }, { "SCMP_ACT_LOG", ESACT_LOG },
                { "SCMP_ACT_ALLOW", ESACT_ALLOW },
            };

            for (const auto& [n, a] : ACTIONS) {
                if (name == n) {
                    out = a;
                    return SBOX_OK;
                }
            }

            if (name == "SCMP_ACT_NOTIFY") {
                error = "seccomp action SCMP_ACT_NOTIFY (user space notification) is not supported";
                return -ENOTSUP;
            }

            error = "unknown seccomp action \"" + name + "\"";
            return -EINVAL;
        }

        /**
         * Maps an OCI operator name to the box operator.
         */
        ESeccompCompare operatorOf(const std::string& name) {
            static const std::pair<const char*, ESeccompCompare> OPS[] = {
                { "SCMP_CMP_NE", ESCMP_NE }, { "SCMP_CMP_LT", ESCMP_LT }, { "SCMP_CMP_LE", ESCMP_LE },
                { "SCMP_CMP_EQ", ESCMP_EQ }, { "SCMP_CMP_GE", ESCMP_GE }, { "SCMP_CMP_GT", ESCMP_GT },
                { "SCMP_CMP_MASKED_EQ", ESCMP_MASKED_EQ },
            };

            for (const auto& [n, op] : OPS) {
                if (name == n) {
                    return op;
                }
            }

            return ESCMP_INVALID;
        }

        /**
         * Returns the Go architecture name of the native ABI.
         */
        std::string nativeGoArch() {
            switch (SeccompNativeArch()) {
            case ESARCH_X86_64:
                return "amd64";
            case ESARCH_AARCH64:
                return "arm64";
            case ESARCH_X86:
                return "386";
            default:
                return "unknown";
            }
        }

        /**
         * Returns the OCI architecture name of a Go architecture.
         */
        std::string seccompArchOfGo(const std::string& goArch) {
            if (goArch == "amd64") {
                return "SCMP_ARCH_X86_64";
            }

            if (goArch == "arm64") {
                return "SCMP_ARCH_AARCH64";
            }

            if (goArch == "386") {
                return "SCMP_ARCH_X86";
            }

            return "SCMP_ARCH_" + goArch;
        }

        /**
         * Parses "4.8" into (major, minor).
         */
        bool parseKernel(const std::string& text, uint32_t& major, uint32_t& minor) {
            char* end = nullptr;
            unsigned long a = std::strtoul(text.c_str(), &end, 10);
            if (end == text.c_str()) {
                return false;
            }

            unsigned long b = 0;
            if (*end == '.') {
                b = std::strtoul(end + 1, nullptr, 10);
            }

            major = uint32_t(a);
            minor = uint32_t(b);
            return true;
        }

        bool contains(const std::vector<std::string>& list, const std::string& item) {
            return std::find(list.begin(), list.end(), item) != list.end();
        }

    }

    /* Converts linux.seccomp to a box profile. */
    int32_t SeccompProfileFromSpec(const SSeccompSpec& spec, SSeccompProfile& out, std::string& error, std::vector<std::string>* warnings) {
        out = SSeccompProfile();

        if (int32_t rc = actionOf(spec.defaultAction, out.defaultAction, error); rc != SBOX_OK) {
            error = "linux.seccomp.defaultAction: " + error;
            return rc;
        }

        out.defaultErrno = spec.defaultErrnoRet.value_or(EPERM);

        // --> libseccomp always includes the native architecture in a filter.
        out.architectures.push_back(SeccompNativeArch());
        for (const std::string& name : spec.architectures) {
            ESeccompArch arch = SeccompArchFromName(name);
            if (arch == ESARCH_INVALID) {
                if (warnings) {
                    warnings->push_back("linux.seccomp: architecture " + name + " is not supported here; its rules are skipped");
                }

                continue;
            }

            if (std::find(out.architectures.begin(), out.architectures.end(), arch) == out.architectures.end()) {
                out.architectures.push_back(arch);
            }
        }

        for (const std::string& flag : spec.flags) {
            if (flag == "SECCOMP_FILTER_FLAG_LOG") {
                out.flags |= ESECF_LOG;
            } else if (flag == "SECCOMP_FILTER_FLAG_SPEC_ALLOW") {
                out.flags |= ESECF_SPEC_ALLOW;
            } else if (flag == "SECCOMP_FILTER_FLAG_TSYNC") {
                // --> The container process is single-threaded when the filter is installed.
            } else if (flag == "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV") {
                // --> Only meaningful with SCMP_ACT_NOTIFY, which is refused below.
            } else {
                error = "linux.seccomp.flags: unknown flag \"" + flag + "\"";
                return -EINVAL;
            }
        }

        for (size_t i = 0; i < spec.syscalls.size(); ++i) {
            const SSyscallSpec& call = spec.syscalls[i];
            SSeccompRule rule;
            rule.names = call.names;

            if (int32_t rc = actionOf(call.action, rule.action, error); rc != SBOX_OK) {
                error = "linux.seccomp.syscalls[" + std::to_string(i) + "]: " + error;
                return rc;
            }

            rule.errnoRet = call.errnoRet.value_or(EPERM);

            for (const SSeccompArgSpec& a : call.args) {
                SSeccompArg arg;
                arg.index = a.index;
                arg.op = operatorOf(a.op);
                arg.value = a.value;
                arg.valueTwo = a.valueTwo;

                if (arg.op == ESCMP_INVALID) {
                    error = "linux.seccomp.syscalls[" + std::to_string(i) + "]: unknown operator \"" + a.op + "\"";
                    return -EINVAL;
                }

                if (a.index > 5) {
                    error = "linux.seccomp.syscalls[" + std::to_string(i) + "]: argument index out of range";
                    return -EINVAL;
                }

                rule.args.push_back(arg);
            }

            out.rules.push_back(std::move(rule));
        }

        if (!spec.listenerPath.empty() && warnings) {
            warnings->push_back("linux.seccomp.listenerPath is ignored (SCMP_ACT_NOTIFY is not supported)");
        }

        return SBOX_OK;
    }

    /* Compiles linux.seccomp. */
    int32_t CompileSeccompSpec(const SSeccompSpec& spec, CSeccompFilter& out, std::string& error, std::vector<std::string>* warnings, std::vector<std::string>* unknown) {
        SSeccompProfile profile;
        if (int32_t rc = SeccompProfileFromSpec(spec, profile, error, warnings); rc != SBOX_OK) {
            return rc;
        }

        int32_t rc = CSeccompFilter::compile(profile, out, unknown);
        if (rc == -E2BIG) {
            error = "linux.seccomp: the filter exceeds the kernel's 4096 instruction limit";
        } else if (rc != SBOX_OK) {
            error = "linux.seccomp: cannot compile the filter";
        }

        return rc;
    }

    /* Returns the context of this host. */
    SDockerSeccompContext SDockerSeccompContext::host(std::vector<std::string> caps) {
        SDockerSeccompContext c;
        c.capabilities = std::move(caps);
        c.goArch = nativeGoArch();

        struct utsname u;
        if (::uname(&u) == 0) {
            parseKernel(u.release, c.kernelMajor, c.kernelMinor);
        }

        return c;
    }

    /* Resolves a Docker profile into an OCI section. */
    int32_t SeccompSpecFromDockerProfile(const CJson& profile, const SDockerSeccompContext& context, SSeccompSpec& out, std::string& error) {
        out = SSeccompSpec();
        error.clear();
        JsonReader r(error, nullptr);

        if (!r.expectObject(profile, "seccomp profile")) {
            return -EINVAL;
        }

        std::vector<std::string> arches;
        if (!r.str(profile, "defaultAction", out.defaultAction, "") || !r.optU32(profile, "defaultErrnoRet", out.defaultErrnoRet, "") ||
            !r.strings(profile, "architectures", arches, "") || !r.strings(profile, "flags", out.flags, "") ||
            !r.str(profile, "listenerPath", out.listenerPath, "") || !r.str(profile, "listenerMetadata", out.listenerMetadata, "")) {
            return -EINVAL;
        }

        const CJson* archMap = profile.find("archMap");
        if (!arches.empty() && archMap && !archMap->isNull()) {
            error = "seccomp profile: 'architectures' and 'archMap' cannot both be set";
            return -EINVAL;
        }

        out.architectures = arches;
        if (archMap && !archMap->isNull()) {
            if (!r.expectArray(*archMap, "archMap")) {
                return -EINVAL;
            }

            std::string native = seccompArchOfGo(context.goArch);
            for (size_t i = 0; i < archMap->size(); ++i) {
                const CJson& entry = archMap->at(i);
                std::string p = "archMap[" + std::to_string(i) + "]";
                std::string arch;
                std::vector<std::string> subs;
                if (!r.expectObject(entry, p) || !r.str(entry, "architecture", arch, p) || !r.strings(entry, "subArchitectures", subs, p)) {
                    return -EINVAL;
                }

                if (arch == native) {
                    out.architectures.push_back(arch);
                    out.architectures.insert(out.architectures.end(), subs.begin(), subs.end());
                }
            }
        }

        const CJson* calls = profile.find("syscalls");
        if (!calls || calls->isNull()) {
            return SBOX_OK;
        }

        if (!r.expectArray(*calls, "syscalls")) {
            return -EINVAL;
        }

        for (size_t i = 0; i < calls->size(); ++i) {
            const CJson& c = calls->at(i);
            std::string p = "syscalls[" + std::to_string(i) + "]";
            if (!r.expectObject(c, p)) {
                return -EINVAL;
            }

            SSyscallSpec call;
            std::string single;
            if (!r.str(c, "name", single, p) || !r.strings(c, "names", call.names, p) || !r.str(c, "action", call.action, p) ||
                !r.optU32(c, "errnoRet", call.errnoRet, p)) {
                return -EINVAL;
            }

            if (!single.empty() && !call.names.empty()) {
                error = p + ": 'name' and 'names' cannot both be set";
                return -EINVAL;
            }

            if (!single.empty()) {
                call.names = { single };
            }

            // --> Filters: excludes first, then includes (dockerd's order).
            bool keep = true;
            for (const char* section : { "excludes", "includes" }) {
                const CJson* f = c.find(section);
                if (!keep || !f || f->isNull()) {
                    continue;
                }

                std::string q = p + "." + section;
                std::vector<std::string> caps, archs;
                std::string minKernel;
                if (!r.expectObject(*f, q) || !r.strings(*f, "caps", caps, q) || !r.strings(*f, "arches", archs, q) ||
                    !r.str(*f, "minKernel", minKernel, q)) {
                    return -EINVAL;
                }

                uint32_t kmaj = 0, kmin = 0;
                bool hasKernel = !minKernel.empty();
                if (hasKernel && !parseKernel(minKernel, kmaj, kmin)) {
                    error = q + ".minKernel: invalid kernel version \"" + minKernel + "\"";
                    return -EINVAL;
                }

                bool kernelAtLeast = context.kernelMajor > kmaj || (context.kernelMajor == kmaj && context.kernelMinor >= kmin);

                if (std::string(section) == "excludes") {
                    if (contains(archs, context.goArch)) {
                        keep = false;
                    }

                    for (const std::string& cap : caps) {
                        keep = keep && !contains(context.capabilities, cap);
                    }

                    if (hasKernel && kernelAtLeast) {
                        keep = false;
                    }
                } else {
                    if (!archs.empty() && !contains(archs, context.goArch)) {
                        keep = false;
                    }

                    for (const std::string& cap : caps) {
                        keep = keep && contains(context.capabilities, cap);
                    }

                    if (hasKernel && !kernelAtLeast) {
                        keep = false;
                    }
                }
            }

            if (!keep) {
                continue;
            }

            if (const CJson* args = c.find("args"); args && !args->isNull()) {
                std::string q = p + ".args";
                if (!r.expectArray(*args, q)) {
                    return -EINVAL;
                }

                for (size_t j = 0; j < args->size(); ++j) {
                    const CJson& a = args->at(j);
                    std::string e = q + "[" + std::to_string(j) + "]";
                    SSeccompArgSpec arg;
                    if (!r.expectObject(a, e) || !r.u32(a, "index", arg.index, e) || !r.u64(a, "value", arg.value, e) ||
                        !r.u64(a, "valueTwo", arg.valueTwo, e) || !r.str(a, "op", arg.op, e)) {
                        return -EINVAL;
                    }

                    call.args.push_back(arg);
                }
            }

            out.syscalls.push_back(std::move(call));
        }

        return SBOX_OK;
    }

    /* Returns Docker's default capability set. */
    std::vector<std::string> DockerDefaultCapabilities() {
        return {
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID",
            "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL",
            "CAP_AUDIT_WRITE",
        };
    }

}
}
