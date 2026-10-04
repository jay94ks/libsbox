#include <sbox/box/policy.hpp>
#include <sys/stat.h>

namespace sbox {

    /* Read-only mounts of the host's program directories. */
    std::vector<SBoxMount> SBoxPolicy::systemMounts(bool withEtc) {
        std::vector<SBoxMount> out;

        for (const char* dir : { "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc" }) {
            if (!withEtc && std::string_view(dir) == "/etc") {
                continue;
            }

            struct stat st;
            if (::stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
                out.push_back(SBoxMount{ dir, dir, EBMNT_READ_ONLY, false, false });
            }
        }

        return out;
    }

    /* Tight preset. */
    SBoxPolicy SBoxPolicy::strict() {
        SBoxPolicy p;
        p.mounts = systemMounts(false);
        p.memoryMax = 256ll << 20;
        p.pidsMax = 64;
        p.cpuQuotaUs = 100000;
        p.cpuPeriodUs = 100000;
        p.wallTimeoutMs = 10000;
        p.cpuTimeLimitMs = 10000;
        p.fileSizeMax = 64ll << 20;
        p.openFilesMax = 256;
        p.tmpSize = 64ll << 20;
        p.tmpNoexec = true;
        p.network = EBNET_NONE;
        p.seccomp = true;
        p.seccompViolation = ESVIO_KILL;
        return p;
    }

    /* Worker preset. */
    SBoxPolicy SBoxPolicy::worker(const std::string& dir, const std::vector<std::string>& sockets) {
        SBoxPolicy p;
        p.mounts = systemMounts(true);
        p.mounts.push_back(SBoxMount{ dir, dir, EBMNT_READ_WRITE, false, false });

        for (const std::string& socket : sockets) {
            // --> connect() needs write access to the socket inode.
            p.mounts.push_back(SBoxMount{ socket, socket, EBMNT_READ_WRITE, true, false });
        }

        p.cwd = dir;
        p.memoryMax = 1ll << 30;
        p.pidsMax = 512;
        p.openFilesMax = 4096;
        p.network = EBNET_NONE;
        p.seccomp = true;
        p.seccompViolation = ESVIO_ERRNO;
        return p;
    }

    /* Debugging preset. */
    SBoxPolicy SBoxPolicy::permissive() {
        SBoxPolicy p;
        p.mounts = systemMounts(true);
        p.network = EBNET_HOST;
        p.seccomp = true;
        p.seccompViolation = ESVIO_LOG;
        return p;
    }

    /* Printable exit reason. */
    const char* BoxExitReasonName(EBoxExitReason reason) noexcept {
        switch (reason) {
        case EBEXIT_NORMAL: return "normal";
        case EBEXIT_SIGNAL: return "signal";
        case EBEXIT_WALL_TIMEOUT: return "wall-timeout";
        case EBEXIT_MEMORY: return "memory";
        case EBEXIT_SECCOMP: return "seccomp";
        case EBEXIT_CPU_TIME: return "cpu-time";
        case EBEXIT_SETUP_FAILURE: return "setup-failure";
        default: return "invalid";
        }
    }

} // namespace sbox
