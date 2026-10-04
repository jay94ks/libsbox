#ifndef __INCLUDE_SBOX_BOX_POLICY_HPP__
#define __INCLUDE_SBOX_BOX_POLICY_HPP__

#include <sbox/common.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/box/seccomp.hpp>

namespace sbox {

    /**
     * Access of a host path bound into the sandbox.
     */
    enum EBindMount : uint32_t {
        EBMNT_READ_ONLY = 0,
        EBMNT_READ_WRITE,
    };

    /**
     * Network of the sandbox.
     */
    enum ENetworkMode : uint32_t {
        EBNET_NONE = 0,         // --> A new, empty network namespace with only "lo" up.
        EBNET_HOST,             // --> Share the caller's network namespace.
        EBNET_NAMESPACE,        // --> Join SBoxPolicy::netnsPath (prepared by the net module).
    };

    /**
     * How one standard stream of the sandbox is connected.
     */
    enum EStdioMode : uint32_t {
        EBSTD_PIPE = 0,         // --> A pipe exposed as CSandbox::stdinPipe() etc.
        EBSTD_INHERIT,          // --> The caller's descriptor SBoxStdio::fd.
        EBSTD_NULL,             // --> /dev/null.
    };

    /**
     * A host path made visible in the sandbox. Mounts are nosuid and nodev; read-only mounts
     * are read-only recursively (submounts included).
     */
    struct SBoxMount {
        std::string source;             // --> Host path (directory, file or UNIX socket).
        std::string target;             // --> Path inside the sandbox.
        EBindMount mode = EBMNT_READ_ONLY;
        bool noexec = false;
        bool optional = false;          // --> Skip silently when the source does not exist.
    };

    /**
     * Connection of a standard stream.
     */
    struct SBoxStdio {
        EStdioMode mode = EBSTD_PIPE;
        int fd = -1;                    // --> EBSTD_INHERIT: the caller's descriptor (not consumed).
    };

    /**
     * Block device I/O limit (cgroup io.max / blkio.throttle).
     */
    struct SBoxIoLimit {
        std::string device;             // --> Device node path ("/dev/vda"), or set major/minor.
        int64_t major = -1;
        int64_t minor = -1;
        uint64_t readBps = 0;           // --> 0 = unlimited.
        uint64_t writeBps = 0;
        uint64_t readIops = 0;
        uint64_t writeIops = 0;
    };

    /**
     * Sandbox policy: what the program may see and use. Zero means "not limited" for every
     * numeric limit.
     *
     * Isolation is always on: new user, pid, mount, ipc, uts and cgroup namespaces, a tmpfs root
     * holding only the listed mounts plus a fresh /proc, a size-limited /tmp and a minimal /dev,
     * no capabilities, no_new_privs and a seccomp allowlist.
     */
    struct SBoxPolicy {
        std::vector<SBoxMount> mounts;

        // Resources (cgroups; rlimit fallbacks where cgroups are unavailable).
        int64_t memoryMax = 0;          // --> Bytes (memory.max / memory.limit_in_bytes).
        int64_t swapMax = 0;            // --> Bytes of swap on top of memoryMax (default none).
        int64_t pidsMax = 0;            // --> Processes and threads (pids.max).
        int64_t cpuQuotaUs = 0;         // --> CPU time per period (cpu.max / cfs_quota_us).
        int64_t cpuPeriodUs = 100000;
        std::vector<SBoxIoLimit> ioLimits;

        // Time.
        int64_t wallTimeoutMs = 0;      // --> Enforced by the caller's event loop.
        int64_t cpuTimeLimitMs = 0;     // --> RLIMIT_CPU (rounded up to seconds; SIGXCPU then SIGKILL).

        // Other rlimits.
        int64_t fileSizeMax = 0;        // --> RLIMIT_FSIZE.
        int64_t openFilesMax = 0;       // --> RLIMIT_NOFILE.
        int64_t stackMax = 0;           // --> RLIMIT_STACK.
        int64_t addressSpaceMax = 0;    // --> RLIMIT_AS.
        bool coreDumps = false;         // --> RLIMIT_CORE stays 0 unless true.
        std::vector<SRlimit> rlimits;   // --> Any other RLIMIT_*.

        // Network.
        ENetworkMode network = EBNET_NONE;
        std::string netnsPath;          // --> EBNET_NAMESPACE: e.g. /run/netns/<name>.

        // Filesystem.
        int64_t tmpSize = 64ll << 20;   // --> /tmp tmpfs size.
        bool tmpNoexec = false;
        int64_t shmSize = 16ll << 20;   // --> /dev/shm tmpfs size.
        std::string stagingDir = "/tmp"; // --> Host directory the root is assembled on (hidden after pivot).

        // Process.
        std::string hostname = "sandbox";
        std::string cwd = "/";
        std::vector<std::string> env = { "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8" };
        uint32_t uid = 0;               // --> Inside the sandbox.
        uint32_t gid = 0;
        int64_t hostUid = -1;           // --> Host uid the sandbox user maps to (-1: auto, see docs).
        int64_t hostGid = -1;

        // Security.
        bool seccomp = true;
        ESeccompViolation seccompViolation = ESVIO_ERRNO;
        std::shared_ptr<const SSeccompProfile> seccompProfile;  // --> Replaces the built-in profile.

        // Standard streams.
        SBoxStdio stdinMode;
        SBoxStdio stdoutMode;
        SBoxStdio stderrMode;

        // Cgroups.
        std::string cgroupParent;       // --> Relative parent path; empty picks CCgroup::defaultParent.
        bool requireCgroupLimits = false; // --> Fail instead of falling back to rlimits.

        /**
         * Returns read-only mounts of the host's program directories (/usr, /bin, /sbin, /lib,
         * /lib64 and, when `withEtc`, /etc), skipping those that do not exist.
         */
        static std::vector<SBoxMount> systemMounts(bool withEtc = true);

        /**
         * Tight preset: system directories (no /etc) read-only, no network, 256 MiB memory,
         * 64 processes, one CPU, 10 s wall and CPU time, 64 MiB files, 256 open files,
         * non-executable /tmp, and seccomp violations kill the program.
         */
        static SBoxPolicy strict();

        /**
         * Worker preset: system directories read-only, `dir` writable (and the working
         * directory), the listed UNIX sockets reachable, no network otherwise.
         */
        static SBoxPolicy worker(const std::string& dir, const std::vector<std::string>& sockets = {});

        /**
         * Debugging preset: system directories, the host network, no limits, and seccomp only
         * logs what it would deny.
         */
        static SBoxPolicy permissive();
    };

    /**
     * Why a sandboxed program ended.
     */
    enum EBoxExitReason : uint32_t {
        EBEXIT_INVALID = 0,
        EBEXIT_NORMAL,              // --> exit() with exitCode.
        EBEXIT_SIGNAL,              // --> Killed by `signal` (not by one of the limits below).
        EBEXIT_WALL_TIMEOUT,        // --> wallTimeoutMs expired; everything was killed.
        EBEXIT_MEMORY,              // --> Killed by the OOM killer of its memory limit.
        EBEXIT_SECCOMP,             // --> Killed by the seccomp filter (SIGSYS).
        EBEXIT_CPU_TIME,            // --> cpuTimeLimitMs reached (SIGXCPU / SIGKILL of RLIMIT_CPU).
        EBEXIT_SETUP_FAILURE,       // --> The sandbox could not be set up (error, failedStep).
    };

    /**
     * Where a resource figure was measured.
     */
    enum EBoxStatSource : uint32_t {
        EBSTAT_NONE = 0,
        EBSTAT_CGROUP,              // --> The sandbox's cgroup: every process, page cache included.
        EBSTAT_RUSAGE,              // --> waitid rusage: reaped processes; peak = largest single RSS.
    };

    /**
     * Outcome of a sandbox run.
     */
    struct SBoxResult {
        EBoxExitReason reason = EBEXIT_INVALID;
        int32_t exitCode = 0;
        int32_t signal = 0;
        uint64_t cpuTimeUs = 0;         // --> User + system.
        uint64_t userTimeUs = 0;
        uint64_t systemTimeUs = 0;
        uint64_t peakMemoryBytes = 0;
        int64_t wallTimeMs = 0;
        uint64_t oomKills = 0;
        EBoxStatSource cpuSource = EBSTAT_NONE;
        EBoxStatSource memorySource = EBSTAT_NONE;
        // --
        int32_t error = SBOX_OK;        // --> Setup failure: negated errno.
        std::string failedStep;
        // --
        bool cgroupUsed = false;
        std::vector<std::string> unenforced;    // --> Limits not enforced (or only by an rlimit fallback).
    };

    /**
     * Returns a printable name of an exit reason ("normal", "wall-timeout", ...).
     */
    SBOX_API const char* BoxExitReasonName(EBoxExitReason reason) noexcept;

} // namespace sbox

#endif
