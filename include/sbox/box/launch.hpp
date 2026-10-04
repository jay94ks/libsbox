#ifndef __INCLUDE_SBOX_BOX_LAUNCH_HPP__
#define __INCLUDE_SBOX_BOX_LAUNCH_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <sbox/box/seccomp.hpp>
#include <functional>
#include <optional>

namespace sbox {

    class CCgroup;

    /**
     * Linux namespace kinds (bit set; the values are libsbox's own, not CLONE_NEW*).
     */
    enum ENamespace : uint32_t {
        ENS_NONE    = 0,
        ENS_USER    = 1u << 0,
        ENS_PID     = 1u << 1,
        ENS_MOUNT   = 1u << 2,
        ENS_IPC     = 1u << 3,
        ENS_UTS     = 1u << 4,
        ENS_NET     = 1u << 5,
        ENS_CGROUP  = 1u << 6,
        ENS_TIME    = 1u << 7,
        ENS_ALL     = 0xffu,
    };

    /**
     * One namespace of the launched process: a new one (empty path) or an existing one to join
     * (a path such as /proc/<pid>/ns/net or a bind-mounted namespace file). Kinds that are not
     * listed are shared with the caller.
     */
    struct SNamespaceSpec {
        ENamespace type = ENS_NONE;
        std::string path;
    };

    /**
     * One user namespace ID mapping line (/proc/<pid>/uid_map format).
     */
    struct SIdMap {
        uint32_t inside = 0;
        uint32_t outside = 0;
        uint32_t count = 1;
    };

    /**
     * Where the launched process's root directory comes from.
     */
    enum ERootfsMode : uint32_t {
        ERFS_HOST = 0,      // --> Keep the caller's root (mounts still apply when a mount ns is new).
        ERFS_TMPFS,         // --> A new empty tmpfs root with the listed mounts (sandbox).
        ERFS_DIRECTORY,     // --> An existing directory, e.g. an OCI bundle rootfs or an overlay.
    };

    /**
     * Generic mount entry (bind, rbind, tmpfs, proc, sysfs, devpts, mqueue, cgroup, overlay ...).
     * Destinations are paths inside the new root, resolved without leaving it (symlinks in an
     * untrusted rootfs cannot point a mount outside). Missing destinations are created.
     */
    struct SMountSpec {
        std::string source;
        std::string destination;
        std::string type;                   // --> Filesystem type; empty or "bind" for binds.
        uint64_t flags = 0;                 // --> MS_* flags (MS_BIND, MS_REC, MS_RDONLY, ...).
        uint64_t propagation = 0;           // --> MS_PRIVATE / MS_SLAVE / MS_SHARED / MS_UNBINDABLE (| MS_REC).
        std::string data;                   // --> Filesystem options ("size=64m,mode=1777").
        bool recursiveReadOnly = false;     // --> Make every submount of a bind read-only too.
        bool optional = false;              // --> A missing bind source is skipped, not an error.
    };

    /**
     * Device node to create in the new root. In a user namespace (where mknod is not allowed)
     * the host node of the same path is bind-mounted instead.
     */
    struct SDeviceNode {
        std::string path;                   // --> Path inside the root, e.g. "/dev/null".
        char type = 'c';                    // --> 'c' or 'b'.
        uint32_t major = 0;
        uint32_t minor = 0;
        uint32_t mode = 0666;
        uint32_t uid = 0;
        uint32_t gid = 0;
    };

    /**
     * Resource limit (setrlimit).
     */
    struct SRlimit {
        int resource = 0;                   // --> RLIMIT_*.
        uint64_t soft = 0;
        uint64_t hard = 0;
    };

    /**
     * Capability sets as bit masks (bit n = capability n). Everything defaults to empty: the
     * launched process holds no capability unless asked.
     */
    struct SCapabilities {
        uint64_t bounding = 0;
        uint64_t effective = 0;
        uint64_t permitted = 0;
        uint64_t inheritable = 0;
        uint64_t ambient = 0;
    };

    /**
     * Descriptor to pass into the process: `source` (in the caller) becomes `target` (in the
     * process). Descriptors not listed are closed before exec.
     */
    struct SFdMapping {
        int source = -1;
        int target = -1;
    };

    /**
     * How the start of the payload is gated (OCI create/start split).
     */
    enum EStartGate : uint32_t {
        ESG_NONE = 0,       // --> Exec as soon as setup is done.
        ESG_INTERNAL,       // --> CProcess::start() releases it.
        ESG_FD,             // --> The process reads one byte from `gateFd` (e.g. a FIFO opened O_RDWR).
    };

    /**
     * Description of one containerized process: everything the launcher sets up between clone3
     * and execve. Value type; build it, then call CProcess::spawn.
     */
    struct SLaunchSpec {
        // Process.
        std::vector<std::string> args;          // --> argv; args[0] is searched in PATH from env unless it has a '/'.
        std::vector<std::string> env;
        std::string executable;                 // --> Explicit path to exec instead of the PATH search.
        std::string cwd = "/";
        std::function<int32_t()> function;      // --> Run this instead of exec (forces `reaper`).
        uint32_t uid = 0;
        uint32_t gid = 0;
        std::vector<uint32_t> additionalGids;
        bool newSession = true;                 // --> setsid() so the process leads its own group.
        std::optional<uint32_t> umask;          // --> File mode creation mask for the process.

        // Namespaces and identity.
        std::vector<SNamespaceSpec> namespaces;
        std::vector<SIdMap> uidMappings;        // --> Written by the caller for a new user namespace.
        std::vector<SIdMap> gidMappings;
        bool denySetgroups = false;             // --> Write "deny" to setgroups (forced when unprivileged).
        std::string hostname;
        std::string domainname;

        // Filesystem (needs a new mount namespace unless rootfsMode is ERFS_HOST without mounts).
        ERootfsMode rootfsMode = ERFS_HOST;
        std::string rootfs;                     // --> ERFS_DIRECTORY: the root directory.
        std::string stagingDir = "/tmp";        // --> ERFS_TMPFS: where the new root is assembled.
        std::string rootTmpfsOptions = "mode=0755,size=16m";
        bool rootReadOnly = false;
        uint64_t rootPropagation = 0;           // --> MS_* for "/" (0 = MS_SLAVE | MS_REC, as runc).
        bool noPivot = false;                   // --> MS_MOVE + chroot instead of pivot_root (runc --no-pivot).
        std::vector<SMountSpec> mounts;
        std::vector<SDeviceNode> devices;
        bool devSymlinks = false;               // --> /dev/fd, stdin, stdout, stderr, ptmx symlinks.
        std::vector<std::string> maskedPaths;
        std::vector<std::string> readonlyPaths;
        std::vector<std::pair<std::string, std::string>> sysctls;   // --> ("net.ipv4.ip_forward", "1").
        bool loopbackUp = false;                // --> Bring "lo" up in a new network namespace.

        // Security.
        SCapabilities capabilities;
        bool noNewPrivileges = true;
        std::shared_ptr<const CSeccompFilter> seccomp;  // --> Installed last, right before execve.
        std::vector<SRlimit> rlimits;
        std::optional<int32_t> oomScoreAdj;
        int parentDeathSignal = 0;              // --> PR_SET_PDEATHSIG for the process (0 = none).

        // Standard I/O.
        std::vector<SFdMapping> fds;            // --> E.g. {{in, 0}, {out, 1}, {err, 2}}.
        bool terminal = false;                  // --> Create a pty in the new devpts; slave on 0/1/2.
        int consoleSocketFd = -1;               // --> Send the pty master here (OCI --console-socket).
        uint16_t terminalRows = 0;
        uint16_t terminalColumns = 0;

        // Lifecycle.
        EStartGate gate = ESG_NONE;
        int gateFd = -1;                        // --> ESG_FD: read end the process waits on.
        bool reaper = false;                    // --> An init forks the payload and forwards signals/status.
        CCgroup* cgroup = nullptr;              // --> Joined before the payload runs (must outlive spawn).
        int64_t setupTimeoutMs = 30000;
    };

    /**
     * Exit status and resource usage of a finished process.
     */
    struct SExitStatus {
        bool exited = false;                    // --> Normal exit (exitCode valid).
        bool signaled = false;                  // --> Killed by `signal`.
        bool coreDumped = false;
        int32_t exitCode = 0;
        int32_t signal = 0;
        uint64_t userTimeUs = 0;                // --> waitid rusage (includes reaped descendants).
        uint64_t systemTimeUs = 0;
        uint64_t maxRssBytes = 0;               // --> Largest single-process RSS seen by rusage.
    };

    /**
     * A launched process: pidfd-based handle (no SIGCHLD, no blocking waitpid).
     *
     * After clone3 the child only runs async-signal-safe code on data prepared beforehand, so
     * a multithreaded caller is fine (except for SLaunchSpec::function, which requires the
     * caller to be single-threaded). Setup failures in the child come back precisely: the
     * failing step and errno travel over a close-on-exec pipe, which also tells exec failures
     * apart from success.
     */
    class SBOX_API CProcess {
    private:
        pid_t _pid = -1;
        pid_t _payloadPid = -1;
        CFd _pidfd;
        CFd _report;                // --> Status pipe from the child (non-blocking read end).
        CFd _gate;                  // --> Write end of the internal start gate.
        CFd _pty;                   // --> Pty master when SLaunchSpec::terminal (internal socket).
        int32_t _error = SBOX_OK;
        std::string _failedStep;
        bool _reaped = false;
        bool _forwarded = false;    // --> A reaper reported the payload's own status.
        bool _started = false;      // --> Exec (or the function) has started.
        SExitStatus _status;
        SExitStatus _forwardedStatus;
        std::vector<uint8_t> _pending;  // --> Partial status records.
        bool _reportEof = false;

    public:
        CProcess() noexcept = default;

        CProcess(CProcess&&) noexcept = default;

        CProcess& operator=(CProcess&&) noexcept = default;

        /**
         * Kills a process that was never waited for (SIGKILL) and reaps it if it already died.
         */
        ~CProcess();

        /**
         * Launches a process.
         *
         * Returns once the payload is running (exec succeeded), or -- with a start gate -- once
         * the process finished its setup and waits at the gate.
         * @return SBOX_OK; a negated errno from the caller side (clone3, pipes, id maps); or the
         *         errno of the child step that failed (see failedStep()), in which case the
         *         child has already been reaped.
         */
        static TTask<int32_t> spawn(const SLaunchSpec& spec, CProcess& out);

        /** Returns the pid of the cloned process (the reaper when one is used). */
        inline pid_t pid() const noexcept { return _pid; }

        /** Returns the payload pid in the caller's pid namespace when known, else pid(). */
        inline pid_t payloadPid() const noexcept { return _payloadPid > 0 ? _payloadPid : _pid; }

        /** Returns the pidfd. */
        inline int pidfd() const noexcept { return _pidfd.get(); }

        /** Returns the error of a failed spawn. */
        inline int32_t error() const noexcept { return _error; }

        /** Returns the child setup step that failed ("mount", "pivot_root", "execve", ...). */
        inline const std::string& failedStep() const noexcept { return _failedStep; }

        /** Returns true once the process has been reaped. */
        inline bool isReaped() const noexcept { return _reaped; }

        /**
         * Takes the pty master (SLaunchSpec::terminal without a console socket).
         */
        inline CFd takePty() noexcept { return std::move(_pty); }

        /**
         * Releases an ESG_INTERNAL start gate.
         */
        int32_t start() noexcept;

        /**
         * After start(): waits until exec succeeded or setup reported an error.
         */
        TTask<int32_t> waitStarted(int64_t timeoutMs = 30000);

        /**
         * Sends a signal through the pidfd (to the reaper when one is used; it forwards
         * catchable signals to the payload).
         */
        int32_t kill(int sig) const noexcept;

        /**
         * Waits for the process to exit and reaps it.
         * @return SBOX_OK, -ETIMEDOUT, or another negated errno.
         */
        TTask<int32_t> wait(SExitStatus& out, int64_t timeoutMs = -1);

        /**
         * Reaps the process if it has exited, without waiting.
         * @return SBOX_OK when reaped, -EAGAIN while still running.
         */
        int32_t tryWait(SExitStatus& out) noexcept;

        /**
         * Gives up the handle without killing the process (it keeps running unsupervised,
         * e.g. an OCI container init after `create`).
         * @return The pidfd.
         */
        CFd detach() noexcept;

    private:
        friend struct LaunchSession;
    };

    /**
     * Parses OCI mount options ("ro", "nosuid", "rbind", "rprivate", "mode=755" ...) into an
     * SMountSpec's flags, propagation, recursiveReadOnly ("rro") and data.
     * @return SBOX_OK (unknown options are passed on as filesystem data).
     */
    SBOX_API int32_t ParseMountOptions(const std::vector<std::string>& options, SMountSpec& out);

    /**
     * Returns the default device nodes of a container: null, zero, full, random, urandom, tty.
     */
    SBOX_API std::vector<SDeviceNode> DefaultDevices();

    /**
     * Returns the capability number of a name ("CAP_NET_ADMIN" or "net_admin"), or -ENOENT.
     */
    SBOX_API int32_t CapabilityFromName(std::string_view name) noexcept;

    /**
     * Returns the highest capability the running kernel knows (/proc/sys/kernel/cap_last_cap).
     */
    SBOX_API int32_t CapabilityLast() noexcept;

    /**
     * Returns the number of threads of the calling process (from /proc/self/task).
     */
    SBOX_API int32_t ThreadCount() noexcept;

} // namespace sbox

#endif
