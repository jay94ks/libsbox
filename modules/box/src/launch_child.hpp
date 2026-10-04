#ifndef __SRC_BOX_LAUNCH_CHILD_HPP__
#define __SRC_BOX_LAUNCH_CHILD_HPP__

#include <sbox/box/launch.hpp>
#include <deque>
#include <sys/resource.h>
#include <sys/types.h>

namespace sbox {

    /**
     * Kinds of status records the child writes to the report pipe.
     */
    enum LaunchRecordKind : uint32_t {
        REC_SYNC = 1,       // --> Namespaces exist: write id maps / join cgroups, then send "go".
        REC_ERROR,          // --> A setup step failed (error, step, index).
        REC_READY,          // --> Setup done; waiting at the start gate.
        REC_EXEC,           // --> (From a reaper) the payload exec'd or its function started.
        REC_PID,            // --> (From an outer reaper) payload pid in the caller's pid namespace.
        REC_EXIT,           // --> (From a reaper) wait status of the payload in `value`.
    };

    /**
     * One status record (fits PIPE_BUF, so writes are atomic).
     */
    struct LaunchRecord {
        uint32_t kind;
        int32_t error;      // --> Negated errno for REC_ERROR.
        uint32_t step;      // --> LaunchStep.
        int32_t index;      // --> Which mount / device / path, or -1.
        int64_t value;
    };

    /**
     * Setup steps of the child, for error reports.
     */
    enum LaunchStep : uint32_t {
        STEP_NONE = 0,
        STEP_FDS_RELOCATE,
        STEP_PDEATHSIG,
        STEP_SETNS,
        STEP_UNSHARE,
        STEP_SYNC,
        STEP_FORK,
        STEP_OOM_SCORE,
        STEP_LOOPBACK,
        STEP_HOSTNAME,
        STEP_DOMAINNAME,
        STEP_PROPAGATION,
        STEP_ROOTFS,
        STEP_MOUNT,
        STEP_MOUNT_FLAGS,
        STEP_DEVICE,
        STEP_DEV_SYMLINK,
        STEP_PIVOT_ROOT,
        STEP_ROOT_PROPAGATION,
        STEP_SYSCTL,
        STEP_READONLY_PATH,
        STEP_MASKED_PATH,
        STEP_ROOT_READONLY,
        STEP_RLIMIT,
        STEP_TERMINAL,
        STEP_SETSID,
        STEP_CAP_BOUNDING,
        STEP_SETGROUPS,
        STEP_SETGID,
        STEP_SETUID,
        STEP_CAPSET,
        STEP_CAP_AMBIENT,
        STEP_CHDIR,
        STEP_FDS,
        STEP_GATE,
        STEP_NO_NEW_PRIVS,
        STEP_SECCOMP,
        STEP_EXEC,
        STEP_COUNT,
    };

    /**
     * Returns the printable name of a step.
     */
    const char* LaunchStepName(uint32_t step) noexcept;

    /**
     * A mount, resolved for the child.
     */
    struct PlanMount {
        const char* source = nullptr;
        int sourceFd = -1;              // --> Bind source opened by the child: a detached tree
                                        //     (open_tree) or, on old kernels, an O_PATH descriptor.
        bool detached = false;          // --> sourceFd is an open_tree clone.
        const char* target = nullptr;   // --> Relative to the new root ("usr/lib").
        const char* fstype = nullptr;
        unsigned long flags = 0;        // --> Flags for the initial mount(2).
        unsigned long propagation = 0;
        const char* data = nullptr;
        bool bind = false;
        bool sourceIsDir = true;
        bool remount = false;           // --> Bind needing a MS_REMOUNT for ro/nosuid/nodev/noexec.
        unsigned long remountFlags = 0;
        bool recursiveReadOnly = false;
        bool skip = false;              // --> Optional mount whose source is missing.
        bool optional = false;
    };

    /**
     * A device node, resolved for the child.
     */
    struct PlanDevice {
        const char* path = nullptr;     // --> Relative to the new root ("dev/null").
        mode_t mode = 0;                // --> Includes S_IFCHR / S_IFBLK.
        dev_t dev = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        const char* hostPath = nullptr; // --> Host node for the bind fallback.
        int hostFd = -1;                // --> Its descriptor (opened by the child, like a bind source).
        bool detached = false;
    };

    /**
     * A namespace to join.
     */
    struct PlanJoin {
        int fd = -1;
        int nstype = 0;                 // --> CLONE_NEW*.
    };

    /**
     * Everything the child needs, prepared by the parent before clone3 so the child performs no
     * allocation and no non-async-signal-safe call (except a SLaunchSpec::function payload).
     */
    struct LaunchPlan {
        std::deque<std::string> storage;    // --> Owns every string the plan points to.

        // Descriptors (child side).
        int reportFd = -1;
        int syncFd = -1;
        int gateFd = -1;
        int consoleFd = -1;
        std::vector<int*> fdSlots;          // --> Every descriptor field above and below (relocation).
        std::vector<int> relocated;         // --> Scratch space for relocation (one per slot).

        // Namespaces.
        std::vector<PlanJoin> joins;        // --> User namespace first.
        int unshareFlags = 0;               // --> Namespaces created by unshare in the child.
        bool newMountNs = false;
        bool newNetNs = false;
        bool newUtsNs = false;
        bool newUserNs = false;
        int64_t setupUid = -1;              // --> Mapped ids the setup runs as (new user ns).
        int64_t setupGid = -1;
        bool earlyFork = false;             // --> Fork after namespaces (pid ns via unshare/join).
        bool reaper = false;                // --> Fork the payload after setup.
        int parentDeathSignal = 0;

        // Filesystem.
        uint32_t rootfsMode = ERFS_HOST;
        const char* rootPath = nullptr;     // --> Staging dir (tmpfs) or rootfs directory.
        const char* rootTmpfsData = nullptr;
        bool rootReadOnly = false;
        unsigned long rootPropagation = 0;      // --> Applied to "/" before the setup.
        unsigned long rootPropagationAfter = 0; // --> Shared propagation applied after pivot.
        bool noPivot = false;
        std::vector<PlanMount> mounts;
        std::vector<PlanDevice> devices;
        bool devSymlinks = false;
        std::vector<const char*> maskedPaths;
        std::vector<const char*> readonlyPaths;
        std::vector<std::pair<const char*, const char*>> sysctls;   // --> (/proc/sys path, value).
        const char* hostname = nullptr;
        const char* domainname = nullptr;
        bool loopbackUp = false;

        // Process.
        std::vector<char*> argv;
        std::vector<char*> envp;
        const char* executable = nullptr;   // --> Direct path, or nullptr for the PATH search.
        const char* searchPath = nullptr;   // --> PATH value for the search.
        const char* cwd = nullptr;
        uid_t uid = 0;
        gid_t gid = 0;
        std::vector<gid_t> groups;
        bool setGroups = true;
        SCapabilities caps;
        int lastCap = 40;
        bool noNewPrivs = true;
        const CSeccompFilter* seccomp = nullptr;
        std::vector<std::pair<int, struct rlimit>> rlimits;
        const char* oomScoreAdj = nullptr;
        std::vector<SFdMapping> fds;
        int maxTarget = 2;
        bool terminal = false;
        uint16_t rows = 0;
        uint16_t columns = 0;
        bool newSession = true;
        int umask = -1;
        const std::function<int32_t()>* function = nullptr;

        /**
         * Copies a string into the plan's storage and returns its stable C pointer.
         */
        const char* keep(std::string text) {
            storage.push_back(std::move(text));
            return storage.back().c_str();
        }

        /**
         * Registers every descriptor field for relocation (call once the plan is complete).
         */
        void collectFdSlots();
    };

    /**
     * Child side of the launch: runs the setup and execs (never returns).
     */
    [[noreturn]] void RunLaunchChild(LaunchPlan& plan) noexcept;

} // namespace sbox

#endif
