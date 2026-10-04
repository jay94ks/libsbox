#ifndef __INCLUDE_SBOX_BOX_CGROUP_HPP__
#define __INCLUDE_SBOX_BOX_CGROUP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <optional>

namespace sbox {

    /**
     * How the cgroup hierarchies of the host are laid out.
     */
    enum ECgroupLayout : uint32_t {
        ECGL_NONE = 0,          // --> No cgroup filesystem mounted.
        ECGL_V1,                // --> Only v1 per-controller hierarchies.
        ECGL_HYBRID,            // --> v1 controllers plus a v2 tree (usually /sys/fs/cgroup/unified).
        ECGL_V2,                // --> Unified v2 only.
    };

    /**
     * Resource controllers libsbox knows (bit set).
     */
    enum ECgroupController : uint32_t {
        ECGC_NONE       = 0,
        ECGC_CPU        = 1u << 0,
        ECGC_CPUACCT    = 1u << 1,  // --> v1 only; v2 accounts CPU in cpu.stat of every cgroup.
        ECGC_CPUSET     = 1u << 2,
        ECGC_MEMORY     = 1u << 3,
        ECGC_PIDS       = 1u << 4,
        ECGC_IO         = 1u << 5,  // --> v2 "io", v1 "blkio".
        ECGC_FREEZER    = 1u << 6,  // --> v1 only; v2 has cgroup.freeze built in.
        ECGC_DEVICES    = 1u << 7,  // --> v1 only; v2 uses an eBPF program instead.
        ECGC_HUGETLB    = 1u << 8,
        ECGC_ALL        = 0x1ffu,
    };

    /**
     * Where the cgroup filesystems are mounted, as found in /proc/self/mountinfo.
     */
    struct SCgroupSystem {
        ECgroupLayout layout = ECGL_NONE;
        std::string unifiedMount;                   // --> v2 mount point, empty when none.
        uint32_t v2Controllers = ECGC_NONE;         // --> Listed in the v2 root's cgroup.controllers.
        std::vector<std::pair<uint32_t, std::string>> v1Mounts;    // --> (controllers, mount point).
        std::string selfV2Path;                     // --> This process's v2 cgroup ("0::" line).

        /**
         * Detects the layout of the calling process's mount namespace.
         * @return SBOX_OK (also for ECGL_NONE) or a negated errno.
         */
        static int32_t detect(SCgroupSystem& out);

        /**
         * Returns the v1 mount point serving `controller`, or an empty string.
         */
        std::string v1MountOf(uint32_t controller) const;

        /**
         * Returns the controller bits of a name ("memory", "blkio", "io", ...), 0 if unknown.
         */
        static uint32_t controllerFromName(std::string_view name) noexcept;
    };

    /**
     * Per-device throttle (OCI `blockIO.throttle*Device`).
     */
    struct SCgroupThrottle {
        int64_t major = 0;
        int64_t minor = 0;
        uint64_t rate = 0;          // --> Bytes or operations per second.
    };

    /**
     * Device access rule (OCI `linux.resources.devices`). Rules are evaluated last-match-wins on
     * top of "allow everything", which is how the v1 device controller behaves for the usual
     * "deny all, then allow these" lists.
     */
    struct SCgroupDeviceRule {
        bool allow = false;
        char type = 'a';            // --> 'a' (all), 'c' (char) or 'b' (block).
        int64_t major = -1;         // --> -1 matches any.
        int64_t minor = -1;         // --> -1 matches any.
        std::string access = "rwm";
    };

    /**
     * Resource limits: the OCI `linux.resources` subset libsbox enforces. Only fields that are
     * set are written; everything else keeps the kernel default.
     */
    struct SCgroupResources {
        std::optional<int64_t> memoryLimit;         // --> Bytes, -1 = unlimited.
        std::optional<int64_t> memoryReservation;   // --> Soft limit (v2 memory.low).
        std::optional<int64_t> memorySwap;          // --> OCI: memory + swap total, -1 = unlimited.
        std::optional<int64_t> pidsLimit;           // --> -1 = unlimited.
        std::optional<uint64_t> cpuShares;          // --> v1 shares (2..262144), mapped to v2 weight.
        std::optional<uint64_t> cpuWeight;          // --> v2 weight (1..10000), wins over shares on v2.
        std::optional<int64_t> cpuQuota;            // --> Microseconds per period, -1 = unlimited.
        std::optional<uint64_t> cpuPeriod;          // --> Microseconds (default 100000).
        std::string cpusetCpus;
        std::string cpusetMems;
        std::optional<uint16_t> blkioWeight;        // --> 10..1000.
        std::vector<SCgroupThrottle> readBps;
        std::vector<SCgroupThrottle> writeBps;
        std::vector<SCgroupThrottle> readIops;
        std::vector<SCgroupThrottle> writeIops;
        std::vector<SCgroupDeviceRule> devices;
        std::vector<std::pair<std::string, std::string>> unified;  // --> Raw v2 knobs (OCI `unified`).

        /** Returns true when nothing is set. */
        bool empty() const noexcept;
    };

    /**
     * Statistics read from a cgroup. The `has*` flags say which groups of values are valid.
     */
    struct SCgroupStats {
        bool hasMemory = false;
        bool hasCpu = false;
        bool hasPids = false;
        // --
        uint64_t memoryCurrent = 0;
        uint64_t memoryPeak = 0;        // --> v2 memory.peak / v1 memory.max_usage_in_bytes.
        uint64_t oomEvents = 0;         // --> Times the limit was hit and reclaim failed.
        uint64_t oomKills = 0;          // --> Processes the OOM killer killed in this cgroup.
        // --
        uint64_t cpuUsageUs = 0;
        uint64_t cpuUserUs = 0;
        uint64_t cpuSystemUs = 0;
        // --
        uint64_t pidsCurrent = 0;
    };

    /**
     * One cgroup, spanning every hierarchy that serves it (the v2 tree and/or v1 controllers).
     *
     * Paths are relative to the hierarchy roots ("sbox/job-1"). On a hybrid host the v2 tree is
     * used for membership, cgroup.kill and CPU accounting while the limits go to the v1
     * controllers that are not available in v2.
     */
    class SBOX_API CCgroup {
    private:
        SCgroupSystem _system;
        std::string _path;
        std::string _v2Dir;                                     // --> Absolute, empty when none.
        std::vector<std::pair<uint32_t, std::string>> _v1Dirs;  // --> (controllers, absolute dir).
        uint32_t _controllers = ECGC_NONE;                      // --> Controllers usable here.
        CFd _v2Fd;
        CFd _deviceProgram;                                     // --> Attached v2 device filter.

    public:
        CCgroup() noexcept = default;

        CCgroup(CCgroup&&) noexcept = default;

        CCgroup& operator=(CCgroup&&) noexcept = default;

        /**
         * Creates (or reuses) a cgroup in every hierarchy, enabling the wanted v2 controllers on
         * the way down. A controller that cannot be enabled is simply not available afterwards.
         * @param path Relative path, e.g. "sbox/job-1".
         * @param out Receives the cgroup.
         * @param controllers Controllers wanted (ECgroupController bits).
         * @return SBOX_OK, -ENOENT when no cgroup filesystem is mounted, -EACCES when the
         *         caller may not create it, or another negated errno.
         */
        static int32_t create(const std::string& path, CCgroup& out, uint32_t controllers = ECGC_ALL);

        /**
         * Opens an existing cgroup without creating anything.
         */
        static int32_t open(const std::string& path, CCgroup& out);

        /**
         * Picks the parent path for new cgroups: "sbox" for root; for other users the topmost
         * delegated v2 cgroup they own (systemd `Delegate=yes`), plus "/sbox".
         * @return SBOX_OK, or -EACCES when no delegated subtree exists (rootless without
         *         delegation: run without cgroups).
         */
        static int32_t defaultParent(std::string& out);

        /** Returns the relative path. */
        inline const std::string& path() const noexcept { return _path; }

        /** Returns true when the cgroup was created/opened. */
        inline bool isValid() const noexcept { return !_path.empty(); }

        /** Returns the controllers limits can be set on. */
        inline uint32_t controllers() const noexcept { return _controllers; }

        /** Returns the layout of the host. */
        inline const SCgroupSystem& system() const noexcept { return _system; }

        /** Returns the v2 directory descriptor (O_PATH|O_DIRECTORY) for CLONE_INTO_CGROUP, or -1. */
        inline int v2Fd() const noexcept { return _v2Fd.get(); }

        /** Returns the absolute v2 directory, or an empty string. */
        inline const std::string& v2Dir() const noexcept { return _v2Dir; }

        /** Returns the absolute v1 directories with the controllers each one serves. */
        inline const std::vector<std::pair<uint32_t, std::string>>& v1Dirs() const noexcept { return _v1Dirs; }

        /**
         * Writes the configured limits.
         * @param res Limits; unset fields are not touched.
         * @param skipped When not null, receives the names of limits that could not be enforced
         *        because their controller is not available here ("memory", "pids", ...).
         * @return SBOX_OK, or the negated errno of the first knob the kernel rejected.
         */
        int32_t apply(const SCgroupResources& res, std::vector<std::string>* skipped = nullptr);

        /**
         * Reads statistics.
         */
        int32_t stats(SCgroupStats& out) const;

        /**
         * Moves a process into the cgroup in every hierarchy.
         * @param v1Only Skip the v2 tree (the process was already placed with CLONE_INTO_CGROUP).
         */
        int32_t addProcess(pid_t pid, bool v1Only = false) const;

        /**
         * Lists the processes in the cgroup (the v2 tree when present, else the first v1 one).
         */
        int32_t processes(std::vector<pid_t>& out) const;

        /**
         * Returns true while any process is in the cgroup.
         */
        bool isPopulated() const;

        /**
         * Sends `sig` to every process: SIGKILL goes through cgroup.kill on v2 (5.14+);
         * otherwise the cgroup is frozen, each process signalled and the cgroup thawed, so that
         * nothing can fork away in between.
         */
        int32_t signalAll(int sig) const;

        /**
         * Freezes or thaws every process (v2 cgroup.freeze or the v1 freezer) and waits until the
         * kernel reports the new state.
         */
        TTask<int32_t> freeze(bool frozen, int64_t timeoutMs = 5000) const;

        /**
         * Kills every process and waits until the cgroup is empty.
         * @return SBOX_OK, -ETIMEDOUT, or another negated errno.
         */
        TTask<int32_t> killAll(int64_t timeoutMs = 5000) const;

        /**
         * Waits until no process is left (zombies of the caller's own children count until they
         * are reaped).
         */
        TTask<int32_t> waitEmpty(int64_t timeoutMs = 5000) const;

        /**
         * Removes the cgroup directories (the parents created on the way stay).
         * @return SBOX_OK, -EBUSY while processes remain, or another negated errno.
         */
        int32_t destroy();
    };

} // namespace sbox

#endif
