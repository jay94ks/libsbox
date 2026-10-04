#include <sbox/box/sandbox.hpp>
#include <sbox/box/cgroup.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/core/eventloop.hpp>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace sbox {

    /**
     * Shared state of a sandbox: owned by the CSandbox handle and by its supervisor task.
     */
    struct CSandbox::SState {
        CEventLoop* loop = nullptr;
        SBoxPolicy policy;
        CProcess process;
        CCgroup cgroup;
        bool hasCgroup = false;
        CStream in;
        CStream out;
        CStream err;
        int64_t startMs = 0;
        bool started = false;
        bool timedOut = false;
        bool killed = false;
        bool done = false;
        SBoxResult result;
        std::vector<std::coroutine_handle<>> waiters;
        std::vector<std::string> unenforced;
        bool memoryByCgroup = false;

        ~SState() {
            if (started && !done) {
                // --> The loop is gone (or the handle died with it): kill what is left; the
                // CProcess destructor reaps when it can.
                process.kill(SIGKILL);
                if (hasCgroup) {
                    cgroup.signalAll(SIGKILL);
                    cgroup.destroy();
                }
            }
        }

        /**
         * Marks the run finished and resumes everyone waiting for it.
         */
        void finish() {
            done = true;
            std::vector<std::coroutine_handle<>> ready;
            ready.swap(waiters);

            for (std::coroutine_handle<> h : ready) {
                loop->post(h);
            }
        }

        /**
         * Kills every process of the sandbox (cgroup and pid namespace).
         */
        void killAll() {
            process.kill(SIGKILL);
            if (hasCgroup) {
                cgroup.signalAll(SIGKILL);
            }
        }
    };

    namespace {

        std::atomic<uint64_t> gSandboxCounter{ 0 };

        /**
         * Depth of a path ("/" = 0, "/a/b" = 2), for ordering mounts parents first.
         */
        size_t depthOf(const std::string& path) {
            size_t depth = 0;
            bool inPart = false;

            for (char c : path) {
                if (c == '/') {
                    inPart = false;
                } else if (!inPart) {
                    inPart = true;
                    ++depth;
                }
            }

            return depth;
        }

        SMountSpec tmpfsMount(const char* destination, unsigned long flags, std::string data) {
            SMountSpec m;
            m.source = "tmpfs";
            m.type = "tmpfs";
            m.destination = destination;
            m.flags = flags;
            m.data = std::move(data);
            return m;
        }

        /**
         * OCI's default masked paths (Docker's list).
         */
        std::vector<std::string> defaultMaskedPaths() {
            return {
                "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
                "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap",
            };
        }

        std::vector<std::string> defaultReadonlyPaths() {
            return { "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger" };
        }

        /**
         * Creates the sandbox cgroup and applies the limits; records what is not enforced.
         */
        int32_t setupCgroup(CSandbox::SState& st, SBoxPolicy& p) {
            std::string parent = p.cgroupParent;
            if (parent.empty() && CCgroup::defaultParent(parent) != SBOX_OK) {
                return -EACCES;
            }

            std::string name = parent + "/box-" + std::to_string(::getpid()) + "-" +
                std::to_string(++gSandboxCounter) + "-" + std::to_string(CEventLoop::nowMs());

            if (int32_t rc = CCgroup::create(name, st.cgroup); rc != SBOX_OK) {
                return rc;
            }

            st.hasCgroup = true;

            SCgroupResources res;
            if (p.memoryMax > 0) {
                res.memoryLimit = p.memoryMax;
                // --> OCI semantics: memory + swap. Without swapMax the program cannot swap.
                res.memorySwap = p.memoryMax + std::max<int64_t>(p.swapMax, 0);
            }

            if (p.pidsMax > 0) {
                res.pidsLimit = p.pidsMax;
            }

            if (p.cpuQuotaUs > 0) {
                res.cpuQuota = p.cpuQuotaUs;
                res.cpuPeriod = uint64_t(p.cpuPeriodUs > 0 ? p.cpuPeriodUs : 100000);
            }

            for (const SBoxIoLimit& io : p.ioLimits) {
                int64_t major = io.major, minor = io.minor;
                if (!io.device.empty()) {
                    struct stat sst;
                    if (::stat(io.device.c_str(), &sst) != 0 || !S_ISBLK(sst.st_mode)) {
                        return -ENODEV;
                    }

                    major = int64_t(::major(sst.st_rdev));
                    minor = int64_t(::minor(sst.st_rdev));
                }

                if (major < 0 || minor < 0) {
                    return -EINVAL;
                }

                if (io.readBps) res.readBps.push_back(SCgroupThrottle{ major, minor, io.readBps });
                if (io.writeBps) res.writeBps.push_back(SCgroupThrottle{ major, minor, io.writeBps });
                if (io.readIops) res.readIops.push_back(SCgroupThrottle{ major, minor, io.readIops });
                if (io.writeIops) res.writeIops.push_back(SCgroupThrottle{ major, minor, io.writeIops });
            }

            std::vector<std::string> skipped;
            if (int32_t rc = st.cgroup.apply(res, &skipped); rc != SBOX_OK) {
                return rc;
            }

            for (const std::string& s : skipped) {
                // --> Swap accounting is often disabled (v1 without swapaccount); that only
                // means the program may swap, not that its memory is unlimited.
                if (s != "memory.swap") {
                    st.unenforced.push_back(s);
                }
            }

            st.memoryByCgroup = p.memoryMax > 0 && std::find(skipped.begin(), skipped.end(), "memory") == skipped.end();
            return SBOX_OK;
        }

        /**
         * Translates a policy into a launch spec.
         */
        int32_t buildSpec(CSandbox::SState& st, const SBoxPolicy& p, SLaunchSpec& s, std::vector<CFd>& childFds, std::string& step) {
            bool root = ::geteuid() == 0;

            s.env = p.env;
            s.cwd = p.cwd.empty() ? "/" : p.cwd;
            s.uid = p.uid;
            s.gid = p.gid;
            s.newSession = true;
            s.parentDeathSignal = SIGKILL;
            s.reaper = true;
            s.hostname = p.hostname;

            // Namespaces.
            s.namespaces = {
                { ENS_USER, "" }, { ENS_PID, "" }, { ENS_MOUNT, "" }, { ENS_IPC, "" },
                { ENS_UTS, "" }, { ENS_CGROUP, "" },
            };

            if (p.network == EBNET_NONE) {
                s.namespaces.push_back({ ENS_NET, "" });
                s.loopbackUp = true;
            } else if (p.network == EBNET_NAMESPACE) {
                if (p.netnsPath.empty()) {
                    step = "netnsPath";
                    return -EINVAL;
                }

                s.namespaces.push_back({ ENS_NET, p.netnsPath });
            }

            // --> The sandbox user maps to the caller (rootless) or, for root, to an
            // unprivileged host uid: host-root ownership would give the program owner access
            // to root's files in bind mounts and to /proc/sys.
            int64_t hostUid = p.hostUid >= 0 ? p.hostUid : (root ? 65534 : int64_t(::geteuid()));
            int64_t hostGid = p.hostGid >= 0 ? p.hostGid : (root ? 65534 : int64_t(::getegid()));
            s.uidMappings = { SIdMap{ p.uid, uint32_t(hostUid), 1 } };
            s.gidMappings = { SIdMap{ p.gid, uint32_t(hostGid), 1 } };

            // Filesystem.
            s.rootfsMode = ERFS_TMPFS;
            s.stagingDir = p.stagingDir;
            s.rootTmpfsOptions = "mode=0755,size=1m";
            s.rootReadOnly = true;
            s.rootPropagation = MS_PRIVATE | MS_REC;

            std::vector<SMountSpec> mounts;

            for (const SBoxMount& m : p.mounts) {
                if (m.target.empty() || m.target[0] != '/') {
                    step = "mount target " + m.target;
                    return -EINVAL;
                }

                SMountSpec b;
                b.source = m.source;
                b.destination = m.target;
                b.flags = MS_BIND | MS_REC | MS_NOSUID | MS_NODEV;
                if (m.mode == EBMNT_READ_ONLY) {
                    b.flags |= MS_RDONLY;
                    b.recursiveReadOnly = true;
                }

                if (m.noexec) {
                    b.flags |= MS_NOEXEC;
                }

                b.optional = m.optional;
                mounts.push_back(b);
            }

            SMountSpec proc;
            proc.source = "proc";
            proc.type = "proc";
            proc.destination = "/proc";
            proc.flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
            mounts.push_back(proc);

            mounts.push_back(tmpfsMount("/dev", MS_NOSUID | MS_NOEXEC, "mode=0755,size=64k"));

            SMountSpec pts;
            pts.source = "devpts";
            pts.type = "devpts";
            pts.destination = "/dev/pts";
            pts.flags = MS_NOSUID | MS_NOEXEC;
            pts.data = "newinstance,ptmxmode=0666,mode=0620";
            mounts.push_back(pts);

            mounts.push_back(tmpfsMount("/dev/shm", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                "mode=1777,size=" + std::to_string(p.shmSize > 0 ? p.shmSize : (16ll << 20))));

            mounts.push_back(tmpfsMount("/tmp", MS_NOSUID | MS_NODEV | (p.tmpNoexec ? MS_NOEXEC : 0),
                "mode=1777,size=" + std::to_string(p.tmpSize > 0 ? p.tmpSize : (64ll << 20))));

            // --> Parents before children ("/tmp" before "/tmp/x"), otherwise in order.
            std::stable_sort(mounts.begin(), mounts.end(), [](const SMountSpec& a, const SMountSpec& b) {
                return depthOf(a.destination) < depthOf(b.destination);
            });

            s.mounts = std::move(mounts);
            s.devices = DefaultDevices();
            s.devSymlinks = true;
            s.maskedPaths = defaultMaskedPaths();
            s.readonlyPaths = defaultReadonlyPaths();

            // Security.
            s.capabilities = SCapabilities();
            s.noNewPrivileges = true;

            if (p.seccomp) {
                auto filter = std::make_shared<CSeccompFilter>();
                SSeccompProfile profile = p.seccompProfile ? *p.seccompProfile : SSeccompProfile::general(p.seccompViolation);

                if (int32_t rc = CSeccompFilter::compile(profile, *filter); rc != SBOX_OK) {
                    step = "seccomp";
                    return rc;
                }

                s.seccomp = filter;
            }

            // Rlimits (plus fallbacks for limits the cgroup could not take).
            auto addLimit = [&](int resource, uint64_t soft, uint64_t hard) {
                s.rlimits.push_back(SRlimit{ resource, soft, hard });
            };

            if (!p.coreDumps) {
                addLimit(RLIMIT_CORE, 0, 0);
            }

            if (p.cpuTimeLimitMs > 0) {
                uint64_t secs = uint64_t((p.cpuTimeLimitMs + 999) / 1000);
                addLimit(RLIMIT_CPU, secs, secs + 1);
            }

            if (p.fileSizeMax > 0) {
                addLimit(RLIMIT_FSIZE, uint64_t(p.fileSizeMax), uint64_t(p.fileSizeMax));
            }

            if (p.openFilesMax > 0) {
                addLimit(RLIMIT_NOFILE, uint64_t(p.openFilesMax), uint64_t(p.openFilesMax));
            }

            if (p.stackMax > 0) {
                addLimit(RLIMIT_STACK, uint64_t(p.stackMax), uint64_t(p.stackMax));
            }

            int64_t addressSpace = p.addressSpaceMax;
            auto unenforced = [&](const char* name) {
                return std::find(st.unenforced.begin(), st.unenforced.end(), name) != st.unenforced.end();
            };

            if (p.memoryMax > 0 && (!st.hasCgroup || unenforced("memory"))) {
                // --> Address space is a coarse stand-in for memory (it counts mappings, not
                // resident pages), but it is the only per-process bound without cgroups.
                if (addressSpace <= 0) {
                    addressSpace = p.memoryMax;
                }

                st.unenforced.erase(std::remove(st.unenforced.begin(), st.unenforced.end(), "memory"), st.unenforced.end());
                st.unenforced.push_back("memory (RLIMIT_AS fallback)");
            }

            if (addressSpace > 0) {
                addLimit(RLIMIT_AS, uint64_t(addressSpace), uint64_t(addressSpace));
            }

            if (p.pidsMax > 0 && (!st.hasCgroup || unenforced("pids"))) {
                addLimit(RLIMIT_NPROC, uint64_t(p.pidsMax), uint64_t(p.pidsMax));
                st.unenforced.erase(std::remove(st.unenforced.begin(), st.unenforced.end(), "pids"), st.unenforced.end());
                st.unenforced.push_back("pids (RLIMIT_NPROC fallback)");
            }

            if (!st.hasCgroup) {
                if (p.cpuQuotaUs > 0) {
                    st.unenforced.push_back("cpu");
                }

                if (!p.ioLimits.empty()) {
                    st.unenforced.push_back("io");
                }
            }

            for (const SRlimit& r : p.rlimits) {
                s.rlimits.push_back(r);
            }

            s.cgroup = st.hasCgroup ? &st.cgroup : nullptr;

            // Standard streams.
            const SBoxStdio* modes[3] = { &p.stdinMode, &p.stdoutMode, &p.stderrMode };
            CStream* streams[3] = { &st.in, &st.out, &st.err };

            for (int target = 0; target < 3; ++target) {
                const SBoxStdio& m = *modes[target];
                CFd child;

                if (m.mode == EBSTD_PIPE) {
                    if (int32_t rc = CPipe::createForChild(*streams[target], child, target != 0); rc != SBOX_OK) {
                        step = "stdio pipe";
                        return rc;
                    }
                } else if (m.mode == EBSTD_INHERIT) {
                    if (m.fd < 0) {
                        step = "stdio fd";
                        return -EBADF;
                    }

                    child.reset(::fcntl(m.fd, F_DUPFD_CLOEXEC, 3));
                } else {
                    child.reset(::open("/dev/null", (target == 0 ? O_RDONLY : O_WRONLY) | O_CLOEXEC));
                }

                if (!child.isValid()) {
                    step = "stdio";
                    return -errno;
                }

                s.fds.push_back(SFdMapping{ child.get(), target });
                childFds.push_back(std::move(child));
            }

            return SBOX_OK;
        }

        /**
         * Computes the result of a finished run.
         */
        void computeResult(CSandbox::SState& st, const SExitStatus& status, const SCgroupStats* cs, int64_t endMs) {
            SBoxResult& r = st.result;
            const SBoxPolicy& p = st.policy;

            r.wallTimeMs = endMs - st.startMs;
            r.exitCode = status.exitCode;
            r.signal = status.signal;
            r.cgroupUsed = st.hasCgroup;
            r.unenforced = st.unenforced;

            if (cs && cs->hasCpu) {
                r.cpuTimeUs = cs->cpuUsageUs;
                r.userTimeUs = cs->cpuUserUs;
                r.systemTimeUs = cs->cpuSystemUs;
                r.cpuSource = EBSTAT_CGROUP;
            } else {
                r.userTimeUs = status.userTimeUs;
                r.systemTimeUs = status.systemTimeUs;
                r.cpuTimeUs = status.userTimeUs + status.systemTimeUs;
                r.cpuSource = EBSTAT_RUSAGE;
            }

            if (cs && cs->hasMemory && cs->memoryPeak > 0) {
                r.peakMemoryBytes = cs->memoryPeak;
                r.memorySource = EBSTAT_CGROUP;
                r.oomKills = cs->oomKills;
            } else {
                r.peakMemoryBytes = status.maxRssBytes;
                r.memorySource = EBSTAT_RUSAGE;
                r.oomKills = cs ? cs->oomKills : 0;
            }

            if (st.timedOut) {
                r.reason = EBEXIT_WALL_TIMEOUT;
            } else if (status.signaled) {
                uint64_t cpuLimitUs = p.cpuTimeLimitMs > 0 ? uint64_t((p.cpuTimeLimitMs + 999) / 1000) * 1000000 : 0;

                if (status.signal == SIGSYS) {
                    r.reason = EBEXIT_SECCOMP;
                } else if (status.signal == SIGXCPU) {
                    r.reason = EBEXIT_CPU_TIME;
                } else if (status.signal == SIGKILL && !st.killed && r.oomKills > 0) {
                    r.reason = EBEXIT_MEMORY;
                } else if (status.signal == SIGKILL && !st.killed && cpuLimitUs && status.userTimeUs + status.systemTimeUs >= cpuLimitUs) {
                    r.reason = EBEXIT_CPU_TIME;
                } else {
                    r.reason = EBEXIT_SIGNAL;
                }
            } else {
                r.reason = EBEXIT_NORMAL;
            }
        }

        /**
         * Awaiter for the end of a run.
         */
        struct SResultAwaiter {
            std::shared_ptr<CSandbox::SState> state;

            bool await_ready() const noexcept { return state->done; }

            void await_suspend(std::coroutine_handle<> h) { state->waiters.push_back(h); }

            SBoxResult await_resume() const { return state->result; }
        };

    }

    /* Move-assigns, killing the sandbox held before. */
    CSandbox& CSandbox::operator=(CSandbox&& other) noexcept {
        if (this != &other) {
            kill();
            _state = std::move(other._state);
        }

        return *this;
    }

    /* Kills a running sandbox. */
    CSandbox::~CSandbox() {
        kill();
    }

    /* Spawns a program. */
    TTask<CSandbox> CSandbox::spawn(SBoxPolicy policy, std::vector<std::string> args) {
        CSandbox box;
        box._state = std::make_shared<SState>();

        if (args.empty()) {
            box._state->result.reason = EBEXIT_SETUP_FAILURE;
            box._state->result.error = -EINVAL;
            box._state->result.failedStep = "args";
            box._state->done = true;
            co_return box;
        }

        co_await start(box._state, std::move(policy), std::move(args), nullptr);
        co_return box;
    }

    /* Runs a function in the sandbox. */
    TTask<CSandbox> CSandbox::fork(SBoxPolicy policy, std::function<int32_t()> fn) {
        CSandbox box;
        box._state = std::make_shared<SState>();
        co_await start(box._state, std::move(policy), {}, std::move(fn));
        co_return box;
    }

    /* Common start path. */
    TTask<void> CSandbox::start(std::shared_ptr<SState> st, SBoxPolicy policy, std::vector<std::string> args, std::function<int32_t()> fn) {
        st->loop = CEventLoop::current();
        st->policy = std::move(policy);
        st->startMs = CEventLoop::nowMs();

        auto failSetup = [&](int32_t error, std::string step) {
            st->result = SBoxResult();
            st->result.reason = EBEXIT_SETUP_FAILURE;
            st->result.error = error;
            st->result.failedStep = std::move(step);
            st->result.unenforced = st->unenforced;

            if (st->hasCgroup) {
                st->cgroup.destroy();
                st->hasCgroup = false;
            }

            st->done = true;
        };

        if (fn && ThreadCount() > 1) {
            failSetup(-EBUSY, "fork rule: other threads exist");
            co_return;
        }

        SBoxPolicy& p = st->policy;

        // --> A cgroup is used whenever one can be created (accounting and kill-all), and
        // carries the limits; without one, limits fall back to rlimits.
        int32_t cg = setupCgroup(*st, p);
        if (cg != SBOX_OK && cg != -EACCES && cg != -EPERM && cg != -ENOENT && cg != -EROFS) {
            failSetup(cg, "cgroup");
            co_return;
        }

        if (cg != SBOX_OK && st->hasCgroup) {
            st->cgroup.destroy();
            st->hasCgroup = false;
        }

        if (!st->hasCgroup) {
            if (p.memoryMax > 0) st->unenforced.push_back("memory");
            if (p.pidsMax > 0) st->unenforced.push_back("pids");
        }

        SLaunchSpec spec;
        std::vector<CFd> childFds;
        std::string step;

        if (int32_t rc = buildSpec(*st, p, spec, childFds, step); rc != SBOX_OK) {
            failSetup(rc, step);
            co_return;
        }

        if (p.requireCgroupLimits) {
            for (const std::string& u : st->unenforced) {
                failSetup(-ENOTSUP, "limit not enforceable: " + u);
                co_return;
            }
        }

        spec.args = std::move(args);
        spec.function = std::move(fn);

        int32_t rc = co_await CProcess::spawn(spec, st->process);
        childFds.clear();

        if (rc != SBOX_OK) {
            failSetup(rc, st->process.failedStep());
            co_return;
        }

        st->started = true;
        st->loop->spawn(supervise(st));
    }

    /* Supervises the program. */
    TTask<void> CSandbox::supervise(std::shared_ptr<SState> st) {
        const SBoxPolicy& p = st->policy;
        SExitStatus status;
        int32_t rc;

        if (p.wallTimeoutMs > 0) {
            int64_t left = st->startMs + p.wallTimeoutMs - CEventLoop::nowMs();
            rc = co_await st->process.wait(status, left > 0 ? left : 0);

            if (rc == -ETIMEDOUT) {
                st->timedOut = true;
                st->killAll();
                rc = co_await st->process.wait(status);
            }
        } else {
            rc = co_await st->process.wait(status);
        }

        int64_t endMs = CEventLoop::nowMs();
        SCgroupStats stats;
        bool haveStats = false;

        if (st->hasCgroup) {
            // --> Without a pid namespace kill a process could escape into; with one the
            // kernel already killed everything when the init died. Either way: nothing survives.
            co_await st->cgroup.killAll(5000);
            haveStats = st->cgroup.stats(stats) == SBOX_OK;
            st->cgroup.destroy();
        }

        computeResult(*st, status, haveStats ? &stats : nullptr, endMs);
        if (rc != SBOX_OK) {
            st->result.error = rc;
        }

        st->finish();
    }

    /* Returns true when started. */
    bool CSandbox::isValid() const noexcept {
        return _state && _state->started;
    }

    /* Returns the setup error. */
    int32_t CSandbox::error() const noexcept {
        return _state ? _state->result.error : -EINVAL;
    }

    /* Returns the failed step. */
    const std::string& CSandbox::failedStep() const noexcept {
        static const std::string empty;
        return _state ? _state->result.failedStep : empty;
    }

    /* Returns the init pid. */
    pid_t CSandbox::pid() const noexcept {
        return _state ? _state->process.pid() : -1;
    }

    /* Returns the stdin pipe. */
    CStream& CSandbox::stdinPipe() noexcept {
        static CStream invalid;
        return _state ? _state->in : invalid;
    }

    /* Returns the stdout pipe. */
    CStream& CSandbox::stdoutPipe() noexcept {
        static CStream invalid;
        return _state ? _state->out : invalid;
    }

    /* Returns the stderr pipe. */
    CStream& CSandbox::stderrPipe() noexcept {
        static CStream invalid;
        return _state ? _state->err : invalid;
    }

    /* Waits for the result. */
    TTask<SBoxResult> CSandbox::wait() {
        if (!_state) {
            SBoxResult r;
            r.reason = EBEXIT_SETUP_FAILURE;
            r.error = -EINVAL;
            co_return r;
        }

        co_return co_await SResultAwaiter{ _state };
    }

    /* Kills the sandbox. */
    int32_t CSandbox::kill() noexcept {
        if (!_state || !_state->started || _state->done) {
            return -ESRCH;
        }

        _state->killed = true;
        _state->killAll();
        return SBOX_OK;
    }

} // namespace sbox
