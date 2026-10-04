#include <sbox/box/launch.hpp>
#include <sbox/box/cgroup.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include "launch_child.hpp"
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif

namespace sbox {

    namespace {

        /**
         * struct clone_args (clone3), spelled out to avoid mixing <linux/sched.h> with <sched.h>.
         */
        struct CloneArgs {
            uint64_t flags;
            uint64_t pidfd;
            uint64_t childTid;
            uint64_t parentTid;
            uint64_t exitSignal;
            uint64_t stack;
            uint64_t stackSize;
            uint64_t tls;
            uint64_t setTid;
            uint64_t setTidSize;
            uint64_t cgroup;
        };

        const char* const CAP_NAMES[] = {
            "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
            "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
            "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
            "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
            "lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
            "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
        };

        int cloneFlagOf(uint32_t ns) noexcept {
            int flags = 0;
            if (ns & ENS_USER) flags |= CLONE_NEWUSER;
            if (ns & ENS_PID) flags |= CLONE_NEWPID;
            if (ns & ENS_MOUNT) flags |= CLONE_NEWNS;
            if (ns & ENS_IPC) flags |= CLONE_NEWIPC;
            if (ns & ENS_UTS) flags |= CLONE_NEWUTS;
            if (ns & ENS_NET) flags |= CLONE_NEWNET;
            if (ns & ENS_CGROUP) flags |= CLONE_NEWCGROUP;
            if (ns & ENS_TIME) flags |= CLONE_NEWTIME;
            return flags;
        }

        std::string idMapText(const std::vector<SIdMap>& maps) {
            std::string text;
            for (const SIdMap& m : maps) {
                text += std::to_string(m.inside) + " " + std::to_string(m.outside) + " " + std::to_string(m.count) + "\n";
            }

            return text;
        }

        /**
         * Parent-side resources of one spawn: descriptors handed to the child (closed after
         * clone3) and the plan.
         */
        struct SpawnContext {
            LaunchPlan plan;
            std::vector<CFd> childFds;      // --> Closed in the parent once the child exists.
            CFd reportRead;
            CFd syncWrite;
            CFd gateWrite;
            CFd consoleRead;
            bool newUserNs = false;
            bool denySetgroups = false;
            std::vector<SIdMap> uidMap;
            std::vector<SIdMap> gidMap;
            bool intoCgroup = false;

            int keepChild(int fd) {
                childFds.emplace_back(fd);
                return fd;
            }
        };

        /**
         * Builds the child plan from a spec. Everything that can fail on the caller side
         * (missing bind sources, namespace paths) fails here, before clone3.
         */
        int32_t buildPlan(const SLaunchSpec& spec, SpawnContext& ctx, std::string& step) {
            LaunchPlan& p = ctx.plan;

            if (spec.args.empty() && !spec.function) {
                step = "args";
                return -EINVAL;
            }

            // Namespaces.
            uint32_t newNs = 0, joinNs = 0;
            std::vector<std::pair<uint32_t, std::string>> joins;

            for (const SNamespaceSpec& ns : spec.namespaces) {
                if (ns.type == ENS_NONE || (ns.type & (ns.type - 1)) != 0) {
                    step = "namespaces";
                    return -EINVAL;
                }

                if (ns.path.empty()) {
                    newNs |= ns.type;
                } else {
                    joinNs |= ns.type;
                    joins.emplace_back(ns.type, ns.path);
                }
            }

            if (newNs & joinNs) {
                step = "namespaces";
                return -EINVAL;
            }

            // --> The user namespace is joined first so the others are entered with its rights.
            std::stable_sort(joins.begin(), joins.end(), [](const auto& a, const auto& b) {
                return (a.first == ENS_USER) > (b.first == ENS_USER);
            });

            for (const auto& [type, path] : joins) {
                int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
                if (fd < 0) {
                    step = "open namespace " + path;
                    return -errno;
                }

                p.joins.push_back(PlanJoin{ ctx.keepChild(fd), cloneFlagOf(type) });
            }

            // --> clone3 can create the new namespaces directly unless some must be created
            // after a join (a new user namespace would otherwise own namespaces we then could
            // not enter, and a joined user namespace must own the new ones).
            bool deferred = (joinNs & ENS_USER) || ((newNs & ENS_USER) && joinNs != 0);
            int newFlags = cloneFlagOf(newNs);

            if (deferred) {
                p.unshareFlags = newFlags;
                p.earlyFork = (newNs & (ENS_PID | ENS_TIME)) || (joinNs & ENS_PID);
            } else {
                p.earlyFork = (joinNs & ENS_PID) != 0;
            }

            ctx.newUserNs = (newNs & ENS_USER) != 0;
            p.newUserNs = ctx.newUserNs;

            if (ctx.newUserNs) {
                ctx.uidMap = spec.uidMappings;
                ctx.gidMap = spec.gidMappings;
                if (ctx.uidMap.empty()) {
                    ctx.uidMap.push_back(SIdMap{ 0, uint32_t(::geteuid()), 1 });
                }

                if (ctx.gidMap.empty()) {
                    ctx.gidMap.push_back(SIdMap{ 0, uint32_t(::getegid()), 1 });
                }

                // --> The setup creates files (mount points, device nodes) in filesystems of
                // the new namespace; that needs ids mapped there: root if mapped, else the
                // first mapped id.
                auto pick = [](const std::vector<SIdMap>& maps) -> int64_t {
                    for (const SIdMap& m : maps) {
                        if (m.inside == 0 && m.count > 0) {
                            return 0;
                        }
                    }

                    return maps.front().inside;
                };

                p.setupUid = pick(ctx.uidMap);
                p.setupGid = pick(ctx.gidMap);
            }
            p.newMountNs = (newNs & ENS_MOUNT) != 0;
            p.newNetNs = (newNs & ENS_NET) != 0;
            p.newUtsNs = (newNs & ENS_UTS) != 0;
            p.reaper = spec.reaper || bool(spec.function);
            p.parentDeathSignal = spec.parentDeathSignal;

            if (!p.newMountNs && (spec.rootfsMode != ERFS_HOST || !spec.mounts.empty() || !spec.devices.empty() ||
                                  !spec.maskedPaths.empty() || !spec.readonlyPaths.empty() || spec.rootReadOnly)) {
                step = "filesystem setup needs a new mount namespace";
                return -EINVAL;
            }

            if ((!spec.hostname.empty() || !spec.domainname.empty()) && !p.newUtsNs) {
                step = "hostname needs a new UTS namespace";
                return -EINVAL;
            }

            // Root.
            p.rootfsMode = spec.rootfsMode;
            if (spec.rootfsMode != ERFS_HOST) {
                const std::string& dir = spec.rootfsMode == ERFS_TMPFS ? spec.stagingDir : spec.rootfs;
                char* real = ::realpath(dir.c_str(), nullptr);
                if (!real) {
                    step = "rootfs " + dir;
                    return -errno;
                }

                p.rootPath = p.keep(real);
                std::free(real);
                p.rootTmpfsData = p.keep(spec.rootTmpfsOptions);
            }

            p.rootReadOnly = spec.rootReadOnly;
            p.noPivot = spec.noPivot;

            // --> Shared propagation is applied after pivot_root (pivot_root refuses shared
            // parents); everything else up front, as runc does.
            if (spec.rootPropagation & MS_SHARED) {
                p.rootPropagation = MS_PRIVATE | MS_REC;
                p.rootPropagationAfter = spec.rootPropagation;
            } else {
                p.rootPropagation = spec.rootPropagation;
            }

            // Mounts.
            for (size_t i = 0; i < spec.mounts.size(); ++i) {
                const SMountSpec& m = spec.mounts[i];
                PlanMount pm;

                if (m.destination.empty() || m.destination[0] != '/') {
                    step = "mount destination " + m.destination;
                    return -EINVAL;
                }

                pm.target = p.keep(m.destination.substr(1));
                pm.bind = (m.flags & MS_BIND) || m.type == "bind";
                pm.propagation = (unsigned long) m.propagation;
                pm.recursiveReadOnly = m.recursiveReadOnly;

                if (pm.bind) {
                    // --> Checked here for a precise error; the child opens the source again in
                    // its own mount namespace (a bind from another namespace's mount is EINVAL).
                    struct stat st{};
                    if (::stat(m.source.c_str(), &st) != 0) {
                        if (errno == ENOENT && m.optional) {
                            pm.skip = true;
                            p.mounts.push_back(pm);
                            continue;
                        }

                        step = "mount source " + m.source;
                        return -errno;
                    }

                    pm.sourceIsDir = S_ISDIR(st.st_mode);
                    pm.optional = m.optional;
                    pm.source = p.keep(m.source);
                    pm.flags = MS_BIND | (unsigned long) (m.flags & MS_REC);

                    unsigned long extra = (unsigned long) m.flags & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC |
                        MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME | MS_NOSYMFOLLOW);
                    pm.remount = extra != 0 || m.recursiveReadOnly;
                    pm.remountFlags = extra | (m.recursiveReadOnly ? MS_RDONLY : 0);
                } else {
                    pm.fstype = p.keep(m.type);
                    pm.source = p.keep(m.source.empty() ? m.type : m.source);
                    pm.flags = (unsigned long) m.flags;
                    pm.data = m.data.empty() ? nullptr : p.keep(m.data);
                }

                p.mounts.push_back(pm);
            }

            // Devices.
            for (const SDeviceNode& d : spec.devices) {
                if (d.path.size() < 2 || d.path[0] != '/' || (d.type != 'c' && d.type != 'b')) {
                    step = "device " + d.path;
                    return -EINVAL;
                }

                PlanDevice pd;
                pd.path = p.keep(d.path.substr(1));
                pd.mode = (d.type == 'b' ? S_IFBLK : S_IFCHR) | (d.mode & 07777);
                pd.dev = makedev(d.major, d.minor);
                pd.uid = d.uid;
                pd.gid = d.gid;

                // --> The host node of the same path backs the bind fallback (user namespaces).
                struct stat st{};
                if (::stat(d.path.c_str(), &st) == 0 && (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) && st.st_rdev == pd.dev) {
                    pd.hostPath = p.keep(d.path);
                }

                p.devices.push_back(pd);
            }

            p.devSymlinks = spec.devSymlinks;

            for (const std::string& path : spec.maskedPaths) {
                p.maskedPaths.push_back(p.keep(path));
            }

            for (const std::string& path : spec.readonlyPaths) {
                p.readonlyPaths.push_back(p.keep(path));
            }

            for (const auto& [key, value] : spec.sysctls) {
                if (key.empty() || key.find("..") != std::string::npos) {
                    step = "sysctl " + key;
                    return -EINVAL;
                }

                std::string path = "/proc/sys/";
                for (char c : key) {
                    path.push_back(c == '.' ? '/' : c);
                }

                p.sysctls.emplace_back(p.keep(path), p.keep(value));
            }

            p.hostname = spec.hostname.empty() ? nullptr : p.keep(spec.hostname);
            p.domainname = spec.domainname.empty() ? nullptr : p.keep(spec.domainname);
            p.loopbackUp = spec.loopbackUp;

            // Process.
            for (const std::string& a : spec.args) {
                p.argv.push_back(const_cast<char*>(p.keep(a)));
            }

            if (p.argv.empty()) {
                p.argv.push_back(const_cast<char*>(p.keep("function")));
            }

            p.argv.push_back(nullptr);

            for (const std::string& e : spec.env) {
                const char* kept = p.keep(e);
                p.envp.push_back(const_cast<char*>(kept));

                if (e.compare(0, 5, "PATH=") == 0) {
                    p.searchPath = kept + 5;
                }
            }

            p.envp.push_back(nullptr);
            p.executable = spec.executable.empty() ? nullptr : p.keep(spec.executable);
            p.cwd = spec.cwd.empty() ? nullptr : p.keep(spec.cwd);
            p.uid = spec.uid;
            p.gid = spec.gid;

            for (uint32_t g : spec.additionalGids) {
                p.groups.push_back(gid_t(g));
            }

            // --> An unprivileged writer of gid_map must deny setgroups first.
            ctx.denySetgroups = ctx.newUserNs && (spec.denySetgroups || ::geteuid() != 0);
            p.setGroups = !ctx.denySetgroups;

            p.caps = spec.capabilities;
            p.lastCap = CapabilityLast();
            p.noNewPrivs = spec.noNewPrivileges;
            p.seccomp = spec.seccomp && spec.seccomp->isValid() ? spec.seccomp.get() : nullptr;

            for (const SRlimit& r : spec.rlimits) {
                struct rlimit rl;
                rl.rlim_cur = r.soft;
                rl.rlim_max = r.hard;
                p.rlimits.emplace_back(r.resource, rl);
            }

            if (spec.oomScoreAdj) {
                p.oomScoreAdj = p.keep(std::to_string(*spec.oomScoreAdj));
            }

            p.fds = spec.fds;
            p.maxTarget = 2;
            for (const SFdMapping& m : spec.fds) {
                if (m.source < 0 || m.target < 0) {
                    step = "fds";
                    return -EBADF;
                }

                p.maxTarget = std::max(p.maxTarget, m.target);
            }

            p.terminal = spec.terminal;
            p.rows = spec.terminalRows;
            p.columns = spec.terminalColumns;
            p.newSession = spec.newSession || spec.terminal;
            p.umask = spec.umask ? int(*spec.umask & 0777) : -1;
            p.function = spec.function ? &spec.function : nullptr;

            return SBOX_OK;
        }

    }

    /**
     * Parent-side record handling (friend of CProcess).
     */
    struct LaunchSession {
        /**
         * Reads whatever records are in the report pipe (non-blocking).
         */
        static int32_t read(CProcess& proc, std::vector<LaunchRecord>& out) {
            out.clear();

            while (proc._report.isValid()) {
                uint8_t buf[sizeof(LaunchRecord) * 16];
                ssize_t n = ::read(proc._report.get(), buf, sizeof(buf));

                if (n > 0) {
                    proc._pending.insert(proc._pending.end(), buf, buf + n);
                    continue;
                }

                if (n == 0) {
                    proc._reportEof = true;
                    proc._report.reset();
                    break;
                }

                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN) {
                    break;
                }

                return -errno;
            }

            size_t whole = proc._pending.size() / sizeof(LaunchRecord);
            for (size_t i = 0; i < whole; ++i) {
                LaunchRecord rec;
                std::memcpy(&rec, proc._pending.data() + i * sizeof(LaunchRecord), sizeof(rec));
                out.push_back(rec);
            }

            proc._pending.erase(proc._pending.begin(), proc._pending.begin() + long(whole * sizeof(LaunchRecord)));
            return SBOX_OK;
        }

        /**
         * Applies the bookkeeping records (pid, exit) and returns the terminal one, if any.
         */
        static void absorb(CProcess& proc, const LaunchRecord& rec) {
            if (rec.kind == REC_PID) {
                proc._payloadPid = pid_t(rec.value);
            } else if (rec.kind == REC_EXIT && !proc._forwarded) {
                // --> The innermost reaper reports first; its status is the payload's.
                int status = int(rec.value);
                proc._forwarded = true;
                proc._forwardedStatus = SExitStatus();
                proc._forwardedStatus.exited = WIFEXITED(status);
                proc._forwardedStatus.signaled = WIFSIGNALED(status);
                proc._forwardedStatus.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
                proc._forwardedStatus.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
                proc._forwardedStatus.coreDumped = WIFSIGNALED(status) && WCOREDUMP(status);
            } else if (rec.kind == REC_ERROR && proc._error == SBOX_OK) {
                proc._error = rec.error;
                proc._failedStep = LaunchStepName(rec.step);
                if (rec.index >= 0) {
                    proc._failedStep += "[" + std::to_string(rec.index) + "]";
                }
            } else if (rec.kind == REC_EXEC) {
                proc._started = true;
            }
        }

        /**
         * Reaps a child whose setup failed (it exits right after reporting).
         */
        static TTask<void> reap(CProcess& proc) {
            if (proc._pidfd.isValid() && !proc._reaped) {
                SExitStatus ignored;
                co_await proc.wait(ignored, 10000);
            }
        }
    };

    /* Kills an unwaited process. */
    CProcess::~CProcess() {
        if (_pidfd.isValid() && !_reaped) {
            ::syscall(SYS_pidfd_send_signal, _pidfd.get(), SIGKILL, nullptr, 0);
            SExitStatus ignored;
            tryWait(ignored);
        }
    }

    /* Launches a process. */
    TTask<int32_t> CProcess::spawn(const SLaunchSpec& spec, CProcess& out) {
        CEventLoop* loop = CEventLoop::current();
        out = CProcess();

        if (spec.function && ThreadCount() > 1) {
            // --> A function payload runs this program's code after a fork: no other thread
            // may hold a lock (malloc, stdio) at that moment.
            out._failedStep = "fork rule: other threads exist";
            out._error = -EBUSY;
            co_return -EBUSY;
        }

        auto ctx = std::make_unique<SpawnContext>();
        LaunchPlan& plan = ctx->plan;

        std::string step;
        if (int32_t rc = buildPlan(spec, *ctx, step); rc != SBOX_OK) {
            out._failedStep = step;
            out._error = rc;
            co_return rc;
        }

        int fds[2];

        // Report pipe: child -> parent.
        if (::pipe2(fds, O_CLOEXEC) != 0) {
            co_return -errno;
        }

        ctx->reportRead.reset(fds[0]);
        plan.reportFd = ctx->keepChild(fds[1]);
        ctx->reportRead.setNonBlocking(true);

        // Sync pipe: parent -> child.
        if (::pipe2(fds, O_CLOEXEC) != 0) {
            co_return -errno;
        }

        plan.syncFd = ctx->keepChild(fds[0]);
        ctx->syncWrite.reset(fds[1]);

        if (spec.gate == ESG_INTERNAL) {
            if (::pipe2(fds, O_CLOEXEC) != 0) {
                co_return -errno;
            }

            plan.gateFd = ctx->keepChild(fds[0]);
            ctx->gateWrite.reset(fds[1]);
        } else if (spec.gate == ESG_FD) {
            if (spec.gateFd < 0) {
                co_return -EBADF;
            }

            plan.gateFd = spec.gateFd;
        }

        if (spec.terminal) {
            if (spec.consoleSocketFd >= 0) {
                plan.consoleFd = spec.consoleSocketFd;
            } else {
                if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
                    co_return -errno;
                }

                ctx->consoleRead.reset(fds[0]);
                plan.consoleFd = ctx->keepChild(fds[1]);
            }
        }

        plan.collectFdSlots();

        // --> New namespaces go into clone3 unless the plan creates them with unshare.
        int cloneFlags = 0;
        if (!plan.unshareFlags) {
            uint32_t newNs = 0;
            for (const SNamespaceSpec& ns : spec.namespaces) {
                if (ns.path.empty()) {
                    newNs |= ns.type;
                }
            }

            cloneFlags = cloneFlagOf(newNs);
        }

        int cgroupFd = spec.cgroup ? spec.cgroup->v2Fd() : -1;

        CloneArgs args;
        std::memset(&args, 0, sizeof(args));
        int pidfd = -1;
        args.flags = uint64_t(CLONE_PIDFD) | uint64_t(uint32_t(cloneFlags));
        args.pidfd = uint64_t(uintptr_t(&pidfd));
        // --> No exit signal: nothing reaches the caller's SIGCHLD handling; waitid uses __WALL.
        args.exitSignal = 0;

        if (cgroupFd >= 0) {
            args.flags |= CLONE_INTO_CGROUP;
            args.cgroup = uint64_t(cgroupFd);
        }

        // --> Block every signal so no handler of the caller runs in the child before it
        // resets the dispositions.
        sigset_t all, old;
        sigfillset(&all);
        pthread_sigmask(SIG_SETMASK, &all, &old);

        long pid = ::syscall(SYS_clone3, &args, sizeof(args));
        int cloneErr = errno;

        if (pid < 0 && cgroupFd >= 0 && (cloneErr == EINVAL || cloneErr == EBUSY || cloneErr == EOPNOTSUPP || cloneErr == EACCES)) {
            // --> Older kernel or a cgroup that refuses direct placement: join after clone.
            args.flags &= ~uint64_t(CLONE_INTO_CGROUP);
            args.cgroup = 0;
            cgroupFd = -1;
            pid = ::syscall(SYS_clone3, &args, sizeof(args));
            cloneErr = errno;
        }

        if (pid == 0) {
            RunLaunchChild(plan);
        }

        pthread_sigmask(SIG_SETMASK, &old, nullptr);

        if (pid < 0) {
            out._failedStep = "clone3";
            out._error = -cloneErr;
            co_return -cloneErr;
        }

        ctx->intoCgroup = cgroupFd >= 0;
        out._pid = pid_t(pid);
        out._pidfd.reset(pidfd);
        out._report = std::move(ctx->reportRead);
        out._gate = std::move(ctx->gateWrite);

        // --> The child holds its own copies now.
        ctx->childFds.clear();

        int64_t deadline = CEventLoop::nowMs() + (spec.setupTimeoutMs > 0 ? spec.setupTimeoutMs : 30000);
        int32_t result = SBOX_OK;
        bool done = false;
        std::vector<LaunchRecord> records;

        while (!done) {
            if (int32_t rc = LaunchSession::read(out, records); rc != SBOX_OK) {
                result = rc;
                break;
            }

            for (const LaunchRecord& rec : records) {
                // --> Every record is absorbed, also those behind a terminal one: a quick
                // payload's exit status may already be in the same batch.
                LaunchSession::absorb(out, rec);

                if (done) {
                    continue;
                }

                if (rec.kind == REC_SYNC) {
                    int32_t rc = SBOX_OK;
                    std::string proc = "/proc/" + std::to_string(out._pid);

                    if (ctx->newUserNs) {
                        const std::vector<SIdMap>& uidMap = ctx->uidMap;
                        const std::vector<SIdMap>& gidMap = ctx->gidMap;

                        if (ctx->denySetgroups) {
                            rc = CFile::writeSome(proc + "/setgroups", "deny");
                            step = "setgroups deny";
                        }

                        if (rc == SBOX_OK) {
                            rc = CFile::writeSome(proc + "/uid_map", idMapText(uidMap));
                            step = "uid_map";
                        }

                        if (rc == SBOX_OK) {
                            rc = CFile::writeSome(proc + "/gid_map", idMapText(gidMap));
                            step = "gid_map";
                        }
                    }

                    if (rc == SBOX_OK && spec.cgroup) {
                        rc = spec.cgroup->addProcess(out._pid, ctx->intoCgroup);
                        step = "cgroup";
                    }

                    if (rc == SBOX_OK) {
                        char go = 1;
                        if (::write(ctx->syncWrite.get(), &go, 1) != 1) {
                            rc = -errno;
                            step = "sync";
                        }
                    }

                    ctx->syncWrite.reset();

                    if (rc != SBOX_OK) {
                        out._failedStep = step;
                        out._error = rc;
                        result = rc;
                        done = true;
                    }
                } else if (rec.kind == REC_ERROR) {
                    result = out._error;
                    done = true;
                } else if (rec.kind == REC_READY || rec.kind == REC_EXEC) {
                    done = true;
                }
            }

            if (done) {
                break;
            }

            if (out._reportEof) {
                // --> No reaper: the pipe closes on a successful exec (close-on-exec), or when
                // the child died without a report (killed): its status will tell.
                out._started = true;
                break;
            }

            int64_t left = deadline - CEventLoop::nowMs();
            if (left <= 0) {
                result = -ETIMEDOUT;
                out._failedStep = "setup timeout";
                out._error = result;
                break;
            }

            int32_t w = co_await loop->waitFd(out._report.get(), EFDE_READ, left);
            if (w < 0 && w != -ETIMEDOUT) {
                result = w;
                break;
            }
        }

        if (result != SBOX_OK) {
            out.kill(SIGKILL);
            co_await LaunchSession::reap(out);
            co_return result;
        }

        if (spec.terminal && ctx->consoleRead.isValid()) {
            char dummy;
            struct iovec iov{ &dummy, 1 };
            alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))];
            struct msghdr msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);

            if (::recvmsg(ctx->consoleRead.get(), &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) > 0) {
                for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
                    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
                        int fd;
                        std::memcpy(&fd, CMSG_DATA(cm), sizeof(int));
                        out._pty.reset(fd);
                    }
                }
            }
        }

        co_return SBOX_OK;
    }

    /* Releases the internal start gate. */
    int32_t CProcess::start() noexcept {
        if (!_gate.isValid()) {
            return -EBADF;
        }

        char go = 1;
        ssize_t n = ::write(_gate.get(), &go, 1);
        int err = errno;
        _gate.reset();
        return n == 1 ? SBOX_OK : -err;
    }

    /* Waits for exec after start(). */
    TTask<int32_t> CProcess::waitStarted(int64_t timeoutMs) {
        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        std::vector<LaunchRecord> records;

        while (true) {
            if (int32_t rc = LaunchSession::read(*this, records); rc != SBOX_OK) {
                co_return rc;
            }

            int32_t terminal = 1;   // --> 1: none yet.
            for (const LaunchRecord& rec : records) {
                LaunchSession::absorb(*this, rec);

                if (terminal == 1 && rec.kind == REC_ERROR) {
                    terminal = _error;
                } else if (terminal == 1 && rec.kind == REC_EXEC) {
                    terminal = SBOX_OK;
                }
            }

            if (terminal != 1) {
                co_return terminal;
            }

            if (_reportEof || _started) {
                _started = true;
                co_return _error;
            }

            int64_t left = deadline - CEventLoop::nowMs();
            if (left <= 0) {
                co_return -ETIMEDOUT;
            }

            co_await loop->waitFd(_report.get(), EFDE_READ, left);
        }
    }

    /* Sends a signal through the pidfd. */
    int32_t CProcess::kill(int sig) const noexcept {
        if (!_pidfd.isValid() || _reaped) {
            return -ESRCH;
        }

        if (::syscall(SYS_pidfd_send_signal, _pidfd.get(), sig, nullptr, 0) != 0) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Reaps without waiting. */
    int32_t CProcess::tryWait(SExitStatus& out) noexcept {
        if (_reaped) {
            out = _status;
            return SBOX_OK;
        }

        if (!_pidfd.isValid()) {
            return -ECHILD;
        }

        siginfo_t si;
        std::memset(&si, 0, sizeof(si));
        struct rusage ru;
        std::memset(&ru, 0, sizeof(ru));

        if (::syscall(SYS_waitid, P_PIDFD, _pidfd.get(), &si, WEXITED | WNOHANG | __WALL, &ru) != 0) {
            return -errno;
        }

        if (si.si_pid == 0) {
            return -EAGAIN;
        }

        SExitStatus st;
        st.exited = si.si_code == CLD_EXITED;
        st.signaled = si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED;
        st.coreDumped = si.si_code == CLD_DUMPED;
        st.exitCode = st.exited ? si.si_status : 0;
        st.signal = st.signaled ? si.si_status : 0;
        st.userTimeUs = uint64_t(ru.ru_utime.tv_sec) * 1000000 + uint64_t(ru.ru_utime.tv_usec);
        st.systemTimeUs = uint64_t(ru.ru_stime.tv_sec) * 1000000 + uint64_t(ru.ru_stime.tv_usec);
        st.maxRssBytes = uint64_t(ru.ru_maxrss) * 1024;

        // --> A reaper writes the payload's status before exiting: it is in the pipe now.
        std::vector<LaunchRecord> records;
        try {
            LaunchSession::read(*this, records);
            for (const LaunchRecord& rec : records) {
                LaunchSession::absorb(*this, rec);
            }
        } catch (...) {
        }

        if (_forwarded) {
            st.exited = _forwardedStatus.exited;
            st.signaled = _forwardedStatus.signaled;
            st.coreDumped = _forwardedStatus.coreDumped;
            st.exitCode = _forwardedStatus.exitCode;
            st.signal = _forwardedStatus.signal;
        }

        _status = st;
        _reaped = true;
        _report.reset();
        out = st;
        return SBOX_OK;
    }

    /* Waits for exit and reaps. */
    TTask<int32_t> CProcess::wait(SExitStatus& out, int64_t timeoutMs) {
        if (_reaped) {
            out = _status;
            co_return SBOX_OK;
        }

        if (!_pidfd.isValid()) {
            co_return -ECHILD;
        }

        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            int32_t rc = tryWait(out);
            if (rc != -EAGAIN) {
                co_return rc;
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            int32_t w = co_await loop->waitFd(_pidfd.get(), EFDE_READ, left);
            if (w == -ETIMEDOUT) {
                co_return -ETIMEDOUT;
            }

            if (w < 0) {
                co_return w;
            }
        }
    }

    /* Gives up supervision. */
    CFd CProcess::detach() noexcept {
        _reaped = true;
        _report.reset();
        _gate.reset();
        return std::move(_pidfd);
    }

    /* Parses OCI mount options. */
    int32_t ParseMountOptions(const std::vector<std::string>& options, SMountSpec& out) {
        struct Flag {
            const char* name;
            bool clear;
            uint64_t flag;
        };

        static const Flag FLAGS[] = {
            { "ro", false, MS_RDONLY }, { "rw", true, MS_RDONLY },
            { "nosuid", false, MS_NOSUID }, { "suid", true, MS_NOSUID },
            { "nodev", false, MS_NODEV }, { "dev", true, MS_NODEV },
            { "noexec", false, MS_NOEXEC }, { "exec", true, MS_NOEXEC },
            { "sync", false, MS_SYNCHRONOUS }, { "async", true, MS_SYNCHRONOUS },
            { "dirsync", false, MS_DIRSYNC }, { "remount", false, MS_REMOUNT },
            { "mand", false, MS_MANDLOCK }, { "nomand", true, MS_MANDLOCK },
            { "noatime", false, MS_NOATIME }, { "atime", true, MS_NOATIME },
            { "nodiratime", false, MS_NODIRATIME }, { "diratime", true, MS_NODIRATIME },
            { "relatime", false, MS_RELATIME }, { "norelatime", true, MS_RELATIME },
            { "strictatime", false, MS_STRICTATIME }, { "nostrictatime", true, MS_STRICTATIME },
            { "lazytime", false, MS_LAZYTIME }, { "nolazytime", true, MS_LAZYTIME },
            { "nosymfollow", false, MS_NOSYMFOLLOW }, { "symfollow", true, MS_NOSYMFOLLOW },
            { "silent", false, MS_SILENT }, { "loud", true, MS_SILENT },
            { "bind", false, MS_BIND }, { "rbind", false, MS_BIND | MS_REC },
        };

        static const Flag PROPAGATION[] = {
            { "private", false, MS_PRIVATE }, { "rprivate", false, MS_PRIVATE | MS_REC },
            { "shared", false, MS_SHARED }, { "rshared", false, MS_SHARED | MS_REC },
            { "slave", false, MS_SLAVE }, { "rslave", false, MS_SLAVE | MS_REC },
            { "unbindable", false, MS_UNBINDABLE }, { "runbindable", false, MS_UNBINDABLE | MS_REC },
        };

        std::string data;

        for (const std::string& opt : options) {
            bool matched = false;

            for (const Flag& f : FLAGS) {
                if (opt == f.name) {
                    out.flags = f.clear ? (out.flags & ~f.flag) : (out.flags | f.flag);
                    matched = true;
                    break;
                }
            }

            for (const Flag& f : PROPAGATION) {
                if (!matched && opt == f.name) {
                    out.propagation = f.flag;
                    matched = true;
                }
            }

            if (!matched && opt == "rro") {
                out.recursiveReadOnly = true;
                out.flags |= MS_RDONLY;
                matched = true;
            }

            if (!matched && (opt == "rrw" || opt == "tmpcopyup" || opt == "idmap" || opt == "ridmap")) {
                matched = true;     // --> Accepted, no effect here.
            }

            if (!matched) {
                if (!data.empty()) {
                    data.push_back(',');
                }

                data += opt;
            }
        }

        if (!data.empty()) {
            out.data = out.data.empty() ? data : out.data + "," + data;
        }

        return SBOX_OK;
    }

    /* Default container devices. */
    std::vector<SDeviceNode> DefaultDevices() {
        return {
            SDeviceNode{ "/dev/null", 'c', 1, 3, 0666, 0, 0 },
            SDeviceNode{ "/dev/zero", 'c', 1, 5, 0666, 0, 0 },
            SDeviceNode{ "/dev/full", 'c', 1, 7, 0666, 0, 0 },
            SDeviceNode{ "/dev/random", 'c', 1, 8, 0666, 0, 0 },
            SDeviceNode{ "/dev/urandom", 'c', 1, 9, 0666, 0, 0 },
            SDeviceNode{ "/dev/tty", 'c', 5, 0, 0666, 0, 0 },
        };
    }

    /* Maps a capability name to its number. */
    int32_t CapabilityFromName(std::string_view name) noexcept {
        if (name.size() > 4 && (name.substr(0, 4) == "CAP_" || name.substr(0, 4) == "cap_")) {
            name.remove_prefix(4);
        }

        for (size_t i = 0; i < sizeof(CAP_NAMES) / sizeof(CAP_NAMES[0]); ++i) {
            std::string_view cap(CAP_NAMES[i]);
            if (cap.size() != name.size()) {
                continue;
            }

            bool same = true;
            for (size_t k = 0; k < cap.size() && same; ++k) {
                char c = name[k];
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }

                same = c == cap[k];
            }

            if (same) {
                return int32_t(i);
            }
        }

        return -ENOENT;
    }

    /* Reads cap_last_cap. */
    int32_t CapabilityLast() noexcept {
        std::string text;
        if (CFile::readAll("/proc/sys/kernel/cap_last_cap", text, 64) != SBOX_OK) {
            return 40;
        }

        int32_t v = int32_t(std::strtol(text.c_str(), nullptr, 10));
        return v > 0 && v < 64 ? v : 40;
    }

    /* Counts the threads of this process. */
    int32_t ThreadCount() noexcept {
        DIR* dir = ::opendir("/proc/self/task");
        if (!dir) {
            return -errno;
        }

        int32_t count = 0;
        while (struct dirent* e = ::readdir(dir)) {
            if (e->d_name[0] != '.') {
                ++count;
            }
        }

        ::closedir(dir);
        return count;
    }

} // namespace sbox
