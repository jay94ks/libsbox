#include <sbox/oci/runtime.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/oci/hooks.hpp>
#include <sbox/oci/seccomp.hpp>
#include "convert.hpp"
#include "procutil.hpp"
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace sbox {
namespace oci {

    namespace {

        /**
         * Exclusive lock of a container directory.
         *
         * A POSIX record lock on <dir>/.lock: unlike flock, it belongs to the process and is not
         * inherited by children, so the container init -- which keeps copies of our descriptors
         * until it executes the program -- cannot hold it after `create` returns. Coroutines of
         * one process exclude each other through an in-process set.
         */
        struct DirLock {
            CFd fd;
            std::string key;

            DirLock() noexcept = default;

            DirLock(DirLock&& other) noexcept : fd(std::move(other.fd)), key(std::move(other.key)) {
                other.key.clear();
            }

            DirLock& operator=(DirLock&& other) noexcept {
                release();
                fd = std::move(other.fd);
                key = std::move(other.key);
                other.key.clear();
                return *this;
            }

            ~DirLock() {
                release();
            }

            /**
             * Drops the lock (closing the only descriptor of the lock file releases it).
             */
            void release() noexcept;
        };

        /**
         * Returns the directories locked by this process.
         */
        std::vector<std::string>& heldLocks() {
            static std::vector<std::string> held;
            return held;
        }

        void DirLock::release() noexcept {
            fd.reset();
            if (!key.empty()) {
                auto& held = heldLocks();
                held.erase(std::remove(held.begin(), held.end(), key), held.end());
                key.clear();
            }
        }

        /**
         * Takes the lock of a container directory without blocking the event loop.
         * @return SBOX_OK, -ENOENT when the directory is gone, -ETIMEDOUT, or another errno.
         */
        TTask<int32_t> lockContainer(const std::string& dir, DirLock& out, int64_t timeoutMs) {
            CEventLoop* loop = CEventLoop::current();
            int64_t deadline = CEventLoop::nowMs() + timeoutMs;
            CFd fd;

            while (true) {
                auto& held = heldLocks();
                if (std::find(held.begin(), held.end(), dir) == held.end()) {
                    if (!fd.isValid()) {
                        fd.reset(::open((dir + "/.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600));
                        if (!fd.isValid()) {
                            co_return -errno;
                        }
                    }

                    struct flock fl;
                    std::memset(&fl, 0, sizeof(fl));
                    fl.l_type = F_WRLCK;
                    fl.l_whence = SEEK_SET;
                    if (::fcntl(fd.get(), F_SETLK, &fl) == 0) {
                        out.release();
                        out.fd = std::move(fd);
                        out.key = dir;
                        held.push_back(dir);
                        co_return SBOX_OK;
                    }

                    if (errno != EACCES && errno != EAGAIN && errno != EINTR) {
                        co_return -errno;
                    }
                }

                if (CEventLoop::nowMs() >= deadline) {
                    co_return -ETIMEDOUT;
                }

                co_await loop->sleepFor(5);
            }
        }

        /**
         * A container directory, possibly locked, with its record.
         */
        struct Container {
            std::string dir;
            DirLock lock;
            SContainerRecord rec;
        };

        /**
         * Writes the record atomically.
         */
        int32_t writeRecord(const std::string& dir, const SContainerRecord& rec) {
            return CFile::writeAtomic(dir + "/state.json", rec.toJson().dump(), 0600);
        }

        /**
         * Reads the record of a container directory.
         */
        int32_t readRecord(const std::string& dir, SContainerRecord& rec, std::string& error) {
            std::string text;
            if (int32_t rc = CFile::readAll(dir + "/state.json", text); rc != SBOX_OK) {
                return rc;
            }

            CJson doc;
            if (CJson::parse(text, doc) != SBOX_OK) {
                error = dir + "/state.json: invalid JSON";
                return -EINVAL;
            }

            return SContainerRecord::fromJson(doc, rec, error);
        }

        /**
         * Returns true when the container's cgroup is frozen (v1 freezer or v2 cgroup.freeze).
         */
        bool cgroupFrozen(const std::string& path) {
            if (path.empty()) {
                return false;
            }

            CCgroup cg;
            if (CCgroup::open(path, cg) != SBOX_OK) {
                return false;
            }

            for (const auto& [bits, dir] : cg.v1Dirs()) {
                if (bits & ECGC_FREEZER) {
                    std::string state;
                    if (CFile::readAll(dir + "/freezer.state", state) == SBOX_OK) {
                        return state.rfind("FROZEN", 0) == 0 || state.rfind("FREEZING", 0) == 0;
                    }
                }
            }

            if (!cg.v2Dir().empty()) {
                std::string state;
                if (CFile::readAll(cg.v2Dir() + "/cgroup.freeze", state) == SBOX_OK) {
                    return !state.empty() && state[0] == '1';
                }
            }

            return false;
        }

        /**
         * Computes the status of a container from its record and the live system.
         */
        EContainerStatus computeStatus(const Container& c) {
            const SContainerRecord& r = c.rec;
            if (r.initPid <= 0) {
                return r.lastStatus == ECST_CREATING ? ECST_CREATING : ECST_STOPPED;
            }

            if (!ProcessAlive(r.initPid, r.initStartTime)) {
                return ECST_STOPPED;
            }

            if (r.lastStatus == ECST_CREATING) {
                return ECST_CREATING;
            }

            if (CFile::exists(c.dir + "/exec.fifo")) {
                return ECST_CREATED;
            }

            if (cgroupFrozen(r.cgroupPath)) {
                return ECST_PAUSED;
            }

            return ECST_RUNNING;
        }

        /**
         * Builds the OCI state of a container.
         */
        SState stateOf(const Container& c, EContainerStatus status) {
            SState s;
            s.id = c.rec.id;
            s.pid = status == ECST_STOPPED ? 0 : c.rec.initPid;
            s.status = status;
            s.bundle = c.rec.bundle;
            s.rootfs = c.rec.rootfs;
            s.created = c.rec.created;
            s.annotations = c.rec.config.annotations;
            return s;
        }

        /**
         * Returns the namespace types of a configuration.
         */
        std::vector<std::string> namespaceTypes(const SSpec& spec) {
            std::vector<std::string> types;
            if (spec.linux_) {
                for (const SNamespaceEntry& ns : spec.linux_->namespaces) {
                    types.push_back(ns.type);
                }
            }

            return types;
        }

        /**
         * Returns the standard stream mappings: the given ones, or 0/1/2 when they are open.
         */
        std::vector<SFdMapping> stdioMappings(const std::vector<SFdMapping>& given, uint32_t preserveFds, bool terminal) {
            std::vector<SFdMapping> fds;
            if (!terminal) {
                if (!given.empty()) {
                    fds = given;
                } else {
                    for (int fd = 0; fd < 3; ++fd) {
                        if (::fcntl(fd, F_GETFD) >= 0) {
                            fds.push_back({ fd, fd });
                        }
                    }
                }
            }

            for (uint32_t i = 0; i < preserveFds; ++i) {
                int fd = 3 + int(i);
                if (::fcntl(fd, F_GETFD) >= 0) {
                    fds.push_back({ fd, fd });
                }
            }

            return fds;
        }

        /**
         * Looks up the program of a process inside a container's root (/proc/<pid>/root), with
         * the PATH of the process, so that "executable file not found" is reported by create
         * as runc does instead of surfacing as an exit status after start.
         * @return SBOX_OK, -ENOENT (not found; `error` says why) or -ESRCH (the init is gone).
         */
        int32_t findExecutable(pid_t pid, const SProcessSpec& p, std::string& error) {
            CFd root(::open(("/proc/" + std::to_string(pid) + "/root").c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
            if (!root.isValid()) {
                // --> The init is gone (killed during setup): create must not report success.
                if (errno == ENOENT || errno == ESRCH) {
                    error = "container init exited during setup";
                    return -ESRCH;
                }

                return SBOX_OK;     // --> Cannot look: let exec report it.
            }

            auto usable = [&](const std::string& path) -> int {
                struct open_how how;
                std::memset(&how, 0, sizeof(how));
                how.flags = O_PATH | O_CLOEXEC;
                how.resolve = RESOLVE_IN_ROOT;
                std::string rel = path;
                while (!rel.empty() && rel[0] == '/') {
                    rel.erase(0, 1);
                }

                CFd fd(int(::syscall(SYS_openat2, root.get(), rel.empty() ? "." : rel.c_str(), &how, sizeof(how))));
                if (!fd.isValid()) {
                    return errno;
                }

                struct stat st;
                if (::fstat(fd.get(), &st) != 0) {
                    return errno;
                }

                if (!S_ISREG(st.st_mode)) {
                    return S_ISDIR(st.st_mode) ? EISDIR : EACCES;
                }

                return (st.st_mode & 0111) ? 0 : EACCES;
            };

            const std::string& file = p.args[0];
            if (file.find('/') != std::string::npos) {
                std::string path = file[0] == '/' ? file : CFile::join(p.cwd.empty() ? "/" : p.cwd, file);
                int err = usable(path);
                if (err != 0) {
                    error = "exec: \"" + file + "\": stat " + path + ": " + std::strerror(err);
                    return -ENOENT;
                }

                return SBOX_OK;
            }

            std::string search = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
            for (const std::string& e : p.env) {
                if (e.rfind("PATH=", 0) == 0) {
                    search = e.substr(5);
                }
            }

            size_t pos = 0;
            while (true) {
                size_t colon = search.find(':', pos);
                std::string dir = search.substr(pos, colon == std::string::npos ? std::string::npos : colon - pos);
                if (dir.empty()) {
                    dir = p.cwd.empty() ? "/" : p.cwd;
                }

                if (usable(CFile::join(dir, file)) == 0) {
                    return SBOX_OK;
                }

                if (colon == std::string::npos) {
                    break;
                }

                pos = colon + 1;
            }

            error = "exec: \"" + file + "\": executable file not found in $PATH";
            return -ENOENT;
        }

        /**
         * Returns true when launching `spec` forks once more after joining namespaces (a pid
         * namespace joined, or created with unshare after a join) -- the box engine's rule.
         */
        bool needsEarlyFork(const SLaunchSpec& spec) {
            uint32_t newNs = 0, joinNs = 0;
            for (const SNamespaceSpec& ns : spec.namespaces) {
                (ns.path.empty() ? newNs : joinNs) |= ns.type;
            }

            bool deferred = (joinNs & ENS_USER) || ((newNs & ENS_USER) && joinNs != 0);
            return deferred ? ((newNs & (ENS_PID | ENS_TIME)) || (joinNs & ENS_PID)) : (joinNs & ENS_PID) != 0;
        }

        /**
         * Connects to a console socket.
         */
        TTask<int32_t> connectConsole(const std::string& path, CSocket& out) {
            SEndpoint ep;
            if (int32_t rc = SEndpoint::fromUnix(path, ep); rc != SBOX_OK) {
                co_return rc;
            }

            co_return co_await out.connect(ep, 10000);
        }

        /**
         * Formats a failed launch like runc's "unable to start container process" messages.
         */
        std::string launchError(const CProcess& proc, int32_t rc) {
            std::string step = proc.failedStep();
            if (step.empty()) {
                step = "launch";
            }

            return "unable to start container process: " + step + ": " + std::strerror(-rc);
        }

        /**
         * Merges `from` into `into`: only fields that are set replace stored ones.
         */
        void mergeResources(SResourcesSpec& into, const SResourcesSpec& from) {
            if (from.memory) {
                SMemorySpec m = into.memory.value_or(SMemorySpec());
                if (from.memory->limit) m.limit = from.memory->limit;
                if (from.memory->reservation) m.reservation = from.memory->reservation;
                if (from.memory->swap) m.swap = from.memory->swap;
                if (from.memory->kernel) m.kernel = from.memory->kernel;
                if (from.memory->kernelTCP) m.kernelTCP = from.memory->kernelTCP;
                if (from.memory->swappiness) m.swappiness = from.memory->swappiness;
                if (from.memory->disableOOMKiller) m.disableOOMKiller = from.memory->disableOOMKiller;
                if (from.memory->checkBeforeUpdate) m.checkBeforeUpdate = from.memory->checkBeforeUpdate;
                into.memory = m;
            }

            if (from.cpu) {
                SCpuSpec c = into.cpu.value_or(SCpuSpec());
                if (from.cpu->shares) c.shares = from.cpu->shares;
                if (from.cpu->quota) c.quota = from.cpu->quota;
                if (from.cpu->burst) c.burst = from.cpu->burst;
                if (from.cpu->period) c.period = from.cpu->period;
                if (from.cpu->realtimeRuntime) c.realtimeRuntime = from.cpu->realtimeRuntime;
                if (from.cpu->realtimePeriod) c.realtimePeriod = from.cpu->realtimePeriod;
                if (!from.cpu->cpus.empty()) c.cpus = from.cpu->cpus;
                if (!from.cpu->mems.empty()) c.mems = from.cpu->mems;
                if (from.cpu->idle) c.idle = from.cpu->idle;
                into.cpu = c;
            }

            if (from.pids && from.pids->limit) {
                into.pids = from.pids;
            }

            if (from.blockIO) {
                SBlockIoSpec b = into.blockIO.value_or(SBlockIoSpec());
                if (from.blockIO->weight) b.weight = from.blockIO->weight;
                if (from.blockIO->leafWeight) b.leafWeight = from.blockIO->leafWeight;
                if (!from.blockIO->weightDevice.empty()) b.weightDevice = from.blockIO->weightDevice;
                if (!from.blockIO->throttleReadBpsDevice.empty()) b.throttleReadBpsDevice = from.blockIO->throttleReadBpsDevice;
                if (!from.blockIO->throttleWriteBpsDevice.empty()) b.throttleWriteBpsDevice = from.blockIO->throttleWriteBpsDevice;
                if (!from.blockIO->throttleReadIOPSDevice.empty()) b.throttleReadIOPSDevice = from.blockIO->throttleReadIOPSDevice;
                if (!from.blockIO->throttleWriteIOPSDevice.empty()) b.throttleWriteIOPSDevice = from.blockIO->throttleWriteIOPSDevice;
                into.blockIO = b;
            }

            for (const auto& kv : from.unified) {
                auto it = std::find_if(into.unified.begin(), into.unified.end(), [&](const auto& x) { return x.first == kv.first; });
                if (it != into.unified.end()) {
                    it->second = kv.second;
                } else {
                    into.unified.push_back(kv);
                }
            }
        }

        /**
         * Lists the processes in the pid namespace of `pid` (for containers without a cgroup).
         */
        void processesInPidNamespace(pid_t pid, std::vector<pid_t>& out) {
            struct stat ref;
            if (::stat(("/proc/" + std::to_string(pid) + "/ns/pid").c_str(), &ref) != 0) {
                return;
            }

            DIR* d = ::opendir("/proc");
            if (!d) {
                return;
            }

            while (struct dirent* e = ::readdir(d)) {
                char* end = nullptr;
                long p = std::strtol(e->d_name, &end, 10);
                if (*end != '\0' || p <= 0) {
                    continue;
                }

                struct stat st;
                if (::stat(("/proc/" + std::string(e->d_name) + "/ns/pid").c_str(), &st) == 0 && st.st_ino == ref.st_ino &&
                    st.st_dev == ref.st_dev) {
                    out.push_back(pid_t(p));
                }
            }

            ::closedir(d);
            std::sort(out.begin(), out.end());
        }

        const std::pair<const char*, int> SIGNALS[] = {
            { "HUP", SIGHUP }, { "INT", SIGINT }, { "QUIT", SIGQUIT }, { "ILL", SIGILL }, { "TRAP", SIGTRAP },
            { "ABRT", SIGABRT }, { "IOT", SIGIOT }, { "BUS", SIGBUS }, { "FPE", SIGFPE }, { "KILL", SIGKILL },
            { "USR1", SIGUSR1 }, { "SEGV", SIGSEGV }, { "USR2", SIGUSR2 }, { "PIPE", SIGPIPE }, { "ALRM", SIGALRM },
            { "TERM", SIGTERM }, { "STKFLT", SIGSTKFLT }, { "CHLD", SIGCHLD }, { "CONT", SIGCONT }, { "STOP", SIGSTOP },
            { "TSTP", SIGTSTP }, { "TTIN", SIGTTIN }, { "TTOU", SIGTTOU }, { "URG", SIGURG }, { "XCPU", SIGXCPU },
            { "XFSZ", SIGXFSZ }, { "VTALRM", SIGVTALRM }, { "PROF", SIGPROF }, { "WINCH", SIGWINCH }, { "IO", SIGIO },
            { "POLL", SIGPOLL }, { "PWR", SIGPWR }, { "SYS", SIGSYS },
        };

    }

    /* Sends a signal to a kept process. */
    int32_t CContainerProcess::kill(int sig) const noexcept {
        if (_adopted) {
            if (!_pidfd.isValid()) {
                return -ESRCH;
            }

            return ::syscall(SYS_pidfd_send_signal, _pidfd.get(), sig, nullptr, 0) == 0 ? SBOX_OK : -errno;
        }

        return _process.kill(sig);
    }

    /* Waits for a kept process. */
    TTask<int32_t> CContainerProcess::wait(SExitStatus& out, int64_t timeoutMs) {
        if (!_adopted) {
            co_return co_await _process.wait(out, timeoutMs);
        }

        if (!_pidfd.isValid()) {
            co_return -ECHILD;
        }

        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            siginfo_t si;
            std::memset(&si, 0, sizeof(si));
            if (::waitid(idtype_t(P_PIDFD), id_t(_pidfd.get()), &si, WEXITED | WNOHANG | __WALL) != 0) {
                co_return -errno;
            }

            if (si.si_pid != 0) {
                out = SExitStatus();
                out.exited = si.si_code == CLD_EXITED;
                out.signaled = si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED;
                out.coreDumped = si.si_code == CLD_DUMPED;
                out.exitCode = out.exited ? si.si_status : 0;
                out.signal = out.signaled ? si.si_status : 0;
                _pidfd.reset();
                co_return SBOX_OK;
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            int32_t w = co_await loop->waitFd(_pidfd.get(), EFDE_READ, left);
            if (w < 0) {
                co_return w;
            }
        }
    }

    /* Creates a runtime. */
    CRuntime::CRuntime(SRuntimeOptions options) : _options(std::move(options)) {
        if (_options.root.empty()) {
            _options.root = DefaultRoot(_options.rootless);
        }
    }

    /* Returns the default state root. */
    std::string CRuntime::DefaultRoot(bool rootless) {
        if (!rootless) {
            return "/run/sbox";
        }

        const char* xdg = std::getenv("XDG_RUNTIME_DIR");
        if (xdg && *xdg) {
            return std::string(xdg) + "/sbox";
        }

        return "/tmp/sbox-" + std::to_string(::geteuid());
    }

    /* Logs through the sink. */
    void CRuntime::log(ELogLevel level, const std::string& message) const {
        if (_options.log) {
            _options.log(level, message);
        }
    }

    /* Records an error. */
    int32_t CRuntime::fail(int32_t rc, std::string message) {
        _error = std::move(message);
        return rc;
    }

    /* Returns the directory of a container. */
    std::string CRuntime::containerDir(const std::string& id) const {
        return CFile::join(_options.root, id);
    }

    /* Creates a container. */
    TTask<int32_t> CRuntime::create(const std::string& id, const SCreateOptions& options, CContainerProcess* keep) {
        _error.clear();

        if (!ValidContainerId(id)) {
            co_return fail(-EINVAL, "invalid container id format: " + id);
        }

        char* realBundle = ::realpath(options.bundle.empty() ? "." : options.bundle.c_str(), nullptr);
        if (!realBundle) {
            co_return fail(-errno, "bundle " + options.bundle + ": " + std::strerror(errno));
        }

        std::string bundle = realBundle;
        std::free(realBundle);

        SSpec spec;
        std::string err;
        std::vector<std::string> warnings;
        if (int32_t rc = LoadSpec(bundle + "/config.json", spec, err, &warnings); rc != SBOX_OK) {
            co_return fail(rc, err);
        }

        SValidateOptions vo;
        vo.rootless = _options.rootless;
        if (int32_t rc = ValidateSpec(spec, err, &warnings, vo); rc != SBOX_OK) {
            co_return fail(rc, "invalid configuration: " + err);
        }

        const SProcessSpec& process = *spec.process;
        if (process.terminal && options.consoleSocket.empty() && !keep) {
            co_return fail(-EINVAL, "cannot allocate tty if runc will detach without setting console socket");
        }

        if (!process.terminal && !options.consoleSocket.empty()) {
            co_return fail(-EINVAL, "cannot use console socket if runc will not detach or allocate tty");
        }

        std::string rootPath = spec.root->path[0] == '/' ? spec.root->path : CFile::join(bundle, spec.root->path);
        char* realRoot = ::realpath(rootPath.c_str(), nullptr);
        if (!realRoot) {
            co_return fail(-errno, "rootfs " + rootPath + ": " + std::strerror(errno));
        }

        std::string rootfs = realRoot;
        std::free(realRoot);

        if (int32_t rc = CFile::makeDirs(_options.root, 0711); rc != SBOX_OK) {
            co_return fail(rc, "cannot create state root " + _options.root + ": " + std::strerror(-rc));
        }

        std::string dir = containerDir(id);
        if (::mkdir(dir.c_str(), 0711) != 0) {
            int32_t rc = -errno;
            co_return fail(rc, rc == -EEXIST ? "container with id exists: " + id : "mkdir " + dir + ": " + std::strerror(-rc));
        }

        DirLock dirLock;
        if (int32_t rc = co_await lockContainer(dir, dirLock, 30000); rc != SBOX_OK) {
            CFile::removeTree(dir);
            co_return fail(rc, "cannot lock " + dir + ": " + std::strerror(-rc));
        }

        for (const std::string& w : warnings) {
            log(ELOG_WARNING, w);
        }

        warnings.clear();

        SContainerRecord rec;
        rec.id = id;
        rec.bundle = bundle;
        rec.rootfs = rootfs;
        rec.created = NowRfc3339Nano();
        rec.ownerUid = uint32_t(::geteuid());
        rec.rootless = _options.rootless;
        rec.lastStatus = ECST_CREATING;
        rec.config = spec;

        // --> Everything below is undone on failure.
        CCgroup cgroup;
        CProcess proc;
        pid_t pid = 0;
        bool adopted = false;
        int32_t result = SBOX_OK;

        do {
            if (int32_t rc = writeRecord(dir, rec); rc != SBOX_OK) {
                result = fail(rc, "cannot write state: " + std::string(std::strerror(-rc)));
                break;
            }

            // Cgroup.
            const SLinuxSpec emptyLinux;
            const SLinuxSpec& l = spec.linux_ ? *spec.linux_ : emptyLinux;
            std::string cgPath;
            int32_t cgrc = SBOX_OK;

            if (_options.systemdCgroup && !l.cgroupsPath.empty()) {
                cgrc = ExpandSystemdCgroupPath(l.cgroupsPath, _options.rootless, cgPath);
                if (cgrc != SBOX_OK) {
                    result = fail(cgrc, "invalid systemd cgroupsPath \"" + l.cgroupsPath + "\" (expected slice:prefix:name)");
                    break;
                }
            } else if (!l.cgroupsPath.empty() && l.cgroupsPath[0] == '/') {
                cgPath = l.cgroupsPath.substr(1);
            } else {
                std::string parent;
                cgrc = CCgroup::defaultParent(parent);
                if (cgrc == SBOX_OK) {
                    cgPath = parent + "/" + (l.cgroupsPath.empty() ? id : l.cgroupsPath);
                }
            }

            if (cgrc == SBOX_OK && !cgPath.empty()) {
                cgrc = CCgroup::create(cgPath, cgroup);
            }

            if (cgrc != SBOX_OK) {
                if (!_options.rootless) {
                    result = fail(cgrc, "cannot create cgroup " + cgPath + ": " + std::strerror(-cgrc));
                    break;
                }

                log(ELOG_WARNING, "running without a cgroup (rootless, no delegated cgroup available)");
                cgroup = CCgroup();
            } else {
                rec.cgroupPath = cgroup.path();
                SCgroupResources res;
                if (l.resources) {
                    ToCgroupResources(*l.resources, res, warnings);
                }

                if (!res.devices.empty() && !_options.rootless) {
                    std::vector<SCgroupDeviceRule> defaults = DefaultDeviceRules(spec);
                    res.devices.insert(res.devices.end(), defaults.begin(), defaults.end());
                } else {
                    res.devices.clear();
                }

                std::vector<std::string> skipped;
                if (int32_t rc = cgroup.apply(res, &skipped); rc != SBOX_OK) {
                    if (!_options.rootless) {
                        result = fail(rc, "cannot apply cgroup resources: " + std::string(std::strerror(-rc)));
                        break;
                    }

                    log(ELOG_WARNING, "cannot apply cgroup resources: " + std::string(std::strerror(-rc)));
                }

                for (const std::string& s : skipped) {
                    log(ELOG_WARNING, "cgroup controller unavailable, limit not enforced: " + s);
                }

                if (int32_t rc = writeRecord(dir, rec); rc != SBOX_OK) {
                    result = fail(rc, "cannot write state");
                    break;
                }
            }

            // Launch spec.
            InitContext ctx;
            ctx.bundle = bundle;
            ctx.rootfs = rootfs;
            ctx.cgroup = cgroup.isValid() ? &cgroup : nullptr;
            ctx.noPivot = options.noPivot;

            SLaunchSpec ls;
            if (int32_t rc = BuildInitSpec(spec, ctx, ls, err, warnings); rc != SBOX_OK) {
                result = fail(rc, err);
                break;
            }

            if (l.seccomp) {
                auto filter = std::make_shared<CSeccompFilter>();
                std::vector<std::string> unknown;
                if (int32_t rc = CompileSeccompSpec(*l.seccomp, *filter, err, &warnings, &unknown); rc != SBOX_OK) {
                    result = fail(rc, err);
                    break;
                }

                if (!unknown.empty()) {
                    std::string names;
                    for (const std::string& n : unknown) {
                        names += (names.empty() ? "" : " ") + n;
                    }

                    log(ELOG_DEBUG, "seccomp: unknown system calls skipped: " + names);
                }

                ls.seccomp = filter;
            }

            for (const std::string& w : warnings) {
                log(ELOG_WARNING, w);
            }

            warnings.clear();
            ls.fds = stdioMappings(options.stdio, options.preserveFds, process.terminal);

            CSocket console;
            if (process.terminal && !options.consoleSocket.empty()) {
                if (int32_t rc = co_await connectConsole(options.consoleSocket, console); rc != SBOX_OK) {
                    result = fail(rc, "cannot connect to console socket " + options.consoleSocket + ": " + std::strerror(-rc));
                    break;
                }

                ls.consoleSocketFd = console.nativeHandle();
            }

            std::string fifo = dir + "/exec.fifo";
            if (::mkfifo(fifo.c_str(), 0622) != 0) {
                result = fail(-errno, "mkfifo " + fifo + ": " + std::strerror(errno));
                break;
            }

            // --> Opened read-write so neither side blocks in open(); the init reads one byte.
            CFd gate(::open(fifo.c_str(), O_RDWR | O_CLOEXEC));
            if (!gate.isValid()) {
                result = fail(-errno, "open " + fifo + ": " + std::strerror(errno));
                break;
            }

            ls.gate = ESG_FD;
            ls.gateFd = gate.get();
            // --> After an early fork the init must not stay a child of a short-lived runtime.
            ls.orphanPayload = true;
            adopted = needsEarlyFork(ls);
            if (adopted && keep) {
                ::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
            }

            int32_t rc = co_await CProcess::spawn(ls, proc);
            gate.reset();
            console.close();

            if (rc != SBOX_OK) {
                result = fail(rc, launchError(proc, rc));
                break;
            }

            pid = proc.payloadPid();
            if (pid != proc.pid()) {
                // --> The outer process of the early fork exits right away.
                SExitStatus outer;
                co_await proc.wait(outer, 5000);
            }

            SProcStat st;
            if (ReadProcStat(pid, st) != SBOX_OK) {
                result = fail(-ESRCH, "container init exited during setup");
                break;
            }

            rec.initPid = pid;
            rec.initStartTime = st.startTime;
            if (int32_t wrc = writeRecord(dir, rec); wrc != SBOX_OK) {
                result = fail(wrc, "cannot write state");
                break;
            }

            if (int32_t frc = findExecutable(pid, process, err); frc != SBOX_OK) {
                result = fail(frc, err);
                break;
            }

            // Hooks.
            if (spec.hooks) {
                Container c;
                c.dir = dir;
                c.rec = rec;
                SHookContext hc;
                hc.stateJson = stateOf(c, ECST_CREATING).toJson().dump();
                hc.defaultTimeoutMs = _options.hookTimeoutMs;

                if (int32_t hrc = co_await RunHooks(spec.hooks->prestart, hc, err); hrc != SBOX_OK) {
                    result = fail(hrc, "prestart hook: " + err);
                    break;
                }

                if (int32_t hrc = co_await RunHooks(spec.hooks->createRuntime, hc, err); hrc != SBOX_OK) {
                    result = fail(hrc, "createRuntime hook: " + err);
                    break;
                }

                hc.containerPid = pid;
                hc.namespaces = namespaceTypes(spec);
                if (int32_t hrc = co_await RunHooks(spec.hooks->createContainer, hc, err); hrc != SBOX_OK) {
                    result = fail(hrc, "createContainer hook: " + err);
                    break;
                }
            }

            rec.lastStatus = ECST_CREATED;
            if (int32_t wrc = writeRecord(dir, rec); wrc != SBOX_OK) {
                result = fail(wrc, "cannot write state");
                break;
            }

            if (!options.pidFile.empty()) {
                if (int32_t wrc = CFile::writeAtomic(options.pidFile, std::to_string(pid), 0644); wrc != SBOX_OK) {
                    result = fail(wrc, "cannot write pid file " + options.pidFile + ": " + std::strerror(-wrc));
                    break;
                }
            }
        } while (false);

        if (result != SBOX_OK) {
            // --> Undo: kill the init, remove the cgroup and the state directory.
            if (pid > 0) {
                CFd pidfd(int(::syscall(SYS_pidfd_open, pid, 0)));
                if (pidfd.isValid() && ProcessAlive(pid, rec.initStartTime)) {
                    ::syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0);
                    if (!adopted) {
                        SExitStatus ignored;
                        co_await proc.wait(ignored, 5000);
                    } else {
                        co_await WaitPidfdExit(pidfd.get(), 5000);
                    }
                }
            }

            if (cgroup.isValid()) {
                co_await cgroup.killAll(5000);
                for (int i = 0; i < 100 && cgroup.destroy() == -EBUSY; ++i) {
                    co_await CEventLoop::current()->sleepFor(10);
                }
            }

            CFile::removeTree(dir);
            co_return result;
        }

        if (keep) {
            *keep = CContainerProcess();
            keep->_pid = pid;
            keep->_pty = proc.takePty();
            if (adopted) {
                keep->_adopted = true;
                keep->_pidfd.reset(int(::syscall(SYS_pidfd_open, pid, 0)));
            } else {
                keep->_process = std::move(proc);
            }
        } else {
            proc.detach();
        }

        co_return SBOX_OK;
    }

    /* Starts a created container. */
    TTask<int32_t> CRuntime::start(const std::string& id) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (co_await lockContainer(c.dir, c.lock, 30000) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        EContainerStatus status = computeStatus(c);
        switch (status) {
        case ECST_CREATED:
            break;
        case ECST_RUNNING:
            co_return fail(-EBUSY, "cannot start an already running container");
        case ECST_PAUSED:
            co_return fail(-EBUSY, "cannot start a container in the paused state");
        case ECST_CREATING:
            co_return fail(-EBUSY, "cannot start a container that is still being created");
        default:
            co_return fail(-ESRCH, "cannot start a container that has stopped");
        }

        const SSpec& spec = c.rec.config;
        if (spec.hooks && !spec.hooks->startContainer.empty()) {
            SHookContext hc;
            hc.stateJson = stateOf(c, ECST_CREATED).toJson().dump();
            hc.defaultTimeoutMs = _options.hookTimeoutMs;
            hc.containerPid = c.rec.initPid;
            hc.namespaces = namespaceTypes(spec);
            if (int32_t rc = co_await RunHooks(spec.hooks->startContainer, hc, err); rc != SBOX_OK) {
                co_return fail(rc, "startContainer hook: " + err);
            }
        }

        std::string fifo = c.dir + "/exec.fifo";
        CFd reader(::open(fifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
        CFd writer(::open(fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC));
        if (!writer.isValid()) {
            // --> ENXIO: nobody holds the read side any more, the init is gone.
            co_return fail(-ESRCH, "cannot start a container that has stopped");
        }

        if (::write(writer.get(), "0", 1) != 1) {
            co_return fail(-errno, "cannot release the start gate: " + std::string(std::strerror(errno)));
        }

        writer.reset();
        ::unlink(fifo.c_str());

        // --> Returns once the init took the byte (it executes the program right after).
        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = CEventLoop::nowMs() + 10000;
        while (reader.isValid() && CEventLoop::nowMs() < deadline) {
            int pending = 0;
            if (::ioctl(reader.get(), FIONREAD, &pending) != 0 || pending == 0) {
                break;
            }

            if (!ProcessAlive(c.rec.initPid, c.rec.initStartTime)) {
                break;
            }

            co_await loop->sleepFor(1);
        }

        reader.reset();
        c.rec.lastStatus = ECST_RUNNING;
        writeRecord(c.dir, c.rec);

        if (spec.hooks && !spec.hooks->poststart.empty()) {
            SHookContext hc;
            hc.stateJson = stateOf(c, ECST_RUNNING).toJson().dump();
            hc.defaultTimeoutMs = _options.hookTimeoutMs;
            if (int32_t rc = co_await RunHooks(spec.hooks->poststart, hc, err); rc != SBOX_OK) {
                log(ELOG_WARNING, "poststart hook: " + err);
            }
        }

        co_return SBOX_OK;
    }

    /* Returns the OCI state. */
    TTask<int32_t> CRuntime::state(const std::string& id, SState& out) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        out = stateOf(c, computeStatus(c));
        co_return SBOX_OK;
    }

    /* Signals a container. */
    TTask<int32_t> CRuntime::kill(const std::string& id, int sig, bool all) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        EContainerStatus status = computeStatus(c);
        if (status == ECST_STOPPED || (status == ECST_CREATING && c.rec.initPid <= 0)) {
            co_return fail(-ESRCH, "container not running");
        }

        CCgroup cg;
        bool haveCgroup = !c.rec.cgroupPath.empty() && CCgroup::open(c.rec.cgroupPath, cg) == SBOX_OK;

        if (all && haveCgroup) {
            if (int32_t rc = cg.signalAll(sig); rc != SBOX_OK) {
                co_return fail(rc, "cannot signal the container processes: " + std::string(std::strerror(-rc)));
            }
        } else {
            CFd pidfd;
            if (OpenVerifiedPidfd(c.rec.initPid, c.rec.initStartTime, pidfd) != SBOX_OK) {
                co_return fail(-ESRCH, "container not running");
            }

            if (::syscall(SYS_pidfd_send_signal, pidfd.get(), sig, nullptr, 0) != 0) {
                int32_t rc = -errno;
                co_return fail(rc, "cannot signal the container init: " + std::string(std::strerror(-rc)));
            }
        }

        if (status == ECST_PAUSED && sig == SIGKILL && haveCgroup) {
            // --> Frozen tasks act on SIGKILL only once thawed (v1 freezer).
            co_await cg.freeze(false);
        }

        co_return SBOX_OK;
    }

    /* Deletes a container. */
    TTask<int32_t> CRuntime::remove(const std::string& id, bool force) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || !CFile::exists(c.dir)) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (co_await lockContainer(c.dir, c.lock, 30000) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        int32_t rrc = readRecord(c.dir, c.rec, err);
        if (rrc == -ENOENT) {
            if (!CFile::exists(c.dir)) {
                co_return fail(-ENOENT, "container does not exist");
            }

            // --> A directory without state: a create that died early. Clean it up.
            CFile::removeTree(c.dir);
            co_return SBOX_OK;
        }

        if (rrc != SBOX_OK) {
            if (!force) {
                co_return fail(rrc, "cannot read container state: " + err);
            }

            CFile::removeTree(c.dir);
            co_return SBOX_OK;
        }

        EContainerStatus status = computeStatus(c);
        if ((status == ECST_RUNNING || status == ECST_PAUSED) && !force) {
            co_return fail(-EBUSY, "cannot delete container " + id + " that is not stopped: " + StatusName(status));
        }

        CCgroup cg;
        bool haveCgroup = !c.rec.cgroupPath.empty() && CCgroup::open(c.rec.cgroupPath, cg) == SBOX_OK;

        if (status != ECST_STOPPED && c.rec.initPid > 0) {
            CFd pidfd;
            if (OpenVerifiedPidfd(c.rec.initPid, c.rec.initStartTime, pidfd) == SBOX_OK) {
                ::syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0);
                if (status == ECST_PAUSED && haveCgroup) {
                    co_await cg.freeze(false);
                }

                co_await WaitPidfdExit(pidfd.get(), 10000);
            }
        }

        if (haveCgroup) {
            if (cgroupFrozen(c.rec.cgroupPath)) {
                co_await cg.freeze(false);
            }

            co_await cg.killAll(5000);
            int32_t drc = SBOX_OK;
            for (int i = 0; i < 200; ++i) {
                drc = cg.destroy();
                if (drc != -EBUSY) {
                    break;
                }

                co_await CEventLoop::current()->sleepFor(10);
            }

            if (drc != SBOX_OK && drc != -ENOENT) {
                log(ELOG_WARNING, "cannot remove cgroup " + c.rec.cgroupPath + ": " + std::strerror(-drc));
            }
        }

        const SSpec& spec = c.rec.config;
        if (spec.hooks && !spec.hooks->poststop.empty() && c.rec.initPid > 0) {
            SHookContext hc;
            hc.stateJson = stateOf(c, ECST_STOPPED).toJson().dump();
            hc.defaultTimeoutMs = _options.hookTimeoutMs;
            if (int32_t rc = co_await RunHooks(spec.hooks->poststop, hc, err); rc != SBOX_OK) {
                log(ELOG_WARNING, "poststop hook: " + err);
            }
        }

        if (int32_t rc = CFile::removeTree(c.dir); rc != SBOX_OK) {
            co_return fail(rc, "cannot remove " + c.dir + ": " + std::strerror(-rc));
        }

        co_return SBOX_OK;
    }

    /* Runs a process in a container. */
    TTask<int32_t> CRuntime::exec(const std::string& id, const SExecOptions& options, CContainerProcess* keep) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        EContainerStatus status = computeStatus(c);
        if (status == ECST_STOPPED || status == ECST_CREATING) {
            co_return fail(-ESRCH, "cannot exec in a stopped container");
        }

        if (status == ECST_PAUSED && !options.ignorePaused) {
            co_return fail(-EBUSY, "cannot exec in a paused container");
        }

        const SProcessSpec& p = options.process;
        if (p.args.empty()) {
            co_return fail(-EINVAL, "process.args must not be empty");
        }

        if (!p.cwd.empty() && p.cwd[0] != '/') {
            co_return fail(-EINVAL, "process.cwd \"" + p.cwd + "\" must be an absolute path");
        }

        if (p.terminal && options.consoleSocket.empty() && !keep) {
            co_return fail(-EINVAL, "cannot allocate tty if runc will detach without setting console socket");
        }

        const SSpec& spec = c.rec.config;
        SLaunchSpec ls;
        std::vector<std::string> warnings;
        if (int32_t rc = ApplyProcess(p, ls, err, warnings); rc != SBOX_OK) {
            co_return fail(rc, err);
        }

        // --> The namespace files are opened first and the init verified afterwards, so a
        // reused pid cannot hand us another process's namespaces.
        std::vector<CFd> nsFds;
        for (const std::string& type : namespaceTypes(spec)) {
            const char* proc = NamespaceProcName(type);
            uint32_t bit = NamespaceFromName(type);
            if (!proc || bit == ENS_NONE) {
                continue;
            }

            std::string path = "/proc/" + std::to_string(c.rec.initPid) + "/ns/" + proc;
            CFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
            if (!fd.isValid()) {
                co_return fail(-ESRCH, "cannot exec in a stopped container");
            }

            ls.namespaces.push_back(SNamespaceSpec{ ENamespace(bit), "/proc/self/fd/" + std::to_string(fd.get()) });
            nsFds.push_back(std::move(fd));
        }

        if (!ProcessAlive(c.rec.initPid, c.rec.initStartTime)) {
            co_return fail(-ESRCH, "cannot exec in a stopped container");
        }

        ls.rootfsMode = ERFS_HOST;

        CCgroup cg;
        if (!c.rec.cgroupPath.empty() && CCgroup::open(c.rec.cgroupPath, cg) == SBOX_OK) {
            ls.cgroup = &cg;
        }

        if (spec.linux_ && spec.linux_->seccomp) {
            auto filter = std::make_shared<CSeccompFilter>();
            if (int32_t rc = CompileSeccompSpec(*spec.linux_->seccomp, *filter, err, &warnings); rc != SBOX_OK) {
                co_return fail(rc, err);
            }

            ls.seccomp = filter;
        }

        for (const std::string& w : warnings) {
            log(ELOG_WARNING, w);
        }

        ls.fds = stdioMappings(options.stdio, options.preserveFds, p.terminal);

        CSocket console;
        if (p.terminal && !options.consoleSocket.empty()) {
            if (int32_t rc = co_await connectConsole(options.consoleSocket, console); rc != SBOX_OK) {
                co_return fail(rc, "cannot connect to console socket " + options.consoleSocket + ": " + std::strerror(-rc));
            }

            ls.consoleSocketFd = console.nativeHandle();
        }

        // --> Kept: the outer process stays as a reaper that forwards signals and the exit
        // status. Not kept: it exits at once and the process goes to our subreaper (the shim).
        ls.orphanPayload = keep == nullptr;

        CProcess proc;
        int32_t rc = co_await CProcess::spawn(ls, proc);
        console.close();
        nsFds.clear();

        if (rc != SBOX_OK) {
            std::string step = proc.failedStep();
            if (step == "execve") {
                co_return fail(rc, "exec failed: exec: \"" + p.args[0] + "\": " + std::strerror(-rc));
            }

            co_return fail(rc, launchError(proc, rc));
        }

        pid_t pid = proc.payloadPid();
        if (!keep && pid != proc.pid()) {
            SExitStatus outer;
            co_await proc.wait(outer, 5000);
        }

        if (!options.pidFile.empty()) {
            if (int32_t wrc = CFile::writeAtomic(options.pidFile, std::to_string(pid), 0644); wrc != SBOX_OK) {
                co_return fail(wrc, "cannot write pid file " + options.pidFile + ": " + std::strerror(-wrc));
            }
        }

        if (keep) {
            *keep = CContainerProcess();
            keep->_pid = pid;
            keep->_pty = proc.takePty();
            keep->_process = std::move(proc);
        } else {
            proc.detach();
        }

        co_return SBOX_OK;
    }

    /* Lists the pids of a container. */
    TTask<int32_t> CRuntime::processes(const std::string& id, std::vector<pid_t>& out) {
        _error.clear();
        out.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        CCgroup cg;
        if (!c.rec.cgroupPath.empty() && CCgroup::open(c.rec.cgroupPath, cg) == SBOX_OK) {
            if (int32_t rc = cg.processes(out); rc != SBOX_OK) {
                co_return fail(rc, "cannot list cgroup processes: " + std::string(std::strerror(-rc)));
            }

            std::sort(out.begin(), out.end());
            co_return SBOX_OK;
        }

        if (computeStatus(c) != ECST_STOPPED) {
            processesInPidNamespace(c.rec.initPid, out);
        }

        co_return SBOX_OK;
    }

    /* Freezes a container. */
    TTask<int32_t> CRuntime::pause(const std::string& id) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        EContainerStatus status = computeStatus(c);
        if (status != ECST_RUNNING && status != ECST_CREATED) {
            co_return fail(-EINVAL, status == ECST_PAUSED ? "container already paused" : "container not running");
        }

        CCgroup cg;
        if (c.rec.cgroupPath.empty() || CCgroup::open(c.rec.cgroupPath, cg) != SBOX_OK) {
            co_return fail(-ENOTSUP, "cannot pause a container without a cgroup");
        }

        if (int32_t rc = co_await cg.freeze(true); rc != SBOX_OK) {
            co_return fail(rc, "cannot freeze the container: " + std::string(std::strerror(-rc)));
        }

        co_return SBOX_OK;
    }

    /* Thaws a container. */
    TTask<int32_t> CRuntime::resume(const std::string& id) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (computeStatus(c) != ECST_PAUSED) {
            co_return fail(-EINVAL, "container not paused");
        }

        CCgroup cg;
        if (CCgroup::open(c.rec.cgroupPath, cg) != SBOX_OK) {
            co_return fail(-ENOTSUP, "cannot resume a container without a cgroup");
        }

        if (int32_t rc = co_await cg.freeze(false); rc != SBOX_OK) {
            co_return fail(rc, "cannot thaw the container: " + std::string(std::strerror(-rc)));
        }

        co_return SBOX_OK;
    }

    /* Updates resource limits. */
    TTask<int32_t> CRuntime::update(const std::string& id, const SResourcesSpec& resources) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || !CFile::exists(c.dir)) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (co_await lockContainer(c.dir, c.lock, 30000) != SBOX_OK || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        if (computeStatus(c) == ECST_STOPPED) {
            co_return fail(-ESRCH, "container not running");
        }

        CCgroup cg;
        if (c.rec.cgroupPath.empty() || CCgroup::open(c.rec.cgroupPath, cg) != SBOX_OK) {
            co_return fail(-ENOTSUP, "cannot update a container without a cgroup");
        }

        SResourcesSpec changes = resources;
        changes.devices.clear();    // --> As runc: device rules are not updatable.

        std::vector<std::string> warnings;
        SCgroupResources res;
        ToCgroupResources(changes, res, warnings);
        for (const std::string& w : warnings) {
            log(ELOG_WARNING, w);
        }

        std::vector<std::string> skipped;
        if (int32_t rc = cg.apply(res, &skipped); rc != SBOX_OK) {
            co_return fail(rc, "cannot update cgroup resources: " + std::string(std::strerror(-rc)));
        }

        for (const std::string& s : skipped) {
            log(ELOG_WARNING, "cgroup controller unavailable, limit not enforced: " + s);
        }

        if (!c.rec.config.linux_) {
            c.rec.config.linux_ = SLinuxSpec();
        }

        if (!c.rec.config.linux_->resources) {
            c.rec.config.linux_->resources = SResourcesSpec();
        }

        mergeResources(*c.rec.config.linux_->resources, changes);
        writeRecord(c.dir, c.rec);
        co_return SBOX_OK;
    }

    /* Reads cgroup statistics. */
    TTask<int32_t> CRuntime::stats(const std::string& id, SCgroupStats& out) {
        _error.clear();
        Container c;
        c.dir = containerDir(id);
        std::string err;

        if (!ValidContainerId(id) || readRecord(c.dir, c.rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        CCgroup cg;
        if (c.rec.cgroupPath.empty() || CCgroup::open(c.rec.cgroupPath, cg) != SBOX_OK) {
            co_return fail(-ENOTSUP, "container has no cgroup");
        }

        if (int32_t rc = cg.stats(out); rc != SBOX_OK) {
            co_return fail(rc, "cannot read cgroup statistics: " + std::string(std::strerror(-rc)));
        }

        co_return SBOX_OK;
    }

    /* Returns the stored configuration. */
    TTask<int32_t> CRuntime::config(const std::string& id, SSpec& out) {
        _error.clear();
        SContainerRecord rec;
        std::string err;

        if (!ValidContainerId(id) || readRecord(containerDir(id), rec, err) != SBOX_OK) {
            co_return fail(-ENOENT, "container does not exist");
        }

        out = rec.config;
        co_return SBOX_OK;
    }

    /* Lists containers. */
    TTask<int32_t> CRuntime::list(std::vector<SState>& out) {
        _error.clear();
        out.clear();

        DIR* d = ::opendir(_options.root.c_str());
        if (!d) {
            if (errno == ENOENT) {
                co_return SBOX_OK;
            }

            int32_t rc = -errno;
            co_return fail(rc, "cannot read " + _options.root + ": " + std::strerror(-rc));
        }

        std::vector<std::string> names;
        while (struct dirent* e = ::readdir(d)) {
            if (e->d_name[0] != '.' && ValidContainerId(e->d_name)) {
                names.push_back(e->d_name);
            }
        }

        ::closedir(d);
        std::sort(names.begin(), names.end());

        for (const std::string& name : names) {
            Container c;
            c.dir = containerDir(name);
            std::string err;
            if (readRecord(c.dir, c.rec, err) != SBOX_OK) {
                continue;
            }

            SState s = stateOf(c, computeStatus(c));
            struct stat st;
            if (::stat(c.dir.c_str(), &st) == 0) {
                s.owner = std::to_string(st.st_uid);
            }

            out.push_back(std::move(s));
        }

        co_return SBOX_OK;
    }

    /* Parses a signal. */
    int32_t ParseSignal(std::string_view text) noexcept {
        if (text.empty()) {
            return -EINVAL;
        }

        if (text[0] >= '0' && text[0] <= '9') {
            int64_t n = 0;
            for (char ch : text) {
                if (ch < '0' || ch > '9') {
                    return -EINVAL;
                }

                n = n * 10 + (ch - '0');
                if (n > SIGRTMAX) {
                    return -EINVAL;
                }
            }

            return n > 0 ? int32_t(n) : -EINVAL;
        }

        std::string name(text);
        for (char& ch : name) {
            if (ch >= 'a' && ch <= 'z') {
                ch = char(ch - 'a' + 'A');
            }
        }

        if (name.rfind("SIG", 0) == 0) {
            name.erase(0, 3);
        }

        for (const auto& [n, sig] : SIGNALS) {
            if (name == n) {
                return sig;
            }
        }

        // --> RTMIN, RTMIN+n, RTMAX, RTMAX-n.
        if (name.rfind("RTMIN", 0) == 0 || name.rfind("RTMAX", 0) == 0) {
            bool min = name[3] == 'I';
            int base = min ? SIGRTMIN : SIGRTMAX;
            std::string rest = name.substr(5);
            if (rest.empty()) {
                return base;
            }

            if ((min && rest[0] != '+') || (!min && rest[0] != '-') || rest.size() < 2) {
                return -EINVAL;
            }

            int off = std::atoi(rest.c_str() + 1);
            int sig = min ? base + off : base - off;
            return sig >= SIGRTMIN && sig <= SIGRTMAX ? sig : -EINVAL;
        }

        return -EINVAL;
    }

}
}
