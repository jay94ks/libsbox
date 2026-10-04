#include "launch_child.hpp"
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <stdio_ext.h>
#include <cstring>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/openat2.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <grp.h>

// --> Everything in this file runs in the child between clone3 and execve. The parent may be
// multithreaded, so only async-signal-safe calls are allowed here: raw system calls (or their
// thin libc wrappers), no allocation, no locks, no stdio. All data was prepared by the parent.

#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

namespace sbox {

    namespace {

        const char* const STEP_NAMES[STEP_COUNT] = {
            "none", "relocate-fds", "pdeathsig", "setns", "unshare", "sync", "fork", "oom-score-adj",
            "loopback", "sethostname", "setdomainname", "mount-propagation", "rootfs", "mount",
            "mount-flags", "device", "dev-symlink", "pivot_root", "root-propagation", "sysctl",
            "readonly-path", "masked-path", "root-readonly", "rlimit", "terminal", "setsid",
            "cap-bounding", "setgroups", "setgid", "setuid", "capset", "cap-ambient", "chdir",
            "fds", "start-gate", "no_new_privs", "seccomp", "execve",
        };

        LaunchPlan* gPlan = nullptr;
        volatile pid_t gForwardTo = 0;

        /**
         * Writes one status record (atomic: smaller than PIPE_BUF).
         */
        void report(int fd, uint32_t kind, int32_t error, uint32_t step, int32_t index, int64_t value) noexcept {
            if (fd < 0) {
                return;
            }

            LaunchRecord rec{ kind, error, step, index, value };
            while (::write(fd, &rec, sizeof(rec)) < 0 && errno == EINTR) {
            }
        }

        /**
         * Reports a failed step and exits.
         */
        [[noreturn]] void fail(uint32_t step, int32_t index, int err) noexcept {
            report(gPlan->reportFd, REC_ERROR, -(err ? err : EIO), step, index, 0);
            ::_exit(126);
        }

        /**
         * Formats "/proc/self/fd/<fd>" into `buf` (at least 32 bytes).
         */
        const char* fdPath(char* buf, int fd) noexcept {
            static const char prefix[] = "/proc/self/fd/";
            std::memcpy(buf, prefix, sizeof(prefix) - 1);

            char digits[16];
            int n = 0;
            unsigned value = unsigned(fd);

            do {
                digits[n++] = char('0' + value % 10);
                value /= 10;
            } while (value && n < 15);

            char* p = buf + sizeof(prefix) - 1;
            while (n > 0) {
                *p++ = digits[--n];
            }

            *p = '\0';
            return buf;
        }

        int sysOpenat2(int dirfd, const char* path, uint64_t flags, uint64_t resolve) noexcept {
            struct open_how how;
            std::memset(&how, 0, sizeof(how));
            how.flags = flags;
            how.resolve = resolve;
            return int(::syscall(SYS_openat2, dirfd, path, &how, sizeof(how)));
        }

        /**
         * Opens `rel` inside the root `rootfd` (symlinks cannot leave the root), creating missing
         * components: directories, and the last one as a file when `lastIsFile`. Symlinks are
         * followed by hand (relative to the root), so a dangling link in an untrusted rootfs
         * creates its target inside the root, never outside.
         * @return An O_PATH descriptor, or -errno.
         */
        int openInRoot(int rootfd, const char* rel, bool create, bool lastIsFile) noexcept {
            const uint64_t resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;

            while (*rel == '/') {
                ++rel;
            }

            if (*rel == '\0') {
                int fd = ::fcntl(rootfd, F_DUPFD_CLOEXEC, 3);
                return fd < 0 ? -errno : fd;
            }

            int fd = sysOpenat2(rootfd, rel, O_PATH | O_CLOEXEC, resolve);
            if (fd >= 0 || errno != ENOENT || !create) {
                return fd >= 0 ? fd : -errno;
            }

            char rest[4096];        // --> Components still to walk.
            char resolved[4096];    // --> Canonical path walked so far (relative to the root).
            char link[4096];
            size_t restLen = std::strlen(rel);
            size_t resolvedLen = 0;
            int links = 0;

            if (restLen >= sizeof(rest)) {
                return -ENAMETOOLONG;
            }

            std::memcpy(rest, rel, restLen + 1);
            resolved[0] = '\0';

            int cur = ::fcntl(rootfd, F_DUPFD_CLOEXEC, 3);
            if (cur < 0) {
                return -errno;
            }

            size_t pos = 0;
            while (true) {
                while (rest[pos] == '/') {
                    ++pos;
                }

                if (rest[pos] == '\0') {
                    return cur;
                }

                size_t end = pos;
                while (rest[end] != '\0' && rest[end] != '/') {
                    ++end;
                }

                char name[256];
                size_t nameLen = end - pos;
                if (nameLen >= sizeof(name)) {
                    ::close(cur);
                    return -ENAMETOOLONG;
                }

                std::memcpy(name, rest + pos, nameLen);
                name[nameLen] = '\0';
                pos = end;

                size_t after = pos;
                while (rest[after] == '/') {
                    ++after;
                }

                bool last = rest[after] == '\0';

                if (std::strcmp(name, ".") == 0) {
                    continue;
                }

                if (std::strcmp(name, "..") == 0) {
                    // --> Pop one component; ".." of the root is the root.
                    while (resolvedLen > 0 && resolved[resolvedLen - 1] != '/') {
                        --resolvedLen;
                    }

                    if (resolvedLen > 0) {
                        --resolvedLen;
                    }

                    resolved[resolvedLen] = '\0';
                    int up = resolvedLen ? sysOpenat2(rootfd, resolved, O_PATH | O_CLOEXEC, resolve)
                                         : ::fcntl(rootfd, F_DUPFD_CLOEXEC, 3);
                    int err = errno;
                    ::close(cur);
                    if (up < 0) {
                        return -err;
                    }

                    cur = up;
                    continue;
                }

                struct stat st;
                if (::fstatat(cur, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
                    if (++links > 40) {
                        ::close(cur);
                        return -ELOOP;
                    }

                    ssize_t n = ::readlinkat(cur, name, link, sizeof(link) - 1);
                    if (n < 0) {
                        int err = errno;
                        ::close(cur);
                        return -err;
                    }

                    link[n] = '\0';
                    size_t tail = std::strlen(rest + pos);
                    if (size_t(n) + 1 + tail >= sizeof(rest)) {
                        ::close(cur);
                        return -ENAMETOOLONG;
                    }

                    // --> rest = link + remaining components.
                    std::memmove(rest + n + 1, rest + pos, tail + 1);
                    std::memcpy(rest, link, size_t(n));
                    rest[n] = '/';
                    pos = 0;

                    if (link[0] == '/') {
                        // --> Absolute links restart at the container root.
                        resolvedLen = 0;
                        resolved[0] = '\0';
                        ::close(cur);
                        cur = ::fcntl(rootfd, F_DUPFD_CLOEXEC, 3);
                        if (cur < 0) {
                            return -errno;
                        }
                    }

                    continue;
                }

                int next = ::openat(cur, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (next < 0 && errno == ENOENT) {
                    int rc;
                    if (last && lastIsFile) {
                        rc = ::openat(cur, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
                        if (rc >= 0) {
                            ::close(rc);
                            rc = 0;
                        }
                    } else {
                        rc = ::mkdirat(cur, name, 0755);
                    }

                    if (rc < 0 && errno != EEXIST) {
                        int err = errno;
                        ::close(cur);
                        return -err;
                    }

                    next = ::openat(cur, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                }

                if (next < 0) {
                    int err = errno;
                    ::close(cur);
                    return -err;
                }

                ::close(cur);
                cur = next;

                if (resolvedLen + 1 + nameLen >= sizeof(resolved)) {
                    ::close(cur);
                    return -ENAMETOOLONG;
                }

                if (resolvedLen) {
                    resolved[resolvedLen++] = '/';
                }

                std::memcpy(resolved + resolvedLen, name, nameLen + 1);
                resolvedLen += nameLen;
            }
        }

        /**
         * Returns the MS_* flags a mount currently has that a bind remount must keep (the
         * kernel refuses to clear flags locked by a more privileged namespace).
         */
        unsigned long lockedFlags(const char* path) noexcept {
            struct statfs sf;
            if (::statfs(path, &sf) != 0) {
                return 0;
            }

            unsigned long out = 0;
            if (sf.f_flags & ST_RDONLY) out |= MS_RDONLY;
            if (sf.f_flags & ST_NOSUID) out |= MS_NOSUID;
            if (sf.f_flags & ST_NODEV) out |= MS_NODEV;
            if (sf.f_flags & ST_NOEXEC) out |= MS_NOEXEC;
            if (sf.f_flags & ST_NOATIME) out |= MS_NOATIME;
            if (sf.f_flags & ST_NODIRATIME) out |= MS_NODIRATIME;
            if (sf.f_flags & ST_RELATIME) out |= MS_RELATIME;
            return out;
        }

        /**
         * Applies ro/nosuid/nodev/noexec to an existing bind mount.
         */
        int remountBind(const char* path, unsigned long flags) noexcept {
            unsigned long keep = lockedFlags(path);
            unsigned long all = MS_BIND | MS_REMOUNT | flags | keep;

            if (::mount(nullptr, path, nullptr, all, nullptr) == 0) {
                return 0;
            }

            // --> Atime flags may conflict (relatime vs noatime); retry with only the required ones.
            all = MS_BIND | MS_REMOUNT | flags | (keep & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC));
            if (::mount(nullptr, path, nullptr, all, nullptr) == 0) {
                return 0;
            }

            return -errno;
        }

        /**
         * Makes a mount tree read-only recursively (mount_setattr, 5.12+).
         */
        int recursiveReadOnly(const char* path) noexcept {
#ifdef SYS_mount_setattr
            struct mount_attr attr;
            std::memset(&attr, 0, sizeof(attr));
            attr.attr_set = MOUNT_ATTR_RDONLY;

            if (::syscall(SYS_mount_setattr, AT_FDCWD, path, AT_RECURSIVE, &attr, sizeof(attr)) == 0) {
                return 0;
            }

            return -errno;
#else
            (void) path;
            return -ENOSYS;
#endif
        }

        /**
         * Closes every descriptor except `a` and `b`.
         */
        void closeAllExcept(int a, int b) noexcept {
            int lo = a < b ? a : b;
            int hi = a < b ? b : a;

            auto closeRange = [](int from, int to) {
                if (from <= to) {
                    ::syscall(SYS_close_range, unsigned(from), unsigned(to), 0u);
                }
            };

            if (lo < 0) {
                closeRange(0, hi - 1);
                closeRange(hi + 1, 0x7fffffff);
                return;
            }

            closeRange(0, lo - 1);
            closeRange(lo + 1, hi - 1);
            closeRange(hi + 1, 0x7fffffff);
        }

        /**
         * Moves `fd` above the descriptors that will be targets of the fd mapping.
         */
        int lift(int fd) noexcept {
            int moved = ::fcntl(fd, F_DUPFD_CLOEXEC, gPlan->maxTarget + 1);
            if (moved >= 0) {
                ::close(fd);
            }

            return moved;
        }

        /**
         * Signal handler of a reaper: forwards the signal to the payload.
         */
        void forwardSignal(int sig) noexcept {
            int saved = errno;
            if (gForwardTo > 0) {
                ::kill(gForwardTo, sig);
            }

            errno = saved;
        }

        /**
         * Drops every capability (used by a reaper after it forked the payload).
         */
        void dropAllCapabilities() noexcept {
            struct __user_cap_header_struct hdr{ _LINUX_CAPABILITY_VERSION_3, 0 };
            struct __user_cap_data_struct data[2];
            std::memset(data, 0, sizeof(data));
            ::syscall(SYS_capset, &hdr, data);
            ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }

        /**
         * Forks the payload. The payload returns from this function; the calling process
         * becomes its reaper: it forwards signals, reaps every child (as a pid-namespace init
         * must) and reports the payload's status before exiting.
         * @param hostPid True when the reaper lives in the caller's pid namespace (its view of
         *        the payload pid is meaningful to the caller).
         */
        void forkPayload(bool hostPid) noexcept {
            int execPipe[2];
            if (::pipe2(execPipe, O_CLOEXEC) != 0) {
                fail(STEP_FORK, -1, errno);
            }

            execPipe[0] = lift(execPipe[0]);
            execPipe[1] = lift(execPipe[1]);
            if (execPipe[0] < 0 || execPipe[1] < 0) {
                fail(STEP_FORK, -1, errno);
            }

            // --> _Fork (not fork): no atfork handlers or locks, and unlike a raw clone it
            // refreshes libc's cached thread id, which a function payload may depend on.
            pid_t pid = ::_Fork();
            if (pid < 0) {
                fail(STEP_FORK, -1, errno);
            }

            if (pid == 0) {
                ::close(execPipe[0]);
                if (::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
                    fail(STEP_PDEATHSIG, -1, errno);
                }

                return;
            }

            // Reaper.
            ::close(execPipe[1]);
            gForwardTo = pid;

            if (hostPid) {
                report(gPlan->reportFd, REC_PID, 0, STEP_NONE, -1, pid);
            }

            closeAllExcept(gPlan->reportFd, execPipe[0]);
            dropAllCapabilities();

            struct sigaction sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sa_handler = forwardSignal;
            sa.sa_flags = SA_RESTART;
            sigemptyset(&sa.sa_mask);

            for (int sig = 1; sig < 32; ++sig) {
                if (sig != SIGKILL && sig != SIGSTOP && sig != SIGCHLD) {
                    ::sigaction(sig, &sa, nullptr);
                }
            }

            // --> EOF on the exec pipe: the payload exec'd (close-on-exec) or exited.
            char byte;
            while (::read(execPipe[0], &byte, 1) < 0 && errno == EINTR) {
            }

            ::close(execPipe[0]);
            report(gPlan->reportFd, REC_EXEC, 0, STEP_NONE, -1, 0);

            int status = 0;
            while (true) {
                int st = 0;
                pid_t got = ::wait4(-1, &st, __WALL, nullptr);
                if (got == pid) {
                    status = st;
                    break;
                }

                if (got < 0 && errno != EINTR) {
                    break;
                }
            }

            report(gPlan->reportFd, REC_EXIT, 0, STEP_NONE, -1, status);

            if (WIFEXITED(status)) {
                ::_exit(WEXITSTATUS(status));
            }

            ::_exit(128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
        }

        /**
         * Brings the loopback interface up in a new network namespace.
         */
        int loopbackUp() noexcept {
            int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (s < 0) {
                return -errno;
            }

            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            std::memcpy(ifr.ifr_name, "lo", 3);

            int rc = 0;
            if (::ioctl(s, SIOCGIFFLAGS, &ifr) != 0) {
                rc = -errno;
            } else {
                ifr.ifr_flags = short(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
                if (::ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
                    rc = -errno;
                }
            }

            ::close(s);
            return rc;
        }

        /**
         * Writes a whole small file (sysctl, oom_score_adj).
         */
        int writeFile(const char* path, const char* value) noexcept {
            int fd = ::open(path, O_WRONLY | O_CLOEXEC);
            if (fd < 0) {
                return -errno;
            }

            size_t len = std::strlen(value);
            ssize_t n = ::write(fd, value, len);
            int err = n < 0 ? errno : 0;
            ::close(fd);

            if (n < 0) {
                return -err;
            }

            return size_t(n) == len ? 0 : -EIO;
        }

        /**
         * Performs the mounts, devices and the root switch.
         */
        void setupFilesystem(LaunchPlan& p) noexcept {
            unsigned long prop = p.rootPropagation ? p.rootPropagation : (MS_SLAVE | MS_REC);
            if (::mount(nullptr, "/", nullptr, prop, nullptr) != 0) {
                fail(STEP_PROPAGATION, -1, errno);
            }

            if (p.rootfsMode == ERFS_HOST && p.mounts.empty()) {
                return;
            }

            const char* root = p.rootfsMode == ERFS_HOST ? "/" : p.rootPath;

            // --> Open bind sources (and host devices) now: in our own mount namespace, and
            // before the new root may cover them.
            for (size_t i = 0; i < p.mounts.size(); ++i) {
                PlanMount& m = p.mounts[i];
                if (!m.bind || m.skip) {
                    continue;
                }

                m.sourceFd = ::open(m.source, O_PATH | O_CLOEXEC);
                if (m.sourceFd < 0) {
                    if (errno == ENOENT && m.optional) {
                        m.skip = true;
                        continue;
                    }

                    fail(STEP_MOUNT, int32_t(i), errno);
                }
            }

            for (PlanDevice& d : p.devices) {
                if (d.hostPath) {
                    d.hostFd = ::open(d.hostPath, O_PATH | O_CLOEXEC);
                }
            }

            if (p.rootfsMode == ERFS_TMPFS) {
                if (::mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, p.rootTmpfsData) != 0) {
                    fail(STEP_ROOTFS, -1, errno);
                }
            } else if (p.rootfsMode == ERFS_DIRECTORY) {
                // --> pivot_root needs the new root to be a mount point.
                if (::mount(root, root, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
                    fail(STEP_ROOTFS, -1, errno);
                }
            }

            int rootfd = ::open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (rootfd < 0) {
                fail(STEP_ROOTFS, -1, errno);
            }

            char target[32];
            char source[32];

            for (size_t i = 0; i < p.mounts.size(); ++i) {
                PlanMount& m = p.mounts[i];
                if (m.skip) {
                    continue;
                }

                int dest = openInRoot(rootfd, m.target, true, m.bind && !m.sourceIsDir);
                if (dest < 0) {
                    fail(STEP_MOUNT, int32_t(i), -dest);
                }

                fdPath(target, dest);

                int rc;
                if (m.bind) {
                    const char* src = m.sourceFd >= 0 ? fdPath(source, m.sourceFd) : m.source;
                    rc = ::mount(src, target, nullptr, m.flags, nullptr);
                } else {
                    rc = ::mount(m.source, target, m.fstype, m.flags, m.data);
                }

                if (rc != 0) {
                    fail(STEP_MOUNT, int32_t(i), errno);
                }

                // --> Re-open: the descriptor still refers to the directory under the new mount.
                ::close(dest);
                dest = openInRoot(rootfd, m.target, false, false);
                if (dest < 0) {
                    fail(STEP_MOUNT, int32_t(i), -dest);
                }

                fdPath(target, dest);

                if (m.bind && m.remount) {
                    if (int err = remountBind(target, m.remountFlags); err != 0) {
                        fail(STEP_MOUNT_FLAGS, int32_t(i), -err);
                    }
                }

                if (m.recursiveReadOnly) {
                    // --> Without mount_setattr only the top mount is read-only (remount above).
                    int err = recursiveReadOnly(target);
                    if (err != 0 && err != -ENOSYS) {
                        fail(STEP_MOUNT_FLAGS, int32_t(i), -err);
                    }
                }

                if (m.propagation && ::mount(nullptr, target, nullptr, m.propagation, nullptr) != 0) {
                    fail(STEP_MOUNT_FLAGS, int32_t(i), errno);
                }

                ::close(dest);
            }

            for (size_t i = 0; i < p.devices.size(); ++i) {
                PlanDevice& d = p.devices[i];

                // --> Resolve the parent directory, then create the node in it.
                const char* slash = std::strrchr(d.path, '/');
                char dir[4096];
                const char* name = d.path;

                if (slash) {
                    size_t n = size_t(slash - d.path);
                    if (n >= sizeof(dir)) {
                        fail(STEP_DEVICE, int32_t(i), ENAMETOOLONG);
                    }

                    std::memcpy(dir, d.path, n);
                    dir[n] = '\0';
                    name = slash + 1;
                } else {
                    dir[0] = '\0';
                }

                int dirfd = openInRoot(rootfd, dir, true, false);
                if (dirfd < 0) {
                    fail(STEP_DEVICE, int32_t(i), -dirfd);
                }

                // --> O_PATH descriptors cannot be used for mknodat; reopen the directory.
                int realDir = ::openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                ::close(dirfd);
                if (realDir < 0) {
                    fail(STEP_DEVICE, int32_t(i), errno);
                }

                ::unlinkat(realDir, name, 0);

                if (::mknodat(realDir, name, d.mode, d.dev) == 0) {
                    ::fchownat(realDir, name, d.uid, d.gid, AT_SYMLINK_NOFOLLOW);
                    // --> mknod honours the umask; set the exact mode.
                    ::fchmodat(realDir, name, d.mode & 07777, 0);
                } else {
                    if ((errno != EPERM && errno != EACCES) || d.hostFd < 0) {
                        fail(STEP_DEVICE, int32_t(i), errno);
                    }

                    // --> In a user namespace: bind the host's node over an empty file.
                    int f = ::openat(realDir, name, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
                    if (f < 0) {
                        fail(STEP_DEVICE, int32_t(i), errno);
                    }

                    ::close(f);

                    int node = openInRoot(rootfd, d.path, false, false);
                    if (node < 0) {
                        fail(STEP_DEVICE, int32_t(i), -node);
                    }

                    fdPath(target, node);
                    if (::mount(fdPath(source, d.hostFd), target, nullptr, MS_BIND, nullptr) != 0) {
                        fail(STEP_DEVICE, int32_t(i), errno);
                    }

                    ::close(node);
                }

                ::close(realDir);
            }

            if (p.devSymlinks) {
                static const char* const links[][2] = {
                    { "/proc/self/fd", "fd" }, { "/proc/self/fd/0", "stdin" },
                    { "/proc/self/fd/1", "stdout" }, { "/proc/self/fd/2", "stderr" },
                    { "pts/ptmx", "ptmx" },
                };

                int devfd = openInRoot(rootfd, "dev", true, false);
                if (devfd < 0) {
                    fail(STEP_DEV_SYMLINK, -1, -devfd);
                }

                int realDev = ::openat(devfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                ::close(devfd);
                if (realDev < 0) {
                    fail(STEP_DEV_SYMLINK, -1, errno);
                }

                for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); ++i) {
                    struct stat st;
                    if (::fstatat(realDev, links[i][1], &st, AT_SYMLINK_NOFOLLOW) == 0) {
                        continue;   // --> Keep what a mount or device already provides.
                    }

                    if (::symlinkat(links[i][0], realDev, links[i][1]) != 0 && errno != EEXIST) {
                        fail(STEP_DEV_SYMLINK, int32_t(i), errno);
                    }
                }

                ::close(realDev);
            }

            if (p.rootfsMode == ERFS_HOST) {
                ::close(rootfd);
                return;
            }

            if (::fchdir(rootfd) != 0) {
                fail(STEP_PIVOT_ROOT, -1, errno);
            }

            ::close(rootfd);

            if (!p.noPivot) {
                // --> pivot_root(".", "."): the old root ends up stacked on "/" and is detached.
                if (::syscall(SYS_pivot_root, ".", ".") != 0) {
                    fail(STEP_PIVOT_ROOT, -1, errno);
                }

                if (::umount2(".", MNT_DETACH) != 0) {
                    fail(STEP_PIVOT_ROOT, -1, errno);
                }
            } else {
                if (::mount(".", "/", nullptr, MS_MOVE, nullptr) != 0) {
                    fail(STEP_PIVOT_ROOT, -1, errno);
                }

                if (::chroot(".") != 0) {
                    fail(STEP_PIVOT_ROOT, -1, errno);
                }
            }

            if (::chdir("/") != 0) {
                fail(STEP_PIVOT_ROOT, -1, errno);
            }

            if (p.rootPropagationAfter && ::mount(nullptr, "/", nullptr, p.rootPropagationAfter, nullptr) != 0) {
                fail(STEP_ROOT_PROPAGATION, -1, errno);
            }
        }

        /**
         * Paths handled after the root switch (and the sysctls): read-only and masked paths and
         * the read-only root.
         */
        void finishFilesystem(LaunchPlan& p) noexcept {
            for (size_t i = 0; i < p.readonlyPaths.size(); ++i) {
                const char* path = p.readonlyPaths[i];
                if (::mount(path, path, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
                    if (errno == ENOENT) {
                        continue;
                    }

                    fail(STEP_READONLY_PATH, int32_t(i), errno);
                }

                if (int err = remountBind(path, MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC); err != 0) {
                    fail(STEP_READONLY_PATH, int32_t(i), -err);
                }
            }

            for (size_t i = 0; i < p.maskedPaths.size(); ++i) {
                const char* path = p.maskedPaths[i];
                struct stat st;

                if (::stat(path, &st) != 0) {
                    if (errno == ENOENT) {
                        continue;
                    }

                    fail(STEP_MASKED_PATH, int32_t(i), errno);
                }

                int rc;
                if (S_ISDIR(st.st_mode)) {
                    rc = ::mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=0");
                } else {
                    rc = ::mount("/dev/null", path, nullptr, MS_BIND, nullptr);
                }

                if (rc != 0 && errno != ENOENT) {
                    fail(STEP_MASKED_PATH, int32_t(i), errno);
                }
            }

            if (p.rootReadOnly && p.rootfsMode != ERFS_HOST) {
                if (int err = remountBind("/", MS_RDONLY); err != 0) {
                    fail(STEP_ROOT_READONLY, -1, -err);
                }
            }
        }

        /**
         * Creates the pty in the container's devpts and returns the slave descriptor.
         */
        int setupTerminal(LaunchPlan& p) noexcept {
            int master = ::open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
            if (master < 0) {
                fail(STEP_TERMINAL, 0, errno);
            }

            int unlock = 0;
            if (::ioctl(master, TIOCSPTLCK, &unlock) != 0) {
                fail(STEP_TERMINAL, 1, errno);
            }

            int slave = ::ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
            if (slave < 0) {
                fail(STEP_TERMINAL, 2, errno);
            }

            if (p.rows || p.columns) {
                struct winsize ws;
                std::memset(&ws, 0, sizeof(ws));
                ws.ws_row = p.rows;
                ws.ws_col = p.columns;
                ::ioctl(master, TIOCSWINSZ, &ws);
            }

            if (::fchown(slave, p.uid, p.gid) != 0 && errno != EINVAL && errno != EPERM) {
                fail(STEP_TERMINAL, 3, errno);
            }

            // --> Hand the master over (SCM_RIGHTS) on the console socket.
            char dummy = 'p';
            struct iovec iov{ &dummy, 1 };
            alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))];
            std::memset(control, 0, sizeof(control));

            struct msghdr msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);

            struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(cm), &master, sizeof(int));

            if (::sendmsg(p.consoleFd, &msg, MSG_NOSIGNAL) < 0) {
                fail(STEP_TERMINAL, 4, errno);
            }

            ::close(master);
            ::close(p.consoleFd);
            p.consoleFd = -1;
            return slave;
        }

        /**
         * Applies the capability sets and the user/group ids.
         */
        void setupIdentity(LaunchPlan& p) noexcept {
            for (int cap = 0; cap <= p.lastCap; ++cap) {
                if (!(p.caps.bounding & (uint64_t(1) << cap))) {
                    if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) {
                        fail(STEP_CAP_BOUNDING, cap, errno);
                    }
                }
            }

            if (::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
                fail(STEP_CAPSET, -1, errno);
            }

            if (p.setGroups) {
                // --> Clearing the groups may be refused (setgroups "deny" in a user namespace
                // we joined); that only matters when groups were asked for.
                if (::syscall(SYS_setgroups, p.groups.size(), p.groups.data()) != 0 && !p.groups.empty()) {
                    fail(STEP_SETGROUPS, -1, errno);
                }
            } else if (!p.groups.empty()) {
                fail(STEP_SETGROUPS, -1, EPERM);
            }

            // --> Raw syscalls: the libc wrappers broadcast to all threads (and we are a clone).
            if (::syscall(SYS_setresgid, p.gid, p.gid, p.gid) != 0) {
                fail(STEP_SETGID, -1, errno);
            }

            if (::syscall(SYS_setresuid, p.uid, p.uid, p.uid) != 0) {
                fail(STEP_SETUID, -1, errno);
            }

            struct __user_cap_header_struct hdr{ _LINUX_CAPABILITY_VERSION_3, 0 };
            struct __user_cap_data_struct data[2];
            data[0].effective = uint32_t(p.caps.effective);
            data[1].effective = uint32_t(p.caps.effective >> 32);
            data[0].permitted = uint32_t(p.caps.permitted);
            data[1].permitted = uint32_t(p.caps.permitted >> 32);
            data[0].inheritable = uint32_t(p.caps.inheritable);
            data[1].inheritable = uint32_t(p.caps.inheritable >> 32);

            if (::syscall(SYS_capset, &hdr, data) != 0) {
                fail(STEP_CAPSET, -1, errno);
            }

            if (::prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0) {
                fail(STEP_CAPSET, -1, errno);
            }

            for (int cap = 0; cap <= p.lastCap; ++cap) {
                if (p.caps.ambient & (uint64_t(1) << cap)) {
                    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
                        fail(STEP_CAP_AMBIENT, cap, errno);
                    }
                }
            }
        }

        /**
         * Installs the fd mapping: targets get their sources, other low descriptors are closed
         * and everything above is close-on-exec.
         */
        void setupFds(LaunchPlan& p, int ttySlave) noexcept {
            if (ttySlave >= 0) {
                for (int t = 0; t <= 2; ++t) {
                    if (::dup2(ttySlave, t) < 0) {
                        fail(STEP_FDS, t, errno);
                    }
                }
            }

            for (size_t i = 0; i < p.fds.size(); ++i) {
                const SFdMapping& m = p.fds[i];
                if (ttySlave >= 0 && m.target <= 2) {
                    continue;
                }

                if (::dup2(m.source, m.target) < 0) {
                    fail(STEP_FDS, int32_t(i), errno);
                }
            }

            for (int fd = 0; fd <= p.maxTarget; ++fd) {
                bool mapped = ttySlave >= 0 && fd <= 2;
                for (const SFdMapping& m : p.fds) {
                    mapped = mapped || m.target == fd;
                }

                if (!mapped) {
                    ::close(fd);
                }
            }

            ::syscall(SYS_close_range, unsigned(p.maxTarget + 1), ~0u, CLOSE_RANGE_CLOEXEC);
        }

        /**
         * Executes the payload, searching PATH when args[0] has no slash.
         */
        [[noreturn]] void execPayload(LaunchPlan& p) noexcept {
            const char* file = p.executable ? p.executable : p.argv[0];

            if (std::strchr(file, '/')) {
                ::execve(file, p.argv.data(), p.envp.data());
                fail(STEP_EXEC, -1, errno);
            }

            const char* path = p.searchPath ? p.searchPath : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
            size_t fileLen = std::strlen(file);
            int firstError = ENOENT;
            bool sawAccess = false;
            char buf[4096];

            while (true) {
                const char* end = std::strchr(path, ':');
                size_t dirLen = end ? size_t(end - path) : std::strlen(path);

                if (dirLen + 1 + fileLen < sizeof(buf)) {
                    size_t n = 0;
                    if (dirLen == 0) {
                        buf[n++] = '.';
                    } else {
                        std::memcpy(buf, path, dirLen);
                        n = dirLen;
                    }

                    buf[n++] = '/';
                    std::memcpy(buf + n, file, fileLen + 1);

                    ::execve(buf, p.argv.data(), p.envp.data());

                    if (errno == EACCES) {
                        sawAccess = true;
                    } else if (errno != ENOENT && errno != ENOTDIR && errno != ESTALE && errno != ENODEV && errno != ETIMEDOUT) {
                        firstError = errno;
                        break;
                    }
                }

                if (!end) {
                    break;
                }

                path = end + 1;
            }

            fail(STEP_EXEC, -1, sawAccess ? EACCES : firstError);
        }

    }

    /* Returns the printable name of a step. */
    const char* LaunchStepName(uint32_t step) noexcept {
        return step < STEP_COUNT ? STEP_NAMES[step] : "unknown";
    }

    /* Registers every descriptor field for relocation. */
    void LaunchPlan::collectFdSlots() {
        fdSlots.clear();
        fdSlots.push_back(&reportFd);
        fdSlots.push_back(&syncFd);
        fdSlots.push_back(&gateFd);
        fdSlots.push_back(&consoleFd);

        for (PlanJoin& j : joins) {
            fdSlots.push_back(&j.fd);
        }

        for (SFdMapping& f : fds) {
            fdSlots.push_back(&f.source);
        }

        relocated.assign(fdSlots.size() * 2, -1);
    }

    /* Child side of the launch. */
    void RunLaunchChild(LaunchPlan& p) noexcept {
        gPlan = &p;

        // --> Reset signal dispositions inherited from the parent; the parent blocked every
        // signal around clone3 so no handler of its own could run here.
        struct sigaction dfl;
        std::memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        for (int sig = 1; sig < NSIG; ++sig) {
            if (sig != SIGKILL && sig != SIGSTOP) {
                ::sigaction(sig, &dfl, nullptr);
            }
        }

        sigset_t none;
        sigemptyset(&none);
        ::sigprocmask(SIG_SETMASK, &none, nullptr);

        // --> Move every descriptor we use above the mapping targets: (old, new) pairs.
        size_t pairs = 0;
        for (int* slot : p.fdSlots) {
            if (*slot < 0) {
                continue;
            }

            int moved = -1;
            for (size_t i = 0; i < pairs; ++i) {
                if (p.relocated[i * 2] == *slot) {
                    moved = p.relocated[i * 2 + 1];
                }
            }

            if (moved < 0) {
                moved = ::fcntl(*slot, F_DUPFD_CLOEXEC, p.maxTarget + 1);
                if (moved < 0) {
                    report(*slot == p.reportFd ? -1 : p.reportFd, REC_ERROR, -errno, STEP_FDS_RELOCATE, -1, 0);
                    ::_exit(126);
                }

                p.relocated[pairs * 2] = *slot;
                p.relocated[pairs * 2 + 1] = moved;
                ++pairs;
            }

            *slot = moved;
        }

        for (size_t i = 0; i < pairs; ++i) {
            ::close(p.relocated[i * 2]);
        }

        if (p.parentDeathSignal && ::prctl(PR_SET_PDEATHSIG, p.parentDeathSignal, 0, 0, 0) != 0) {
            fail(STEP_PDEATHSIG, -1, errno);
        }

        // Namespaces: join (user first), then create what clone3 could not.
        for (size_t i = 0; i < p.joins.size(); ++i) {
            if (::setns(p.joins[i].fd, p.joins[i].nstype) != 0) {
                fail(STEP_SETNS, int32_t(i), errno);
            }

            ::close(p.joins[i].fd);
            p.joins[i].fd = -1;
        }

        if (p.unshareFlags && ::unshare(p.unshareFlags) != 0) {
            fail(STEP_UNSHARE, -1, errno);
        }

        // --> The parent writes the id maps and joins the cgroups, then lets us continue.
        report(p.reportFd, REC_SYNC, 0, STEP_SYNC, -1, 0);
        char go = 0;
        ssize_t got;
        while ((got = ::read(p.syncFd, &go, 1)) < 0 && errno == EINTR) {
        }

        if (got != 1) {
            ::_exit(125);
        }

        ::close(p.syncFd);
        p.syncFd = -1;

        if (p.earlyFork) {
            // --> A joined or unshared pid namespace only applies to children.
            forkPayload(true);
        }

        if (p.oomScoreAdj) {
            if (int err = writeFile("/proc/self/oom_score_adj", p.oomScoreAdj); err != 0) {
                fail(STEP_OOM_SCORE, -1, -err);
            }
        }

        if (p.newNetNs && p.loopbackUp) {
            if (int err = loopbackUp(); err != 0) {
                fail(STEP_LOOPBACK, -1, -err);
            }
        }

        if (p.hostname && ::sethostname(p.hostname, std::strlen(p.hostname)) != 0) {
            fail(STEP_HOSTNAME, -1, errno);
        }

        if (p.domainname && ::setdomainname(p.domainname, std::strlen(p.domainname)) != 0) {
            fail(STEP_DOMAINNAME, -1, errno);
        }

        if (p.newMountNs) {
            setupFilesystem(p);
        }

        for (size_t i = 0; i < p.sysctls.size(); ++i) {
            if (int err = writeFile(p.sysctls[i].first, p.sysctls[i].second); err != 0) {
                fail(STEP_SYSCTL, int32_t(i), -err);
            }
        }

        if (p.newMountNs) {
            finishFilesystem(p);
        }

        for (size_t i = 0; i < p.rlimits.size(); ++i) {
            if (::syscall(SYS_prlimit64, 0, p.rlimits[i].first, &p.rlimits[i].second, nullptr) != 0) {
                fail(STEP_RLIMIT, p.rlimits[i].first, errno);
            }
        }

        if (p.newSession && ::setsid() < 0) {
            fail(STEP_SETSID, -1, errno);
        }

        int ttySlave = -1;
        if (p.terminal) {
            ttySlave = setupTerminal(p);
            if (::ioctl(ttySlave, TIOCSCTTY, 0) != 0) {
                fail(STEP_TERMINAL, 5, errno);
            }
        }

        if (p.seccomp && !p.noNewPrivs) {
            // --> Without no_new_privs the filter needs CAP_SYS_ADMIN: install it while we
            // still hold it (as runc does). The rest of the setup then runs under it.
            if (int err = p.seccomp->install(); err != 0) {
                fail(STEP_SECCOMP, -1, -err);
            }
        }

        setupIdentity(p);

        if (p.cwd && ::chdir(p.cwd) != 0) {
            fail(STEP_CHDIR, -1, errno);
        }

        setupFds(p, ttySlave);

        if (p.reaper) {
            forkPayload(false);
        }

        if (p.gateFd >= 0) {
            report(p.reportFd, REC_READY, 0, STEP_GATE, -1, 0);

            char byte = 0;
            ssize_t n;
            while ((n = ::read(p.gateFd, &byte, 1)) < 0 && errno == EINTR) {
            }

            if (n != 1) {
                // --> The gate was closed without a start: abort quietly.
                ::_exit(125);
            }

            ::close(p.gateFd);
            p.gateFd = -1;
        }

        if (p.noNewPrivs && ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fail(STEP_NO_NEW_PRIVS, -1, errno);
        }

        if (p.seccomp && p.noNewPrivs) {
            if (int err = p.seccomp->install(); err != 0) {
                fail(STEP_SECCOMP, -1, -err);
            }
        }

        if (p.function) {
            // --> Close every internal descriptor (report and exec pipes) before user code runs.
            ::syscall(SYS_close_range, unsigned(p.maxTarget + 1), ~0u, 0u);

            // --> Output the caller buffered before the fork belongs to the caller.
            ::__fpurge(stdout);
            ::__fpurge(stderr);

            int32_t code = (*p.function)();
            std::fflush(nullptr);
            ::_exit(int(code & 0xff));
        }

        execPayload(p);
    }

} // namespace sbox
