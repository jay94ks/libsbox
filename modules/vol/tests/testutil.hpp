#ifndef __TESTS_VOL_TESTUTIL_HPP__
#define __TESTS_VOL_TESTUTIL_HPP__

// Helpers shared by the vol tests (each test file is its own executable).

#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/stream.hpp>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <linux/loop.h>
#include <sched.h>
#include <signal.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace testutil {

    using namespace sbox;

    /**
     * Fails a check inside a forked child: prints the location and returns from the child body.
     */
#define CHILD_CHECK(cond)                                                               \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::fprintf(stderr, "%s:%d: child check failed: %s\n", __FILE__, __LINE__, #cond); \
            return __LINE__;                                                            \
        }                                                                               \
    } while (0)

    /**
     * Creates a unique directory under /tmp (mode 0755) and removes it on destruction.
     */
    struct TempDir {
        std::string path;

        explicit TempDir(const char* tag = "vol") {
            std::string tmpl = std::string("/tmp/sbox-test-") + tag + "-XXXXXX";
            std::vector<char> buf(tmpl.begin(), tmpl.end());
            buf.push_back('\0');
            char* p = ::mkdtemp(buf.data());
            path = p ? p : "";
            if (p) {
                ::chmod(p, 0755);
            }
        }

        ~TempDir() {
            if (!path.empty()) {
                ::umount2(path.c_str(), MNT_DETACH);
                CFile::removeTree(path);
            }
        }

        std::string operator/(const std::string& leaf) const { return CFile::join(path, leaf); }
    };

    /** Returns true when running as root. */
    inline bool isRoot() { return ::geteuid() == 0; }

    /** Writes a small file. */
    inline bool writeFile(const std::string& path, const std::string& data, mode_t mode = 0644) {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
        if (fd < 0) {
            return false;
        }

        bool ok = ::write(fd, data.data(), data.size()) == ssize_t(data.size());
        ::close(fd);
        return ok;
    }

    /** Reads a small file ("" when missing). */
    inline std::string readFile(const std::string& path) {
        std::string out;
        CFile::readAll(path, out);
        return out;
    }

    /**
     * Waits for a child through a pidfd on the current loop and returns its wait status
     * (or -1).
     */
    inline TTask<int> waitChild(pid_t pid, int64_t timeoutMs = 120000) {
        int pidfd = int(::syscall(SYS_pidfd_open, pid, 0));
        if (pidfd < 0) {
            co_return -1;
        }

        int32_t rc = co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, timeoutMs);
        if (rc == -ETIMEDOUT) {
            ::kill(pid, SIGKILL);
            co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, 10000);
        }

        siginfo_t info{};
        int status = -1;
        if (::waitid(idtype_t(P_PIDFD), id_t(pidfd), &info, WEXITED) == 0) {
            status = info.si_code == CLD_EXITED ? (info.si_status << 8) : (info.si_status & 0x7f);
        }

        ::close(pidfd);
        co_return status;
    }

    /**
     * Runs `fn` in a forked child inside a new private mount namespace (so mounts never reach
     * the host table) and returns its exit code, 77 when the namespace cannot be created, or
     * -1 when the child died abnormally. Must be called outside an event loop.
     */
    inline int runInPrivateMountNs(const std::function<int()>& fn) {
        std::fflush(nullptr);
        pid_t pid = ::fork();
        if (pid < 0) {
            return -1;
        }

        if (pid == 0) {
            if (::unshare(CLONE_NEWNS) != 0) {
                ::_exit(77);
            }

            if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
                ::_exit(77);
            }

            int code = fn();
            std::fflush(nullptr);
            ::_exit(code);
        }

        CEventLoop loop;
        int status = loop.run(waitChild(pid));
        if (status < 0 || (status & 0x7f) != 0) {
            return -1;
        }

        return (status >> 8) & 0xff;
    }

    /**
     * Runs a program (argv[0] is a path) and waits on the current loop.
     * @param out Receives stdout when not null.
     * @param in Written to stdin (closed afterwards).
     * @return The exit code, or -1.
     */
    inline TTask<int> runProgram(std::vector<std::string> argv, std::string* out = nullptr, std::string in = std::string()) {
        int outPipe[2] = { -1, -1 };
        int inPipe[2] = { -1, -1 };
        if (::pipe2(outPipe, O_CLOEXEC) != 0 || ::pipe2(inPipe, O_CLOEXEC) != 0) {
            co_return -1;
        }

        std::vector<char*> args;
        for (std::string& a : argv) {
            args.push_back(a.data());
        }

        args.push_back(nullptr);
        std::fflush(nullptr);
        pid_t pid = ::fork();
        if (pid == 0) {
            ::dup2(inPipe[0], 0);
            ::dup2(outPipe[1], 1);
            if (out == nullptr) {
                int devnull = ::open("/dev/null", O_WRONLY);
                ::dup2(devnull, 1);
            }

            ::execv(args[0], args.data());
            ::_exit(127);
        }

        ::close(outPipe[1]);
        ::close(inPipe[0]);
        CStream reader{ CFd(outPipe[0]) };
        CStream writer{ CFd(inPipe[1]) };
        if (pid < 0) {
            co_return -1;
        }

        if (!in.empty()) {
            co_await writer.send(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(in.data()), in.size()));
        }

        writer.close();
        std::vector<uint8_t> bytes;
        co_await reader.recvAll(bytes, size_t(64) << 20, 120000);
        if (out != nullptr) {
            out->assign(bytes.begin(), bytes.end());
        }

        int status = co_await waitChild(pid);
        if (status < 0 || (status & 0x7f) != 0) {
            co_return -1;
        }

        co_return (status >> 8) & 0xff;
    }

    /** Returns the first existing path among candidates (or ""). */
    inline std::string findTool(const char* name) {
        const char* dirs[] = { "/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin" };
        for (const char* d : dirs) {
            std::string p = std::string(d) + "/" + name;
            if (::access(p.c_str(), X_OK) == 0) {
                return p;
            }
        }

        return std::string();
    }

    /**
     * Loop device bound to an image file (LOOP_CONFIGURE with autoclear): it goes away when
     * the last user closes it and it is unmounted.
     */
    struct LoopDevice {
        std::string path;
        int fd = -1;

        /* Attaches `image`; returns false when loop devices are unavailable. */
        bool attach(const std::string& image) {
            int ctl = ::open("/dev/loop-control", O_RDWR | O_CLOEXEC);
            if (ctl < 0) {
                return false;
            }

            int file = ::open(image.c_str(), O_RDWR | O_CLOEXEC);
            if (file < 0) {
                ::close(ctl);
                return false;
            }

            bool ok = false;
            for (int attempt = 0; attempt < 32 && !ok; ++attempt) {
                int n = ::ioctl(ctl, LOOP_CTL_GET_FREE);
                if (n < 0) {
                    break;
                }

                std::string dev = "/dev/loop" + std::to_string(n);
                int d = ::open(dev.c_str(), O_RDWR | O_CLOEXEC);
                if (d < 0) {
                    continue;
                }

                loop_config cfg{};
                cfg.fd = uint32_t(file);
                cfg.info.lo_flags = LO_FLAGS_AUTOCLEAR;
                if (::ioctl(d, LOOP_CONFIGURE, &cfg) == 0) {
                    path = dev;
                    fd = d;
                    ok = true;
                } else {
                    ::close(d);
                }
            }

            ::close(file);
            ::close(ctl);
            return ok;
        }

        ~LoopDevice() {
            if (fd >= 0) {
                ::close(fd);
            }
        }
    };

}

#endif
