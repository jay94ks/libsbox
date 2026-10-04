#include <sbox/net/netns.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/stream.hpp>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

namespace sbox {
namespace net {

    namespace {

        const char* const THREAD_NETNS = "/proc/thread-self/ns/net";

        /* Opens the calling thread's namespace file. */
        int openThreadNetns() noexcept {
            int fd = ::open(THREAD_NETNS, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                // --> Kernels without /proc/thread-self: the main thread's entry is the same
                // for single-threaded programs.
                fd = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
            }

            return fd;
        }

        /* Makes `dir` a shared mount (bind-mounting it onto itself first when needed). */
        int32_t makeSharedDir(const std::string& dir) noexcept {
            if (::mount("", dir.c_str(), "none", MS_SHARED | MS_REC, nullptr) == 0) {
                return SBOX_OK;
            }

            if (errno != EINVAL) {
                return -errno;
            }

            // --> Not a mount point yet: iproute2 bind-mounts the directory onto itself so it can
            // carry its own propagation type.
            if (::mount(dir.c_str(), dir.c_str(), "none", MS_BIND | MS_REC, nullptr) < 0) {
                return -errno;
            }

            if (::mount("", dir.c_str(), "none", MS_SHARED | MS_REC, nullptr) < 0) {
                return -errno;
            }

            return SBOX_OK;
        }

    }

    /* Enters the namespace at `path`. */
    CNetnsScope::CNetnsScope(const std::string& path) noexcept : _error(SBOX_OK) {
        if (path.empty()) {
            return;
        }

        CFd ns(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!ns.isValid()) {
            _error = -errno;
            return;
        }

        enter(ns.get());
    }

    /* Enters the namespace referred to by a descriptor. */
    CNetnsScope::CNetnsScope(int nsFd) noexcept : _error(SBOX_OK) {
        if (nsFd >= 0) {
            enter(nsFd);
        }
    }

    /* Saves the current namespace and switches. */
    void CNetnsScope::enter(int nsFd) noexcept {
        CFd saved(openThreadNetns());
        if (!saved.isValid()) {
            _error = -errno;
            return;
        }

        if (::setns(nsFd, CLONE_NEWNET) < 0) {
            _error = -errno;
            return;
        }

        _saved = std::move(saved);
    }

    /* Restores the original namespace. */
    CNetnsScope::~CNetnsScope() {
        if (!_saved.isValid()) {
            return;
        }

        if (::setns(_saved.get(), CLONE_NEWNET) < 0) {
            // --> Continuing would configure the wrong network from here on.
            std::fprintf(stderr, "sbox::net: cannot restore the network namespace: %s\n", std::strerror(errno));
            std::abort();
        }
    }

    /* Creates and pins a new namespace. */
    int32_t CNetns::create(const std::string& path) noexcept {
        size_t slash = path.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            int32_t r = CFile::makeDirs(path.substr(0, slash));
            if (r != SBOX_OK) {
                return r;
            }
        }

        CFd file(::open(path.c_str(), O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444));
        if (!file.isValid()) {
            return -errno;
        }

        file.reset();

        CFd saved(openThreadNetns());
        if (!saved.isValid()) {
            int32_t err = -errno;
            ::unlink(path.c_str());
            return err;
        }

        if (::unshare(CLONE_NEWNET) < 0) {
            int32_t err = -errno;
            ::unlink(path.c_str());
            return err;
        }

        int32_t result = SBOX_OK;
        if (::mount(THREAD_NETNS, path.c_str(), "none", MS_BIND, nullptr) < 0
            && ::mount("/proc/self/ns/net", path.c_str(), "none", MS_BIND, nullptr) < 0) {
            result = -errno;
        }

        if (::setns(saved.get(), CLONE_NEWNET) < 0) {
            std::fprintf(stderr, "sbox::net: cannot restore the network namespace: %s\n", std::strerror(errno));
            std::abort();
        }

        if (result != SBOX_OK) {
            ::unlink(path.c_str());
        }

        return result;
    }

    /* Creates a named namespace in a shared directory. */
    int32_t CNetns::createNamed(std::string_view name, std::string& outPath, const std::string& dir) noexcept {
        if (name.empty() || name.find('/') != std::string_view::npos || name == "." || name == "..") {
            return -EINVAL;
        }

        int32_t r = CFile::makeDirs(dir);
        if (r != SBOX_OK) {
            return r;
        }

        r = makeSharedDir(dir);
        if (r != SBOX_OK) {
            return r;
        }

        outPath = CFile::join(dir, name);
        return create(outPath);
    }

    /* Unpins and removes a namespace file. */
    int32_t CNetns::remove(const std::string& path) noexcept {
        if (::umount2(path.c_str(), MNT_DETACH) < 0 && errno != EINVAL && errno != ENOENT) {
            return -errno;
        }

        if (::unlink(path.c_str()) < 0 && errno != ENOENT) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Opens a namespace file. */
    int32_t CNetns::open(const std::string& path, CFd& out) noexcept {
        CFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!fd.isValid()) {
            return -errno;
        }

        out = std::move(fd);
        return SBOX_OK;
    }

    /* Opens the current namespace. */
    int32_t CNetns::openCurrent(CFd& out) noexcept {
        CFd fd(openThreadNetns());
        if (!fd.isValid()) {
            return -errno;
        }

        out = std::move(fd);
        return SBOX_OK;
    }

    /* Creates an anonymous namespace held by a descriptor. */
    int32_t CNetns::createAnonymous(CFd& out) noexcept {
        CFd saved(openThreadNetns());
        if (!saved.isValid()) {
            return -errno;
        }

        if (::unshare(CLONE_NEWNET) < 0) {
            return -errno;
        }

        CFd created(openThreadNetns());
        int32_t result = created.isValid() ? SBOX_OK : -errno;

        if (::setns(saved.get(), CLONE_NEWNET) < 0) {
            std::fprintf(stderr, "sbox::net: cannot restore the network namespace: %s\n", std::strerror(errno));
            std::abort();
        }

        if (result == SBOX_OK) {
            out = std::move(created);
        }

        return result;
    }

    /* Returns the namespace inode. */
    int32_t CNetns::inode(const std::string& path, uint64_t& out) noexcept {
        struct stat st;
        if (::stat(path.c_str(), &st) < 0) {
            return -errno;
        }

        out = uint64_t(st.st_ino);
        return SBOX_OK;
    }

    /* Returns true when the path is an nsfs network namespace. */
    bool CNetns::isNetns(const std::string& path) noexcept {
        struct statfs fs;
        if (::statfs(path.c_str(), &fs) < 0 || fs.f_type != NSFS_MAGIC) {
            return false;
        }

        CFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!fd.isValid()) {
            return false;
        }

        // --> setns with a mismatching type fails with EINVAL; checking the type through the
        // NS_GET_NSTYPE ioctl would need linux/nsfs.h, which is not on every build host.
        CFd saved(openThreadNetns());
        if (!saved.isValid()) {
            return false;
        }

        if (::setns(fd.get(), CLONE_NEWNET) < 0) {
            return false;
        }

        if (::setns(saved.get(), CLONE_NEWNET) < 0) {
            std::fprintf(stderr, "sbox::net: cannot restore the network namespace: %s\n", std::strerror(errno));
            std::abort();
        }

        return true;
    }

    /* Runs a function in a child process inside the namespace. */
    TTask<int32_t> CNetns::run(const std::string& path, std::function<int32_t()> fn) {
        CFd ns(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!ns.isValid()) {
            co_return -errno;
        }

        CStream resultRead;
        CFd resultWrite;
        int32_t r = CPipe::createForChild(resultRead, resultWrite, true);
        if (r != SBOX_OK) {
            co_return r;
        }

        pid_t pid = ::fork();
        if (pid < 0) {
            co_return -errno;
        }

        if (pid == 0) {
            int32_t value = -ECHILD;
            if (::setns(ns.get(), CLONE_NEWNET) < 0) {
                value = -errno;
            }
            else {
                value = fn();
            }

            ssize_t n = ::write(resultWrite.get(), &value, sizeof(value));
            ::_exit(n == ssize_t(sizeof(value)) ? 0 : 1);
        }

        resultWrite.reset();

        CFd pidfd(int(::syscall(SYS_pidfd_open, pid, 0)));
        int32_t value = -ECHILD;
        uint8_t buffer[sizeof(int32_t)];
        SIoResult got = co_await resultRead.recvExact(SByteSpan(buffer, sizeof(buffer)));
        if (got.ok()) {
            std::memcpy(&value, buffer, sizeof(value));
        }

        resultRead.close();

        if (pidfd.isValid()) {
            co_await CEventLoop::current()->waitFd(pidfd.get(), EFDE_READ);
            siginfo_t info;
            std::memset(&info, 0, sizeof(info));
            ::waitid(idtype_t(P_PIDFD), id_t(pidfd.get()), &info, WEXITED);
        }
        else {
            // --> No pidfd support: the child has already written its result (or died, closing
            // the pipe), so this reap does not wait long.
            int status = 0;
            ::waitpid(pid, &status, 0);
        }

        co_return value;
    }

}
}
