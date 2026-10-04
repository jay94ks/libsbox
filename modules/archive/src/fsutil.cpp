#include "fsutil.hpp"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#else
struct open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_IN_ROOT 0x10
#endif

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

// --> The *xattrat family (Linux 6.13) has the same number on every architecture.
#ifndef SYS_setxattrat
#define SYS_setxattrat 463
#endif

#ifndef SYS_getxattrat
#define SYS_getxattrat 464
#endif

#ifndef SYS_listxattrat
#define SYS_listxattrat 465
#endif

namespace sbox {
namespace archive {
namespace fsutil {

    namespace {

        /* struct xattr_args of the *xattrat system calls. */
        struct XattrArgs {
            uint64_t value;
            uint32_t size;
            uint32_t flags;
        };

        // --> 1 = *xattrat available, 0 = unknown, -1 = missing (fall back to /proc/self/fd).
        std::atomic<int32_t> g_xattrAt{ 0 };

        /* "/proc/self/fd/<dirfd>/<name>" for the l*xattr fallback. */
        std::string procPath(int dirfd, const char* name) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "/proc/self/fd/%d/", dirfd);
            return std::string(buf) + name;
        }

        /* Splits a path into components. */
        void splitInto(const std::string& path, std::deque<std::string>& out, bool front) {
            std::vector<std::string> comps;
            size_t start = 0;
            while (start <= path.size()) {
                size_t slash = path.find('/', start);
                if (slash == std::string::npos) {
                    slash = path.size();
                }

                if (slash > start) {
                    comps.push_back(path.substr(start, slash - start));
                }

                start = slash + 1;
            }

            if (front) {
                out.insert(out.begin(), comps.begin(), comps.end());
            } else {
                out.insert(out.end(), comps.begin(), comps.end());
            }
        }

        /* Duplicates a descriptor with O_CLOEXEC. */
        int32_t dupFd(int fd, CFd& out) {
            int d = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
            if (d < 0) {
                return -errno;
            }

            out.reset(d);
            return SBOX_OK;
        }

        /* Resolves `rel` under `rootFd` with O_NOFOLLOW opens, emulating RESOLVE_IN_ROOT. */
        int32_t walkInRoot(int rootFd, const std::string& rel, CFd& out) {
            std::vector<CFd> stack;
            stack.emplace_back();
            int32_t rc = dupFd(rootFd, stack.back());
            if (rc < 0) {
                return rc;
            }

            std::deque<std::string> todo;
            splitInto(rel, todo, false);
            int32_t links = 0;
            while (!todo.empty()) {
                std::string c = std::move(todo.front());
                todo.pop_front();
                if (c.empty() || c == ".") {
                    continue;
                }

                if (c == "..") {
                    if (stack.size() > 1) {
                        stack.pop_back();
                    }

                    continue;
                }

                int fd = ::openat(stack.back().get(), c.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                    return -errno;
                }

                CFd f(fd);
                struct stat st{};
                if (::fstat(fd, &st) != 0) {
                    return -errno;
                }

                if (S_ISLNK(st.st_mode)) {
                    if (++links > 40) {
                        return -ELOOP;
                    }

                    char target[4096];
                    ssize_t n = ::readlinkat(fd, "", target, sizeof(target));
                    if (n < 0) {
                        return -errno;
                    }

                    if (size_t(n) >= sizeof(target)) {
                        return -ENAMETOOLONG;
                    }

                    std::string t(target, size_t(n));
                    if (!t.empty() && t[0] == '/') {
                        stack.resize(1);
                    }

                    splitInto(t, todo, true);
                    continue;
                }

                if (!S_ISDIR(st.st_mode)) {
                    return -ENOTDIR;
                }

                stack.push_back(std::move(f));
            }

            out = std::move(stack.back());
            return SBOX_OK;
        }

    }

    /* Raw openat2. */
    int openat2(int dirfd, const char* path, uint64_t flags, uint64_t resolve) noexcept {
        struct open_how how;
        std::memset(&how, 0, sizeof(how));
        how.flags = flags;
        how.resolve = resolve;
        return int(::syscall(SYS_openat2, dirfd, path, &how, sizeof(how)));
    }

    /* The resolve flags used for in-root lookups. */
    uint64_t resolveInRoot() noexcept {
        return RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    }

    /* Opens a directory inside the root. */
    int32_t openDirInRoot(int rootFd, const std::string& rel, bool& noOpenat2, CFd& out) noexcept {
        if (rel.empty()) {
            return dupFd(rootFd, out);
        }

        if (!noOpenat2) {
            for (int32_t attempt = 0; attempt < 8; ++attempt) {
                int fd = openat2(rootFd, rel.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC, resolveInRoot());
                if (fd >= 0) {
                    out.reset(fd);
                    return SBOX_OK;
                }

                if (errno == EAGAIN || errno == EINTR) {
                    // --> RESOLVE_IN_ROOT refuses lookups racing with a rename; just retry.
                    continue;
                }

                if (errno == ENOSYS || errno == E2BIG) {
                    noOpenat2 = true;
                    break;
                }

                return -errno;
            }

            if (!noOpenat2) {
                return -EAGAIN;
            }
        }

        try {
            return walkInRoot(rootFd, rel, out);
        } catch (const std::bad_alloc&) {
            return -ENOMEM;
        }
    }

    /* Removes a tree without following symlinks. */
    int32_t removeTreeAt(int dirfd, const char* name) noexcept {
        if (::unlinkat(dirfd, name, 0) == 0 || errno == ENOENT) {
            return SBOX_OK;
        }

        if (errno != EISDIR && errno != EPERM) {
            return -errno;
        }

        int fd = ::openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        DIR* d = ::fdopendir(fd);
        if (!d) {
            int32_t err = -errno;
            ::close(fd);
            return err;
        }

        std::vector<std::string> names;
        try {
            while (struct dirent* ent = ::readdir(d)) {
                if (std::strcmp(ent->d_name, ".") && std::strcmp(ent->d_name, "..")) {
                    names.emplace_back(ent->d_name);
                }
            }
        } catch (const std::bad_alloc&) {
            ::closedir(d);
            return -ENOMEM;
        }

        int32_t rc = SBOX_OK;
        for (const std::string& n : names) {
            rc = removeTreeAt(::dirfd(d), n.c_str());
            if (rc < 0) {
                break;
            }
        }

        ::closedir(d);
        if (rc < 0) {
            return rc;
        }

        if (::unlinkat(dirfd, name, AT_REMOVEDIR) != 0 && errno != ENOENT) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Sets an xattr without following a final symlink. */
    int32_t setXattrAt(int dirfd, const char* name, const std::string& key, const std::string& value) noexcept {
        if (g_xattrAt.load() >= 0) {
            XattrArgs args{ uint64_t(uintptr_t(value.data())), uint32_t(value.size()), 0 };
            long r = ::syscall(SYS_setxattrat, dirfd, name, AT_SYMLINK_NOFOLLOW, key.c_str(), &args, sizeof(args));
            if (r == 0) {
                g_xattrAt.store(1);
                return SBOX_OK;
            }

            if (errno != ENOSYS) {
                return -errno;
            }

            g_xattrAt.store(-1);
        }

        try {
            std::string p = procPath(dirfd, name);
            if (::lsetxattr(p.c_str(), key.c_str(), value.data(), value.size(), 0) != 0) {
                return -errno;
            }
        } catch (const std::bad_alloc&) {
            return -ENOMEM;
        }

        return SBOX_OK;
    }

    /* Reads an xattr without following a final symlink. */
    int32_t getXattrAt(int dirfd, const char* name, const std::string& key, std::string& value) noexcept {
        try {
            value.resize(256);
            for (int32_t attempt = 0; attempt < 4; ++attempt) {
                ssize_t n;
                if (g_xattrAt.load() >= 0) {
                    XattrArgs args{ uint64_t(uintptr_t(value.data())), uint32_t(value.size()), 0 };
                    n = ::syscall(SYS_getxattrat, dirfd, name, AT_SYMLINK_NOFOLLOW, key.c_str(), &args, sizeof(args));
                    if (n < 0 && errno == ENOSYS) {
                        g_xattrAt.store(-1);
                        continue;
                    }
                } else {
                    std::string p = procPath(dirfd, name);
                    n = ::lgetxattr(p.c_str(), key.c_str(), value.data(), value.size());
                }

                if (n >= 0) {
                    value.resize(size_t(n));
                    return SBOX_OK;
                }

                if (errno != ERANGE) {
                    return -errno;
                }

                value.resize(65536);
            }
        } catch (const std::bad_alloc&) {
            return -ENOMEM;
        }

        return -ERANGE;
    }

    /* Lists xattr names without following a final symlink. */
    int32_t listXattrsAt(int dirfd, const char* name, std::vector<std::string>& names) noexcept {
        names.clear();
        try {
            std::vector<char> buf(1024);
            for (int32_t attempt = 0; attempt < 4; ++attempt) {
                ssize_t n;
                if (g_xattrAt.load() >= 0) {
                    n = ::syscall(SYS_listxattrat, dirfd, name, AT_SYMLINK_NOFOLLOW, buf.data(), buf.size());
                    if (n < 0 && errno == ENOSYS) {
                        g_xattrAt.store(-1);
                        continue;
                    }
                } else {
                    std::string p = procPath(dirfd, name);
                    n = ::llistxattr(p.c_str(), buf.data(), buf.size());
                }

                if (n >= 0) {
                    size_t pos = 0;
                    while (pos < size_t(n)) {
                        size_t len = ::strnlen(buf.data() + pos, size_t(n) - pos);
                        if (len) {
                            names.emplace_back(buf.data() + pos, len);
                        }

                        pos += len + 1;
                    }

                    return SBOX_OK;
                }

                if (errno == ENOTSUP) {
                    return SBOX_OK;
                }

                if (errno != ERANGE) {
                    return -errno;
                }

                buf.resize(buf.size() * 16);
            }
        } catch (const std::bad_alloc&) {
            return -ENOMEM;
        }

        return -ERANGE;
    }

    /* Splits "a/b/c" into "a/b" and "c". */
    void splitPath(const std::string& rel, std::string& parent, std::string& leaf) {
        size_t slash = rel.rfind('/');
        if (slash == std::string::npos) {
            parent.clear();
            leaf = rel;
        } else {
            parent = rel.substr(0, slash);
            leaf = rel.substr(slash + 1);
        }
    }

}
}
}
