#include "util.hpp"
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <ctime>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#endif

#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif

#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

namespace sbox {
namespace image {

    namespace {

        /* Layout of struct open_how (kept local so old headers work). */
        struct OpenHow {
            uint64_t flags;
            uint64_t mode;
            uint64_t resolve;
        };

        /* Splits a path into non-empty components. */
        std::vector<std::string> components(std::string_view path) {
            std::vector<std::string> out;
            size_t start = 0;
            while (start <= path.size()) {
                size_t slash = path.find('/', start);
                std::string_view c = path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
                if (!c.empty() && c != ".") {
                    out.emplace_back(c);
                }

                if (slash == std::string_view::npos) {
                    break;
                }

                start = slash + 1;
            }

            return out;
        }

        /*
         * Opens `path` under `rootFd` resolving symlinks with the root as "/" (a fallback for
         * kernels without openat2).
         */
        int openInRootWalk(int rootFd, const std::string& path) {
            std::vector<std::string> pending = components(path);
            std::reverse(pending.begin(), pending.end());
            std::vector<CFd> stack;
            stack.emplace_back(::fcntl(rootFd, F_DUPFD_CLOEXEC, 0));
            int32_t links = 0;
            while (!pending.empty()) {
                std::string c = pending.back();
                pending.pop_back();
                if (c == "..") {
                    if (stack.size() > 1) {
                        stack.pop_back();
                    }

                    continue;
                }

                int cur = stack.back().get();
                struct stat st{};
                if (::fstatat(cur, c.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                    return -errno;
                }

                if (S_ISLNK(st.st_mode)) {
                    if (++links > 40) {
                        return -ELOOP;
                    }

                    char buf[4096];
                    ssize_t n = ::readlinkat(cur, c.c_str(), buf, sizeof(buf) - 1);
                    if (n < 0) {
                        return -errno;
                    }

                    std::string target(buf, size_t(n));
                    if (!target.empty() && target[0] == '/') {
                        stack.resize(1);
                    }

                    std::vector<std::string> more = components(target);
                    for (auto it = more.rbegin(); it != more.rend(); ++it) {
                        pending.push_back(*it);
                    }

                    continue;
                }

                int fd = ::openat(cur, c.c_str(), (pending.empty() ? O_RDONLY : O_PATH | O_DIRECTORY) | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                    return -errno;
                }

                stack.emplace_back(fd);
            }

            return stack.back().release();
        }

    }

    /* Returns random hex. */
    std::string RandomHex(size_t bytes) {
        std::vector<uint8_t> raw(bytes);
        size_t got = 0;
        while (got < bytes) {
            ssize_t n = ::getrandom(raw.data() + got, bytes - got, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                // --> getrandom cannot fail once the pool is initialized; keep names unique anyway.
                for (size_t i = got; i < bytes; ++i) {
                    raw[i] = uint8_t((uint64_t(::getpid()) * 131 + i * 7 + uint64_t(::time(nullptr))) & 0xff);
                }

                break;
            }

            got += size_t(n);
        }

        static const char DIGITS[] = "0123456789abcdef";
        std::string out(bytes * 2, '0');
        for (size_t i = 0; i < bytes; ++i) {
            out[i * 2] = DIGITS[raw[i] >> 4];
            out[i * 2 + 1] = DIGITS[raw[i] & 15];
        }

        return out;
    }

    /* Reads and parses a JSON file. */
    int32_t ReadJsonFile(const std::string& path, CJson& out, size_t limit) {
        std::string text;
        int32_t r = CFile::readAll(path, text, limit);
        if (r != SBOX_OK) {
            return r;
        }

        return CJson::parse(text, out);
    }

    /* Writes a JSON file atomically. */
    int32_t WriteJsonFile(const std::string& path, const CJson& json, bool pretty, uint32_t mode) {
        std::string text = json.dump(pretty);
        if (pretty) {
            text.push_back('\n');
        }

        return CFile::writeAtomic(path, text, mode);
    }

    /* Returns true for an existing directory. */
    bool IsDirectory(const std::string& path) {
        struct stat st{};
        return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    }

    /* Lists a directory. */
    int32_t ListDirectory(const std::string& path, std::vector<std::string>& out) {
        out.clear();
        DIR* d = ::opendir(path.c_str());
        if (!d) {
            return -errno;
        }

        while (struct dirent* e = ::readdir(d)) {
            if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0) {
                continue;
            }

            out.emplace_back(e->d_name);
        }

        ::closedir(d);
        return SBOX_OK;
    }

    /* Reads a file inside a root without leaving it. */
    int32_t ReadFileInRoot(const std::string& rootfs, const std::string& path, std::string& out, size_t limit) {
        out.clear();
        CFd root(::open(rootfs.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
        if (!root.isValid()) {
            return -errno;
        }

        std::string rel = path;
        while (!rel.empty() && rel.front() == '/') {
            rel.erase(rel.begin());
        }

        OpenHow how{};
        how.flags = O_RDONLY | O_CLOEXEC;
        how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
        int fd = int(::syscall(SYS_openat2, root.get(), rel.c_str(), &how, sizeof(how)));
        if (fd < 0 && (errno == ENOSYS || errno == EPERM)) {
            fd = openInRootWalk(root.get(), rel);
            if (fd < 0) {
                return fd;
            }
        } else if (fd < 0) {
            return -errno;
        }

        CFd file(fd);
        struct stat st{};
        if (::fstat(file.get(), &st) != 0) {
            return -errno;
        }

        if (!S_ISREG(st.st_mode)) {
            return -EINVAL;
        }

        char buf[65536];
        while (true) {
            ssize_t n = ::read(file.get(), buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            if (n == 0) {
                break;
            }

            if (out.size() + size_t(n) > limit) {
                return -EFBIG;
            }

            out.append(buf, size_t(n));
        }

        return SBOX_OK;
    }

    /* Returns the size of the regular files in a tree. */
    uint64_t TreeSize(const std::string& path) {
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0) {
            return 0;
        }

        if (S_ISREG(st.st_mode)) {
            return uint64_t(st.st_size);
        }

        if (!S_ISDIR(st.st_mode)) {
            return 0;
        }

        std::vector<std::string> names;
        if (ListDirectory(path, names) != SBOX_OK) {
            return 0;
        }

        uint64_t total = 0;
        for (const std::string& n : names) {
            total += TreeSize(CFile::join(path, n));
        }

        return total;
    }

    /* Returns true for root in the initial user namespace. */
    bool IsRealRoot() {
        if (::geteuid() != 0) {
            return false;
        }

        std::string map;
        if (CFile::readAll("/proc/self/uid_map", map) != SBOX_OK) {
            return true;
        }

        // --> The initial namespace maps the whole range: "0 0 4294967295".
        return map.find("4294967295") != std::string::npos;
    }

}
}
