#include <sbox/core/file.hpp>
#include <sbox/core/fd.hpp>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {

    /* Reads a whole file. */
    int32_t CFile::readAll(const std::string& path, std::string& out, size_t limit) noexcept {
        CFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!fd.isValid()) {
            return -errno;
        }

        out.clear();
        char chunk[8192];

        while (true) {
            ssize_t n = ::read(fd.get(), chunk, sizeof(chunk));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            if (n == 0) {
                return SBOX_OK;
            }

            if (out.size() + size_t(n) > limit) {
                return -EFBIG;
            }

            out.append(chunk, size_t(n));
        }
    }

    /* Writes to an existing (control) file in one call. */
    int32_t CFile::writeSome(const std::string& path, std::string_view data, bool truncate) noexcept {
        CFd fd(::open(path.c_str(), O_WRONLY | O_CLOEXEC | (truncate ? O_TRUNC : 0)));
        if (!fd.isValid()) {
            return -errno;
        }

        while (true) {
            ssize_t n = ::write(fd.get(), data.data(), data.size());
            if (n >= 0) {
                return size_t(n) == data.size() ? SBOX_OK : -EIO;
            }

            if (errno != EINTR) {
                return -errno;
            }
        }
    }

    /* Atomically replaces a file. */
    int32_t CFile::writeAtomic(const std::string& path, std::string_view data, uint32_t mode) noexcept {
        std::string temp = path + ".tmp." + std::to_string(::getpid());

        CFd fd(::open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode));
        if (!fd.isValid()) {
            return -errno;
        }

        size_t done = 0;
        while (done < data.size()) {
            ssize_t n = ::write(fd.get(), data.data() + done, data.size() - done);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                int32_t err = -errno;
                ::unlink(temp.c_str());
                return err;
            }

            done += size_t(n);
        }

        if (::fsync(fd.get()) < 0 || ::rename(temp.c_str(), path.c_str()) < 0) {
            int32_t err = -errno;
            ::unlink(temp.c_str());
            return err;
        }

        return SBOX_OK;
    }

    /* Creates a directory and its parents. */
    int32_t CFile::makeDirs(const std::string& path, uint32_t mode) noexcept {
        if (path.empty()) {
            return -EINVAL;
        }

        std::string partial;
        partial.reserve(path.size());

        size_t pos = 0;
        while (pos <= path.size()) {
            size_t next = path.find('/', pos);
            if (next == std::string::npos) {
                next = path.size();
            }

            partial.assign(path, 0, next);
            pos = next + 1;

            if (partial.empty() || partial.back() == '/') {
                continue;
            }

            if (::mkdir(partial.c_str(), mode) < 0 && errno != EEXIST) {
                return -errno;
            }
        }

        struct stat st{};
        if (::stat(path.c_str(), &st) < 0) {
            return -errno;
        }

        return S_ISDIR(st.st_mode) ? SBOX_OK : -ENOTDIR;
    }

    namespace {

        /**
         * Removes everything below the directory `dirFd` (same device only), then nothing else.
         */
        int32_t removeContents(int dirFd, dev_t device) noexcept {
            int dupFd = ::fcntl(dirFd, F_DUPFD_CLOEXEC, 0);
            if (dupFd < 0) {
                return -errno;
            }

            DIR* dir = ::fdopendir(dupFd);
            if (!dir) {
                ::close(dupFd);
                return -errno;
            }

            int32_t result = SBOX_OK;
            while (dirent* entry = ::readdir(dir)) {
                if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
                    continue;
                }

                struct stat st{};
                if (::fstatat(dirFd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                    continue;
                }

                if (S_ISDIR(st.st_mode)) {
                    if (st.st_dev != device) {
                        // --> A mount point below the tree: never delete into another filesystem.
                        result = -EBUSY;
                        continue;
                    }

                    CFd child(::openat(dirFd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
                    if (child.isValid()) {
                        int32_t r = removeContents(child.get(), device);
                        if (r < 0) {
                            result = r;
                        }
                    }

                    if (::unlinkat(dirFd, entry->d_name, AT_REMOVEDIR) < 0 && result == SBOX_OK) {
                        result = -errno;
                    }
                }
                else if (::unlinkat(dirFd, entry->d_name, 0) < 0 && result == SBOX_OK) {
                    result = -errno;
                }
            }

            ::closedir(dir);
            return result;
        }

    }

    /* Removes a file or directory tree. */
    int32_t CFile::removeTree(const std::string& path) noexcept {
        struct stat st{};
        if (::lstat(path.c_str(), &st) < 0) {
            return errno == ENOENT ? SBOX_OK : -errno;
        }

        if (!S_ISDIR(st.st_mode)) {
            return ::unlink(path.c_str()) < 0 ? -errno : SBOX_OK;
        }

        CFd dir(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (!dir.isValid()) {
            return -errno;
        }

        int32_t r = removeContents(dir.get(), st.st_dev);
        if (r < 0) {
            return r;
        }

        return ::rmdir(path.c_str()) < 0 ? -errno : SBOX_OK;
    }

    /* Checks existence. */
    bool CFile::exists(const std::string& path) noexcept {
        struct stat st{};
        return ::lstat(path.c_str(), &st) == 0;
    }

    /* Joins two path components. */
    std::string CFile::join(std::string_view base, std::string_view leaf) {
        std::string out(base);

        while (!leaf.empty() && leaf.front() == '/') {
            leaf.remove_prefix(1);
        }

        if (out.empty()) {
            return "/" + std::string(leaf);
        }

        if (out.back() != '/') {
            out.push_back('/');
        }

        out.append(leaf);
        return out;
    }

    /* Splits text into lines. */
    std::vector<std::string_view> CFile::splitLines(std::string_view text) {
        std::vector<std::string_view> lines;

        while (!text.empty()) {
            size_t nl = text.find('\n');
            if (nl == std::string_view::npos) {
                lines.push_back(text);
                break;
            }

            lines.push_back(text.substr(0, nl));
            text.remove_prefix(nl + 1);
        }

        return lines;
    }

} // namespace sbox
