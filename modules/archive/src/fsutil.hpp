#ifndef __SRC_ARCHIVE_FSUTIL_HPP__
#define __SRC_ARCHIVE_FSUTIL_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>

namespace sbox {
namespace archive {
namespace fsutil {

    /* openat2(2) with the given flags and RESOLVE_* bits; -1/errno on failure (ENOSYS on old kernels). */
    int openat2(int dirfd, const char* path, uint64_t flags, uint64_t resolve) noexcept;

    /* RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS. */
    uint64_t resolveInRoot() noexcept;

    /*
     * Opens directory `rel` (cleaned, relative, "" = root) inside `rootFd` as O_PATH, resolving
     * symlinks as if rootFd were "/". Uses openat2 unless `noOpenat2` (or the kernel lacks it,
     * which flips `noOpenat2` to true), else an O_NOFOLLOW component walk.
     */
    int32_t openDirInRoot(int rootFd, const std::string& rel, bool& noOpenat2, CFd& out) noexcept;

    /* Removes `name` in `dirfd` and everything below it without following symlinks. ENOENT is OK. */
    int32_t removeTreeAt(int dirfd, const char* name) noexcept;

    /* Sets an xattr on `name` in `dirfd` without following a final symlink. */
    int32_t setXattrAt(int dirfd, const char* name, const std::string& key, const std::string& value) noexcept;

    /* Reads an xattr of `name` in `dirfd` (no final symlink follow); -ENODATA when absent. */
    int32_t getXattrAt(int dirfd, const char* name, const std::string& key, std::string& value) noexcept;

    /* Lists xattr names of `name` in `dirfd` (no final symlink follow). */
    int32_t listXattrsAt(int dirfd, const char* name, std::vector<std::string>& names) noexcept;

    /* Splits a cleaned relative path into parent and last component. */
    void splitPath(const std::string& rel, std::string& parent, std::string& leaf);

}
}
}

#endif
