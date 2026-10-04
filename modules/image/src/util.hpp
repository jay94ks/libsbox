#ifndef __SRC_IMAGE_UTIL_HPP__
#define __SRC_IMAGE_UTIL_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>

namespace sbox {
namespace image {

    /**
     * Returns `bytes` random bytes as lower-case hex (getrandom).
     */
    std::string RandomHex(size_t bytes);

    /**
     * Reads and parses a JSON file.
     * @return SBOX_OK, -ENOENT, -EINVAL for invalid JSON, or another negated errno.
     */
    int32_t ReadJsonFile(const std::string& path, CJson& out, size_t limit = size_t(64) << 20);

    /**
     * Writes a JSON file atomically (temporary sibling + rename).
     */
    int32_t WriteJsonFile(const std::string& path, const CJson& json, bool pretty = false, uint32_t mode = 0644);

    /**
     * Returns true when `path` is an existing directory.
     */
    bool IsDirectory(const std::string& path);

    /**
     * Lists the names in a directory (without "." and "..").
     */
    int32_t ListDirectory(const std::string& path, std::vector<std::string>& out);

    /**
     * Opens `path` inside `rootfs` without leaving it (openat2 RESOLVE_IN_ROOT, or a lexical
     * walk on older kernels) and reads it.
     */
    int32_t ReadFileInRoot(const std::string& rootfs, const std::string& path, std::string& out, size_t limit = size_t(4) << 20);

    /**
     * Returns the sum of the apparent sizes of the regular files under a tree.
     */
    uint64_t TreeSize(const std::string& path);

    /**
     * Returns true when the process runs as root in the initial user namespace.
     */
    bool IsRealRoot();

}
}

#endif
