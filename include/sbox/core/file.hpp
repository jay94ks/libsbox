#ifndef __INCLUDE_SBOX_CORE_FILE_HPP__
#define __INCLUDE_SBOX_CORE_FILE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {

    /**
     * Synchronous filesystem helpers. They block, which is fine for the small control files
     * libsbox touches (cgroup knobs, /proc entries, state files); bulk data goes through
     * CStream or the archive code.
     */
    class SBOX_API CFile {
    public:
        /**
         * Reads a whole file.
         * @param limit Maximum size accepted; a larger file yields -EFBIG.
         * @return SBOX_OK or a negated errno.
         */
        static int32_t readAll(const std::string& path, std::string& out, size_t limit = size_t(64) << 20) noexcept;

        /**
         * Writes `data` to an existing file in one write(2) (O_WRONLY, no truncation flags beyond
         * O_TRUNC when `truncate`). This is the form kernel control files (cgroup, /proc) expect.
         */
        static int32_t writeSome(const std::string& path, std::string_view data, bool truncate = false) noexcept;

        /**
         * Atomically replaces a file: writes a temporary sibling, fsyncs it and renames it over
         * `path`.
         */
        static int32_t writeAtomic(const std::string& path, std::string_view data, uint32_t mode = 0644) noexcept;

        /**
         * Creates a directory and its missing parents. Existing directories are not an error.
         */
        static int32_t makeDirs(const std::string& path, uint32_t mode = 0755) noexcept;

        /**
         * Removes a file or a directory tree without following symlinks and without crossing
         * into other mounts. A missing path is not an error.
         */
        static int32_t removeTree(const std::string& path) noexcept;

        /**
         * Returns true when `path` exists (lstat succeeds).
         */
        static bool exists(const std::string& path) noexcept;

        /**
         * Joins two path components with exactly one separator.
         */
        static std::string join(std::string_view base, std::string_view leaf);

        /**
         * Splits text into lines (without terminators); a trailing newline adds no empty line.
         */
        static std::vector<std::string_view> splitLines(std::string_view text);
    };

} // namespace sbox

#endif
