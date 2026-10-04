#ifndef __SRC_VOL_UTIL_HPP__
#define __SRC_VOL_UTIL_HPP__

// Internal helpers of the vol module: store lock, clock, random names, small file utilities.

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vol/local.hpp>

namespace sbox {
namespace vol {

    /**
     * Exclusive flock on a file, waited for on the event loop (LOCK_NB retries with short
     * sleeps). Each lock opens its own file description, so two locks in one process exclude
     * each other too.
     */
    class StoreLock {
    private:
        CFd _fd;

    public:
        StoreLock() noexcept = default;

        StoreLock(StoreLock&&) noexcept = default;

        StoreLock& operator=(StoreLock&&) noexcept = default;

        /** Releases the lock. */
        ~StoreLock() = default;

        /**
         * Waits for the lock on `path` (created with mode 0600 when missing).
         * @return SBOX_OK, -ETIMEDOUT, or another negated errno.
         */
        TTask<int32_t> lock(std::string path, int64_t timeoutMs);

        /** Releases the lock early. */
        inline void unlock() noexcept { _fd.reset(); }
    };

    /**
     * Returns the current UTC time in RFC 3339 form ("2026-10-04T12:34:56Z").
     */
    std::string NowRfc3339();

    /**
     * Returns the kernel boot id (/proc/sys/kernel/random/boot_id), or an empty string.
     */
    std::string BootId();

    /**
     * Fills `out` with random bytes (getrandom).
     */
    int32_t RandomBytes(uint8_t* out, size_t size) noexcept;

    /**
     * Returns `size` random bytes as lowercase hex.
     */
    std::string RandomHex(size_t size);

    /**
     * Converts a JSON object of strings into a map (non-string values are serialized).
     */
    TStringMap MapFromJson(const CJson& json);

    /**
     * Converts a map into a JSON object.
     */
    CJson MapToJson(const TStringMap& map);

    /**
     * Reads and parses a JSON file.
     */
    int32_t ReadJsonFile(const std::string& path, CJson& out);

    /**
     * Returns strerror text for a negated errno.
     */
    std::string ErrorText(int32_t code);

    /**
     * Freezes the filesystem mounted at `path` (FIFREEZE).
     */
    int32_t FreezeFs(const std::string& path) noexcept;

    /**
     * Thaws the filesystem mounted at `path` (FITHAW).
     */
    int32_t ThawFs(const std::string& path) noexcept;

}
}

#endif
