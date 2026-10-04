#ifndef __INCLUDE_SBOX_NET_LOCK_HPP__
#define __INCLUDE_SBOX_NET_LOCK_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>

namespace sbox {
namespace net {

    /**
     * Exclusive advisory lock on a file (flock), shared by every process that uses the same
     * state directory: concurrent CLI invocations (sbox-cni, sboxnet) and long-running daemons.
     *
     * Waiting never blocks the event loop: the lock is retried with LOCK_NB and short sleeps.
     * Two CFileLock objects in one process exclude each other too (each has its own open file
     * description). The lock is released on destruction.
     */
    class SBOX_API CFileLock {
    private:
        CFd _fd;

    public:
        CFileLock() noexcept = default;

        CFileLock(CFileLock&&) noexcept = default;

        CFileLock& operator=(CFileLock&&) noexcept = default;

        /** Releases the lock. */
        ~CFileLock();

        /** Returns true while the lock is held. */
        inline bool isLocked() const noexcept { return _fd.isValid(); }

        /**
         * Tries once to take the lock (creating the file with mode 0600 when missing).
         * @return SBOX_OK, -EWOULDBLOCK when another holder has it, or another error.
         */
        int32_t tryLock(const std::string& path) noexcept;

        /**
         * Waits for the lock.
         * @return SBOX_OK, -ETIMEDOUT, or another error.
         */
        TTask<int32_t> lock(std::string path, int64_t timeoutMs = 30000);

        /**
         * Releases the lock.
         */
        void unlock() noexcept;
    };

}
}

#endif
