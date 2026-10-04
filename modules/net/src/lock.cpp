#include <sbox/net/lock.hpp>
#include <sbox/core/eventloop.hpp>
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace sbox {
namespace net {

    /* Releases the lock. */
    CFileLock::~CFileLock() {
        unlock();
    }

    /* Tries to take the lock once. */
    int32_t CFileLock::tryLock(const std::string& path) noexcept {
        unlock();

        CFd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600));
        if (!fd.isValid()) {
            return -errno;
        }

        while (::flock(fd.get(), LOCK_EX | LOCK_NB) < 0) {
            if (errno == EINTR) {
                continue;
            }

            return errno == EWOULDBLOCK ? -EWOULDBLOCK : -errno;
        }

        _fd = std::move(fd);
        return SBOX_OK;
    }

    /* Waits for the lock. */
    TTask<int32_t> CFileLock::lock(std::string path, int64_t timeoutMs) {
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        int64_t delay = 1;

        while (true) {
            int32_t r = tryLock(path);
            if (r != -EWOULDBLOCK) {
                co_return r;
            }

            if (deadline >= 0 && CEventLoop::nowMs() >= deadline) {
                co_return -ETIMEDOUT;
            }

            // --> Lock holders keep it for milliseconds; back off gently up to 20 ms.
            co_await CEventLoop::current()->sleepFor(delay);
            delay = delay < 20 ? delay * 2 : 20;
        }
    }

    /* Releases the lock. */
    void CFileLock::unlock() noexcept {
        if (_fd.isValid()) {
            ::flock(_fd.get(), LOCK_UN);
            _fd.reset();
        }
    }

}
}
