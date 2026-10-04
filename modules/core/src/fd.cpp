#include <sbox/core/fd.hpp>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace sbox {

    /* Takes over another descriptor. */
    CFd& CFd::operator=(CFd&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }

        return *this;
    }

    /* Closes the held descriptor. */
    CFd::~CFd() {
        reset();
    }

    /* Closes the held descriptor and takes `fd`. */
    void CFd::reset(int fd) noexcept {
        if (_fd >= 0 && _fd != fd) {
            // --> close() may report EINTR, but on Linux the descriptor is released regardless,
            // so retrying would risk closing a descriptor another thread has just been given.
            ::close(_fd);
        }

        _fd = fd;
    }

    /* Duplicates the descriptor with O_CLOEXEC. */
    CFd CFd::duplicate() const noexcept {
        if (_fd < 0) {
            errno = EBADF;
            return CFd();
        }

        return CFd(::fcntl(_fd, F_DUPFD_CLOEXEC, 0));
    }

    /* Switches O_NONBLOCK. */
    int32_t CFd::setNonBlocking(bool on) const noexcept {
        int flags = ::fcntl(_fd, F_GETFL);
        if (flags < 0) {
            return -errno;
        }

        flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        return ::fcntl(_fd, F_SETFL, flags) < 0 ? -errno : SBOX_OK;
    }

    /* Switches FD_CLOEXEC. */
    int32_t CFd::setCloseOnExec(bool on) const noexcept {
        int flags = ::fcntl(_fd, F_GETFD);
        if (flags < 0) {
            return -errno;
        }

        flags = on ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC);
        return ::fcntl(_fd, F_SETFD, flags) < 0 ? -errno : SBOX_OK;
    }

} // namespace sbox
