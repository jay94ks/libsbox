#ifndef __INCLUDE_SBOX_CORE_FD_HPP__
#define __INCLUDE_SBOX_CORE_FD_HPP__

#include <sbox/common.hpp>

namespace sbox {

    /**
     * Owning wrapper around a file descriptor: closes it on destruction, moves but never copies.
     */
    class SBOX_API CFd {
    private:
        int _fd;

    public:
        CFd() noexcept : _fd(-1) {}

        explicit CFd(int fd) noexcept : _fd(fd) {}

        CFd(CFd&& other) noexcept : _fd(other.release()) {}

        CFd(const CFd&) = delete;

        CFd& operator=(const CFd&) = delete;

        /**
         * Takes over another descriptor, closing the one held before.
         */
        CFd& operator=(CFd&& other) noexcept;

        ~CFd();

        /** Returns true when a descriptor is held. */
        inline bool isValid() const noexcept { return _fd >= 0; }

        /** Returns the raw descriptor (or -1) without giving up ownership. */
        inline int get() const noexcept { return _fd; }

        /** Gives up ownership; the caller closes the returned descriptor. */
        inline int release() noexcept { int fd = _fd; _fd = -1; return fd; }

        /**
         * Closes the held descriptor (if any) and takes ownership of `fd`.
         */
        void reset(int fd = -1) noexcept;

        /**
         * Duplicates the descriptor with O_CLOEXEC.
         * @return The duplicate, or an invalid CFd when dup fails (errno is left set).
         */
        CFd duplicate() const noexcept;

        /**
         * Switches O_NONBLOCK on or off.
         * @return SBOX_OK or a negated errno.
         */
        int32_t setNonBlocking(bool on) const noexcept;

        /**
         * Switches FD_CLOEXEC on or off.
         * @return SBOX_OK or a negated errno.
         */
        int32_t setCloseOnExec(bool on) const noexcept;
    };

} // namespace sbox

#endif
