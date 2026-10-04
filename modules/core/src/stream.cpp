#include <sbox/core/stream.hpp>
#include <sbox/core/eventloop.hpp>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {

    namespace {

        /*
         * write(2) that reports EPIPE instead of raising SIGPIPE: the signal is blocked in this
         * thread for the call and a SIGPIPE the write itself caused is consumed before the
         * mask is restored. A reader that closes early (a sandboxed program closing its stdin)
         * must not be able to kill a caller that did not ignore SIGPIPE.
         */
        ssize_t writeNoSigpipe(int fd, const void* data, size_t size) noexcept {
            sigset_t pipeSet, saved, pending;
            sigemptyset(&pipeSet);
            sigaddset(&pipeSet, SIGPIPE);
            ::pthread_sigmask(SIG_BLOCK, &pipeSet, &saved);

            // --> A SIGPIPE that was already pending is not ours to consume.
            sigemptyset(&pending);
            ::sigpending(&pending);
            bool wasPending = sigismember(&pending, SIGPIPE) == 1;

            ssize_t n = ::write(fd, data, size);
            int err = errno;
            if (n < 0 && err == EPIPE && !wasPending) {
                struct timespec zero{ 0, 0 };
                while (::sigtimedwait(&pipeSet, nullptr, &zero) < 0 && errno == EINTR) {
                }
            }

            ::pthread_sigmask(SIG_SETMASK, &saved, nullptr);
            errno = err;
            return n;
        }

    }

    /* Takes ownership of a descriptor. */
    CStream::CStream(CFd fd) noexcept : _fd(std::move(fd)) {
        if (_fd.isValid()) {
            struct stat st{};
            _fd.setNonBlocking(true);
            _socket = ::fstat(_fd.get(), &st) == 0 && S_ISSOCK(st.st_mode);
        }
    }

    /* Move-assigns, closing the held descriptor first. */
    CStream& CStream::operator=(CStream&& other) noexcept {
        if (this != &other) {
            close();
            _fd = std::move(other._fd);
            _socket = other._socket;
        }

        return *this;
    }

    /* Closes the descriptor. */
    CStream::~CStream() {
        close();
    }

    /* Gives up the descriptor. */
    CFd CStream::release() noexcept {
        if (CEventLoop* loop = CEventLoop::current(); loop && _fd.isValid()) {
            loop->cancelFd(_fd.get());
        }

        return CFd(_fd.release());
    }

    /* Closes the descriptor and wakes waiters. */
    void CStream::close() noexcept {
        if (!_fd.isValid()) {
            return;
        }

        if (CEventLoop* loop = CEventLoop::current()) {
            loop->cancelFd(_fd.get());
        }

        _fd.reset();
    }

    /* One non-blocking read. */
    SIoResult CStream::tryRecv(const SByteSpan& buffer) noexcept {
        if (!_fd.isValid()) {
            return SIoResult{ -EBADF, 0 };
        }

        while (true) {
            ssize_t n = ::read(_fd.get(), buffer.data, buffer.size);
            if (n >= 0) {
                return SIoResult{ SBOX_OK, size_t(n) };
            }

            if (errno != EINTR) {
                // --> A pty master reports EIO once the slave side is gone; that is its EOF.
                if (errno == EIO) {
                    return SIoResult{ SBOX_OK, 0 };
                }

                return SIoResult{ -errno, 0 };
            }
        }
    }

    /* One non-blocking write. */
    SIoResult CStream::trySend(const SReadOnlyByteSpan& buffer) noexcept {
        if (!_fd.isValid()) {
            return SIoResult{ -EBADF, 0 };
        }

        while (true) {
            ssize_t n = _socket
                ? ::send(_fd.get(), buffer.data, buffer.size, MSG_NOSIGNAL | MSG_DONTWAIT)
                : writeNoSigpipe(_fd.get(), buffer.data, buffer.size);

            if (n >= 0) {
                return SIoResult{ SBOX_OK, size_t(n) };
            }

            if (errno != EINTR) {
                return SIoResult{ -errno, 0 };
            }
        }
    }

    /* Waits for and reads available bytes. */
    TTask<SIoResult> CStream::recv(const SByteSpan& buffer, int64_t timeoutMs) {
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            SIoResult r = tryRecv(buffer);
            if (r.error != -EAGAIN) {
                co_return r;
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return SIoResult{ -ETIMEDOUT, 0 };
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, left);
            if (w < 0) {
                co_return SIoResult{ w, 0 };
            }
        }
    }

    /* Reads exactly the buffer size. */
    TTask<SIoResult> IStream::recvExact(const SByteSpan& buffer, int64_t timeoutMs) {
        size_t got = 0;
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (got < buffer.size) {
            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return SIoResult{ -ETIMEDOUT, got };
            }

            SIoResult r = co_await recv(buffer.slice(got), left);
            if (!r.ok()) {
                co_return SIoResult{ r.error, got };
            }

            if (r.bytes == 0) {
                co_return SIoResult{ -ENODATA, got };
            }

            got += r.bytes;
        }

        co_return SIoResult{ SBOX_OK, got };
    }

    /* Reads until EOF. */
    TTask<SIoResult> IStream::recvAll(std::vector<uint8_t>& out, size_t limit, int64_t timeoutMs) {
        size_t total = 0;
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            size_t base = out.size();
            out.resize(base + 16384);

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                out.resize(base);
                co_return SIoResult{ -ETIMEDOUT, total };
            }

            SIoResult r = co_await recv(SByteSpan(out.data() + base, 16384), left);
            out.resize(base + r.bytes);

            if (!r.ok()) {
                co_return SIoResult{ r.error, total };
            }

            if (r.bytes == 0) {
                co_return SIoResult{ SBOX_OK, total };
            }

            total += r.bytes;
            if (total > limit) {
                co_return SIoResult{ -EFBIG, total };
            }
        }
    }

    /* Writes the whole buffer. */
    TTask<SIoResult> CStream::send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs) {
        size_t sent = 0;
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (sent < buffer.size) {
            SIoResult r = trySend(buffer.slice(sent));
            if (r.ok()) {
                sent += r.bytes;
                continue;
            }

            if (r.error != -EAGAIN) {
                co_return SIoResult{ r.error, sent };
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return SIoResult{ -ETIMEDOUT, sent };
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_WRITE, left);
            if (w < 0) {
                co_return SIoResult{ w, sent };
            }
        }

        co_return SIoResult{ SBOX_OK, sent };
    }

    /* Creates a non-blocking pipe pair. */
    int32_t CPipe::create(CStream& readEnd, CStream& writeEnd) noexcept {
        int fds[2];
        if (::pipe2(fds, O_CLOEXEC | O_NONBLOCK) < 0) {
            return -errno;
        }

        readEnd = CStream(CFd(fds[0]));
        writeEnd = CStream(CFd(fds[1]));
        return SBOX_OK;
    }

    /* Creates a pipe with one wrapped end. */
    int32_t CPipe::createForChild(CStream& parentEnd, CFd& childEnd, bool parentReads) noexcept {
        int fds[2];
        if (::pipe2(fds, O_CLOEXEC) < 0) {
            return -errno;
        }

        if (parentReads) {
            parentEnd = CStream(CFd(fds[0]));
            childEnd.reset(fds[1]);
        }
        else {
            parentEnd = CStream(CFd(fds[1]));
            childEnd.reset(fds[0]);
        }

        return SBOX_OK;
    }

} // namespace sbox
