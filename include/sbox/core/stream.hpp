#ifndef __INCLUDE_SBOX_CORE_STREAM_HPP__
#define __INCLUDE_SBOX_CORE_STREAM_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/span.hpp>
#include <sbox/core/task.hpp>

namespace sbox {

    /**
     * Outcome of an I/O operation: how many bytes moved and why it stopped.
     * `error` is SBOX_OK or a negated errno; a recv that returns 0 bytes with SBOX_OK is EOF.
     */
    struct SIoResult {
        int32_t error;
        size_t bytes;

        /** Returns true when the operation did not fail. */
        constexpr bool ok() const noexcept { return error == SBOX_OK; }
    };

    /**
     * Asynchronous byte stream: what protocol code (HTTP, TLS, archive pipelines) reads from and
     * writes to, whether the bytes travel over a plain descriptor (CStream) or through another
     * layer (a TLS session).
     */
    class SBOX_API IStream {
    public:
        virtual ~IStream() = default;

        /**
         * Reads what is available, waiting until at least one byte arrives.
         * @param buffer Destination.
         * @param timeoutMs Maximum wait, negative for none.
         * @return bytes > 0 with SBOX_OK; bytes == 0 with SBOX_OK at EOF; or an error
         *         (-ETIMEDOUT, -ECANCELED when closed meanwhile, -EBADF when not open, ...).
         */
        virtual TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) = 0;

        /**
         * Writes the whole buffer, waiting for room as often as needed.
         * @return SBOX_OK with the full count, or the error that stopped it (bytes = written).
         */
        virtual TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) = 0;

        /**
         * Closes the stream, waking pending recv/send with -ECANCELED.
         */
        virtual void close() noexcept = 0;

        /**
         * Reads exactly `buffer.size` bytes.
         * @return SBOX_OK with the full count, -ENODATA when EOF came first (bytes tells how many
         *         arrived), or another error.
         */
        TTask<SIoResult> recvExact(const SByteSpan& buffer, int64_t timeoutMs = -1);

        /**
         * Reads until EOF, appending to `out`.
         * @param limit Maximum bytes to accept; more yields -EFBIG.
         */
        TTask<SIoResult> recvAll(std::vector<uint8_t>& out, size_t limit = size_t(-1), int64_t timeoutMs = -1);
    };

    using IStreamPtr = std::shared_ptr<IStream>;

    /**
     * Non-blocking byte stream over a descriptor (pipe end, stream socket, pty, tun device)
     * whose waits run on the calling thread's CEventLoop.
     *
     * The coroutine methods must be awaited on a thread whose CEventLoop is running.
     * One reader and one writer may be active at the same time.
     */
    class SBOX_API CStream : public IStream {
    protected:
        CFd _fd;
        bool _socket = false;   // --> Writes use send(MSG_NOSIGNAL) instead of write().

    public:
        CStream() noexcept = default;

        /**
         * Takes ownership of `fd` and switches it to non-blocking mode.
         */
        explicit CStream(CFd fd) noexcept;

        CStream(CStream&& other) noexcept = default;

        CStream& operator=(CStream&& other) noexcept;

        virtual ~CStream();

        /** Returns true when a descriptor is held. */
        inline bool isValid() const noexcept { return _fd.isValid(); }

        /** Returns the raw descriptor. */
        inline int nativeHandle() const noexcept { return _fd.get(); }

        /**
         * Gives up the descriptor without closing it (it stays non-blocking).
         */
        CFd release() noexcept;

        /**
         * Reads what is available (see IStream::recv).
         */
        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Writes the whole buffer (see IStream::send). Writing to a closed peer is -EPIPE
         * and never raises SIGPIPE (MSG_NOSIGNAL for sockets, a briefly blocked and consumed
         * signal for pipes).
         */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Closes the descriptor, waking pending recv/send with -ECANCELED.
         */
        void close() noexcept override;

        /**
         * Performs one non-blocking read; -EAGAIN when nothing is available.
         */
        virtual SIoResult tryRecv(const SByteSpan& buffer) noexcept;

        /**
         * Performs one non-blocking write; -EAGAIN when there is no room.
         */
        virtual SIoResult trySend(const SReadOnlyByteSpan& buffer) noexcept;
    };

    /**
     * Factory for anonymous pipes as CStream pairs.
     */
    class SBOX_API CPipe {
    public:
        /**
         * Creates a pipe (O_CLOEXEC, non-blocking).
         * @param readEnd Receives the read end.
         * @param writeEnd Receives the write end.
         * @return SBOX_OK or a negated errno.
         */
        static int32_t create(CStream& readEnd, CStream& writeEnd) noexcept;

        /**
         * Creates a raw pipe where only one end is wrapped. The other end stays blocking so it
         * can be handed to a child as a standard stream.
         * @param parentEnd Receives the wrapped (non-blocking) end.
         * @param childEnd Receives the raw end.
         * @param parentReads True when the parent reads (child writes), false for the reverse.
         */
        static int32_t createForChild(CStream& parentEnd, CFd& childEnd, bool parentReads) noexcept;
    };

} // namespace sbox

#endif
