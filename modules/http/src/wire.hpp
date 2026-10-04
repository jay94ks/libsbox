#ifndef __SRC_HTTP_WIRE_HPP__
#define __SRC_HTTP_WIRE_HPP__

#include <sbox/http/message.hpp>
#include <functional>

namespace sbox {
namespace http {
namespace wire {

    /**
     * Connection: an IStream with a read buffer for line-oriented parsing.
     */
    class Connection {
    public:
        IStreamPtr stream;
        std::vector<uint8_t> buffer;
        size_t head = 0;            // --> First unread byte in buffer.
        size_t tail = 0;            // --> One past the last buffered byte.
        uint64_t received = 0;      // --> Bytes ever read from the stream.
        int64_t idleSince = 0;      // --> When it entered the pool (monotonic ms).
        bool reused = false;        // --> Taken from the pool at least once.
        bool broken = false;        // --> Must not carry another message.
        std::string key;            // --> Pool key.

        explicit Connection(IStreamPtr s);

        ~Connection();

        Connection(const Connection&) = delete;

        Connection& operator=(const Connection&) = delete;

        /** Returns the number of buffered unread bytes. */
        inline size_t buffered() const noexcept { return tail - head; }

        /**
         * Reads one line (LF or CRLF terminated, terminator removed).
         * @param limit Maximum line length.
         * @param deadline Monotonic ms deadline, or -1.
         * @return SBOX_OK; -ENODATA on EOF before any byte; -ECONNRESET on EOF mid-line;
         *         -EMSGSIZE when longer than `limit`; -ETIMEDOUT; or a stream error.
         */
        TTask<int32_t> readLine(std::string& out, size_t limit, int64_t deadline);

        /**
         * Reads buffered bytes, or straight from the stream when nothing is buffered.
         */
        TTask<SIoResult> readSome(const SByteSpan& dst, int64_t timeoutMs);

        /**
         * Writes the whole buffer.
         */
        TTask<int32_t> sendAll(const SReadOnlyByteSpan& bytes, int64_t timeoutMs);

        /**
         * Closes the stream and marks the connection broken.
         */
        void close() noexcept;
    };

    using ConnectionPtr = std::shared_ptr<Connection>;

    /**
     * Message body framing.
     */
    enum Framing {
        FRAME_NONE,
        FRAME_LENGTH,
        FRAME_CHUNKED,
        FRAME_CLOSE,
    };

    /**
     * Splits one header line into a validated name and a trimmed value.
     * @return SBOX_OK or -EBADMSG.
     */
    int32_t SplitHeaderLine(std::string_view line, std::string_view& name, std::string_view& value);

    /**
     * Reads header lines up to the empty line.
     * @param budget Remaining head bytes; reduced by what was read. Exceeding it is -EMSGSIZE.
     */
    TTask<int32_t> ReadHeaderBlock(Connection& conn, CHeaders& out, size_t& budget, int64_t deadline, bool allowFold);

    /**
     * Parses Content-Length (all values must agree).
     * @return SBOX_OK, -ENOENT when absent, -EBADMSG when invalid.
     */
    int32_t ParseContentLength(const CHeaders& headers, uint64_t& out);

    /**
     * Decides the framing of a response body (RFC 9112 section 6.3).
     * @param forceClose Set when the connection cannot be reused after this message.
     * @return SBOX_OK or -EBADMSG.
     */
    int32_t ResponseFraming(std::string_view method, int32_t status, const CHeaders& headers, Framing& framing, uint64_t& length, bool& forceClose);

    /**
     * Decides the framing of a request body.
     * @return SBOX_OK, -EBADMSG (400) or -ENOTSUP (501 unsupported transfer coding).
     */
    int32_t RequestFraming(const CHeaders& headers, Framing& framing, uint64_t& length);

    /**
     * Body reader decoding a framed body off a Connection.
     */
    class Body : public IBodyReader {
    public:
        /**
         * Called once when the body ends or fails; `clean` tells whether the connection is
         * positioned at the next message.
         */
        std::function<void(ConnectionPtr, bool clean)> onDone;

    private:
        ConnectionPtr _conn;
        Framing _framing;
        uint64_t _remaining;            // --> Body bytes (LENGTH) or chunk bytes (CHUNKED) left.
        int64_t _declared;
        int64_t _idleTimeoutMs;
        uint64_t _maxBytes;             // --> 0 for no limit.
        uint64_t _total = 0;
        size_t _maxTrailerBytes;
        bool _done = false;
        int32_t _error = SBOX_OK;
        int32_t _chunkState = 0;        // --> 0 size line next, 1 data, 2 CRLF after data.
        CHeaders _trailers;

    public:
        Body(ConnectionPtr conn, Framing framing, uint64_t length, int64_t idleTimeoutMs, uint64_t maxBytes, size_t maxTrailerBytes);

        ~Body() override;

        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) override;

        void close() noexcept override;

        int64_t contentLength() const noexcept override;

        bool isComplete() const noexcept override;

        const CHeaders& trailers() const noexcept override;

        /**
         * Completes a body that has no bytes (FRAME_NONE) right away, handing the connection
         * back through onDone.
         */
        void settleEmpty() noexcept;

        /** Returns the error that stopped the body, or SBOX_OK. */
        inline int32_t error() const noexcept { return _error; }

    private:
        /**
         * Ends the body; hands the connection back through onDone.
         */
        void finish(bool clean) noexcept;

        /**
         * Fails the body with `error`.
         */
        SIoResult fail(int32_t error) noexcept;

        /**
         * Reads body bytes bounded by _remaining.
         */
        TTask<SIoResult> readBounded(const SByteSpan& buffer, int64_t timeoutMs);
    };

    /**
     * Sends a body from a stream.
     * @param length Exact length, or -1 for chunked transfer coding.
     * @return SBOX_OK, -ENODATA when the stream ended before `length`, or an I/O error.
     */
    TTask<int32_t> SendStreamBody(Connection& conn, IStream& source, int64_t length, int64_t timeoutMs);

    /**
     * Wraps a stream so `prefix` bytes are read first (bytes already buffered past a CONNECT
     * response or an upgrade).
     */
    IStreamPtr PrefixStream(IStreamPtr inner, std::vector<uint8_t> prefix);

}
}
}

#endif
