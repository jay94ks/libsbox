#include "wire.hpp"
#include "lex.hpp"
#include <sbox/core/eventloop.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

namespace sbox {
namespace http {
namespace wire {

    namespace {

        constexpr size_t INITIAL_BUFFER = 16384;
        constexpr size_t CHUNK_SIZE = 65536;
        constexpr size_t CHUNK_LINE_LIMIT = 4096;

        /*
         * Returns the time left until `deadline` (-1 for none, 0 when passed).
         */
        int64_t timeLeft(int64_t deadline) noexcept {
            if (deadline < 0) {
                return -1;
            }

            int64_t left = deadline - CEventLoop::nowMs();
            return left > 0 ? left : 0;
        }

        /*
         * Maps line-reading errors inside a body to body errors.
         */
        int32_t bodyLineError(int32_t r) noexcept {
            if (r == -ENODATA) {
                return -ECONNRESET;
            }

            if (r == -EMSGSIZE) {
                return -EBADMSG;
            }

            return r;
        }

        /*
         * Splits the Transfer-Encoding list; true when it is exactly "chunked" (identity ignored).
         */
        bool onlyChunked(const CHeaders& headers, bool& endsChunked) {
            std::vector<std::string> codings = SplitHeaderList(headers.combined("Transfer-Encoding"));
            std::erase_if(codings, [](const std::string& c) { return EqualsNoCase(c, "identity"); });

            endsChunked = !codings.empty() && EqualsNoCase(codings.back(), "chunked");
            return codings.size() == 1 && endsChunked;
        }

        /**
         * Stream that yields buffered prefix bytes before reading the inner stream.
         */
        class Prefixed : public IStream {
        private:
            IStreamPtr _inner;
            std::vector<uint8_t> _prefix;
            size_t _pos = 0;

        public:
            Prefixed(IStreamPtr inner, std::vector<uint8_t> prefix)
                : _inner(std::move(inner)), _prefix(std::move(prefix)) {}

            TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs) override {
                if (_pos < _prefix.size()) {
                    size_t n = std::min(buffer.size, _prefix.size() - _pos);
                    std::memcpy(buffer.data, _prefix.data() + _pos, n);
                    _pos += n;
                    co_return SIoResult{ SBOX_OK, n };
                }

                co_return co_await _inner->recv(buffer, timeoutMs);
            }

            TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs) override {
                co_return co_await _inner->send(buffer, timeoutMs);
            }

            void close() noexcept override {
                _inner->close();
            }
        };

    }

    /* Wraps a stream. */
    Connection::Connection(IStreamPtr s) : stream(std::move(s)) {}

    /* Closes the stream. */
    Connection::~Connection() {
        close();
    }

    /* Reads one line. */
    TTask<int32_t> Connection::readLine(std::string& out, size_t limit, int64_t deadline) {
        size_t scanned = head;

        while (true) {
            uint8_t* begin = buffer.data();
            uint8_t* found = scanned < tail ? static_cast<uint8_t*>(std::memchr(begin + scanned, '\n', tail - scanned)) : nullptr;

            if (found) {
                size_t end = size_t(found - begin);
                size_t lineEnd = end;
                if (lineEnd > head && buffer[lineEnd - 1] == '\r') {
                    --lineEnd;
                }

                if (lineEnd - head > limit) {
                    co_return -EMSGSIZE;
                }

                out.assign(reinterpret_cast<const char*>(begin + head), lineEnd - head);
                head = end + 1;
                if (head == tail) {
                    head = tail = 0;
                }

                co_return SBOX_OK;
            }

            // --> +1 leaves room for the CR of a line that is exactly `limit` long.
            if (tail - head > limit + 1) {
                co_return -EMSGSIZE;
            }

            if (head > 0) {
                std::memmove(begin, begin + head, tail - head);
                tail -= head;
                head = 0;
            }

            scanned = tail;

            if (buffer.size() < INITIAL_BUFFER) {
                buffer.resize(INITIAL_BUFFER);
            } else if (tail == buffer.size()) {
                buffer.resize(buffer.size() * 2);
            }

            if (deadline >= 0 && timeLeft(deadline) == 0) {
                co_return -ETIMEDOUT;
            }

            SIoResult r = co_await stream->recv(SByteSpan(buffer.data() + tail, buffer.size() - tail), timeLeft(deadline));
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return tail == head ? -ENODATA : -ECONNRESET;
            }

            tail += r.bytes;
            received += r.bytes;
        }
    }

    /* Reads buffered or fresh bytes. */
    TTask<SIoResult> Connection::readSome(const SByteSpan& dst, int64_t timeoutMs) {
        if (head < tail) {
            size_t n = std::min(dst.size, tail - head);
            std::memcpy(dst.data, buffer.data() + head, n);
            head += n;
            if (head == tail) {
                head = tail = 0;
            }

            co_return SIoResult{ SBOX_OK, n };
        }

        // --> Nothing buffered: read straight into the caller's buffer (no extra copy for
        // large bodies).
        SIoResult r = co_await stream->recv(dst, timeoutMs);
        received += r.bytes;
        co_return r;
    }

    /* Writes everything. */
    TTask<int32_t> Connection::sendAll(const SReadOnlyByteSpan& bytes, int64_t timeoutMs) {
        SIoResult r = co_await stream->send(bytes, timeoutMs);
        co_return r.error;
    }

    /* Closes the stream. */
    void Connection::close() noexcept {
        broken = true;
        if (stream) {
            stream->close();
        }
    }

    /* Splits a header line. */
    int32_t SplitHeaderLine(std::string_view line, std::string_view& name, std::string_view& value) {
        size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            return -EBADMSG;
        }

        name = line.substr(0, colon);
        if (!IsToken(name)) {
            // --> Also rejects whitespace between the name and the colon (RFC 9112 5.1).
            return -EBADMSG;
        }

        value = lex::Trim(line.substr(colon + 1));
        for (char c : value) {
            unsigned char u = (unsigned char) c;
            if ((u < 0x20 && c != '\t') || u == 0x7f) {
                return -EBADMSG;
            }
        }

        return SBOX_OK;
    }

    /* Reads the header block. */
    TTask<int32_t> ReadHeaderBlock(Connection& conn, CHeaders& out, size_t& budget, int64_t deadline, bool allowFold) {
        std::string line;
        std::string pendingName, pendingValue;
        bool pending = false;

        while (true) {
            int32_t r = co_await conn.readLine(line, budget, deadline);
            if (r != SBOX_OK) {
                co_return r;
            }

            size_t used = line.size() + 2;
            if (used > budget) {
                co_return -EMSGSIZE;
            }

            budget -= used;

            if (line.empty()) {
                if (pending) {
                    out.add(pendingName, pendingValue);
                }

                co_return SBOX_OK;
            }

            if (lex::IsWs(line[0])) {
                // --> obs-fold: a client replaces it with a space; a server rejects it.
                if (!allowFold || !pending) {
                    co_return -EBADMSG;
                }

                std::string_view more = lex::Trim(line);
                for (char c : more) {
                    unsigned char u = (unsigned char) c;
                    if ((u < 0x20 && c != '\t') || u == 0x7f) {
                        co_return -EBADMSG;
                    }
                }

                if (!more.empty()) {
                    pendingValue.push_back(' ');
                    pendingValue += more;
                }

                continue;
            }

            std::string_view name, value;
            if (SplitHeaderLine(line, name, value) != SBOX_OK) {
                co_return -EBADMSG;
            }

            if (pending) {
                out.add(pendingName, pendingValue);
            }

            pendingName = std::string(name);
            pendingValue = std::string(value);
            pending = true;
        }
    }

    /* Parses Content-Length. */
    int32_t ParseContentLength(const CHeaders& headers, uint64_t& out) {
        bool seen = false;
        uint64_t value = 0;

        for (const CHeaders::SField& f : headers) {
            if (!EqualsNoCase(f.name, "Content-Length")) {
                continue;
            }

            for (const std::string& item : SplitHeaderList(f.value)) {
                if (item.empty() || item.size() > 18) {
                    return -EBADMSG;
                }

                uint64_t v = 0;
                for (char c : item) {
                    if (c < '0' || c > '9') {
                        return -EBADMSG;
                    }

                    v = v * 10 + uint64_t(c - '0');
                }

                if (seen && v != value) {
                    return -EBADMSG;
                }

                seen = true;
                value = v;
            }

            if (!seen) {
                return -EBADMSG;
            }
        }

        if (!seen) {
            return -ENOENT;
        }

        out = value;
        return SBOX_OK;
    }

    /* Decides response framing. */
    int32_t ResponseFraming(std::string_view method, int32_t status, const CHeaders& headers, Framing& framing, uint64_t& length, bool& forceClose) {
        forceClose = false;
        length = 0;

        if (method == "HEAD" || (status >= 100 && status < 200) || status == 204 || status == 304) {
            framing = FRAME_NONE;
            return SBOX_OK;
        }

        if (headers.has("Transfer-Encoding")) {
            bool endsChunked = false;
            bool only = onlyChunked(headers, endsChunked);

            if (!endsChunked) {
                // --> A body whose transfer coding is not chunked runs until the close; we do
                // not undo other codings, so refuse rather than hand out coded bytes.
                std::vector<std::string> codings = SplitHeaderList(headers.combined("Transfer-Encoding"));
                std::erase_if(codings, [](const std::string& c) { return EqualsNoCase(c, "identity"); });
                if (!codings.empty()) {
                    return -ENOTSUP;
                }

                framing = FRAME_CLOSE;
                forceClose = true;
                return SBOX_OK;
            }

            if (!only) {
                return -ENOTSUP;
            }

            framing = FRAME_CHUNKED;
            // --> Both framings present smells of smuggling; never reuse such a connection.
            forceClose = headers.has("Content-Length");
            return SBOX_OK;
        }

        int32_t r = ParseContentLength(headers, length);
        if (r == -ENOENT) {
            framing = FRAME_CLOSE;
            forceClose = true;
            return SBOX_OK;
        }

        if (r != SBOX_OK) {
            return r;
        }

        framing = length == 0 ? FRAME_NONE : FRAME_LENGTH;
        return SBOX_OK;
    }

    /* Decides request framing. */
    int32_t RequestFraming(const CHeaders& headers, Framing& framing, uint64_t& length) {
        length = 0;

        if (headers.has("Transfer-Encoding")) {
            if (headers.has("Content-Length")) {
                return -EBADMSG;
            }

            bool endsChunked = false;
            if (!onlyChunked(headers, endsChunked)) {
                return endsChunked ? -ENOTSUP : (headers.combined("Transfer-Encoding").empty() ? -EBADMSG : -ENOTSUP);
            }

            framing = FRAME_CHUNKED;
            return SBOX_OK;
        }

        int32_t r = ParseContentLength(headers, length);
        if (r == -ENOENT) {
            framing = FRAME_NONE;
            return SBOX_OK;
        }

        if (r != SBOX_OK) {
            return r;
        }

        framing = length == 0 ? FRAME_NONE : FRAME_LENGTH;
        return SBOX_OK;
    }

    /* Creates a body reader. */
    Body::Body(ConnectionPtr conn, Framing framing, uint64_t length, int64_t idleTimeoutMs, uint64_t maxBytes, size_t maxTrailerBytes)
        : _conn(std::move(conn)), _framing(framing), _remaining(length),
          _declared(framing == FRAME_LENGTH ? int64_t(length) : (framing == FRAME_NONE ? 0 : -1)),
          _idleTimeoutMs(idleTimeoutMs), _maxBytes(maxBytes), _maxTrailerBytes(maxTrailerBytes) {}

    /* Drops an unfinished body's connection. */
    Body::~Body() {
        if (!_done && _conn) {
            _conn->broken = true;
            ConnectionPtr c = std::move(_conn);
            if (onDone) {
                onDone(std::move(c), false);
            }
        }
    }

    /* Ends the body. */
    void Body::finish(bool clean) noexcept {
        _done = true;
        ConnectionPtr c = std::move(_conn);

        if (c && !clean) {
            c->broken = true;
        }

        if (onDone) {
            auto cb = std::move(onDone);
            onDone = nullptr;
            cb(std::move(c), clean);
        }
    }

    /* Completes an empty body. */
    void Body::settleEmpty() noexcept {
        if (_framing == FRAME_NONE && !_done) {
            finish(true);
        }
    }

    /* Fails the body. */
    SIoResult Body::fail(int32_t error) noexcept {
        _error = error;
        if (!_done) {
            finish(false);
        }

        return SIoResult{ error, 0 };
    }

    /* Reads bytes bounded by the remaining count. */
    TTask<SIoResult> Body::readBounded(const SByteSpan& buffer, int64_t timeoutMs) {
        size_t n = size_t(std::min<uint64_t>(buffer.size, _remaining));
        SIoResult r = co_await _conn->readSome(SByteSpan(buffer.data, n), timeoutMs);

        if (!r.ok()) {
            co_return fail(r.error);
        }

        if (r.bytes == 0) {
            co_return fail(-ECONNRESET);
        }

        _remaining -= r.bytes;
        _total += r.bytes;

        if (_maxBytes != 0 && _total > _maxBytes) {
            co_return fail(-EFBIG);
        }

        co_return r;
    }

    /* Reads decoded body bytes. */
    TTask<SIoResult> Body::recv(const SByteSpan& buffer, int64_t timeoutMs) {
        if (_error != SBOX_OK) {
            co_return SIoResult{ _error, 0 };
        }

        if (_done) {
            co_return SIoResult{ SBOX_OK, 0 };
        }

        if (buffer.size == 0) {
            co_return SIoResult{ SBOX_OK, 0 };
        }

        int64_t timeout = _idleTimeoutMs;
        if (timeoutMs >= 0 && (timeout < 0 || timeoutMs < timeout)) {
            timeout = timeoutMs;
        }

        switch (_framing) {
        case FRAME_NONE:
            finish(true);
            co_return SIoResult{ SBOX_OK, 0 };

        case FRAME_LENGTH: {
            if (_remaining == 0) {
                finish(true);
                co_return SIoResult{ SBOX_OK, 0 };
            }

            SIoResult r = co_await readBounded(buffer, timeout);
            if (r.ok() && _remaining == 0) {
                // --> Hand the connection back as soon as the last byte arrived, not only when
                // the caller comes back for the EOF.
                finish(true);
            }

            co_return r;
        }

        case FRAME_CLOSE: {
            SIoResult r = co_await _conn->readSome(buffer, timeout);
            if (!r.ok()) {
                co_return fail(r.error);
            }

            if (r.bytes == 0) {
                finish(false);
                co_return r;
            }

            _total += r.bytes;
            if (_maxBytes != 0 && _total > _maxBytes) {
                co_return fail(-EFBIG);
            }

            co_return r;
        }

        case FRAME_CHUNKED:
            break;
        }

        while (true) {
            int64_t deadline = timeout < 0 ? -1 : CEventLoop::nowMs() + timeout;

            if (_chunkState == 1) {
                SIoResult r = co_await readBounded(buffer, timeout);
                if (r.ok() && _remaining == 0) {
                    _chunkState = 2;
                }

                co_return r;
            }

            std::string line;

            if (_chunkState == 2) {
                int32_t lr = co_await _conn->readLine(line, 2, deadline);
                if (lr != SBOX_OK) {
                    co_return fail(bodyLineError(lr));
                }

                if (!line.empty()) {
                    co_return fail(-EBADMSG);
                }

                _chunkState = 0;
                continue;
            }

            int32_t lr = co_await _conn->readLine(line, CHUNK_LINE_LIMIT, deadline);
            if (lr != SBOX_OK) {
                co_return fail(bodyLineError(lr));
            }

            // --> chunk-size [ BWS ";" chunk-ext ]: at most 15 hex digits so it cannot overflow.
            uint64_t size = 0;
            size_t i = 0;
            while (i < line.size()) {
                char c = line[i];
                int32_t v = (c >= '0' && c <= '9') ? c - '0'
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (v < 0) {
                    break;
                }

                if (i >= 15) {
                    co_return fail(-EBADMSG);
                }

                size = (size << 4) | uint64_t(v);
                ++i;
            }

            if (i == 0) {
                co_return fail(-EBADMSG);
            }

            std::string_view rest = lex::Trim(std::string_view(line).substr(i));
            if (!rest.empty() && rest[0] != ';') {
                co_return fail(-EBADMSG);
            }

            if (size == 0) {
                size_t budget = _maxTrailerBytes;
                int32_t tr = co_await ReadHeaderBlock(*_conn, _trailers, budget, deadline, false);
                if (tr != SBOX_OK) {
                    co_return fail(bodyLineError(tr));
                }

                finish(true);
                co_return SIoResult{ SBOX_OK, 0 };
            }

            if (_maxBytes != 0 && _total + size > _maxBytes) {
                co_return fail(-EFBIG);
            }

            _remaining = size;
            _chunkState = 1;
        }
    }

    /* Abandons the body. */
    void Body::close() noexcept {
        if (_done) {
            return;
        }

        // --> Wakes a pending recv; the connection cannot carry another message anyway.
        if (_conn) {
            _conn->close();
        }

        fail(-ECANCELED);
    }

    /* Returns the declared length. */
    int64_t Body::contentLength() const noexcept {
        return _declared;
    }

    /* Returns true once the body ended. */
    bool Body::isComplete() const noexcept {
        return _done && _error == SBOX_OK;
    }

    /* Returns the trailers. */
    const CHeaders& Body::trailers() const noexcept {
        return _trailers;
    }

    /* Sends a body from a stream. */
    TTask<int32_t> SendStreamBody(Connection& conn, IStream& source, int64_t length, int64_t timeoutMs) {
        constexpr size_t HEAD_ROOM = 18;     // --> Up to 16 hex digits and CRLF.
        std::vector<uint8_t> frame(HEAD_ROOM + CHUNK_SIZE + 2);

        if (length >= 0) {
            uint64_t left = uint64_t(length);

            while (left > 0) {
                size_t want = size_t(std::min<uint64_t>(CHUNK_SIZE, left));
                SIoResult r = co_await source.recv(SByteSpan(frame.data(), want), timeoutMs);
                if (!r.ok()) {
                    co_return r.error;
                }

                if (r.bytes == 0) {
                    co_return -ENODATA;
                }

                int32_t s = co_await conn.sendAll(SReadOnlyByteSpan(frame.data(), r.bytes), timeoutMs);
                if (s != SBOX_OK) {
                    co_return s;
                }

                left -= r.bytes;
            }

            co_return SBOX_OK;
        }

        while (true) {
            SIoResult r = co_await source.recv(SByteSpan(frame.data() + HEAD_ROOM, CHUNK_SIZE), timeoutMs);
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                static const char LAST[] = "0\r\n\r\n";
                co_return co_await conn.sendAll(BytesOf(std::string_view(LAST, 5)), timeoutMs);
            }

            char hex[20];
            int32_t hexLen = std::snprintf(hex, sizeof(hex), "%zx\r\n", r.bytes);
            size_t start = HEAD_ROOM - size_t(hexLen);
            std::memcpy(frame.data() + start, hex, size_t(hexLen));
            frame[HEAD_ROOM + r.bytes] = '\r';
            frame[HEAD_ROOM + r.bytes + 1] = '\n';

            int32_t s = co_await conn.sendAll(SReadOnlyByteSpan(frame.data() + start, size_t(hexLen) + r.bytes + 2), timeoutMs);
            if (s != SBOX_OK) {
                co_return s;
            }
        }
    }

    /* Wraps a stream with a prefix. */
    IStreamPtr PrefixStream(IStreamPtr inner, std::vector<uint8_t> prefix) {
        if (prefix.empty()) {
            return inner;
        }

        return std::make_shared<Prefixed>(std::move(inner), std::move(prefix));
    }

}
}
}
