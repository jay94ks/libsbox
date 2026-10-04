#include <sbox/http/message.hpp>
#include <sbox/core/eventloop.hpp>
#include <algorithm>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace http {

    namespace {

        /**
         * Body reader over bytes held in memory.
         */
        class MemoryBody : public IBodyReader {
        private:
            std::string _bytes;
            size_t _pos = 0;
            bool _closed = false;
            CHeaders _trailers;

        public:
            explicit MemoryBody(std::string bytes) : _bytes(std::move(bytes)) {}

            TTask<SIoResult> recv(const SByteSpan& buffer, int64_t) override {
                if (_closed) {
                    co_return SIoResult{ -EBADF, 0 };
                }

                size_t n = std::min(buffer.size, _bytes.size() - _pos);
                if (n > 0) {
                    std::memcpy(buffer.data, _bytes.data() + _pos, n);
                    _pos += n;
                }

                co_return SIoResult{ SBOX_OK, n };
            }

            void close() noexcept override {
                _closed = true;
            }

            int64_t contentLength() const noexcept override {
                return int64_t(_bytes.size());
            }

            bool isComplete() const noexcept override {
                return _pos == _bytes.size();
            }

            const CHeaders& trailers() const noexcept override {
                return _trailers;
            }
        };

    }

    /* Returns the reason phrase of a status. */
    const char* ReasonPhrase(int32_t status) noexcept {
        switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 422: return "Unprocessable Content";
        case 426: return "Upgrade Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default: return "Unknown";
        }
    }

    /* Bodies cannot be written. */
    TTask<SIoResult> IBodyReader::send(const SReadOnlyByteSpan&, int64_t) {
        co_return SIoResult{ -ENOTSUP, 0 };
    }

    /* Reads the rest of the body as text. */
    TTask<int32_t> IBodyReader::readText(std::string& out, size_t limit, int64_t timeoutMs) {
        out.clear();
        int64_t declared = contentLength();
        if (declared > 0 && uint64_t(declared) > limit) {
            co_return -EFBIG;
        }

        if (declared > 0) {
            out.reserve(size_t(declared));
        }

        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        char chunk[16384];

        while (true) {
            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            SIoResult r = co_await recv(SByteSpan(reinterpret_cast<uint8_t*>(chunk), sizeof(chunk)), left);
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return SBOX_OK;
            }

            if (out.size() + r.bytes > limit) {
                co_return -EFBIG;
            }

            out.append(chunk, r.bytes);
        }
    }

    /* Reads the rest of the body as JSON. */
    TTask<int32_t> IBodyReader::readJson(CJson& out, size_t limit, int64_t timeoutMs) {
        std::string text;
        int32_t r = co_await readText(text, limit, timeoutMs);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return CJson::parse(text, out);
    }

    /* Reads and drops the rest of the body. */
    TTask<int32_t> IBodyReader::discard(size_t limit, int64_t timeoutMs) {
        uint8_t chunk[16384];
        size_t total = 0;
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;

        while (true) {
            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            SIoResult r = co_await recv(SByteSpan(chunk, sizeof(chunk)), left);
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return SBOX_OK;
            }

            total += r.bytes;
            if (total > limit) {
                co_return -EFBIG;
            }
        }
    }

    /* Returns an empty, complete body. */
    std::shared_ptr<IBodyReader> IBodyReader::createEmpty() {
        return std::make_shared<MemoryBody>(std::string());
    }

    /* Returns a body over memory. */
    std::shared_ptr<IBodyReader> IBodyReader::createFromBytes(std::string bytes) {
        return std::make_shared<MemoryBody>(std::move(bytes));
    }

    /* Parses and stores the URL. */
    int32_t SRequest::setUrl(std::string_view text) {
        return SUrl::parse(text, url);
    }

    /* Sets an in-memory body. */
    void SRequest::setBody(std::string_view data, std::string_view contentType) {
        body.assign(data.begin(), data.end());
        bodyStream.reset();
        bodyLength = -1;

        if (!contentType.empty()) {
            headers.set("Content-Type", contentType);
        }
    }

    /* Sets a JSON body. */
    void SRequest::setJson(const CJson& value, std::string_view contentType) {
        setBody(value.dump(), contentType);
    }

    /* Sets a streamed body. */
    void SRequest::setBodyStream(IStreamPtr stream, int64_t length) {
        body.clear();
        bodyStream = std::move(stream);
        bodyLength = length;
    }

    /* Reads the body as text. */
    TTask<int32_t> SResponse::readText(std::string& out, size_t limit) {
        if (!body) {
            out.clear();
            co_return SBOX_OK;
        }

        co_return co_await body->readText(out, limit);
    }

    /* Reads the body as JSON. */
    TTask<int32_t> SResponse::readJson(CJson& out, size_t limit) {
        if (!body) {
            co_return -ENODATA;
        }

        co_return co_await body->readJson(out, limit);
    }

}
}
