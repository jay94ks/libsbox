#ifndef __INCLUDE_SBOX_HTTP_MESSAGE_HPP__
#define __INCLUDE_SBOX_HTTP_MESSAGE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/task.hpp>
#include <sbox/http/headers.hpp>
#include <sbox/http/url.hpp>

namespace sbox {
namespace http {

    /**
     * Returns the standard reason phrase of a status code ("Not Found"), or "Unknown".
     */
    SBOX_API const char* ReasonPhrase(int32_t status) noexcept;

    /**
     * Body of a received message (a client's response or a server's request), read as a stream.
     *
     * The reader decodes the message framing (Content-Length, chunked transfer coding with
     * trailers, or read-until-close) and hands out only body bytes, so a multi-gigabyte blob can
     * be copied to disk chunk by chunk without being buffered. recv() returns 0 bytes with
     * SBOX_OK once the body ended; a connection that closed early yields -ECONNRESET and a
     * framing error -EBADMSG. On a client, the connection goes back to the keep-alive pool as
     * soon as the body has been read to its end; closing an unfinished body drops the connection.
     * send() is not supported.
     */
    class SBOX_API IBodyReader : public IStream {
    public:
        /**
         * Returns the declared Content-Length, or -1 when the length is not known in advance
         * (chunked or read-until-close).
         */
        virtual int64_t contentLength() const noexcept = 0;

        /**
         * Returns true once the whole body has been read.
         */
        virtual bool isComplete() const noexcept = 0;

        /**
         * Returns the trailer fields of a chunked body (valid once isComplete()).
         */
        virtual const CHeaders& trailers() const noexcept = 0;

        /**
         * Not supported on a body: returns -ENOTSUP.
         */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Reads the rest of the body into `out` (replacing its contents).
         * @param limit Maximum body size; a larger body yields -EFBIG.
         * @return SBOX_OK or a negated errno.
         */
        TTask<int32_t> readText(std::string& out, size_t limit = size_t(64) << 20, int64_t timeoutMs = -1);

        /**
         * Reads the rest of the body and parses it as JSON.
         * @return SBOX_OK, -EINVAL for invalid JSON, or the read error.
         */
        TTask<int32_t> readJson(CJson& out, size_t limit = size_t(16) << 20, int64_t timeoutMs = -1);

        /**
         * Reads and drops the rest of the body.
         * @param limit Gives up with -EFBIG after this many bytes.
         */
        TTask<int32_t> discard(size_t limit = size_t(-1), int64_t timeoutMs = -1);

        /**
         * Returns a reader that is already complete and yields no bytes.
         */
        static std::shared_ptr<IBodyReader> createEmpty();

        /**
         * Returns a reader over bytes held in memory (useful for tests and adapters).
         */
        static std::shared_ptr<IBodyReader> createFromBytes(std::string bytes);
    };

    using IBodyReaderPtr = std::shared_ptr<IBodyReader>;

    /**
     * Request a client sends.
     *
     * The body comes either from `body` (memory; sent with Content-Length and replayable on
     * redirects and retries) or from `bodyStream` (sent with `bodyLength` as Content-Length when
     * >= 0, otherwise with chunked transfer coding; not replayable).
     */
    struct SBOX_API SRequest {
        std::string method = "GET";
        SUrl url;
        CHeaders headers;
        std::vector<uint8_t> body;
        IStreamPtr bodyStream;
        int64_t bodyLength = -1;        // --> Length of bodyStream, or -1 for chunked.
        std::string unixSocket;         // --> Connect to this UNIX socket instead of url's host.
        bool followRedirects = true;

        /**
         * Parses `text` into `url`.
         * @return SBOX_OK or -EINVAL.
         */
        int32_t setUrl(std::string_view text);

        /**
         * Sets an in-memory body and, when given, its Content-Type.
         */
        void setBody(std::string_view data, std::string_view contentType = {});

        /**
         * Sets a JSON body and its Content-Type.
         */
        void setJson(const CJson& value, std::string_view contentType = "application/json");

        /**
         * Sets a streamed body.
         * @param length Exact length, or -1 to send it chunked.
         */
        void setBodyStream(IStreamPtr stream, int64_t length = -1);

        /** Returns true when the request carries a body. */
        inline bool hasBody() const noexcept { return bodyStream != nullptr || !body.empty(); }
    };

    /**
     * Response a client received. The body is a stream that must be read (or closed) by the
     * caller; reading it to the end returns the connection to the pool.
     */
    struct SBOX_API SResponse {
        int32_t status = 0;
        int32_t versionMinor = 1;       // --> 0 for HTTP/1.0, 1 for HTTP/1.1.
        std::string reason;
        CHeaders headers;
        IBodyReaderPtr body;            // --> Never null after a successful send.
        SUrl url;                       // --> Final URL after redirects.
        int32_t redirects = 0;          // --> Number of redirects followed.

        /** Returns true for a 2xx status. */
        inline bool isSuccess() const noexcept { return status >= 200 && status < 300; }

        /**
         * Reads the whole body as text (see IBodyReader::readText).
         */
        TTask<int32_t> readText(std::string& out, size_t limit = size_t(64) << 20);

        /**
         * Reads the whole body as JSON (see IBodyReader::readJson).
         */
        TTask<int32_t> readJson(CJson& out, size_t limit = size_t(16) << 20);
    };

}
}

#endif
