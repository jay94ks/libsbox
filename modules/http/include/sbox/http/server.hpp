#ifndef __INCLUDE_SBOX_HTTP_SERVER_HPP__
#define __INCLUDE_SBOX_HTTP_SERVER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/task.hpp>
#include <sbox/http/message.hpp>
#include <functional>

namespace sbox {
namespace http {

    /**
     * Settings of a CHttpServer. Timeouts are in milliseconds; negative means none.
     */
    struct SBOX_API SServerOptions {
        size_t maxHeaderBytes = 65536;      // --> Request line plus header fields; beyond: 431 (or 414).
        uint64_t maxBodyBytes = uint64_t(16) << 20;     // --> Request body limit (413), 0 for none.
        int64_t headerTimeoutMs = 30000;    // --> Time to receive a whole request head.
        int64_t keepAliveTimeoutMs = 60000; // --> Idle time allowed between requests on a connection.
        int64_t bodyTimeoutMs = 60000;      // --> Longest gap while reading a request body or writing a response.
        size_t maxConnections = 1024;       // --> Further connections are closed right after accept.
        std::string serverHeader = "libsbox-http";      // --> Server field value, empty to omit.
        std::string jsonContentType = "application/json";   // --> Used by SServerResponse::setJson.
    };

    /**
     * Request as a handler sees it.
     */
    struct SBOX_API SServerRequest {
        std::string method;
        std::string target;         // --> Request target as sent.
        std::string path;           // --> Path of the target, still percent-encoded.
        std::string query;          // --> Query of the target without '?'.
        std::string routeRest;      // --> For prefix routes: the path after the matched prefix.
        int32_t versionMinor = 1;
        CHeaders headers;
        IBodyReaderPtr body;        // --> Never null; limited to SServerOptions::maxBodyBytes (-EFBIG).
        SEndpoint peer;

        /**
         * Returns the decoded value of a query parameter, or an empty string.
         */
        std::string queryParam(std::string_view name) const;

        /**
         * Reads the whole body as text.
         */
        TTask<int32_t> readText(std::string& out);

        /**
         * Reads the whole body as JSON. An empty body yields an empty object.
         * @return SBOX_OK, -EINVAL for invalid JSON, or the read error.
         */
        TTask<int32_t> readJson(CJson& out);
    };

    /**
     * Response a handler fills in. The server writes it after the handler returns: an
     * in-memory body with Content-Length, or a streamed body with its length or chunked.
     */
    struct SBOX_API SServerResponse {
        int32_t status = 200;
        CHeaders headers;
        std::string body;
        IStreamPtr bodyStream;              // --> Streamed body; read to EOF and closed afterwards.
        int64_t bodyLength = -1;            // --> Length of bodyStream, or -1 for chunked.
        bool closeConnection = false;       // --> Close the connection after this response.
        std::string jsonContentType = "application/json";   // --> Preset by the server from its options.

        /**
         * Sets a JSON body with the server's JSON content type.
         */
        void setJson(const CJson& value, int32_t code = 200);

        /**
         * Sets a text body.
         */
        void setText(std::string_view text, int32_t code = 200, std::string_view contentType = "text/plain; charset=utf-8");

        /**
         * Sets a streamed body.
         * @param length Exact length, or -1 to send it chunked.
         */
        void setStream(IStreamPtr stream, int64_t length, std::string_view contentType = "application/octet-stream");
    };

    /**
     * Request handler: a coroutine that fills in the response. Handlers stored in a server must
     * stay valid (captures included) while the server runs.
     */
    using THandler = std::function<TTask<void>(SServerRequest&, SServerResponse&)>;

    /**
     * HTTP/1.1 server over a CListener (TCP or UNIX socket), as used for Docker plugin sockets.
     *
     * Each accepted connection runs in its own coroutine on the calling thread's loop and
     * serves requests one after another (keep-alive, HTTP/1.0 keep-alive on request, chunked
     * request bodies, Expect: 100-continue). Requests are dispatched by exact path first, then
     * by the longest matching prefix; HEAD falls back to the GET handler (the body is not sent);
     * a path that matches with another method gets 405 with an Allow header, an unknown path the
     * fallback handler or 404. A handler that throws yields 500.
     *
     * Malformed requests get 400, oversized heads 431 (414 for the request line), oversized
     * bodies 413, unsupported transfer codings 501, other HTTP versions 505; such a connection
     * is closed afterwards.
     */
    class SBOX_API CHttpServer {
    public:
        /** Shared state (pool or routes and connections); defined in the source file. */
        struct SState;

    private:
        std::shared_ptr<SState> _state;

    public:
        /**
         * Creates a server with no routes.
         */
        explicit CHttpServer(SServerOptions options = {});

        CHttpServer(const CHttpServer&) = delete;

        CHttpServer& operator=(const CHttpServer&) = delete;

        /**
         * Destroys the server; serve() must have returned.
         */
        ~CHttpServer();

        /** Returns the settings. */
        SServerOptions& options() noexcept;

        /**
         * Adds a route for an exact path.
         * @param method Method to match ("GET", "POST"), or "" / "*" for any method.
         */
        void route(std::string_view method, std::string_view path, THandler handler);

        /**
         * Adds a route for every path starting with `prefix` (the longest prefix wins).
         */
        void routePrefix(std::string_view method, std::string_view prefix, THandler handler);

        /**
         * Sets the handler for requests no route matched (default: 404).
         */
        void fallback(THandler handler);

        /**
         * Accepts and serves connections until stop() is called, then closes the listener and
         * waits for the connections to finish. A stop() issued before serve() started makes it
         * return at once.
         * @return SBOX_OK after a stop, -EBUSY when already serving, or an accept error.
         */
        TTask<int32_t> serve(CListener& listener);

        /**
         * Stops serving: closes the listener and idle connections; requests in progress finish
         * and their connections close afterwards.
         * @param force Also close connections with a request in progress.
         */
        void stop(bool force = false) noexcept;

        /** Returns true while serve() is running. */
        bool isServing() const noexcept;

        /** Returns the number of open connections. */
        size_t activeConnections() const noexcept;

        /** Returns the number of requests handled so far (for diagnostics). */
        uint64_t requestsServed() const noexcept;
    };

}
}

#endif
