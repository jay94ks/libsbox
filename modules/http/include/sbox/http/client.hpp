#ifndef __INCLUDE_SBOX_HTTP_CLIENT_HPP__
#define __INCLUDE_SBOX_HTTP_CLIENT_HPP__

#include <sbox/common.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/task.hpp>
#include <sbox/http/message.hpp>
#include <sbox/http/proxy.hpp>

namespace sbox {
namespace http {

    /**
     * Hook that turns a connected transport into a TLS session for https URLs.
     *
     * The http module does not implement TLS; the tls module (or a test double) provides it.
     * An adapter over `tls::ConnectTls(transport, options, out)` sets the server name for SNI and
     * certificate verification from `serverName` and returns the TLS stream in `out`.
     * The hook enforces its own handshake timeout.
     */
    class SBOX_API ITlsConnector {
    public:
        virtual ~ITlsConnector() = default;

        /**
         * Runs the client handshake over `transport`.
         * @param transport Connected byte stream (TCP socket or a proxy CONNECT tunnel).
         * @param serverName Host name of the URL (IPv6 literals without brackets).
         * @param out Receives the encrypted stream; closing it closes the transport.
         * @return SBOX_OK or a negated errno.
         */
        virtual TTask<int32_t> connect(IStreamPtr transport, const std::string& serverName, IStreamPtr& out) = 0;
    };

    using ITlsConnectorPtr = std::shared_ptr<ITlsConnector>;

    /**
     * Settings of a CHttpClient. Timeouts are in milliseconds; negative means none.
     */
    struct SBOX_API SClientOptions {
        int64_t connectTimeoutMs = 30000;   // --> Per address tried, and for the proxy CONNECT exchange.
        int64_t headerTimeoutMs = 60000;    // --> From the end of the request until the response head arrived.
        int64_t idleTimeoutMs = 60000;      // --> Longest gap while sending a request or reading a body.
        int64_t poolIdleTimeoutMs = 90000;  // --> Idle keep-alive connections older than this are dropped.
        size_t maxIdlePerHost = 8;
        int32_t maxRedirects = 10;
        size_t maxHeaderBytes = 65536;      // --> Status line plus header fields (also trailers).
        std::string userAgent = "libsbox-http/1";   // --> Sent unless the request sets one; empty for none.
        SProxyConfig proxy;                 // --> Direct by default; see SProxyConfig::fromEnvironment().
        ITlsConnectorPtr tls;               // --> Needed for https; without it https fails with -EPROTONOSUPPORT.
    };

    /**
     * HTTP/1.1 client with a keep-alive connection pool.
     *
     * - Schemes: "http", "https" (through the ITlsConnector hook) and "http+unix" whose host is
     *   the percent-encoded socket path ("http+unix://%2Frun%2Fdocker.sock/info"). Any request
     *   can also be sent to a UNIX socket with SRequest::unixSocket.
     * - Connections are pooled per (scheme, host, port, route) and reused while idle for less
     *   than poolIdleTimeoutMs. A request on a reused connection that the server had closed is
     *   retried once on a new connection when its body is replayable.
     * - Redirects (301, 302, 303, 307, 308) are followed up to maxRedirects: 303 (and 301/302
     *   for POST) turn into GET without a body, 307/308 keep method and body (a streamed body
     *   cannot be replayed, so such a redirect is returned as is). Authorization, Cookie and
     *   Proxy-Authorization are dropped when the redirect leaves the origin (scheme, host, port),
     *   as registries redirect blob downloads to CDN hosts.
     * - The response body is a stream (SResponse::body); read it to the end or close it.
     *
     * Methods must be awaited on a running CEventLoop. One client is used from one loop.
     * Results: SBOX_OK, -EINVAL (bad URL or header), -EPROTONOSUPPORT (scheme, or https without
     * TLS hook), -ETIMEDOUT, -ECONNRESET (closed early), -EBADMSG (malformed response),
     * -EMSGSIZE (response head too large), -ELOOP (too many redirects), -ECONNREFUSED / -EACCES
     * (proxy refused CONNECT / wants authentication) or another socket error.
     */
    class SBOX_API CHttpClient {
    public:
        /** Shared state (pool or routes and connections); defined in the source file. */
        struct SState;

    private:
        std::shared_ptr<SState> _state;

    public:
        /**
         * Creates a client.
         */
        explicit CHttpClient(SClientOptions options = {});

        CHttpClient(const CHttpClient&) = delete;

        CHttpClient& operator=(const CHttpClient&) = delete;

        /**
         * Destroys the client and its idle connections. Bodies still being read stay valid.
         */
        ~CHttpClient();

        /** Returns the settings. */
        const SClientOptions& options() const noexcept;

        /** Returns the settings for adjustment (affects later requests). */
        SClientOptions& options() noexcept;

        /**
         * Sends a request and receives the response head, following redirects when the
         * request allows it.
         * @param out Receives the response; its body must be read or closed.
         */
        TTask<int32_t> send(SRequest request, SResponse& out);

        /**
         * Sends a GET request.
         */
        TTask<int32_t> get(std::string url, SResponse& out, CHeaders headers = {});

        /**
         * Sends a request and reads the whole response body into `body`.
         * @param limit Maximum body size (-EFBIG beyond it).
         */
        TTask<int32_t> fetch(SRequest request, SResponse& out, std::string& body, size_t limit = size_t(64) << 20);

        /**
         * Closes every idle pooled connection.
         */
        void closeIdle() noexcept;

        /**
         * Returns the number of idle pooled connections.
         */
        size_t idleConnections() const noexcept;

        /**
         * Returns how many connections the client has opened so far (for diagnostics).
         */
        uint64_t connectionsOpened() const noexcept;
    };

}
}

#endif
