#include <sbox/http/client.hpp>
#include <sbox/http/auth.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include "wire.hpp"
#include <cerrno>
#include <map>
#include <netinet/in.h>
#include <netinet/tcp.h>

namespace sbox {
namespace http {

    namespace {

        constexpr size_t INLINE_BODY_LIMIT = 65536;   // --> Bodies up to this size go out with the head.
        constexpr size_t REDIRECT_DRAIN_LIMIT = 1 << 20;

        /**
         * How a request reaches its server.
         */
        enum RouteMode {
            ROUTE_DIRECT,
            ROUTE_UNIX,
            ROUTE_FORWARD,      // --> Plain http through a proxy, absolute-form target.
            ROUTE_TUNNEL,       // --> https through a proxy CONNECT tunnel.
        };

        /**
         * Resolved connection route of a request.
         */
        struct Route {
            RouteMode mode = ROUTE_DIRECT;
            bool tls = false;
            std::string host;           // --> Target host (decoded, no brackets).
            uint16_t port = 0;
            std::string unixPath;
            SUrl proxy;
            std::string proxyAuth;      // --> Proxy-Authorization value, or empty.
            std::string key;            // --> Pool key.
        };

        /*
         * Checks request header names and values for CR/LF injection.
         */
        bool validRequestHeaders(const CHeaders& headers) {
            for (const CHeaders::SField& f : headers) {
                if (!IsToken(f.name)) {
                    return false;
                }

                for (char c : f.value) {
                    unsigned char u = (unsigned char) c;
                    if ((u < 0x20 && c != '\t') || u == 0x7f) {
                        return false;
                    }
                }
            }

            return true;
        }

        /*
         * Builds the route of a request.
         */
        int32_t makeRoute(const SClientOptions& options, const SUrl& url, const std::string& unixSocket, Route& out) {
            out = Route{};

            if (url.scheme != "http" && url.scheme != "https" && url.scheme != "http+unix") {
                return -EPROTONOSUPPORT;
            }

            if (!url.hasAuthority) {
                return -EINVAL;
            }

            out.tls = url.scheme == "https";

            if (url.scheme == "http+unix" || !unixSocket.empty()) {
                out.mode = ROUTE_UNIX;
                out.unixPath = unixSocket;

                if (out.unixPath.empty() && PercentDecode(url.host, out.unixPath) != SBOX_OK) {
                    return -EINVAL;
                }

                if (out.unixPath.empty()) {
                    return -EINVAL;
                }

                out.key = std::string(out.tls ? "us|" : "u|") + out.unixPath;
                return SBOX_OK;
            }

            if (url.host.empty()) {
                return -EINVAL;
            }

            if (PercentDecode(url.host, out.host) != SBOX_OK) {
                return -EINVAL;
            }

            out.port = url.effectivePort();
            std::string hostPort = url.scheme + "://" + url.hostPort() + ":" + std::to_string(out.port);

            std::string proxy = options.proxy.select(url);
            if (proxy.empty()) {
                out.mode = ROUTE_DIRECT;
                out.key = "d|" + hostPort;
                return SBOX_OK;
            }

            // --> Accept "host:port" without a scheme, as many environments write it.
            if (proxy.find("://") == std::string::npos) {
                proxy = "http://" + proxy;
            }

            if (SUrl::parse(proxy, out.proxy) != SBOX_OK || out.proxy.host.empty()) {
                return -EINVAL;
            }

            if (out.proxy.scheme != "http") {
                return -EPROTONOSUPPORT;
            }

            std::string user, password;
            if (out.proxy.credentials(user, password) == SBOX_OK) {
                out.proxyAuth = EncodeBasicAuth(user, password);
            }

            out.mode = out.tls ? ROUTE_TUNNEL : ROUTE_FORWARD;
            out.key = (out.tls ? "t|" : "f|") + out.proxy.toString() + "|" + hostPort;
            return SBOX_OK;
        }

        /*
         * Connects a TCP socket to host:port, trying each resolved address.
         */
        TTask<int32_t> connectTcp(std::string host, uint16_t port, int64_t timeoutMs, IStreamPtr& out) {
            std::vector<SEndpoint> endpoints;
            int32_t r = co_await ResolveEndpoints(host, port, endpoints);
            if (r != SBOX_OK) {
                co_return r;
            }

            int32_t last = -EHOSTUNREACH;
            for (const SEndpoint& ep : endpoints) {
                auto sock = std::make_shared<CSocket>();
                last = co_await sock->connect(ep, timeoutMs);

                if (last == SBOX_OK) {
                    int one = 1;
                    ::setsockopt(sock->nativeHandle(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    out = std::move(sock);
                    co_return SBOX_OK;
                }
            }

            co_return last;
        }

        /*
         * Parses "HTTP/1.x SSS reason".
         */
        int32_t parseStatusLine(std::string_view line, SResponse& out) {
            if (line.size() < 12 || line.substr(0, 5) != "HTTP/" || line[6] != '.' || line[8] != ' ') {
                return -EBADMSG;
            }

            if (line[5] != '1' || line[7] < '0' || line[7] > '9') {
                return -EBADMSG;
            }

            int32_t status = 0;
            for (size_t i = 9; i < 12; ++i) {
                if (line[i] < '0' || line[i] > '9') {
                    return -EBADMSG;
                }

                status = status * 10 + (line[i] - '0');
            }

            if (status < 100 || (line.size() > 12 && line[12] != ' ')) {
                return -EBADMSG;
            }

            out.status = status;
            out.versionMinor = line[7] - '0';
            out.reason = line.size() > 13 ? std::string(line.substr(13)) : std::string();
            return SBOX_OK;
        }

        /*
         * Reads a response head (skipping 1xx interim responses).
         */
        TTask<int32_t> readResponseHead(wire::Connection& conn, size_t maxHeaderBytes, int64_t deadline, SResponse& out) {
            while (true) {
                size_t budget = maxHeaderBytes;
                std::string line;

                int32_t r = co_await conn.readLine(line, budget, deadline);
                if (r != SBOX_OK) {
                    co_return r == -ENODATA ? -ECONNRESET : r;
                }

                if (line.size() + 2 > budget) {
                    co_return -EMSGSIZE;
                }

                budget -= line.size() + 2;

                out.headers.clear();
                r = parseStatusLine(line, out);
                if (r != SBOX_OK) {
                    co_return r;
                }

                r = co_await wire::ReadHeaderBlock(conn, out.headers, budget, deadline, true);
                if (r != SBOX_OK) {
                    co_return r == -ENODATA ? -ECONNRESET : r;
                }

                if (out.status == 101) {
                    co_return -ENOTSUP;
                }

                if (out.status >= 200) {
                    co_return SBOX_OK;
                }
            }
        }

        /*
         * Returns true when two URLs share scheme, host and port.
         */
        bool sameOrigin(const SUrl& a, const SUrl& b) {
            return a.scheme == b.scheme && a.host == b.host && a.effectivePort() == b.effectivePort();
        }

        /*
         * Returns true for the redirect statuses the client follows.
         */
        bool isRedirect(int32_t status) {
            return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
        }

    }

    /**
     * Shared client state; bodies keep a weak reference to return connections to the pool.
     */
    struct CHttpClient::SState {
        SClientOptions options;
        std::map<std::string, std::vector<wire::ConnectionPtr>> idle;
        uint64_t opened = 0;

        /*
         * Drops pooled connections that idled too long.
         */
        void prune() {
            int64_t now = CEventLoop::nowMs();

            for (auto it = idle.begin(); it != idle.end();) {
                std::erase_if(it->second, [&](const wire::ConnectionPtr& c) {
                    return options.poolIdleTimeoutMs >= 0 && now - c->idleSince > options.poolIdleTimeoutMs;
                });

                it = it->second.empty() ? idle.erase(it) : std::next(it);
            }
        }

        /*
         * Takes a pooled connection for `key`, or nullptr.
         */
        wire::ConnectionPtr take(const std::string& key) {
            prune();

            auto it = idle.find(key);
            if (it == idle.end() || it->second.empty()) {
                return nullptr;
            }

            wire::ConnectionPtr c = std::move(it->second.back());
            it->second.pop_back();
            if (it->second.empty()) {
                idle.erase(it);
            }

            c->reused = true;
            return c;
        }

        /*
         * Returns a connection after its response body ended.
         */
        void release(wire::ConnectionPtr c, bool reusable) {
            if (!c) {
                return;
            }

            if (!reusable || c->broken || c->buffered() != 0 || c->key.empty()) {
                c->close();
                return;
            }

            prune();
            std::vector<wire::ConnectionPtr>& list = idle[c->key];
            if (list.size() >= options.maxIdlePerHost) {
                c->close();
                return;
            }

            c->idleSince = CEventLoop::nowMs();
            list.push_back(std::move(c));
        }

        /*
         * Opens a connection along `route`.
         */
        TTask<int32_t> connect(const Route& route, wire::ConnectionPtr& out) {
            IStreamPtr transport;
            int32_t r = SBOX_OK;

            if (route.tls && !options.tls) {
                co_return -EPROTONOSUPPORT;
            }

            if (route.mode == ROUTE_UNIX) {
                SEndpoint ep;
                r = SEndpoint::fromUnix(route.unixPath, ep);
                if (r != SBOX_OK) {
                    co_return r;
                }

                auto sock = std::make_shared<CSocket>();
                r = co_await sock->connect(ep, options.connectTimeoutMs);
                if (r != SBOX_OK) {
                    co_return r;
                }

                transport = std::move(sock);
            } else if (route.mode == ROUTE_DIRECT) {
                r = co_await connectTcp(route.host, route.port, options.connectTimeoutMs, transport);
                if (r != SBOX_OK) {
                    co_return r;
                }
            } else {
                std::string proxyHost;
                if (PercentDecode(route.proxy.host, proxyHost) != SBOX_OK) {
                    co_return -EINVAL;
                }

                uint16_t proxyPort = route.proxy.port >= 0 ? uint16_t(route.proxy.port) : uint16_t(80);
                r = co_await connectTcp(proxyHost, proxyPort, options.connectTimeoutMs, transport);
                if (r != SBOX_OK) {
                    co_return r;
                }

                if (route.mode == ROUTE_TUNNEL) {
                    r = co_await tunnel(route, transport);
                    if (r != SBOX_OK) {
                        co_return r;
                    }
                }
            }

            if (route.tls) {
                IStreamPtr secure;
                r = co_await options.tls->connect(transport, route.host, secure);
                if (r != SBOX_OK || !secure) {
                    transport->close();
                    co_return r != SBOX_OK ? r : -EPROTO;
                }

                transport = std::move(secure);
            }

            out = std::make_shared<wire::Connection>(std::move(transport));
            out->key = route.key;
            ++opened;
            co_return SBOX_OK;
        }

        /*
         * Asks the proxy for a CONNECT tunnel to the target and positions `transport` inside it.
         */
        TTask<int32_t> tunnel(const Route& route, IStreamPtr& transport) {
            std::string authority = (route.host.find(':') != std::string::npos ? "[" + route.host + "]" : route.host)
                + ":" + std::to_string(route.port);

            std::string head = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
            if (!route.proxyAuth.empty()) {
                head += "Proxy-Authorization: " + route.proxyAuth + "\r\n";
            }

            if (!options.userAgent.empty()) {
                head += "User-Agent: " + options.userAgent + "\r\n";
            }

            head += "\r\n";

            wire::Connection conn(transport);
            int32_t r = co_await conn.sendAll(BytesOf(head), options.connectTimeoutMs);
            if (r != SBOX_OK) {
                co_return r;
            }

            int64_t deadline = options.connectTimeoutMs < 0 ? -1 : CEventLoop::nowMs() + options.connectTimeoutMs;
            SResponse resp;
            r = co_await readResponseHead(conn, options.maxHeaderBytes, deadline, resp);
            if (r != SBOX_OK) {
                co_return r;
            }

            if (resp.status < 200 || resp.status >= 300) {
                co_return resp.status == 407 ? -EACCES : -ECONNREFUSED;
            }

            // --> Bytes the proxy already forwarded past its response belong to the tunnel.
            std::vector<uint8_t> extra(conn.buffer.begin() + ptrdiff_t(conn.head), conn.buffer.begin() + ptrdiff_t(conn.tail));
            conn.stream.reset();
            transport = wire::PrefixStream(std::move(transport), std::move(extra));
            co_return SBOX_OK;
        }

        /*
         * Builds the request head.
         */
        std::string buildHead(const SRequest& req, const SUrl& url, const Route& route, bool& inlineBody) const {
            std::string target;
            if (route.mode == ROUTE_FORWARD) {
                SUrl abs = url;
                abs.userinfo.clear();
                abs.hasUserinfo = false;
                abs.hasFragment = false;
                abs.fragment.clear();
                if (abs.path.empty()) {
                    abs.path = "/";
                }

                target = abs.toString();
            } else {
                target = url.requestTarget();
            }

            std::string head;
            head.reserve(512);
            head += req.method;
            head.push_back(' ');
            head += target;
            head += " HTTP/1.1\r\n";

            if (!req.headers.has("Host")) {
                head += "Host: ";
                head += (route.mode == ROUTE_UNIX && url.scheme == "http+unix") || url.host.empty() ? std::string("localhost") : url.hostPort();
                head += "\r\n";
            }

            if (!options.userAgent.empty() && !req.headers.has("User-Agent")) {
                head += "User-Agent: " + options.userAgent + "\r\n";
            }

            if (!req.headers.has("Authorization")) {
                std::string user, password;
                if (url.credentials(user, password) == SBOX_OK) {
                    head += "Authorization: " + EncodeBasicAuth(user, password) + "\r\n";
                }
            }

            if (route.mode == ROUTE_FORWARD && !route.proxyAuth.empty() && !req.headers.has("Proxy-Authorization")) {
                head += "Proxy-Authorization: " + route.proxyAuth + "\r\n";
            }

            inlineBody = false;
            if (req.bodyStream) {
                if (req.bodyLength >= 0) {
                    head += "Content-Length: " + std::to_string(req.bodyLength) + "\r\n";
                } else {
                    head += "Transfer-Encoding: chunked\r\n";
                }
            } else if (!req.body.empty() || req.method == "POST" || req.method == "PUT" || req.method == "PATCH") {
                head += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";
                inlineBody = req.body.size() <= INLINE_BODY_LIMIT;
            }

            for (const CHeaders::SField& f : req.headers) {
                if (EqualsNoCase(f.name, "Content-Length") || EqualsNoCase(f.name, "Transfer-Encoding")) {
                    continue;
                }

                head += f.name;
                head += ": ";
                head += f.value;
                head += "\r\n";
            }

            head += "\r\n";

            if (inlineBody) {
                head.append(reinterpret_cast<const char*>(req.body.data()), req.body.size());
            }

            return head;
        }

        /*
         * Sends one request and reads the response head (no redirects).
         */
        TTask<int32_t> exchange(std::shared_ptr<SState> self, const SRequest& req, SResponse& out) {
            Route route;
            int32_t r = makeRoute(options, req.url, req.unixSocket, route);
            if (r != SBOX_OK) {
                co_return r;
            }

            bool replayable = !req.bodyStream;

            for (int32_t attempt = 0; attempt < 2; ++attempt) {
                wire::ConnectionPtr conn = take(route.key);
                bool fresh = !conn;

                if (fresh) {
                    r = co_await connect(route, conn);
                    if (r != SBOX_OK) {
                        co_return r;
                    }
                }

                bool inlineBody = false;
                std::string head = buildHead(req, req.url, route, inlineBody);

                r = co_await conn->sendAll(BytesOf(head), options.idleTimeoutMs);
                if (r == SBOX_OK && !inlineBody) {
                    if (req.bodyStream) {
                        r = co_await wire::SendStreamBody(*conn, *req.bodyStream, req.bodyLength, options.idleTimeoutMs);
                    } else if (!req.body.empty()) {
                        r = co_await conn->sendAll(BytesOf(req.body), options.idleTimeoutMs);
                    }
                }

                if (r != SBOX_OK) {
                    conn->close();
                    if (!fresh && replayable && r != -ETIMEDOUT) {
                        continue;
                    }

                    co_return r;
                }

                uint64_t mark = conn->received;
                int64_t deadline = options.headerTimeoutMs < 0 ? -1 : CEventLoop::nowMs() + options.headerTimeoutMs;

                out = SResponse{};
                r = co_await readResponseHead(*conn, options.maxHeaderBytes, deadline, out);
                if (r != SBOX_OK) {
                    conn->close();

                    // --> A pooled connection the server closed while idle fails before any
                    // response byte; that is safe to retry once on a fresh connection.
                    bool closedEarly = r == -ECONNRESET || r == -EPIPE;
                    if (!fresh && replayable && closedEarly && conn->received == mark) {
                        continue;
                    }

                    co_return r;
                }

                wire::Framing framing = wire::FRAME_NONE;
                uint64_t length = 0;
                bool forceClose = false;

                r = wire::ResponseFraming(req.method, out.status, out.headers, framing, length, forceClose);
                if (r != SBOX_OK) {
                    conn->close();
                    co_return r;
                }

                bool keepAlive = !forceClose && !out.headers.hasToken("Connection", "close")
                    && (out.versionMinor >= 1 || out.headers.hasToken("Connection", "keep-alive"));

                auto body = std::make_shared<wire::Body>(conn, framing, length, options.idleTimeoutMs, 0, options.maxHeaderBytes);
                std::weak_ptr<SState> weak = self;
                body->onDone = [weak, keepAlive](wire::ConnectionPtr c, bool clean) {
                    if (auto s = weak.lock()) {
                        s->release(std::move(c), clean && keepAlive);
                    } else if (c) {
                        c->close();
                    }
                };

                body->settleEmpty();
                out.body = std::move(body);
                co_return SBOX_OK;
            }

            co_return -ECONNRESET;
        }
    };

    /* Creates a client. */
    CHttpClient::CHttpClient(SClientOptions options) : _state(std::make_shared<SState>()) {
        _state->options = std::move(options);
    }

    /* Destroys the client. */
    CHttpClient::~CHttpClient() {
        closeIdle();
    }

    /* Returns the settings. */
    const SClientOptions& CHttpClient::options() const noexcept {
        return _state->options;
    }

    /* Returns the settings for adjustment. */
    SClientOptions& CHttpClient::options() noexcept {
        return _state->options;
    }

    /* Sends a request, following redirects. */
    TTask<int32_t> CHttpClient::send(SRequest request, SResponse& out) {
        std::shared_ptr<SState> state = _state;

        if (!IsToken(request.method) || !validRequestHeaders(request.headers)) {
            co_return -EINVAL;
        }

        int32_t redirects = 0;

        while (true) {
            int32_t r = co_await state->exchange(state, request, out);
            if (r != SBOX_OK) {
                co_return r;
            }

            out.url = request.url;
            out.url.hasFragment = false;
            out.url.fragment.clear();
            out.redirects = redirects;

            if (!request.followRedirects || !isRedirect(out.status)) {
                co_return SBOX_OK;
            }

            const std::string* location = out.headers.find("Location");
            SUrl next;
            if (!location || SUrl::resolve(request.url, *location, next) != SBOX_OK) {
                co_return SBOX_OK;
            }

            if (next.scheme != "http" && next.scheme != "https" && next.scheme != "http+unix") {
                co_return SBOX_OK;
            }

            bool dropBody = out.status == 303 || ((out.status == 301 || out.status == 302) && request.method == "POST");
            if (!dropBody && request.bodyStream) {
                // --> 307/308 must resend the body, which a stream cannot do.
                co_return SBOX_OK;
            }

            if (redirects >= state->options.maxRedirects) {
                out.body->close();
                co_return -ELOOP;
            }

            // --> Drain a small redirect body so the connection can be reused.
            if (co_await out.body->discard(REDIRECT_DRAIN_LIMIT, state->options.idleTimeoutMs) != SBOX_OK) {
                out.body->close();
            }

            if (dropBody) {
                if (request.method != "HEAD") {
                    request.method = "GET";
                }

                request.body.clear();
                request.bodyStream.reset();
                request.bodyLength = -1;
                request.headers.remove("Content-Type");
                request.headers.remove("Content-Encoding");
                request.headers.remove("Content-Language");
                request.headers.remove("Content-Location");
            }

            if (!sameOrigin(request.url, next)) {
                request.headers.remove("Authorization");
                request.headers.remove("Cookie");
                request.headers.remove("Proxy-Authorization");

                // --> A UNIX socket route belongs to the original host only.
                request.unixSocket.clear();

                // --> A Host override names the old origin.
                request.headers.remove("Host");
            }

            request.url = std::move(next);
            ++redirects;
        }
    }

    /* Sends a GET request. */
    TTask<int32_t> CHttpClient::get(std::string url, SResponse& out, CHeaders headers) {
        SRequest req;
        if (req.setUrl(url) != SBOX_OK) {
            co_return -EINVAL;
        }

        req.headers = std::move(headers);
        co_return co_await send(std::move(req), out);
    }

    /* Sends a request and reads the whole body. */
    TTask<int32_t> CHttpClient::fetch(SRequest request, SResponse& out, std::string& body, size_t limit) {
        int32_t r = co_await send(std::move(request), out);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await out.body->readText(body, limit);
    }

    /* Closes idle connections. */
    void CHttpClient::closeIdle() noexcept {
        for (auto& [key, list] : _state->idle) {
            for (const wire::ConnectionPtr& c : list) {
                c->close();
            }
        }

        _state->idle.clear();
    }

    /* Counts idle connections. */
    size_t CHttpClient::idleConnections() const noexcept {
        size_t n = 0;
        for (const auto& [key, list] : _state->idle) {
            n += list.size();
        }

        return n;
    }

    /* Returns the number of connections opened. */
    uint64_t CHttpClient::connectionsOpened() const noexcept {
        return _state->opened;
    }

}
}
