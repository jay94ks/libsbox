#include <sbox/http/server.hpp>
#include <sbox/core/eventloop.hpp>
#include "lex.hpp"
#include "wire.hpp"
#include <cerrno>
#include <algorithm>
#include <exception>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <set>

namespace sbox {
namespace http {

    namespace {

        constexpr size_t INLINE_BODY_LIMIT = 65536;
        constexpr size_t LEFTOVER_DRAIN_LIMIT = 256 * 1024;   // --> Unread request body we still skip to keep the connection.
        constexpr int32_t MAX_LEADING_EMPTY_LINES = 4;
        constexpr int64_t LINGER_MS = 1000;
        constexpr size_t LINGER_LIMIT = 1 << 20;

        /**
         * One route of the table.
         */
        struct Route {
            std::string method;     // --> Empty for any.
            std::string path;
            bool prefix = false;
            THandler handler;
        };

        /**
         * Bookkeeping of one open connection (lives in the connection coroutine's frame).
         */
        struct ServerConn {
            wire::ConnectionPtr conn;
            CSocket* socket = nullptr;
            bool idle = true;       // --> Waiting for the next request (safe to close on stop).
            bool linger = false;    // --> Unread request bytes may remain: drain before closing.
        };

        /*
         * Returns true when a route method matches a request method.
         */
        bool methodMatches(const std::string& routeMethod, const std::string& method) {
            return routeMethod.empty() || routeMethod == method;
        }

        /*
         * Parses "METHOD SP target SP HTTP/1.x".
         * @return SBOX_OK, -EBADMSG (400) or -EPROTONOSUPPORT (505).
         */
        int32_t parseRequestLine(std::string_view line, SServerRequest& req) {
            size_t sp1 = line.find(' ');
            if (sp1 == std::string_view::npos || sp1 == 0) {
                return -EBADMSG;
            }

            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string_view::npos || sp2 == sp1 + 1 || line.find(' ', sp2 + 1) != std::string_view::npos) {
                return -EBADMSG;
            }

            std::string_view method = line.substr(0, sp1);
            std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
            std::string_view version = line.substr(sp2 + 1);

            if (!IsToken(method)) {
                return -EBADMSG;
            }

            for (char c : target) {
                unsigned char u = (unsigned char) c;
                if (u <= 0x20 || u >= 0x7f) {
                    return -EBADMSG;
                }
            }

            if (version.size() != 8 || version.substr(0, 5) != "HTTP/" || version[6] != '.'
                || version[5] < '0' || version[5] > '9' || version[7] < '0' || version[7] > '9') {
                return -EBADMSG;
            }

            if (version[5] != '1') {
                return -EPROTONOSUPPORT;
            }

            req.method = std::string(method);
            req.target = std::string(target);
            req.versionMinor = version[7] - '0';

            if (target[0] == '/') {
                size_t q = target.find('?');
                req.path = std::string(target.substr(0, q));
                if (q != std::string_view::npos) {
                    req.query = std::string(target.substr(q + 1));
                }

                size_t hash = req.query.find('#');
                if (hash != std::string::npos) {
                    req.query.resize(hash);
                }

                return SBOX_OK;
            }

            if (target == "*") {
                req.path = "*";
                return SBOX_OK;
            }

            // --> absolute-form (what proxies receive); servers must accept it too.
            SUrl url;
            if (SUrl::parse(target, url) == SBOX_OK && url.isAbsolute() && url.hasAuthority) {
                req.path = url.path.empty() ? std::string("/") : url.path;
                req.query = url.query;
                return SBOX_OK;
            }

            return -EBADMSG;
        }

        /*
         * Builds a minimal response head with a short text body.
         */
        std::string simpleResponse(int32_t status, bool keepAlive, std::string_view extraHeaders = {}) {
            std::string text = std::string(ReasonPhrase(status)) + "\n";
            std::string out = "HTTP/1.1 " + std::to_string(status) + " " + ReasonPhrase(status) + "\r\n";
            out += "Date: " + FormatHttpDate() + "\r\n";
            out += "Content-Type: text/plain; charset=utf-8\r\n";
            out += "Content-Length: " + std::to_string(text.size()) + "\r\n";
            out += extraHeaders;
            if (!keepAlive) {
                out += "Connection: close\r\n";
            }

            out += "\r\n";
            out += text;
            return out;
        }

    }

    /**
     * Server state shared with the connection coroutines.
     */
    struct CHttpServer::SState {
        SServerOptions options;
        std::vector<Route> routes;
        THandler fallback;
        CListener* listener = nullptr;
        bool serving = false;
        bool stopping = false;
        std::set<ServerConn*> conns;
        std::coroutine_handle<> drainWaiter;
        uint64_t served = 0;

        /**
         * Awaiter that resumes once every connection ended.
         */
        struct DrainAwaiter {
            SState* state;

            inline bool await_ready() const noexcept { return state->conns.empty(); }

            inline void await_suspend(std::coroutine_handle<> h) noexcept { state->drainWaiter = h; }

            inline void await_resume() const noexcept {}
        };

        /*
         * Closes idle connections (all of them when `force`).
         */
        void closeConnections(bool force) noexcept {
            for (ServerConn* c : conns) {
                if (force || c->idle) {
                    c->conn->close();
                }
            }
        }

        /*
         * Finds the handler of a request; sets `status` to 404/405 when none matches.
         */
        const THandler* dispatch(SServerRequest& req, int32_t& status, std::string& allow) const {
            auto pathMatches = [&](const Route& r) {
                return r.prefix ? req.path.compare(0, r.path.size(), r.path) == 0 : r.path == req.path;
            };

            // --> Exact routes first, then the longest matching prefix.
            auto match = [&](const std::string& method) -> const Route* {
                const Route* best = nullptr;

                for (const Route& r : routes) {
                    if (!r.prefix && r.path == req.path && methodMatches(r.method, method)) {
                        return &r;
                    }
                }

                for (const Route& r : routes) {
                    if (r.prefix && pathMatches(r) && methodMatches(r.method, method)
                        && (!best || r.path.size() > best->path.size())) {
                        best = &r;
                    }
                }

                return best;
            };

            const Route* found = match(req.method);
            if (!found && req.method == "HEAD") {
                // --> HEAD is served by the GET handler; the body is not sent.
                found = match("GET");
            }

            if (found) {
                req.routeRest = found->prefix ? req.path.substr(found->path.size()) : std::string();
                return &found->handler;
            }

            if (fallback) {
                return &fallback;
            }

            std::vector<std::string> allowed;
            for (const Route& r : routes) {
                if (pathMatches(r) && std::find(allowed.begin(), allowed.end(), r.method) == allowed.end()) {
                    allowed.push_back(r.method);
                }
            }

            if (allowed.empty()) {
                status = 404;
                return nullptr;
            }

            status = 405;
            for (const std::string& m : allowed) {
                allow += allow.empty() ? m : ", " + m;
            }

            return nullptr;
        }

        /*
         * Writes a handler's response.
         * @return false when the connection failed.
         */
        TTask<bool> writeResponse(wire::Connection& conn, const SServerRequest& req, SServerResponse& resp, bool& keepAlive) {
            int32_t status = resp.status;
            if (status < 100 || status > 999) {
                status = 500;
            }

            bool headOnly = req.method == "HEAD";
            bool noBody = status < 200 || status == 204 || status == 304;
            bool stream = resp.bodyStream != nullptr && !noBody;
            bool chunked = stream && resp.bodyLength < 0 && req.versionMinor >= 1;

            if (stream && resp.bodyLength < 0 && !chunked) {
                // --> An HTTP/1.0 client gets a close-delimited body.
                keepAlive = false;
            }

            std::string head = "HTTP/1.1 " + std::to_string(status) + " " + ReasonPhrase(status) + "\r\n";
            head.reserve(512 + (headOnly || stream ? 0 : resp.body.size()));

            if (!resp.headers.has("Date")) {
                head += "Date: " + FormatHttpDate() + "\r\n";
            }

            if (!options.serverHeader.empty() && !resp.headers.has("Server")) {
                head += "Server: " + options.serverHeader + "\r\n";
            }

            bool userLength = headOnly && resp.headers.has("Content-Length") && resp.body.empty() && !stream;

            for (const CHeaders::SField& f : resp.headers) {
                if (EqualsNoCase(f.name, "Transfer-Encoding") || EqualsNoCase(f.name, "Connection")
                    || (EqualsNoCase(f.name, "Content-Length") && !userLength)) {
                    continue;
                }

                bool valid = IsToken(f.name);
                for (char c : f.value) {
                    unsigned char u = (unsigned char) c;
                    if ((u < 0x20 && c != '\t') || u == 0x7f) {
                        valid = false;
                    }
                }

                // --> Drop fields that would break the framing (CR/LF in a value).
                if (!valid) {
                    continue;
                }

                head += f.name;
                head += ": ";
                head += f.value;
                head += "\r\n";
            }

            if (!noBody && !userLength) {
                if (stream) {
                    if (resp.bodyLength >= 0) {
                        head += "Content-Length: " + std::to_string(resp.bodyLength) + "\r\n";
                    } else if (chunked) {
                        head += "Transfer-Encoding: chunked\r\n";
                    }
                } else {
                    head += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
                }
            }

            if (!keepAlive) {
                head += "Connection: close\r\n";
            } else if (req.versionMinor == 0) {
                head += "Connection: keep-alive\r\n";
            }

            head += "\r\n";

            bool sendBody = !headOnly && !noBody;
            bool inlineBody = sendBody && !stream && resp.body.size() <= INLINE_BODY_LIMIT;
            if (inlineBody) {
                head += resp.body;
            }

            int32_t r = co_await conn.sendAll(BytesOf(head), options.bodyTimeoutMs);
            if (r == SBOX_OK && sendBody && !inlineBody) {
                if (stream) {
                    r = co_await wire::SendStreamBody(conn, *resp.bodyStream, chunked ? -1 : resp.bodyLength, options.bodyTimeoutMs);
                } else {
                    r = co_await conn.sendAll(BytesOf(resp.body), options.bodyTimeoutMs);
                }
            }

            if (resp.bodyStream) {
                resp.bodyStream->close();
            }

            co_return r == SBOX_OK;
        }

        /*
         * Serves one connection until it closes.
         */
        static TTask<void> runConnection(std::shared_ptr<SState> self, std::shared_ptr<CSocket> socket, SEndpoint peer) {
            ServerConn sc;
            sc.conn = std::make_shared<wire::Connection>(socket);
            sc.socket = socket.get();
            self->conns.insert(&sc);

            co_await self->serveConnection(sc, peer);

            if (sc.linger && socket->isValid()) {
                co_await lingerClose(*socket);
            }

            sc.conn->close();
            self->conns.erase(&sc);

            if (self->conns.empty() && self->drainWaiter) {
                CEventLoop::current()->post(std::exchange(self->drainWaiter, nullptr));
            }
        }

        /*
         * Sends a protocol error response; the connection closes afterwards.
         */
        TTask<void> sendError(ServerConn& sc, int32_t status) {
            sc.linger = true;
            co_await sc.conn->sendAll(BytesOf(simpleResponse(status, false)), options.bodyTimeoutMs);
        }

        /*
         * Half-closes and drains what the client still sends, so closing with unread input
         * does not turn into a reset that destroys the response in flight (lingering close).
         */
        static TTask<void> lingerClose(CSocket& socket) {
            socket.shutdownWrite();

            uint8_t sink[4096];
            size_t total = 0;
            int64_t deadline = CEventLoop::nowMs() + LINGER_MS;

            while (total < LINGER_LIMIT) {
                int64_t left = deadline - CEventLoop::nowMs();
                if (left <= 0) {
                    break;
                }

                SIoResult r = co_await socket.recv(SByteSpan(sink, sizeof(sink)), left);
                if (!r.ok() || r.bytes == 0) {
                    break;
                }

                total += r.bytes;
            }
        }

        /*
         * Request loop of one connection.
         */
        TTask<void> serveConnection(ServerConn& sc, SEndpoint peer) {
            wire::Connection& conn = *sc.conn;
            bool first = true;
            int32_t emptyLines = 0;

            while (!stopping) {
                sc.idle = true;

                int64_t wait = first ? options.headerTimeoutMs : options.keepAliveTimeoutMs;
                int64_t deadline = wait < 0 ? -1 : CEventLoop::nowMs() + wait;

                std::string line;
                int32_t r = co_await conn.readLine(line, options.maxHeaderBytes, deadline);
                sc.idle = false;

                if (r == -EMSGSIZE) {
                    co_await sendError(sc, 414);
                    co_return;
                }

                if (r != SBOX_OK) {
                    co_return;
                }

                if (line.empty()) {
                    // --> RFC 9112 2.2: ignore a few empty lines before a request line.
                    if (++emptyLines > MAX_LEADING_EMPTY_LINES) {
                        co_return;
                    }

                    continue;
                }

                emptyLines = 0;
                first = false;

                SServerRequest req;
                req.peer = peer;

                r = parseRequestLine(line, req);
                if (r != SBOX_OK) {
                    co_await sendError(sc, r == -EPROTONOSUPPORT ? 505 : 400);
                    co_return;
                }

                size_t budget = options.maxHeaderBytes > line.size() + 2 ? options.maxHeaderBytes - line.size() - 2 : 0;
                int64_t headDeadline = options.headerTimeoutMs < 0 ? -1 : CEventLoop::nowMs() + options.headerTimeoutMs;

                r = co_await wire::ReadHeaderBlock(conn, req.headers, budget, headDeadline, false);
                if (r == -EMSGSIZE) {
                    co_await sendError(sc, 431);
                    co_return;
                }

                if (r == -EBADMSG) {
                    co_await sendError(sc, 400);
                    co_return;
                }

                if (r != SBOX_OK) {
                    co_return;
                }

                // --> HTTP/1.1 requires exactly one Host field (RFC 9112 3.2).
                if (req.versionMinor >= 1 && req.headers.getAll("Host").size() != 1) {
                    co_await sendError(sc, 400);
                    co_return;
                }

                wire::Framing framing = wire::FRAME_NONE;
                uint64_t length = 0;
                r = wire::RequestFraming(req.headers, framing, length);
                if (r != SBOX_OK) {
                    co_await sendError(sc, r == -ENOTSUP ? 501 : 400);
                    co_return;
                }

                if (framing == wire::FRAME_LENGTH && options.maxBodyBytes != 0 && length > options.maxBodyBytes) {
                    co_await sendError(sc, 413);
                    co_return;
                }

                bool keepAlive = req.versionMinor >= 1
                    ? !req.headers.hasToken("Connection", "close")
                    : req.headers.hasToken("Connection", "keep-alive");

                if (const std::string* expect = req.headers.find("Expect")) {
                    if (!EqualsNoCase(*expect, "100-continue")) {
                        co_await sendError(sc, 417);
                        co_return;
                    }

                    if (framing != wire::FRAME_NONE && req.versionMinor >= 1) {
                        static const char CONTINUE[] = "HTTP/1.1 100 Continue\r\n\r\n";
                        r = co_await conn.sendAll(BytesOf(std::string_view(CONTINUE, sizeof(CONTINUE) - 1)), options.bodyTimeoutMs);
                        if (r != SBOX_OK) {
                            co_return;
                        }
                    }
                }

                auto body = std::make_shared<wire::Body>(sc.conn, framing, length, options.bodyTimeoutMs, options.maxBodyBytes, options.maxHeaderBytes);
                body->settleEmpty();
                req.body = body;

                SServerResponse resp;
                resp.jsonContentType = options.jsonContentType;

                int32_t status = 0;
                std::string allow;
                const THandler* handler = dispatch(req, status, allow);

                if (handler) {
                    // --> Copy: a handler may change the route table while it runs.
                    THandler h = *handler;
                    bool failed = false;

                    try {
                        co_await h(req, resp);
                    } catch (const std::exception&) {
                        failed = true;
                    } catch (...) {
                        failed = true;
                    }

                    if (failed) {
                        resp = SServerResponse{};
                        resp.setText("Internal Server Error\n", 500);
                    }
                } else {
                    resp.setText(std::string(ReasonPhrase(status)) + "\n", status);
                    if (!allow.empty()) {
                        resp.headers.set("Allow", allow);
                    }
                }

                ++served;

                // --> Skip a small unread body so the next request can be parsed; otherwise close.
                if (!body->isComplete()) {
                    if (body->error() != SBOX_OK) {
                        keepAlive = false;
                    } else if (co_await body->discard(LEFTOVER_DRAIN_LIMIT, options.bodyTimeoutMs) != SBOX_OK) {
                        keepAlive = false;
                    }
                }

                if (body->error() == -EFBIG && resp.status < 400) {
                    resp = SServerResponse{};
                    resp.setText(std::string(ReasonPhrase(413)) + "\n", 413);
                }

                if (conn.broken || stopping || resp.closeConnection) {
                    keepAlive = false;
                }

                bool ok = co_await writeResponse(conn, req, resp, keepAlive);
                if (!ok || !keepAlive) {
                    sc.linger = ok && !body->isComplete();
                    co_return;
                }
            }
        }
    };

    /* Returns a query parameter. */
    std::string SServerRequest::queryParam(std::string_view name) const {
        SQueryParams params;
        if (ParseQuery(query, params) != SBOX_OK) {
            return {};
        }

        for (const auto& [k, v] : params) {
            if (k == name) {
                return v;
            }
        }

        return {};
    }

    /* Reads the body as text. */
    TTask<int32_t> SServerRequest::readText(std::string& out) {
        co_return co_await body->readText(out, size_t(-1));
    }

    /* Reads the body as JSON. */
    TTask<int32_t> SServerRequest::readJson(CJson& out) {
        std::string text;
        int32_t r = co_await body->readText(text, size_t(-1));
        if (r != SBOX_OK) {
            co_return r;
        }

        if (lex::Trim(text).empty()) {
            out = CJson::object();
            co_return SBOX_OK;
        }

        co_return CJson::parse(text, out);
    }

    /* Sets a JSON body. */
    void SServerResponse::setJson(const CJson& value, int32_t code) {
        status = code;
        body = value.dump();
        body.push_back('\n');
        bodyStream.reset();
        headers.set("Content-Type", jsonContentType);
    }

    /* Sets a text body. */
    void SServerResponse::setText(std::string_view text, int32_t code, std::string_view contentType) {
        status = code;
        body = std::string(text);
        bodyStream.reset();
        headers.set("Content-Type", contentType);
    }

    /* Sets a streamed body. */
    void SServerResponse::setStream(IStreamPtr stream, int64_t length, std::string_view contentType) {
        body.clear();
        bodyStream = std::move(stream);
        bodyLength = length;
        headers.set("Content-Type", contentType);
    }

    /* Creates a server. */
    CHttpServer::CHttpServer(SServerOptions options) : _state(std::make_shared<SState>()) {
        _state->options = std::move(options);
    }

    /* Destroys the server. */
    CHttpServer::~CHttpServer() = default;

    /* Returns the settings. */
    SServerOptions& CHttpServer::options() noexcept {
        return _state->options;
    }

    /* Adds an exact route. */
    void CHttpServer::route(std::string_view method, std::string_view path, THandler handler) {
        _state->routes.push_back(Route{ method == "*" ? std::string() : std::string(method), std::string(path), false, std::move(handler) });
    }

    /* Adds a prefix route. */
    void CHttpServer::routePrefix(std::string_view method, std::string_view prefix, THandler handler) {
        _state->routes.push_back(Route{ method == "*" ? std::string() : std::string(method), std::string(prefix), true, std::move(handler) });
    }

    /* Sets the fallback handler. */
    void CHttpServer::fallback(THandler handler) {
        _state->fallback = std::move(handler);
    }

    /* Accept loop. */
    TTask<int32_t> CHttpServer::serve(CListener& listener) {
        std::shared_ptr<SState> state = _state;
        if (state->serving) {
            co_return -EBUSY;
        }

        // --> `stopping` is not reset here: a stop() issued before this task first ran (spawn
        // starts it later) must still end it.
        state->serving = true;
        state->listener = &listener;

        int32_t result = SBOX_OK;

        while (!state->stopping) {
            CSocket sock;
            int32_t r = co_await listener.accept(sock);

            if (r != SBOX_OK) {
                if (state->stopping) {
                    break;
                }

                if (r == -EMFILE || r == -ENFILE || r == -ENOBUFS || r == -ENOMEM) {
                    // --> Out of descriptors: back off instead of spinning.
                    co_await CEventLoop::current()->sleepFor(50);
                    continue;
                }

                result = r;
                break;
            }

            if (state->conns.size() >= state->options.maxConnections) {
                sock.close();
                continue;
            }

            SEndpoint peer = sock.remoteEndpoint();
            if (peer.family() == AF_INET || peer.family() == AF_INET6) {
                int one = 1;
                ::setsockopt(sock.nativeHandle(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            }

            auto shared = std::make_shared<CSocket>(std::move(sock));
            CEventLoop::current()->spawn(SState::runConnection(state, std::move(shared), peer));
        }

        state->stopping = true;
        state->listener = nullptr;
        listener.close();
        state->closeConnections(false);

        co_await SState::DrainAwaiter{ state.get() };

        state->serving = false;
        state->stopping = false;
        co_return result;
    }

    /* Stops serving. */
    void CHttpServer::stop(bool force) noexcept {
        _state->stopping = true;

        if (_state->listener) {
            _state->listener->close();
        }

        _state->closeConnections(force);
    }

    /* Returns true while serving. */
    bool CHttpServer::isServing() const noexcept {
        return _state->serving;
    }

    /* Counts open connections. */
    size_t CHttpServer::activeConnections() const noexcept {
        return _state->conns.size();
    }

    /* Counts handled requests. */
    uint64_t CHttpServer::requestsServed() const noexcept {
        return _state->served;
    }

}
}
