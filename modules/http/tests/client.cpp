#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/http/auth.hpp>
#include <sys/resource.h>

using namespace sbox;
using namespace sbox::http;
using namespace testsupport;

namespace {

    constexpr uint64_t BIG_DOWNLOAD = uint64_t(64) << 20;
    constexpr uint64_t BIG_UPLOAD = uint64_t(32) << 20;

    /*
     * Returns the peak resident set size in KiB.
     */
    long peakRssKb() {
        struct rusage ru{};
        ::getrusage(RUSAGE_SELF, &ru);
        return ru.ru_maxrss;
    }

    /*
     * Adds the routes most tests use.
     */
    void addCommonRoutes(CHttpServer& s) {
        s.route("GET", "/hello", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            CJson info = CJson::object();
            info.set("host", req.headers.get("Host"));
            info.set("ua", req.headers.get("User-Agent"));
            info.set("auth", req.headers.get("Authorization"));
            info.set("query", req.queryParam("q"));
            res.setJson(info);
            co_return;
        });

        s.route("POST", "/echo", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            std::string body;
            int32_t r = co_await req.readText(body);
            res.headers.set("X-Method", req.method);
            res.headers.set("X-Read", std::to_string(r));
            res.setText(body, 200, req.headers.get("Content-Type", "application/octet-stream"));
        });

        s.route("*", "/method", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            std::string body;
            co_await req.readText(body);
            res.setText(req.method + ":" + body);
        });

        s.route("GET", "/big", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.setStream(std::make_shared<PatternStream>(BIG_DOWNLOAD), int64_t(BIG_DOWNLOAD));
            co_return;
        });

        s.route("GET", "/big-chunked", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.setStream(std::make_shared<PatternStream>(3 << 20), -1);
            co_return;
        });

        s.route("PUT", "/upload", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            size_t maxChunk = 0;
            int64_t n = co_await verifyPattern(*req.body, maxChunk);
            CJson out = CJson::object();
            out.set("bytes", n);
            out.set("chunked", req.headers.hasToken("Transfer-Encoding", "chunked"));
            res.setJson(out);
        });

        s.route("GET", "/range", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            const uint64_t size = 1000;
            std::string all;
            for (uint64_t i = 0; i < size; ++i) {
                all.push_back(char(patternByte(i)));
            }

            const std::string* range = req.headers.find("Range");
            if (!range) {
                res.setText(all, 200, "application/octet-stream");
                co_return;
            }

            uint64_t first = 0, last = 0;
            if (ParseRange(*range, size, first, last) != SBOX_OK) {
                res.setText("", 416);
                SContentRange cr;
                cr.unsatisfied = true;
                cr.completeLength = int64_t(size);
                res.headers.set("Content-Range", cr.toString());
                co_return;
            }

            SContentRange cr{ first, last, int64_t(size), false };
            res.setText(all.substr(first, last - first + 1), 206, "application/octet-stream");
            res.headers.set("Content-Range", cr.toString());
        });

        s.route("HEAD", "/head", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.headers.set("Content-Length", "12345");
            res.headers.set("Docker-Content-Digest", "sha256:abc");
            co_return;
        });

        s.route("GET", "/close", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.closeConnection = true;
            res.setText("bye");
            co_return;
        });
    }

    /*
     * Accepts one connection, reads the request head, writes `response` raw and closes after
     * `holdMs`.
     */
    TTask<void> rawServeOnce(CListener* listener, std::string response, std::string* seen, int64_t holdMs) {
        CSocket s;
        if (co_await listener->accept(s, 5000) != SBOX_OK) {
            co_return;
        }

        std::string head = co_await readHead(s);
        if (seen) {
            *seen = head;
        }

        if (!response.empty()) {
            co_await s.send(BytesOf(response));
        }

        if (holdMs > 0) {
            co_await CEventLoop::current()->sleepFor(holdMs);
        }

        s.close();
    }

    /*
     * Runs one GET against a raw server answering `response`; returns the send result and
     * (when it succeeded) the body read result through `bodyResult`.
     */
    TTask<int32_t> getFromRaw(std::string response, int32_t& bodyResult, std::string& body, SClientOptions options = {}, int64_t holdMs = 0) {
        CListener listener;
        SEndpoint ep;
        SEndpoint::fromIp("127.0.0.1", 0, ep);
        REQUIRE(listener.listen(ep) == SBOX_OK);

        bool done = false;
        CEventLoop::current()->spawn([](CListener* l, std::string resp, int64_t hold, bool* flag) -> TTask<void> {
            co_await rawServeOnce(l, std::move(resp), nullptr, hold);
            *flag = true;
        }(&listener, response, holdMs, &done));

        CHttpClient client(options);
        SResponse res;
        int32_t r = co_await client.get("http://127.0.0.1:" + std::to_string(listener.localEndpoint().port()) + "/x", res);

        bodyResult = 1;
        body.clear();
        if (r == SBOX_OK) {
            bodyResult = co_await res.body->readText(body);
        }

        while (!done) {
            co_await CEventLoop::current()->sleepFor(1);
        }

        co_return r;
    }

    /**
     * Tiny forward proxy: CONNECT tunnels to numeric endpoints, anything else gets a 200 whose
     * body echoes the request head.
     */
    struct MiniProxy {
        CListener listener;
        std::vector<std::string> heads;
        bool done = false;

        int32_t start() {
            SEndpoint ep;
            SEndpoint::fromIp("127.0.0.1", 0, ep);
            int32_t r = listener.listen(ep);
            if (r != SBOX_OK) {
                return r;
            }

            CEventLoop::current()->spawn(acceptLoop(this));
            return SBOX_OK;
        }

        std::string url(const char* auth = nullptr) const {
            return std::string("http://") + (auth ? auth : "") + "127.0.0.1:" + std::to_string(listener.localEndpoint().port());
        }

        static TTask<void> acceptLoop(MiniProxy* self) {
            while (true) {
                auto s = std::make_shared<CSocket>();
                if (co_await self->listener.accept(*s) != SBOX_OK) {
                    break;
                }

                CEventLoop::current()->spawn(handle(self, s));
            }

            self->done = true;
        }

        static TTask<void> handle(MiniProxy* self, std::shared_ptr<CSocket> s) {
            std::string head = co_await readHead(*s);
            self->heads.push_back(head);

            if (head.rfind("CONNECT ", 0) == 0) {
                std::string authority = head.substr(8, head.find(' ', 8) - 8);
                SEndpoint ep;
                auto up = std::make_shared<CSocket>();

                if (SEndpoint::parse(authority, ep) != SBOX_OK || co_await up->connect(ep, 2000) != SBOX_OK) {
                    co_await s->send(BytesOf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"));
                    s->close();
                    co_return;
                }

                co_await s->send(BytesOf("HTTP/1.1 200 Connection established\r\n\r\n"));
                CEventLoop::current()->spawn(pump(s, up));
                co_await pump(up, s);
                co_return;
            }

            std::string firstLine = head.substr(0, head.find("\r\n"));
            std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(firstLine.size()) + "\r\nConnection: close\r\n\r\n" + firstLine;
            co_await s->send(BytesOf(resp));
            s->close();
        }

        TTask<void> stop() {
            listener.close();
            while (!done) {
                co_await CEventLoop::current()->sleepFor(1);
            }
        }
    };

}

TEST_CASE("streams a large download without buffering it") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            long before = peakRssKb();

            SResponse res;
            REQUIRE(co_await client.get(srv.base() + "/big", res) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.body->contentLength() == int64_t(BIG_DOWNLOAD));

            size_t maxChunk = 0;
            int64_t n = co_await verifyPattern(*res.body, maxChunk);
            CHECK(n == int64_t(BIG_DOWNLOAD));
            CHECK(maxChunk <= 65536);
            CHECK(res.body->isComplete());

            long grown = peakRssKb() - before;
            MESSAGE("peak RSS growth during 64 MiB download: " << grown << " KiB");
            CHECK(grown < 24 * 1024);

            // --> The connection went back to the pool once the body ended.
            CHECK(client.idleConnections() == 1);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("streams a chunked upload and a chunked download") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SServerOptions opts;
        opts.maxBodyBytes = 0;
        TestServer srv(opts);
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;

            SRequest req;
            req.method = "PUT";
            REQUIRE(req.setUrl(srv.base() + "/upload") == SBOX_OK);
            req.setBodyStream(std::make_shared<PatternStream>(BIG_UPLOAD), -1);

            SResponse res;
            REQUIRE(co_await client.send(std::move(req), res) == SBOX_OK);
            CJson out;
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(out.get("bytes").asInt() == int64_t(BIG_UPLOAD));
            CHECK(out.get("chunked").asBool());

            SRequest sized;
            sized.method = "PUT";
            REQUIRE(sized.setUrl(srv.base() + "/upload") == SBOX_OK);
            sized.setBodyStream(std::make_shared<PatternStream>(1 << 20), 1 << 20);
            REQUIRE(co_await client.send(std::move(sized), res) == SBOX_OK);
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(out.get("bytes").asInt() == (1 << 20));
            CHECK_FALSE(out.get("chunked").asBool());

            REQUIRE(co_await client.get(srv.base() + "/big-chunked", res) == SBOX_OK);
            CHECK(res.headers.hasToken("Transfer-Encoding", "chunked"));
            CHECK(res.body->contentLength() == -1);
            size_t maxChunk = 0;
            CHECK(co_await verifyPattern(*res.body, maxChunk) == (3 << 20));

            CHECK(client.connectionsOpened() == 1);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("round trip over TCP with JSON, query and headers") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            SResponse res;
            REQUIRE(co_await client.get(srv.base() + "/hello?q=a%20b", res) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.isSuccess());
            CHECK(res.reason == "OK");
            CHECK(res.headers.get("Content-Type") == "application/json");
            CJson info;
            REQUIRE(co_await res.readJson(info) == SBOX_OK);
            CHECK(info.get("host").asString() == "127.0.0.1:" + std::to_string(srv.port()));
            CHECK(info.get("ua").asString() == "libsbox-http/1");
            CHECK(info.get("query").asString() == "a b");

            SRequest post;
            post.method = "POST";
            REQUIRE(post.setUrl(srv.base() + "/echo") == SBOX_OK);
            CJson payload = CJson::object();
            payload.set("Name", "vol1");
            post.setJson(payload);

            std::string text;
            REQUIRE(co_await client.fetch(std::move(post), res, text) == SBOX_OK);
            CHECK(text == "{\"Name\":\"vol1\"}");
            CHECK(res.headers.get("Content-Type") == "application/json");

            REQUIRE(co_await client.get(srv.base() + "/missing", res) == SBOX_OK);
            CHECK(res.status == 404);
            CHECK(co_await res.body->discard() == SBOX_OK);

            // --> Credentials in the URL become Basic auth.
            REQUIRE(co_await client.get("http://alice:s%3Acret@127.0.0.1:" + std::to_string(srv.port()) + "/hello", res) == SBOX_OK);
            REQUIRE(co_await res.readJson(info) == SBOX_OK);
            CHECK(info.get("auth").asString() == EncodeBasicAuth("alice", "s:cret"));

            CHECK(client.connectionsOpened() == 1);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("Docker plugin style round trip over a UNIX socket") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TempDir dir;
        REQUIRE(!dir.path.empty());
        std::string sock = dir.path + "/plugin.sock";

        SServerOptions opts;
        opts.jsonContentType = "application/vnd.docker.plugins.v1.2+json";
        TestServer srv(opts);

        srv.server.route("POST", "/Plugin.Activate", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            CJson in;
            int32_t r = co_await req.readJson(in);
            CJson out = CJson::object();
            out.set("Implements", CJson::fromStrings({ "VolumeDriver" }));
            out.set("ReadResult", r);
            res.setJson(out);
        });

        srv.server.route("POST", "/VolumeDriver.Create", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            CJson in;
            co_await req.readJson(in);
            CJson out = CJson::object();
            out.set("Err", in.get("Name").asString() == "v1" ? "" : "bad name");
            res.setJson(out);
        });

        SEndpoint ep;
        REQUIRE(SEndpoint::fromUnix(sock, ep) == SBOX_OK);
        REQUIRE(srv.start(ep) == SBOX_OK);

        {
            CHttpClient client;

            SRequest act;
            act.method = "POST";
            act.unixSocket = sock;
            REQUIRE(act.setUrl("http://plugin/Plugin.Activate") == SBOX_OK);
            act.headers.set("Accept", "application/vnd.docker.plugins.v1.2+json");

            SResponse res;
            REQUIRE(co_await client.send(std::move(act), res) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.headers.get("Content-Type") == "application/vnd.docker.plugins.v1.2+json");
            CJson out;
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(out.get("Implements").at(0).asString() == "VolumeDriver");
            CHECK(out.get("ReadResult").asInt() == 0);

            SRequest create;
            create.method = "POST";
            REQUIRE(create.setUrl("http+unix://" + PercentEncode(sock) + "/VolumeDriver.Create") == SBOX_OK);
            CJson in = CJson::object();
            in.set("Name", "v1");
            create.setJson(in, "application/vnd.docker.plugins.v1.2+json");

            REQUIRE(co_await client.send(std::move(create), res) == SBOX_OK);
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(out.get("Err").asString() == "");

            // --> Both forms share one pooled UNIX connection.
            CHECK(client.connectionsOpened() == 1);
            CHECK(client.idleConnections() == 1);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("keep-alive reuses one connection; Connection: close does not") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            for (int32_t i = 0; i < 5; ++i) {
                SResponse res;
                std::string text;
                SRequest req;
                REQUIRE(req.setUrl(srv.base() + "/hello") == SBOX_OK);
                REQUIRE(co_await client.fetch(std::move(req), res, text) == SBOX_OK);
                CHECK(res.status == 200);
            }

            CHECK(client.connectionsOpened() == 1);
            CHECK(client.idleConnections() == 1);
            CHECK(srv.server.activeConnections() == 1);
            CHECK(srv.server.requestsServed() == 5);

            // --> A HEAD response has no body even with Content-Length; the connection stays.
            SRequest head;
            head.method = "HEAD";
            REQUIRE(head.setUrl(srv.base() + "/head") == SBOX_OK);
            SResponse res;
            REQUIRE(co_await client.send(std::move(head), res) == SBOX_OK);
            CHECK(res.headers.get("Content-Length") == "12345");
            CHECK(res.headers.get("Docker-Content-Digest") == "sha256:abc");
            CHECK(res.body->isComplete());
            CHECK(client.connectionsOpened() == 1);
            CHECK(client.idleConnections() == 1);

            std::string text;
            SRequest closeReq;
            REQUIRE(closeReq.setUrl(srv.base() + "/close") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(closeReq), res, text) == SBOX_OK);
            CHECK(text == "bye");
            CHECK(res.headers.hasToken("Connection", "close"));
            CHECK(client.idleConnections() == 0);

            REQUIRE(co_await client.get(srv.base() + "/hello", res) == SBOX_OK);
            CHECK(co_await res.body->discard() == SBOX_OK);
            CHECK(client.connectionsOpened() == 2);

            // --> An unread body that is closed drops its connection.
            REQUIRE(co_await client.get(srv.base() + "/range", res) == SBOX_OK);
            res.body->close();
            CHECK(client.idleConnections() == 0);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("a pooled connection the server closed is retried once") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SServerOptions opts;
        opts.keepAliveTimeoutMs = 30;
        TestServer srv(opts);
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            SResponse res;
            std::string text;

            SRequest a;
            REQUIRE(a.setUrl(srv.base() + "/hello") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(a), res, text) == SBOX_OK);
            CHECK(client.idleConnections() == 1);

            co_await CEventLoop::current()->sleepFor(150);

            SRequest b;
            b.method = "POST";
            REQUIRE(b.setUrl(srv.base() + "/echo") == SBOX_OK);
            b.setBody("again", "text/plain");
            REQUIRE(co_await client.fetch(std::move(b), res, text) == SBOX_OK);
            CHECK(text == "again");
            CHECK(client.connectionsOpened() == 2);
        }

        {
            // --> Pool entries older than the pool idle timeout are not used at all.
            CHttpClient client;
            client.options().poolIdleTimeoutMs = 10;
            SResponse res;
            REQUIRE(co_await client.get(srv.base() + "/hello", res) == SBOX_OK);
            CHECK(co_await res.body->discard() == SBOX_OK);
            co_await CEventLoop::current()->sleepFor(20);
            REQUIRE(co_await client.get(srv.base() + "/hello", res) == SBOX_OK);
            CHECK(co_await res.body->discard() == SBOX_OK);
            CHECK(client.connectionsOpened() == 2);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("redirect to another host drops Authorization") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer cdn;
        cdn.server.route("GET", "/cdn/blob", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            res.headers.set("X-Saw-Auth", req.headers.has("Authorization") ? "yes" : "no");
            res.headers.set("X-Saw-Cookie", req.headers.has("Cookie") ? "yes" : "no");
            res.setText("blob-bytes:" + req.queryParam("sig"));
            co_return;
        });

        // --> 127.0.0.2 is a different host on the loopback network.
        REQUIRE(cdn.startTcp("127.0.0.2") == SBOX_OK);
        std::string cdnBase = cdn.base("127.0.0.2");

        TestServer registry;
        registry.server.route("GET", "/v2/x/blobs/sha256:ab", [cdnBase](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            if (!req.headers.has("Authorization")) {
                res.setText("no auth", 401);
                co_return;
            }

            res.status = 307;
            res.headers.set("Location", cdnBase + "/cdn/blob?sig=s1");
            co_return;
        });

        registry.server.route("GET", "/v2/x/moved", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.status = 301;
            res.headers.set("Location", "../x/final");
            res.setText("moved body that gets drained", 301);
            res.headers.set("Location", "../x/final");
            co_return;
        });

        registry.server.route("GET", "/v2/x/final", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            res.headers.set("X-Saw-Auth", req.headers.has("Authorization") ? "yes" : "no");
            res.setText("final");
            co_return;
        });

        REQUIRE(registry.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            CHeaders headers;
            headers.set("Authorization", "Bearer secret-token");
            headers.set("Cookie", "c=1");

            SResponse res;
            REQUIRE(co_await client.get(registry.base() + "/v2/x/blobs/sha256:ab", res, headers) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.redirects == 1);
            CHECK(res.url.host == "127.0.0.2");
            CHECK(res.headers.get("X-Saw-Auth") == "no");
            CHECK(res.headers.get("X-Saw-Cookie") == "no");
            std::string text;
            REQUIRE(co_await res.readText(text) == SBOX_OK);
            CHECK(text == "blob-bytes:s1");

            // --> Same origin: the header stays (relative Location, 301 GET stays GET).
            REQUIRE(co_await client.get(registry.base() + "/v2/x/moved", res, headers) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.url.path == "/v2/x/final");
            CHECK(res.headers.get("X-Saw-Auth") == "yes");
            REQUIRE(co_await res.readText(text) == SBOX_OK);
            CHECK(text == "final");

            // --> The drained redirect body let the connection be reused.
            CHECK(client.connectionsOpened() == 2);

            SRequest manual;
            manual.followRedirects = false;
            manual.headers = headers;
            REQUIRE(manual.setUrl(registry.base() + "/v2/x/blobs/sha256:ab") == SBOX_OK);
            REQUIRE(co_await client.send(std::move(manual), res) == SBOX_OK);
            CHECK(res.status == 307);
            CHECK(res.headers.get("Location") == cdnBase + "/cdn/blob?sig=s1");
            CHECK(co_await res.body->discard() == SBOX_OK);
        }

        co_await cdn.stop();
        co_await registry.stop();
    };

    loop.run(body());
}

TEST_CASE("redirect method and body rules") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);

        for (int32_t code : { 301, 302, 303, 307, 308 }) {
            srv.server.route("*", "/r" + std::to_string(code), [code](SServerRequest& req, SServerResponse& res) -> TTask<void> {
                co_await req.body->discard();
                res.status = code;
                res.headers.set("Location", "/method");
            });
        }

        srv.server.route("*", "/loop", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.status = 302;
            res.headers.set("Location", "/loop");
            co_return;
        });

        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;

            auto post = [&](int32_t code) -> TTask<std::string> {
                SRequest req;
                req.method = "POST";
                REQUIRE(req.setUrl(srv.base() + "/r" + std::to_string(code)) == SBOX_OK);
                req.setBody("payload", "text/plain");
                SResponse res;
                std::string text;
                REQUIRE(co_await client.fetch(std::move(req), res, text) == SBOX_OK);
                co_return text;
            };

            CHECK(co_await post(301) == "GET:");
            CHECK(co_await post(302) == "GET:");
            CHECK(co_await post(303) == "GET:");
            CHECK(co_await post(307) == "POST:payload");
            CHECK(co_await post(308) == "POST:payload");

            SRequest put;
            put.method = "PUT";
            REQUIRE(put.setUrl(srv.base() + "/r302") == SBOX_OK);
            put.setBody("p2");
            SResponse res;
            std::string text;
            REQUIRE(co_await client.fetch(std::move(put), res, text) == SBOX_OK);
            CHECK(text == "PUT:p2");

            // --> A streamed body cannot be replayed: the 307 itself comes back.
            SRequest streamed;
            streamed.method = "POST";
            REQUIRE(streamed.setUrl(srv.base() + "/r307") == SBOX_OK);
            streamed.setBodyStream(std::make_shared<PatternStream>(1000), 1000);
            REQUIRE(co_await client.send(std::move(streamed), res) == SBOX_OK);
            CHECK(res.status == 307);
            co_await res.body->discard();

            client.options().maxRedirects = 3;
            CHECK(co_await client.get(srv.base() + "/loop", res) == -ELOOP);
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("range requests for resuming") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            CHeaders h;
            h.set("Range", FormatRange(990));
            SResponse res;
            REQUIRE(co_await client.get(srv.base() + "/range", res, h) == SBOX_OK);
            CHECK(res.status == 206);
            SContentRange cr;
            REQUIRE(SContentRange::parse(res.headers.get("Content-Range"), cr) == SBOX_OK);
            CHECK(cr.first == 990);
            CHECK(cr.last == 999);
            CHECK(cr.completeLength == 1000);
            std::string text;
            REQUIRE(co_await res.readText(text) == SBOX_OK);
            REQUIRE(text.size() == 10);
            CHECK(uint8_t(text[0]) == patternByte(990));

            h.set("Range", FormatRange(5000));
            REQUIRE(co_await client.get(srv.base() + "/range", res, h) == SBOX_OK);
            CHECK(res.status == 416);
            REQUIRE(SContentRange::parse(res.headers.get("Content-Range"), cr) == SBOX_OK);
            CHECK(cr.unsatisfied);
            co_await res.body->discard();
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("malformed responses are rejected") {
    CEventLoop loop;
    int32_t br = 0;
    std::string text;

    CHECK(loop.run(getFromRaw("HTTP/1.1 2000 OK\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/2 200\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 099 Low\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("garbage\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nBad Header\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nX : y\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\n", br, text)) == -EBADMSG);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", br, text)) == -ENOTSUP);
    CHECK(loop.run(getFromRaw("", br, text)) == -ECONNRESET);
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nX-Partial: y\r\n", br, text)) == -ECONNRESET);

    SClientOptions small;
    small.maxHeaderBytes = 1024;
    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nX-Big: " + std::string(4000, 'a') + "\r\n\r\n", br, text, small)) == -EMSGSIZE);

    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", br, text)) == SBOX_OK);
    CHECK(br == -EBADMSG);

    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", br, text)) == SBOX_OK);
    CHECK(br == -ECONNRESET);
}

TEST_CASE("lenient but valid responses are accepted") {
    CEventLoop loop;
    int32_t br = 0;
    std::string text;

    // --> Interim 1xx responses are skipped; obs-fold is unfolded; LF-only lines work.
    CHECK(loop.run(getFromRaw("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Fold: a\r\n  b\r\nContent-Length: 2\r\n\r\nok", br, text)) == SBOX_OK);
    CHECK(br == SBOX_OK);
    CHECK(text == "ok");

    CHECK(loop.run(getFromRaw("HTTP/1.0 200\nContent-Type: text/plain\n\nuntil close", br, text)) == SBOX_OK);
    CHECK(br == SBOX_OK);
    CHECK(text == "until close");

    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nDigest: abc\r\n\r\n", br, text)) == SBOX_OK);
    CHECK(br == SBOX_OK);
    CHECK(text == "Wikipedia");
}

TEST_CASE("header and body timeouts") {
    CEventLoop loop;
    int32_t br = 0;
    std::string text;

    SClientOptions fast;
    fast.headerTimeoutMs = 100;
    fast.idleTimeoutMs = 100;

    CHECK(loop.run(getFromRaw("", br, text, fast, 600)) == -ETIMEDOUT);

    CHECK(loop.run(getFromRaw("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", br, text, fast, 600)) == SBOX_OK);
    CHECK(br == -ETIMEDOUT);
}

TEST_CASE("connection failures and unsupported schemes") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CHttpClient client;
        SResponse res;

        CHECK(co_await client.get("ftp://example.com/x", res) == -EPROTONOSUPPORT);
        CHECK(co_await client.get("not a url", res) == -EINVAL);
        CHECK(co_await client.get("/relative", res) == -EPROTONOSUPPORT);

        // --> https without a TLS hook.
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        CHECK(co_await client.get("https://127.0.0.1:" + std::to_string(srv.port()) + "/hello", res) == -EPROTONOSUPPORT);

        // --> A closed port.
        uint16_t port = srv.port();
        co_await srv.stop();
        int32_t r = co_await client.get("http://127.0.0.1:" + std::to_string(port) + "/hello", res);
        CHECK(r == -ECONNREFUSED);

        SRequest bad;
        REQUIRE(bad.setUrl("http://127.0.0.1:1/") == SBOX_OK);
        bad.headers.add("X-Evil", "a\r\nInjected: 1");
        CHECK(co_await client.send(std::move(bad), res) == -EINVAL);
    };

    loop.run(body());
}

TEST_CASE("https through a pluggable TLS hook and a CONNECT proxy") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        MiniProxy proxy;
        REQUIRE(proxy.start() == SBOX_OK);

        {
            auto tls = std::make_shared<IdentityTls>();
            SClientOptions opts;
            opts.tls = tls;
            opts.proxy.httpsProxy = proxy.url("user:p%40ss@");
            CHttpClient client(opts);

            std::string url = "https://127.0.0.1:" + std::to_string(srv.port()) + "/hello";
            for (int32_t i = 0; i < 2; ++i) {
                SResponse res;
                REQUIRE(co_await client.get(url, res) == SBOX_OK);
                CHECK(res.status == 200);
                CJson info;
                REQUIRE(co_await res.readJson(info) == SBOX_OK);
                CHECK(info.get("host").asString() == "127.0.0.1:" + std::to_string(srv.port()));
            }

            // --> One tunnel, reused for the second request.
            REQUIRE(proxy.heads.size() == 1);
            std::string authority = "127.0.0.1:" + std::to_string(srv.port());
            CHECK(proxy.heads[0].rfind("CONNECT " + authority + " HTTP/1.1\r\n", 0) == 0);
            CHECK(proxy.heads[0].find("Host: " + authority + "\r\n") != std::string::npos);
            CHECK(proxy.heads[0].find("Proxy-Authorization: " + EncodeBasicAuth("user", "p@ss") + "\r\n") != std::string::npos);
            REQUIRE(tls->names.size() == 1);
            CHECK(tls->names[0] == "127.0.0.1");
            CHECK(client.connectionsOpened() == 1);

            // --> NO_PROXY sends the request directly.
            client.options().proxy.noProxy = "127.0.0.0/8";
            SResponse res;
            REQUIRE(co_await client.get(url, res) == SBOX_OK);
            co_await res.body->discard();
            CHECK(proxy.heads.size() == 1);
            CHECK(tls->names.size() == 2);
        }

        {
            // --> A proxy refusing the tunnel.
            SClientOptions opts;
            opts.tls = std::make_shared<IdentityTls>();
            opts.proxy.httpsProxy = proxy.url();
            CHttpClient client(opts);
            SResponse res;
            CHECK(co_await client.get("https://not-numeric.invalid/x", res) == -ECONNREFUSED);
        }

        co_await srv.stop();
        co_await proxy.stop();
    };

    loop.run(body());
}

TEST_CASE("plain http through a forward proxy uses absolute-form targets") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        MiniProxy proxy;
        REQUIRE(proxy.start() == SBOX_OK);

        {
            SClientOptions opts;
            opts.proxy.httpProxy = proxy.url("u:p@");
            CHttpClient client(opts);

            SResponse res;
            std::string text;
            SRequest req;
            REQUIRE(req.setUrl("http://example.invalid:8080/path?x=1#frag") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(req), res, text) == SBOX_OK);
            CHECK(text == "GET http://example.invalid:8080/path?x=1 HTTP/1.1");
            REQUIRE(proxy.heads.size() == 1);
            CHECK(proxy.heads[0].find("Host: example.invalid:8080\r\n") != std::string::npos);
            CHECK(proxy.heads[0].find("Proxy-Authorization: " + EncodeBasicAuth("u", "p") + "\r\n") != std::string::npos);
        }

        co_await proxy.stop();
    };

    loop.run(body());
}

TEST_CASE("round trip over IPv6 loopback") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addCommonRoutes(srv.server);

        SEndpoint ep;
        if (SEndpoint::fromIp("::1", 0, ep) != SBOX_OK || srv.start(ep) != SBOX_OK) {
            MESSAGE("IPv6 loopback unavailable; skipping");
            co_return;
        }

        {
            CHttpClient client;
            SResponse res;
            REQUIRE(co_await client.get("http://[::1]:" + std::to_string(srv.port()) + "/hello", res) == SBOX_OK);
            CJson info;
            REQUIRE(co_await res.readJson(info) == SBOX_OK);
            CHECK(info.get("host").asString() == "[::1]:" + std::to_string(srv.port()));
        }

        co_await srv.stop();
    };

    loop.run(body());
}
