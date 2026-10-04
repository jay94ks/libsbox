#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <stdexcept>

using namespace sbox;
using namespace sbox::http;
using namespace testsupport;

namespace {

    /*
     * Adds the routes these tests use.
     */
    void addRoutes(CHttpServer& s) {
        s.route("GET", "/ok", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.setText("ok");
            co_return;
        });

        s.route("POST", "/ok", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            std::string body;
            int32_t r = co_await req.readText(body);
            res.setText("posted:" + std::to_string(r) + ":" + body + ":" + req.body->trailers().get("X-Sum"));
        });

        s.route("POST", "/ignore-body", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            res.setText("ignored");
            co_return;
        });

        s.route("POST", "/json", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            CJson in;
            int32_t r = co_await req.readJson(in);
            if (r != SBOX_OK) {
                CJson err = CJson::object();
                err.set("Err", "bad json");
                res.setJson(err, 400);
                co_return;
            }

            CJson out = CJson::object();
            out.set("members", int64_t(in.size()));
            res.setJson(out);
        });

        s.routePrefix("GET", "/files/", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            res.setText("files:" + req.routeRest);
            co_return;
        });

        s.routePrefix("GET", "/files/special/", [](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            res.setText("special:" + req.routeRest);
            co_return;
        });

        s.route("GET", "/throw", [](SServerRequest&, SServerResponse&) -> TTask<void> {
            co_await CEventLoop::current()->yield();
            throw std::runtime_error("handler failure");
        });

        s.route("GET", "/slow", [](SServerRequest&, SServerResponse& res) -> TTask<void> {
            co_await CEventLoop::current()->sleepFor(150);
            res.setText("slow done");
        });
    }

    /*
     * Returns the endpoint a test server listens on.
     */
    SEndpoint endpointOf(const TestServer& srv) {
        return srv.listener.localEndpoint();
    }

    /*
     * Returns the status code of the first response in `raw`, or 0.
     */
    int32_t statusOf(const std::string& raw) {
        if (raw.size() < 12 || raw.compare(0, 5, "HTTP/") != 0) {
            return 0;
        }

        return std::atoi(raw.c_str() + 9);
    }

    /*
     * Counts occurrences of `needle`.
     */
    size_t countOf(const std::string& hay, const std::string& needle) {
        size_t n = 0;
        for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1)) {
            ++n;
        }

        return n;
    }

}

TEST_CASE("protocol errors get the right status and close the connection") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SServerOptions opts;
        opts.maxHeaderBytes = 1024;
        opts.maxBodyBytes = 100;
        TestServer srv(opts);
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        SEndpoint ep = endpointOf(srv);

        struct Case {
            std::string request;
            int32_t status;
        };

        std::vector<Case> cases = {
            { "GET /ok HTTP/1.1\r\nHost: a\r\nX-Big: " + std::string(2000, 'x') + "\r\n\r\n", 431 },
            { "GET /" + std::string(2000, 'x') + " HTTP/1.1\r\nHost: a\r\n\r\n", 414 },
            { "POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 101\r\n\r\n", 413 },
            { "GET /ok HTTP/1.1\r\nHost: a\r\nBad Header\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1\r\nHost : a\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1\r\nHost: a\r\nX: a\r\n folded\r\n\r\n", 400 },
            { "POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", 400 },
            { "POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", 501 },
            { "POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 2\r\n\r\n", 400 },
            { "GET /ok HTTP/2.0\r\nHost: a\r\n\r\n", 505 },
            { "GET  /ok HTTP/1.1\r\nHost: a\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1 extra\r\nHost: a\r\n\r\n", 400 },
            { "GET ok HTTP/1.1\r\nHost: a\r\n\r\n", 400 },
            { "G(T /ok HTTP/1.1\r\nHost: a\r\n\r\n", 400 },
            { "GET /ok HTTP/1.1\r\nHost: a\r\nExpect: something\r\n\r\n", 417 },
        };

        for (const Case& c : cases) {
            std::string raw = co_await rawExchange(ep, c.request);
            CAPTURE(c.request.substr(0, 60));
            CHECK(statusOf(raw) == c.status);
            CHECK(raw.find("Connection: close\r\n") != std::string::npos);
        }

        // --> A chunked body over the limit fails the read; the handler's answer becomes 413.
        std::string chunked = "POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
            "64\r\n" + std::string(100, 'a') + "\r\n1\r\nb\r\n0\r\n\r\n";
        std::string raw = co_await rawExchange(ep, chunked);
        CHECK(statusOf(raw) == 413);

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("routing: exact, prefix, 404, 405 and HEAD") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        {
            CHttpClient client;
            SResponse res;
            std::string text;

            SRequest a;
            REQUIRE(a.setUrl(srv.base() + "/files/a/b.txt") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(a), res, text) == SBOX_OK);
            CHECK(text == "files:a/b.txt");

            SRequest b;
            REQUIRE(b.setUrl(srv.base() + "/files/special/x") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(b), res, text) == SBOX_OK);
            CHECK(text == "special:x");

            SRequest c;
            REQUIRE(c.setUrl(srv.base() + "/nothing") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(c), res, text) == SBOX_OK);
            CHECK(res.status == 404);

            SRequest d;
            d.method = "DELETE";
            REQUIRE(d.setUrl(srv.base() + "/ok") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(d), res, text) == SBOX_OK);
            CHECK(res.status == 405);
            CHECK(res.headers.get("Allow") == "GET, POST");

            SRequest e;
            e.method = "HEAD";
            REQUIRE(e.setUrl(srv.base() + "/ok") == SBOX_OK);
            REQUIRE(co_await client.send(std::move(e), res) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(res.headers.get("Content-Length") == "2");
            CHECK(res.body->isComplete());

            SRequest f;
            REQUIRE(f.setUrl(srv.base() + "/throw") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(f), res, text) == SBOX_OK);
            CHECK(res.status == 500);

            // --> All of the above ran on one keep-alive connection.
            CHECK(client.connectionsOpened() == 1);
        }

        srv.server.fallback([](SServerRequest& req, SServerResponse& res) -> TTask<void> {
            res.setText("fallback:" + req.path, 418);
            co_return;
        });

        {
            CHttpClient client;
            SResponse res;
            std::string text;
            SRequest a;
            REQUIRE(a.setUrl(srv.base() + "/elsewhere") == SBOX_OK);
            REQUIRE(co_await client.fetch(std::move(a), res, text) == SBOX_OK);
            CHECK(res.status == 418);
            CHECK(text == "fallback:/elsewhere");
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("request bodies: chunked with trailers, unread, JSON, Expect") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        SEndpoint ep = endpointOf(srv);

        std::string raw = co_await rawExchange(ep,
            "POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
            "3\r\nabc\r\n2;ext\r\nde\r\n0\r\nX-Sum: 5\r\n\r\n"
            "POST /ignore-body HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nxxxx"
            "GET /ok HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");

        // --> Three pipelined requests, the unread body skipped in between.
        CHECK(countOf(raw, "HTTP/1.1 200 OK") == 3);
        CHECK(raw.find("posted:0:abcde:5") != std::string::npos);
        CHECK(raw.find("ignored") != std::string::npos);
        CHECK(raw.find("\r\n\r\nok") != std::string::npos);

        raw = co_await rawExchange(ep,
            "POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nhello");
        CHECK(raw.rfind("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n", 0) == 0);
        CHECK(raw.find("posted:0:hello:") != std::string::npos);

        {
            CHttpClient client;
            SResponse res;

            SRequest good;
            good.method = "POST";
            REQUIRE(good.setUrl(srv.base() + "/json") == SBOX_OK);
            good.setBody("{\"a\":1,\"b\":2}", "application/json");
            CJson out;
            REQUIRE(co_await client.send(std::move(good), res) == SBOX_OK);
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(out.get("members").asInt() == 2);

            SRequest empty;
            empty.method = "POST";
            REQUIRE(empty.setUrl(srv.base() + "/json") == SBOX_OK);
            REQUIRE(co_await client.send(std::move(empty), res) == SBOX_OK);
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(res.status == 200);
            CHECK(out.get("members").asInt() == 0);

            SRequest bad;
            bad.method = "POST";
            REQUIRE(bad.setUrl(srv.base() + "/json") == SBOX_OK);
            bad.setBody("{nope", "application/json");
            REQUIRE(co_await client.send(std::move(bad), res) == SBOX_OK);
            REQUIRE(co_await res.readJson(out) == SBOX_OK);
            CHECK(res.status == 400);
            CHECK(out.get("Err").asString() == "bad json");
        }

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("HTTP/1.0 connection handling") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        SEndpoint ep = endpointOf(srv);

        std::string raw = co_await rawExchange(ep, "GET /ok HTTP/1.0\r\n\r\n");
        CHECK(statusOf(raw) == 200);
        CHECK(raw.find("Connection: close\r\n") != std::string::npos);

        raw = co_await rawExchange(ep, "GET /ok HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /ok HTTP/1.0\r\n\r\n");
        CHECK(countOf(raw, "HTTP/1.1 200 OK") == 2);
        CHECK(raw.find("Connection: keep-alive\r\n") != std::string::npos);

        // --> Leading empty lines before a request line are tolerated.
        raw = co_await rawExchange(ep, "\r\n\r\nGET /ok HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        CHECK(statusOf(raw) == 200);

        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("idle keep-alive connections time out") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SServerOptions opts;
        opts.keepAliveTimeoutMs = 50;
        opts.headerTimeoutMs = 50;
        TestServer srv(opts);
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        SEndpoint ep = endpointOf(srv);

        int64_t start = CEventLoop::nowMs();
        std::string raw = co_await rawExchange(ep, "GET /ok HTTP/1.1\r\nHost: a\r\n\r\n", 3000);
        CHECK(statusOf(raw) == 200);
        CHECK(CEventLoop::nowMs() - start < 2000);

        // --> A client that never finishes its head is dropped after the header timeout.
        start = CEventLoop::nowMs();
        raw = co_await rawExchange(ep, "GET /ok HTTP/1.1\r\nHost:", 3000);
        CHECK(raw.empty());
        CHECK(CEventLoop::nowMs() - start < 2000);

        co_await CEventLoop::current()->sleepFor(20);
        CHECK(srv.server.activeConnections() == 0);
        co_await srv.stop();
    };

    loop.run(body());
}

TEST_CASE("graceful stop lets a request in progress finish") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);

        CHttpClient idleClient;
        SResponse first;
        std::string text;
        SRequest warm;
        REQUIRE(warm.setUrl(srv.base() + "/ok") == SBOX_OK);
        REQUIRE(co_await idleClient.fetch(std::move(warm), first, text) == SBOX_OK);
        CHECK(srv.server.activeConnections() == 1);

        bool slowDone = false;
        int32_t slowResult = 1;
        std::string slowText;
        std::string slowConnection;

        CEventLoop::current()->spawn([](std::string url, bool* done, int32_t* result, std::string* out, std::string* conn) -> TTask<void> {
            CHttpClient client;
            SResponse res;
            SRequest req;
            req.setUrl(url);
            *result = co_await client.fetch(std::move(req), res, *out);
            *conn = res.headers.get("Connection");
            *done = true;
        }(srv.base() + "/slow", &slowDone, &slowResult, &slowText, &slowConnection));

        co_await CEventLoop::current()->sleepFor(50);
        CHECK(srv.server.activeConnections() == 2);

        int64_t start = CEventLoop::nowMs();
        co_await srv.stop();

        CHECK(slowDone);
        CHECK(slowResult == SBOX_OK);
        CHECK(slowText == "slow done");
        CHECK(slowConnection == "close");
        CHECK(srv.result == SBOX_OK);
        CHECK(srv.server.activeConnections() == 0);
        CHECK(CEventLoop::nowMs() - start < 1000);

        // --> The listener is closed: new connections are refused.
        SResponse res;
        CHECK(co_await idleClient.get(srv.base() + "/ok", res) == -ECONNREFUSED);
    };

    loop.run(body());
}

TEST_CASE("forced stop and connection limit") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SServerOptions opts;
        opts.maxConnections = 1;
        TestServer srv(opts);
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        SEndpoint ep = endpointOf(srv);

        CSocket holder;
        REQUIRE(co_await holder.connect(ep, 1000) == SBOX_OK);
        co_await CEventLoop::current()->sleepFor(20);
        CHECK(srv.server.activeConnections() == 1);

        // --> Over the limit: accepted and closed at once.
        std::string raw = co_await rawExchange(ep, "GET /ok HTTP/1.1\r\nHost: a\r\n\r\n", 1000);
        CHECK(raw.empty());

        bool slowDone = false;
        holder.close();
        co_await CEventLoop::current()->sleepFor(20);

        CEventLoop::current()->spawn([](SEndpoint target, bool* done) -> TTask<void> {
            co_await rawExchange(target, "GET /slow HTTP/1.1\r\nHost: a\r\n\r\n", 2000);
            *done = true;
        }(ep, &slowDone));

        co_await CEventLoop::current()->sleepFor(30);
        int64_t start = CEventLoop::nowMs();
        co_await srv.stop(true);
        CHECK(CEventLoop::nowMs() - start < 1000);

        while (!slowDone) {
            co_await CEventLoop::current()->sleepFor(5);
        }
    };

    loop.run(body());
}

TEST_CASE("serve rejects a second concurrent call and can run again after stop") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        TestServer srv;
        addRoutes(srv.server);
        REQUIRE(srv.startTcp() == SBOX_OK);
        co_await CEventLoop::current()->yield();

        CListener other;
        SEndpoint ep;
        SEndpoint::fromIp("127.0.0.1", 0, ep);
        REQUIRE(other.listen(ep) == SBOX_OK);
        CHECK(co_await srv.server.serve(other) == -EBUSY);
        co_await srv.stop();
        CHECK_FALSE(srv.server.isServing());

        // --> Restart on a fresh listener.
        srv.done = false;
        REQUIRE(srv.startTcp() == SBOX_OK);
        CHttpClient client;
        SResponse res;
        std::string text;
        SRequest req;
        REQUIRE(req.setUrl(srv.base() + "/ok") == SBOX_OK);
        REQUIRE(co_await client.fetch(std::move(req), res, text) == SBOX_OK);
        CHECK(text == "ok");
        co_await srv.stop();
    };

    loop.run(body());
}
