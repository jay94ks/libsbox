#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include "wire.hpp"

using namespace sbox;
using namespace sbox::http;
using namespace testsupport;

namespace {

    /**
     * Outcome of decoding a body.
     */
    struct Decoded {
        int32_t error = SBOX_OK;
        std::string body;
        CHeaders trailers;
        size_t leftover = 0;
        bool doneCalled = false;
        bool clean = false;
    };

    /*
     * Feeds `raw` (optionally one byte at a time) through a socket pair and decodes it.
     */
    TTask<Decoded> decode(std::string raw, wire::Framing framing, uint64_t length = 0, bool trickle = false, uint64_t maxBytes = 0, size_t maxTrailer = 4096) {
        CSocket a, b;
        REQUIRE(CSocket::pair(a, b) == SBOX_OK);

        auto writer = std::make_shared<CSocket>(std::move(a));
        CEventLoop::current()->spawn([](std::shared_ptr<CSocket> w, std::string data, bool slow) -> TTask<void> {
            if (slow) {
                for (char c : data) {
                    co_await w->send(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(&c), 1));
                    co_await CEventLoop::current()->yield();
                }
            } else {
                co_await w->send(BytesOf(data));
            }

            w->shutdownWrite();
        }(writer, raw, trickle));

        auto conn = std::make_shared<wire::Connection>(std::make_shared<CSocket>(std::move(b)));
        auto body = std::make_shared<wire::Body>(conn, framing, length, 2000, maxBytes, maxTrailer);

        Decoded out;
        body->onDone = [&out](wire::ConnectionPtr, bool clean) {
            out.doneCalled = true;
            out.clean = clean;
        };

        body->settleEmpty();
        out.error = co_await body->readText(out.body, size_t(64) << 20);
        out.trailers = body->trailers();

        // --> Give the writer a chance to finish so the leftover count is stable.
        co_await CEventLoop::current()->sleepFor(5);
        out.leftover = conn->buffered();
        co_return out;
    }

}

TEST_CASE("chunked body with extensions and trailers") {
    CEventLoop loop;
    Decoded d = loop.run(decode("5\r\nhello\r\n6;ext=1;q=\"a;b\"\r\n world\r\nA \r\n0123456789\r\n0\r\nX-Trailer: yes\r\nX-Other: 2\r\n\r\n", wire::FRAME_CHUNKED));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "hello world0123456789");
    CHECK(d.trailers.get("x-trailer") == "yes");
    CHECK(d.trailers.get("x-other") == "2");
    CHECK(d.doneCalled);
    CHECK(d.clean);
}

TEST_CASE("chunked body delivered one byte at a time") {
    CEventLoop loop;
    Decoded d = loop.run(decode("3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n", wire::FRAME_CHUNKED, 0, true));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "abcd");
}

TEST_CASE("chunked body with bare LF line endings") {
    CEventLoop loop;
    Decoded d = loop.run(decode("5\nhello\n0\n\n", wire::FRAME_CHUNKED));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "hello");
}

TEST_CASE("bytes after the last chunk stay buffered for the next message") {
    CEventLoop loop;
    Decoded d = loop.run(decode("3\r\nabc\r\n0\r\n\r\nNEXT", wire::FRAME_CHUNKED));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "abc");
    CHECK(d.leftover == 4);
}

TEST_CASE("malformed chunked framing is rejected") {
    CEventLoop loop;
    CHECK(loop.run(decode("5\r\nhelloX\r\n0\r\n\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("zz\r\nabc\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("-1\r\nabc\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("\r\nabc\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("5 x\r\nhello\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("10000000000000000\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("0\r\nBad Trailer\r\n\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode("0\r\nX: " + std::string(5000, 'a') + "\r\n\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
    CHECK(loop.run(decode(std::string(5000, '1') + "\r\n", wire::FRAME_CHUNKED)).error == -EBADMSG);
}

TEST_CASE("truncated bodies report a reset") {
    CEventLoop loop;
    CHECK(loop.run(decode("5\r\nhel", wire::FRAME_CHUNKED)).error == -ECONNRESET);
    CHECK(loop.run(decode("5\r\nhello\r\n", wire::FRAME_CHUNKED)).error == -ECONNRESET);
    CHECK(loop.run(decode("5\r\nhello\r\n0\r\n", wire::FRAME_CHUNKED)).error == -ECONNRESET);
    Decoded d = loop.run(decode("hel", wire::FRAME_LENGTH, 5));
    CHECK(d.error == -ECONNRESET);
    CHECK(d.doneCalled);
    CHECK_FALSE(d.clean);
}

TEST_CASE("chunked sizes count toward the body limit") {
    CEventLoop loop;
    CHECK(loop.run(decode("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n", wire::FRAME_CHUNKED, 0, false, 8)).error == -EFBIG);
    CHECK(loop.run(decode("5\r\nhello\r\n0\r\n\r\n", wire::FRAME_CHUNKED, 0, false, 8)).error == SBOX_OK);
}

TEST_CASE("length, close-delimited and empty framings") {
    CEventLoop loop;
    Decoded d = loop.run(decode("hello world", wire::FRAME_LENGTH, 5));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "hello");
    CHECK(d.clean);

    d = loop.run(decode("until close", wire::FRAME_CLOSE));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body == "until close");
    CHECK(d.doneCalled);
    CHECK_FALSE(d.clean);

    d = loop.run(decode("ignored", wire::FRAME_NONE));
    CHECK(d.error == SBOX_OK);
    CHECK(d.body.empty());
    CHECK(d.clean);
}

TEST_CASE("response framing rules") {
    CHeaders h;
    wire::Framing f;
    uint64_t len = 0;
    bool close = false;

    h.add("Content-Length", "10");
    REQUIRE(wire::ResponseFraming("HEAD", 200, h, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_NONE);
    REQUIRE(wire::ResponseFraming("GET", 304, h, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_NONE);
    REQUIRE(wire::ResponseFraming("GET", 204, h, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_NONE);
    REQUIRE(wire::ResponseFraming("GET", 200, h, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_LENGTH);
    CHECK(len == 10);
    CHECK_FALSE(close);

    h.add("Content-Length", "10, 10");
    REQUIRE(wire::ResponseFraming("GET", 200, h, f, len, close) == SBOX_OK);
    h.add("Content-Length", "11");
    CHECK(wire::ResponseFraming("GET", 200, h, f, len, close) == -EBADMSG);

    CHeaders neg;
    neg.add("Content-Length", "-1");
    CHECK(wire::ResponseFraming("GET", 200, neg, f, len, close) == -EBADMSG);

    CHeaders te;
    te.add("Transfer-Encoding", "chunked");
    te.add("Content-Length", "3");
    REQUIRE(wire::ResponseFraming("GET", 200, te, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_CHUNKED);
    CHECK(close);

    CHeaders gz;
    gz.add("Transfer-Encoding", "gzip, chunked");
    CHECK(wire::ResponseFraming("GET", 200, gz, f, len, close) == -ENOTSUP);

    CHeaders none;
    REQUIRE(wire::ResponseFraming("GET", 200, none, f, len, close) == SBOX_OK);
    CHECK(f == wire::FRAME_CLOSE);
    CHECK(close);
}

TEST_CASE("request framing rules") {
    wire::Framing f;
    uint64_t len = 0;

    CHeaders both;
    both.add("Transfer-Encoding", "chunked");
    both.add("Content-Length", "3");
    CHECK(wire::RequestFraming(both, f, len) == -EBADMSG);

    CHeaders gz;
    gz.add("Transfer-Encoding", "gzip");
    CHECK(wire::RequestFraming(gz, f, len) == -ENOTSUP);

    CHeaders ch;
    ch.add("Transfer-Encoding", "Chunked");
    REQUIRE(wire::RequestFraming(ch, f, len) == SBOX_OK);
    CHECK(f == wire::FRAME_CHUNKED);

    CHeaders none;
    REQUIRE(wire::RequestFraming(none, f, len) == SBOX_OK);
    CHECK(f == wire::FRAME_NONE);
}

TEST_CASE("header lines are validated") {
    std::string_view n, v;
    CHECK(wire::SplitHeaderLine("Name:  value  ", n, v) == SBOX_OK);
    CHECK(n == "Name");
    CHECK(v == "value");
    CHECK(wire::SplitHeaderLine("Name : value", n, v) == -EBADMSG);
    CHECK(wire::SplitHeaderLine(": value", n, v) == -EBADMSG);
    CHECK(wire::SplitHeaderLine("no colon", n, v) == -EBADMSG);
    CHECK(wire::SplitHeaderLine("X: a\rb", n, v) == -EBADMSG);
    CHECK(wire::SplitHeaderLine("X: tab\tok", n, v) == SBOX_OK);
}

TEST_CASE("chunked encoder output decodes back") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CSocket a, b;
        REQUIRE(CSocket::pair(a, b) == SBOX_OK);

        auto writerConn = std::make_shared<wire::Connection>(std::make_shared<CSocket>(std::move(a)));
        CEventLoop::current()->spawn([](std::shared_ptr<wire::Connection> w) -> TTask<void> {
            PatternStream src(1000003);
            int32_t r = co_await wire::SendStreamBody(*w, src, -1, 5000);
            CHECK(r == SBOX_OK);
            static_cast<CSocket*>(w->stream.get())->shutdownWrite();
        }(writerConn));

        auto conn = std::make_shared<wire::Connection>(std::make_shared<CSocket>(std::move(b)));
        wire::Body reader(conn, wire::FRAME_CHUNKED, 0, 5000, 0, 4096);

        size_t maxChunk = 0;
        int64_t n = co_await verifyPattern(reader, maxChunk);
        CHECK(n == 1000003);
        CHECK(reader.isComplete());
    };

    loop.run(body());
}

TEST_CASE("stream body with a declared length stops at the length and detects short sources") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CSocket a, b;
        REQUIRE(CSocket::pair(a, b) == SBOX_OK);
        wire::Connection w(std::make_shared<CSocket>(std::move(a)));

        PatternStream shortSrc(10);
        CHECK(co_await wire::SendStreamBody(w, shortSrc, 20, 1000) == -ENODATA);

        PatternStream longSrc(100);
        CHECK(co_await wire::SendStreamBody(w, longSrc, 50, 1000) == SBOX_OK);
        CHECK(longSrc.pos == 50);
    };

    loop.run(body());
}
