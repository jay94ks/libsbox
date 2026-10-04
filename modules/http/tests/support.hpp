#ifndef __TESTS_HTTP_SUPPORT_HPP__
#define __TESTS_HTTP_SUPPORT_HPP__

// Helpers shared by the http tests (each test file is its own executable).

#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/file.hpp>
#include <sbox/http/client.hpp>
#include <sbox/http/server.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

namespace testsupport {

    using namespace sbox;
    using namespace sbox::http;

    /**
     * Byte at offset `pos` of the test pattern.
     */
    inline uint8_t patternByte(uint64_t pos) noexcept {
        return uint8_t((pos * 31u + 7u + (pos >> 13)) & 0xff);
    }

    /**
     * Stream generating `total` pattern bytes on the fly (nothing is buffered).
     */
    class PatternStream : public IStream {
    public:
        uint64_t total;
        uint64_t pos = 0;
        bool closed = false;

        explicit PatternStream(uint64_t n) : total(n) {}

        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t) override {
            size_t n = size_t(std::min<uint64_t>(buffer.size, total - pos));
            for (size_t i = 0; i < n; ++i) {
                buffer.data[i] = patternByte(pos + i);
            }

            pos += n;
            co_return SIoResult{ SBOX_OK, n };
        }

        TTask<SIoResult> send(const SReadOnlyByteSpan&, int64_t) override {
            co_return SIoResult{ -ENOTSUP, 0 };
        }

        void close() noexcept override {
            closed = true;
        }
    };

    /**
     * Reads a stream to its end checking the pattern; returns the byte count or a negated errno
     * (-EILSEQ on a mismatch). `maxChunk` receives the largest single read.
     */
    inline TTask<int64_t> verifyPattern(IStream& stream, size_t& maxChunk) {
        std::vector<uint8_t> buf(65536);
        uint64_t pos = 0;
        maxChunk = 0;

        while (true) {
            SIoResult r = co_await stream.recv(SByteSpan(buf.data(), buf.size()));
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return int64_t(pos);
            }

            maxChunk = std::max(maxChunk, r.bytes);
            for (size_t i = 0; i < r.bytes; ++i) {
                if (buf[i] != patternByte(pos + i)) {
                    co_return -EILSEQ;
                }
            }

            pos += r.bytes;
        }
    }

    /**
     * A CHttpServer serving on its own listener in a spawned task.
     */
    struct TestServer {
        CHttpServer server;
        CListener listener;
        bool done = false;
        int32_t result = 1;

        explicit TestServer(SServerOptions options = {}) : server(std::move(options)) {}

        /**
         * Listens on `ep` and starts serving.
         */
        int32_t start(const SEndpoint& ep) {
            int32_t r = listener.listen(ep);
            if (r != SBOX_OK) {
                return r;
            }

            CEventLoop::current()->spawn([](TestServer* self) -> TTask<void> {
                self->result = co_await self->server.serve(self->listener);
                self->done = true;
            }(this));

            return SBOX_OK;
        }

        /**
         * Listens on 127.0.0.1:0 (or another loopback address).
         */
        int32_t startTcp(const char* address = "127.0.0.1") {
            SEndpoint ep;
            SEndpoint::fromIp(address, 0, ep);
            return start(ep);
        }

        /** Returns the bound port. */
        uint16_t port() const { return listener.localEndpoint().port(); }

        /** Returns "http://addr:port". */
        std::string base(const char* address = "127.0.0.1") const {
            return std::string("http://") + address + ":" + std::to_string(port());
        }

        /**
         * Stops the server and waits for serve() to return.
         */
        TTask<void> stop(bool force = false) {
            server.stop(force);
            while (!done) {
                co_await CEventLoop::current()->sleepFor(1);
            }
        }
    };

    /**
     * Temporary directory removed on destruction.
     */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/tmp/sbox-http-test-XXXXXX";
            const char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
        }

        ~TempDir() {
            if (!path.empty()) {
                CFile::removeTree(path);
            }
        }
    };

    /**
     * Reads from a stream until "\r\n\r\n" (a request or response head) or EOF.
     */
    inline TTask<std::string> readHead(IStream& s, int64_t timeoutMs = 5000) {
        std::string out;
        char c;

        while (out.size() < 1 << 20) {
            SIoResult r = co_await s.recv(SByteSpan(reinterpret_cast<uint8_t*>(&c), 1), timeoutMs);
            if (!r.ok() || r.bytes == 0) {
                break;
            }

            out.push_back(c);
            if (out.size() >= 4 && out.compare(out.size() - 4, 4, "\r\n\r\n") == 0) {
                break;
            }
        }

        co_return out;
    }

    /**
     * Connects to `ep`, sends `request` raw and reads until the server closes (or timeout).
     */
    inline TTask<std::string> rawExchange(SEndpoint ep, std::string request, int64_t timeoutMs = 3000) {
        CSocket sock;
        if (co_await sock.connect(ep, 2000) != SBOX_OK) {
            co_return std::string("<connect failed>");
        }

        co_await sock.send(BytesOf(request));

        std::vector<uint8_t> all;
        co_await sock.recvAll(all, size_t(4) << 20, timeoutMs);
        co_return std::string(all.begin(), all.end());
    }

    /**
     * TLS connector double that passes the transport through and records the server name.
     */
    class IdentityTls : public ITlsConnector {
    public:
        std::vector<std::string> names;

        TTask<int32_t> connect(IStreamPtr transport, const std::string& serverName, IStreamPtr& out) override {
            names.push_back(serverName);
            out = std::move(transport);
            co_return SBOX_OK;
        }
    };

    /**
     * Copies bytes from one stream to the other until EOF or error, then closes both.
     */
    inline TTask<void> pump(IStreamPtr from, IStreamPtr to) {
        std::vector<uint8_t> buf(65536);

        while (true) {
            SIoResult r = co_await from->recv(SByteSpan(buf.data(), buf.size()));
            if (!r.ok() || r.bytes == 0) {
                break;
            }

            SIoResult w = co_await to->send(SReadOnlyByteSpan(buf.data(), r.bytes));
            if (!w.ok()) {
                break;
            }
        }

        from->close();
        to->close();
    }

}

#endif
