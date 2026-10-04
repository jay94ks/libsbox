#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/tls/client.hpp>
#include <sbox/tls/trust.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <cstdio>
#include <cstdlib>
#include <string>

// --> Live handshake with Docker Hub's registry (registry-1.docker.io:443). Runs only with
// SBOX_TEST_NETWORK=1. Honours HTTPS_PROXY with a minimal HTTP CONNECT, and the system trust
// store (SSL_CERT_FILE included, which is how an intercepting proxy's CA gets trusted).

using namespace sbox;
using namespace sbox::tls;

namespace {

    const char* HOST = "registry-1.docker.io";

    /* Splits "http://host:port/" into host and port. */
    bool parseProxy(std::string url, std::string& host, uint16_t& port) {
        size_t scheme = url.find("://");
        if (scheme != std::string::npos) {
            url = url.substr(scheme + 3);
        }

        size_t at = url.rfind('@');
        if (at != std::string::npos) {
            url = url.substr(at + 1);
        }

        size_t slash = url.find('/');
        if (slash != std::string::npos) {
            url = url.substr(0, slash);
        }

        size_t colon = url.rfind(':');
        if (colon == std::string::npos) {
            host = url;
            port = 80;
            return !host.empty();
        }

        host = url.substr(0, colon);
        port = uint16_t(std::atoi(url.c_str() + colon + 1));
        return !host.empty() && port != 0;
    }

    /* Opens a TCP stream to HOST:443, through the HTTPS proxy when one is configured. */
    TTask<int32_t> openTransport(IStreamPtr& out, std::string& via) {
        const char* proxy = std::getenv("HTTPS_PROXY");
        if (!proxy || !*proxy) {
            proxy = std::getenv("https_proxy");
        }

        std::string host = HOST;
        uint16_t port = 443;
        bool tunnel = false;
        if (proxy && *proxy && parseProxy(proxy, host, port)) {
            tunnel = true;
        }

        std::vector<SEndpoint> endpoints;
        int32_t rc = co_await ResolveEndpoints(host, port, endpoints);
        if (rc != SBOX_OK || endpoints.empty()) {
            co_return rc != SBOX_OK ? rc : -EHOSTUNREACH;
        }

        auto sock = std::make_shared<CSocket>();
        rc = co_await sock->connect(endpoints[0], 10000);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        via = tunnel ? "proxy " + host + ":" + std::to_string(port) : "direct";

        if (tunnel) {
            std::string request = std::string("CONNECT ") + HOST + ":443 HTTP/1.1\r\nHost: " + HOST + ":443\r\n\r\n";
            SIoResult s = co_await sock->send(BytesOf(request), 10000);
            if (!s.ok()) {
                co_return s.error;
            }

            // --> Read the proxy's response header byte by byte so no TLS byte is consumed.
            std::string head;
            while (head.find("\r\n\r\n") == std::string::npos && head.size() < 8192) {
                uint8_t c;
                SIoResult r = co_await sock->recv(SByteSpan(&c, 1), 10000);
                if (!r.ok() || r.bytes == 0) {
                    co_return r.ok() ? -ECONNRESET : r.error;
                }

                head.push_back(char(c));
            }

            if (head.compare(0, 12, "HTTP/1.1 200") != 0 && head.compare(0, 12, "HTTP/1.0 200") != 0) {
                MESSAGE("proxy refused CONNECT: " << head.substr(0, head.find('\r')));
                co_return -ECONNREFUSED;
            }
        }

        out = sock;
        co_return SBOX_OK;
    }

    /* One request over TLS with the given version limits. */
    TTask<void> fetchRegistry(ETlsVersion minVersion, ETlsVersion maxVersion) {
        IStreamPtr tcp;
        std::string via;
        int32_t rc = co_await openTransport(tcp, via);
        REQUIRE(rc == SBOX_OK);

        STlsClientOptions o;
        o.serverName = HOST;
        o.minVersion = minVersion;
        o.maxVersion = maxVersion;
        STlsReport report;
        o.report = &report;

        IStreamPtr tls;
        rc = co_await ConnectTls(tcp, o, tls);
        INFO("via ", via, ": ", report.reason);
        if (rc == -EPROTONOSUPPORT && minVersion == maxVersion) {
            MESSAGE("server does not offer the requested version only: " << report.reason);
            co_return;
        }

        REQUIRE(rc == SBOX_OK);
        char params[64];
        std::snprintf(params, sizeof(params), "group 0x%04x, scheme 0x%04x", report.group, report.signatureScheme);
        MESSAGE("connected via " << via << ": " << report.cipherSuiteName << ", " << params << ", alpn '" << report.alpn
                << "', " << report.peerCertificates.size() << " certificates");

        std::string request = std::string("GET /v2/ HTTP/1.1\r\nHost: ") + HOST + "\r\nConnection: close\r\nUser-Agent: libsbox-test\r\n\r\n";
        SIoResult s = co_await tls->send(BytesOf(request), 10000);
        REQUIRE(s.ok());

        std::vector<uint8_t> body;
        SIoResult r = co_await tls->recvAll(body, size_t(1) << 20, 15000);
        std::string text(body.begin(), body.end());
        INFO("response: ", text.substr(0, 200), " / recv error ", r.error);
        CHECK(text.compare(0, 9, "HTTP/1.1 ") == 0);
        // --> Anonymous /v2/ on Docker Hub answers 401 with a Bearer challenge.
        CHECK(text.find(" 401 ") != std::string::npos);
        tls->close();
    }

    bool enabled() {
        const char* v = std::getenv("SBOX_TEST_NETWORK");
        if (!v || std::string(v) != "1") {
            MESSAGE("SBOX_TEST_NETWORK is not 1: skipping live registry test");
            return false;
        }

        return true;
    }

}

TEST_CASE("live: registry-1.docker.io over the best version") {
    if (!enabled()) {
        return;
    }

    CEventLoop loop;
    loop.run(fetchRegistry(ETLSV_1_2, ETLSV_1_3));
}

TEST_CASE("live: registry-1.docker.io over TLS 1.2 only") {
    if (!enabled()) {
        return;
    }

    CEventLoop loop;
    loop.run(fetchRegistry(ETLSV_1_2, ETLSV_1_2));
}

TEST_CASE("live: registry-1.docker.io over TLS 1.3 only") {
    if (!enabled()) {
        return;
    }

    CEventLoop loop;
    loop.run(fetchRegistry(ETLSV_1_3, ETLSV_1_3));
}
