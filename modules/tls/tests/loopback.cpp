#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/tls/client.hpp>
#include <sbox/tls/trust.hpp>
#include "protocol.hpp"
#include "support.hpp"

// --> Handshakes against `openssl s_server` over loopback TCP: every TLS 1.3 and TLS 1.2 suite,
// several server key types, HelloRetryRequest, ALPN, client certificates, KeyUpdate, bulk data,
// and the failure paths (host mismatch, unknown CA, version mismatch, timeouts, garbage).
// Skipped when the openssl binary is not installed.

using namespace sbox;
using namespace sbox::tls;
using namespace tlstest;

namespace {

    struct Outcome {
        int32_t rc = -1;
        STlsReport report;
        std::string response;
        int32_t readError = 0;
    };

    /* Connects, handshakes and (on success) sends `request` and reads to EOF. */
    TTask<Outcome> fetch(Server& server, STlsClientOptions options, std::string request = "GET / HTTP/1.0\r\n\r\n") {
        Outcome out;
        IStreamPtr tcp;
        out.rc = co_await server.connect(tcp);
        if (out.rc != SBOX_OK) {
            co_return out;
        }

        options.report = &out.report;
        IStreamPtr tls;
        out.rc = co_await ConnectTls(tcp, options, tls);
        if (out.rc != SBOX_OK) {
            tcp->close();
            co_return out;
        }

        if (!request.empty()) {
            SIoResult s = co_await tls->send(BytesOf(request), 5000);
            if (!s.ok()) {
                out.readError = s.error;
                co_return out;
            }
        }

        std::vector<uint8_t> all;
        SIoResult r = co_await tls->recvAll(all, size_t(4) << 20, 10000);
        out.readError = r.error;
        out.response.assign(all.begin(), all.end());

        auto stream = std::static_pointer_cast<CTlsStream>(tls);
        co_await stream->shutdown(1000);
        tls->close();
        co_return out;
    }

    /* Client options trusting only the test root. */
    STlsClientOptions trusting(const Pki& pki, const std::string& host = "localhost") {
        STlsClientOptions o;
        o.serverName = host;
        o.trustStore = CTrustStore::create();
        REQUIRE(o.trustStore->addFile(pki.file("root.pem")) == 1);
        return o;
    }

    /* Server arguments presenting leaf `name` with the intermediate. */
    // --> Extra arguments come as one space separated string: GCC 13 crashes on braced
    // initializer lists inside co_await expressions.
    std::vector<std::string> serving(const Pki& pki, const std::string& name, const std::string& extra) {
        std::vector<std::string> args = { "-cert", pki.file(name + ".pem"), "-key", pki.file(name + ".key"),
                                          "-cert_chain", pki.file("inter.pem") };
        size_t start = 0;
        while (start < extra.size()) {
            size_t sp = extra.find(' ', start);
            if (sp == std::string::npos) {
                sp = extra.size();
            }

            if (sp > start) {
                args.push_back(extra.substr(start, sp - start));
            }

            start = sp + 1;
        }

        return args;
    }

    /* Returns the PKI shared by this process's test cases (generated once), or null with the
     * reason the test is skipped. */
    Pki* prepare(CEventLoop& loop) {
        static std::unique_ptr<Pki> shared;
        static bool attempted = false;

        if (OpensslPath().empty()) {
            MESSAGE("openssl binary not found: skipping loopback tests");
            return nullptr;
        }

        if (!attempted) {
            attempted = true;
            shared = std::make_unique<Pki>();
            if (!loop.run(shared->standard())) {
                shared.reset();
            }
        }

        if (!shared) {
            MESSAGE("failed to generate the test PKI with openssl: skipping");
        }

        return shared.get();
    }

}

TEST_CASE("TLS 1.3: every cipher suite against openssl s_server") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    const std::pair<const char*, uint16_t> suites[] = {
        { "TLS_AES_128_GCM_SHA256", TLS_AES_128_GCM_SHA256 },
        { "TLS_AES_256_GCM_SHA384", TLS_AES_256_GCM_SHA384 },
        { "TLS_CHACHA20_POLY1305_SHA256", TLS_CHACHA20_POLY1305_SHA256 },
    };

    for (auto [name, id] : suites) {
        CAPTURE(name);
        loop.run([](Pki& p, const char* suiteName, uint16_t suiteId) -> TTask<void> {
            Server server;
            REQUIRE(co_await server.start(serving(p, "ec", std::string("-tls1_3 -ciphersuites ") + suiteName + " -www")));

            Outcome o = co_await fetch(server, trusting(p));
            CHECK(o.rc == SBOX_OK);
            CHECK(o.report.reason == "");
            CHECK(o.report.version == ETLSV_1_3);
            CHECK(o.report.cipherSuite == suiteId);
            CHECK(o.report.group == GROUP_X25519);
            CHECK(o.report.signatureScheme == SIG_ECDSA_SECP256R1_SHA256);
            CHECK(o.report.peerCertificates.size() == 2);
            CHECK(o.response.find("200 ok") != std::string::npos);
            CHECK(o.response.find(suiteName) != std::string::npos);
            CHECK(o.readError == SBOX_OK);

            co_await server.stop();
        }(pki, name, id));
    }
}

TEST_CASE("TLS 1.3: server key types (P-384, RSA-PSS, Ed25519)") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    const std::pair<const char*, uint16_t> keys[] = {
        { "ec384", SIG_ECDSA_SECP384R1_SHA384 },
        { "rsa", SIG_RSA_PSS_RSAE_SHA256 },
        { "ed", SIG_ED25519 },
    };

    for (auto [name, scheme] : keys) {
        CAPTURE(name);
        loop.run([](Pki& p, const char* leaf, uint16_t expected) -> TTask<void> {
            Server server;
            REQUIRE(co_await server.start(serving(p, leaf, std::string("-tls1_3 -www"))));

            Outcome o = co_await fetch(server, trusting(p));
            CHECK(o.rc == SBOX_OK);
            CHECK(o.report.reason == "");
            CHECK(o.report.signatureScheme == expected);
            CHECK(o.response.find("200 ok") != std::string::npos);

            co_await server.stop();
        }(pki, name, scheme));
    }
}

TEST_CASE("TLS 1.2: every ECDHE suite against openssl s_server") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    struct Case {
        const char* leaf;
        const char* cipher;
        uint16_t id;
        const char* groups;
        uint16_t group;
    };

    const Case cases[] = {
        { "ec", "ECDHE-ECDSA-AES128-GCM-SHA256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "X25519", GROUP_X25519 },
        { "ec", "ECDHE-ECDSA-AES256-GCM-SHA384", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "P-256", GROUP_SECP256R1 },
        { "ec", "ECDHE-ECDSA-CHACHA20-POLY1305", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "P-384", GROUP_SECP384R1 },
        { "rsa", "ECDHE-RSA-AES128-GCM-SHA256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "X25519", GROUP_X25519 },
        { "rsa", "ECDHE-RSA-AES256-GCM-SHA384", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "P-256", GROUP_SECP256R1 },
        { "rsa", "ECDHE-RSA-CHACHA20-POLY1305", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "X25519", GROUP_X25519 },
    };

    for (const Case& c : cases) {
        CAPTURE(c.cipher);
        loop.run([](Pki& p, Case k) -> TTask<void> {
            Server server;
            REQUIRE(co_await server.start(serving(p, k.leaf, std::string("-tls1_2 -cipher ") + k.cipher + " -groups " + k.groups + " -www")));

            Outcome o = co_await fetch(server, trusting(p));
            CHECK(o.rc == SBOX_OK);
            CHECK(o.report.reason == "");
            CHECK(o.report.version == ETLSV_1_2);
            CHECK(o.report.cipherSuite == k.id);
            CHECK(o.report.group == k.group);
            CHECK(o.response.find("200 ok") != std::string::npos);
            CHECK(o.response.find(k.cipher) != std::string::npos);

            co_await server.stop();
        }(pki, c));
    }
}

TEST_CASE("TLS 1.2: RSA PKCS#1 v1.5 ServerKeyExchange signature") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server server;
        REQUIRE(co_await server.start(serving(p, "rsa", std::string("-tls1_2 -sigalgs RSA+SHA384 -www"))));

        Outcome o = co_await fetch(server, trusting(p));
        CHECK(o.rc == SBOX_OK);
        CHECK(o.report.signatureScheme == SIG_RSA_PKCS1_SHA384);
        CHECK(o.response.find("200 ok") != std::string::npos);

        co_await server.stop();
    }(pki));
}

TEST_CASE("TLS 1.3: HelloRetryRequest to P-256 and P-384") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    const std::pair<const char*, uint16_t> groups[] = { { "P-256", GROUP_SECP256R1 }, { "P-384", GROUP_SECP384R1 } };
    for (auto [name, id] : groups) {
        CAPTURE(name);
        loop.run([](Pki& p, const char* g, uint16_t expected) -> TTask<void> {
            Server server;
            REQUIRE(co_await server.start(serving(p, "ec", std::string("-tls1_3 -groups ") + g + " -www")));

            Outcome o = co_await fetch(server, trusting(p));
            CHECK(o.rc == SBOX_OK);
            CHECK(o.report.reason == "");
            CHECK(o.report.helloRetry);
            CHECK(o.report.group == expected);
            CHECK(o.response.find("200 ok") != std::string::npos);

            co_await server.stop();
        }(pki, name, id));
    }
}

TEST_CASE("ALPN, record padding, SNI wildcard and IP address verification") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server server;
        REQUIRE(co_await server.start(serving(p, "ec", std::string("-alpn http/1.1 -www"))));

        STlsClientOptions o = trusting(p);
        o.recordPadding = 256;
        Outcome a = co_await fetch(server, o);
        CHECK(a.rc == SBOX_OK);
        CHECK(a.report.alpn == "http/1.1");
        CHECK(a.response.find("200 ok") != std::string::npos);

        Outcome b = co_await fetch(server, trusting(p, "Foo.Test.Example."));
        CHECK(b.rc == SBOX_OK);
        CHECK(b.report.reason == "");

        Outcome c = co_await fetch(server, trusting(p, "127.0.0.1"));
        CHECK(c.rc == SBOX_OK);
        CHECK(c.report.reason == "");

        co_await server.stop();
    }(pki));
}

TEST_CASE("Certificate verification failures and the insecure option") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server server;
        REQUIRE(co_await server.start(serving(p, "ec", std::string("-www"))));

        Outcome wrongHost = co_await fetch(server, trusting(p, "registry.example.com"));
        CHECK(wrongHost.rc == -EKEYREJECTED);
        CHECK(wrongHost.report.alertSent == AD_BAD_CERTIFICATE);
        CHECK(wrongHost.report.reason.find("does not match host") != std::string::npos);

        Outcome deepWildcard = co_await fetch(server, trusting(p, "a.b.test.example"));
        CHECK(deepWildcard.rc == -EKEYREJECTED);

        STlsClientOptions untrusted;
        untrusted.serverName = "localhost";
        untrusted.trustStore = CTrustStore::create();
        Outcome unknownCa = co_await fetch(server, untrusted);
        CHECK(unknownCa.rc == -EKEYREJECTED);
        CHECK(unknownCa.report.alertSent == AD_UNKNOWN_CA);

        STlsClientOptions future = trusting(p);
        future.verifyTimeSeconds = int64_t(::time(nullptr)) + 400 * 86400;
        Outcome expired = co_await fetch(server, future);
        CHECK(expired.rc == -EKEYREJECTED);
        CHECK(expired.report.alertSent == AD_CERTIFICATE_EXPIRED);

        STlsClientOptions insecure;
        insecure.serverName = "registry.example.com";
        insecure.insecure = true;
        insecure.trustStore = CTrustStore::create();
        Outcome ok = co_await fetch(server, insecure);
        CHECK(ok.rc == SBOX_OK);
        CHECK(ok.response.find("200 ok") != std::string::npos);

        // --> Trusting the intermediate directly is enough (path ends at any anchor).
        STlsClientOptions interOnly;
        interOnly.serverName = "localhost";
        interOnly.trustStore = CTrustStore::create();
        REQUIRE(interOnly.trustStore->addFile(p.file("inter.pem")) == 1);
        Outcome viaInter = co_await fetch(server, interOnly);
        CHECK(viaInter.rc == SBOX_OK);

        co_await server.stop();
    }(pki));
}

TEST_CASE("Server that omits the intermediate is rejected") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server server;
        std::vector<std::string> args = { "-cert", p.file("ec.pem"), "-key", p.file("ec.key"), "-www" };
        REQUIRE(co_await server.start(args));

        Outcome o = co_await fetch(server, trusting(p));
        CHECK(o.rc == -EKEYREJECTED);
        CHECK(o.report.alertSent == AD_UNKNOWN_CA);

        co_await server.stop();
    }(pki));
}

TEST_CASE("Version negotiation limits") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server only12;
        REQUIRE(co_await only12.start(serving(p, "ec", std::string("-tls1_2 -www"))));
        STlsClientOptions min13 = trusting(p);
        min13.minVersion = ETLSV_1_3;
        Outcome a = co_await fetch(only12, min13);
        CHECK(a.rc == -EPROTONOSUPPORT);
        co_await only12.stop();

        Server only13;
        REQUIRE(co_await only13.start(serving(p, "ec", std::string("-tls1_3 -www"))));
        STlsClientOptions max12 = trusting(p);
        max12.maxVersion = ETLSV_1_2;
        Outcome b = co_await fetch(only13, max12);
        CHECK(b.rc == -EPROTONOSUPPORT);
        CHECK(b.report.alertReceived == AD_PROTOCOL_VERSION);

        Outcome c = co_await fetch(only13, trusting(p));
        CHECK(c.rc == SBOX_OK);
        co_await only13.stop();
    }(pki));
}

TEST_CASE("Client certificates (mutual TLS) in TLS 1.3 and TLS 1.2") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        for (const char* version : { "-tls1_3", "-tls1_2" }) {
            for (const char* client : { "client", "clientrsa" }) {
                CAPTURE(version);
                CAPTURE(client);
                Server server;
                REQUIRE(co_await server.start(serving(p, "ec", std::string(version) + " -Verify 2 -CAfile " + p.file("root.pem") + " -verify_return_error -www")));

                STlsClientOptions o = trusting(p);
                o.clientCertificatePem = p.read(std::string(client) + "-chain.pem");
                o.clientKeyPem = p.read(std::string(client) + ".key");
                Outcome ok = co_await fetch(server, o);
                CHECK(ok.rc == SBOX_OK);
                CHECK(ok.report.reason == "");
                CHECK(ok.report.clientCertificateSent);
                CHECK(ok.response.find("200 ok") != std::string::npos);

                co_await server.stop();
            }
        }

        // --> Without a certificate the server refuses; in TLS 1.3 that alert arrives after
        // our Finished, so it surfaces on the first read.
        Server server;
        REQUIRE(co_await server.start(serving(p, "ec", "-tls1_3 -Verify 2 -CAfile " + p.file("root.pem") + " -verify_return_error -www")));
        Outcome refused = co_await fetch(server, trusting(p));
        bool failedSomewhere = refused.rc != SBOX_OK || refused.readError != SBOX_OK;
        CHECK(failedSomewhere);
        CHECK(refused.report.clientCertificateSent == false);
        co_await server.stop();

        STlsClientOptions bad = trusting(p);
        bad.clientCertificatePem = p.read("client-chain.pem");
        bad.clientKeyPem = p.read("rsa.key");     // --> Not the certificate's key.
        Server server2;
        REQUIRE(co_await server2.start(serving(p, "ec", std::string("-www"))));
        Outcome mismatch = co_await fetch(server2, bad);
        CHECK(mismatch.rc == -EINVAL);
        co_await server2.stop();
    }(pki));
}

TEST_CASE("KeyUpdate in both directions and bulk data") {
    CEventLoop loop;
    Pki* shared = prepare(loop);
    if (!shared) {
        return;
    }

    Pki& pki = *shared;

    loop.run([](Pki& p) -> TTask<void> {
        Server server;
        REQUIRE(co_await server.start(serving(p, "ec", std::string("-tls1_3"))));

        IStreamPtr tcp, tls;
        REQUIRE(co_await server.connect(tcp) == SBOX_OK);
        STlsReport report;
        STlsClientOptions o = trusting(p);
        o.report = &report;
        REQUIRE(co_await ConnectTls(tcp, o, tls) == SBOX_OK);

        SIoResult s = co_await tls->send(BytesOf(std::string("hello-from-client\n")), 5000);
        REQUIRE(s.ok());
        CHECK(co_await server.waitOutput("hello-from-client"));

        // --> "K": the server updates its keys and requests ours to be updated too.
        REQUIRE(co_await server.type("K\n"));
        // --> s_server reads stdin in chunks and drops the rest of a chunk holding a command.
        co_await CEventLoop::current()->sleepFor(300);
        REQUIRE(co_await server.type("after-key-update\n"));

        std::string got;
        while (got.find("after-key-update\n") == std::string::npos) {
            uint8_t buf[256];
            SIoResult r = co_await tls->recv(SByteSpan(buf, sizeof(buf)), 5000);
            INFO("error ", r.error, ": ", std::static_pointer_cast<CTlsStream>(tls)->failureReason(), " / server: ", server.output);
            REQUIRE(r.ok());
            REQUIRE(r.bytes > 0);
            got.append(reinterpret_cast<char*>(buf), r.bytes);
        }

        s = co_await tls->send(BytesOf(std::string("ping-after-update\n")), 5000);
        REQUIRE(s.ok());
        CHECK(co_await server.waitOutput("ping-after-update"));

        // --> 1 MiB in one send: many records, several transport writes.
        std::string bulk;
        for (int32_t i = 0; bulk.size() < (size_t(1) << 20); ++i) {
            bulk += "line-" + std::to_string(i) + "-abcdefghijklmnopqrstuvwxyz\n";
        }
        bulk += "END-OF-BULK\n";

        s = co_await tls->send(BytesOf(bulk), 20000);
        REQUIRE(s.ok());
        CHECK(s.bytes == bulk.size());
        CHECK(co_await server.waitOutput("END-OF-BULK", 20000));
        CHECK(server.output.find("line-1000-abcdefghijklmnopqrstuvwxyz") != std::string::npos);

        auto stream = std::static_pointer_cast<CTlsStream>(tls);
        CHECK(co_await stream->shutdown(1000) == SBOX_OK);
        SIoResult after = co_await tls->send(BytesOf(std::string("x")), 1000);
        CHECK(after.error == -EPIPE);
        tls->close();

        co_await server.stop();
    }(pki));
}

TEST_CASE("Handshake timeout and non-TLS peers") {
    CEventLoop loop;

    loop.run([]() -> TTask<void> {
        CListener listener;
        SEndpoint ep;
        SEndpoint::fromIp("127.0.0.1", 0, ep);
        REQUIRE(listener.listen(ep) == SBOX_OK);
        SEndpoint bound = listener.localEndpoint();

        // -- A peer that accepts and stays silent.
        {
            auto client = std::make_shared<CSocket>();
            REQUIRE(co_await client->connect(bound, 2000) == SBOX_OK);
            CSocket peer;
            REQUIRE(co_await listener.accept(peer, 2000) == SBOX_OK);

            STlsClientOptions o;
            o.serverName = "localhost";
            o.handshakeTimeoutMs = 200;
            o.trustStore = CTrustStore::create();
            STlsReport report;
            o.report = &report;

            IStreamPtr tls;
            int64_t start = CEventLoop::nowMs();
            CHECK(co_await ConnectTls(client, o, tls) == -ETIMEDOUT);
            CHECK(CEventLoop::nowMs() - start < 2000);
            CHECK(report.reason.find("timed out") != std::string::npos);
        }

        // -- A peer that answers with plain HTTP.
        {
            auto client = std::make_shared<CSocket>();
            REQUIRE(co_await client->connect(bound, 2000) == SBOX_OK);
            CSocket peer;
            REQUIRE(co_await listener.accept(peer, 2000) == SBOX_OK);
            REQUIRE((co_await peer.send(BytesOf(std::string("HTTP/1.1 400 Bad Request\r\n\r\n")))).ok());

            STlsClientOptions o;
            o.serverName = "localhost";
            o.trustStore = CTrustStore::create();
            STlsReport report;
            o.report = &report;

            IStreamPtr tls;
            CHECK(co_await ConnectTls(client, o, tls) == -EBADMSG);
            CHECK(!report.reason.empty());
        }

        // -- A peer that closes immediately.
        {
            auto client = std::make_shared<CSocket>();
            REQUIRE(co_await client->connect(bound, 2000) == SBOX_OK);
            {
                CSocket peer;
                REQUIRE(co_await listener.accept(peer, 2000) == SBOX_OK);
            }

            STlsClientOptions o;
            o.serverName = "localhost";
            o.trustStore = CTrustStore::create();
            IStreamPtr tls;
            CHECK(co_await ConnectTls(client, o, tls) == -ECONNRESET);
        }

        // -- Invalid options.
        {
            auto client = std::make_shared<CSocket>();
            STlsClientOptions o;    // --> No server name and not insecure.
            IStreamPtr tls;
            CHECK(co_await ConnectTls(client, o, tls) == -EINVAL);
        }
    }());
}
