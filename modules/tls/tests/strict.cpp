#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/tls/client.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include "protocol.hpp"
#include "wire.hpp"
#include <algorithm>
#include <cstring>
#include <functional>

// --> A scripted fake server answers the client's ClientHello with crafted (mostly invalid)
// messages; the client must refuse each with the right error and alert.

using namespace sbox;
using namespace sbox::tls;

namespace {

    const uint8_t HRR_RANDOM[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    };

    /* Fields of the ClientHello the fake server needs. */
    struct Hello {
        std::vector<uint8_t> sessionId;
        std::vector<uint16_t> extensions;
        std::vector<uint8_t> raw;
    };

    /* Reads one handshake message (possibly spanning records), skipping CCS records. */
    TTask<bool> readClientHello(CSocket& peer, Hello& out) {
        std::vector<uint8_t> hs;
        while (hs.size() < 4 || hs.size() < 4 + ((size_t(hs[1]) << 16 | size_t(hs[2]) << 8 | hs[3]))) {
            uint8_t header[5];
            SIoResult r = co_await peer.recvExact(SByteSpan(header, 5), 5000);
            if (!r.ok()) {
                co_return false;
            }

            size_t len = size_t(header[3]) << 8 | header[4];
            std::vector<uint8_t> body(len);
            r = co_await peer.recvExact(BytesOf(body), 5000);
            if (!r.ok()) {
                co_return false;
            }

            if (header[0] == CT_HANDSHAKE) {
                hs.insert(hs.end(), body.begin(), body.end());
            }
        }

        out.raw = hs;
        Reader r(BytesOf(hs));
        r.u8();
        r.u24();
        r.u16();
        r.bytes(32);
        out.sessionId = ToVector(r.block(1).rest());
        r.block(2);
        r.block(1);
        Reader exts = r.block(2);
        while (exts.ok() && exts.left() > 0) {
            out.extensions.push_back(uint16_t(exts.u16()));
            exts.block(2);
        }

        co_return r.done();
    }

    /* Wraps a handshake body into a plaintext record. */
    std::vector<uint8_t> record(uint8_t contentType, uint8_t hsType, const std::vector<uint8_t>& body) {
        std::vector<uint8_t> msg;
        Writer m(msg);
        m.u8(hsType);
        m.u24(uint32_t(body.size()));
        m.bytes(body);

        std::vector<uint8_t> out;
        Writer w(out);
        w.u8(contentType);
        w.u16(VER_TLS12);
        w.u16(uint32_t(msg.size()));
        w.bytes(msg);
        return out;
    }

    /* ServerHello builder. */
    struct HelloSpec {
        uint16_t version = VER_TLS12;
        std::vector<uint8_t> random = std::vector<uint8_t>(32, 0x11);
        bool echoSession = true;
        uint16_t suite = TLS_AES_128_GCM_SHA256;
        std::function<void(Writer&)> extensions;
    };

    std::vector<uint8_t> serverHello(const Hello& ch, const HelloSpec& spec) {
        std::vector<uint8_t> body;
        Writer w(body);
        w.u16(spec.version);
        w.bytes(BytesOf(spec.random));
        w.begin(1);
        if (spec.echoSession) {
            w.bytes(ch.sessionId);
        }
        w.end();
        w.u16(spec.suite);
        w.u8(0);
        w.begin(2);
        if (spec.extensions) {
            spec.extensions(w);
        }
        w.end();
        return record(CT_HANDSHAKE, HS_SERVER_HELLO, body);
    }

    /* Extension writers. */
    void ext13(Writer& w) {
        w.u16(EXT_SUPPORTED_VERSIONS);
        w.begin(2);
        w.u16(VER_TLS13);
        w.end();
    }

    void keyShare(Writer& w, uint16_t group, size_t length) {
        w.u16(EXT_KEY_SHARE);
        w.begin(2);
        w.u16(group);
        if (length) {
            w.begin(2);
            std::vector<uint8_t> v(length, 0x09);
            w.bytes(BytesOf(v));
            w.end();
        }
        w.end();
    }

    void ems(Writer& w) {
        w.u16(EXT_EXTENDED_MASTER_SECRET);
        w.u16(0);
    }

    struct Result {
        int32_t rc = 0;
        STlsReport report;
    };

    /* Runs the client against `script`, which plays the server side on `peer`. */
    Result runScripted(std::function<TTask<void>(CSocket&, Hello&)> script, ETlsVersion maxVersion = ETLSV_1_3) {
        CEventLoop loop;
        Result result;

        loop.run([](Result& res, std::function<TTask<void>(CSocket&, Hello&)>& play, ETlsVersion maxV) -> TTask<void> {
            CListener listener;
            SEndpoint ep;
            SEndpoint::fromIp("127.0.0.1", 0, ep);
            REQUIRE(listener.listen(ep) == SBOX_OK);

            auto client = std::make_shared<CSocket>();
            REQUIRE(co_await client->connect(listener.localEndpoint(), 2000) == SBOX_OK);
            auto peer = std::make_shared<CSocket>();
            REQUIRE(co_await listener.accept(*peer, 2000) == SBOX_OK);

            bool serverDone = false;
            CEventLoop::current()->spawn([](std::shared_ptr<CSocket> p, std::function<TTask<void>(CSocket&, Hello&)>* fn,
                                            bool* done) -> TTask<void> {
                Hello ch;
                if (co_await readClientHello(*p, ch)) {
                    co_await (*fn)(*p, ch);
                }

                // --> Drain whatever the client says (alerts) until it hangs up.
                uint8_t buf[512];
                while (true) {
                    SIoResult r = co_await p->recv(SByteSpan(buf, sizeof(buf)), 3000);
                    if (!r.ok() || r.bytes == 0) {
                        break;
                    }
                }

                *done = true;
            }(peer, &play, &serverDone));

            STlsClientOptions o;
            o.serverName = "localhost";
            o.trustStore = CTrustStore::create();
            o.maxVersion = maxV;
            o.handshakeTimeoutMs = 3000;
            o.report = &res.report;

            IStreamPtr tls;
            res.rc = co_await ConnectTls(client, o, tls);
            client->close();

            while (!serverDone) {
                co_await CEventLoop::current()->sleepFor(5);
            }
        }(result, script, maxVersion));

        return result;
    }

    /* Script: send one buffer. */
    std::function<TTask<void>(CSocket&, Hello&)> sendHello(HelloSpec spec) {
        return [spec](CSocket& peer, Hello& ch) -> TTask<void> {
            std::vector<uint8_t> out = serverHello(ch, spec);
            co_await peer.send(BytesOf(out), 2000);
        };
    }

}

TEST_CASE("TLS 1.2 ServerHello carrying the TLS 1.3 downgrade sentinel is refused") {
    HelloSpec spec;
    spec.suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    const uint8_t sentinel[8] = { 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01 };
    std::memcpy(spec.random.data() + 24, sentinel, 8);
    spec.echoSession = false;
    spec.extensions = ems;

    Result r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);
    CHECK(r.report.reason.find("downgrade") != std::string::npos);
}

TEST_CASE("TLS 1.3 ServerHello must echo the session id") {
    HelloSpec spec;
    spec.echoSession = false;
    spec.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_X25519, 32); };

    Result r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);
}

TEST_CASE("Unsolicited and duplicated ServerHello extensions are refused") {
    HelloSpec spec;
    spec.extensions = [](Writer& w) {
        ext13(w);
        keyShare(w, GROUP_X25519, 32);
        w.u16(0x1234);
        w.u16(0);
    };

    Result r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_UNSUPPORTED_EXTENSION);

    spec.extensions = [](Writer& w) { ext13(w); ext13(w); keyShare(w, GROUP_X25519, 32); };
    r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);
}

TEST_CASE("A cipher suite that was not offered is refused") {
    HelloSpec spec;
    spec.suite = 0x1304;    // --> TLS_AES_128_CCM_SHA256: not offered.
    spec.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_X25519, 32); };

    Result r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);

    // --> A TLS 1.2 suite in a TLS 1.3 ServerHello.
    spec.suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
}

TEST_CASE("Old protocol versions and missing extended master secret are refused") {
    HelloSpec old;
    old.version = 0x0301;
    old.suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    old.echoSession = false;
    Result r = runScripted(sendHello(old));
    CHECK(r.rc == -EPROTONOSUPPORT);
    CHECK(r.report.alertSent == AD_PROTOCOL_VERSION);

    HelloSpec noEms;
    noEms.suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    noEms.echoSession = false;
    r = runScripted(sendHello(noEms));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_HANDSHAKE_FAILURE);

    // --> The server echoing our random session id would mean resumption, never offered.
    HelloSpec resume;
    resume.suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    resume.extensions = ems;
    r = runScripted(sendHello(resume));
    CHECK(r.rc == -EPROTO);
}

TEST_CASE("Invalid TLS 1.3 key shares are refused") {
    HelloSpec spec;
    spec.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_SECP256R1, 65); };   // --> Not offered as a share.
    Result r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);

    spec.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_X25519, 31); };       // --> Wrong length.
    r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);

    spec.extensions = [](Writer& w) { ext13(w); };                                    // --> No key_share.
    r = runScripted(sendHello(spec));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_MISSING_EXTENSION);
}

TEST_CASE("HelloRetryRequest rules") {
    // --> Asking for the group whose share was already sent.
    HelloSpec same;
    same.random.assign(HRR_RANDOM, HRR_RANDOM + 32);
    same.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_X25519, 0); };
    Result r = runScripted(sendHello(same));
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_ILLEGAL_PARAMETER);

    // --> A second HelloRetryRequest.
    HelloSpec hrr;
    hrr.random.assign(HRR_RANDOM, HRR_RANDOM + 32);
    hrr.extensions = [](Writer& w) { ext13(w); keyShare(w, GROUP_SECP256R1, 0); };
    r = runScripted([hrr](CSocket& peer, Hello& ch) -> TTask<void> {
        std::vector<uint8_t> out = serverHello(ch, hrr);
        co_await peer.send(BytesOf(out), 2000);

        Hello second;
        if (co_await readClientHello(peer, second)) {
            CHECK(second.sessionId == ch.sessionId);
            CHECK(std::find(second.extensions.begin(), second.extensions.end(), EXT_KEY_SHARE) != second.extensions.end());
            out = serverHello(second, hrr);
            co_await peer.send(BytesOf(out), 2000);
        }
    });
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_UNEXPECTED_MESSAGE);
    CHECK(r.report.helloRetry);
}

TEST_CASE("Record layer violations") {
    // --> Oversized plaintext record.
    Result r = runScripted([](CSocket& peer, Hello&) -> TTask<void> {
        std::vector<uint8_t> out = { CT_HANDSHAKE, 3, 3, 0x40, 0x01 };
        out.resize(5 + 0x4001, 0);
        co_await peer.send(BytesOf(out), 2000);
    });
    CHECK(r.rc == -EBADMSG);
    CHECK(r.report.alertSent == AD_RECORD_OVERFLOW);

    // --> Application data before any keys.
    r = runScripted([](CSocket& peer, Hello&) -> TTask<void> {
        std::vector<uint8_t> out = { CT_APPLICATION_DATA, 3, 3, 0, 3, 1, 2, 3 };
        co_await peer.send(BytesOf(out), 2000);
    });
    CHECK(r.rc == -EBADMSG);
    CHECK(r.report.alertSent == AD_UNEXPECTED_MESSAGE);

    // --> A fatal alert from the server.
    r = runScripted([](CSocket& peer, Hello&) -> TTask<void> {
        std::vector<uint8_t> out = { CT_ALERT, 3, 3, 0, 2, ALERT_FATAL, AD_HANDSHAKE_FAILURE };
        co_await peer.send(BytesOf(out), 2000);
    });
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertReceived == AD_HANDSHAKE_FAILURE);
    CHECK(r.report.reason.find("handshake_failure") != std::string::npos);

    // --> A wrong first handshake message.
    r = runScripted([](CSocket& peer, Hello&) -> TTask<void> {
        std::vector<uint8_t> out = record(CT_HANDSHAKE, HS_CERTIFICATE, std::vector<uint8_t>(3, 0));
        co_await peer.send(BytesOf(out), 2000);
    });
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_UNEXPECTED_MESSAGE);

    // --> A truncated ServerHello.
    r = runScripted([](CSocket& peer, Hello&) -> TTask<void> {
        std::vector<uint8_t> out = record(CT_HANDSHAKE, HS_SERVER_HELLO, std::vector<uint8_t>(10, 3));
        co_await peer.send(BytesOf(out), 2000);
    });
    CHECK(r.rc == -EPROTO);
    CHECK(r.report.alertSent == AD_DECODE_ERROR);
}

TEST_CASE("ClientHello contents") {
    Hello seen;
    Result r = runScripted([&seen](CSocket& peer, Hello& ch) -> TTask<void> {
        seen = ch;
        peer.close();
        co_return;
    });
    CHECK(r.rc == -ECONNRESET);

    auto has = [&](uint16_t ext) { return std::find(seen.extensions.begin(), seen.extensions.end(), ext) != seen.extensions.end(); };
    CHECK(seen.sessionId.size() == 32);     // --> Middlebox compatibility mode.
    CHECK(has(EXT_SERVER_NAME));
    CHECK(has(EXT_SUPPORTED_VERSIONS));
    CHECK(has(EXT_KEY_SHARE));
    CHECK(has(EXT_SIGNATURE_ALGORITHMS));
    CHECK(has(EXT_SUPPORTED_GROUPS));
    CHECK(has(EXT_ALPN));
    CHECK(has(EXT_EXTENDED_MASTER_SECRET));
    CHECK(has(EXT_RENEGOTIATION_INFO));
    CHECK_FALSE(has(EXT_EARLY_DATA));
    CHECK_FALSE(has(EXT_PRE_SHARED_KEY));
    CHECK_FALSE(has(EXT_SESSION_TICKET));

    // --> A TLS 1.2-only client sends no TLS 1.3 extensions.
    Result r12 = runScripted([&seen](CSocket& peer, Hello& ch) -> TTask<void> {
        seen = ch;
        peer.close();
        co_return;
    }, ETLSV_1_2);
    CHECK(r12.rc == -ECONNRESET);
    CHECK_FALSE(has(EXT_SUPPORTED_VERSIONS));
    CHECK_FALSE(has(EXT_KEY_SHARE));
    CHECK(has(EXT_EXTENDED_MASTER_SECRET));
}
