#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <sbox/vpn/ipsec/esp.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include "testutil.hpp"
#include <deque>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

namespace {

    SEndpoint ep(const char* addr, uint16_t port) {
        SEndpoint e;
        SEndpoint::fromIp(addr, port, e);
        return e;
    }

    net::SIpAddress ip(const char* text) {
        net::SIpAddress a;
        net::SIpAddress::parse(text, a);
        return a;
    }

    /**
     * Initiator and responder wired back to back in memory, with an optional NAT in front of
     * the initiator (address and port rewriting) and a drop filter.
     */
    struct Pipe {
        struct Packet {
            std::vector<uint8_t> data;
            bool toResponder;
            bool natT;
        };

        std::deque<Packet> queue;
        bool nat = false;
        std::function<bool(const Packet&)> drop;
        size_t delivered = 0;

        // -- Addresses.
        const char* clientIp = "192.168.1.10";
        const char* natIp = "203.0.113.7";
        const char* serverIp = "198.51.100.1";

        void attach(CIkev1Initiator& i, CIkev1Responder& r) {
            i.sender([this](const SReadOnlyByteSpan& m, const SEndpoint&, const SEndpoint&, bool natT) {
                queue.push_back(Packet{ std::vector<uint8_t>(m.data, m.data + m.size), true, natT });
            });
            r.sender([this](const SReadOnlyByteSpan& m, const SEndpoint&, const SEndpoint&, bool natT) {
                queue.push_back(Packet{ std::vector<uint8_t>(m.data, m.data + m.size), false, natT });
            });
        }

        /** Delivers queued packets until quiet. */
        void run(CIkev1Initiator& i, CIkev1Responder& r, size_t limit = 100) {
            size_t n = 0;
            while (!queue.empty() && n++ < limit) {
                Packet p = std::move(queue.front());
                queue.pop_front();
                if (drop && drop(p)) {
                    continue;
                }

                ++delivered;
                SIkeDatagram dg;
                dg.data = p.data;
                dg.natT = p.natT;
                uint16_t clientPort = p.natT ? 4500 : 500;
                uint16_t natPort = p.natT ? 40001 : 40000;
                if (p.toResponder) {
                    dg.remote = nat ? ep(natIp, natPort) : ep(clientIp, clientPort);
                    dg.local = ep(serverIp, p.natT ? 4500 : 500);
                    r.handle(dg);
                }
                else {
                    dg.remote = ep(serverIp, p.natT ? 4500 : 500);
                    dg.local = ep(clientIp, clientPort);
                    i.handle(dg);
                }
            }
        }
    };

    SIkev1Config serverConfig(const std::string& psk = "s3cret-psk") {
        SIkev1Config c;
        SIkePsk p;
        p.secret = psk;
        c.psks.push_back(p);
        c.retransmitMs = 100;
        return c;
    }

    SIkev1Config clientConfig(const std::string& psk = "s3cret-psk") {
        SIkev1Config c = serverConfig(psk);
        return c;
    }

    /** Runs a full negotiation in memory; returns both SAs. */
    struct Result {
        bool up = false;
        SIkev1IpsecSa client;
        SIkev1IpsecSa server;
        int32_t failure = 0;
        std::string reason;
    };

    Result negotiate(SIkev1Config cc, SIkev1Config sc, bool nat, Pipe* pipeOut = nullptr) {
        Pipe pipe;
        pipe.nat = nat;
        CIkev1Responder r(sc);
        CIkev1Initiator i(cc, ep(pipe.serverIp, 500), 4500);
        pipe.attach(i, r);
        Result res;
        bool serverUp = false;
        r.onSaUp([&](const SIkev1IpsecSa& sa) {
            res.server = sa;
            serverUp = true;
        });
        i.onSaUp([&](const SIkev1IpsecSa& sa) { res.client = sa; });
        i.onFailed([&](int32_t e, const std::string& why) {
            res.failure = e;
            res.reason = why;
        });
        i.start(ip(pipe.clientIp), 500, 4500);
        pipe.run(i, r);
        res.up = serverUp && i.established();
        if (pipeOut) {
            pipeOut->delivered = pipe.delivered;
        }

        return res;
    }

    void checkMirror(const Result& r) {
        CHECK(r.server.inboundSpi == r.client.outboundSpi);
        CHECK(r.server.outboundSpi == r.client.inboundSpi);
        CHECK(r.server.inEncKey == r.client.outEncKey);
        CHECK(r.server.outEncKey == r.client.inEncKey);
        CHECK(r.server.inIntegKey == r.client.outIntegKey);
        CHECK(r.server.outIntegKey == r.client.inIntegKey);
        CHECK(r.server.encr == r.client.encr);
        CHECK(r.server.integ == r.client.integ);
        CHECK(r.server.encap == r.client.encap);
        CHECK_FALSE(r.server.inEncKey.empty());
    }

}

TEST_CASE("Main Mode + Quick Mode in memory, default proposals") {
    Result r = negotiate(clientConfig(), serverConfig(), false);
    REQUIRE_MESSAGE(r.up, r.reason);
    checkMirror(r);
    CHECK_FALSE(r.server.encap);
    CHECK(r.server.protocol == 17);
    CHECK(r.server.localPort == 1701);
    CHECK(r.server.remotePort == 1701);
    CHECK(r.server.remote.toString() == "192.168.1.10");
    CHECK(r.server.identity.find("192.168.1.10") == 0);
    CHECK(r.server.proposal.find("transport") != std::string::npos);
}

TEST_CASE("Windows-like proposals: 3DES/AES + SHA1 + MODP-1024/2048, ESP AES-CBC/3DES + SHA1") {
    struct Case { uint16_t encr; uint16_t bits; uint16_t hash; uint16_t group; uint8_t esp; uint16_t espBits; uint16_t auth; };
    const Case cases[] = {
        { EIKE1_ENCR_3DES, 192, EIKE1_HASH_SHA1, 2, EIKE1_ESP_3DES, 0, EIKE1_AA_HMAC_SHA1 },
        { EIKE1_ENCR_AES, 256, EIKE1_HASH_SHA1, 14, EIKE1_ESP_AES, 256, EIKE1_AA_HMAC_SHA1 },
        { EIKE1_ENCR_AES, 128, EIKE1_HASH_SHA256, 19, EIKE1_ESP_AES, 128, EIKE1_AA_HMAC_SHA256 },
        { EIKE1_ENCR_AES, 256, EIKE1_HASH_SHA384, 20, EIKE1_ESP_AES_GCM_16, 256, EIKE1_AA_NONE },
        { EIKE1_ENCR_AES, 192, EIKE1_HASH_SHA512, 2, EIKE1_ESP_AES, 192, EIKE1_AA_HMAC_SHA512 },
    };

    for (const Case& c : cases) {
        CAPTURE(c.encr);
        CAPTURE(c.group);
        SIkev1Config cc = clientConfig();
        SIkev1Suite s;
        s.encr = c.encr;
        s.keyBits = c.bits;
        s.hash = c.hash;
        s.group = c.group;
        cc.suites = { s };
        cc.esp = { SIkev1EspSuite{ c.esp, c.espBits, c.auth } };
        Result r = negotiate(cc, serverConfig(), false);
        REQUIRE_MESSAGE(r.up, r.reason);
        checkMirror(r);
    }
}

TEST_CASE("NAT detected: initiator floats to 4500, UDP-encapsulated transport with NAT-OA") {
    Result r = negotiate(clientConfig(), serverConfig(), true);
    REQUIRE_MESSAGE(r.up, r.reason);
    checkMirror(r);
    CHECK(r.server.encap);
    CHECK(r.server.remoteIkePort == 40001);
    CHECK(r.server.localIkePort == 4500);
    CHECK(r.server.remote.toString() == "203.0.113.7");
    CHECK(r.server.remoteOriginal.toString() == "192.168.1.10");
}

TEST_CASE("forceEncap makes a client without NAT use UDP 4500") {
    SIkev1Config sc = serverConfig();
    sc.forceEncap = true;
    Result r = negotiate(clientConfig(), sc, false);
    REQUIRE_MESSAGE(r.up, r.reason);
    CHECK(r.server.encap);
    CHECK(r.client.encap);
    CHECK(r.server.remoteIkePort == 4500);
}

TEST_CASE("PFS Quick Mode") {
    SIkev1Config cc = clientConfig();
    cc.pfs = true;
    Result r = negotiate(cc, serverConfig(), false);
    REQUIRE_MESSAGE(r.up, r.reason);
    checkMirror(r);
}

TEST_CASE("Wrong PSK fails, no SA") {
    Result r = negotiate(clientConfig("wrong"), serverConfig(), false);
    CHECK_FALSE(r.up);
}

TEST_CASE("PSK selection: per-address and per-FQDN keys, trial decryption") {
    SIkev1Config sc = serverConfig("default-key");
    SIkePsk byAddr;
    byAddr.id = "192.168.1.10";
    byAddr.secret = "address-key";
    sc.psks.insert(sc.psks.begin(), byAddr);
    SIkePsk byName;
    byName.id = "@phone.test";
    byName.secret = "phone-key";
    sc.psks.push_back(byName);

    CHECK(negotiate(clientConfig("address-key"), sc, false).up);
    CHECK(negotiate(clientConfig("default-key"), sc, false).up);

    SIkev1Config named = clientConfig("phone-key");
    named.identity = "@phone.test";
    CHECK(negotiate(named, sc, false).up);

    // --> The FQDN-bound key is not accepted for another identity.
    SIkev1Config other = clientConfig("phone-key");
    other.identity = "@laptop.test";
    CHECK_FALSE(negotiate(other, sc, false).up);
}

TEST_CASE("No common proposal: NO-PROPOSAL-CHOSEN reaches the initiator") {
    SIkev1Config cc = clientConfig();
    SIkev1Suite s;
    s.encr = EIKE1_ENCR_3DES;
    s.keyBits = 192;
    s.hash = EIKE1_HASH_MD5;
    s.group = 2;
    cc.suites = { s };
    SIkev1Config sc = serverConfig();
    SIkev1Suite only;
    only.encr = EIKE1_ENCR_AES;
    only.keyBits = 256;
    only.hash = EIKE1_HASH_SHA256;
    only.group = 14;
    sc.suites = { only };
    Result r = negotiate(cc, sc, false);
    CHECK_FALSE(r.up);
    CHECK(r.failure == -ECONNREFUSED);
}

TEST_CASE("Quick Mode selectors other than L2TP are refused") {
    SIkev1Config cc = clientConfig();
    cc.l2tpPort = 1702;
    Result r = negotiate(cc, serverConfig(), false);
    CHECK_FALSE(r.up);
}

TEST_CASE("Lost messages are retransmitted; duplicates get the cached reply") {
    Pipe pipe;
    CIkev1Responder r(serverConfig());
    CIkev1Initiator i(clientConfig(), ep(pipe.serverIp, 500), 4500);
    pipe.attach(i, r);
    // --> Drop the first MM2, the first MM6 and the first QM2.
    int responderSent = 0;
    pipe.drop = [&](const Pipe::Packet& p) {
        if (p.toResponder) {
            return false;
        }

        ++responderSent;
        return responderSent == 1 || responderSent == 4 || responderSent == 6;
    };

    bool up = false;
    r.onSaUp([&](const SIkev1IpsecSa&) { up = true; });
    i.start(ip(pipe.clientIp), 500, 4500);
    int64_t t = CEventLoop::nowMs();
    for (int round = 0; round < 60 && !(up && i.established()); ++round) {
        pipe.run(i, r);
        t += 250;
        i.tick(t);
        r.tick(t);
    }

    CHECK(up);
    CHECK(i.established());
}

TEST_CASE("Informational: DPD R-U-THERE is acknowledged, DELETE tears the SA down on both ends") {
    Pipe pipe;
    CIkev1Responder r(serverConfig());
    CIkev1Initiator i(clientConfig(), ep(pipe.serverIp, 500), 4500);
    pipe.attach(i, r);
    std::vector<uint32_t> serverDown;
    std::vector<uint32_t> clientDown;
    r.onSaDown([&](const SIkev1IpsecSa& sa) { serverDown.push_back(sa.inboundSpi); });
    i.onSaDown([&](const SIkev1IpsecSa& sa) { clientDown.push_back(sa.inboundSpi); });
    i.start(ip(pipe.clientIp), 500, 4500);
    pipe.run(i, r);
    REQUIRE(i.established());
    REQUIRE(r.sessions().size() == 1);
    CHECK(r.sessions()[0].state == "ESTABLISHED");

    uint32_t seq = i.sendDpd();
    REQUIRE(seq != 0);
    pipe.run(i, r);
    CHECK(i.dpdAcked() == seq);

    i.shutdown();
    pipe.run(i, r);
    CHECK(serverDown.size() == 1);
    CHECK(clientDown.size() == 1);
    CHECK(r.sessions().empty());
}

TEST_CASE("Server DPD declares a silent peer dead and reports its SAs down") {
    Pipe pipe;
    SIkev1Config sc = serverConfig();
    sc.dpdSeconds = 1;
    sc.dpdTries = 2;
    CIkev1Responder r(sc);
    CIkev1Initiator i(clientConfig(), ep(pipe.serverIp, 500), 4500);
    pipe.attach(i, r);
    size_t down = 0;
    r.onSaDown([&](const SIkev1IpsecSa&) { ++down; });
    i.start(ip(pipe.clientIp), 500, 4500);
    pipe.run(i, r);
    REQUIRE(i.established());

    // --> The client answers DPD while alive...
    int64_t t = CEventLoop::nowMs();
    for (int k = 0; k < 6; ++k) {
        t += 600;
        r.tick(t);
        pipe.run(i, r);
    }

    CHECK(down == 0);

    // --> ... and stops answering.
    pipe.drop = [](const Pipe::Packet& p) { return !p.toResponder; };
    for (int k = 0; k < 20 && down == 0; ++k) {
        t += 600;
        r.tick(t);
        pipe.run(i, r);
    }

    CHECK(down == 1);
    CHECK(r.sessions().empty());
}

TEST_CASE("INITIAL-CONTACT replaces the previous SAs of a reconnecting client") {
    Pipe pipe;
    CIkev1Responder r(serverConfig());
    size_t up = 0;
    size_t down = 0;
    r.onSaUp([&](const SIkev1IpsecSa&) { ++up; });
    r.onSaDown([&](const SIkev1IpsecSa&) { ++down; });
    for (int k = 0; k < 2; ++k) {
        CIkev1Initiator i(clientConfig(), ep(pipe.serverIp, 500), 4500);
        pipe.attach(i, r);
        i.start(ip(pipe.clientIp), 500, 4500);
        pipe.run(i, r);
        REQUIRE(i.established());
        pipe.queue.clear();
    }

    CHECK(up == 2);
    CHECK(down == 1);
    CHECK(r.sessions().size() == 1);
}

TEST_CASE("Responder rejects Aggressive Mode and garbage without state") {
    CIkev1Responder r(serverConfig());
    size_t sent = 0;
    r.sender([&](const SReadOnlyByteSpan&, const SEndpoint&, const SEndpoint&, bool) { ++sent; });
    SIkeDatagram dg;
    dg.remote = ep("10.0.0.2", 500);
    dg.local = ep("10.0.0.1", 500);
    SIkeHeader h;
    h.spiI = 0x1234;
    h.version = IKEV1_VERSION;
    h.exchange = EIKE1_X_AGGRESSIVE;
    h.length = IKE_HEADER_SIZE;
    h.encode(dg.data);
    r.handle(dg);
    CHECK(sent == 1);
    CHECK(r.sessions().empty());

    dg.data.assign(10, 0xff);
    r.handle(dg);
    CHECK(r.sessions().empty());
}

TEST_CASE("Over real sockets on loopback (shared with an IKEv2 responder)") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        // --> The IKEv2 responder owns UDP 500/4500 and forwards IKEv1 to us.
        SIkeServerConfig v2;
        v2.listenAddress = "127.0.0.1";
        v2.port = 0;
        v2.natPort = 0;
        v2.forwarding = false;
        SIkePsk psk;
        psk.secret = "v2-psk";
        v2.psks.push_back(psk);
        v2.dataPath.kind = EIDP_USER;
        struct NullPath : IIpsecDataPath {
            const char* kind() const noexcept override { return "null"; }
            TTask<int32_t> start() override { co_return SBOX_OK; }
            TTask<void> stop() override { co_return; }
            void attachSocket(CIkeSocket*) override {}
            bool supports(uint16_t, uint16_t, uint16_t) const noexcept override { return true; }
            TTask<int32_t> allocateSpi(net::SIpAddress, net::SIpAddress, uint32_t, uint32_t& spi) override {
                spi = 0x1000;
                co_return SBOX_OK;
            }
            TTask<int32_t> installChild(SIpsecChildSa) override { co_return SBOX_OK; }
            TTask<int32_t> removeChild(SIpsecChildSa, bool) override { co_return SBOX_OK; }
            TTask<int32_t> updateChild(SIpsecChildSa) override { co_return SBOX_OK; }
            TTask<int32_t> stats(SIpsecChildSa, SIpsecChildStats&) override { co_return SBOX_OK; }
            std::string interfaceName() const override { return std::string(); }
        };

        CIkeServer v2server(v2);
        REQUIRE(co_await v2server.start(std::make_shared<NullPath>()) == SBOX_OK);

        CIkev1Responder r(serverConfig());
        Log log;
        r.logger([&](EIkeLogLevel l, const std::string& m) { log.add(l, m); });
        CIkeSocket* shared = v2server.socket();
        r.sender([shared](const SReadOnlyByteSpan& m, const SEndpoint& local, const SEndpoint& remote, bool natT) {
            shared->send(m, local, remote, natT);
        });
        v2server.ikev1Handler([&r](SIkeDatagram& dg) { r.handle(dg); });
        bool serverUp = false;
        r.onSaUp([&](const SIkev1IpsecSa&) { serverUp = true; });

        CIkeSocket client;
        SIkeSocketOptions o;
        o.address = "127.0.0.1";
        o.port = 0;
        o.natPort = 0;
        REQUIRE(client.open(o) == SBOX_OK);
        SEndpoint server = ep("127.0.0.1", v2server.port());
        SIkev1Config cc = clientConfig();
        cc.retransmitMs = 200;
        CIkev1Initiator i(cc, server, v2server.natPort());
        i.sender([&client](const SReadOnlyByteSpan& m, const SEndpoint& local, const SEndpoint& remote, bool natT) {
            client.send(m, local, remote, natT);
        });
        client.start([&i](SIkeDatagram& dg) { i.handle(dg); });
        i.start(ip("127.0.0.1"), client.port(), client.natPort());

        bool ok = co_await WaitFor([&] { return serverUp && i.established(); }, 5000);
        CHECK_MESSAGE(ok, "log has " << log.lines.size() << " lines");
        CHECK(log.contains("Main Mode established"));
        CHECK(v2server.sessions().empty());
        client.close();
        co_await v2server.stop();
    }());
}
