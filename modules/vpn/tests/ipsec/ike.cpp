#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/initiator.hpp>
#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include "testutil.hpp"

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    /** Base server configuration on 127.0.0.1 with ephemeral ports. */
    SIkeServerConfig baseConfig() {
        SIkeServerConfig c;
        c.listenAddress = "127.0.0.1";
        c.port = 0;
        c.natPort = 0;
        net::SIpPrefix::parse("10.77.0.0/24", c.pool);
        net::SIpAddress dns;
        net::SIpAddress::parse("10.77.0.53", dns);
        c.dns.push_back(dns);
        net::SIpPrefix route;
        net::SIpPrefix::parse("10.88.0.0/16", route);
        c.routes.push_back(route);
        c.dnsDomain = "corp.test";
        c.forwarding = false;
        c.retransmitBaseMs = 200;
        return c;
    }

    /** Base initiator configuration towards a server. */
    SIkeInitiatorConfig clientFor(const CIkeServer& server) {
        SIkeInitiatorConfig c;
        c.server = "127.0.0.1";
        c.serverPort = server.port();
        c.serverNatPort = server.natPort();
        c.timeoutMs = 5000;
        c.retransmitMs = 300;
        return c;
    }

    /** Collects server log lines. */
    struct Log {
        std::vector<std::string> lines;

        void attach(CIkeServer& s) {
            s.logger([this](EIkeLogLevel, const std::string& m) { lines.push_back(m); });
        }

        bool contains(const std::string& text) const {
            for (const std::string& l : lines) {
                if (l.find(text) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }
    };

    /** Finds a child in a list by inbound SPI. */
    const SIpsecChildSa* byInbound(const std::vector<SIpsecChildSa>& list, uint32_t spi) {
        for (const SIpsecChildSa& c : list) {
            if (c.inboundSpi == spi) {
                return &c;
            }
        }

        return nullptr;
    }

    /** Checks that the server's child mirrors the client's (keys, SPIs, selectors). */
    void checkMirror(const SIpsecChildSa& client, const std::vector<SIpsecChildSa>& serverActive) {
        const SIpsecChildSa* srv = byInbound(serverActive, client.outboundSpi);
        REQUIRE(srv != nullptr);
        CHECK(srv->outboundSpi == client.inboundSpi);
        CHECK(srv->inEncKey == client.outEncKey);
        CHECK(srv->outEncKey == client.inEncKey);
        CHECK(srv->inIntegKey == client.outIntegKey);
        CHECK(srv->outIntegKey == client.inIntegKey);
        CHECK(srv->encr == client.encr);
        CHECK(srv->integ == client.integ);
        CHECK(srv->localTs == client.remoteTs);
        CHECK(srv->remoteTs == client.localTs);
        CHECK(srv->encap == client.encap);
        if (client.encap) {
            // --> Both ends must use the NAT-T ports the IKE_AUTH exchange ran on.
            CHECK(srv->remotePort == client.localPort);
            CHECK(srv->localPort == client.remotePort);
        }
    }

}

TEST_CASE("PSK: IKE_SA_INIT + IKE_AUTH + CHILD SA with configuration payload and TS narrowing") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "correct horse battery staple";
        cfg.psks.push_back(psk);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        Log log;
        log.attach(server);
        REQUIRE(co_await server.start(path) == SBOX_OK);
        CHECK(server.port() != 0);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = psk.secret;
        CIkeInitiator client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "connect failed " << r << " notify " << client.lastNotify());
        CHECK(client.established());
        CHECK(client.virtualIp().toString() == "10.77.0.2");

        bool sawDns = false;
        bool sawSubnet = false;
        bool sawDomain = false;
        for (const SIkeCfgAttribute& a : client.configReply()) {
            sawDns = sawDns || (a.type == EIKE_CA_INTERNAL_IP4_DNS && a.value == std::vector<uint8_t>{ 10, 77, 0, 53 });
            sawSubnet = sawSubnet || (a.type == EIKE_CA_INTERNAL_IP4_SUBNET && a.value == std::vector<uint8_t>{ 10, 88, 0, 0, 255, 255, 0, 0 });
            sawDomain = sawDomain || (a.type == EIKE_CA_INTERNAL_DNS_DOMAIN && a.value.size() == 9);
        }

        CHECK(sawDns);
        CHECK(sawSubnet);
        CHECK(sawDomain);

        SIpsecChildSa child = client.child();
        REQUIRE(child.localTs.size() == 1);
        CHECK(child.localTs[0].toString() == "10.77.0.2/32");
        REQUIRE(child.remoteTs.size() == 1);
        CHECK(child.remoteTs[0].toString() == "10.88.0.0/16");
        CHECK_FALSE(child.encap);

        REQUIRE(path->active.size() == 1);
        checkMirror(child, path->active);

        std::vector<SIkeSessionInfo> sessions = server.sessions();
        REQUIRE(sessions.size() == 1);
        CHECK(sessions[0].identity == "road.test");
        CHECK(sessions[0].virtualIp == "10.77.0.2");
        CHECK(sessions[0].state == "established");

        // --> Liveness check and orderly deletion.
        CHECK(co_await client.dpd() == SBOX_OK);
        CHECK(co_await client.close() == SBOX_OK);
        for (int32_t i = 0; i < 50 && !server.sessions().empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.sessions().empty());
        CHECK(path->active.empty());
        CHECK(log.contains("established"));
        co_await server.stop();
    }());
}

TEST_CASE("PSK: a wrong key is rejected with AUTHENTICATION_FAILED") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "right";
        cfg.psks.push_back(psk);
        SIkePsk phone;
        phone.id = "@phone.test";
        phone.secret = "phone key";
        cfg.psks.push_back(phone);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        // --> Per-identity keys match by identity bytes, whatever ID type the client picked.
        for (const char* id : { "@phone.test", "phone.test", "keyid:70686f6e652e74657374" }) {
            SIkeInitiatorConfig byId = clientFor(server);
            byId.identity = id;
            byId.psk = "phone key";
            CIkeInitiator device(byId);
            CHECK_MESSAGE(co_await device.connect() == SBOX_OK, id);
            co_await device.close();
        }

        size_t installedBefore = path->installed.size();
        CHECK(installedBefore == 3);
        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = "wrong";
        CIkeInitiator client(cc);
        CHECK(co_await client.connect() == -EACCES);
        CHECK(client.lastNotify() == EIKE_N_AUTHENTICATION_FAILED);
        CHECK(path->installed.size() == installedBefore);

        // --> A per-identity key is not accepted for another identity's default.
        SIkeInitiatorConfig crossed = clientFor(server);
        crossed.identity = "@road.test";
        crossed.psk = "phone key";
        CIkeInitiator other(crossed);
        CHECK(co_await other.connect() == -EACCES);
        for (int32_t i = 0; i < 50 && !server.sessions().empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.sessions().empty());
        co_await server.stop();
    }());
}

TEST_CASE("EAP-MSCHAPv2 with a server certificate, and a wrong password") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        const Pki& pki = Pki::get();
        SIkeServerConfig cfg = baseConfig();
        cfg.certificate = pki.server;
        cfg.serverId = "vpn.test";
        SIkeUser alice;
        alice.name = "alice";
        alice.password = "s3cret";
        cfg.users.push_back(alice);
        SIkeUser bob;
        bob.name = "bob";
        bob.password = "hunter2";
        bob.address = "10.77.0.42";
        cfg.users.push_back(bob);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        for (bool rfc7427 : { true, false }) {
            SIkeInitiatorConfig cc = clientFor(server);
            cc.auth = EIKE_IAUTH_EAP;
            cc.identity = "10.0.0.7";       // --> Windows sends its address as IDi.
            cc.remoteId = "vpn.test";
            cc.user = "CORP\\Alice";
            cc.password = "s3cret";
            cc.caCertificates = { pki.ca };
            cc.rfc7427 = rfc7427;
            CIkeInitiator client(cc);
            int32_t r = co_await client.connect();
            REQUIRE_MESSAGE(r == SBOX_OK, "EAP connect failed " << r << " notify " << client.lastNotify());
            CHECK(client.virtualIp().isValid());
            checkMirror(client.child(), path->active);
            CHECK(co_await client.close() == SBOX_OK);
        }

        // --> A client that dials by address asks for that IDr; it is in the certificate's
        // SAN, so the server answers with it instead of its default "vpn.test".
        SIkeInitiatorConfig byIp = clientFor(server);
        byIp.auth = EIKE_IAUTH_EAP;
        byIp.remoteId = "127.0.0.1";
        byIp.user = "alice";
        byIp.password = "s3cret";
        byIp.caCertificates = { pki.ca };
        CIkeInitiator dialer(byIp);
        CHECK(co_await dialer.connect() == SBOX_OK);
        co_await dialer.close();

        // --> An IDr we cannot prove is refused by the client (we answer with our own).
        SIkeInitiatorConfig wrongIdr = byIp;
        wrongIdr.remoteId = "@elsewhere.test";
        CIkeInitiator confused(wrongIdr);
        CHECK(co_await confused.connect() == -EACCES);

        // --> A fixed per-user address.
        SIkeInitiatorConfig cb = clientFor(server);
        cb.auth = EIKE_IAUTH_EAP;
        cb.user = "bob";
        cb.password = "hunter2";
        cb.caCertificates = { pki.ca };
        CIkeInitiator bobClient(cb);
        REQUIRE(co_await bobClient.connect() == SBOX_OK);
        CHECK(bobClient.virtualIp().toString() == "10.77.0.42");
        co_await bobClient.close();

        SIkeInitiatorConfig bad = clientFor(server);
        bad.auth = EIKE_IAUTH_EAP;
        bad.user = "alice";
        bad.password = "nope";
        bad.caCertificates = { pki.ca };
        CIkeInitiator wrong(bad);
        CHECK(co_await wrong.connect() == -EACCES);

        // --> The client refuses a server certificate it does not trust.
        SIkeInitiatorConfig untrusting = clientFor(server);
        untrusting.auth = EIKE_IAUTH_EAP;
        untrusting.user = "alice";
        untrusting.password = "s3cret";
        untrusting.caCertificates = { pki.otherCa };
        CIkeInitiator suspicious(untrusting);
        CHECK(co_await suspicious.connect() == -EACCES);

        co_await server.stop();
    }());
}

TEST_CASE("Certificates on both sides; untrusted and mismatched identities fail") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        const Pki& pki = Pki::get();
        SIkeServerConfig cfg = baseConfig();
        cfg.certificate = pki.server;
        cfg.caCertificates = { pki.ca };

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        Log log;
        log.attach(server);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.auth = EIKE_IAUTH_CERT;
        cc.certificate = pki.client;
        cc.caCertificates = { pki.ca };
        CIkeInitiator client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "cert connect failed " << r << " notify " << client.lastNotify());
        checkMirror(client.child(), path->active);
        std::vector<SIkeSessionInfo> sessions = server.sessions();
        REQUIRE(sessions.size() == 1);
        CHECK(sessions[0].identity.find("CN=laptop") != std::string::npos);
        co_await client.close();

        // --> FQDN and RFC822 identities bound through the subjectAltName.
        for (const char* id : { "@laptop.test", "alice@test" }) {
            SIkeInitiatorConfig byName = cc;
            byName.identity = id;
            CIkeInitiator named(byName);
            CHECK(co_await named.connect() == SBOX_OK);
            co_await named.close();
        }

        SIkeInitiatorConfig wrongId = cc;
        wrongId.identity = "@someone.else";
        CIkeInitiator liar(wrongId);
        CHECK(co_await liar.connect() == -EACCES);

        SIkeInitiatorConfig foreign = cc;
        foreign.certificate = pki.stranger;
        CIkeInitiator stranger(foreign);
        CHECK(co_await stranger.connect() == -EACCES);
        CHECK(log.contains("untrusted certificate"));

        co_await server.stop();
    }());
}

TEST_CASE("IKE fragmentation (RFC 7383) in both directions") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        const Pki& pki = Pki::get();
        SIkeServerConfig cfg = baseConfig();
        cfg.certificate = pki.server;
        cfg.caCertificates = { pki.ca };
        cfg.fragmentSize = 576;

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.auth = EIKE_IAUTH_CERT;
        cc.certificate = pki.client;
        cc.caCertificates = { pki.ca };
        cc.fragmentSize = 576;
        CIkeInitiator client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "fragmented connect failed " << r);
        CHECK(client.fragmentsReceived() >= 2);
        checkMirror(client.child(), path->active);
        co_await client.close();

        // --> Without fragmentation support the same exchange uses one large datagram.
        SIkeInitiatorConfig plain = cc;
        plain.fragmentation = false;
        CIkeInitiator whole(plain);
        REQUIRE(co_await whole.connect() == SBOX_OK);
        CHECK(whole.fragmentsReceived() == 0);
        co_await whole.close();
        co_await server.stop();
    }());
}

TEST_CASE("CHILD SA rekey with PFS, IKE SA rekey, then DPD and DELETE on the new SA") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "rekey me";
        cfg.psks.push_back(psk);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = psk.secret;
        cc.pfsGroup = EIKE_DH_CURVE25519;
        CIkeInitiator client(cc);
        REQUIRE(co_await client.connect() == SBOX_OK);
        SIpsecChildSa first = client.child();

        REQUIRE(co_await client.rekeyChild() == SBOX_OK);
        SIpsecChildSa second = client.child();
        CHECK(second.inboundSpi != first.inboundSpi);
        CHECK(second.reqid == first.reqid);
        CHECK(second.outEncKey != first.outEncKey);
        REQUIRE(path->active.size() == 1);
        checkMirror(second, path->active);
        REQUIRE(!path->removed.empty());
        CHECK(path->removed.back().first.inboundSpi == first.outboundSpi);
        CHECK_FALSE(path->removed.back().second);     // --> Policies stay across a rekey.

        auto oldSpis = client.spis();
        REQUIRE(co_await client.rekeyIke() == SBOX_OK);
        auto newSpis = client.spis();
        CHECK(newSpis.first != oldSpis.first);
        CHECK(newSpis.second != oldSpis.second);

        for (int32_t i = 0; i < 50 && server.sessions().size() != 1; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        std::vector<SIkeSessionInfo> sessions = server.sessions();
        REQUIRE(sessions.size() == 1);
        CHECK(sessions[0].spiR == newSpis.second);
        CHECK(sessions[0].virtualIp == "10.77.0.2");
        CHECK(sessions[0].children.size() == 1);
        CHECK(path->active.size() == 1);

        CHECK(co_await client.dpd() == SBOX_OK);
        REQUIRE(co_await client.rekeyChild() == SBOX_OK);
        checkMirror(client.child(), path->active);
        CHECK(co_await client.close() == SBOX_OK);
        for (int32_t i = 0; i < 50 && !server.sessions().empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.sessions().empty());
        CHECK(path->active.empty());
        co_await server.stop();
    }());
}

TEST_CASE("Server DPD: answered checks keep the SA, a silent peer is removed") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "dpd";
        cfg.psks.push_back(psk);
        cfg.dpdSeconds = 1;
        cfg.retransmitTries = 2;
        cfg.retransmitBaseMs = 200;

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = psk.secret;
        {
            CIkeInitiator client(cc);
            REQUIRE(co_await client.connect() == SBOX_OK);
            for (int32_t i = 0; i < 400 && client.answeredRequests() < 2; ++i) {
                co_await CEventLoop::current()->sleepFor(10);
            }

            CHECK(client.answeredRequests() >= 2);
            CHECK(server.sessions().size() == 1);
        }

        // --> The client is gone without DELETE: DPD gives up and removes the SA.
        for (int32_t i = 0; i < 600 && !server.sessions().empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.sessions().empty());
        CHECK(path->active.empty());
        co_await server.stop();
    }());
}

TEST_CASE("Server-side disconnect sends DELETE to the client") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "bye";
        cfg.psks.push_back(psk);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = psk.secret;
        CIkeInitiator client(cc);
        REQUIRE(co_await client.connect() == SBOX_OK);

        CHECK(co_await server.disconnect("10.77.0.2") == 1);
        for (int32_t i = 0; i < 100 && !client.deletedByPeer(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(client.deletedByPeer());
        CHECK(server.sessions().empty());
        CHECK(path->active.empty());
        co_await server.stop();
    }());
}

TEST_CASE("COOKIE, INVALID_KE_PAYLOAD, forced NAT-T and legacy Windows proposals") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "cookies";
        cfg.psks.push_back(psk);
        cfg.cookieThreshold = 0;
        cfg.forceEncap = true;
        cfg.ikeProposals.resize(2);
        REQUIRE(ParseIkeProposal("aes256gcm16-prfsha256-ecp256", EIKE_PROTO_IKE, cfg.ikeProposals[0]) == SBOX_OK);
        REQUIRE(ParseIkeProposal("aes256-sha1-modp1024", EIKE_PROTO_IKE, cfg.ikeProposals[1]) == SBOX_OK);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@road.test";
        cc.psk = psk.secret;
        cc.ikeProposals.resize(1);
        // --> Our first KE guess (modp2048) is not acceptable: the server asks for ecp256.
        REQUIRE(ParseIkeProposal("aes256gcm16-prfsha256-modp2048-ecp256", EIKE_PROTO_IKE, cc.ikeProposals[0]) == SBOX_OK);
        CIkeInitiator client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "connect failed " << r);
        CHECK(client.natT());
        CHECK(client.child().encap);
        CHECK(client.ikeProposal() == "aes256gcm16-prfsha256-ecp256");
        checkMirror(client.child(), path->active);
        co_await client.close();

        // --> What Windows offers without a custom IPsec policy.
        SIkeInitiatorConfig win = cc;
        win.ikeProposals.resize(1);
        win.espProposals.resize(1);
        REQUIRE(ParseIkeProposal("aes256-sha1-modp1024", EIKE_PROTO_IKE, win.ikeProposals[0]) == SBOX_OK);
        REQUIRE(ParseIkeProposal("aes256-sha1", EIKE_PROTO_ESP, win.espProposals[0]) == SBOX_OK);
        CIkeInitiator windows(win);
        r = co_await windows.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "legacy connect failed " << r);
        CHECK(windows.ikeProposal() == "aes256-sha1-prfsha1-modp1024");
        CHECK(windows.espProposal().find("aes256-sha1") == 0);
        co_await windows.close();

        // --> Nothing in common.
        SIkeInitiatorConfig odd = cc;
        odd.ikeProposals.resize(1);
        REQUIRE(ParseIkeProposal("3des-sha512-modp2048", EIKE_PROTO_IKE, odd.ikeProposals[0]) == SBOX_OK);
        CIkeInitiator none(odd);
        CHECK(co_await none.connect() == -EPROTO);
        CHECK(none.lastNotify() == EIKE_N_NO_PROPOSAL_CHOSEN);

        co_await server.stop();
    }());
}

TEST_CASE("INITIAL_CONTACT replaces the previous SA of the same identity and keeps its address") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "again";
        cfg.psks.push_back(psk);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.identity = "@phone.test";
        cc.psk = psk.secret;
        CIkeInitiator first(cc);
        REQUIRE(co_await first.connect() == SBOX_OK);
        net::SIpAddress vip = first.virtualIp();

        CIkeInitiator second(cc);
        REQUIRE(co_await second.connect() == SBOX_OK);
        CHECK(second.virtualIp() == vip);
        CHECK(server.sessions().size() == 1);
        CHECK(path->active.size() == 1);
        co_await second.close();
        co_await server.stop();
    }());
}

TEST_CASE("Duplicated requests are answered from the responder's cache, never processed twice") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        const Pki& pki = Pki::get();
        SIkeServerConfig cfg = baseConfig();
        cfg.certificate = pki.server;
        SIkeUser alice;
        alice.name = "alice";
        alice.password = "s3cret";
        cfg.users.push_back(alice);
        cfg.fragmentSize = 700;

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        SIkeInitiatorConfig cc = clientFor(server);
        cc.auth = EIKE_IAUTH_EAP;
        cc.user = "alice";
        cc.password = "s3cret";
        cc.caCertificates = { pki.ca };
        cc.fragmentSize = 700;
        cc.duplicateRequests = true;
        cc.pfsGroup = EIKE_DH_ECP256;
        CIkeInitiator client(cc);
        int32_t r = co_await client.connect();
        REQUIRE_MESSAGE(r == SBOX_OK, "connect " << r);
        CHECK(path->installed.size() == 1);
        REQUIRE(co_await client.rekeyChild() == SBOX_OK);
        CHECK(path->installed.size() == 2);
        CHECK(path->active.size() == 1);
        REQUIRE(co_await client.rekeyIke() == SBOX_OK);
        CHECK(co_await client.dpd() == SBOX_OK);
        checkMirror(client.child(), path->active);
        CHECK(co_await client.close() == SBOX_OK);
        for (int32_t i = 0; i < 50 && !server.sessions().empty(); ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(server.sessions().empty());
        co_await server.stop();
    }());
}

TEST_CASE("IKEv1 datagrams on the shared ports go to the IKEv1 handler") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg = baseConfig();
        SIkePsk psk;
        psk.secret = "v1";
        cfg.psks.push_back(psk);
        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        std::vector<SIkeDatagram> v1;
        server.ikev1Handler([&v1](SIkeDatagram& dg) { v1.push_back(dg); });
        REQUIRE(co_await server.start(path) == SBOX_OK);
        REQUIRE(server.socket() != nullptr);

        // --> An ISAKMP Main Mode header (version 1.0) to both ports.
        SIkeHeader h;
        h.spiI = 0x42;
        h.version = 0x10;
        h.exchange = 2;
        std::vector<uint8_t> msg;
        h.length = IKE_HEADER_SIZE;
        h.encode(msg);

        CIkeSocket sender;
        SIkeSocketOptions so;
        so.address = "127.0.0.1";
        so.port = 0;
        so.natPort = 0;
        REQUIRE(sender.open(so) == SBOX_OK);
        SEndpoint to;
        SEndpoint::fromIp("127.0.0.1", server.port(), to);
        REQUIRE(sender.send(BytesOf(msg), SEndpoint(), to, false) == SBOX_OK);
        SEndpoint::fromIp("127.0.0.1", server.natPort(), to);
        REQUIRE(sender.send(BytesOf(msg), SEndpoint(), to, true) == SBOX_OK);

        for (int32_t i = 0; i < 100 && v1.size() < 2; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        REQUIRE(v1.size() == 2);
        CHECK(v1[0].data == msg);
        CHECK(v1[1].natT);
        CHECK(server.sessions().empty());
        sender.close();
        co_await server.stop();
    }());
}
