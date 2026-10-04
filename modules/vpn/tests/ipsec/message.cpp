#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/eap.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <sbox/vpn/ipsec/initiator.hpp>
#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include "ipsec/crypto.hpp"
#include "ipsec/ikesa.hpp"
#include "testutil.hpp"
#include <algorithm>
#include <cstring>
#include <random>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    SIkePayload pl(uint8_t type, std::vector<uint8_t> body) {
        SIkePayload p;
        p.type = type;
        p.body = std::move(body);
        return p;
    }

    /** A realistic IKE_AUTH-like payload chain covering every codec. */
    std::vector<SIkePayload> samplePayloads() {
        std::vector<SIkePayload> out;
        SIkeId id;
        REQUIRE(SIkeId::fromString("CN=client, O=Example, C=KR", id) == SBOX_OK);
        out.push_back(pl(EIKE_PL_IDI, id.body()));

        std::vector<uint8_t> body;
        EncodeIkeCert(EIKE_CERT_X509_SIGNATURE, BytesOf(std::vector<uint8_t>(40, 0x30)), body);
        out.push_back(pl(EIKE_PL_CERTREQ, body));

        body.clear();
        EncodeIkeAuth(EIKE_AUTH_PSK, BytesOf(std::vector<uint8_t>(32, 7)), body);
        out.push_back(pl(EIKE_PL_AUTH, body));

        SIkeConfig cp;
        cp.cfgType = EIKE_CFG_REQUEST;
        cp.attributes.push_back(SIkeCfgAttribute{ EIKE_CA_INTERNAL_IP4_ADDRESS, {} });
        cp.attributes.push_back(SIkeCfgAttribute{ EIKE_CA_INTERNAL_IP4_DNS, { 1, 1, 1, 1 } });
        body.clear();
        EncodeIkeConfig(cp, body);
        out.push_back(pl(EIKE_PL_CP, body));

        std::vector<SIkeProposal> props = DefaultEspProposals();
        for (SIkeProposal& p : props) {
            p.spi = { 1, 2, 3, 4 };
        }

        body.clear();
        EncodeIkeSa(props, body);
        out.push_back(pl(EIKE_PL_SA, body));

        net::SIpPrefix a;
        net::SIpPrefix::parse("10.0.0.0/8", a);
        std::vector<SIkeTrafficSelector> ts = { SIkeTrafficSelector::fromPrefix(a), SIkeTrafficSelector::any(true) };
        ts[0].protocol = 17;
        ts[0].startPort = 500;
        ts[0].endPort = 500;
        body.clear();
        EncodeIkeTs(ts, body);
        out.push_back(pl(EIKE_PL_TSI, body));
        out.push_back(pl(EIKE_PL_TSR, body));

        SIkeDelete del;
        del.protocol = EIKE_PROTO_ESP;
        del.spis = { 0x11111111u, 0x22222222u };
        body.clear();
        EncodeIkeDelete(del, body);
        out.push_back(pl(EIKE_PL_DELETE, body));

        out.push_back(MakeIkeNotify(EIKE_N_INITIAL_CONTACT));
        SEapPacket eap;
        eap.code = EEAP_RESPONSE;
        eap.identifier = 9;
        eap.type = EEAP_T_IDENTITY;
        eap.data = { 'b', 'o', 'b' };
        out.push_back(pl(EIKE_PL_EAP, eap.encode()));
        return out;
    }

    /** Runs every decoder over a payload body; returns how many accepted it. */
    int32_t decodeAll(const SIkePayload& p) {
        int32_t ok = 0;
        SReadOnlyByteSpan b = BytesOf(p.body);
        std::vector<SIkeProposal> props;
        ok += DecodeIkeSa(b, props) == SBOX_OK;
        uint16_t group;
        std::vector<uint8_t> data;
        ok += DecodeIkeKe(b, group, data) == SBOX_OK;
        SIkeId id;
        if (DecodeIkeId(b, id) == SBOX_OK) {
            ++ok;
            (void)id.toString();
        }

        uint8_t enc;
        ok += DecodeIkeCert(b, enc, data) == SBOX_OK;
        ok += DecodeIkeAuth(b, enc, data) == SBOX_OK;
        SIkeNotify n;
        ok += DecodeIkeNotify(b, n) == SBOX_OK;
        SIkeDelete d;
        ok += DecodeIkeDelete(b, d) == SBOX_OK;
        std::vector<SIkeTrafficSelector> ts;
        if (DecodeIkeTs(b, ts) == SBOX_OK) {
            ++ok;
            for (const SIkeTrafficSelector& t : ts) {
                (void)t.toPrefixes();
                (void)t.toString();
            }
        }

        SIkeConfig cp;
        ok += DecodeIkeConfig(b, cp) == SBOX_OK;
        SEapPacket eap;
        ok += SEapPacket::parse(b, eap) == SBOX_OK;
        uint16_t num, total;
        ok += DecodeIkeFragmentHeader(b, num, total) == SBOX_OK;
        return ok;
    }

    /** Applies one random mutation. */
    void mutate(std::vector<uint8_t>& v, std::mt19937& rng) {
        if (v.empty()) {
            v.push_back(uint8_t(rng()));
            return;
        }

        switch (rng() % 6) {
        case 0:
            v[rng() % v.size()] ^= uint8_t(1u << (rng() % 8));
            break;
        case 1:
            v[rng() % v.size()] = uint8_t(rng());
            break;
        case 2:
            v.resize(rng() % v.size());
            break;
        case 3:
            v.insert(v.begin() + long(rng() % v.size()), uint8_t(rng()));
            break;
        case 4: {
            // --> Length fields are 16-bit big endian: hit them with extreme values.
            size_t at = rng() % v.size();
            v[at] = (rng() & 1) ? 0xff : 0x00;
            break;
        }
        default:
            v.erase(v.begin() + long(rng() % v.size()));
            break;
        }
    }

}

TEST_CASE("Header and payload chain round trip") {
    std::vector<SIkePayload> payloads = samplePayloads();
    SIkeHeader h;
    h.spiI = 0x0102030405060708ull;
    h.spiR = 0x1112131415161718ull;
    h.exchange = EIKE_X_AUTH;
    h.flags = EIKE_F_INITIATOR;
    h.messageId = 1;
    std::vector<uint8_t> msg = ipsec::EncodePlainMessage(h, payloads);

    SIkeHeader parsed;
    REQUIRE(SIkeHeader::parse(BytesOf(msg), parsed) == SBOX_OK);
    CHECK(parsed.spiI == h.spiI);
    CHECK(parsed.spiR == h.spiR);
    CHECK(parsed.exchange == EIKE_X_AUTH);
    CHECK(parsed.length == msg.size());
    CHECK(parsed.fromInitiator());
    CHECK_FALSE(parsed.isResponse());

    std::vector<SIkePayload> back;
    REQUIRE(ParseIkePayloads(parsed.nextPayload, BytesOf(msg).slice(IKE_HEADER_SIZE), back) == SBOX_OK);
    REQUIRE(back.size() == payloads.size());
    for (size_t i = 0; i < back.size(); ++i) {
        CHECK(back[i].type == payloads[i].type);
        CHECK(back[i].body == payloads[i].body);
    }

    SIkeId id;
    REQUIRE(DecodeIkeId(BytesOf(back[0].body), id) == SBOX_OK);
    CHECK(id.type == EIKE_ID_DER_ASN1_DN);
    CHECK(id.toString() == "CN=client, O=Example, C=KR");

    std::vector<SIkeProposal> props;
    REQUIRE(DecodeIkeSa(BytesOf(back[4].body), props) == SBOX_OK);
    CHECK(props.size() == DefaultEspProposals().size());
    CHECK(props[0].spi == std::vector<uint8_t>{ 1, 2, 3, 4 });
    CHECK(props[0].transforms == DefaultEspProposals()[0].transforms);

    std::vector<SIkeTrafficSelector> ts;
    REQUIRE(DecodeIkeTs(BytesOf(back[5].body), ts) == SBOX_OK);
    REQUIRE(ts.size() == 2);
    CHECK(ts[0].toString() == "10.0.0.0/8[17/500]");
    CHECK(ts[1].toString() == "::/0");

    SIkeDelete del;
    REQUIRE(DecodeIkeDelete(BytesOf(back[7].body), del) == SBOX_OK);
    CHECK(del.spis == std::vector<uint32_t>{ 0x11111111u, 0x22222222u });

    SIkeConfig cp;
    REQUIRE(DecodeIkeConfig(BytesOf(back[3].body), cp) == SBOX_OK);
    REQUIRE(cp.attributes.size() == 2);
    CHECK(cp.attributes[1].value == std::vector<uint8_t>{ 1, 1, 1, 1 });

    // --> Identities.
    for (const char* text : { "10.1.2.3", "2001:db8::1", "@vpn.example.com", "user@example.com", "keyid:0102ff" }) {
        SIkeId x;
        REQUIRE(SIkeId::fromString(text, x) == SBOX_OK);
        std::string expected = text[0] == '@' ? std::string(text + 1) : std::string(text);
        CHECK(x.toString() == expected);
    }
}

TEST_CASE("Traffic selector arithmetic") {
    SIkeTrafficSelector a = SIkeTrafficSelector::any(false);
    net::SIpPrefix p;
    net::SIpPrefix::parse("192.168.1.0/24", p);
    SIkeTrafficSelector b = SIkeTrafficSelector::fromPrefix(p);
    b.protocol = 6;
    SIkeTrafficSelector x;
    REQUIRE(SIkeTrafficSelector::intersect(a, b, x));
    CHECK(x.toString() == "192.168.1.0/24[6]");
    CHECK_FALSE(SIkeTrafficSelector::intersect(b, SIkeTrafficSelector::any(true), x));

    SIkeTrafficSelector odd;
    net::SIpAddress::parse("10.0.0.1", odd.start);
    net::SIpAddress::parse("10.0.0.9", odd.end);
    std::vector<net::SIpPrefix> parts = odd.toPrefixes();
    std::vector<std::string> text;
    for (const net::SIpPrefix& q : parts) {
        text.push_back(q.toString());
    }

    CHECK(text == std::vector<std::string>{ "10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/31" });
    CHECK(SIkeTrafficSelector::any(true).toPrefixes().size() == 1);
    CHECK(SIkeTrafficSelector::any(false).toPrefixes()[0].toString() == "0.0.0.0/0");
}

TEST_CASE("Proposal parsing, formatting and selection") {
    SIkeProposal p;
    REQUIRE(ParseIkeProposal("aes256-sha256-modp2048", EIKE_PROTO_IKE, p) == SBOX_OK);
    CHECK(FormatIkeProposal(p) == "aes256-sha256-prfsha256-modp2048");
    CHECK(ParseIkeProposal("aes256-bogus", EIKE_PROTO_IKE, p) == -EINVAL);
    CHECK(ParseIkeProposal("aes256-sha256", EIKE_PROTO_IKE, p) == -EINVAL);     // --> No DH.
    CHECK(ParseIkeProposal("aes128gcm16-noesn", EIKE_PROTO_ESP, p) == SBOX_OK);
    CHECK(ParseIkeProposal("aes128-sha1-prfsha1", EIKE_PROTO_ESP, p) == -EINVAL);

    // --> Windows default IKE offer: 3DES and AES with SHA1/SHA2 and MODP-1024.
    std::vector<SIkeProposal> windows(3);
    ParseIkeProposal("3des-sha1-modp1024", EIKE_PROTO_IKE, windows[0]);
    ParseIkeProposal("aes256-sha1-modp1024", EIKE_PROTO_IKE, windows[1]);
    ParseIkeProposal("aes128-sha256-modp1024", EIKE_PROTO_IKE, windows[2]);
    for (size_t i = 0; i < windows.size(); ++i) {
        windows[i].number = uint8_t(i + 1);
    }

    SIkeProposal chosen;
    REQUIRE(SelectIkeProposal(windows, DefaultIkeProposals(), EIKE_DH_MODP1024, EIKE_DHM_REQUIRED, nullptr, chosen));
    CHECK(chosen.number == 2);      // --> Our preference (AES-256) wins over the offer order.
    CHECK(FormatIkeProposal(chosen) == "aes256-sha1-prfsha1-modp1024");

    std::vector<SIkeProposal> strict(1);
    ParseIkeProposal("aes256gcm16-prfsha384-ecp384", EIKE_PROTO_IKE, strict[0]);
    CHECK_FALSE(SelectIkeProposal(windows, strict, EIKE_DH_MODP1024, EIKE_DHM_REQUIRED, nullptr, chosen));

    // --> The KE group the peer guessed wins when acceptable.
    std::vector<SIkeProposal> modern(1);
    ParseIkeProposal("aes128gcm16-prfsha256-ecp256-curve25519", EIKE_PROTO_IKE, modern[0]);
    REQUIRE(SelectIkeProposal(modern, DefaultIkeProposals(), EIKE_DH_ECP256, EIKE_DHM_REQUIRED, nullptr, chosen));
    CHECK(chosen.first(EIKE_TT_DH).id == EIKE_DH_ECP256);

    // --> ESP: DH ignored in IKE_AUTH, required with KE, "none" without.
    std::vector<SIkeProposal> esp(1);
    ParseIkeProposal("aes256gcm16-ecp256-noesn", EIKE_PROTO_ESP, esp[0]);
    esp[0].spi = { 9, 9, 9, 9 };
    REQUIRE(SelectIkeProposal(esp, DefaultEspProposals(), 0, EIKE_DHM_IGNORED, nullptr, chosen));
    CHECK(chosen.ofType(EIKE_TT_DH).empty());
    CHECK(chosen.spi == std::vector<uint8_t>{ 9, 9, 9, 9 });
    REQUIRE(SelectIkeProposal(esp, DefaultEspProposals(), EIKE_DH_ECP256, EIKE_DHM_REQUIRED, nullptr, chosen));
    CHECK(chosen.first(EIKE_TT_DH).id == EIKE_DH_ECP256);
    CHECK_FALSE(SelectIkeProposal(esp, DefaultEspProposals(), 0, EIKE_DHM_NONE, nullptr, chosen));

    // --> The data path filter removes transforms it cannot run.
    auto noGcm = [](uint16_t encr, uint16_t, uint16_t) { return encr != EIKE_ENCR_AES_GCM_16; };
    CHECK_FALSE(SelectIkeProposal(esp, DefaultEspProposals(), 0, EIKE_DHM_IGNORED, noGcm, chosen));

    // --> Only ESN offered: we insist on 32-bit sequence numbers by default.
    std::vector<SIkeProposal> esnOnly(1);
    ParseIkeProposal("aes128-sha256-esn", EIKE_PROTO_ESP, esnOnly[0]);
    CHECK_FALSE(SelectIkeProposal(esnOnly, DefaultEspProposals(), 0, EIKE_DHM_IGNORED, nullptr, chosen));
}

TEST_CASE("Random mutations of messages never crash the decoders") {
    std::mt19937 rng(20261004);
    std::vector<SIkePayload> payloads = samplePayloads();
    SIkeHeader h;
    h.spiI = 1;
    h.spiR = 2;
    h.exchange = EIKE_X_AUTH;
    std::vector<uint8_t> msg = ipsec::EncodePlainMessage(h, payloads);

    int32_t accepted = 0;
    for (int32_t i = 0; i < 20000; ++i) {
        std::vector<uint8_t> m = msg;
        int32_t rounds = 1 + int32_t(rng() % 4);
        for (int32_t k = 0; k < rounds; ++k) {
            mutate(m, rng);
        }

        SIkeHeader parsed;
        if (SIkeHeader::parse(BytesOf(m), parsed) != SBOX_OK) {
            continue;
        }

        std::vector<SIkePayload> out;
        if (ParseIkePayloads(parsed.nextPayload, BytesOf(m).slice(IKE_HEADER_SIZE, parsed.length - IKE_HEADER_SIZE), out) == SBOX_OK) {
            ++accepted;
        }

        for (const SIkePayload& p : out) {
            decodeAll(p);
        }
    }

    // --> Bodies on their own too.
    for (const SIkePayload& p : payloads) {
        CHECK(decodeAll(p) > 0);
        for (int32_t i = 0; i < 3000; ++i) {
            SIkePayload q = p;
            mutate(q.body, rng);
            decodeAll(q);
        }
    }

    CHECK(accepted > 0);
}

TEST_CASE("Encrypted payloads: tampering is rejected, fragments reassemble in any order") {
    for (uint16_t encr : { uint16_t(EIKE_ENCR_AES_CBC), uint16_t(EIKE_ENCR_AES_GCM_16), uint16_t(EIKE_ENCR_CHACHA20_POLY1305) }) {
        ipsec::IkeSa a;
        ipsec::IkeSa b;
        a.initiator = true;
        b.initiator = false;
        for (ipsec::IkeSa* s : { &a, &b }) {
            s->spiI = 0x1111;
            s->spiR = 0x2222;
            s->suite.encr = encr;
            s->suite.keyBits = encr == EIKE_ENCR_CHACHA20_POLY1305 ? 0 : 256;
            s->suite.integ = encr == EIKE_ENCR_AES_CBC ? EIKE_INTEG_HMAC_SHA2_256_128 : EIKE_INTEG_NONE;
            s->suite.prf = EIKE_PRF_HMAC_SHA2_256;
            s->ni.assign(32, 1);
            s->nr.assign(32, 2);
            s->fragmentation = true;
            s->fragmentSize = 600;
        }

        std::vector<uint8_t> seed(32, 0x5a);
        REQUIRE(a.installKeys(BytesOf(seed)) == SBOX_OK);
        REQUIRE(b.installKeys(BytesOf(seed)) == SBOX_OK);

        std::vector<SIkePayload> payloads = samplePayloads();
        payloads.push_back(pl(EIKE_PL_CERT, std::vector<uint8_t>(3000, 0x42)));

        std::vector<std::vector<uint8_t>> datagrams;
        REQUIRE(a.encrypt(EIKE_X_AUTH, false, 1, payloads, datagrams) == SBOX_OK);
        REQUIRE(datagrams.size() >= 5);
        for (const auto& d : datagrams) {
            CHECK(d.size() <= 600);
        }

        // --> Deliver in reverse with a duplicate: only the last needed fragment completes it.
        std::vector<std::vector<uint8_t>> order(datagrams.rbegin(), datagrams.rend());
        order.insert(order.begin() + 1, order[0]);
        std::vector<SIkePayload> out;
        int32_t complete = 0;
        for (size_t i = 0; i < order.size(); ++i) {
            SIkeHeader h;
            REQUIRE(SIkeHeader::parse(BytesOf(order[i]), h) == SBOX_OK);
            int32_t r = b.decrypt(h, BytesOf(order[i]), out);
            if (r == SBOX_OK) {
                ++complete;
                CHECK(i + 1 == order.size());
            }
            else {
                CHECK(r == -EAGAIN);
            }
        }

        REQUIRE(complete == 1);
        REQUIRE(out.size() == payloads.size());
        CHECK(out.back().body == payloads.back().body);

        // --> Whole-message protection: every single-bit flip is caught.
        a.fragmentation = false;
        REQUIRE(a.encrypt(EIKE_X_INFORMATIONAL, false, 2, samplePayloads(), datagrams) == SBOX_OK);
        REQUIRE(datagrams.size() == 1);
        std::mt19937 rng(7);
        for (int32_t i = 0; i < 300; ++i) {
            std::vector<uint8_t> m = datagrams[0];
            size_t at = IKE_HEADER_SIZE + rng() % (m.size() - IKE_HEADER_SIZE);
            m[at] ^= uint8_t(1u << (rng() % 8));
            SIkeHeader h;
            if (SIkeHeader::parse(BytesOf(m), h) != SBOX_OK) {
                continue;
            }

            CHECK(b.decrypt(h, BytesOf(m), out) != SBOX_OK);
        }

        SIkeHeader h;
        REQUIRE(SIkeHeader::parse(BytesOf(datagrams[0]), h) == SBOX_OK);
        REQUIRE(b.decrypt(h, BytesOf(datagrams[0]), out) == SBOX_OK);

        // --> Our own message reflected back is refused (wrong Initiator flag).
        CHECK(a.decrypt(h, BytesOf(datagrams[0]), out) == -EBADMSG);
    }
}

TEST_CASE("A live responder survives garbage and mutated messages, then still serves a client") {
    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SIkeServerConfig cfg;
        cfg.listenAddress = "127.0.0.1";
        cfg.port = 0;
        cfg.natPort = 0;
        cfg.forwarding = false;
        net::SIpPrefix::parse("10.66.0.0/24", cfg.pool);
        SIkePsk psk;
        psk.secret = "fuzz";
        cfg.psks.push_back(psk);
        const Pki& pki = Pki::get();
        cfg.certificate = pki.server;
        SIkeUser u;
        u.name = "u";
        u.password = "p";
        cfg.users.push_back(u);

        auto path = std::make_shared<FakeDataPath>();
        CIkeServer server(cfg);
        REQUIRE(co_await server.start(path) == SBOX_OK);

        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        REQUIRE(fd >= 0);
        auto sendTo = [&](uint16_t port, const std::vector<uint8_t>& data) {
            sockaddr_in sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        };

        // --> A valid IKE_SA_INIT request as a mutation seed.
        std::vector<SIkePayload> init;
        std::vector<uint8_t> body;
        EncodeIkeSa(DefaultIkeProposals(), body);
        init.push_back(pl(EIKE_PL_SA, body));
        CIkeDh dh;
        REQUIRE(dh.generate(EIKE_DH_CURVE25519) == SBOX_OK);
        body.clear();
        EncodeIkeKe(EIKE_DH_CURVE25519, BytesOf(dh.publicValue()), body);
        init.push_back(pl(EIKE_PL_KE, body));
        init.push_back(pl(EIKE_PL_NONCE, std::vector<uint8_t>(32, 3)));
        init.push_back(MakeIkeNotify(EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED));

        std::mt19937 rng(4242);
        for (int32_t i = 0; i < 1500; ++i) {
            SIkeHeader h;
            h.spiI = 0x1000 + uint64_t(i);
            h.exchange = uint8_t(rng() % 3 == 0 ? EIKE_X_AUTH : EIKE_X_SA_INIT);
            h.flags = EIKE_F_INITIATOR;
            std::vector<uint8_t> m = ipsec::EncodePlainMessage(h, init);
            int32_t rounds = int32_t(rng() % 4);
            for (int32_t k = 0; k < rounds; ++k) {
                mutate(m, rng);
            }

            bool nat = rng() & 1;
            if (nat) {
                m.insert(m.begin(), 4, 0);
            }

            sendTo(nat ? server.natPort() : server.port(), m);
            if (i % 100 == 0) {
                co_await CEventLoop::current()->sleepFor(1);
            }
        }

        std::vector<uint8_t> tiny = { 0xff };
        sendTo(server.natPort(), tiny);
        sendTo(server.port(), std::vector<uint8_t>());
        sendTo(server.natPort(), std::vector<uint8_t>(12, 0x41));
        co_await CEventLoop::current()->sleepFor(200);
        ::close(fd);

        SIkeInitiatorConfig cc;
        cc.server = "127.0.0.1";
        cc.serverPort = server.port();
        cc.serverNatPort = server.natPort();
        cc.identity = "@after.fuzz";
        cc.psk = "fuzz";
        CIkeInitiator client(cc);
        CHECK(co_await client.connect() == SBOX_OK);
        co_await client.close();
        co_await server.stop();
    }());
}
