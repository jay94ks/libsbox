#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include <sbox/vpn/ipsec/eap.hpp>
#include "ipsec/crypto.hpp"
#include "ipsec/ikesa.hpp"
#include <string>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    std::vector<uint8_t> hex(std::string_view text) {
        std::vector<uint8_t> out;
        REQUIRE(ipsec::FromHex(text, out));
        return out;
    }

    std::vector<uint8_t> range(uint8_t from, size_t count) {
        std::vector<uint8_t> out(count);
        for (size_t i = 0; i < count; ++i) {
            out[i] = uint8_t(from + i);
        }

        return out;
    }

    std::string str(const std::vector<uint8_t>& v) {
        return ipsec::ToHex(BytesOf(v));
    }

}

// --> Expected values below were computed independently with Python's hmac/hashlib and the
// `cryptography` package (OpenSSL), see docs/logs/2026-10-04-vpn-ipsec.md.

TEST_CASE("prf+ matches an independent HMAC implementation for every PRF") {
    std::vector<uint8_t> key = range(0, 32);
    std::string seedText = "libsbox prf+ seed";
    std::string seed = seedText + seedText + seedText;

    struct Case { uint16_t prf; const char* expected; };
    const Case cases[] = {
        { EIKE_PRF_HMAC_SHA1, "46852e12b52eeb7e73846a7887b3682e99a0f310bf0e62e343acb209feb9325e9a808c572029dd43e5371a6a1e1619852f86adc79c723f28f1af4fbe15442ba8e3abaefd49af26fd9daa63e078b4d782a227be59c21d82fdb9d6a893f6c9101676d39be5" },
        { EIKE_PRF_HMAC_SHA2_256, "490be8b65e0a09d707bbd16a74f95f1bbe4ef32ecd9d97ee4c3182434255fc9802087f068c261e9981d5641d6b51fa50e9ba0768ba71c3acda3102f5945635166f98ab53a0f2f10c1cdea9a4db32d595cacce0a9f024c4ebdd42ac4f79bd92a5519d0722" },
        { EIKE_PRF_HMAC_SHA2_384, "591bd3722b7e33876a3af0cf74bf26e325498cfac231512785b4530e59ea061c99894ab8241d29b3d38ab75687683f3dd86cf2195f7ae22cb66a74073244d06d7df1f23c20b946cf1658560a99f78580d6dbc6ff6634b84a6e36c880ff2820bf733bbabc" },
        { EIKE_PRF_HMAC_SHA2_512, "4e91c52541670c7c036d6bb0bbcb4e03b4c2638e41a92b169301a0ed1876d3535c978763d0693de03213bf7cb865cbaf1a2e75c11afe3346a9f54cb417a9a10193928790f3506fba8b159431c380b75360c81d646c4c4e69a197c0afa0c49cdba8ef0fc1" },
    };

    for (const Case& c : cases) {
        std::vector<uint8_t> out;
        REQUIRE(IkePrfPlus(c.prf, BytesOf(key), BytesOf(seed), 100, out) == SBOX_OK);
        CHECK(str(out) == c.expected);
    }

    std::vector<uint8_t> out;
    CHECK(IkePrfPlus(EIKE_PRF_HMAC_SHA1, BytesOf(key), BytesOf(seed), 20 * 256, out) == -EINVAL);
    CHECK(IkePrfPlus(99, BytesOf(key), BytesOf(seed), 20, out) == -ENOTSUP);
}

TEST_CASE("X25519 and MODP-2048 agree with known vectors; ECP groups agree with each other") {
    std::vector<uint8_t> secret;

    CIkeDh a;
    REQUIRE(a.loadPrivate(EIKE_DH_CURVE25519, BytesOf(range(1, 32))) == SBOX_OK);
    CHECK(str(a.publicValue()) == "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
    REQUIRE(a.agree(BytesOf(hex("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b")), secret) == SBOX_OK);
    CHECK(str(secret) == "a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77");
    CHECK(a.agree(BytesOf(std::vector<uint8_t>(32, 0)), secret) == -EINVAL);
    CHECK(a.agree(BytesOf(std::vector<uint8_t>(31, 9)), secret) == -EINVAL);

    CIkeDh m;
    REQUIRE(m.loadPrivate(EIKE_DH_MODP2048, BytesOf(hex("1122334455667788"))) == SBOX_OK);
    CHECK(m.publicValue().size() == 256);
    std::vector<uint8_t> yb = hex(
        "211d5f1743083d13f8c5439aa86f15c5ba769ca68d2ab1d990ad7f9214c58197ce52495b5315aca2b2a12bfdddaf4d3ac61052f061254386d3267a0d579c4cadbee37644e39a47241f2f56271f07f915c41b3e16168502837c114e2c95afcb5176beea28aa3c5813ff7ecec771113c57c08b25a08f1ea27199e6494a4301066597eae3924dba8c77c4871ecd2a438cfec0511054b26696ae4203db01dfba0042399bd2f37d4642db4eb35f57ad3091faa81c2981ac8feb9c6878f35ed2518373ea3dd4b2ce41af3135f0cd4eb74b5bf8c3d226da819ae3e8f0ff94ce6f57157a468cb274389f1cac890249021d05faab7b043c6e10c7228c247aed6396380614");
    REQUIRE(m.agree(BytesOf(yb), secret) == SBOX_OK);
    CHECK(str(secret) == "f476e6ebe4dafaaac4c906fbdc5b5d1544973f25e94cb322a16cb6d47282798a659202b66214a2a9806371779f212bf48651d19bc35370b6e26b9f33def9e89ea2f21e8b2ff6f104353ff4502ca442217656bd90831b6d44d334e42258db8e9bb656d78306d103aac9ba9bc48a0d11645eae00dde549682835d464537305f3e8b16c5ce1d06abe7eb5c8a692fc433ffc1b873437b3be118eb8d9a2b1b11f8d533e814999d7eb8d8c1a56d226b8da88b83db2967feb58d97a295fde994f960ec2170622491b1cc7f5d348810db73780d56a94f8dc78a487d9c8e0ae78ceb73c4aee317fd2cfc65575630d029a33a7a2a6b411ee586c65cf081dbc2114ee0e63c2");

    // --> RFC 6989: 1 and p-1 are rejected.
    std::vector<uint8_t> one(256, 0);
    one[255] = 1;
    CHECK(m.agree(BytesOf(one), secret) == -EINVAL);

    for (uint16_t group : { uint16_t(EIKE_DH_MODP1024), uint16_t(EIKE_DH_MODP2048), uint16_t(EIKE_DH_ECP256),
                            uint16_t(EIKE_DH_ECP384), uint16_t(EIKE_DH_CURVE25519) }) {
        CIkeDh x;
        CIkeDh y;
        REQUIRE(x.generate(group) == SBOX_OK);
        REQUIRE(y.generate(group) == SBOX_OK);
        CHECK(x.publicValue().size() == CIkeDh::publicSize(group));

        std::vector<uint8_t> s1;
        std::vector<uint8_t> s2;
        REQUIRE(x.agree(BytesOf(y.publicValue()), s1) == SBOX_OK);
        REQUIRE(y.agree(BytesOf(x.publicValue()), s2) == SBOX_OK);
        CHECK(s1 == s2);
        CHECK(!s1.empty());
    }

    CIkeDh bad;
    CHECK(bad.generate(5) == -ENOTSUP);
}

TEST_CASE("CIpsecCipher matches AES-CBC+HMAC, AES-GCM and ChaCha20-Poly1305 vectors and rejects tampering") {
    std::vector<uint8_t> aad = hex("00112233445566778899aabbccddeeff");
    aad.push_back('h');
    aad.push_back('d');
    aad.push_back('r');
    aad.push_back('!');
    std::vector<uint8_t> plain = range(0, 48);

    struct Case {
        uint16_t encr;
        uint16_t bits;
        uint16_t integ;
        std::vector<uint8_t> key;
        std::vector<uint8_t> integKey;
        std::vector<uint8_t> iv;
        const char* expected;
    };

    std::vector<uint8_t> gcmKey = range(0x30, 16);
    for (uint8_t b : hex("cafebabe")) {
        gcmKey.push_back(b);
    }

    std::vector<uint8_t> chachaKey = range(0x50, 32);
    for (uint8_t b : hex("cafebabe")) {
        chachaKey.push_back(b);
    }

    std::vector<Case> cases = {
        { EIKE_ENCR_AES_CBC, 256, EIKE_INTEG_HMAC_SHA2_256_128, range(0xa0, 32), range(0xc0, 32), range(0xe0, 16),
          "e0e1e2e3e4e5e6e7e8e9eaebecedeeef910eed6382bc6ba6ea37c84ad2cb154f215f53a814a91280063cfb28233f626b4063b5e3ddfd79bcfbc969a3d6fa5db3182a7728fecd82f896de29ca6d4d0e00" },
        { EIKE_ENCR_AES_GCM_16, 128, EIKE_INTEG_NONE, gcmKey, {}, hex("0001020304050607"),
          "0001020304050607bfdd37d851cdd0e88c14437e019f00a7d477d3697021fc9c4cc15ad9ffef59dfd0aaeea5ea85d896a1f1b83706583d8c807386b8712be6b4a84999d89666c932" },
        { EIKE_ENCR_CHACHA20_POLY1305, 0, EIKE_INTEG_NONE, chachaKey, {}, hex("0001020304050607"),
          "0001020304050607c9787516a216b489dafe213b2bdb387302ccef37e9263bee9ab82e4c62a890131d8b5cc4befc7d31fc5127b4aeefc4702a2e0f19273213f1c60d1c19308ca626" },
    };

    for (const Case& c : cases) {
        CIpsecCipher cipher;
        REQUIRE(cipher.init(c.encr, c.bits, c.integ, BytesOf(c.key), BytesOf(c.integKey)) == SBOX_OK);

        std::vector<uint8_t> sealed;
        REQUIRE(cipher.seal(BytesOf(aad), BytesOf(plain), sealed, BytesOf(c.iv)) == SBOX_OK);
        CHECK(str(sealed) == c.expected);

        std::vector<uint8_t> opened;
        REQUIRE(cipher.open(BytesOf(aad), BytesOf(sealed), opened) == SBOX_OK);
        CHECK(opened == plain);

        // --> Random/counter IVs round-trip too.
        std::vector<uint8_t> sealed2;
        REQUIRE(cipher.seal(BytesOf(aad), BytesOf(plain), sealed2) == SBOX_OK);
        REQUIRE(cipher.open(BytesOf(aad), BytesOf(sealed2), opened) == SBOX_OK);
        CHECK(opened == plain);

        for (size_t at : { size_t(0), sealed.size() / 2, sealed.size() - 1 }) {
            std::vector<uint8_t> bad = sealed;
            bad[at] ^= 0x01;
            CHECK(cipher.open(BytesOf(aad), BytesOf(bad), opened) == -EKEYREJECTED);
        }

        std::vector<uint8_t> badAad = aad;
        badAad[0] ^= 0x80;
        CHECK(cipher.open(BytesOf(badAad), BytesOf(sealed), opened) == -EKEYREJECTED);
        CHECK(cipher.open(BytesOf(aad), SReadOnlyByteSpan(sealed.data(), 5), opened) == -EBADMSG);
    }

    CIpsecCipher wrong;
    CHECK(wrong.init(EIKE_ENCR_AES_CBC, 256, EIKE_INTEG_NONE, BytesOf(range(0, 32)), SReadOnlyByteSpan()) == -EINVAL);
    CHECK(wrong.init(EIKE_ENCR_AES_CBC, 100, EIKE_INTEG_HMAC_SHA1_96, BytesOf(range(0, 32)), BytesOf(range(0, 20))) == -EINVAL);
    CHECK(wrong.init(77, 128, EIKE_INTEG_NONE, BytesOf(range(0, 16)), SReadOnlyByteSpan()) == -ENOTSUP);

    CIpsecCipher des3;
    REQUIRE(des3.init(EIKE_ENCR_3DES, 0, EIKE_INTEG_HMAC_SHA1_96, BytesOf(range(1, 24)), BytesOf(range(2, 20))) == SBOX_OK);
    std::vector<uint8_t> sealed;
    std::vector<uint8_t> opened;
    REQUIRE(des3.seal(SReadOnlyByteSpan(), BytesOf(plain), sealed) == SBOX_OK);
    CHECK(sealed.size() == 8 + 48 + 12);
    REQUIRE(des3.open(SReadOnlyByteSpan(), BytesOf(sealed), opened) == SBOX_OK);
    CHECK(opened == plain);
}

TEST_CASE("MS-CHAPv2 matches RFC 2759 9.2 and RFC 3079 3.5.3") {
    std::vector<uint8_t> authChallenge = hex("5B5D7C7D7B3F2F3E3C2C602132262628");
    std::vector<uint8_t> peerChallenge = hex("21402324255E262A28295F2B3A337C7E");

    uint8_t challenge[8];
    REQUIRE(MsChapChallengeHash(BytesOf(peerChallenge), BytesOf(authChallenge), "User", SByteSpan(challenge, 8)) == SBOX_OK);
    CHECK(ipsec::ToHex(SReadOnlyByteSpan(challenge, 8), true) == "D02E4386BCE91226");

    std::vector<uint8_t> hash(16);
    REQUIRE(MsChapNtPasswordHash("clientPass", BytesOf(hash)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(hash), true) == "44EBBA8D5312B8D611474411F56989AE");

    std::vector<uint8_t> nt(24);
    REQUIRE(MsChapNtResponse(BytesOf(authChallenge), BytesOf(peerChallenge), "User", BytesOf(hash), BytesOf(nt)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(nt), true) == "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");

    std::vector<uint8_t> hashHash(16);
    REQUIRE(MsChapHashNtPasswordHash(BytesOf(hash), BytesOf(hashHash)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(hashHash), true) == "41C00C584BD2D91C4017A2A12FA59F3F");

    CHECK(MsChapAuthenticatorResponse(BytesOf(hash), BytesOf(nt), BytesOf(peerChallenge), BytesOf(authChallenge), "User")
          == "S=407A5589115FD0D6209F510FE9C04566932CDA56");

    std::vector<uint8_t> master(16);
    REQUIRE(MsChapMasterKey(BytesOf(hash), BytesOf(nt), BytesOf(master)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(master), true) == "FDECE3717A8C838CB388E527AE3CDD31");

    // --> RFC 3079 3.5.3's SendStartKey128 is the server's send key (Magic3), which is the
    // client's receive key.
    std::vector<uint8_t> serverSend(16);
    REQUIRE(MsChapAsymmetricStartKey(BytesOf(master), true, true, BytesOf(serverSend)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(serverSend), true) == "8B7CDC149B993A1BA118CB153F56DCCB");

    std::vector<uint8_t> clientRecv(16);
    REQUIRE(MsChapAsymmetricStartKey(BytesOf(master), false, false, BytesOf(clientRecv)) == SBOX_OK);
    CHECK(clientRecv == serverSend);

    std::vector<uint8_t> clientSend(16);
    REQUIRE(MsChapAsymmetricStartKey(BytesOf(master), true, false, BytesOf(clientSend)) == SBOX_OK);
    CHECK(ipsec::ToHex(BytesOf(clientSend), true) == "D5F0E9521E3EA9589645E86051C82226");

    // --> MSK = peer send key | peer receive key | 32 zero bytes.
    std::vector<uint8_t> msk;
    REQUIRE(MsChapV2Msk(BytesOf(hash), BytesOf(nt), msk) == SBOX_OK);
    REQUIRE(msk.size() == 64);
    CHECK(std::vector<uint8_t>(msk.begin(), msk.begin() + 16) == clientSend);
    CHECK(std::vector<uint8_t>(msk.begin() + 16, msk.begin() + 32) == clientRecv);
    CHECK(std::vector<uint8_t>(msk.begin() + 32, msk.end()) == std::vector<uint8_t>(32, 0));

    CHECK(MsChapUserName("CORP\\User") == "User");
    CHECK(MsChapUserName("User") == "User");

    // --> Non-ASCII passwords are converted to UTF-16 (two code units for U+1F600).
    std::vector<uint8_t> h2(16);
    CHECK(MsChapNtPasswordHash("p\xc3\xa4ss\xf0\x9f\x98\x80", BytesOf(h2)) == SBOX_OK);
    CHECK(MsChapNtPasswordHash("bad\xc3", BytesOf(h2)) == -EINVAL);
}

TEST_CASE("EAP-MSCHAPv2 server and peer authenticate and derive the same MSK") {
    std::vector<uint8_t> aliceHash(16);
    REQUIRE(MsChapNtPasswordHash("s3cret", BytesOf(aliceHash)) == SBOX_OK);

    auto lookup = [&](const std::string& user, std::vector<uint8_t>& out) {
        if (user != "alice") {
            return false;
        }

        out = aliceHash;
        return true;
    };

    for (bool askIdentity : { true, false }) {
        CEapMsChapV2Server server(lookup);
        CEapMsChapV2Peer peer("alice", "CORP\\alice", "s3cret");

        std::vector<uint8_t> request = server.start(askIdentity);
        EEapStatus serverStatus = EEAPS_CONTINUE;
        EEapStatus peerStatus = EEAPS_CONTINUE;
        int32_t rounds = 0;

        while (serverStatus == EEAPS_CONTINUE && rounds++ < 10) {
            std::vector<uint8_t> response;
            peerStatus = peer.process(BytesOf(request), response);
            REQUIRE(peerStatus == EEAPS_CONTINUE);
            serverStatus = server.process(BytesOf(response), request);
        }

        REQUIRE(serverStatus == EEAPS_SUCCESS);
        std::vector<uint8_t> none;
        CHECK(peer.process(BytesOf(request), none) == EEAPS_SUCCESS);
        CHECK(server.user() == "alice");
        CHECK(server.identity() == (askIdentity ? "alice" : ""));
        CHECK(server.msk().size() == 64);
        CHECK(server.msk() == peer.msk());
    }

    // --> Wrong password: the server sends an MS-CHAPv2 Failure, then EAP-Failure.
    CEapMsChapV2Server server(lookup);
    CEapMsChapV2Peer peer("alice", "alice", "wrong");
    std::vector<uint8_t> request = server.start(false);
    std::vector<uint8_t> response;
    REQUIRE(peer.process(BytesOf(request), response) == EEAPS_CONTINUE);
    REQUIRE(server.process(BytesOf(response), request) == EEAPS_CONTINUE);
    CHECK(peer.process(BytesOf(request), response) == EEAPS_FAILURE);
    CHECK(server.process(BytesOf(response), request) == EEAPS_FAILURE);
    SEapPacket last;
    REQUIRE(SEapPacket::parse(BytesOf(request), last) == SBOX_OK);
    CHECK(last.code == EEAP_FAILURE);
    CHECK(server.msk().empty());

    // --> Garbage never succeeds.
    CEapMsChapV2Server s2(lookup);
    s2.start(true);
    std::vector<uint8_t> junk = { 2, 9, 0, 3 };
    CHECK(s2.process(BytesOf(junk), request) == EEAPS_FAILURE);
}

TEST_CASE("SKEYSEED, SK_* split, CHILD KEYMAT and rekey SKEYSEED match an independent computation") {
    std::vector<uint8_t> ni = range(0x10, 32);
    std::vector<uint8_t> nr = range(0x40, 32);
    std::vector<uint8_t> gir = range(0x80, 32);

    std::vector<uint8_t> skeyseed;
    REQUIRE(ipsec::ComputeSkeyseed(EIKE_PRF_HMAC_SHA2_256, BytesOf(ni), BytesOf(nr), BytesOf(gir), skeyseed) == SBOX_OK);
    CHECK(str(skeyseed) == "d962ef6e1398f0b4c4a0541c7ce335a4eb85a116a981052a841ee091a413cacb");

    ipsec::Suite suite;
    suite.encr = EIKE_ENCR_AES_CBC;
    suite.keyBits = 256;
    suite.integ = EIKE_INTEG_HMAC_SHA2_256_128;
    suite.prf = EIKE_PRF_HMAC_SHA2_256;
    ipsec::IkeKeys keys;
    REQUIRE(ipsec::DeriveIkeKeys(suite, BytesOf(skeyseed), BytesOf(ni), BytesOf(nr), 0x0102030405060708ull, 0x1112131415161718ull,
                                 keys) == SBOX_OK);

    std::string km = "c722ec79f3a6f0fdf87e7d7286473ceedfc74bf31ac7839e19182a1423795f9ed5059c6d4aa25e27ad4c0f860b90ccd9ca06fb1931f2b2f36f0b0fa2f5e6374d9ef86245814f6807fea335556ec21e4b17b916775a7ae93b8b2b04a0e5d51382010462b0dd90c5a9331cde56e9c2c7bab1558566bee0337afcf43c5d50b22276856b5081172d29354a66752eb21ca7f0661cdc5db04232cff5fc6f18f6542a725ea13121d56eb4117e3bba0e0e9889870821a071acb94a43cc11491e739e7343e65667302cf21036f38897f1978b6ee3a95285135855d319981f0cdb08ef494c";
    CHECK(str(keys.d) + str(keys.ai) + str(keys.ar) + str(keys.ei) + str(keys.er) + str(keys.pi) + str(keys.pr) == km);
    CHECK(keys.ai.size() == 32);
    CHECK(keys.ei.size() == 32);

    ipsec::ChildKeys child;
    std::vector<uint8_t> none;
    REQUIRE(ipsec::DeriveChildKeys(EIKE_PRF_HMAC_SHA2_256, BytesOf(keys.d), BytesOf(none), BytesOf(ni), BytesOf(nr), suite, child)
            == SBOX_OK);
    CHECK(str(child.encIr) + str(child.integIr) + str(child.encRi) + str(child.integRi)
          == "805d03c6852b82de66e86f2407798f6c03e6364920e12105b1e0bd6f25bd8c0a76d7646a381dab8cf3ec2a1ec97174f639109469d17a39b6c8f99eb39aaabf7f12a8648ec9f39988ef980da80392e18a3cfd336140018769d6d3a7617f7b691fdaf689a1b0e683c47c08a1bd29ccd37ffb3e6f5077d1b0e6cef96e609a475855");

    std::vector<uint8_t> rekey;
    REQUIRE(ipsec::ComputeRekeySkeyseed(EIKE_PRF_HMAC_SHA2_256, BytesOf(keys.d), BytesOf(gir), BytesOf(ni), BytesOf(nr), rekey)
            == SBOX_OK);
    CHECK(str(rekey) == "5049693599cb472e9e8492ad3ddde2fac3b9fd7c7ceadef12616e4ada1b0de71");

    // --> AEAD suites take a 4-byte salt per direction and no integrity keys.
    ipsec::Suite gcm;
    gcm.encr = EIKE_ENCR_AES_GCM_16;
    gcm.keyBits = 128;
    gcm.prf = EIKE_PRF_HMAC_SHA2_256;
    ipsec::IkeKeys aead;
    REQUIRE(ipsec::DeriveIkeKeys(gcm, BytesOf(skeyseed), BytesOf(ni), BytesOf(nr), 1, 2, aead) == SBOX_OK);
    CHECK(aead.ai.empty());
    CHECK(aead.ei.size() == 20);
}
