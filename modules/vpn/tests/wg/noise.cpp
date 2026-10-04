#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/key.hpp>
#include "wg/noise.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace sbox;
using namespace sbox::vpn;

// --> Known-answer vectors produced by an independent Python implementation of the whitepaper
// (hashlib BLAKE2s, the `cryptography` package's X25519 and ChaCha20-Poly1305, a separate
// HChaCha20) with fixed static/ephemeral keys, timestamp and indices.
static const char* V_SI = "0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60";
static const char* V_SR = "2022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
static const char* V_EI = "4042434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60";
static const char* V_ER = "6062636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f40";
static const char* V_PSK = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
static const char* V_TS = "400000006553f10012345678";
static const char* V_SI_PUB = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
static const char* V_SR_PUB = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
static const char* V_INIT = "010000004433221164b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466158a0e4ca242d151ca97ab90159a98b67e616625e68b4065d357376b6598e644ad7d678c0295d22de4cb43d5135581ed36346bfa7cf42a18330daeeb3233b39d517ed513ef373141b9e1436330c647cdddd3aaa589155cefce16ac8c00000000000000000000000000000000";
static const char* V_RESP = "020000008877665544332211244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49a8b99e8780ad38953a84c8852712892b1bbed38a2916d9d85504aebebebf338c00000000000000000000000000000000";
static const char* V_T_SEND_I = "e3916bcfbbb22df88182fbb8a7a716cecd481608da4a009066b6b5b76efc08ba";
static const char* V_T_RECV_I = "4a3f7bf2149bb9e7a6eb1b70b1179979b4c97ea3b7acc849d7fc1994134a9b1e";
static const char* V_PAYLOAD = "4500001c000100004001000000000000000000000000000000000000";
static const char* V_DATA = "040000008877665500000000000000006ee552279228644a4db0e714aaab6b127bc1ccddcfd66cc297010e0aa2f0613a9ed5797c1b719d5d2be1bbdb69f11cbd";
static const char* V_SECRET = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
static const char* V_COOKIE = "0497b4e10443a6ed853e75ddf99d4d1c";
static const char* V_NONCE = "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
static const char* V_COOKIE_REPLY = "0300000044332211c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfcc8ad9aae25ea8ec1aa6f38ef56e8baeafcc7d4c48d9fefd40dda181a4271df3";
static const char* V_MAC2_INIT = "a3a01c2ddfd01450f240aa78925e4136";

static std::vector<uint8_t> unhex(const char* text) {
    std::vector<uint8_t> out;
    size_t n = std::strlen(text);
    for (size_t i = 0; i + 1 < n; i += 2) {
        out.push_back(uint8_t(std::stoi(std::string(text + i, 2), nullptr, 16)));
    }

    return out;
}

static std::string hex(const uint8_t* data, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(d[data[i] >> 4]);
        out.push_back(d[data[i] & 15]);
    }

    return out;
}

static SWgKey key(const char* h) {
    SWgKey k;
    REQUIRE(SWgKey::fromHex(h, k) == SBOX_OK);
    return k;
}

TEST_CASE("keys: base64/hex round trip, public key derivation") {
    SWgKey priv;
    REQUIRE(GenerateWgPrivateKey(priv) == SBOX_OK);
    CHECK((priv.bytes[0] & 7) == 0);
    CHECK((priv.bytes[31] & 0xc0) == 0x40);

    std::string b64 = priv.toBase64();
    CHECK(b64.size() == 44);
    SWgKey back;
    REQUIRE(SWgKey::fromBase64(b64, back) == SBOX_OK);
    CHECK(back == priv);

    CHECK(SWgKey::fromBase64("short", back) == -EINVAL);
    CHECK(SWgKey::fromBase64(b64.substr(0, 43) + "x", back) == -EINVAL);

    SWgKey pub;
    REQUIRE(DeriveWgPublicKey(key(V_SI), pub) == SBOX_OK);
    CHECK(pub.toHex() == V_SI_PUB);

    // --> RFC 7748 6.1 test vector: Alice's private key and public key in wg's base64 form.
    SWgKey alice;
    REQUIRE(SWgKey::fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice) == SBOX_OK);
    REQUIRE(DeriveWgPublicKey(alice, pub) == SBOX_OK);
    CHECK(pub.toHex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    CHECK(pub.toBase64() == "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");

    // --> Low-order points are refused.
    uint8_t secret[32];
    SWgKey zero;
    zero.valid = true;
    CHECK(WgSharedSecret(alice, zero, secret) == -EKEYREJECTED);
}

TEST_CASE("noise: initiation, response and transport keys match the reference") {
    SWgKey si = key(V_SI), sr = key(V_SR);
    SWgKey siPub, srPub;
    REQUIRE(DeriveWgPublicKey(si, siPub) == SBOX_OK);
    REQUIRE(DeriveWgPublicKey(sr, srPub) == SBOX_OK);
    CHECK(srPub.toHex() == V_SR_PUB);

    std::vector<uint8_t> ei = unhex(V_EI), er = unhex(V_ER), psk = unhex(V_PSK), ts = unhex(V_TS);

    uint8_t ss[32];
    REQUIRE(WgSharedSecret(si, srPub, ss) == SBOX_OK);

    // -- Initiator builds the initiation.
    NoiseHandshake hi;
    uint8_t init[MSG_INITIATION_BYTES];
    REQUIRE(NoiseCreateInitiation(siPub, srPub, ss, ei.data(), ts.data(), 0x11223344, hi, init));
    uint8_t mac1Key[32];
    NoiseLabelKey("mac1----", srPub, mac1Key);
    NoiseMac(init + OFF_INIT_MAC1, SReadOnlyByteSpan(mac1Key, 32), SReadOnlyByteSpan(init, OFF_INIT_MAC1));
    CHECK(hex(init, sizeof(init)) == V_INIT);

    // -- Responder consumes it.
    NoiseHandshake hr;
    SWgKey remote;
    REQUIRE(NoiseConsumeInitiationStatic(sr, srPub, init, hr, remote));
    CHECK(remote == siPub);
    uint8_t ss2[32];
    REQUIRE(WgSharedSecret(sr, siPub, ss2) == SBOX_OK);
    uint8_t gotTs[12];
    REQUIRE(NoiseConsumeInitiationFinish(hr, ss2, init, gotTs));
    CHECK(hex(gotTs, 12) == V_TS);
    CHECK(hr.remoteIndex == 0x11223344u);

    // -- Responder answers.
    uint8_t resp[MSG_RESPONSE_BYTES];
    REQUIRE(NoiseCreateResponse(hr, siPub, psk.data(), er.data(), 0x55667788, resp));
    NoiseLabelKey("mac1----", siPub, mac1Key);
    NoiseMac(resp + OFF_RESP_MAC1, SReadOnlyByteSpan(mac1Key, 32), SReadOnlyByteSpan(resp, OFF_RESP_MAC1));
    CHECK(hex(resp, sizeof(resp)) == V_RESP);

    // -- Initiator consumes the response; a wrong psk fails and leaves the state untouched.
    NoiseHandshake saved = hi;
    uint8_t wrong[32];
    std::memset(wrong, 0, sizeof(wrong));
    CHECK_FALSE(NoiseConsumeResponse(hi, si, wrong, resp));
    CHECK(std::memcmp(&saved, &hi, sizeof(hi)) == 0);
    REQUIRE(NoiseConsumeResponse(hi, si, psk.data(), resp));
    CHECK(hi.remoteIndex == 0x55667788u);

    uint8_t sendI[32], recvI[32], sendR[32], recvR[32];
    NoiseDeriveKeys(hi, true, sendI, recvI);
    NoiseDeriveKeys(hr, false, sendR, recvR);
    CHECK(hex(sendI, 32) == V_T_SEND_I);
    CHECK(hex(recvI, 32) == V_T_RECV_I);
    CHECK(std::memcmp(sendI, recvR, 32) == 0);
    CHECK(std::memcmp(recvI, sendR, 32) == 0);

    // -- First data message.
    std::vector<uint8_t> payload = unhex(V_PAYLOAD);
    std::vector<uint8_t> data(16 + 32 + 16);
    StoreLe32(data.data(), MSG_DATA);
    StoreLe32(data.data() + 4, 0x55667788);
    StoreLe64(data.data() + 8, 0);
    std::memcpy(data.data() + 16, payload.data(), payload.size());
    std::memset(data.data() + 16 + payload.size(), 0, 32 - payload.size());
    REQUIRE(NoiseSeal(sendI, 0, SReadOnlyByteSpan(data.data() + 16, 32), SReadOnlyByteSpan(), data.data() + 16));
    CHECK(hex(data.data(), data.size()) == V_DATA);
}

TEST_CASE("noise: cookie reply and MAC2 match the reference") {
    SWgKey srPub = key(V_SR_PUB);
    std::vector<uint8_t> secret = unhex(V_SECRET), nonce = unhex(V_NONCE), init = unhex(V_INIT);

    uint8_t cookie[16];
    const uint8_t addr[4] = { 192, 0, 2, 1 };
    NoiseMakeCookie(secret.data(), addr, 4, 51820, cookie);
    CHECK(hex(cookie, 16) == V_COOKIE);

    uint8_t cookieKey[32];
    NoiseLabelKey("cookie--", srPub, cookieKey);
    uint8_t reply[MSG_COOKIE_REPLY_BYTES];
    REQUIRE(NoiseCreateCookieReply(cookieKey, 0x11223344, nonce.data(), cookie, init.data() + OFF_INIT_MAC1, reply));
    CHECK(hex(reply, sizeof(reply)) == V_COOKIE_REPLY);

    uint8_t opened[16];
    REQUIRE(NoiseConsumeCookieReply(cookieKey, reply, init.data() + OFF_INIT_MAC1, opened));
    CHECK(std::memcmp(opened, cookie, 16) == 0);

    // --> A reply bound to another MAC1 does not open.
    uint8_t otherMac[16];
    std::memset(otherMac, 1, sizeof(otherMac));
    CHECK_FALSE(NoiseConsumeCookieReply(cookieKey, reply, otherMac, opened));

    uint8_t mac2[16];
    NoiseMac(mac2, SReadOnlyByteSpan(cookie, 16), SReadOnlyByteSpan(init.data(), OFF_INIT_MAC2));
    CHECK(hex(mac2, 16) == V_MAC2_INIT);
}

TEST_CASE("noise: TAI64N timestamps increase") {
    uint8_t a[12], b[12];
    NoiseTai64n(a);
    std::memcpy(b, a, 12);
    CHECK_FALSE(NoiseTimestampAfter(b, a));
    b[11] = uint8_t(b[11] + 1);
    CHECK(NoiseTimestampAfter(b, a));
    CHECK((a[0] & 0x40) == 0x40);
}
