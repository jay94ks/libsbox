#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/esp.hpp>
#include "ipsec/crypto.hpp"

using namespace sbox;
using namespace sbox::vpn;

namespace {

    SEspKeys gcmKeys() {
        SEspKeys k;
        k.encr = EIKE_ENCR_AES_GCM_16;
        k.keyBits = 128;
        k.encKey.assign(20, 0x11);
        return k;
    }

    SEspKeys cbcKeys() {
        SEspKeys k;
        k.encr = EIKE_ENCR_AES_CBC;
        k.keyBits = 256;
        k.integ = EIKE_INTEG_HMAC_SHA2_256_128;
        k.encKey.assign(32, 0x22);
        k.integKey.assign(32, 0x33);
        return k;
    }

    std::vector<uint8_t> packet(size_t n, uint8_t seed) {
        std::vector<uint8_t> p(n);
        for (size_t i = 0; i < n; ++i) {
            p[i] = uint8_t(seed + i);
        }

        p[0] = 0x45;    // --> Looks like IPv4.
        return p;
    }

}

TEST_CASE("ESP round trip for AEAD and encrypt-then-MAC transforms") {
    for (const SEspKeys& keys : { gcmKeys(), cbcKeys() }) {
        CEspSa out;
        CEspSa in;
        REQUIRE(out.init(0x01020304u, false, keys) == SBOX_OK);
        REQUIRE(in.init(0x01020304u, true, keys) == SBOX_OK);

        for (size_t size : { size_t(20), size_t(21), size_t(100), size_t(1399) }) {
            std::vector<uint8_t> inner = packet(size, uint8_t(size));
            std::vector<uint8_t> esp;
            REQUIRE(out.encapsulate(BytesOf(inner), ESP_NEXT_IPV4, esp) == SBOX_OK);
            CHECK(CEspSa::packetSpi(BytesOf(esp)) == 0x01020304u);
            CHECK(ipsec::GetBe32(esp.data() + 4) == out.sequence());

            std::vector<uint8_t> back;
            uint8_t next = 0;
            REQUIRE(in.decapsulate(BytesOf(esp), back, next) == SBOX_OK);
            CHECK(back == inner);
            CHECK(next == ESP_NEXT_IPV4);

            // --> The same packet again is a replay.
            CHECK(in.decapsulate(BytesOf(esp), back, next) == -EALREADY);

            // --> A tampered fresh packet fails the ICV (replay is checked first).
            std::vector<uint8_t> fresh;
            REQUIRE(out.encapsulate(BytesOf(inner), ESP_NEXT_IPV4, fresh) == SBOX_OK);
            fresh[fresh.size() / 2] ^= 0x10;
            CHECK(in.decapsulate(BytesOf(fresh), back, next) == -EKEYREJECTED);
        }

        CHECK(out.packets() == 8);
        CHECK(in.packets() == 4);
        CHECK(in.lastUsed() > 0);
    }
}

TEST_CASE("ESP anti-replay window") {
    SEspKeys keys = gcmKeys();
    CEspSa out;
    CEspSa in;
    REQUIRE(out.init(7, false, keys) == SBOX_OK);
    REQUIRE(in.init(7, true, keys, 64) == SBOX_OK);

    std::vector<std::vector<uint8_t>> sent;
    for (int32_t i = 0; i < 200; ++i) {
        std::vector<uint8_t> esp;
        REQUIRE(out.encapsulate(BytesOf(packet(40, uint8_t(i))), ESP_NEXT_IPV4, esp) == SBOX_OK);
        sent.push_back(esp);
    }

    std::vector<uint8_t> back;
    uint8_t next;
    // --> 100 first, then reordered packets inside the window are accepted once.
    REQUIRE(in.decapsulate(BytesOf(sent[99]), back, next) == SBOX_OK);
    CHECK(in.decapsulate(BytesOf(sent[60]), back, next) == SBOX_OK);
    CHECK(in.decapsulate(BytesOf(sent[60]), back, next) == -EALREADY);
    CHECK(in.decapsulate(BytesOf(sent[36]), back, next) == SBOX_OK);
    // --> Too old (100 - 64 = 36 is the edge; 35 and below are outside).
    CHECK(in.decapsulate(BytesOf(sent[34]), back, next) == -EALREADY);
    // --> A big jump forward shifts the window.
    CHECK(in.decapsulate(BytesOf(sent[199]), back, next) == SBOX_OK);
    CHECK(in.decapsulate(BytesOf(sent[150]), back, next) == SBOX_OK);
    CHECK(in.decapsulate(BytesOf(sent[120]), back, next) == -EALREADY);
    CHECK(in.sequence() == 200);
}

TEST_CASE("ESP layout matches RFC 4303 / RFC 4106 when built by hand") {
    SEspKeys keys = gcmKeys();
    CIpsecCipher cipher;
    REQUIRE(cipher.init(keys.encr, keys.keyBits, keys.integ, BytesOf(keys.encKey), BytesOf(keys.integKey)) == SBOX_OK);

    // --> SPI | seq | IV | E(payload | 1 2 | padlen=2 | next=4) | ICV, AAD = SPI | seq.
    std::vector<uint8_t> payload = packet(20, 1);
    std::vector<uint8_t> plain = payload;
    plain.push_back(1);
    plain.push_back(2);
    plain.push_back(2);
    plain.push_back(4);
    REQUIRE(plain.size() % 4 == 0);

    std::vector<uint8_t> esp = { 0, 0, 0, 9, 0, 0, 0, 1 };
    std::vector<uint8_t> aad = esp;
    std::vector<uint8_t> iv = { 0, 0, 0, 0, 0, 0, 0, 1 };
    REQUIRE(cipher.seal(BytesOf(aad), BytesOf(plain), esp, BytesOf(iv)) == SBOX_OK);

    CEspSa in;
    REQUIRE(in.init(9, true, keys) == SBOX_OK);
    std::vector<uint8_t> back;
    uint8_t next = 0;
    REQUIRE(in.decapsulate(BytesOf(esp), back, next) == SBOX_OK);
    CHECK(back == payload);
    CHECK(next == 4);

    // --> Non-monotonic padding bytes are refused.
    plain[20] = 7;
    std::vector<uint8_t> bad = { 0, 0, 0, 9, 0, 0, 0, 2 };
    aad.assign(bad.begin(), bad.end());
    REQUIRE(cipher.seal(BytesOf(aad), BytesOf(plain), bad, BytesOf(iv)) == SBOX_OK);
    CHECK(in.decapsulate(BytesOf(bad), back, next) == -EBADMSG);

    // --> Wrong SPI and short packets.
    std::vector<uint8_t> other = esp;
    other[3] = 8;
    CHECK(in.decapsulate(BytesOf(other), back, next) == -EBADMSG);
    CHECK(in.decapsulate(SReadOnlyByteSpan(esp.data(), 10), back, next) == -EBADMSG);

    // --> Direction misuse.
    std::vector<uint8_t> tmp;
    CHECK(in.encapsulate(BytesOf(payload), 4, tmp) == -EINVAL);
}
