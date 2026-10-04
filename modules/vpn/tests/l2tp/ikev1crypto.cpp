#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/l2tp/ikev1crypto.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "testutil.hpp"

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

// --> Expected values were computed independently with Python's hashlib/hmac (key derivation)
// and the `cryptography` package (CBC), following RFC 2409 sections 5, 5.5 and Appendix B.

namespace {

    struct Inputs {
        std::vector<uint8_t> psk;
        std::vector<uint8_t> ni;
        std::vector<uint8_t> nr;
        std::vector<uint8_t> gxy;
        std::vector<uint8_t> gxi;
        std::vector<uint8_t> gxr;
        uint64_t ckyI = 0x0102030405060708ull;
        uint64_t ckyR = 0x1112131415161718ull;

        Inputs() {
            std::string p = "windows-psk-123";
            psk.assign(p.begin(), p.end());
            for (int i = 0; i < 32; ++i) {
                ni.push_back(uint8_t(0x10 + i));
            }

            for (int i = 0; i < 16; ++i) {
                nr.push_back(uint8_t(0x80 + i));
            }

            for (int i = 0; i < 128; ++i) {
                gxy.push_back(uint8_t(i * 7 + 3));
                gxi.push_back(uint8_t(i * 5 + 1));
                gxr.push_back(uint8_t(i * 11 + 9));
            }
        }
    };

    struct Expected {
        const char* name;
        uint16_t hash;
        uint16_t encr;
        uint16_t keyBits;
        const char* skeyid;
        const char* d;
        const char* a;
        const char* e;
        const char* key;
        const char* iv;
        const char* hashI;
        const char* hashR;
        const char* p2iv;
        const char* keymat;
        const char* keymatPfs;
        const char* natd;
    };

    const Expected VECTORS[] = {
        { "sha1/aes256", EIKE1_HASH_SHA1, EIKE1_ENCR_AES, 256, "4caba29747421d809e4b2eb7afc608f0a691c801",
          "a9551f0e6abb1f540be7bae4cb5077daed970b2d", "a9b80c2234fec59a1fd522b73d10f3f6c8bea5d3", "121df22c60321d3c98da7029e9331e0171c54771",
          "e312275f2f94323b21326ea695a53ca4198c3ddba2c3e69dd883048881b41140", "d118e046b45a29556c9b42bff2eca143",
          "7ce91893e56aa51388e26804a2c3d32969362403", "11f9dc7d4c2d4f195cf8007c4f30bf6287190853", "e854a44ee30cc46f4940027252ba5a98",
          "fb99bb6f11b8924dbc42805598421ef3db68fe10aa212e5fd2961437419c372b4bbafa27e269b113185f5e1733bbf16739985ef0",
          "e56aafce6911c0eafbcaaf22987f054f20f3abdb17e809916e5d527d1510f48005c2b3ef55e043deefbdff16284562ecfe477fe6",
          "a44b6462d5a1361bfbe845cb7ec1e337d558f0da" },
        { "sha256/3des", EIKE1_HASH_SHA256, EIKE1_ENCR_3DES, 192, "ada245dd3d564b2fd8d6801671578a485de857d1f9a7dbeb4b1b848d355a5358",
          "d8e81542c834baa10acbb2f9b9395c1e7b3413099f9ed580e485d51c3129be08", "3876770f75795b9e1818d40798eb9ef4e8a10c57c29745010a4ccfd0e8fdd8bb",
          "2401100c559900ee39cafc5c4f52a668ff2740a8954fdabc26c4e07fbeb0fe68", "2401100c559900ee39cafc5c4f52a668ff2740a8954fdabc",
          "b78d31348d9fbb45", "d3255b171df1be7c4120432e72b719c7ca475b78fea37912032553de28d0eec0",
          "8f91495902ef5b0c36f167005a89dba7ebea3758a6305631463bcdf7e571dbaa", "d71a4009aeb704a9",
          "e04937b0203cc4ddecc254e35a1e2b9599276a8d3ef57996bf70a597743352bb27dddfb99b7580530915b5df835f97b96d2af1d1",
          "0b2c0671f7ed2cd9562a8634d7da75ebc4910875545a5e5245fa815e71f7f6e2e2e6e52447ba15f308a196db4067dd1448f7b862",
          "59c9ac43b9288e215f6a6b397a6fd9c4c6c693361f24df3b3e2e95dd548d8f7b" },
        { "sha1/3des", EIKE1_HASH_SHA1, EIKE1_ENCR_3DES, 192, "4caba29747421d809e4b2eb7afc608f0a691c801",
          "a9551f0e6abb1f540be7bae4cb5077daed970b2d", "a9b80c2234fec59a1fd522b73d10f3f6c8bea5d3", "121df22c60321d3c98da7029e9331e0171c54771",
          "e312275f2f94323b21326ea695a53ca4198c3ddba2c3e69d", "d118e046b45a2955", "7ce91893e56aa51388e26804a2c3d32969362403",
          "11f9dc7d4c2d4f195cf8007c4f30bf6287190853", "98fe314c5fa3035f",
          "fb99bb6f11b8924dbc42805598421ef3db68fe10aa212e5fd2961437419c372b4bbafa27e269b113185f5e1733bbf16739985ef0",
          "e56aafce6911c0eafbcaaf22987f054f20f3abdb17e809916e5d527d1510f48005c2b3ef55e043deefbdff16284562ecfe477fe6",
          "a44b6462d5a1361bfbe845cb7ec1e337d558f0da" },
        { "md5/aes128", EIKE1_HASH_MD5, EIKE1_ENCR_AES, 128, "e8b857578c3c42001b0aea2940acc603", "8d99ced207404f10ecdfc47438417d39",
          "9da511601660c95d66d8f67a1a2f4bee", "2d78bd0e84f039e57867cbc907178180", "2d78bd0e84f039e57867cbc907178180",
          "a5cb9c91bc84a99495aad63824eb40b6", "339db39e38e38712a4e485e47e835979", "54b6c150ba6e4ec5e4af00681168137f",
          "450d4496dce0668e08473114f409bf2d",
          "c19dea910930e04a355e967512e2cf7e110154b600303d36f970d640e5e91a01ca030c1edc90ee1f8a9d03f40a4105a2a9f45ad8",
          "42f45f1ed05fb7bbada379b20678e22cf6c167912f6086d4e5519531b73d1aca59a6b8f1b311d9c20db51ccb957f139b3f55f2c9",
          "aa2b0a6e89e98ff54fd8e99cdc5373c2" },
    };

}

TEST_CASE("Phase 1 keys: SKEYID (PSK), SKEYID_d/a/e, key expansion, IV, HASH_I/HASH_R") {
    Inputs in;
    for (const Expected& x : VECTORS) {
        CAPTURE(x.name);
        std::vector<uint8_t> skeyid;
        REQUIRE(Ikev1SkeyidPsk(x.hash, Bytes(in.psk), Bytes(in.ni), Bytes(in.nr), skeyid) == SBOX_OK);
        CHECK(Hex(skeyid) == x.skeyid);

        SIkev1Suite suite;
        suite.hash = x.hash;
        suite.encr = x.encr;
        suite.keyBits = x.keyBits;
        SIkev1Keys keys;
        REQUIRE(Ikev1DeriveKeys(suite, Bytes(skeyid), Bytes(in.gxy), in.ckyI, in.ckyR, Bytes(in.gxi), Bytes(in.gxr), keys) == SBOX_OK);
        CHECK(Hex(keys.skeyidD) == x.d);
        CHECK(Hex(keys.skeyidA) == x.a);
        CHECK(Hex(keys.skeyidE) == x.e);
        CHECK(Hex(keys.encKey) == x.key);
        CHECK(Hex(keys.iv) == x.iv);

        std::vector<uint8_t> sai;
        for (int i = 0; i < 40; ++i) {
            sai.push_back(uint8_t(i));
        }

        std::vector<uint8_t> idb = { 1, 17, 1, 0xf4, 192, 168, 1, 10 };
        std::vector<uint8_t> h;
        REQUIRE(Ikev1Phase1Hash(x.hash, Bytes(skeyid), Bytes(in.gxi), Bytes(in.gxr), in.ckyI, in.ckyR, Bytes(sai), Bytes(idb), h) == SBOX_OK);
        CHECK(Hex(h) == x.hashI);
        REQUIRE(Ikev1Phase1Hash(x.hash, Bytes(skeyid), Bytes(in.gxr), Bytes(in.gxi), in.ckyR, in.ckyI, Bytes(sai), Bytes(idb), h) == SBOX_OK);
        CHECK(Hex(h) == x.hashR);

        std::vector<uint8_t> p1iv;
        for (size_t i = 0; i < Ikev1BlockSize(x.encr); ++i) {
            p1iv.push_back(uint8_t(i));
        }

        std::vector<uint8_t> iv;
        REQUIRE(Ikev1Phase2Iv(x.hash, Ikev1BlockSize(x.encr), Bytes(p1iv), 0xdeadbeef, iv) == SBOX_OK);
        CHECK(Hex(iv) == x.p2iv);

        std::vector<uint8_t> spi = { 0xc0, 0xff, 0xee, 0x01 };
        std::vector<uint8_t> km;
        REQUIRE(Ikev1QuickKeymat(x.hash, Bytes(keys.skeyidD), SReadOnlyByteSpan(), 3, Bytes(spi), Bytes(in.ni), Bytes(in.nr), 52, km) == SBOX_OK);
        CHECK(Hex(km) == x.keymat);
        REQUIRE(Ikev1QuickKeymat(x.hash, Bytes(keys.skeyidD), SReadOnlyByteSpan(in.gxy.data(), 32), 3, Bytes(spi), Bytes(in.ni), Bytes(in.nr), 52,
                                 km) == SBOX_OK);
        CHECK(Hex(km) == x.keymatPfs);

        net::SIpAddress a;
        net::SIpAddress::parse("10.0.0.1", a);
        REQUIRE(Ikev1NatHash(x.hash, in.ckyI, in.ckyR, a, 500, h) == SBOX_OK);
        CHECK(Hex(h) == x.natd);
    }
}

TEST_CASE("Phase 1 CBC matches AES-CBC and 3DES-CBC references and chains the IV") {
    std::vector<uint8_t> key;
    for (int i = 0; i < 32; ++i) {
        key.push_back(uint8_t(i));
    }

    std::vector<uint8_t> iv;
    for (int i = 100; i < 116; ++i) {
        iv.push_back(uint8_t(i));
    }

    std::vector<uint8_t> pt;
    for (int i = 0; i < 48; ++i) {
        pt.push_back(uint8_t(i));
    }

    CIkev1Cipher aes;
    REQUIRE(aes.init(EIKE1_ENCR_AES, Bytes(key)) == SBOX_OK);
    std::vector<uint8_t> ivCopy = iv;
    std::vector<uint8_t> ct;
    REQUIRE(aes.encrypt(ivCopy, Bytes(pt), ct) == SBOX_OK);
    CHECK(Hex(ct) == "1b4dd132a4c840a32931649f08e9c042097899abe7ae5b31fbe063c45c9287b248d94c83a5b7217cd0c16a1fc65c6c42");
    CHECK(Hex(ivCopy) == "48d94c83a5b7217cd0c16a1fc65c6c42");

    // --> Decrypting in two halves with the chained IV gives the plaintext back.
    std::vector<uint8_t> div = iv;
    std::vector<uint8_t> first;
    std::vector<uint8_t> second;
    REQUIRE(aes.decrypt(div, SReadOnlyByteSpan(ct.data(), 16), first) == SBOX_OK);
    REQUIRE(aes.decrypt(div, SReadOnlyByteSpan(ct.data() + 16, 32), second) == SBOX_OK);
    first.insert(first.end(), second.begin(), second.end());
    CHECK(first == pt);

    std::vector<uint8_t> dkey;
    for (int i = 1; i <= 24; ++i) {
        dkey.push_back(uint8_t(i));
    }

    std::vector<uint8_t> div3 = { 0, 1, 2, 3, 4, 5, 6, 7 };
    std::vector<uint8_t> pt3(pt.begin(), pt.begin() + 24);
    CIkev1Cipher des;
    REQUIRE(des.init(EIKE1_ENCR_3DES, Bytes(dkey)) == SBOX_OK);
    REQUIRE(des.encrypt(div3, Bytes(pt3), ct) == SBOX_OK);
    CHECK(Hex(ct) == "c7b64ccccdb0d3046b717e6ca4bac00f451b55b2e93323e8");

    CHECK(des.decrypt(div3, SReadOnlyByteSpan(ct.data(), 5), first) == -EBADMSG);
    CHECK(aes.init(EIKE1_ENCR_DES, Bytes(key)) == -ENOTSUP);
}

TEST_CASE("Vendor IDs are the MD5 values implementations expect") {
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_RFC3947)) == "4a131c81070358455c5728f20e95452f");
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_NATT_DRAFT_02)) == "cd60464335df21f87cfdb2fc68b6a448");
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_NATT_DRAFT_02N)) == "90cb80913ebb696e086381b5ec427b1f");
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_NATT_DRAFT_03)) == "7d9419a65310ca6f2c179d9215529d56");
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_FRAGMENTATION)) == "4048b7d56ebce88525e7de7f00d6c2d3");
    CHECK(Hex(Ikev1VendorId(EIKE1_VID_DPD)) == "afcad71368a1f1c96b8696fc77570100");

    // --> Windows appends a version to MS NT5 ISAKMPOAKLEY and flags to FRAGMENTATION.
    std::vector<uint8_t> ms = Ikev1VendorId(EIKE1_VID_MS_NT5);
    ms[19] = 0x0a;
    CHECK(Ikev1ClassifyVendorId(Bytes(ms)) == EIKE1_VID_MS_NT5);
    std::vector<uint8_t> frag = Ikev1VendorId(EIKE1_VID_FRAGMENTATION);
    frag.insert(frag.end(), { 0x80, 0, 0, 0 });
    CHECK(Ikev1ClassifyVendorId(Bytes(frag)) == EIKE1_VID_FRAGMENTATION);
    CHECK(Ikev1ClassifyVendorId(Bytes(Ikev1VendorId(EIKE1_VID_RFC3947))) == EIKE1_VID_RFC3947);
    std::vector<uint8_t> junk(16, 0x42);
    CHECK(Ikev1ClassifyVendorId(Bytes(junk)) == EIKE1_VID_UNKNOWN);
}

TEST_CASE("Key expansion only kicks in when SKEYID_e is shorter than the key") {
    std::vector<uint8_t> e(20, 0x11);
    std::vector<uint8_t> out;
    REQUIRE(Ikev1ExpandKey(EIKE1_HASH_SHA1, Bytes(e), 16, out) == SBOX_OK);
    CHECK(out == std::vector<uint8_t>(16, 0x11));
    REQUIRE(Ikev1ExpandKey(EIKE1_HASH_SHA1, Bytes(e), 32, out) == SBOX_OK);
    CHECK(out.size() == 32);
    CHECK(out != std::vector<uint8_t>(32, 0x11));
    CHECK(Ikev1KeySize(EIKE1_ENCR_AES, 100) == 0);
    CHECK(Ikev1KeySize(EIKE1_ENCR_3DES, 0) == 24);
}

TEST_CASE("ESP transform mapping") {
    uint16_t encr = 0;
    uint16_t bits = 0;
    uint16_t integ = 0;
    CHECK(Ikev1EspTransform(EIKE1_ESP_AES, 256, EIKE1_AA_HMAC_SHA1, encr, bits, integ));
    CHECK(encr == EIKE_ENCR_AES_CBC);
    CHECK(bits == 256);
    CHECK(integ == EIKE_INTEG_HMAC_SHA1_96);
    CHECK(Ikev1EspTransform(EIKE1_ESP_3DES, 0, EIKE1_AA_HMAC_SHA256, encr, bits, integ));
    CHECK(encr == EIKE_ENCR_3DES);
    CHECK(integ == EIKE_INTEG_HMAC_SHA2_256_128);
    CHECK(Ikev1EspTransform(EIKE1_ESP_AES_GCM_16, 128, EIKE1_AA_NONE, encr, bits, integ));
    CHECK(encr == EIKE_ENCR_AES_GCM_16);
    CHECK_FALSE(Ikev1EspTransform(EIKE1_ESP_AES, 256, EIKE1_AA_HMAC_MD5, encr, bits, integ));
    CHECK_FALSE(Ikev1EspTransform(EIKE1_ESP_DES, 0, EIKE1_AA_HMAC_SHA1, encr, bits, integ));
    CHECK_FALSE(Ikev1EspTransform(EIKE1_ESP_AES, 100, EIKE1_AA_HMAC_SHA1, encr, bits, integ));
}
