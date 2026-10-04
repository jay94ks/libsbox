#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "crypto.hpp"
#include "keyschedule.hpp"
#include "protocol.hpp"
#include "record.hpp"
#include <cerrno>
#include <string>

// --> RFC 8448 section 3 ("Simple 1-RTT Handshake") traced through the client's key schedule,
// record protection, Finished and CertificateVerify code. The handshake bytes are the RFC's
// own (as transcribed in Botan's tls_13_rfc8448/transcripts.vec); the intermediate secrets,
// keys and IVs are the values the RFC prints.

using namespace sbox;
using namespace sbox::tls;

namespace {

    const char* RFC_RECORD_CLIENT_HELLO_1 =
        "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000061301"
        "13031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001010102"
        "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529a"
        "af2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00"
        "020101001c00024001";

    const char* RFC_MESSAGE_SERVER_HELLO =
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024"
        "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

    const char* RFC_RECORD_SERVER_HANDSHAKE_MESSAGES =
        "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca"
        "07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b"
        "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c"
        "7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092"
        "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a8"
        "9441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f"
        "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a3"
        "6ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e"
        "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052c"
        "f93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe"
        "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb"
        "5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038"
        "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd50278"
        "4016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e"
        "750edc53370d2b";

    const char* RFC_MESSAGE_ENCRYPTED_EXTENSIONS =
        "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000";

    const char* RFC_MESSAGE_SERVER_CERTIFICATE =
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a"
        "06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a"
        "0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d98"
        "0836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312"
        "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d0"
        "3e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355"
        "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f"
        "8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102"
        "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8"
        "f8961229ac9187b42b4de10000";

    const char* RFC_MESSAGE_SERVER_CERTIFICATE_VERIFY =
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d3"
        "3a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c"
        "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3";

    const char* RFC_MESSAGE_SERVER_FINISHED =
        "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";

    const char* RFC_SERVER_MESSAGE_TO_SIGN =
        "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
        "20202020202020202020202020202020544c5320312e332c207365727665722043657274696669636174655665726966"
        "7900764d6632b3c35c3f3205e3499ac3edbaabb88295fba751461d3678e2e5ea0687";

    const char* RFC_RECORD_CLIENT_FINISHED =
        "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1c"
        "aeacab6867d726c40546";

    const char* RFC_RECORD_NEW_SESSION_TICKET =
        "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a"
        "015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0"
        "9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77"
        "f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74"
        "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f";

    const char* RFC_CLIENT_APP_DATA =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
        "3031";

    const char* RFC_RECORD_CLIENT_APP_DATA =
        "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b"
        "62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4";

    const char* RFC_SERVER_APP_DATA =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
        "3031";

    const char* RFC_RECORD_SERVER_APP_DATA =
        "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8"
        "fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d";

    const char* RFC_RECORD_CLIENT_CLOSE_NOTIFY =
        "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3";

    const char* RFC_RECORD_SERVER_CLOSE_NOTIFY =
        "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9";

    std::vector<uint8_t> hex(std::string_view s) {
        std::vector<uint8_t> out;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int hi = -1;
        for (char c : s) {
            int v = nib(c);
            if (v < 0) {
                continue;
            }

            if (hi < 0) {
                hi = v;
            }
            else {
                out.push_back(uint8_t(hi << 4 | v));
                hi = -1;
            }
        }

        return out;
    }

    std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts) {
        std::vector<uint8_t> out;
        for (const auto& p : parts) {
            out.insert(out.end(), p.begin(), p.end());
        }

        return out;
    }

    std::vector<uint8_t> slice(const std::vector<uint8_t>& v, size_t from, size_t n = size_t(-1)) {
        if (n == size_t(-1)) {
            n = v.size() - from;
        }

        return std::vector<uint8_t>(v.begin() + long(from), v.begin() + long(from + n));
    }

    const char* CLIENT_X25519_PRIVATE = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
    const char* CLIENT_X25519_PUBLIC = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
    const char* SERVER_X25519_PUBLIC = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    const char* ECDHE = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    const char* HANDSHAKE_SECRET = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    const char* CLIENT_HS_SECRET = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const char* SERVER_HS_SECRET = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const char* SERVER_HS_KEY = "3fce516009c21727d0f2e4e86ee403bc";
    const char* SERVER_HS_IV = "5d313eb2671276ee13000b30";
    const char* CLIENT_HS_KEY = "dbfaa693d1762c5b666af5d950258d01";
    const char* CLIENT_HS_IV = "5bd3c71b836e0b76bb73265f";
    const char* MASTER_SECRET = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    const char* SERVER_AP_KEY = "9f02283b6c9c07efc26bb9f2ac92e356";
    const char* SERVER_AP_IV = "cf782b88dd83549aadf1e984";
    const char* CLIENT_AP_KEY = "17422dda596ed5d9acd890e3c63f5051";
    const char* CLIENT_AP_IV = "5b78923dee08579033e523d9";

    /* Opens one TLS 1.3 record with `cipher`, returning the inner type and plaintext. */
    int32_t openRecord(RecordCipher& cipher, const std::vector<uint8_t>& record, uint8_t& type, std::vector<uint8_t>& plain) {
        REQUIRE(record.size() > 5);
        std::vector<uint8_t> body = slice(record, 5);
        size_t length = 0;
        int32_t rc = cipher.open13(record.data(), BytesOf(body), type, length);
        if (rc == SBOX_OK) {
            plain.assign(body.begin(), body.begin() + long(length));
        }

        return rc;
    }

    struct Trace {
        std::vector<uint8_t> ch = slice(hex(RFC_RECORD_CLIENT_HELLO_1), 5);
        std::vector<uint8_t> sh = hex(RFC_MESSAGE_SERVER_HELLO);
        std::vector<uint8_t> ee = hex(RFC_MESSAGE_ENCRYPTED_EXTENSIONS);
        std::vector<uint8_t> cert = hex(RFC_MESSAGE_SERVER_CERTIFICATE);
        std::vector<uint8_t> cv = hex(RFC_MESSAGE_SERVER_CERTIFICATE_VERIFY);
        std::vector<uint8_t> fin = hex(RFC_MESSAGE_SERVER_FINISHED);
    };

}

TEST_CASE("RFC 8448 X25519 key exchange") {
    KeyShare client;
    REQUIRE(client.loadPrivate(GROUP_X25519, BytesOf(hex(CLIENT_X25519_PRIVATE))) == SBOX_OK);
    CHECK(client.publicValue() == hex(CLIENT_X25519_PUBLIC));

    std::vector<uint8_t> shared;
    REQUIRE(client.agree(BytesOf(hex(SERVER_X25519_PUBLIC)), shared) == SBOX_OK);
    CHECK(shared == hex(ECDHE));

    // --> A small-order point (all zeros) must be refused.
    std::vector<uint8_t> zero(32, 0);
    CHECK(client.agree(BytesOf(zero), shared) == -EINVAL);
}

TEST_CASE("RFC 8448 handshake key schedule and traffic keys") {
    Trace t;
    const SuiteInfo* suite = FindSuite(TLS_AES_128_GCM_SHA256);
    REQUIRE(suite != nullptr);

    std::vector<uint8_t> hs = Tls13HandshakeSecret(HASH_SHA256, BytesOf(hex(ECDHE)));
    CHECK(hs == hex(HANDSHAKE_SECRET));

    std::vector<uint8_t> th = Hash(HASH_SHA256, BytesOf(cat({ t.ch, t.sh })));
    std::vector<uint8_t> chts = DeriveSecret(HASH_SHA256, BytesOf(hs), "c hs traffic", BytesOf(th));
    std::vector<uint8_t> shts = DeriveSecret(HASH_SHA256, BytesOf(hs), "s hs traffic", BytesOf(th));
    CHECK(chts == hex(CLIENT_HS_SECRET));
    CHECK(shts == hex(SERVER_HS_SECRET));

    std::vector<uint8_t> key, iv;
    REQUIRE(Tls13TrafficKeys(*suite, BytesOf(shts), key, iv));
    CHECK(key == hex(SERVER_HS_KEY));
    CHECK(iv == hex(SERVER_HS_IV));
    REQUIRE(Tls13TrafficKeys(*suite, BytesOf(chts), key, iv));
    CHECK(key == hex(CLIENT_HS_KEY));
    CHECK(iv == hex(CLIENT_HS_IV));

    std::vector<uint8_t> master = Tls13MasterSecret(HASH_SHA256, BytesOf(hs));
    CHECK(master == hex(MASTER_SECRET));
}

TEST_CASE("RFC 8448 full 1-RTT trace: records, CertificateVerify, Finished") {
    Trace t;
    const SuiteInfo* suite = FindSuite(TLS_AES_128_GCM_SHA256);
    REQUIRE(suite != nullptr);

    std::vector<uint8_t> hs = Tls13HandshakeSecret(HASH_SHA256, BytesOf(hex(ECDHE)));
    std::vector<uint8_t> th = Hash(HASH_SHA256, BytesOf(cat({ t.ch, t.sh })));
    std::vector<uint8_t> chts = DeriveSecret(HASH_SHA256, BytesOf(hs), "c hs traffic", BytesOf(th));
    std::vector<uint8_t> shts = DeriveSecret(HASH_SHA256, BytesOf(hs), "s hs traffic", BytesOf(th));

    // -- The server's encrypted flight decrypts to EE || Certificate || CV || Finished.
    RecordCipher serverHs;
    REQUIRE(Tls13InstallKeys(serverHs, *suite, BytesOf(shts)));

    uint8_t type = 0;
    std::vector<uint8_t> plain;
    REQUIRE(openRecord(serverHs, hex(RFC_RECORD_SERVER_HANDSHAKE_MESSAGES), type, plain) == SBOX_OK);
    CHECK(type == CT_HANDSHAKE);
    CHECK(plain == cat({ t.ee, t.cert, t.cv, t.fin }));

    // -- CertificateVerify: RSA-PSS-RSAE-SHA256 by the server's (1024-bit, test-only) key.
    std::vector<uint8_t> certDer = slice(t.cert, 4 + 1 + 3 + 3, 0x1b0);
    certpp::x509::CCert leaf;
    REQUIRE(leaf.importDer(certpp::COctet(certDer.data(), certDer.size())) == certpp::ERET_OK);

    std::vector<uint8_t> thCert = Hash(HASH_SHA256, BytesOf(cat({ t.ch, t.sh, t.ee, t.cert })));
    std::vector<uint8_t> content = Tls13SignedContent(true, BytesOf(thCert));
    CHECK(content == hex(RFC_SERVER_MESSAGE_TO_SIGN));

    uint16_t scheme = uint16_t(t.cv[4] << 8 | t.cv[5]);
    CHECK(scheme == SIG_RSA_PSS_RSAE_SHA256);
    std::vector<uint8_t> signature = slice(t.cv, 8);
    CHECK(SchemeFitsKey(leaf, scheme, true));
    CHECK_FALSE(SchemeFitsKey(leaf, SIG_RSA_PKCS1_SHA256, true));
    CHECK(SchemeFitsKey(leaf, SIG_RSA_PKCS1_SHA256, false));
    CHECK(VerifySignature(leaf, scheme, true, BytesOf(content), BytesOf(signature)) == SBOX_OK);

    std::vector<uint8_t> tampered = content;
    tampered.back() ^= 1;
    CHECK(VerifySignature(leaf, scheme, true, BytesOf(tampered), BytesOf(signature)) == -EKEYREJECTED);

    // -- Server Finished.
    std::vector<uint8_t> thCv = Hash(HASH_SHA256, BytesOf(cat({ t.ch, t.sh, t.ee, t.cert, t.cv })));
    CHECK(Tls13Finished(HASH_SHA256, BytesOf(shts), BytesOf(thCv)) == slice(t.fin, 4));

    // -- Application traffic keys.
    std::vector<uint8_t> thFin = Hash(HASH_SHA256, BytesOf(cat({ t.ch, t.sh, t.ee, t.cert, t.cv, t.fin })));
    std::vector<uint8_t> master = Tls13MasterSecret(HASH_SHA256, BytesOf(hs));
    std::vector<uint8_t> cats = DeriveSecret(HASH_SHA256, BytesOf(master), "c ap traffic", BytesOf(thFin));
    std::vector<uint8_t> sats = DeriveSecret(HASH_SHA256, BytesOf(master), "s ap traffic", BytesOf(thFin));

    std::vector<uint8_t> key, iv;
    REQUIRE(Tls13TrafficKeys(*suite, BytesOf(sats), key, iv));
    CHECK(key == hex(SERVER_AP_KEY));
    CHECK(iv == hex(SERVER_AP_IV));
    REQUIRE(Tls13TrafficKeys(*suite, BytesOf(cats), key, iv));
    CHECK(key == hex(CLIENT_AP_KEY));
    CHECK(iv == hex(CLIENT_AP_IV));

    // -- Client Finished, protected with the client handshake keys, is byte-exact.
    std::vector<uint8_t> clientFinished = { HS_FINISHED, 0, 0, 32 };
    std::vector<uint8_t> verify = Tls13Finished(HASH_SHA256, BytesOf(chts), BytesOf(thFin));
    clientFinished.insert(clientFinished.end(), verify.begin(), verify.end());

    RecordCipher clientHs;
    REQUIRE(Tls13InstallKeys(clientHs, *suite, BytesOf(chts)));
    std::vector<uint8_t> wire;
    REQUIRE(clientHs.seal13(CT_HANDSHAKE, BytesOf(clientFinished), 0, wire));
    CHECK(wire == hex(RFC_RECORD_CLIENT_FINISHED));

    // -- Client application data and close_notify.
    RecordCipher clientAp;
    REQUIRE(Tls13InstallKeys(clientAp, *suite, BytesOf(cats)));
    wire.clear();
    REQUIRE(clientAp.seal13(CT_APPLICATION_DATA, BytesOf(hex(RFC_CLIENT_APP_DATA)), 0, wire));
    CHECK(wire == hex(RFC_RECORD_CLIENT_APP_DATA));

    std::vector<uint8_t> closeNotify = { ALERT_WARNING, AD_CLOSE_NOTIFY };
    wire.clear();
    REQUIRE(clientAp.seal13(CT_ALERT, BytesOf(closeNotify), 0, wire));
    CHECK(wire == hex(RFC_RECORD_CLIENT_CLOSE_NOTIFY));

    // -- Server records: NewSessionTicket, application data, close_notify (sequence 0..2).
    RecordCipher serverAp;
    REQUIRE(Tls13InstallKeys(serverAp, *suite, BytesOf(sats)));

    REQUIRE(openRecord(serverAp, hex(RFC_RECORD_NEW_SESSION_TICKET), type, plain) == SBOX_OK);
    CHECK(type == CT_HANDSHAKE);
    CHECK(plain.at(0) == HS_NEW_SESSION_TICKET);

    REQUIRE(openRecord(serverAp, hex(RFC_RECORD_SERVER_APP_DATA), type, plain) == SBOX_OK);
    CHECK(type == CT_APPLICATION_DATA);
    CHECK(plain == hex(RFC_SERVER_APP_DATA));

    REQUIRE(openRecord(serverAp, hex(RFC_RECORD_SERVER_CLOSE_NOTIFY), type, plain) == SBOX_OK);
    CHECK(type == CT_ALERT);
    CHECK(plain == closeNotify);
}

TEST_CASE("RFC 8448 record protection rejects tampering and replay") {
    const SuiteInfo* suite = FindSuite(TLS_AES_128_GCM_SHA256);
    RecordCipher a, b;
    REQUIRE(a.init(*suite, BytesOf(hex(SERVER_AP_KEY)), BytesOf(hex(SERVER_AP_IV))));
    REQUIRE(b.init(*suite, BytesOf(hex(SERVER_AP_KEY)), BytesOf(hex(SERVER_AP_IV))));

    std::vector<uint8_t> record = hex(RFC_RECORD_SERVER_APP_DATA);
    uint8_t type = 0;
    std::vector<uint8_t> plain;

    // --> Out of sequence (expects the NewSessionTicket's sequence number 0): fails.
    CHECK(openRecord(a, record, type, plain) == -EBADMSG);

    std::vector<uint8_t> nst = hex(RFC_RECORD_NEW_SESSION_TICKET);
    REQUIRE(openRecord(b, nst, type, plain) == SBOX_OK);
    std::vector<uint8_t> bad = record;
    bad[10] ^= 0x01;
    CHECK(openRecord(b, bad, type, plain) == -EBADMSG);

    // --> The header is authenticated too.
    RecordCipher c;
    REQUIRE(c.init(*suite, BytesOf(hex(SERVER_AP_KEY)), BytesOf(hex(SERVER_AP_IV))));
    REQUIRE(openRecord(c, nst, type, plain) == SBOX_OK);
    bad = record;
    bad[2] = 0x01;
    CHECK(openRecord(c, bad, type, plain) == -EBADMSG);
}

TEST_CASE("HKDF-Expand-Label and Derive-Secret building blocks") {
    // --> Derive-Secret(Early-Secret, "derived", "") from RFC 8448.
    std::vector<uint8_t> early = HkdfExtract(HASH_SHA256, SReadOnlyByteSpan(), SReadOnlyByteSpan());
    CHECK(early == hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));

    std::vector<uint8_t> empty = Hash(HASH_SHA256, SReadOnlyByteSpan());
    CHECK(DeriveSecret(HASH_SHA256, BytesOf(early), "derived", BytesOf(empty))
          == hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));

    // --> finished_key and the resumption PSK derivation (RFC 8448, via mbed TLS's vectors).
    CHECK(HkdfExpandLabel(HASH_SHA256, BytesOf(hex("2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f")),
                          "finished", SReadOnlyByteSpan(), 32)
          == hex("5ace394c26980d581243f627d1150ae27e37fa52364e0a7f20ac686d09cd0e8e"));

    std::vector<uint8_t> nonce = { 0, 0 };
    CHECK(HkdfExpandLabel(HASH_SHA256, BytesOf(hex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")),
                          "resumption", BytesOf(nonce), 32)
          == hex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"));
}

TEST_CASE("TLS 1.2 PRF matches a known SHA-256 vector") {
    // --> Widely used P_SHA256 test vector (secret/seed/label from the IETF TLS mailing list).
    std::vector<uint8_t> secret = hex("9bbe436ba940f017b17652849a71db35");
    std::vector<uint8_t> seed = hex("a0ba9f936cda311827a6f796ffd5198c");
    std::vector<uint8_t> out = Prf12(HASH_SHA256, BytesOf(secret), "test label", BytesOf(seed), 100);
    CHECK(out == hex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af"
                     "0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187"
                     "347b66"));
}

TEST_CASE("TLS 1.2 AEAD record round trip for every TLS 1.2 suite") {
    const uint16_t suites[] = {
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    for (uint16_t id : suites) {
        const SuiteInfo* suite = FindSuite(id);
        REQUIRE(suite != nullptr);
        std::vector<uint8_t> key(suite->keyLength, 0x42), iv(suite->ivLength, 0x24);

        RecordCipher w, r;
        REQUIRE(w.init(*suite, BytesOf(key), BytesOf(iv)));
        REQUIRE(r.init(*suite, BytesOf(key), BytesOf(iv)));

        std::string msg = "hello over tls 1.2";
        std::vector<uint8_t> wire;
        REQUIRE(w.seal12(CT_APPLICATION_DATA, BytesOf(msg), wire));
        REQUIRE(w.seal12(CT_APPLICATION_DATA, BytesOf(msg), wire));

        size_t first = 5 + ((size_t(wire[3]) << 8) | wire[4]);
        for (int32_t i = 0; i < 2; ++i) {
            size_t at = i == 0 ? 0 : first;
            size_t len = (size_t(wire[at + 3]) << 8) | wire[at + 4];
            std::vector<uint8_t> body(wire.begin() + long(at + 5), wire.begin() + long(at + 5 + len));
            size_t off = 0, plen = 0;
            REQUIRE(r.open12(wire.data() + at, BytesOf(body), off, plen) == SBOX_OK);
            CHECK(std::string(body.begin() + long(off), body.begin() + long(off + plen)) == msg);
        }
    }
}
