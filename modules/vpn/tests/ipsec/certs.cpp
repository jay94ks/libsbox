#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/profiles.hpp>
#include "ipsec/ikesa.hpp"
#include "testutil.hpp"
#include <certpp/io/buffer.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/x509/chain.hpp>
#include <certpp/x509/chain/pfx.hpp>
#include <certpp/x509/exts/bc.hpp>
#include <certpp/x509/exts/eku.hpp>
#include <certpp/x509/exts/ku.hpp>
#include <cstdlib>

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    /** Generates an RSA CA and server certificate once (RSA keys take a moment). */
    struct RsaPki {
        CIkeCertificate ca;
        CIkeCertificate server;

        static const RsaPki& get() {
            static RsaPki pki = [] {
                RsaPki p;
                SVpnCertOptions o;
                o.commonName = "RSA Test CA";
                REQUIRE(GenerateVpnCa(o, p.ca) == SBOX_OK);
                SVpnCertOptions s;
                s.commonName = "vpn.example.com";
                s.dnsNames = { "vpn.example.com" };
                s.ipAddresses = { "192.0.2.10" };
                REQUIRE(IssueVpnCertificate(p.ca, s, p.server) == SBOX_OK);
                return p;
            }();
            return pki;
        }
    };

}

TEST_CASE("Generated CA and server certificate carry what Windows, Apple and Android require") {
    const RsaPki& pki = RsaPki::get();
    REQUIRE(pki.ca.isValid());
    REQUIRE(pki.server.hasPrivateKey());
    CHECK(pki.ca.isCa());
    CHECK_FALSE(pki.server.isCa());
    CHECK(pki.server.subject() == "CN=vpn.example.com, O=libsbox VPN");
    CHECK(pki.server.issuer() == pki.ca.subject());
    CHECK(pki.server.dnsNames() == std::vector<std::string>{ "vpn.example.com" });
    CHECK(pki.server.ipAddresses() == std::vector<std::string>{ "192.0.2.10" });
    CHECK(pki.server.checkTime() == SBOX_OK);
    CHECK(pki.server.verifySignedBy(pki.ca) == SBOX_OK);
    CHECK(VerifyIkeCertificate(pki.server, {}, { pki.ca }) == SBOX_OK);

    auto eku = pki.server.native().extension<certpp::x509::CEkuExtension>();
    REQUIRE(eku);
    CHECK(eku->has(certpp::x509::CEkuExtension::OID_SERVER_AUTH));
    CHECK(eku->has(OID_IKE_INTERMEDIATE));
    auto ku = pki.server.native().extension<certpp::x509::CKeyUsagesExtension>();
    REQUIRE(ku);
    CHECK((ku->bits() & certpp::x509::EKUSE_DIGITAL_SIGNATURE) != 0);
    auto caKu = pki.ca.native().extension<certpp::x509::CKeyUsagesExtension>();
    REQUIRE(caKu);
    CHECK((caKu->bits() & certpp::x509::EKUSE_KEY_CERT_SIGN) != 0);

    // --> PEM round trip with the key, and the key alone.
    std::string pem = pki.server.toPem(true);
    CIkeCertificate back;
    REQUIRE(CIkeCertificate::fromPem(pem, back) == SBOX_OK);
    CHECK(back.hasPrivateKey());
    CHECK(back.der() == pki.server.der());

    CIkeCertificate split;
    REQUIRE(CIkeCertificate::fromPem(pki.server.toPem(false), split, pki.server.keyPem()) == SBOX_OK);
    CHECK(split.hasPrivateKey());
    CHECK(CIkeCertificate::fromPem(pki.server.toPem(false), split, pki.ca.keyPem()) == -EKEYREJECTED);

    std::vector<CIkeCertificate> bundle;
    REQUIRE(CIkeCertificate::loadBundle(pki.ca.toPem() + pki.server.toPem(), bundle) == SBOX_OK);
    CHECK(bundle.size() == 2);

    // --> Not trusted by a different CA.
    const Pki& ec = Pki::get();
    CHECK(VerifyIkeCertificate(pki.server, {}, { ec.ca }) == -EKEYREJECTED);
}

TEST_CASE("AUTH signatures: RSA method 1, RFC 7427 and ECDSA methods verify and reject tampering") {
    const RsaPki& rsa = RsaPki::get();
    const Pki& ec = Pki::get();
    std::vector<uint8_t> octets(200, 0x5a);

    struct Case { const CIkeCertificate* cert; std::vector<uint16_t> hashes; uint8_t method; };
    const Case cases[] = {
        { &rsa.server, {}, EIKE_AUTH_RSA_SIG },
        { &rsa.server, { 2, 3, 4 }, EIKE_AUTH_DIGITAL_SIGNATURE },
        { &ec.server, {}, EIKE_AUTH_ECDSA_256 },
        { &ec.server, { 2 }, EIKE_AUTH_DIGITAL_SIGNATURE },
    };

    for (const Case& c : cases) {
        uint8_t method = 0;
        std::vector<uint8_t> sig;
        REQUIRE(ipsec::SignAuth(*c.cert, BytesOf(octets), c.hashes, method, sig) == SBOX_OK);
        CHECK(method == c.method);
        CHECK(ipsec::VerifyAuth(*c.cert, method, BytesOf(sig), BytesOf(octets)) == SBOX_OK);

        std::vector<uint8_t> other = octets;
        other[3] ^= 1;
        CHECK(ipsec::VerifyAuth(*c.cert, method, BytesOf(sig), BytesOf(other)) == -EKEYREJECTED);

        std::vector<uint8_t> bad = sig;
        bad[bad.size() - 2] ^= 0x40;
        CHECK(ipsec::VerifyAuth(*c.cert, method, BytesOf(bad), BytesOf(octets)) != SBOX_OK);
    }

    // --> A signature by one key never verifies under another.
    uint8_t method = 0;
    std::vector<uint8_t> sig;
    REQUIRE(ipsec::SignAuth(rsa.server, BytesOf(octets), {}, method, sig) == SBOX_OK);
    CHECK(ipsec::VerifyAuth(rsa.ca, method, BytesOf(sig), BytesOf(octets)) == -EKEYREJECTED);
    CHECK(ipsec::VerifyAuth(ec.server, method, BytesOf(sig), BytesOf(octets)) == -EKEYREJECTED);
}

TEST_CASE("Identity binding to certificates") {
    const Pki& pki = Pki::get();
    SIkeId id;
    REQUIRE(SIkeId::fromString("@laptop.test", id) == SBOX_OK);
    CHECK(ipsec::IdMatchesCertificate(id, pki.client));
    REQUIRE(SIkeId::fromString("@LAPTOP.test", id) == SBOX_OK);
    CHECK(ipsec::IdMatchesCertificate(id, pki.client));
    REQUIRE(SIkeId::fromString("alice@test", id) == SBOX_OK);
    CHECK(ipsec::IdMatchesCertificate(id, pki.client));
    REQUIRE(SIkeId::fromString("@other.test", id) == SBOX_OK);
    CHECK_FALSE(ipsec::IdMatchesCertificate(id, pki.client));
    REQUIRE(SIkeId::fromString("127.0.0.1", id) == SBOX_OK);
    CHECK(ipsec::IdMatchesCertificate(id, pki.server));

    id.type = EIKE_ID_DER_ASN1_DN;
    id.data = pki.client.subjectDer();
    CHECK(ipsec::IdMatchesCertificate(id, pki.client));
    CHECK(id.toString() == pki.client.subject());
    CHECK_FALSE(ipsec::IdMatchesCertificate(id, pki.server));
}

TEST_CASE("PKCS#12 export loads back with the key") {
    const Pki& pki = Pki::get();
    std::vector<uint8_t> p12;
    REQUIRE(ExportIkePkcs12(pki.client, "pass", p12, 2048) == SBOX_OK);
    CHECK(p12.size() > 200);

    certpp::x509::CPfxFormat pfx;
    certpp::x509::CCertCollection collection;
    REQUIRE(pfx.load(certpp::SReadOnlyByteSpan(p12.data(), p12.size()),
                     certpp::SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("pass"), 4), collection) == certpp::ERET_OK);
    REQUIRE(collection.count() >= 1);
    certpp::x509::SCertEntry entry;
    REQUIRE(collection.at(0, entry) == certpp::ERET_OK);
    CHECK(entry.hasPrivateKey());
    CHECK(ExportIkePkcs12(pki.ca.isValid() ? CIkeCertificate() : pki.ca, "x", p12) == -EINVAL);
}

TEST_CASE("OpenSSL accepts the generated chain (when openssl is installed)") {
    if (::access("/usr/bin/openssl", X_OK) != 0) {
        MESSAGE("openssl not installed; skipping the cross-check");
        return;
    }

    const RsaPki& pki = RsaPki::get();
    TempDir dir;
    REQUIRE(CFile::writeAtomic(dir.join("ca.pem"), pki.ca.toPem(), 0600) == SBOX_OK);
    REQUIRE(CFile::writeAtomic(dir.join("server.pem"), pki.server.toPem(), 0600) == SBOX_OK);
    REQUIRE(CFile::writeAtomic(dir.join("server.key"), pki.server.keyPem(), 0600) == SBOX_OK);

    std::string verify = "/usr/bin/openssl verify -purpose sslserver -CAfile " + dir.join("ca.pem") + " " + dir.join("server.pem")
        + " > " + dir.join("verify.txt") + " 2>&1";
    CHECK(std::system(verify.c_str()) == 0);

    std::string ext = "/usr/bin/openssl x509 -noout -text -in " + dir.join("server.pem") + " > " + dir.join("text.txt") + " 2>&1";
    REQUIRE(std::system(ext.c_str()) == 0);
    std::string text;
    REQUIRE(CFile::readAll(dir.join("text.txt"), text) == SBOX_OK);
    CHECK(text.find("TLS Web Server Authentication") != std::string::npos);
    CHECK(text.find("1.3.6.1.5.5.8.2.2") != std::string::npos);
    CHECK(text.find("DNS:vpn.example.com") != std::string::npos);
    CHECK(text.find("IP Address:192.0.2.10") != std::string::npos);

    std::string key = "/usr/bin/openssl pkey -noout -in " + dir.join("server.key") + " > /dev/null 2>&1";
    CHECK(std::system(key.c_str()) == 0);
}

TEST_CASE("Client setup material for Windows, Apple and Android") {
    const Pki& pki = Pki::get();
    SVpnClientProfile p;
    p.name = "Office";
    p.server = "vpn.test";
    p.user = "alice";
    p.ca = pki.ca;
    p.routes = { "10.88.0.0/16" };

    std::string win = WindowsVpnSetup(p);
    CHECK(win.find("Add-VpnConnection -Name 'Office' -ServerAddress 'vpn.test' -TunnelType Ikev2 -AuthenticationMethod Eap") != std::string::npos);
    CHECK(win.find("Cert:\\LocalMachine\\Root") != std::string::npos);
    CHECK(win.find("Set-VpnConnectionIPsecConfiguration") != std::string::npos);
    CHECK(win.find("Add-VpnConnectionRoute -ConnectionName 'Office' -DestinationPrefix '10.88.0.0/16'") != std::string::npos);
    CHECK(win.find("-----BEGIN CERTIFICATE-----") != std::string::npos);

    std::string mc = AppleMobileConfig(p);
    CHECK(mc.find("<string>IKEv2</string>") != std::string::npos);
    CHECK(mc.find("com.apple.security.root") != std::string::npos);
    CHECK(mc.find("<key>ExtendedAuthEnabled</key><integer>1</integer>") != std::string::npos);
    CHECK(mc.find("<key>RemoteIdentifier</key><string>vpn.test</string>") != std::string::npos);

    p.auth = EVPA_PSK;
    p.psk = "a&b";
    p.localId = "@phone";
    mc = AppleMobileConfig(p);
    CHECK(mc.find("<string>SharedSecret</string>") != std::string::npos);
    CHECK(mc.find("a&amp;b") != std::string::npos);
    CHECK(WindowsVpnSetup(p).find("does not support pre-shared keys") != std::string::npos);
    CHECK(AndroidVpnSetup(p).find("IKEv2/IPSec PSK") != std::string::npos);

    p.auth = EVPA_CERT;
    REQUIRE(ExportIkePkcs12(pki.client, "pw", p.clientPkcs12, 2048) == SBOX_OK);
    p.clientPkcs12Password = "pw";
    mc = AppleMobileConfig(p);
    CHECK(mc.find("com.apple.security.pkcs12") != std::string::npos);
    CHECK(mc.find("<string>Certificate</string>") != std::string::npos);
    CHECK(WindowsVpnSetup(p).find("MachineCertificate") != std::string::npos);
    CHECK(AndroidVpnSetup(p).find("IKEv2/IPSec RSA") != std::string::npos);
}
