#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/tls/trust.hpp>
#include <sbox/tls/verify.hpp>
#include <certpp/x509/chain/pem.hpp>
#include "support.hpp"
#include <cstdlib>

// --> Host name matching, trust store loading and certificate path validation against
// certificate hierarchies generated with the openssl CLI (skipped when it is absent).

using namespace sbox;
using namespace sbox::tls;
using namespace tlstest;

namespace {

    /* Decodes every CERTIFICATE block of a PEM text. */
    std::vector<std::vector<uint8_t>> ders(const std::string& pem) {
        std::vector<std::vector<uint8_t>> out;
        certpp::CString text(pem.data(), pem.size());
        size_t cursor = 0;

        while (true) {
            certpp::CString label;
            certpp::COctet der;
            if (certpp::x509::CPemChainFormat::nextBlock(text, cursor, label, der) != certpp::ERET_OK) {
                break;
            }

            out.emplace_back(der.toPtr(), der.toPtr() + der.size());
        }

        return out;
    }

    /* Concatenates DER lists. */
    std::vector<std::vector<uint8_t>> chainOf(std::initializer_list<std::vector<std::vector<uint8_t>>> parts) {
        std::vector<std::vector<uint8_t>> out;
        for (const auto& p : parts) {
            out.insert(out.end(), p.begin(), p.end());
        }

        return out;
    }

    const std::string CA_EXT = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";
    const std::string LEAF_EXT = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                 "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n";

    /* A PKI with the edge-case certificates this file needs. */
    struct EdgePki : Pki {
        TTask<bool> build() {
            if (!co_await standard()) {
                co_return false;
            }

            bool r = true;

            // --> Leaf restricted to client authentication.
            r = r && co_await key("eku.key", "ec256")
                && co_await issue("eku", "/CN=localhost", "inter",
                                  "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:localhost\n");

            // --> A non-CA certificate used as an issuer.
            r = r && co_await key("notca.key", "ec256")
                && co_await issue("notca", "/CN=not a ca", "root", "basicConstraints=CA:FALSE\n")
                && co_await key("undernotca.key", "ec256")
                && co_await issue("undernotca", "/CN=localhost", "notca", LEAF_EXT);

            // --> inter has pathlen:0, so a CA below it cannot issue.
            r = r && co_await key("inter2.key", "ec256")
                && co_await issue("inter2", "/CN=second level", "inter", CA_EXT)
                && co_await key("deep.key", "ec256")
                && co_await issue("deep", "/CN=localhost", "inter2", LEAF_EXT);

            // --> Name constrained intermediate.
            r = r && co_await key("nc.key", "ec256")
                && co_await issue("nc", "/CN=constrained", "root",
                                  CA_EXT + "nameConstraints=critical,permitted;DNS:allowed.example,excluded;DNS:bad.allowed.example\n")
                && co_await key("ncgood.key", "ec256")
                && co_await issue("ncgood", "/CN=good", "nc",
                                  "basicConstraints=CA:FALSE\nsubjectAltName=DNS:www.allowed.example\n")
                && co_await key("ncout.key", "ec256")
                && co_await issue("ncout", "/CN=out", "nc", "basicConstraints=CA:FALSE\nsubjectAltName=DNS:www.other.example\n")
                && co_await key("ncexcl.key", "ec256")
                && co_await issue("ncexcl", "/CN=excluded", "nc",
                                  "basicConstraints=CA:FALSE\nsubjectAltName=DNS:x.bad.allowed.example\n");

            // --> Unknown critical extension, SHA-1 signature, small RSA key.
            r = r && co_await key("crit.key", "ec256")
                && co_await issue("crit", "/CN=localhost", "inter", LEAF_EXT + "1.2.3.4.5=critical,ASN1:NULL\n")
                && co_await key("sha1.key", "ec256")
                && co_await issue("sha1", "/CN=localhost", "inter", LEAF_EXT, "-days 30", "-sha1")
                && co_await key("rsa1024.key", "rsa1024")
                && co_await issue("rsa1024", "/CN=localhost", "inter", LEAF_EXT);

            // --> Self-signed server certificate (pinned by adding it to a store).
            r = r && co_await key("self.key", "ec256")
                && co_await selfSigned("self", "/CN=localhost", LEAF_EXT);

            // --> Cross-signing: the same intermediate (subject and key) issued by two roots.
            r = r && co_await key("rootb.key", "ec256")
                && co_await selfSigned("rootb", "/CN=sbox test root B", CA_EXT)
                && co_await key("cross.key", "ec256")
                && co_await issue("cross", "/CN=cross intermediate", "root", CA_EXT);

            std::string crossKey = read("cross.key");
            r = r && !crossKey.empty() && write("crossb.key", crossKey);

            r = r && co_await issue("crossb", "/CN=cross intermediate", "rootb", CA_EXT)
                && co_await key("crossleaf.key", "ec256")
                && co_await issue("crossleaf", "/CN=localhost", "cross", LEAF_EXT);

            co_return r;
        }
    };

    EdgePki* sharedPki() {
        static std::unique_ptr<EdgePki> pki;
        static bool attempted = false;

        if (OpensslPath().empty()) {
            MESSAGE("openssl binary not found: skipping certificate path tests");
            return nullptr;
        }

        if (!attempted) {
            attempted = true;
            pki = std::make_unique<EdgePki>();
            CEventLoop loop;
            if (!loop.run(pki->build())) {
                pki.reset();
                MESSAGE("failed to generate test certificates: skipping");
            }
        }

        return pki.get();
    }

    /* Verifies `chain` for `host` against `store`; returns the code and fills the reason. */
    int32_t check(const std::vector<std::vector<uint8_t>>& chain, const CTrustStore& store, std::string_view host,
                  std::string& reason, int64_t now = 0) {
        STlsVerifyParams p;
        p.host = host;
        p.nowSeconds = now;
        return VerifyServerChain(chain, store, p, &reason);
    }

}

TEST_CASE("dNSName matching follows RFC 6125") {
    CHECK(MatchDnsName("example.com", "example.com"));
    CHECK(MatchDnsName("Example.COM", "example.com"));
    CHECK(MatchDnsName("example.com.", "EXAMPLE.com"));
    CHECK(MatchDnsName("example.com", "example.com."));
    CHECK_FALSE(MatchDnsName("example.com", "www.example.com"));
    CHECK_FALSE(MatchDnsName("www.example.com", "example.com"));

    CHECK(MatchDnsName("*.example.com", "www.example.com"));
    CHECK(MatchDnsName("*.example.com", "WWW.Example.Com"));
    CHECK_FALSE(MatchDnsName("*.example.com", "example.com"));
    CHECK_FALSE(MatchDnsName("*.example.com", "a.b.example.com"));
    CHECK_FALSE(MatchDnsName("*.example.com", ".example.com"));
    CHECK_FALSE(MatchDnsName("*.com", "example.com"));
    CHECK_FALSE(MatchDnsName("*", "example"));
    CHECK_FALSE(MatchDnsName("w*.example.com", "www.example.com"));
    CHECK_FALSE(MatchDnsName("*w.example.com", "www.example.com"));
    CHECK_FALSE(MatchDnsName("www.*.com", "www.example.com"));
    CHECK_FALSE(MatchDnsName("*.*.example.com", "a.b.example.com"));
    CHECK_FALSE(MatchDnsName("", "example.com"));
    CHECK_FALSE(MatchDnsName("example.com", ""));
    CHECK_FALSE(MatchDnsName("exa mple.com", "exa mple.com"));
    CHECK_FALSE(MatchDnsName("a..example.com", "a..example.com"));

    // --> IP literals never match dNSName entries, wildcard or not.
    CHECK_FALSE(MatchDnsName("127.0.0.1", "127.0.0.1"));
    CHECK_FALSE(MatchDnsName("*.0.0.1", "127.0.0.1"));
    CHECK_FALSE(MatchDnsName("::1", "::1"));
}

TEST_CASE("IP literal parsing") {
    std::vector<uint8_t> ip;
    REQUIRE(ParseIpLiteral("192.168.1.2", ip));
    CHECK(ip == std::vector<uint8_t>{ 192, 168, 1, 2 });
    REQUIRE(ParseIpLiteral("[::1]", ip));
    CHECK(ip.size() == 16);
    CHECK(ip[15] == 1);
    REQUIRE(ParseIpLiteral("fe80::1", ip));
    CHECK(ip.size() == 16);
    CHECK_FALSE(ParseIpLiteral("registry-1.docker.io", ip));
    CHECK_FALSE(ParseIpLiteral("1.2.3", ip));
    CHECK_FALSE(ParseIpLiteral("", ip));
}

TEST_CASE("Trust store loading, dedupe, layering and system locations") {
    EdgePki* pki = sharedPki();
    if (!pki) {
        return;
    }

    CTrustStorePtr store = CTrustStore::create();
    CHECK(store->addPem("not a certificate") == -EINVAL);
    CHECK(store->addFile(pki->file("missing.pem")) == -ENOENT);
    CHECK(store->addFile(pki->file("root.pem")) == 1);
    CHECK(store->addFile(pki->file("root.pem")) == 0);     // --> Duplicate.
    CHECK(store->size() == 1);

    std::vector<std::vector<uint8_t>> rootDer = ders(pki->read("rootb.pem"));
    REQUIRE(rootDer.size() == 1);
    CHECK(store->addDer(BytesOf(rootDer[0])) == 1);
    CHECK(store->size() == 2);

    // --> A bundle with two certificates and junk between them.
    CTrustStorePtr bundle = CTrustStore::create();
    CHECK(bundle->addPem("junk\n" + pki->read("root.pem") + "\nmore junk\n" + pki->read("rootb.pem")) == 2);

    // --> Directory loading picks *.pem / *.crt files.
    TempDir dir;
    CFile::writeAtomic(dir / "a.crt", pki->read("root.pem"));
    CFile::writeAtomic(dir / "b.pem", pki->read("rootb.pem"));
    CFile::writeAtomic(dir / "c.txt", pki->read("inter.pem"));
    CTrustStorePtr fromDir = CTrustStore::create();
    CHECK(fromDir->addDirectory(dir.path) == 2);

    // --> SSL_CERT_FILE / SSL_CERT_DIR are honoured.
    ::setenv("SSL_CERT_FILE", pki->file("root.pem").c_str(), 1);
    ::setenv("SSL_CERT_DIR", dir.path.c_str(), 1);
    CTrustStorePtr sys = CTrustStore::create();
    CHECK(sys->loadSystem() == 2);      // --> root.pem, then rootb from the directory (root deduped).
    ::unsetenv("SSL_CERT_FILE");
    ::unsetenv("SSL_CERT_DIR");

    // --> Layering: a child store sees its parent's anchors.
    std::string reason;
    std::vector<std::vector<uint8_t>> chain = chainOf({ ders(pki->read("ec.pem")), ders(pki->read("inter.pem")) });
    CTrustStorePtr parent = CTrustStore::create();
    parent->addFile(pki->file("root.pem"));
    CTrustStorePtr child = CTrustStore::create(parent);
    CHECK(child->size() == 0);
    CHECK(child->parent() == parent);
    CHECK(check(chain, *child, "localhost", reason) == SBOX_OK);

    CHECK(CTrustStore::system() != nullptr);
    CHECK(CTrustStore::system() == CTrustStore::system());
}

TEST_CASE("Certificate path validation") {
    EdgePki* pki = sharedPki();
    if (!pki) {
        return;
    }

    CTrustStorePtr store = CTrustStore::create();
    REQUIRE(store->addFile(pki->file("root.pem")) == 1);

    auto leaf = [&](const std::string& name) { return ders(pki->read(name + ".pem")); };
    std::vector<std::vector<uint8_t>> inter = leaf("inter");
    std::string reason;

    SUBCASE("valid chains") {
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "localhost", reason) == SBOX_OK);
        CHECK(reason.empty());
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "127.0.0.1", reason) == SBOX_OK);
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "x.test.example", reason) == SBOX_OK);
        CHECK(check(chainOf({ leaf("rsa"), inter }), *store, "localhost", reason) == SBOX_OK);
        CHECK(check(chainOf({ leaf("ed"), inter }), *store, "localhost", reason) == SBOX_OK);
        // --> Extra, unrelated certificates and a redundant root in the chain are tolerated.
        CHECK(check(chainOf({ leaf("ec"), leaf("rootb"), inter, leaf("root") }), *store, "localhost", reason) == SBOX_OK);
    }

    SUBCASE("host name mismatches") {
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "example.com", reason) == -EKEYREJECTED);
        CHECK(reason.find("does not match") != std::string::npos);
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "127.0.0.2", reason) == -EKEYREJECTED);
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "a.b.test.example", reason) == -EKEYREJECTED);
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "", reason) == -EINVAL);
        CHECK(check({}, *store, "localhost", reason) == -EINVAL);
    }

    SUBCASE("missing issuer and untrusted root") {
        CHECK(check(leaf("ec"), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("unknown CA") != std::string::npos);

        CTrustStorePtr other = CTrustStore::create();
        other->addFile(pki->file("rootb.pem"));
        CHECK(check(chainOf({ leaf("ec"), inter }), *other, "localhost", reason) == -EKEYREJECTED);
    }

    SUBCASE("validity period") {
        int64_t now = int64_t(::time(nullptr));
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "localhost", reason, now + 60 * 86400) == -EKEYREJECTED);
        CHECK(reason.find("expired") != std::string::npos);
        CHECK(check(chainOf({ leaf("ec"), inter }), *store, "localhost", reason, now - 86400) == -EKEYREJECTED);
        CHECK(reason.find("not yet valid") != std::string::npos);
    }

    SUBCASE("extended key usage") {
        CHECK(check(chainOf({ leaf("eku"), inter }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("extendedKeyUsage") != std::string::npos);
    }

    SUBCASE("issuer must be a CA within its path length") {
        CHECK(check(chainOf({ leaf("undernotca"), leaf("notca") }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("not a CA") != std::string::npos);

        CHECK(check(chainOf({ leaf("deep"), leaf("inter2"), inter }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("path length") != std::string::npos);
    }

    SUBCASE("name constraints") {
        CHECK(check(chainOf({ leaf("ncgood"), leaf("nc") }), *store, "www.allowed.example", reason) == SBOX_OK);
        CHECK(check(chainOf({ leaf("ncout"), leaf("nc") }), *store, "www.other.example", reason) == -EKEYREJECTED);
        CHECK(reason.find("name constraints") != std::string::npos);
        CHECK(check(chainOf({ leaf("ncexcl"), leaf("nc") }), *store, "x.bad.allowed.example", reason) == -EKEYREJECTED);
        CHECK(reason.find("excluded") != std::string::npos);
    }

    SUBCASE("unknown critical extension, SHA-1 and small RSA keys") {
        CHECK(check(chainOf({ leaf("crit"), inter }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("critical") != std::string::npos);
        CHECK(check(chainOf({ leaf("sha1"), inter }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("SHA-1") != std::string::npos);
        CHECK(check(chainOf({ leaf("rsa1024"), inter }), *store, "localhost", reason) == -EKEYREJECTED);
        CHECK(reason.find("2048") != std::string::npos);
    }

    SUBCASE("pinned self-signed certificate") {
        CHECK(check(leaf("self"), *store, "localhost", reason) == -EKEYREJECTED);
        CTrustStorePtr pinned = CTrustStore::create();
        REQUIRE(pinned->addFile(pki->file("self.pem")) == 1);
        CHECK(check(leaf("self"), *pinned, "localhost", reason) == SBOX_OK);
        CHECK(check(leaf("self"), *pinned, "other.example", reason) == -EKEYREJECTED);
    }

    SUBCASE("backtracking over a cross-signed intermediate") {
        CTrustStorePtr onlyB = CTrustStore::create();
        REQUIRE(onlyB->addFile(pki->file("rootb.pem")) == 1);

        // --> The first candidate issuer (signed by root A) dead-ends; the cross-sign succeeds.
        std::vector<std::vector<uint8_t>> chain = chainOf({ leaf("crossleaf"), leaf("cross"), leaf("crossb") });
        CHECK(check(chain, *onlyB, "localhost", reason) == SBOX_OK);
        CHECK(check(chain, *store, "localhost", reason) == SBOX_OK);
        CHECK(check(chainOf({ leaf("crossleaf"), leaf("cross") }), *onlyB, "localhost", reason) == -EKEYREJECTED);
    }

    SUBCASE("MatchCertificateHost") {
        std::vector<uint8_t> ec = leaf("ec")[0];
        CHECK(MatchCertificateHost(BytesOf(ec), "localhost"));
        CHECK(MatchCertificateHost(BytesOf(ec), "LOCALHOST."));
        CHECK(MatchCertificateHost(BytesOf(ec), "foo.test.example"));
        CHECK(MatchCertificateHost(BytesOf(ec), "127.0.0.1"));
        CHECK_FALSE(MatchCertificateHost(BytesOf(ec), "::1"));
        CHECK_FALSE(MatchCertificateHost(BytesOf(ec), "test.example"));

        std::vector<uint8_t> v6 = leaf("crossleaf")[0];
        CHECK(MatchCertificateHost(BytesOf(v6), "[::1]"));
        CHECK(MatchCertificateHost(BytesOf(v6), "::1"));
    }
}
