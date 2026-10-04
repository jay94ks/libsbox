#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/core/file.hpp>
#include <sbox/net/address.hpp>
#include "crypto.hpp"
#include "der.hpp"
#include <certpp/crypto/asym.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/name.hpp>
#include <certpp/string.hpp>
#include <certpp/time.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/x509/chain.hpp>
#include <certpp/x509/chain/pem.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/x509/exts/bc.hpp>
#include <certpp/x509/exts/eku.hpp>
#include <certpp/x509/exts/ku.hpp>
#include <certpp/x509/exts/san.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace certpp::crypto;
    using namespace certpp::x509;
    using namespace ipsec;

    struct CIkeCertificate::SImpl {
        CCert cert;
        IPrivateKeyPtr key;
        std::vector<uint8_t> der;
        std::vector<std::vector<uint8_t>> chain;
    };

    CIkeCertificate::CIkeCertificate() = default;

    CIkeCertificate::~CIkeCertificate() = default;

    CIkeCertificate::CIkeCertificate(const CIkeCertificate&) = default;

    CIkeCertificate& CIkeCertificate::operator=(const CIkeCertificate&) = default;

    namespace {

        const std::vector<uint8_t> EMPTY_BYTES;
        const std::vector<std::vector<uint8_t>> EMPTY_CHAIN;

        /* Loads a PEM collection. */
        int32_t loadCollection(std::string_view text, CCertCollection& out) {
            CPemChainFormat format(true);
            if (format.load(certpp::SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.data()), text.size()),
                            certpp::SReadOnlyByteSpan(), out) != certpp::ERET_OK) {
                return -EINVAL;
            }

            return out.count() ? SBOX_OK : -EINVAL;
        }

        /* Random positive serial number. */
        certpp::COctet randomSerial() {
            uint8_t serial[16];
            IkeRandom(SByteSpan(serial, sizeof(serial)));
            serial[0] = uint8_t((serial[0] & 0x7f) | 0x40);
            return certpp::COctet(serial, sizeof(serial));
        }

        /* Generates a key pair. */
        int32_t generateKey(const SVpnCertOptions& options, SKeyPair& out) {
            IAsymmetricPtr asym = IAsymmetric::builtIn(options.ecdsa ? EASYM_P256 : EASYM_RSA);
            if (!asym) {
                return -ENOTSUP;
            }

            certpp::ERetCode rc = certpp::ERET_AGAIN;
            for (int32_t attempt = 0; attempt < 16 && rc == certpp::ERET_AGAIN; ++attempt) {
                rc = asym->generateKeyPair(options.ecdsa ? 256 : options.rsaBits, out);
            }

            return rc == certpp::ERET_OK && !out.empty() ? SBOX_OK : -EIO;
        }

        /* SHA-1 of the encoded public key (RFC 5280 4.2.1.2 method 1). */
        certpp::COctet keyIdentifier(const IPublicKeyPtr& key) {
            certpp::COctet pub;
            if (!key || key->serialize(pub) != certpp::ERET_OK) {
                return certpp::COctet();
            }

            std::vector<uint8_t> h = Hash(EHASH_SHA1, SReadOnlyByteSpan(pub.toPtr(), pub.size()));
            return certpp::COctet(h.data(), h.size());
        }

        /* Builds a DN from options. */
        bool makeName(const SVpnCertOptions& options, certpp::CDistinguishedName& out) {
            std::string text = "CN=" + options.commonName;
            if (!options.organization.empty()) {
                text += ", O=" + options.organization;
            }

            return certpp::CDistinguishedName::tryParse(out, certpp::CString(text.c_str()));
        }

        /* Issues a certificate (self-signed when `ca` is null). */
        int32_t issue(const CIkeCertificate* ca, const SVpnCertOptions& options, bool isCa, CIkeCertificate& out) {
            if (options.commonName.empty() || options.days == 0) {
                return -EINVAL;
            }

            if (ca && (!ca->isValid() || !ca->hasPrivateKey())) {
                return -EINVAL;
            }

            SKeyPair pair;
            int32_t r = generateKey(options, pair);
            if (r != SBOX_OK) {
                return r;
            }

            CCertBuilder b;
            if (!makeName(options, b.subject)) {
                return -EINVAL;
            }

            b.issuer = ca ? ca->native().subject() : b.subject;
            b.serialNumber = randomSerial();
            certpp::SDateTime now = certpp::SDateTime::now(true);
            b.notBefore = now.subtract(uint64_t(3600) * 1000);
            b.notAfter = now.add(uint64_t(options.days) * 86400 * 1000);
            b.subjectKey = pair.publicKey;
            b.issuerKeyPair = ca ? SKeyPair(ca->native().publicKey(), ca->privateKey()) : pair;
            b.digestAlgo = EHASH_SHA256;

            CBasicConstraintsExtensionBuilder bc;
            bc.setIsCa(isCa);
            IExtensionPtr bcExt = bc.build();
            if (!bcExt) {
                return -EIO;
            }

            bcExt->critical(true);
            b.extensions.add(bcExt);

            CKeyUsagesExtensionBuilder ku;
            if (isCa) {
                ku.setBits(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN | EKUSE_DIGITAL_SIGNATURE);
            }
            else {
                // --> keyEncipherment for RSA keeps old Windows builds happy; ECDSA cannot encipher.
                ku.setBits(uint16_t(EKUSE_DIGITAL_SIGNATURE | (options.ecdsa ? 0 : EKUSE_KEY_ENCIPHERMENT)));
            }

            IExtensionPtr kuExt = ku.build();
            if (!kuExt) {
                return -EIO;
            }

            kuExt->critical(true);
            b.extensions.add(kuExt);

            if (!isCa) {
                CEkuExtensionBuilder eku;
                if (options.server) {
                    eku.addPurpose(certpp::CString(CEkuExtension::OID_SERVER_AUTH));
                    eku.addPurpose(certpp::CString(OID_IKE_INTERMEDIATE));
                }
                else {
                    eku.addPurpose(certpp::CString(CEkuExtension::OID_CLIENT_AUTH));
                }

                IExtensionPtr ekuExt = eku.build();
                if (!ekuExt) {
                    return -EIO;
                }

                b.extensions.add(ekuExt);

                CSanExtensionBuilder san;
                size_t names = 0;
                for (const std::string& dns : options.dnsNames) {
                    san.addName(CGeneralName(EGNAME_DNS, certpp::CString(dns.c_str())));
                    ++names;
                }

                for (const std::string& ip : options.ipAddresses) {
                    net::SIpAddress addr;
                    if (net::SIpAddress::parse(ip, addr) != SBOX_OK) {
                        return -EINVAL;
                    }

                    san.addName(CGeneralName(EGNAME_IP_ADDRESS, certpp::COctet(addr.bytes, addr.length())));
                    ++names;
                }

                for (const std::string& email : options.emails) {
                    san.addName(CGeneralName(EGNAME_RFC822, certpp::CString(email.c_str())));
                    ++names;
                }

                if (names) {
                    IExtensionPtr sanExt = san.build();
                    if (!sanExt) {
                        return -EINVAL;
                    }

                    b.extensions.add(sanExt);
                }
            }

            CSkiExtensionBuilder ski;
            ski.setKeyIdentifier(keyIdentifier(pair.publicKey));
            if (IExtensionPtr skiExt = ski.build()) {
                b.extensions.add(skiExt);
            }

            if (ca) {
                CAkiExtensionBuilder aki;
                aki.setKeyIdentifier(keyIdentifier(ca->native().publicKey()));
                if (IExtensionPtr akiExt = aki.build()) {
                    b.extensions.add(akiExt);
                }
            }

            CCert cert;
            if (b.build(cert) != certpp::ERET_OK) {
                return -EIO;
            }

            IPrivateKeyPtr key = pair.privateKey;
            if (cert.privateKey(key) != certpp::ERET_OK) {
                return -EIO;
            }

            out = CIkeCertificate::fromNative(cert, pair.privateKey);
            return SBOX_OK;
        }

    }

    /* Loads PEM text. */
    int32_t CIkeCertificate::fromPem(std::string_view certPem, CIkeCertificate& out, std::string_view keyPem) {
        std::string text(certPem);
        if (!keyPem.empty()) {
            text += "\n";
            text += keyPem;
        }

        CCertCollection collection;
        int32_t r = loadCollection(text, collection);
        if (r != SBOX_OK) {
            return r;
        }

        SCertEntry leaf;
        if (collection.at(0, leaf) != certpp::ERET_OK) {
            return -EINVAL;
        }

        IPrivateKeyPtr key = leaf.privateKey ? leaf.privateKey : leaf.cert.privateKey();
        if (!keyPem.empty() && !key) {
            return -EKEYREJECTED;
        }

        auto impl = std::make_shared<SImpl>();
        impl->cert = leaf.cert;
        impl->key = key;
        const certpp::COctet& leafRaw = leaf.cert.rawData();
        impl->der.assign(leafRaw.toPtr(), leafRaw.toPtr() + leafRaw.size());

        for (size_t i = 1; i < collection.count(); ++i) {
            SCertEntry entry;
            if (collection.at(i, entry) == certpp::ERET_OK) {
                const certpp::COctet& raw = entry.cert.rawData();
                impl->chain.emplace_back(raw.toPtr(), raw.toPtr() + raw.size());
            }
        }

        out._impl = std::move(impl);
        return SBOX_OK;
    }

    /* Loads DER. */
    int32_t CIkeCertificate::fromDer(const SReadOnlyByteSpan& der, CIkeCertificate& out) {
        CCert cert;
        if (der.empty() || cert.importDer(certpp::COctet(der.data, der.size)) != certpp::ERET_OK) {
            return -EINVAL;
        }

        out = fromNative(cert, nullptr);
        return SBOX_OK;
    }

    /* Wraps libcertpp objects. */
    CIkeCertificate CIkeCertificate::fromNative(const certpp::x509::CCert& cert, std::shared_ptr<certpp::crypto::IPrivateKey> key) {
        CIkeCertificate out;
        auto impl = std::make_shared<SImpl>();
        impl->cert = cert;
        impl->key = std::move(key);
        const certpp::COctet& raw = cert.rawData();
        impl->der.assign(raw.toPtr(), raw.toPtr() + raw.size());
        out._impl = std::move(impl);
        return out;
    }

    /* Loads files. */
    int32_t CIkeCertificate::loadFiles(const std::string& certPath, const std::string& keyPath, CIkeCertificate& out) {
        std::string cert;
        int32_t r = CFile::readAll(certPath, cert);
        if (r != SBOX_OK) {
            return r;
        }

        std::string key;
        if (!keyPath.empty()) {
            r = CFile::readAll(keyPath, key);
            if (r != SBOX_OK) {
                return r;
            }
        }

        r = fromPem(cert, out, key);
        if (!key.empty()) {
            std::memset(key.data(), 0, key.size());
        }

        return r;
    }

    /* Loads a bundle. */
    int32_t CIkeCertificate::loadBundle(std::string_view pem, std::vector<CIkeCertificate>& out) {
        CCertCollection collection;
        int32_t r = loadCollection(pem, collection);
        if (r != SBOX_OK) {
            return r;
        }

        out.clear();
        for (size_t i = 0; i < collection.count(); ++i) {
            SCertEntry entry;
            if (collection.at(i, entry) != certpp::ERET_OK) {
                continue;
            }

            out.push_back(fromNative(entry.cert, nullptr));
        }

        return SBOX_OK;
    }

    /* Loaded state. */
    bool CIkeCertificate::isValid() const noexcept {
        return _impl && !_impl->der.empty();
    }

    /* Key state. */
    bool CIkeCertificate::hasPrivateKey() const noexcept {
        return _impl && _impl->key;
    }

    /* Leaf DER. */
    const std::vector<uint8_t>& CIkeCertificate::der() const {
        return _impl ? _impl->der : EMPTY_BYTES;
    }

    /* Chain DERs. */
    const std::vector<std::vector<uint8_t>>& CIkeCertificate::chain() const {
        return _impl ? _impl->chain : EMPTY_CHAIN;
    }

    /* Subject text. */
    std::string CIkeCertificate::subject() const {
        SReadOnlyByteSpan issuer, subject, spki;
        if (!_impl || !CertFields(BytesOf(_impl->der), issuer, subject, spki)) {
            return std::string();
        }

        return DnToString(subject);
    }

    /* Issuer text. */
    std::string CIkeCertificate::issuer() const {
        SReadOnlyByteSpan issuer, subject, spki;
        if (!_impl || !CertFields(BytesOf(_impl->der), issuer, subject, spki)) {
            return std::string();
        }

        return DnToString(issuer);
    }

    /* Subject DER. */
    std::vector<uint8_t> CIkeCertificate::subjectDer() const {
        SReadOnlyByteSpan issuer, subject, spki;
        if (!_impl || !CertFields(BytesOf(_impl->der), issuer, subject, spki)) {
            return {};
        }

        return std::vector<uint8_t>(subject.begin(), subject.end());
    }

    /* SPKI hash. */
    std::vector<uint8_t> CIkeCertificate::keyHash() const {
        SReadOnlyByteSpan issuer, subject, spki;
        if (!_impl || !CertFields(BytesOf(_impl->der), issuer, subject, spki)) {
            return {};
        }

        return Hash(EHASH_SHA1, spki);
    }

    namespace {

        /* SAN entries of one type. */
        std::vector<std::string> sanOf(const CCert& cert, EGeneralNameType type) {
            std::vector<std::string> out;
            auto san = cert.extension<CSanExtension>();
            if (!san) {
                return out;
            }

            for (const CGeneralName& n : san->names()) {
                if (n.type() != type) {
                    continue;
                }

                if (type == EGNAME_IP_ADDRESS) {
                    net::SIpAddress addr;
                    if (net::SIpAddress::fromBytes(n.raw().toPtr(), n.raw().size(), addr) == SBOX_OK) {
                        out.push_back(addr.toString());
                    }
                }
                else {
                    out.emplace_back(n.text().toPtr(), n.text().size());
                }
            }

            return out;
        }

    }

    /* DNS SANs. */
    std::vector<std::string> CIkeCertificate::dnsNames() const {
        return _impl ? sanOf(_impl->cert, EGNAME_DNS) : std::vector<std::string>();
    }

    /* IP SANs. */
    std::vector<std::string> CIkeCertificate::ipAddresses() const {
        return _impl ? sanOf(_impl->cert, EGNAME_IP_ADDRESS) : std::vector<std::string>();
    }

    /* Email SANs. */
    std::vector<std::string> CIkeCertificate::emails() const {
        return _impl ? sanOf(_impl->cert, EGNAME_RFC822) : std::vector<std::string>();
    }

    /* CA flag. */
    bool CIkeCertificate::isCa() const {
        if (!_impl) {
            return false;
        }

        auto bc = _impl->cert.extension<CBasicConstraintsExtension>();
        return bc && bc->isCa();
    }

    /* ECDSA key. */
    bool CIkeCertificate::isEcdsa() const {
        if (!_impl) {
            return false;
        }

        IPublicKeyPtr pub = _impl->cert.publicKey();
        if (!pub) {
            return false;
        }

        EAsymmetrics which = pub->algorithm();
        return which == EASYM_P256 || which == EASYM_P384 || which == EASYM_P521;
    }

    /* Validity period. */
    int32_t CIkeCertificate::checkTime() const {
        if (!_impl) {
            return -EINVAL;
        }

        certpp::SDateTime now = certpp::SDateTime::now(true);
        if (now.diff(_impl->cert.notBefore()).milliseconds < 0 || _impl->cert.notAfter().diff(now).milliseconds < 0) {
            return -EKEYEXPIRED;
        }

        return SBOX_OK;
    }

    /* Signature check. */
    int32_t CIkeCertificate::verifySignedBy(const CIkeCertificate& issuer) const {
        if (!_impl || !issuer._impl) {
            return -EINVAL;
        }

        return _impl->cert.verifyBy(issuer._impl->cert) == certpp::ERET_OK ? SBOX_OK : -EKEYREJECTED;
    }

    /* PEM export. */
    std::string CIkeCertificate::toPem(bool withKey) const {
        if (!_impl) {
            return std::string();
        }

        certpp::CString text;
        certpp::COctet der(_impl->der.data(), _impl->der.size());
        CPemChainFormat::appendBlock(text, "CERTIFICATE", der);
        for (const std::vector<uint8_t>& c : _impl->chain) {
            CPemChainFormat::appendBlock(text, "CERTIFICATE", certpp::COctet(c.data(), c.size()));
        }

        std::string out(text.toPtr(), text.size());
        if (withKey) {
            out += keyPem();
        }

        return out;
    }

    /* Key PEM. */
    std::string CIkeCertificate::keyPem() const {
        if (!_impl || !_impl->key) {
            return std::string();
        }

        certpp::COctet der;
        if (CCert::exportPkcs8PrivateKey(_impl->key, der) != certpp::ERET_OK) {
            return std::string();
        }

        certpp::CString text;
        CPemChainFormat::appendBlock(text, "PRIVATE KEY", der);
        der.secureClear();
        return std::string(text.toPtr(), text.size());
    }

    /* Native certificate. */
    const certpp::x509::CCert& CIkeCertificate::native() const {
        static const CCert EMPTY;
        return _impl ? _impl->cert : EMPTY;
    }

    /* Native key. */
    std::shared_ptr<certpp::crypto::IPrivateKey> CIkeCertificate::privateKey() const {
        return _impl ? _impl->key : nullptr;
    }

    /* Chain verification. */
    int32_t VerifyIkeCertificate(const CIkeCertificate& leaf, const std::vector<CIkeCertificate>& intermediates,
                                 const std::vector<CIkeCertificate>& trusted) {
        if (!leaf.isValid()) {
            return -EINVAL;
        }

        int32_t r = leaf.checkTime();
        if (r != SBOX_OK) {
            return r;
        }

        const CIkeCertificate* current = &leaf;
        for (int32_t depth = 0; depth < 8; ++depth) {
            for (const CIkeCertificate& anchor : trusted) {
                if (current->der() == anchor.der()) {
                    return anchor.checkTime();
                }

                if (current->verifySignedBy(anchor) == SBOX_OK) {
                    if (!anchor.isCa()) {
                        return -EKEYREJECTED;
                    }

                    return anchor.checkTime();
                }
            }

            const CIkeCertificate* next = nullptr;
            for (const CIkeCertificate& inter : intermediates) {
                if (inter.der() != current->der() && current->verifySignedBy(inter) == SBOX_OK) {
                    next = &inter;
                    break;
                }
            }

            if (!next || !next->isCa()) {
                return -EKEYREJECTED;
            }

            r = next->checkTime();
            if (r != SBOX_OK) {
                return r;
            }

            current = next;
        }

        return -EKEYREJECTED;
    }

    /* Generates a CA. */
    int32_t GenerateVpnCa(const SVpnCertOptions& options, CIkeCertificate& out) {
        SVpnCertOptions o = options;
        if (o.days == 825) {
            o.days = 3650;      // --> The 825-day ceiling applies to leaf certificates only.
        }

        return issue(nullptr, o, true, out);
    }

    /* Issues a leaf certificate. */
    int32_t IssueVpnCertificate(const CIkeCertificate& ca, const SVpnCertOptions& options, CIkeCertificate& out) {
        return issue(&ca, options, false, out);
    }

}
}
