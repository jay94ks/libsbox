#ifndef __INCLUDE_SBOX_VPN_IPSEC_CERTS_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_CERTS_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <memory>
#include <string>
#include <vector>

namespace certpp {
namespace x509 {
    class CCert;
}
namespace crypto {
    class IPrivateKey;
}
}

// --> X.509 material for IKE: loading PEM certificates/keys, chain verification for peer
// certificates, and a small CA that issues certificates the built-in VPN clients accept
// (serverAuth + IKE intermediate EKU, SAN with the server name). Everything goes through
// libcertpp.

namespace sbox {
namespace vpn {

    /** OID of the "IP Security IKE Intermediate" extended key usage (RFC 4945 5.1.3.12). */
    constexpr const char* OID_IKE_INTERMEDIATE = "1.3.6.1.5.5.8.2.2";

    /**
     * A certificate (with an optional private key and chain) usable by IKE.
     */
    class SBOX_API CIkeCertificate {
    private:
        struct SImpl;
        std::shared_ptr<SImpl> _impl;

    public:
        CIkeCertificate();

        ~CIkeCertificate();

        CIkeCertificate(const CIkeCertificate&);

        CIkeCertificate& operator=(const CIkeCertificate&);

        /**
         * Loads the first CERTIFICATE block of `certPem` as the leaf and further blocks as its
         * chain; a private key is taken from `keyPem` or from `certPem` itself (RSA PKCS#1,
         * SEC1 EC or PKCS#8, unencrypted).
         * @return SBOX_OK, -EINVAL (no certificate), -EKEYREJECTED (key does not match).
         */
        static int32_t fromPem(std::string_view certPem, CIkeCertificate& out, std::string_view keyPem = std::string_view());

        /**
         * Loads a DER certificate (no key).
         */
        static int32_t fromDer(const SReadOnlyByteSpan& der, CIkeCertificate& out);

        /**
         * Wraps a libcertpp certificate and (optional) private key.
         */
        static CIkeCertificate fromNative(const certpp::x509::CCert& cert, std::shared_ptr<certpp::crypto::IPrivateKey> key);

        /**
         * Loads PEM files (the key file is optional; empty path skips it).
         */
        static int32_t loadFiles(const std::string& certPath, const std::string& keyPath, CIkeCertificate& out);

        /**
         * Loads every CERTIFICATE block of a PEM bundle (trust anchors).
         */
        static int32_t loadBundle(std::string_view pem, std::vector<CIkeCertificate>& out);

        /** Returns true when a certificate is loaded. */
        bool isValid() const noexcept;

        /** Returns true when the private key is attached. */
        bool hasPrivateKey() const noexcept;

        /** Returns the DER encoding of the leaf. */
        const std::vector<uint8_t>& der() const;

        /** Returns the DER encodings of the chain certificates (excluding the leaf). */
        const std::vector<std::vector<uint8_t>>& chain() const;

        /** Returns the subject as text ("C=KR, O=..., CN=..."). */
        std::string subject() const;

        /** Returns the issuer as text. */
        std::string issuer() const;

        /** Returns the DER subject Name (for ID_DER_ASN1_DN). */
        std::vector<uint8_t> subjectDer() const;

        /** Returns the SHA-1 of the SubjectPublicKeyInfo (CERTREQ authority hash). */
        std::vector<uint8_t> keyHash() const;

        /** Returns the dNSName SAN entries. */
        std::vector<std::string> dnsNames() const;

        /** Returns the iPAddress SAN entries as text. */
        std::vector<std::string> ipAddresses() const;

        /** Returns the rfc822Name SAN entries. */
        std::vector<std::string> emails() const;

        /** Returns true for a CA certificate (basicConstraints cA). */
        bool isCa() const;

        /** Returns true when the key is ECDSA. */
        bool isEcdsa() const;

        /**
         * Checks the validity period against the current time.
         * @return SBOX_OK or -EKEYEXPIRED.
         */
        int32_t checkTime() const;

        /**
         * Checks that `issuer` signed this certificate.
         * @return SBOX_OK or -EKEYREJECTED.
         */
        int32_t verifySignedBy(const CIkeCertificate& issuer) const;

        /**
         * Exports PEM (certificate, chain, and the key when `withKey`).
         */
        std::string toPem(bool withKey = false) const;

        /**
         * Exports the private key alone as PEM (empty when none).
         */
        std::string keyPem() const;

        /** Returns the libcertpp certificate. */
        const certpp::x509::CCert& native() const;

        /** Returns the libcertpp private key (null when none). */
        std::shared_ptr<certpp::crypto::IPrivateKey> privateKey() const;
    };

    /**
     * Verifies `leaf` up to one of `trusted` through `intermediates` (signatures, validity
     * periods and the CA flag of every issuer).
     * @return SBOX_OK, -EKEYREJECTED (no path), -EKEYEXPIRED (a certificate is out of date).
     */
    SBOX_API int32_t VerifyIkeCertificate(const CIkeCertificate& leaf, const std::vector<CIkeCertificate>& intermediates,
                                          const std::vector<CIkeCertificate>& trusted);

    /**
     * Options for generated certificates.
     */
    struct SVpnCertOptions {
        std::string commonName;
        std::string organization = "libsbox VPN";
        std::vector<std::string> dnsNames;      // --> SAN dNSName entries.
        std::vector<std::string> ipAddresses;   // --> SAN iPAddress entries.
        std::vector<std::string> emails;        // --> SAN rfc822Name entries (client certificates).
        uint32_t days = 825;                    // --> Apple rejects longer server lifetimes.
        bool ecdsa = false;                     // --> ECDSA P-256 instead of RSA.
        uint32_t rsaBits = 2048;
        bool server = true;                     // --> serverAuth + IKE intermediate; false: clientAuth.
    };

    /**
     * Generates a self-signed CA (basicConstraints cA, keyCertSign/cRLSign).
     */
    SBOX_API int32_t GenerateVpnCa(const SVpnCertOptions& options, CIkeCertificate& out);

    /**
     * Issues a server or client certificate signed by `ca` (which needs its private key).
     * Server certificates carry EKU serverAuth + IKE intermediate and a SAN with every name and
     * address, which Windows, macOS/iOS and Android all check.
     */
    SBOX_API int32_t IssueVpnCertificate(const CIkeCertificate& ca, const SVpnCertOptions& options, CIkeCertificate& out);

}
}

#endif
