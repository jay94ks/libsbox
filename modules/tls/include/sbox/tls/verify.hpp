#ifndef __INCLUDE_SBOX_TLS_VERIFY_HPP__
#define __INCLUDE_SBOX_TLS_VERIFY_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/tls/trust.hpp>

namespace sbox {
namespace tls {

    /**
     * Inputs of a server certificate chain verification.
     */
    struct STlsVerifyParams {
        std::string_view host;          // --> DNS name or IP literal the certificate must name.
        int64_t nowSeconds = 0;         // --> Unix time used for validity checks; 0 means now.
    };

    /**
     * Verifies a server certificate chain as sent in a TLS Certificate message.
     *
     * Builds a path from the leaf (chain[0]) through the other certificates of `chain` (in any
     * order) to an anchor of `trust` by exact issuer/subject name match and signature
     * verification, backtracking over alternatives (cross-signed roots). Checked on the way:
     * validity periods of every certificate on the path (anchor included); BasicConstraints
     * cA and pathLenConstraint and KeyUsage keyCertSign on issuers; ExtendedKeyUsage
     * serverAuth (or anyExtendedKeyUsage) wherever the extension is present; DNS and IP name
     * constraints; unknown critical extensions are rejected; MD5/SHA-1 signatures and RSA keys
     * below 2048 bits are rejected below the anchor; and the leaf must name `host` in its
     * subjectAltName (dNSName with RFC 6125 wildcard rules, or iPAddress for an IP literal).
     * The legacy subject common name is not consulted.
     *
     * @param chain DER certificates, leaf first.
     * @param reason Receives a human-readable reason on failure (may be null).
     * @return SBOX_OK, -EKEYREJECTED when the chain is not trusted or does not name the host,
     *         -EINVAL for an empty chain or empty host.
     */
    SBOX_API int32_t VerifyServerChain(const std::vector<std::vector<uint8_t>>& chain, const CTrustStore& trust,
                                       const STlsVerifyParams& params, std::string* reason = nullptr);

    /**
     * Matches a host name against one subjectAltName dNSName pattern (RFC 6125 6.4).
     *
     * Comparison is ASCII case-insensitive and ignores one trailing dot. A wildcard is accepted
     * only as the whole left-most label ("*.example.com"), matches exactly one non-empty label,
     * and needs at least two labels after it ("*.com" never matches). IP literals never match
     * a dNSName.
     */
    SBOX_API bool MatchDnsName(std::string_view pattern, std::string_view host);

    /**
     * Returns true when the DER certificate's subjectAltName names `host` (dNSName for a host
     * name, iPAddress for an IPv4/IPv6 literal, brackets allowed).
     */
    SBOX_API bool MatchCertificateHost(const SReadOnlyByteSpan& certDer, std::string_view host);

    /**
     * Parses an IPv4 or IPv6 literal (IPv6 optionally in brackets) into 4 or 16 bytes.
     * @return false when `host` is not an IP literal.
     */
    SBOX_API bool ParseIpLiteral(std::string_view host, std::vector<uint8_t>& out);

}
}

#endif
