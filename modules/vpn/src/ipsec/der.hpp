#ifndef __SRC_VPN_IPSEC_DER_HPP__
#define __SRC_VPN_IPSEC_DER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <string>
#include <vector>

// --> Minimal DER walker/writer for the few certificate fields IKE needs as raw bytes (subject
// Name for ID_DER_ASN1_DN, SubjectPublicKeyInfo for CERTREQ hashes) and for AlgorithmIdentifier
// and ECDSA signature value conversions. This is structure encoding, not cryptography.

namespace sbox {
namespace vpn {
namespace ipsec {

    /**
     * One DER element (views the input).
     */
    struct DerElement {
        uint8_t tag = 0;
        const uint8_t* header = nullptr;    // --> Start of the TLV.
        size_t headerSize = 0;
        const uint8_t* content = nullptr;
        size_t contentSize = 0;

        /** Returns the whole TLV. */
        inline SReadOnlyByteSpan whole() const { return SReadOnlyByteSpan(header, headerSize + contentSize); }

        /** Returns the content. */
        inline SReadOnlyByteSpan value() const { return SReadOnlyByteSpan(content, contentSize); }
    };

    /**
     * Reads the TLV at the start of `in`; advances `in` past it.
     */
    bool DerNext(SReadOnlyByteSpan& in, DerElement& out);

    /**
     * Appends a DER TLV.
     */
    void DerPut(std::vector<uint8_t>& out, uint8_t tag, const SReadOnlyByteSpan& content);

    /**
     * Extracts the TBSCertificate fields of a DER certificate.
     */
    bool CertFields(const SReadOnlyByteSpan& cert, SReadOnlyByteSpan& issuer, SReadOnlyByteSpan& subject,
                    SReadOnlyByteSpan& spki);

    /**
     * Formats a DER Name as "C=KR, O=Example, CN=vpn" (common attributes only).
     */
    std::string DnToString(const SReadOnlyByteSpan& name);

    /**
     * Encodes "CN=vpn, O=Example, C=KR" as a DER Name (UTF8String, PrintableString for C).
     * @return false on an unknown attribute or syntax error.
     */
    bool DnFromString(std::string_view text, std::vector<uint8_t>& out);

    /**
     * Converts a DER Ecdsa-Sig-Value to fixed-size r || s.
     */
    bool EcdsaDerToRaw(const SReadOnlyByteSpan& der, size_t coord, std::vector<uint8_t>& out);

    /**
     * Converts fixed-size r || s to a DER Ecdsa-Sig-Value.
     */
    bool EcdsaRawToDer(const SReadOnlyByteSpan& raw, std::vector<uint8_t>& out);

}
}
}

#endif
