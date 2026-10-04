#ifndef __INCLUDE_SBOX_VPN_L2TP_IKEV1_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_IKEV1_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/address.hpp>
#include <string>
#include <vector>

// --> IKEv1 / ISAKMP wire format (RFC 2408, RFC 2409, RFC 2407 IPsec DOI) with the NAT
// traversal (RFC 3947 and its drafts) and DPD (RFC 3706) extensions: constants, the payload
// chain, SA/proposal/transform/attribute codec, identification, notify, delete. The 28-byte
// header is the one IKEv2 uses (SIkeHeader parses it); the generic payload header is the same
// too, but IKEv1 has its own payload numbering, so the chain parser lives here. Decoders never
// trust lengths: anything inconsistent is -EBADMSG.

namespace sbox {
namespace vpn {

    /**
     * ISAKMP payload types (RFC 2408 3.1, RFC 3947, draft NAT-T, Cisco/Microsoft fragments).
     */
    enum EIkev1Payload : uint8_t {
        EIKE1_PL_NONE = 0,
        EIKE1_PL_SA = 1,
        EIKE1_PL_PROPOSAL = 2,
        EIKE1_PL_TRANSFORM = 3,
        EIKE1_PL_KE = 4,
        EIKE1_PL_ID = 5,
        EIKE1_PL_CERT = 6,
        EIKE1_PL_CR = 7,
        EIKE1_PL_HASH = 8,
        EIKE1_PL_SIG = 9,
        EIKE1_PL_NONCE = 10,
        EIKE1_PL_NOTIFY = 11,
        EIKE1_PL_DELETE = 12,
        EIKE1_PL_VENDOR = 13,
        EIKE1_PL_NATD = 20,             // --> RFC 3947.
        EIKE1_PL_NATOA = 21,            // --> RFC 3947.
        EIKE1_PL_NATD_DRAFT = 130,      // --> draft-ietf-ipsec-nat-t-ike-02/03.
        EIKE1_PL_NATOA_DRAFT = 131,
        EIKE1_PL_FRAGMENT = 132,        // --> Cisco/Microsoft IKE fragmentation.
    };

    /**
     * ISAKMP exchange types.
     */
    enum EIkev1Exchange : uint8_t {
        EIKE1_X_MAIN = 2,               // --> Identity protection (Main Mode).
        EIKE1_X_AGGRESSIVE = 4,
        EIKE1_X_INFO = 5,               // --> Informational.
        EIKE1_X_QUICK = 32,             // --> Quick Mode (RFC 2409 5.5).
    };

    /**
     * ISAKMP header flags.
     */
    enum EIkev1Flags : uint8_t {
        EIKE1_F_ENCRYPTED = 0x01,
        EIKE1_F_COMMIT = 0x02,
        EIKE1_F_AUTH_ONLY = 0x04,
    };

    /** ISAKMP major/minor version byte (1.0). */
    constexpr uint8_t IKEV1_VERSION = 0x10;

    /** IPsec DOI (RFC 2407). */
    constexpr uint32_t IKEV1_DOI_IPSEC = 1;

    /** SIT_IDENTITY_ONLY situation. */
    constexpr uint32_t IKEV1_SIT_IDENTITY_ONLY = 1;

    /**
     * Protocol identifiers of proposals, notify and delete payloads.
     */
    enum EIkev1Protocol : uint8_t {
        EIKE1_PROTO_ISAKMP = 1,
        EIKE1_PROTO_AH = 2,
        EIKE1_PROTO_ESP = 3,
    };

    /** Transform identifier KEY_IKE of Phase 1 proposals. */
    constexpr uint8_t IKEV1_KEY_IKE = 1;

    /**
     * Phase 1 (Oakley) attribute types (RFC 2409 Appendix A).
     */
    enum EIkev1Attr : uint16_t {
        EIKE1_A_ENCR = 1,
        EIKE1_A_HASH = 2,
        EIKE1_A_AUTH = 3,
        EIKE1_A_GROUP = 4,
        EIKE1_A_LIFE_TYPE = 11,
        EIKE1_A_LIFE_DURATION = 12,
        EIKE1_A_KEY_LENGTH = 14,
    };

    /**
     * Phase 1 encryption algorithms.
     */
    enum EIkev1Encr : uint16_t {
        EIKE1_ENCR_DES = 1,             // --> Not supported (56-bit).
        EIKE1_ENCR_3DES = 5,
        EIKE1_ENCR_AES = 7,             // --> Needs a KEY_LENGTH attribute (128/192/256).
    };

    /**
     * Phase 1 hash algorithms (their HMAC is the PRF).
     */
    enum EIkev1Hash : uint16_t {
        EIKE1_HASH_MD5 = 1,
        EIKE1_HASH_SHA1 = 2,
        EIKE1_HASH_SHA256 = 4,
        EIKE1_HASH_SHA384 = 5,
        EIKE1_HASH_SHA512 = 6,
    };

    /**
     * Phase 1 authentication methods.
     */
    enum EIkev1Auth : uint16_t {
        EIKE1_AUTH_PSK = 1,
        EIKE1_AUTH_DSS = 2,
        EIKE1_AUTH_RSA_SIG = 3,
        EIKE1_AUTH_XAUTH_INIT_PSK = 65001,  // --> XAUTH variants (not supported).
    };

    /**
     * Life types (Phase 1 and IPsec attributes).
     */
    enum EIkev1LifeType : uint16_t {
        EIKE1_LIFE_SECONDS = 1,
        EIKE1_LIFE_KILOBYTES = 2,
    };

    /**
     * IPsec DOI attribute types (RFC 2407 4.5).
     */
    enum EIkev1IpsecAttr : uint16_t {
        EIKE1_IA_LIFE_TYPE = 1,
        EIKE1_IA_LIFE_DURATION = 2,
        EIKE1_IA_GROUP = 3,
        EIKE1_IA_ENCAP = 4,
        EIKE1_IA_AUTH = 5,
        EIKE1_IA_KEY_LENGTH = 6,
    };

    /**
     * Encapsulation modes (RFC 2407, RFC 3947, draft NAT-T).
     */
    enum EIkev1Encap : uint16_t {
        EIKE1_ENCAP_TUNNEL = 1,
        EIKE1_ENCAP_TRANSPORT = 2,
        EIKE1_ENCAP_UDP_TUNNEL = 3,
        EIKE1_ENCAP_UDP_TRANSPORT = 4,
        EIKE1_ENCAP_UDP_TUNNEL_DRAFT = 61443,
        EIKE1_ENCAP_UDP_TRANSPORT_DRAFT = 61444,
    };

    /**
     * ESP transform identifiers (RFC 2407 4.4.4).
     */
    enum EIkev1EspId : uint8_t {
        EIKE1_ESP_DES = 2,
        EIKE1_ESP_3DES = 3,
        EIKE1_ESP_NULL = 11,
        EIKE1_ESP_AES = 12,
        EIKE1_ESP_AES_GCM_8 = 18,
        EIKE1_ESP_AES_GCM_12 = 19,
        EIKE1_ESP_AES_GCM_16 = 20,
    };

    /**
     * IPsec authentication algorithms (RFC 2407 4.5, RFC 4868).
     */
    enum EIkev1AuthAlg : uint16_t {
        EIKE1_AA_NONE = 0,
        EIKE1_AA_HMAC_MD5 = 1,
        EIKE1_AA_HMAC_SHA1 = 2,
        EIKE1_AA_HMAC_SHA256 = 5,
        EIKE1_AA_HMAC_SHA384 = 6,
        EIKE1_AA_HMAC_SHA512 = 7,
    };

    /**
     * Identification types (RFC 2407 4.6.2.1).
     */
    enum EIkev1IdType : uint8_t {
        EIKE1_ID_IPV4_ADDR = 1,
        EIKE1_ID_FQDN = 2,
        EIKE1_ID_USER_FQDN = 3,
        EIKE1_ID_IPV4_ADDR_SUBNET = 4,
        EIKE1_ID_IPV6_ADDR = 5,
        EIKE1_ID_IPV6_ADDR_SUBNET = 6,
        EIKE1_ID_IPV4_ADDR_RANGE = 7,
        EIKE1_ID_IPV6_ADDR_RANGE = 8,
        EIKE1_ID_DER_ASN1_DN = 9,
        EIKE1_ID_KEY_ID = 11,
    };

    /**
     * Notify message types (RFC 2408 3.14.1, RFC 2407 4.6.3, RFC 3706).
     */
    enum EIkev1Notify : uint16_t {
        EIKE1_N_INVALID_PAYLOAD_TYPE = 1,
        EIKE1_N_DOI_NOT_SUPPORTED = 2,
        EIKE1_N_SITUATION_NOT_SUPPORTED = 3,
        EIKE1_N_INVALID_COOKIE = 4,
        EIKE1_N_INVALID_MAJOR_VERSION = 5,
        EIKE1_N_INVALID_EXCHANGE_TYPE = 7,
        EIKE1_N_INVALID_FLAGS = 8,
        EIKE1_N_INVALID_MESSAGE_ID = 9,
        EIKE1_N_INVALID_PROTOCOL_ID = 10,
        EIKE1_N_INVALID_SPI = 11,
        EIKE1_N_INVALID_TRANSFORM_ID = 12,
        EIKE1_N_ATTRIBUTES_NOT_SUPPORTED = 13,
        EIKE1_N_NO_PROPOSAL_CHOSEN = 14,
        EIKE1_N_PAYLOAD_MALFORMED = 16,
        EIKE1_N_INVALID_KEY_INFORMATION = 17,
        EIKE1_N_INVALID_ID_INFORMATION = 18,
        EIKE1_N_INVALID_HASH_INFORMATION = 23,
        EIKE1_N_AUTHENTICATION_FAILED = 24,
        EIKE1_N_INVALID_SIGNATURE = 25,
        // --
        EIKE1_N_RESPONDER_LIFETIME = 24576,
        EIKE1_N_REPLAY_STATUS = 24577,
        EIKE1_N_INITIAL_CONTACT = 24578,
        EIKE1_N_R_U_THERE = 36136,
        EIKE1_N_R_U_THERE_ACK = 36137,
    };

    /**
     * NAT traversal dialects, from the oldest to RFC 3947.
     */
    enum EIkev1NatT {
        EIKE1_NATT_NONE = 0,
        EIKE1_NATT_DRAFT_02,            // --> draft-ietf-ipsec-nat-t-ike-02 (and "02\n").
        EIKE1_NATT_DRAFT_03,
        EIKE1_NATT_RFC3947,
    };

    /**
     * Well-known vendor ID payloads.
     */
    enum EIkev1Vendor {
        EIKE1_VID_UNKNOWN = 0,
        EIKE1_VID_RFC3947,              // --> MD5("RFC 3947").
        EIKE1_VID_NATT_DRAFT_02,        // --> MD5("draft-ietf-ipsec-nat-t-ike-02").
        EIKE1_VID_NATT_DRAFT_02N,       // --> MD5("draft-ietf-ipsec-nat-t-ike-02\n").
        EIKE1_VID_NATT_DRAFT_03,        // --> MD5("draft-ietf-ipsec-nat-t-ike-03").
        EIKE1_VID_DPD,                  // --> RFC 3706.
        EIKE1_VID_MS_NT5,               // --> "MS NT5 ISAKMPOAKLEY" (+ 4-byte version).
        EIKE1_VID_FRAGMENTATION,        // --> MD5("FRAGMENTATION") (+ optional flags).
        EIKE1_VID_XAUTH,
    };

    /**
     * Returns the payload bytes of a vendor ID (empty for EIKE1_VID_UNKNOWN).
     */
    SBOX_API std::vector<uint8_t> Ikev1VendorId(EIkev1Vendor which);

    /**
     * Identifies a received vendor ID payload (prefix match where vendors append versions).
     */
    SBOX_API EIkev1Vendor Ikev1ClassifyVendorId(const SReadOnlyByteSpan& data);

    /**
     * One payload of an ISAKMP chain.
     */
    struct SIkev1Payload {
        uint8_t type = 0;
        std::vector<uint8_t> body;      // --> Without the 4-byte generic header.
        size_t offset = 0;              // --> Offset of the generic header in the parsed data.
        size_t size = 0;                // --> Encoded size including the generic header.
    };

    /**
     * Parses a payload chain starting with `first`. Trailing bytes after the last payload
     * (encryption padding) are allowed; `end` receives the offset where the chain ended.
     * @return SBOX_OK or -EBADMSG.
     */
    SBOX_API int32_t ParseIkev1Payloads(uint8_t first, const SReadOnlyByteSpan& data, std::vector<SIkev1Payload>& out,
                                        size_t* end = nullptr);

    /**
     * Encodes a payload chain.
     * @param firstType Receives the type of the first payload (0 when empty).
     */
    SBOX_API void EncodeIkev1Payloads(const std::vector<SIkev1Payload>& payloads, std::vector<uint8_t>& out, uint8_t& firstType);

    /**
     * Returns the first payload of `type`, or nullptr.
     */
    SBOX_API const SIkev1Payload* FindIkev1Payload(const std::vector<SIkev1Payload>& payloads, uint8_t type) noexcept;

    /**
     * Builds a payload.
     */
    SBOX_API SIkev1Payload MakeIkev1Payload(uint8_t type, std::vector<uint8_t> body);

    // -- SA payload

    /**
     * One data attribute (RFC 2408 3.3). Basic (TV) attributes carry 16-bit values; variable
     * (TLV) ones up to 8 bytes are represented as an integer as well.
     */
    struct SIkev1Attribute {
        uint16_t type = 0;
        uint64_t value = 0;
        bool variable = false;          // --> Encoded as TLV.
    };

    /**
     * One transform of a proposal.
     */
    struct SBOX_API SIkev1Transform {
        uint8_t number = 1;
        uint8_t id = 0;                 // --> KEY_IKE (Phase 1) or the ESP transform id.
        std::vector<SIkev1Attribute> attributes;

        /**
         * Returns the value of attribute `type`, or `fallback` when absent.
         */
        uint64_t attr(uint16_t type, uint64_t fallback = 0) const noexcept;

        /**
         * Returns true when attribute `type` is present.
         */
        bool has(uint16_t type) const noexcept;
    };

    /**
     * One proposal.
     */
    struct SIkev1Proposal {
        uint8_t number = 1;
        uint8_t protocol = EIKE1_PROTO_ISAKMP;
        std::vector<uint8_t> spi;
        std::vector<SIkev1Transform> transforms;
    };

    /**
     * SA payload contents (IPsec DOI, SIT_IDENTITY_ONLY).
     */
    struct SIkev1Sa {
        uint32_t doi = IKEV1_DOI_IPSEC;
        uint32_t situation = IKEV1_SIT_IDENTITY_ONLY;
        std::vector<SIkev1Proposal> proposals;
    };

    /**
     * Decodes an SA payload body.
     * @return SBOX_OK, -EBADMSG, or -ENOTSUP for another DOI/situation.
     */
    SBOX_API int32_t DecodeIkev1Sa(const SReadOnlyByteSpan& body, SIkev1Sa& out);

    /**
     * Encodes an SA payload body.
     */
    SBOX_API void EncodeIkev1Sa(const SIkev1Sa& sa, std::vector<uint8_t>& out);

    // -- Identification

    /**
     * Identification payload (Phase 1 identities and Quick Mode client IDs).
     */
    struct SBOX_API SIkev1Id {
        uint8_t type = EIKE1_ID_IPV4_ADDR;
        uint8_t protocol = 0;           // --> IP protocol (0: any; Quick Mode uses 17 for L2TP).
        uint16_t port = 0;              // --> 0: any.
        std::vector<uint8_t> data;

        /**
         * Builds an identity from text: an IPv4/IPv6 literal, "user@domain", or a name (FQDN).
         */
        static SIkev1Id fromString(std::string_view text);

        /**
         * Builds an address identity.
         */
        static SIkev1Id fromAddress(const net::SIpAddress& address, uint8_t protocol = 0, uint16_t port = 0);

        /**
         * Returns the single address of an IPV4/IPV6_ADDR identity (or the first of a
         * subnet/range), invalid otherwise.
         */
        net::SIpAddress address() const;

        /**
         * Formats the identity for logs and PSK lookup.
         */
        std::string toString() const;

        /**
         * Returns the payload body (the bytes the Phase 1 hashes cover).
         */
        std::vector<uint8_t> body() const;

        /** Compares every field. */
        inline bool operator==(const SIkev1Id& o) const noexcept {
            return type == o.type && protocol == o.protocol && port == o.port && data == o.data;
        }
    };

    /**
     * Decodes an ID payload body.
     */
    SBOX_API int32_t DecodeIkev1Id(const SReadOnlyByteSpan& body, SIkev1Id& out);

    // -- Notify, Delete

    /**
     * Notification payload contents.
     */
    struct SIkev1Notify {
        uint32_t doi = IKEV1_DOI_IPSEC;
        uint8_t protocol = EIKE1_PROTO_ISAKMP;
        uint16_t type = 0;
        std::vector<uint8_t> spi;
        std::vector<uint8_t> data;
    };

    /**
     * Decodes a Notification payload body.
     */
    SBOX_API int32_t DecodeIkev1Notify(const SReadOnlyByteSpan& body, SIkev1Notify& out);

    /**
     * Encodes a Notification payload body.
     */
    SBOX_API void EncodeIkev1Notify(const SIkev1Notify& notify, std::vector<uint8_t>& out);

    /**
     * Delete payload contents.
     */
    struct SIkev1Delete {
        uint32_t doi = IKEV1_DOI_IPSEC;
        uint8_t protocol = EIKE1_PROTO_ESP;
        uint8_t spiSize = 4;
        std::vector<std::vector<uint8_t>> spis;
    };

    /**
     * Decodes a Delete payload body.
     */
    SBOX_API int32_t DecodeIkev1Delete(const SReadOnlyByteSpan& body, SIkev1Delete& out);

    /**
     * Encodes a Delete payload body.
     */
    SBOX_API void EncodeIkev1Delete(const SIkev1Delete& del, std::vector<uint8_t>& out);

    /**
     * Encodes a NAT-OA payload body (ID type, reserved, address).
     */
    SBOX_API void EncodeIkev1NatOa(const net::SIpAddress& address, std::vector<uint8_t>& out);

    /**
     * Decodes a NAT-OA payload body.
     */
    SBOX_API int32_t DecodeIkev1NatOa(const SReadOnlyByteSpan& body, net::SIpAddress& out);

    /**
     * Returns a printable name of an exchange, payload or notify type (for logs).
     */
    SBOX_API std::string Ikev1NotifyName(uint16_t type);

}
}

#endif
