#ifndef __INCLUDE_SBOX_VPN_IPSEC_IKEMESSAGE_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_IKEMESSAGE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/address.hpp>
#include <string>
#include <vector>

// --> IKEv2 wire format (RFC 7296 section 3): the fixed header, the generic payload chain and
// typed encoders/decoders for every payload the responder and initiator use. Decoders never
// trust lengths: anything inconsistent is -EBADMSG. The header layout is shared with ISAKMP
// (IKEv1), so the header helpers are usable by an IKEv1 implementation as well.

namespace sbox {
namespace vpn {

    /**
     * Exchange types (RFC 7296 3.1).
     */
    enum EIkeExchange : uint8_t {
        EIKE_X_SA_INIT = 34,
        EIKE_X_AUTH = 35,
        EIKE_X_CREATE_CHILD_SA = 36,
        EIKE_X_INFORMATIONAL = 37,
    };

    /**
     * Header flags.
     */
    enum EIkeFlags : uint8_t {
        EIKE_F_INITIATOR = 0x08,    // --> Sent by the original initiator of the IKE SA.
        EIKE_F_VERSION = 0x10,      // --> Can speak a higher major version (never set).
        EIKE_F_RESPONSE = 0x20,     // --> The message is a response.
    };

    /**
     * Payload types (RFC 7296 3.2, RFC 7383).
     */
    enum EIkePayloadType : uint8_t {
        EIKE_PL_NONE = 0,
        EIKE_PL_SA = 33,
        EIKE_PL_KE = 34,
        EIKE_PL_IDI = 35,
        EIKE_PL_IDR = 36,
        EIKE_PL_CERT = 37,
        EIKE_PL_CERTREQ = 38,
        EIKE_PL_AUTH = 39,
        EIKE_PL_NONCE = 40,
        EIKE_PL_NOTIFY = 41,
        EIKE_PL_DELETE = 42,
        EIKE_PL_VENDOR = 43,
        EIKE_PL_TSI = 44,
        EIKE_PL_TSR = 45,
        EIKE_PL_SK = 46,
        EIKE_PL_CP = 47,
        EIKE_PL_EAP = 48,
        EIKE_PL_SKF = 53,
    };

    /**
     * Security protocol identifiers (proposals, notify, delete).
     */
    enum EIkeProtocol : uint8_t {
        EIKE_PROTO_NONE = 0,
        EIKE_PROTO_IKE = 1,
        EIKE_PROTO_AH = 2,
        EIKE_PROTO_ESP = 3,
    };

    /**
     * Notify message types (RFC 7296 3.10.1 and extensions).
     */
    enum EIkeNotifyType : uint16_t {
        EIKE_N_UNSUPPORTED_CRITICAL_PAYLOAD = 1,
        EIKE_N_INVALID_IKE_SPI = 4,
        EIKE_N_INVALID_MAJOR_VERSION = 5,
        EIKE_N_INVALID_SYNTAX = 7,
        EIKE_N_INVALID_MESSAGE_ID = 9,
        EIKE_N_INVALID_SPI = 11,
        EIKE_N_NO_PROPOSAL_CHOSEN = 14,
        EIKE_N_INVALID_KE_PAYLOAD = 17,
        EIKE_N_AUTHENTICATION_FAILED = 24,
        EIKE_N_SINGLE_PAIR_REQUIRED = 34,
        EIKE_N_NO_ADDITIONAL_SAS = 35,
        EIKE_N_INTERNAL_ADDRESS_FAILURE = 36,
        EIKE_N_FAILED_CP_REQUIRED = 37,
        EIKE_N_TS_UNACCEPTABLE = 38,
        EIKE_N_INVALID_SELECTORS = 39,
        EIKE_N_TEMPORARY_FAILURE = 43,
        EIKE_N_CHILD_SA_NOT_FOUND = 44,
        // --
        EIKE_N_INITIAL_CONTACT = 16384,
        EIKE_N_SET_WINDOW_SIZE = 16385,
        EIKE_N_ADDITIONAL_TS_POSSIBLE = 16386,
        EIKE_N_IPCOMP_SUPPORTED = 16387,
        EIKE_N_NAT_DETECTION_SOURCE_IP = 16388,
        EIKE_N_NAT_DETECTION_DESTINATION_IP = 16389,
        EIKE_N_COOKIE = 16390,
        EIKE_N_USE_TRANSPORT_MODE = 16391,
        EIKE_N_HTTP_CERT_LOOKUP_SUPPORTED = 16392,
        EIKE_N_REKEY_SA = 16393,
        EIKE_N_ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
        EIKE_N_NON_FIRST_FRAGMENTS_ALSO = 16395,
        EIKE_N_MOBIKE_SUPPORTED = 16396,
        EIKE_N_ADDITIONAL_IP4_ADDRESS = 16397,
        EIKE_N_ADDITIONAL_IP6_ADDRESS = 16398,
        EIKE_N_NO_ADDITIONAL_ADDRESSES = 16399,
        EIKE_N_UPDATE_SA_ADDRESSES = 16400,
        EIKE_N_COOKIE2 = 16401,
        EIKE_N_NO_NATS_ALLOWED = 16402,
        EIKE_N_MULTIPLE_AUTH_SUPPORTED = 16404,
        EIKE_N_REDIRECT_SUPPORTED = 16406,
        EIKE_N_EAP_ONLY_AUTHENTICATION = 16417,
        EIKE_N_IKEV2_FRAGMENTATION_SUPPORTED = 16430,
        EIKE_N_SIGNATURE_HASH_ALGORITHMS = 16431,
    };

    /**
     * Identification types (RFC 7296 3.5).
     */
    enum EIkeIdType : uint8_t {
        EIKE_ID_IPV4_ADDR = 1,
        EIKE_ID_FQDN = 2,
        EIKE_ID_RFC822_ADDR = 3,
        EIKE_ID_IPV6_ADDR = 5,
        EIKE_ID_DER_ASN1_DN = 9,
        EIKE_ID_DER_ASN1_GN = 10,
        EIKE_ID_KEY_ID = 11,
    };

    /**
     * Authentication methods (RFC 7296 3.8, RFC 4754, RFC 7427).
     */
    enum EIkeAuthMethod : uint8_t {
        EIKE_AUTH_RSA_SIG = 1,          // --> RSASSA-PKCS1-v1_5 with SHA-1.
        EIKE_AUTH_PSK = 2,
        EIKE_AUTH_DSS = 3,
        EIKE_AUTH_ECDSA_256 = 9,        // --> ECDSA P-256 with SHA-256, raw r || s.
        EIKE_AUTH_ECDSA_384 = 10,
        EIKE_AUTH_ECDSA_521 = 11,
        EIKE_AUTH_DIGITAL_SIGNATURE = 14,   // --> RFC 7427: AlgorithmIdentifier + signature.
    };

    /**
     * Certificate encodings (RFC 7296 3.6).
     */
    enum EIkeCertEncoding : uint8_t {
        EIKE_CERT_X509_SIGNATURE = 4,
    };

    /**
     * Traffic selector types (RFC 7296 3.13.1).
     */
    enum EIkeTsType : uint8_t {
        EIKE_TS_IPV4_ADDR_RANGE = 7,
        EIKE_TS_IPV6_ADDR_RANGE = 8,
    };

    /**
     * Configuration payload types (RFC 7296 3.15).
     */
    enum EIkeCfgType : uint8_t {
        EIKE_CFG_REQUEST = 1,
        EIKE_CFG_REPLY = 2,
        EIKE_CFG_SET = 3,
        EIKE_CFG_ACK = 4,
    };

    /**
     * Configuration attribute types (RFC 7296 3.15.1, RFC 8598).
     */
    enum EIkeCfgAttr : uint16_t {
        EIKE_CA_INTERNAL_IP4_ADDRESS = 1,
        EIKE_CA_INTERNAL_IP4_NETMASK = 2,
        EIKE_CA_INTERNAL_IP4_DNS = 3,
        EIKE_CA_INTERNAL_IP4_NBNS = 4,
        EIKE_CA_INTERNAL_IP4_DHCP = 6,
        EIKE_CA_APPLICATION_VERSION = 7,
        EIKE_CA_INTERNAL_IP6_ADDRESS = 8,
        EIKE_CA_INTERNAL_IP6_DNS = 10,
        EIKE_CA_INTERNAL_IP4_SUBNET = 13,
        EIKE_CA_SUPPORTED_ATTRIBUTES = 14,
        EIKE_CA_INTERNAL_IP6_SUBNET = 15,
        EIKE_CA_INTERNAL_DNS_DOMAIN = 25,
    };

    /**
     * Transform attribute: KEY_LENGTH (RFC 7296 3.3.5).
     */
    constexpr uint16_t IKE_ATTR_KEY_LENGTH = 14;

    /** Size of the fixed IKE header. */
    constexpr size_t IKE_HEADER_SIZE = 28;

    /** Size of a generic payload header. */
    constexpr size_t IKE_PAYLOAD_HEADER_SIZE = 4;

    /**
     * Fixed IKE header.
     */
    struct SBOX_API SIkeHeader {
        uint64_t spiI = 0;
        uint64_t spiR = 0;
        uint8_t nextPayload = 0;
        uint8_t version = 0x20;     // --> Major 2, minor 0.
        uint8_t exchange = 0;
        uint8_t flags = 0;
        uint32_t messageId = 0;
        uint32_t length = 0;

        /**
         * Parses the header of `data` (checks the length field against the datagram).
         * @return SBOX_OK or -EBADMSG.
         */
        static int32_t parse(const SReadOnlyByteSpan& data, SIkeHeader& out) noexcept;

        /**
         * Appends the 28-byte encoding.
         */
        void encode(std::vector<uint8_t>& out) const;

        /** Returns true for a response. */
        inline bool isResponse() const noexcept { return (flags & EIKE_F_RESPONSE) != 0; }

        /** Returns true when sent by the original initiator. */
        inline bool fromInitiator() const noexcept { return (flags & EIKE_F_INITIATOR) != 0; }
    };

    /**
     * One payload of a chain (type and raw body, without the generic header).
     */
    struct SIkePayload {
        uint8_t type = 0;
        bool critical = false;
        uint8_t next = 0;               // --> Raw next-payload field (the inner type of SK/SKF).
        std::vector<uint8_t> body;
    };

    /**
     * Parses a payload chain starting with payload type `first`. Parsing stops after an SK/SKF
     * payload (its body runs to the end of the message).
     * @return SBOX_OK or -EBADMSG.
     */
    SBOX_API int32_t ParseIkePayloads(uint8_t first, const SReadOnlyByteSpan& data, std::vector<SIkePayload>& out);

    /**
     * Encodes a payload chain (generic headers with next-payload chaining).
     * @param firstType Receives the type of the first payload (EIKE_PL_NONE when empty).
     */
    SBOX_API void EncodeIkePayloads(const std::vector<SIkePayload>& payloads, std::vector<uint8_t>& out, uint8_t& firstType);

    /**
     * Returns the first payload of `type` or nullptr.
     */
    SBOX_API const SIkePayload* FindIkePayload(const std::vector<SIkePayload>& payloads, uint8_t type) noexcept;

    /**
     * Returns true when the payload type is one RFC 7296 / RFC 7383 defines.
     */
    SBOX_API bool IsKnownIkePayload(uint8_t type) noexcept;

    // -- Security Association payload

    /**
     * One transform of a proposal.
     */
    struct SIkeTransform {
        uint8_t type = 0;
        uint16_t id = 0;
        uint16_t keyLength = 0;     // --> KEY_LENGTH attribute in bits, 0 when absent.

        /** Compares all fields. */
        inline bool operator==(const SIkeTransform& o) const noexcept {
            return type == o.type && id == o.id && keyLength == o.keyLength;
        }
    };

    /**
     * One proposal of an SA payload.
     */
    struct SBOX_API SIkeProposal {
        uint8_t number = 1;
        uint8_t protocol = EIKE_PROTO_IKE;
        std::vector<uint8_t> spi;
        std::vector<SIkeTransform> transforms;

        /**
         * Returns the transforms of one type.
         */
        std::vector<SIkeTransform> ofType(uint8_t type) const;

        /**
         * Returns the first transform of `type`, or a zero transform when absent.
         */
        SIkeTransform first(uint8_t type) const noexcept;

        /**
         * Formats the proposal as "AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024".
         */
        std::string toString() const;
    };

    /**
     * Decodes an SA payload body.
     * @return SBOX_OK or -EBADMSG.
     */
    SBOX_API int32_t DecodeIkeSa(const SReadOnlyByteSpan& body, std::vector<SIkeProposal>& out);

    /**
     * Encodes an SA payload body.
     */
    SBOX_API void EncodeIkeSa(const std::vector<SIkeProposal>& proposals, std::vector<uint8_t>& out);

    // -- Key Exchange

    /**
     * Decodes a KE payload body.
     */
    SBOX_API int32_t DecodeIkeKe(const SReadOnlyByteSpan& body, uint16_t& group, std::vector<uint8_t>& data);

    /**
     * Encodes a KE payload body.
     */
    SBOX_API void EncodeIkeKe(uint16_t group, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out);

    // -- Identification

    /**
     * Identification payload contents.
     */
    struct SBOX_API SIkeId {
        uint8_t type = EIKE_ID_FQDN;
        std::vector<uint8_t> data;

        /**
         * Builds an identity from text: an IPv4/IPv6 literal, "user@domain" (RFC822), a
         * distinguished name containing '=' (DER encoded through libcertpp), "keyid:<hex>",
         * or anything else as FQDN.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromString(std::string_view text, SIkeId& out);

        /**
         * Formats the identity for logs and lookups (DNs through libcertpp).
         */
        std::string toString() const;

        /**
         * Returns the payload body (type, three reserved octets, data); this is also the
         * "RestOfIDPayload" the AUTH computation MACs.
         */
        std::vector<uint8_t> body() const;

        /** Compares type and data. */
        inline bool operator==(const SIkeId& o) const noexcept { return type == o.type && data == o.data; }
    };

    /**
     * Decodes an IDi/IDr payload body.
     */
    SBOX_API int32_t DecodeIkeId(const SReadOnlyByteSpan& body, SIkeId& out);

    // -- Certificate, certificate request, authentication

    /**
     * Decodes a CERT or CERTREQ body into encoding and data.
     */
    SBOX_API int32_t DecodeIkeCert(const SReadOnlyByteSpan& body, uint8_t& encoding, std::vector<uint8_t>& data);

    /**
     * Encodes a CERT or CERTREQ body.
     */
    SBOX_API void EncodeIkeCert(uint8_t encoding, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out);

    /**
     * Decodes an AUTH payload body.
     */
    SBOX_API int32_t DecodeIkeAuth(const SReadOnlyByteSpan& body, uint8_t& method, std::vector<uint8_t>& data);

    /**
     * Encodes an AUTH payload body.
     */
    SBOX_API void EncodeIkeAuth(uint8_t method, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out);

    // -- Notify, Delete

    /**
     * Notify payload contents.
     */
    struct SIkeNotify {
        uint8_t protocol = EIKE_PROTO_NONE;
        std::vector<uint8_t> spi;
        uint16_t type = 0;
        std::vector<uint8_t> data;
    };

    /**
     * Decodes a Notify payload body.
     */
    SBOX_API int32_t DecodeIkeNotify(const SReadOnlyByteSpan& body, SIkeNotify& out);

    /**
     * Encodes a Notify payload body.
     */
    SBOX_API void EncodeIkeNotify(const SIkeNotify& notify, std::vector<uint8_t>& out);

    /**
     * Builds a Notify payload of `type` with optional data and no SPI.
     */
    SBOX_API SIkePayload MakeIkeNotify(uint16_t type, const SReadOnlyByteSpan& data = SReadOnlyByteSpan());

    /**
     * Delete payload contents.
     */
    struct SIkeDelete {
        uint8_t protocol = EIKE_PROTO_IKE;
        std::vector<uint32_t> spis;     // --> ESP/AH SPIs (host order); empty for IKE.
    };

    /**
     * Decodes a Delete payload body.
     */
    SBOX_API int32_t DecodeIkeDelete(const SReadOnlyByteSpan& body, SIkeDelete& out);

    /**
     * Encodes a Delete payload body.
     */
    SBOX_API void EncodeIkeDelete(const SIkeDelete& del, std::vector<uint8_t>& out);

    // -- Traffic selectors

    /**
     * One traffic selector (an address range, a protocol and a port range).
     */
    struct SBOX_API SIkeTrafficSelector {
        uint8_t type = EIKE_TS_IPV4_ADDR_RANGE;
        uint8_t protocol = 0;           // --> 0 means any.
        uint16_t startPort = 0;
        uint16_t endPort = 65535;
        net::SIpAddress start;
        net::SIpAddress end;

        /**
         * Builds a selector covering a prefix, any protocol and port.
         */
        static SIkeTrafficSelector fromPrefix(const net::SIpPrefix& prefix);

        /**
         * Returns a selector covering everything of one family (0.0.0.0/0 or ::/0).
         */
        static SIkeTrafficSelector any(bool ipv6);

        /**
         * Computes the intersection of two selectors.
         * @return true when they overlap (`out` receives the intersection).
         */
        static bool intersect(const SIkeTrafficSelector& a, const SIkeTrafficSelector& b, SIkeTrafficSelector& out);

        /**
         * Returns true when `addr` is inside the address range.
         */
        bool containsAddress(const net::SIpAddress& addr) const noexcept;

        /**
         * Returns the selector as a prefix when the range is exactly one prefix.
         * @return true on success.
         */
        bool toPrefix(net::SIpPrefix& out) const noexcept;

        /**
         * Splits the address range into the minimal list of prefixes covering it.
         */
        std::vector<net::SIpPrefix> toPrefixes() const;

        /**
         * Formats "10.0.0.0/24[udp/500]" or "10.0.0.1-10.0.0.9".
         */
        std::string toString() const;

        /** Compares all fields. */
        bool operator==(const SIkeTrafficSelector& o) const noexcept;
    };

    /**
     * Decodes a TSi/TSr payload body (unknown selector types are skipped).
     */
    SBOX_API int32_t DecodeIkeTs(const SReadOnlyByteSpan& body, std::vector<SIkeTrafficSelector>& out);

    /**
     * Encodes a TSi/TSr payload body.
     */
    SBOX_API void EncodeIkeTs(const std::vector<SIkeTrafficSelector>& selectors, std::vector<uint8_t>& out);

    // -- Configuration

    /**
     * One configuration attribute.
     */
    struct SIkeCfgAttribute {
        uint16_t type = 0;
        std::vector<uint8_t> value;
    };

    /**
     * Configuration payload contents.
     */
    struct SIkeConfig {
        uint8_t cfgType = EIKE_CFG_REQUEST;
        std::vector<SIkeCfgAttribute> attributes;
    };

    /**
     * Decodes a CP payload body.
     */
    SBOX_API int32_t DecodeIkeConfig(const SReadOnlyByteSpan& body, SIkeConfig& out);

    /**
     * Encodes a CP payload body.
     */
    SBOX_API void EncodeIkeConfig(const SIkeConfig& config, std::vector<uint8_t>& out);

    // -- Encrypted fragment header

    /**
     * Reads the Fragment Number and Total Fragments of an SKF payload body.
     */
    SBOX_API int32_t DecodeIkeFragmentHeader(const SReadOnlyByteSpan& body, uint16_t& number, uint16_t& total);

}
}

#endif
