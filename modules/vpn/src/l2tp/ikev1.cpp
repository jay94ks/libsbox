#include <sbox/vpn/l2tp/ikev1.hpp>
#include "ipsec/crypto.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using ipsec::GetBe16;
    using ipsec::GetBe32;
    using ipsec::PutBe16;
    using ipsec::PutBe32;

    namespace {

        /* MD5 of a string (vendor IDs are MD5 hashes of well-known strings). */
        std::vector<uint8_t> md5Of(std::string_view text) {
            return ipsec::Hash(certpp::crypto::EHASH_MD5, BytesOf(text));
        }

        /* Vendor ID table: identifier, defining string or raw bytes. */
        struct VendorEntry {
            EIkev1Vendor which;
            const char* text;           // --> MD5 input, or nullptr when `raw` is used.
            const uint8_t* raw;
            size_t rawSize;
            size_t matchSize;           // --> Prefix compared on receipt.
        };

        const uint8_t DPD_VID[16] = { 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00 };
        const uint8_t MS_NT5_VID[20] = { 0x1e, 0x2b, 0x51, 0x69, 0x05, 0x99, 0x1c, 0x7d, 0x7c, 0x96,
                                         0xfc, 0xbf, 0xb5, 0x87, 0xe4, 0x61, 0x00, 0x00, 0x00, 0x09 };
        const uint8_t XAUTH_VID[8] = { 0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12 };

        const VendorEntry VENDORS[] = {
            { EIKE1_VID_RFC3947, "RFC 3947", nullptr, 0, 16 },
            { EIKE1_VID_NATT_DRAFT_02, "draft-ietf-ipsec-nat-t-ike-02", nullptr, 0, 16 },
            { EIKE1_VID_NATT_DRAFT_02N, "draft-ietf-ipsec-nat-t-ike-02\n", nullptr, 0, 16 },
            { EIKE1_VID_NATT_DRAFT_03, "draft-ietf-ipsec-nat-t-ike-03", nullptr, 0, 16 },
            { EIKE1_VID_DPD, nullptr, DPD_VID, sizeof(DPD_VID), 14 },
            { EIKE1_VID_MS_NT5, nullptr, MS_NT5_VID, sizeof(MS_NT5_VID), 16 },
            { EIKE1_VID_FRAGMENTATION, "FRAGMENTATION", nullptr, 0, 16 },
            { EIKE1_VID_XAUTH, nullptr, XAUTH_VID, sizeof(XAUTH_VID), 8 },
        };

        /* Returns the bytes of a table entry. */
        std::vector<uint8_t> vendorBytes(const VendorEntry& e) {
            if (e.text) {
                return md5Of(e.text);
            }

            return std::vector<uint8_t>(e.raw, e.raw + e.rawSize);
        }

        /* Checks the minimum body size of a payload type. */
        bool bodySizeOk(uint8_t type, size_t size) {
            switch (type) {
            case EIKE1_PL_SA: return size >= 8;
            case EIKE1_PL_ID: return size >= 4;
            case EIKE1_PL_NOTIFY: return size >= 8;
            case EIKE1_PL_DELETE: return size >= 8;
            case EIKE1_PL_HASH: return size >= 1;
            case EIKE1_PL_NONCE: return size >= 1;
            case EIKE1_PL_KE: return size >= 1;
            default: return true;
            }
        }

        /* Decodes the attribute list of a transform body. */
        int32_t decodeAttributes(const SReadOnlyByteSpan& data, std::vector<SIkev1Attribute>& out) {
            size_t at = 0;
            while (at < data.size) {
                if (data.size - at < 4) {
                    return -EBADMSG;
                }

                uint16_t typeField = GetBe16(data.data + at);
                SIkev1Attribute a;
                a.type = uint16_t(typeField & 0x7fff);
                if (typeField & 0x8000) {
                    a.value = GetBe16(data.data + at + 2);
                    at += 4;
                }
                else {
                    size_t length = GetBe16(data.data + at + 2);
                    if (data.size - at - 4 < length || length > 8 || length == 0) {
                        // --> Longer variable attributes exist in other DOIs only; refuse them.
                        return -EBADMSG;
                    }

                    a.variable = true;
                    for (size_t i = 0; i < length; ++i) {
                        a.value = (a.value << 8) | data.data[at + 4 + i];
                    }

                    at += 4 + length;
                }

                out.push_back(a);
            }

            return SBOX_OK;
        }

        /* Encodes one attribute. */
        void encodeAttribute(const SIkev1Attribute& a, std::vector<uint8_t>& out) {
            if (!a.variable && a.value <= 0xffff) {
                PutBe16(out, 0x8000u | a.type);
                PutBe16(out, uint32_t(a.value));
                return;
            }

            PutBe16(out, a.type & 0x7fffu);
            if (a.value > 0xffffffffull) {
                PutBe16(out, 8);
                PutBe32(out, uint32_t(a.value >> 32));
                PutBe32(out, uint32_t(a.value));
            }
            else {
                PutBe16(out, 4);
                PutBe32(out, uint32_t(a.value));
            }
        }

    }

    /* Vendor ID bytes. */
    std::vector<uint8_t> Ikev1VendorId(EIkev1Vendor which) {
        for (const VendorEntry& e : VENDORS) {
            if (e.which == which) {
                return vendorBytes(e);
            }
        }

        return {};
    }

    /* Vendor ID classification. */
    EIkev1Vendor Ikev1ClassifyVendorId(const SReadOnlyByteSpan& data) {
        for (const VendorEntry& e : VENDORS) {
            std::vector<uint8_t> bytes = vendorBytes(e);
            size_t n = e.matchSize < bytes.size() ? e.matchSize : bytes.size();
            if (data.size >= n && std::memcmp(data.data, bytes.data(), n) == 0) {
                // --> Exact-length vendor IDs must match exactly (no prefix collisions).
                if (e.text && data.size != bytes.size() && e.which != EIKE1_VID_FRAGMENTATION) {
                    continue;
                }

                return e.which;
            }
        }

        return EIKE1_VID_UNKNOWN;
    }

    /* Parses a payload chain. */
    int32_t ParseIkev1Payloads(uint8_t first, const SReadOnlyByteSpan& data, std::vector<SIkev1Payload>& out, size_t* end) {
        out.clear();
        uint8_t next = first;
        size_t at = 0;
        size_t guard = 0;
        while (next != EIKE1_PL_NONE) {
            if (++guard > 256) {
                return -EBADMSG;
            }

            if (data.size - at < 4) {
                return -EBADMSG;
            }

            uint8_t following = data.data[at];
            size_t length = GetBe16(data.data + at + 2);
            if (length < 4 || length > data.size - at) {
                return -EBADMSG;
            }

            SIkev1Payload p;
            p.type = next;
            p.offset = at;
            p.size = length;
            p.body.assign(data.data + at + 4, data.data + at + length);
            if (!bodySizeOk(p.type, p.body.size())) {
                return -EBADMSG;
            }

            out.push_back(std::move(p));
            at += length;
            next = following;
        }

        if (end) {
            *end = at;
        }

        return SBOX_OK;
    }

    /* Encodes a payload chain. */
    void EncodeIkev1Payloads(const std::vector<SIkev1Payload>& payloads, std::vector<uint8_t>& out, uint8_t& firstType) {
        firstType = payloads.empty() ? uint8_t(EIKE1_PL_NONE) : payloads[0].type;
        for (size_t i = 0; i < payloads.size(); ++i) {
            const SIkev1Payload& p = payloads[i];
            out.push_back(i + 1 < payloads.size() ? payloads[i + 1].type : uint8_t(EIKE1_PL_NONE));
            out.push_back(0);
            PutBe16(out, uint32_t(p.body.size() + 4));
            out.insert(out.end(), p.body.begin(), p.body.end());
        }
    }

    /* Finds a payload. */
    const SIkev1Payload* FindIkev1Payload(const std::vector<SIkev1Payload>& payloads, uint8_t type) noexcept {
        for (const SIkev1Payload& p : payloads) {
            if (p.type == type) {
                return &p;
            }
        }

        return nullptr;
    }

    /* Builds a payload. */
    SIkev1Payload MakeIkev1Payload(uint8_t type, std::vector<uint8_t> body) {
        SIkev1Payload p;
        p.type = type;
        p.body = std::move(body);
        return p;
    }

    /* Attribute lookup. */
    uint64_t SIkev1Transform::attr(uint16_t type, uint64_t fallback) const noexcept {
        for (const SIkev1Attribute& a : attributes) {
            if (a.type == type) {
                return a.value;
            }
        }

        return fallback;
    }

    /* Attribute presence. */
    bool SIkev1Transform::has(uint16_t type) const noexcept {
        for (const SIkev1Attribute& a : attributes) {
            if (a.type == type) {
                return true;
            }
        }

        return false;
    }

    /* Decodes an SA payload. */
    int32_t DecodeIkev1Sa(const SReadOnlyByteSpan& body, SIkev1Sa& out) {
        out = SIkev1Sa();
        if (body.size < 8) {
            return -EBADMSG;
        }

        out.doi = GetBe32(body.data);
        out.situation = GetBe32(body.data + 4);
        if (out.doi != IKEV1_DOI_IPSEC) {
            return -ENOTSUP;
        }

        if (out.situation != IKEV1_SIT_IDENTITY_ONLY) {
            return -ENOTSUP;
        }

        size_t at = 8;
        uint8_t next = EIKE1_PL_PROPOSAL;
        if (at == body.size) {
            return -EBADMSG;
        }

        while (next == EIKE1_PL_PROPOSAL) {
            if (body.size - at < 8) {
                return -EBADMSG;
            }

            const uint8_t* p = body.data + at;
            uint8_t following = p[0];
            size_t length = GetBe16(p + 2);
            if (length < 8 || length > body.size - at) {
                return -EBADMSG;
            }

            SIkev1Proposal prop;
            prop.number = p[4];
            prop.protocol = p[5];
            size_t spiSize = p[6];
            size_t count = p[7];
            if (8 + spiSize > length) {
                return -EBADMSG;
            }

            prop.spi.assign(p + 8, p + 8 + spiSize);
            size_t tat = 8 + spiSize;
            uint8_t tnext = count ? uint8_t(EIKE1_PL_TRANSFORM) : uint8_t(EIKE1_PL_NONE);
            while (tnext == EIKE1_PL_TRANSFORM) {
                if (length - tat < 8) {
                    return -EBADMSG;
                }

                const uint8_t* t = p + tat;
                uint8_t tfollow = t[0];
                size_t tlen = GetBe16(t + 2);
                if (tlen < 8 || tlen > length - tat) {
                    return -EBADMSG;
                }

                SIkev1Transform tr;
                tr.number = t[4];
                tr.id = t[5];
                int32_t r = decodeAttributes(SReadOnlyByteSpan(t + 8, tlen - 8), tr.attributes);
                if (r != SBOX_OK) {
                    return r;
                }

                prop.transforms.push_back(std::move(tr));
                if (prop.transforms.size() > 255) {
                    return -EBADMSG;
                }

                tat += tlen;
                tnext = tfollow;
            }

            if (tnext != EIKE1_PL_NONE || prop.transforms.size() != count) {
                return -EBADMSG;
            }

            out.proposals.push_back(std::move(prop));
            if (out.proposals.size() > 64) {
                return -EBADMSG;
            }

            at += length;
            next = following;
        }

        if (next != EIKE1_PL_NONE) {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

    /* Encodes an SA payload. */
    void EncodeIkev1Sa(const SIkev1Sa& sa, std::vector<uint8_t>& out) {
        PutBe32(out, sa.doi);
        PutBe32(out, sa.situation);
        for (size_t i = 0; i < sa.proposals.size(); ++i) {
            const SIkev1Proposal& prop = sa.proposals[i];
            size_t start = out.size();
            out.push_back(i + 1 < sa.proposals.size() ? uint8_t(EIKE1_PL_PROPOSAL) : uint8_t(EIKE1_PL_NONE));
            out.push_back(0);
            PutBe16(out, 0);
            out.push_back(prop.number);
            out.push_back(prop.protocol);
            out.push_back(uint8_t(prop.spi.size()));
            out.push_back(uint8_t(prop.transforms.size()));
            out.insert(out.end(), prop.spi.begin(), prop.spi.end());
            for (size_t j = 0; j < prop.transforms.size(); ++j) {
                const SIkev1Transform& t = prop.transforms[j];
                size_t tstart = out.size();
                out.push_back(j + 1 < prop.transforms.size() ? uint8_t(EIKE1_PL_TRANSFORM) : uint8_t(EIKE1_PL_NONE));
                out.push_back(0);
                PutBe16(out, 0);
                out.push_back(t.number);
                out.push_back(t.id);
                PutBe16(out, 0);
                for (const SIkev1Attribute& a : t.attributes) {
                    encodeAttribute(a, out);
                }

                ipsec::SetBe16(out.data() + tstart + 2, uint32_t(out.size() - tstart));
            }

            ipsec::SetBe16(out.data() + start + 2, uint32_t(out.size() - start));
        }
    }

    /* Identity from text. */
    SIkev1Id SIkev1Id::fromString(std::string_view text) {
        net::SIpAddress a;
        if (net::SIpAddress::parse(text, a) == SBOX_OK) {
            return fromAddress(a);
        }

        SIkev1Id id;
        id.type = text.find('@') != std::string_view::npos && text.front() != '@' ? EIKE1_ID_USER_FQDN : EIKE1_ID_FQDN;
        // --> A leading '@' (strongSwan convention) forces an FQDN and is not sent.
        if (!text.empty() && text.front() == '@') {
            text.remove_prefix(1);
        }

        id.data.assign(text.begin(), text.end());
        return id;
    }

    /* Identity from an address. */
    SIkev1Id SIkev1Id::fromAddress(const net::SIpAddress& address, uint8_t protocol, uint16_t port) {
        SIkev1Id id;
        id.type = address.isV6() ? EIKE1_ID_IPV6_ADDR : EIKE1_ID_IPV4_ADDR;
        id.protocol = protocol;
        id.port = port;
        id.data.assign(address.bytes, address.bytes + address.length());
        return id;
    }

    /* Address of an identity. */
    net::SIpAddress SIkev1Id::address() const {
        net::SIpAddress a;
        switch (type) {
        case EIKE1_ID_IPV4_ADDR:
        case EIKE1_ID_IPV4_ADDR_SUBNET:
        case EIKE1_ID_IPV4_ADDR_RANGE:
            if (data.size() >= 4) {
                net::SIpAddress::fromBytes(data.data(), 4, a);
            }

            break;

        case EIKE1_ID_IPV6_ADDR:
        case EIKE1_ID_IPV6_ADDR_SUBNET:
        case EIKE1_ID_IPV6_ADDR_RANGE:
            if (data.size() >= 16) {
                net::SIpAddress::fromBytes(data.data(), 16, a);
            }

            break;

        default:
            break;
        }

        return a;
    }

    /* Printable identity. */
    std::string SIkev1Id::toString() const {
        std::string text;
        switch (type) {
        case EIKE1_ID_IPV4_ADDR:
        case EIKE1_ID_IPV6_ADDR: {
            net::SIpAddress a = address();
            text = a.isValid() ? a.toString() : std::string("?");
            break;
        }

        case EIKE1_ID_IPV4_ADDR_SUBNET:
        case EIKE1_ID_IPV6_ADDR_SUBNET: {
            size_t half = data.size() / 2;
            net::SIpAddress a;
            net::SIpAddress m;
            net::SIpAddress::fromBytes(data.data(), half, a);
            net::SIpAddress::fromBytes(data.data() + half, half, m);
            uint32_t bits = 0;
            for (size_t i = half; i < data.size(); ++i) {
                bits += uint32_t(__builtin_popcount(data[i]));
            }

            text = a.toString() + "/" + std::to_string(bits);
            break;
        }

        case EIKE1_ID_FQDN:
        case EIKE1_ID_USER_FQDN:
            for (uint8_t c : data) {
                text.push_back(c >= 0x20 && c < 0x7f ? char(c) : '?');
            }

            break;

        default:
            text = "type" + std::to_string(type) + ":" + ipsec::ToHex(BytesOf(data));
            break;
        }

        if (protocol || port) {
            text += "[" + std::to_string(protocol) + "/" + std::to_string(port) + "]";
        }

        return text;
    }

    /* ID payload body. */
    std::vector<uint8_t> SIkev1Id::body() const {
        std::vector<uint8_t> out;
        out.push_back(type);
        out.push_back(protocol);
        PutBe16(out, port);
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

    /* Decodes an ID payload. */
    int32_t DecodeIkev1Id(const SReadOnlyByteSpan& body, SIkev1Id& out) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        out = SIkev1Id();
        out.type = body[0];
        out.protocol = body[1];
        out.port = GetBe16(body.data + 2);
        out.data.assign(body.data + 4, body.data + body.size);
        switch (out.type) {
        case EIKE1_ID_IPV4_ADDR:
            return out.data.size() == 4 ? SBOX_OK : -EBADMSG;
        case EIKE1_ID_IPV6_ADDR:
            return out.data.size() == 16 ? SBOX_OK : -EBADMSG;
        case EIKE1_ID_IPV4_ADDR_SUBNET:
        case EIKE1_ID_IPV4_ADDR_RANGE:
            return out.data.size() == 8 ? SBOX_OK : -EBADMSG;
        case EIKE1_ID_IPV6_ADDR_SUBNET:
        case EIKE1_ID_IPV6_ADDR_RANGE:
            return out.data.size() == 32 ? SBOX_OK : -EBADMSG;
        default:
            return SBOX_OK;
        }
    }

    /* Decodes a notification. */
    int32_t DecodeIkev1Notify(const SReadOnlyByteSpan& body, SIkev1Notify& out) {
        if (body.size < 8) {
            return -EBADMSG;
        }

        out = SIkev1Notify();
        out.doi = GetBe32(body.data);
        out.protocol = body[4];
        size_t spiSize = body[5];
        out.type = GetBe16(body.data + 6);
        if (8 + spiSize > body.size) {
            return -EBADMSG;
        }

        out.spi.assign(body.data + 8, body.data + 8 + spiSize);
        out.data.assign(body.data + 8 + spiSize, body.data + body.size);
        return SBOX_OK;
    }

    /* Encodes a notification. */
    void EncodeIkev1Notify(const SIkev1Notify& notify, std::vector<uint8_t>& out) {
        PutBe32(out, notify.doi);
        out.push_back(notify.protocol);
        out.push_back(uint8_t(notify.spi.size()));
        PutBe16(out, notify.type);
        out.insert(out.end(), notify.spi.begin(), notify.spi.end());
        out.insert(out.end(), notify.data.begin(), notify.data.end());
    }

    /* Decodes a delete payload. */
    int32_t DecodeIkev1Delete(const SReadOnlyByteSpan& body, SIkev1Delete& out) {
        if (body.size < 8) {
            return -EBADMSG;
        }

        out = SIkev1Delete();
        out.doi = GetBe32(body.data);
        out.protocol = body[4];
        out.spiSize = body[5];
        size_t count = GetBe16(body.data + 6);
        if (out.spiSize == 0 || out.spiSize > 16 || body.size != 8 + count * out.spiSize) {
            return -EBADMSG;
        }

        for (size_t i = 0; i < count; ++i) {
            const uint8_t* p = body.data + 8 + i * out.spiSize;
            out.spis.emplace_back(p, p + out.spiSize);
        }

        return SBOX_OK;
    }

    /* Encodes a delete payload. */
    void EncodeIkev1Delete(const SIkev1Delete& del, std::vector<uint8_t>& out) {
        PutBe32(out, del.doi);
        out.push_back(del.protocol);
        out.push_back(del.spiSize);
        PutBe16(out, uint32_t(del.spis.size()));
        for (const std::vector<uint8_t>& spi : del.spis) {
            out.insert(out.end(), spi.begin(), spi.end());
        }
    }

    /* Encodes NAT-OA. */
    void EncodeIkev1NatOa(const net::SIpAddress& address, std::vector<uint8_t>& out) {
        out.push_back(address.isV6() ? uint8_t(EIKE1_ID_IPV6_ADDR) : uint8_t(EIKE1_ID_IPV4_ADDR));
        out.push_back(0);
        PutBe16(out, 0);
        out.insert(out.end(), address.bytes, address.bytes + address.length());
    }

    /* Decodes NAT-OA. */
    int32_t DecodeIkev1NatOa(const SReadOnlyByteSpan& body, net::SIpAddress& out) {
        if (body.size == 8 && body[0] == EIKE1_ID_IPV4_ADDR) {
            return net::SIpAddress::fromBytes(body.data + 4, 4, out);
        }

        if (body.size == 20 && body[0] == EIKE1_ID_IPV6_ADDR) {
            return net::SIpAddress::fromBytes(body.data + 4, 16, out);
        }

        return -EBADMSG;
    }

    /* Notify names. */
    std::string Ikev1NotifyName(uint16_t type) {
        switch (type) {
        case EIKE1_N_INVALID_PAYLOAD_TYPE: return "INVALID-PAYLOAD-TYPE";
        case EIKE1_N_INVALID_COOKIE: return "INVALID-COOKIE";
        case EIKE1_N_INVALID_EXCHANGE_TYPE: return "INVALID-EXCHANGE-TYPE";
        case EIKE1_N_INVALID_MESSAGE_ID: return "INVALID-MESSAGE-ID";
        case EIKE1_N_INVALID_SPI: return "INVALID-SPI";
        case EIKE1_N_NO_PROPOSAL_CHOSEN: return "NO-PROPOSAL-CHOSEN";
        case EIKE1_N_PAYLOAD_MALFORMED: return "PAYLOAD-MALFORMED";
        case EIKE1_N_INVALID_KEY_INFORMATION: return "INVALID-KEY-INFORMATION";
        case EIKE1_N_INVALID_ID_INFORMATION: return "INVALID-ID-INFORMATION";
        case EIKE1_N_INVALID_HASH_INFORMATION: return "INVALID-HASH-INFORMATION";
        case EIKE1_N_AUTHENTICATION_FAILED: return "AUTHENTICATION-FAILED";
        case EIKE1_N_RESPONDER_LIFETIME: return "RESPONDER-LIFETIME";
        case EIKE1_N_INITIAL_CONTACT: return "INITIAL-CONTACT";
        case EIKE1_N_R_U_THERE: return "R-U-THERE";
        case EIKE1_N_R_U_THERE_ACK: return "R-U-THERE-ACK";
        default: return "NOTIFY-" + std::to_string(type);
        }
    }

}
}
