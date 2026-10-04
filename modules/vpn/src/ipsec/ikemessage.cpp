#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "crypto.hpp"
#include "der.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace ipsec;

    namespace {

        __extension__ typedef unsigned __int128 U128;

        /* Address bytes as a 128-bit number (IPv4 in the low 32 bits). */
        U128 toNumber(const net::SIpAddress& a) {
            U128 v = 0;
            for (size_t i = 0; i < a.length(); ++i) {
                v = (v << 8) | a.bytes[i];
            }

            return v;
        }

        /* 128-bit number back to an address of `family`. */
        net::SIpAddress fromNumber(U128 v, uint8_t family) {
            net::SIpAddress a;
            a.family = family;
            size_t n = family == 4 ? 4 : 16;
            for (size_t i = 0; i < n; ++i) {
                a.bytes[n - 1 - i] = uint8_t(v & 0xff);
                v >>= 8;
            }

            return a;
        }

        /* Returns true for a valid, known payload type. */
        bool knownType(uint8_t t) {
            return (t >= EIKE_PL_SA && t <= EIKE_PL_EAP) || t == EIKE_PL_SKF;
        }

    }

    /* Parses the fixed header. */
    int32_t SIkeHeader::parse(const SReadOnlyByteSpan& data, SIkeHeader& out) noexcept {
        if (data.size < IKE_HEADER_SIZE) {
            return -EBADMSG;
        }

        const uint8_t* p = data.data;
        out.spiI = GetBe64(p);
        out.spiR = GetBe64(p + 8);
        out.nextPayload = p[16];
        out.version = p[17];
        out.exchange = p[18];
        out.flags = p[19];
        out.messageId = GetBe32(p + 20);
        out.length = GetBe32(p + 24);

        if (out.length < IKE_HEADER_SIZE || out.length > data.size) {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

    /* Encodes the fixed header. */
    void SIkeHeader::encode(std::vector<uint8_t>& out) const {
        PutBe64(out, spiI);
        PutBe64(out, spiR);
        out.push_back(nextPayload);
        out.push_back(version);
        out.push_back(exchange);
        out.push_back(flags);
        PutBe32(out, messageId);
        PutBe32(out, length);
    }

    /* Known payload types. */
    bool IsKnownIkePayload(uint8_t type) noexcept {
        return knownType(type);
    }

    /* Parses a payload chain. */
    int32_t ParseIkePayloads(uint8_t first, const SReadOnlyByteSpan& data, std::vector<SIkePayload>& out) {
        out.clear();
        uint8_t type = first;
        size_t at = 0;

        while (type != EIKE_PL_NONE) {
            if (data.size - at < IKE_PAYLOAD_HEADER_SIZE) {
                return -EBADMSG;
            }

            const uint8_t* p = data.data + at;
            uint8_t next = p[0];
            size_t length = GetBe16(p + 2);
            if (length < IKE_PAYLOAD_HEADER_SIZE || length > data.size - at) {
                return -EBADMSG;
            }

            SIkePayload pl;
            pl.type = type;
            pl.critical = (p[1] & 0x80) != 0;
            pl.next = next;
            pl.body.assign(p + IKE_PAYLOAD_HEADER_SIZE, p + length);
            out.push_back(std::move(pl));
            at += length;

            // --> The Encrypted payload is always last; its "next" names the first inner payload.
            if (type == EIKE_PL_SK || type == EIKE_PL_SKF) {
                return SBOX_OK;
            }

            type = next;

            // --> A sane bound on payload count keeps malicious chains cheap.
            if (out.size() > 256) {
                return -EBADMSG;
            }
        }

        return SBOX_OK;
    }

    /* Encodes a payload chain. */
    void EncodeIkePayloads(const std::vector<SIkePayload>& payloads, std::vector<uint8_t>& out, uint8_t& firstType) {
        firstType = payloads.empty() ? uint8_t(EIKE_PL_NONE) : payloads[0].type;
        for (size_t i = 0; i < payloads.size(); ++i) {
            const SIkePayload& pl = payloads[i];
            uint8_t next = i + 1 < payloads.size() ? payloads[i + 1].type : pl.next;
            out.push_back(next);
            out.push_back(pl.critical ? 0x80 : 0x00);
            PutBe16(out, uint32_t(pl.body.size() + IKE_PAYLOAD_HEADER_SIZE));
            Append(out, BytesOf(pl.body));
        }
    }

    /* Finds a payload. */
    const SIkePayload* FindIkePayload(const std::vector<SIkePayload>& payloads, uint8_t type) noexcept {
        for (const SIkePayload& pl : payloads) {
            if (pl.type == type) {
                return &pl;
            }
        }

        return nullptr;
    }

    // ---------------------------------------------------------------------------------------

    /* Transforms of one type. */
    std::vector<SIkeTransform> SIkeProposal::ofType(uint8_t type) const {
        std::vector<SIkeTransform> out;
        for (const SIkeTransform& t : transforms) {
            if (t.type == type) {
                out.push_back(t);
            }
        }

        return out;
    }

    /* First transform of a type. */
    SIkeTransform SIkeProposal::first(uint8_t type) const noexcept {
        for (const SIkeTransform& t : transforms) {
            if (t.type == type) {
                return t;
            }
        }

        SIkeTransform none;
        none.type = type;
        return none;
    }

    /* Formats a proposal. */
    std::string SIkeProposal::toString() const {
        std::string out;
        for (const SIkeTransform& t : transforms) {
            if (!out.empty()) {
                out += '/';
            }

            out += IkeTransformName(t.type, t.id);
            if (t.keyLength) {
                out += '_';
                out += std::to_string(t.keyLength);
            }
        }

        return out;
    }

    /* Decodes an SA payload. */
    int32_t DecodeIkeSa(const SReadOnlyByteSpan& body, std::vector<SIkeProposal>& out) {
        out.clear();
        size_t at = 0;
        bool last = false;

        while (!last) {
            if (body.size - at < 8) {
                return -EBADMSG;
            }

            const uint8_t* p = body.data + at;
            if (p[0] != 0 && p[0] != 2) {
                return -EBADMSG;
            }

            last = p[0] == 0;
            size_t length = GetBe16(p + 2);
            if (length < 8 || length > body.size - at) {
                return -EBADMSG;
            }

            SIkeProposal prop;
            prop.number = p[4];
            prop.protocol = p[5];
            size_t spiSize = p[6];
            size_t count = p[7];
            if (8 + spiSize > length) {
                return -EBADMSG;
            }

            prop.spi.assign(p + 8, p + 8 + spiSize);

            size_t t = 8 + spiSize;
            for (size_t i = 0; i < count; ++i) {
                if (length - t < 8) {
                    return -EBADMSG;
                }

                const uint8_t* q = p + t;
                size_t tlen = GetBe16(q + 2);
                if (tlen < 8 || tlen > length - t || (q[0] != 0 && q[0] != 3)) {
                    return -EBADMSG;
                }

                if ((q[0] == 0) != (i + 1 == count)) {
                    return -EBADMSG;
                }

                SIkeTransform tr;
                tr.type = q[4];
                tr.id = GetBe16(q + 6);

                size_t a = 8;
                while (a < tlen) {
                    if (tlen - a < 4) {
                        return -EBADMSG;
                    }

                    uint16_t attr = GetBe16(q + a);
                    if (attr & 0x8000) {
                        if ((attr & 0x7fff) == IKE_ATTR_KEY_LENGTH) {
                            tr.keyLength = GetBe16(q + a + 2);
                        }
                        else {
                            // --> An unknown attribute makes the transform unusable (RFC 7296
                            // 3.3.6); 0xffff never matches a key length we accept.
                            tr.keyLength = 0xffff;
                        }

                        a += 4;
                    }
                    else {
                        size_t alen = GetBe16(q + a + 2);
                        if (alen > tlen - a - 4) {
                            return -EBADMSG;
                        }

                        tr.keyLength = 0xffff;
                        a += 4 + alen;
                    }
                }

                prop.transforms.push_back(tr);
                t += tlen;
            }

            if (t != length) {
                return -EBADMSG;
            }

            out.push_back(std::move(prop));
            at += length;

            if (out.size() > 64) {
                return -EBADMSG;
            }
        }

        return at == body.size ? SBOX_OK : -EBADMSG;
    }

    /* Encodes an SA payload. */
    void EncodeIkeSa(const std::vector<SIkeProposal>& proposals, std::vector<uint8_t>& out) {
        for (size_t i = 0; i < proposals.size(); ++i) {
            const SIkeProposal& prop = proposals[i];
            size_t start = out.size();
            out.push_back(i + 1 < proposals.size() ? 2 : 0);
            out.push_back(0);
            PutBe16(out, 0);
            out.push_back(prop.number);
            out.push_back(prop.protocol);
            out.push_back(uint8_t(prop.spi.size()));
            out.push_back(uint8_t(prop.transforms.size()));
            Append(out, BytesOf(prop.spi));

            for (size_t j = 0; j < prop.transforms.size(); ++j) {
                const SIkeTransform& t = prop.transforms[j];
                out.push_back(j + 1 < prop.transforms.size() ? 3 : 0);
                out.push_back(0);
                PutBe16(out, t.keyLength ? 12 : 8);
                out.push_back(t.type);
                out.push_back(0);
                PutBe16(out, t.id);
                if (t.keyLength) {
                    PutBe16(out, 0x8000u | IKE_ATTR_KEY_LENGTH);
                    PutBe16(out, t.keyLength);
                }
            }

            SetBe16(out.data() + start + 2, uint32_t(out.size() - start));
        }
    }

    // ---------------------------------------------------------------------------------------

    /* Decodes KE. */
    int32_t DecodeIkeKe(const SReadOnlyByteSpan& body, uint16_t& group, std::vector<uint8_t>& data) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        group = GetBe16(body.data);
        data.assign(body.data + 4, body.data + body.size);
        return SBOX_OK;
    }

    /* Encodes KE. */
    void EncodeIkeKe(uint16_t group, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        PutBe16(out, group);
        PutBe16(out, 0);
        Append(out, data);
    }

    // ---------------------------------------------------------------------------------------

    /* Identity from text. */
    int32_t SIkeId::fromString(std::string_view text, SIkeId& out) {
        if (text.empty()) {
            return -EINVAL;
        }

        net::SIpAddress addr;
        if (net::SIpAddress::parse(text, addr) == SBOX_OK) {
            out.type = addr.isV4() ? EIKE_ID_IPV4_ADDR : EIKE_ID_IPV6_ADDR;
            out.data.assign(addr.bytes, addr.bytes + addr.length());
            return SBOX_OK;
        }

        if (text.substr(0, 6) == "keyid:") {
            std::vector<uint8_t> raw;
            if (!FromHex(text.substr(6), raw) || raw.empty()) {
                return -EINVAL;
            }

            out.type = EIKE_ID_KEY_ID;
            out.data = std::move(raw);
            return SBOX_OK;
        }

        if (text.find('=') != std::string_view::npos) {
            std::vector<uint8_t> der;
            if (!DnFromString(text, der)) {
                return -EINVAL;
            }

            out.type = EIKE_ID_DER_ASN1_DN;
            out.data = std::move(der);
            return SBOX_OK;
        }

        if (text[0] == '@') {
            // --> "@name" forces FQDN even for names with an '@' later (strongSwan convention).
            text.remove_prefix(1);
            if (text.empty()) {
                return -EINVAL;
            }

            out.type = EIKE_ID_FQDN;
        }
        else {
            out.type = text.find('@') != std::string_view::npos ? EIKE_ID_RFC822_ADDR : EIKE_ID_FQDN;
        }

        out.data.assign(text.begin(), text.end());
        return SBOX_OK;
    }

    /* Identity to text. */
    std::string SIkeId::toString() const {
        switch (type) {
        case EIKE_ID_IPV4_ADDR:
        case EIKE_ID_IPV6_ADDR: {
            net::SIpAddress addr;
            if (net::SIpAddress::fromBytes(data.data(), data.size(), addr) == SBOX_OK) {
                return addr.toString();
            }

            break;
        }

        case EIKE_ID_FQDN:
        case EIKE_ID_RFC822_ADDR:
            return std::string(data.begin(), data.end());

        case EIKE_ID_DER_ASN1_DN: {
            std::string dn = DnToString(BytesOf(data));
            if (!dn.empty()) {
                return dn;
            }

            break;
        }

        case EIKE_ID_KEY_ID:
            return "keyid:" + ToHex(BytesOf(data));

        default:
            break;
        }

        return "id" + std::to_string(type) + ":" + ToHex(BytesOf(data));
    }

    /* Identity body. */
    std::vector<uint8_t> SIkeId::body() const {
        std::vector<uint8_t> out;
        out.push_back(type);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        Append(out, BytesOf(data));
        return out;
    }

    /* Decodes an ID payload. */
    int32_t DecodeIkeId(const SReadOnlyByteSpan& body, SIkeId& out) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        out.type = body[0];
        out.data.assign(body.data + 4, body.data + body.size);
        if ((out.type == EIKE_ID_IPV4_ADDR && out.data.size() != 4) || (out.type == EIKE_ID_IPV6_ADDR && out.data.size() != 16)) {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

    // ---------------------------------------------------------------------------------------

    /* Decodes CERT/CERTREQ. */
    int32_t DecodeIkeCert(const SReadOnlyByteSpan& body, uint8_t& encoding, std::vector<uint8_t>& data) {
        if (body.size < 1) {
            return -EBADMSG;
        }

        encoding = body[0];
        data.assign(body.data + 1, body.data + body.size);
        return SBOX_OK;
    }

    /* Encodes CERT/CERTREQ. */
    void EncodeIkeCert(uint8_t encoding, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        out.push_back(encoding);
        Append(out, data);
    }

    /* Decodes AUTH. */
    int32_t DecodeIkeAuth(const SReadOnlyByteSpan& body, uint8_t& method, std::vector<uint8_t>& data) {
        if (body.size < 5) {
            return -EBADMSG;
        }

        method = body[0];
        data.assign(body.data + 4, body.data + body.size);
        return SBOX_OK;
    }

    /* Encodes AUTH. */
    void EncodeIkeAuth(uint8_t method, const SReadOnlyByteSpan& data, std::vector<uint8_t>& out) {
        out.push_back(method);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        Append(out, data);
    }

    // ---------------------------------------------------------------------------------------

    /* Decodes Notify. */
    int32_t DecodeIkeNotify(const SReadOnlyByteSpan& body, SIkeNotify& out) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        out.protocol = body[0];
        size_t spiSize = body[1];
        out.type = GetBe16(body.data + 2);
        if (4 + spiSize > body.size) {
            return -EBADMSG;
        }

        out.spi.assign(body.data + 4, body.data + 4 + spiSize);
        out.data.assign(body.data + 4 + spiSize, body.data + body.size);
        return SBOX_OK;
    }

    /* Encodes Notify. */
    void EncodeIkeNotify(const SIkeNotify& notify, std::vector<uint8_t>& out) {
        out.push_back(notify.protocol);
        out.push_back(uint8_t(notify.spi.size()));
        PutBe16(out, notify.type);
        Append(out, BytesOf(notify.spi));
        Append(out, BytesOf(notify.data));
    }

    /* Builds a Notify payload. */
    SIkePayload MakeIkeNotify(uint16_t type, const SReadOnlyByteSpan& data) {
        SIkeNotify n;
        n.type = type;
        Append(n.data, data);

        SIkePayload pl;
        pl.type = EIKE_PL_NOTIFY;
        EncodeIkeNotify(n, pl.body);
        return pl;
    }

    /* Decodes Delete. */
    int32_t DecodeIkeDelete(const SReadOnlyByteSpan& body, SIkeDelete& out) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        out.protocol = body[0];
        size_t spiSize = body[1];
        size_t count = GetBe16(body.data + 2);
        out.spis.clear();

        if (out.protocol == EIKE_PROTO_IKE) {
            // --> RFC 7296 3.11: SPI size 0 and no SPIs for the IKE SA itself.
            return spiSize == 0 && body.size == 4 ? SBOX_OK : -EBADMSG;
        }

        if (spiSize != 4 || body.size != 4 + count * 4) {
            return -EBADMSG;
        }

        for (size_t i = 0; i < count; ++i) {
            out.spis.push_back(GetBe32(body.data + 4 + i * 4));
        }

        return SBOX_OK;
    }

    /* Encodes Delete. */
    void EncodeIkeDelete(const SIkeDelete& del, std::vector<uint8_t>& out) {
        out.push_back(del.protocol);
        out.push_back(del.protocol == EIKE_PROTO_IKE ? 0 : 4);
        PutBe16(out, del.protocol == EIKE_PROTO_IKE ? 0 : uint32_t(del.spis.size()));
        if (del.protocol != EIKE_PROTO_IKE) {
            for (uint32_t spi : del.spis) {
                PutBe32(out, spi);
            }
        }
    }

    // ---------------------------------------------------------------------------------------

    /* Selector from a prefix. */
    SIkeTrafficSelector SIkeTrafficSelector::fromPrefix(const net::SIpPrefix& prefix) {
        SIkeTrafficSelector ts;
        ts.type = prefix.address.isV6() ? EIKE_TS_IPV6_ADDR_RANGE : EIKE_TS_IPV4_ADDR_RANGE;
        ts.start = prefix.network().address;
        ts.end = prefix.last();
        return ts;
    }

    /* Selector covering a whole family. */
    SIkeTrafficSelector SIkeTrafficSelector::any(bool ipv6) {
        net::SIpPrefix all;
        net::SIpAddress::parse(ipv6 ? "::" : "0.0.0.0", all.address);
        all.length = 0;
        return fromPrefix(all);
    }

    /* Intersection. */
    bool SIkeTrafficSelector::intersect(const SIkeTrafficSelector& a, const SIkeTrafficSelector& b, SIkeTrafficSelector& out) {
        if (a.type != b.type || a.start.family != b.start.family) {
            return false;
        }

        uint8_t proto;
        if (a.protocol == 0) {
            proto = b.protocol;
        }
        else if (b.protocol == 0 || b.protocol == a.protocol) {
            proto = a.protocol;
        }
        else {
            return false;
        }

        uint16_t sp = a.startPort > b.startPort ? a.startPort : b.startPort;
        uint16_t ep = a.endPort < b.endPort ? a.endPort : b.endPort;
        if (sp > ep) {
            return false;
        }

        net::SIpAddress s = a.start.compare(b.start) > 0 ? a.start : b.start;
        net::SIpAddress e = a.end.compare(b.end) < 0 ? a.end : b.end;
        if (s.compare(e) > 0) {
            return false;
        }

        out.type = a.type;
        out.protocol = proto;
        out.startPort = sp;
        out.endPort = ep;
        out.start = s;
        out.end = e;
        return true;
    }

    /* Address containment. */
    bool SIkeTrafficSelector::containsAddress(const net::SIpAddress& addr) const noexcept {
        if (addr.family != start.family) {
            return false;
        }

        return start.compare(addr) <= 0 && addr.compare(end) <= 0;
    }

    /* Range to prefixes. */
    std::vector<net::SIpPrefix> SIkeTrafficSelector::toPrefixes() const {
        std::vector<net::SIpPrefix> out;
        if (!start.isValid() || start.family != end.family || start.compare(end) > 0) {
            return out;
        }

        uint32_t width = start.bits();
        U128 cur = toNumber(start);
        U128 last = toNumber(end);

        // --> mask(k) = 2^k - 1 without shifting a 128-bit value by 128.
        auto mask = [](uint32_t k) -> U128 {
            return k >= 128 ? ~U128(0) : ((U128(1) << k) - 1);
        };

        while (true) {
            // --> Largest aligned block starting at `cur` that stays within `last`.
            uint32_t k = 0;
            while (k < width) {
                U128 m = mask(k + 1);
                if ((cur & m) != 0 || cur + m < cur || cur + m > last) {
                    break;
                }

                ++k;
            }

            out.emplace_back(fromNumber(cur, start.family), uint8_t(width - k));

            U128 blockEnd = cur + mask(k);
            if (blockEnd >= last || out.size() > 256) {
                break;
            }

            cur = blockEnd + 1;
        }

        return out;
    }

    /* Range as one prefix. */
    bool SIkeTrafficSelector::toPrefix(net::SIpPrefix& out) const noexcept {
        std::vector<net::SIpPrefix> all = toPrefixes();
        if (all.size() != 1) {
            return false;
        }

        out = all[0];
        return true;
    }

    /* Formats a selector. */
    std::string SIkeTrafficSelector::toString() const {
        std::string out;
        net::SIpPrefix prefix;
        if (toPrefix(prefix)) {
            out = prefix.toString();
        }
        else {
            out = start.toString() + "-" + end.toString();
        }

        if (protocol != 0 || startPort != 0 || endPort != 65535) {
            out += "[" + std::to_string(protocol);
            if (startPort != 0 || endPort != 65535) {
                out += "/" + std::to_string(startPort);
                if (endPort != startPort) {
                    out += "-" + std::to_string(endPort);
                }
            }

            out += "]";
        }

        return out;
    }

    /* Equality. */
    bool SIkeTrafficSelector::operator==(const SIkeTrafficSelector& o) const noexcept {
        return type == o.type && protocol == o.protocol && startPort == o.startPort && endPort == o.endPort
            && start == o.start && end == o.end;
    }

    /* Decodes TS. */
    int32_t DecodeIkeTs(const SReadOnlyByteSpan& body, std::vector<SIkeTrafficSelector>& out) {
        out.clear();
        if (body.size < 4) {
            return -EBADMSG;
        }

        size_t count = body[0];
        size_t at = 4;
        for (size_t i = 0; i < count; ++i) {
            if (body.size - at < 8) {
                return -EBADMSG;
            }

            const uint8_t* p = body.data + at;
            size_t length = GetBe16(p + 2);
            if (length < 8 || length > body.size - at) {
                return -EBADMSG;
            }

            uint8_t type = p[0];
            size_t addrLen = type == EIKE_TS_IPV4_ADDR_RANGE ? 4 : type == EIKE_TS_IPV6_ADDR_RANGE ? 16 : 0;
            if (addrLen) {
                if (length != 8 + 2 * addrLen) {
                    return -EBADMSG;
                }

                SIkeTrafficSelector ts;
                ts.type = type;
                ts.protocol = p[1];
                ts.startPort = GetBe16(p + 4);
                ts.endPort = GetBe16(p + 6);
                net::SIpAddress::fromBytes(p + 8, addrLen, ts.start);
                net::SIpAddress::fromBytes(p + 8 + addrLen, addrLen, ts.end);
                out.push_back(ts);
            }

            at += length;
        }

        return at == body.size ? SBOX_OK : -EBADMSG;
    }

    /* Encodes TS. */
    void EncodeIkeTs(const std::vector<SIkeTrafficSelector>& selectors, std::vector<uint8_t>& out) {
        out.push_back(uint8_t(selectors.size()));
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        for (const SIkeTrafficSelector& ts : selectors) {
            size_t addrLen = ts.start.length();
            out.push_back(addrLen == 16 ? EIKE_TS_IPV6_ADDR_RANGE : EIKE_TS_IPV4_ADDR_RANGE);
            out.push_back(ts.protocol);
            PutBe16(out, uint32_t(8 + 2 * addrLen));
            PutBe16(out, ts.startPort);
            PutBe16(out, ts.endPort);
            Append(out, SReadOnlyByteSpan(ts.start.bytes, addrLen));
            Append(out, SReadOnlyByteSpan(ts.end.bytes, addrLen));
        }
    }

    // ---------------------------------------------------------------------------------------

    /* Decodes CP. */
    int32_t DecodeIkeConfig(const SReadOnlyByteSpan& body, SIkeConfig& out) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        out.cfgType = body[0];
        out.attributes.clear();
        size_t at = 4;
        while (at < body.size) {
            if (body.size - at < 4) {
                return -EBADMSG;
            }

            SIkeCfgAttribute attr;
            attr.type = GetBe16(body.data + at) & 0x7fff;
            size_t length = GetBe16(body.data + at + 2);
            if (length > body.size - at - 4) {
                return -EBADMSG;
            }

            attr.value.assign(body.data + at + 4, body.data + at + 4 + length);
            out.attributes.push_back(std::move(attr));
            at += 4 + length;

            if (out.attributes.size() > 256) {
                return -EBADMSG;
            }
        }

        return SBOX_OK;
    }

    /* Encodes CP. */
    void EncodeIkeConfig(const SIkeConfig& config, std::vector<uint8_t>& out) {
        out.push_back(config.cfgType);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        for (const SIkeCfgAttribute& attr : config.attributes) {
            PutBe16(out, attr.type & 0x7fffu);
            PutBe16(out, uint32_t(attr.value.size()));
            Append(out, BytesOf(attr.value));
        }
    }

    /* Reads SKF numbering. */
    int32_t DecodeIkeFragmentHeader(const SReadOnlyByteSpan& body, uint16_t& number, uint16_t& total) {
        if (body.size < 4) {
            return -EBADMSG;
        }

        number = GetBe16(body.data);
        total = GetBe16(body.data + 2);
        if (number == 0 || total == 0 || number > total) {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

}
}
