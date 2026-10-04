#include "der.hpp"
#include <cstdio>
#include <cstring>

namespace sbox {
namespace vpn {
namespace ipsec {

    namespace {

        struct AttrName {
            const char* name;
            uint8_t oid[10];
            size_t oidSize;
        };

        const AttrName ATTRS[] = {
            { "CN", { 0x55, 0x04, 0x03 }, 3 },
            { "C", { 0x55, 0x04, 0x06 }, 3 },
            { "L", { 0x55, 0x04, 0x07 }, 3 },
            { "ST", { 0x55, 0x04, 0x08 }, 3 },
            { "O", { 0x55, 0x04, 0x0a }, 3 },
            { "OU", { 0x55, 0x04, 0x0b }, 3 },
            { "SN", { 0x55, 0x04, 0x05 }, 3 },
            { "E", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 }, 9 },
            { "DC", { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 }, 10 },
        };

        /* Trims spaces at both ends. */
        std::string_view trim(std::string_view s) {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
                s.remove_prefix(1);
            }

            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
                s.remove_suffix(1);
            }

            return s;
        }

        /* Appends a DER INTEGER from unsigned big-endian bytes. */
        void putUnsigned(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
            while (n > 1 && p[0] == 0) {
                ++p;
                --n;
            }

            std::vector<uint8_t> v;
            if (n == 0 || (p[0] & 0x80)) {
                v.push_back(0);
            }

            v.insert(v.end(), p, p + n);
            DerPut(out, 0x02, BytesOf(v));
        }

    }

    /* Reads one TLV. */
    bool DerNext(SReadOnlyByteSpan& in, DerElement& out) {
        if (in.size < 2) {
            return false;
        }

        const uint8_t* p = in.data;
        uint8_t tag = p[0];
        if ((tag & 0x1f) == 0x1f) {
            return false;
        }

        size_t at = 1;
        size_t length = p[at++];
        if (length & 0x80) {
            size_t count = length & 0x7f;
            if (count == 0 || count > 4 || at + count > in.size) {
                return false;
            }

            length = 0;
            for (size_t i = 0; i < count; ++i) {
                length = (length << 8) | p[at++];
            }
        }

        if (length > in.size - at) {
            return false;
        }

        out.tag = tag;
        out.header = p;
        out.headerSize = at;
        out.content = p + at;
        out.contentSize = length;
        in = in.slice(at + length);
        return true;
    }

    /* Appends a TLV. */
    void DerPut(std::vector<uint8_t>& out, uint8_t tag, const SReadOnlyByteSpan& content) {
        out.push_back(tag);
        size_t n = content.size;
        if (n < 0x80) {
            out.push_back(uint8_t(n));
        }
        else if (n < 0x100) {
            out.push_back(0x81);
            out.push_back(uint8_t(n));
        }
        else if (n < 0x10000) {
            out.push_back(0x82);
            out.push_back(uint8_t(n >> 8));
            out.push_back(uint8_t(n));
        }
        else {
            out.push_back(0x83);
            out.push_back(uint8_t(n >> 16));
            out.push_back(uint8_t(n >> 8));
            out.push_back(uint8_t(n));
        }

        if (n) {
            out.insert(out.end(), content.data, content.data + n);
        }
    }

    /* TBSCertificate fields. */
    bool CertFields(const SReadOnlyByteSpan& cert, SReadOnlyByteSpan& issuer, SReadOnlyByteSpan& subject,
                    SReadOnlyByteSpan& spki) {
        SReadOnlyByteSpan in = cert;
        DerElement certificate;
        if (!DerNext(in, certificate) || certificate.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan c = certificate.value();
        DerElement tbs;
        if (!DerNext(c, tbs) || tbs.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan t = tbs.value();
        DerElement e;
        if (!DerNext(t, e)) {
            return false;
        }

        if (e.tag == 0xa0 && !DerNext(t, e)) {
            return false;
        }

        // --> e is the serial number now; then signature, issuer, validity, subject, spki.
        DerElement sig;
        DerElement iss;
        DerElement validity;
        DerElement sub;
        DerElement key;
        if (e.tag != 0x02 || !DerNext(t, sig) || !DerNext(t, iss) || !DerNext(t, validity) || !DerNext(t, sub)
            || !DerNext(t, key)) {
            return false;
        }

        if (iss.tag != 0x30 || sub.tag != 0x30 || key.tag != 0x30) {
            return false;
        }

        issuer = iss.whole();
        subject = sub.whole();
        spki = key.whole();
        return true;
    }

    /* DN to text. */
    std::string DnToString(const SReadOnlyByteSpan& name) {
        SReadOnlyByteSpan in = name;
        DerElement seq;
        if (!DerNext(in, seq) || seq.tag != 0x30) {
            return std::string();
        }

        std::string out;
        SReadOnlyByteSpan sets = seq.value();
        while (sets.size) {
            DerElement set;
            if (!DerNext(sets, set) || set.tag != 0x31) {
                break;
            }

            SReadOnlyByteSpan atvs = set.value();
            while (atvs.size) {
                DerElement atv;
                if (!DerNext(atvs, atv) || atv.tag != 0x30) {
                    break;
                }

                SReadOnlyByteSpan parts = atv.value();
                DerElement oid;
                DerElement value;
                if (!DerNext(parts, oid) || oid.tag != 0x06 || !DerNext(parts, value)) {
                    break;
                }

                std::string key;
                for (const AttrName& a : ATTRS) {
                    if (a.oidSize == oid.contentSize && std::memcmp(a.oid, oid.content, a.oidSize) == 0) {
                        key = a.name;
                        break;
                    }
                }

                if (key.empty()) {
                    // --> Dotted form for attributes this formatter does not name.
                    uint64_t acc = 0;
                    for (size_t i = 0; i < oid.contentSize; ++i) {
                        acc = (acc << 7) | (oid.content[i] & 0x7f);
                        if (!(oid.content[i] & 0x80)) {
                            char buf[32];
                            if (key.empty()) {
                                std::snprintf(buf, sizeof(buf), "%u.%u", uint32_t(acc < 80 ? acc / 40 : 2),
                                              uint32_t(acc < 80 ? acc % 40 : acc - 80));
                            }
                            else {
                                std::snprintf(buf, sizeof(buf), ".%llu", static_cast<unsigned long long>(acc));
                            }

                            key += buf;
                            acc = 0;
                        }
                    }
                }

                if (!out.empty()) {
                    out += ", ";
                }

                out += key;
                out += '=';
                out.append(reinterpret_cast<const char*>(value.content), value.contentSize);
            }
        }

        return out;
    }

    /* Text to DN. */
    bool DnFromString(std::string_view text, std::vector<uint8_t>& out) {
        std::vector<uint8_t> sets;
        while (!text.empty()) {
            size_t comma = text.find(',');
            std::string_view part = trim(text.substr(0, comma));
            text = comma == std::string_view::npos ? std::string_view() : text.substr(comma + 1);
            if (part.empty()) {
                continue;
            }

            size_t eq = part.find('=');
            if (eq == std::string_view::npos) {
                return false;
            }

            std::string_view key = trim(part.substr(0, eq));
            std::string_view value = trim(part.substr(eq + 1));

            const AttrName* attr = nullptr;
            for (const AttrName& a : ATTRS) {
                if (key.size() == std::strlen(a.name)) {
                    bool same = true;
                    for (size_t i = 0; i < key.size(); ++i) {
                        char c = key[i];
                        if (c >= 'a' && c <= 'z') {
                            c = char(c - 'a' + 'A');
                        }

                        same = same && c == a.name[i];
                    }

                    if (same) {
                        attr = &a;
                        break;
                    }
                }
            }

            if (!attr || value.empty()) {
                return false;
            }

            std::vector<uint8_t> atv;
            DerPut(atv, 0x06, SReadOnlyByteSpan(attr->oid, attr->oidSize));

            // --> C is a PrintableString, E/DC are IA5String, the rest UTF8String (RFC 5280).
            uint8_t stringTag = 0x0c;
            if (std::strcmp(attr->name, "C") == 0) {
                stringTag = 0x13;
            }
            else if (std::strcmp(attr->name, "E") == 0 || std::strcmp(attr->name, "DC") == 0) {
                stringTag = 0x16;
            }

            DerPut(atv, stringTag, BytesOf(value));

            std::vector<uint8_t> seq;
            DerPut(seq, 0x30, BytesOf(atv));
            DerPut(sets, 0x31, BytesOf(seq));
        }

        if (sets.empty()) {
            return false;
        }

        out.clear();
        DerPut(out, 0x30, BytesOf(sets));
        return true;
    }

    /* DER signature to r || s. */
    bool EcdsaDerToRaw(const SReadOnlyByteSpan& der, size_t coord, std::vector<uint8_t>& out) {
        SReadOnlyByteSpan in = der;
        DerElement seq;
        if (!DerNext(in, seq) || seq.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan v = seq.value();
        DerElement r;
        DerElement s;
        if (!DerNext(v, r) || !DerNext(v, s) || r.tag != 0x02 || s.tag != 0x02) {
            return false;
        }

        out.assign(coord * 2, 0);
        const DerElement* parts[2] = { &r, &s };
        for (int32_t i = 0; i < 2; ++i) {
            const uint8_t* p = parts[i]->content;
            size_t n = parts[i]->contentSize;
            while (n > 0 && p[0] == 0) {
                ++p;
                --n;
            }

            if (n > coord) {
                return false;
            }

            std::memcpy(out.data() + size_t(i) * coord + (coord - n), p, n);
        }

        return true;
    }

    /* r || s to DER signature. */
    bool EcdsaRawToDer(const SReadOnlyByteSpan& raw, std::vector<uint8_t>& out) {
        if (raw.size == 0 || raw.size % 2 != 0) {
            return false;
        }

        size_t coord = raw.size / 2;
        std::vector<uint8_t> body;
        putUnsigned(body, raw.data, coord);
        putUnsigned(body, raw.data + coord, coord);
        out.clear();
        DerPut(out, 0x30, BytesOf(body));
        return true;
    }

}
}
}
