#ifndef __SRC_TLS_DER_HPP__
#define __SRC_TLS_DER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

// --> A minimal DER walker used only to cut the raw issuer/subject Name elements out of a
// certificate: issuer/subject matching compares those bytes exactly (as most verifiers do),
// while every field with meaning (keys, extensions, validity) comes from libcertpp's parser.

namespace sbox {
namespace tls {

    /**
     * One DER element: its tag byte, the whole element and its content.
     */
    struct DerElement {
        uint8_t tag = 0;
        SReadOnlyByteSpan whole;
        SReadOnlyByteSpan content;
    };

    /**
     * Reads one element from the front of `in` and advances `in` past it.
     * Supports single-byte tags and definite lengths up to 4 length bytes.
     */
    inline bool DerNext(SReadOnlyByteSpan& in, DerElement& out) {
        if (in.size < 2) {
            return false;
        }

        uint8_t tag = in[0];
        if ((tag & 0x1f) == 0x1f) {
            return false;
        }

        size_t pos = 2;
        size_t len = in[1];
        if (len & 0x80) {
            size_t n = len & 0x7f;
            if (n == 0 || n > 4 || in.size < 2 + n) {
                return false;
            }

            len = 0;
            for (size_t i = 0; i < n; ++i) {
                len = (len << 8) | in[2 + i];
            }

            pos += n;
        }

        if (in.size - pos < len) {
            return false;
        }

        out.tag = tag;
        out.whole = SReadOnlyByteSpan(in.data, pos + len);
        out.content = SReadOnlyByteSpan(in.data + pos, len);
        in = in.slice(pos + len);
        return true;
    }

    /**
     * Extracts the raw issuer and subject Name elements (tag and length included) of a
     * DER-encoded certificate.
     */
    inline bool DerCertificateNames(const SReadOnlyByteSpan& cert, SReadOnlyByteSpan& issuer, SReadOnlyByteSpan& subject) {
        SReadOnlyByteSpan in = cert;
        DerElement certificate, tbs, e;

        if (!DerNext(in, certificate) || certificate.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan c = certificate.content;
        if (!DerNext(c, tbs) || tbs.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan t = tbs.content;
        if (!DerNext(t, e)) {
            return false;
        }

        // --> Optional [0] EXPLICIT version, then serialNumber.
        if (e.tag == 0xa0 && !DerNext(t, e)) {
            return false;
        }

        DerElement sigAlg, iss, validity, sub;
        if (!DerNext(t, sigAlg) || !DerNext(t, iss) || !DerNext(t, validity) || !DerNext(t, sub)) {
            return false;
        }

        if (iss.tag != 0x30 || sub.tag != 0x30) {
            return false;
        }

        issuer = iss.whole;
        subject = sub.whole;
        return true;
    }

    /**
     * One extension of a certificate: the OID's content octets and the critical flag.
     */
    struct DerExtension {
        SReadOnlyByteSpan oid;
        bool critical = false;
    };

    /**
     * Lists the extensions of a DER-encoded certificate (empty for a v1 certificate).
     * @return false when the structure cannot be walked.
     */
    inline bool DerCertificateExtensions(const SReadOnlyByteSpan& cert, std::vector<DerExtension>& out) {
        SReadOnlyByteSpan in = cert;
        DerElement certificate, tbs, e;

        if (!DerNext(in, certificate) || certificate.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan c = certificate.content;
        if (!DerNext(c, tbs) || tbs.tag != 0x30) {
            return false;
        }

        SReadOnlyByteSpan t = tbs.content;
        while (!t.empty()) {
            if (!DerNext(t, e)) {
                return false;
            }

            if (e.tag != 0xa3) {
                continue;
            }

            DerElement seq;
            SReadOnlyByteSpan x = e.content;
            if (!DerNext(x, seq) || seq.tag != 0x30) {
                return false;
            }

            SReadOnlyByteSpan list = seq.content;
            while (!list.empty()) {
                DerElement ext, oid, next;
                if (!DerNext(list, ext) || ext.tag != 0x30) {
                    return false;
                }

                SReadOnlyByteSpan body = ext.content;
                if (!DerNext(body, oid) || oid.tag != 0x06 || !DerNext(body, next)) {
                    return false;
                }

                DerExtension d;
                d.oid = oid.content;
                d.critical = next.tag == 0x01 && next.content.size == 1 && next.content[0] != 0;
                out.push_back(d);
            }
        }

        return true;
    }

}
}

#endif
