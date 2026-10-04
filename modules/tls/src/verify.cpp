#include <sbox/tls/verify.hpp>
#include "verifyimpl.hpp"
#include "trustimpl.hpp"
#include "der.hpp"
#include "protocol.hpp"
#include <certpp/x509/exts/san.hpp>
#include <certpp/x509/exts/eku.hpp>
#include <certpp/x509/exts/bc.hpp>
#include <certpp/x509/exts/ku.hpp>
#include <certpp/x509/exts/nc.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <ctime>

namespace sbox {
namespace tls {

    using certpp::x509::CCert;

    namespace {

        constexpr size_t MAX_PATH_DEPTH = 8;    // --> Intermediates between leaf and anchor.
        constexpr size_t MAX_CHAIN = 16;        // --> Certificates accepted from the server.

        /* ASCII lower-casing. */
        std::string lower(std::string_view s) {
            std::string out(s);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

        /* Lower-cases and drops one trailing dot. */
        std::string normalizeName(std::string_view s) {
            if (!s.empty() && s.back() == '.') {
                s.remove_suffix(1);
            }

            return lower(s);
        }

        /* Returns true for a printable-ASCII DNS name without empty labels. */
        bool plausibleDnsName(std::string_view s) {
            if (s.empty() || s.size() > 253 || s.front() == '.' || s.find("..") != std::string_view::npos) {
                return false;
            }

            for (char c : s) {
                if (c <= 0x20 || c >= 0x7f) {
                    return false;
                }
            }

            return true;
        }

        /* Converts a certificate time to Unix seconds (-1 when unusable). */
        int64_t unixTime(const certpp::SDateTime& t) {
            if (t.year < 1900) {
                return -1;
            }

            // --> X.509 times are UTC (RFC 5280 4.1.2.5); timegm keeps the fields as UTC.
            std::tm tm{};
            tm.tm_year = int(t.year) - 1900;
            tm.tm_mon = int(t.month) - 1;
            tm.tm_mday = int(t.day);
            tm.tm_hour = int(t.hour);
            tm.tm_min = int(t.minute);
            tm.tm_sec = int(t.second);
            return int64_t(::timegm(&tm));
        }

        /* One parsed certificate of the presented chain. */
        struct Node {
            const std::vector<uint8_t>* der = nullptr;
            CCert cert;
            std::string issuer;
            std::string subject;
            int64_t notBefore = 0;
            int64_t notAfter = 0;
        };

        /* Parses one certificate. */
        bool parseNode(const std::vector<uint8_t>& der, Node& out) {
            SReadOnlyByteSpan issuer, subject;
            if (!DerCertificateNames(BytesOf(der), issuer, subject)) {
                return false;
            }

            if (out.cert.importDer(certpp::COctet(der.data(), der.size())) != certpp::ERET_OK) {
                return false;
            }

            out.der = &der;
            out.issuer.assign(reinterpret_cast<const char*>(issuer.data), issuer.size);
            out.subject.assign(reinterpret_cast<const char*>(subject.data), subject.size);
            out.notBefore = unixTime(out.cert.notBefore());
            out.notAfter = unixTime(out.cert.notAfter());
            return out.notBefore >= 0 && out.notAfter >= 0;
        }

        /* Rejects unknown critical extensions. */
        bool criticalExtensionsKnown(const SReadOnlyByteSpan& der) {
            // --> 2.5.29.x: keyUsage(15), subjectAltName(17), basicConstraints(19),
            // nameConstraints(30), certificatePolicies(32), policyConstraints(36),
            // extKeyUsage(37), inhibitAnyPolicy(54).
            static const uint8_t KNOWN[] = { 15, 17, 19, 30, 32, 36, 37, 54 };

            std::vector<DerExtension> exts;
            if (!DerCertificateExtensions(der, exts)) {
                return false;
            }

            for (const DerExtension& e : exts) {
                if (!e.critical) {
                    continue;
                }

                bool known = false;
                if (e.oid.size == 3 && e.oid[0] == 0x55 && e.oid[1] == 0x1d) {
                    for (uint8_t k : KNOWN) {
                        known = known || e.oid[2] == k;
                    }
                }

                if (!known) {
                    return false;
                }
            }

            return true;
        }

        /* Returns true when the certificate is not restricted away from TLS server use. */
        bool serverAuthAllowed(const CCert& cert) {
            auto eku = cert.extension<certpp::x509::CEkuExtension>();
            if (!eku) {
                return true;
            }

            return eku->has(certpp::x509::CEkuExtension::OID_SERVER_AUTH)
                || eku->has(certpp::x509::CEkuExtension::OID_ANY_EXTENDED_KEY_USAGE);
        }

        /* Returns true for MD5/SHA-1 based certificate signatures. */
        bool weakSignature(const CCert& cert) {
            std::string name = lower(std::string_view(cert.signAlgo().toPtr() ? cert.signAlgo().toPtr() : "", cert.signAlgo().size()));
            return name.find("md5") != std::string::npos || name.find("sha1") != std::string::npos
                || name.find("md2") != std::string::npos;
        }

        /* Returns true for an RSA key below 2048 bits. */
        bool weakKey(const CCert& cert) {
            auto pub = cert.publicKey();
            return pub && pub->algorithm() == certpp::crypto::EASYM_RSA && pub->keySize() < 2048;
        }

        /* Names of a certificate's subjectAltName. */
        void sanNames(const CCert& cert, std::vector<std::string>& dns, std::vector<std::vector<uint8_t>>& ips) {
            auto san = cert.extension<certpp::x509::CSanExtension>();
            if (!san) {
                return;
            }

            for (const certpp::x509::CGeneralName& n : san->names()) {
                if (n.type() == certpp::x509::EGNAME_DNS) {
                    dns.emplace_back(n.text().toPtr() ? n.text().toPtr() : "", n.text().size());
                }
                else if (n.type() == certpp::x509::EGNAME_IP_ADDRESS) {
                    ips.emplace_back(n.raw().toPtr(), n.raw().toPtr() + n.raw().size());
                }
            }
        }

        /* dNSName name constraint match (RFC 5280 4.2.1.10). */
        bool dnsWithin(const std::string& name, std::string_view base) {
            std::string b = normalizeName(base);
            std::string n = normalizeName(name);

            if (b.empty()) {
                return true;
            }

            if (b.front() == '.') {
                return n.size() > b.size() && n.compare(n.size() - b.size(), b.size(), b) == 0;
            }

            return n == b || (n.size() > b.size() && n.compare(n.size() - b.size(), b.size(), b) == 0
                              && n[n.size() - b.size() - 1] == '.');
        }

        /* iPAddress name constraint match: address || mask. */
        bool ipWithin(const std::vector<uint8_t>& ip, const certpp::COctet& raw) {
            if (raw.size() != ip.size() * 2) {
                return false;
            }

            const uint8_t* addr = raw.toPtr();
            const uint8_t* mask = addr + ip.size();
            for (size_t i = 0; i < ip.size(); ++i) {
                if ((ip[i] & mask[i]) != (addr[i] & mask[i])) {
                    return false;
                }
            }

            return true;
        }

        /* Applies one certificate's name constraints to the leaf names. */
        bool nameConstraintsHold(const CCert& ca, const std::vector<std::string>& dns,
                                 const std::vector<std::vector<uint8_t>>& ips, std::string& reason) {
            auto nc = ca.extension<certpp::x509::CNameConstraintsExtension>();
            if (!nc) {
                return true;
            }

            auto text = [](const certpp::x509::CGeneralName& g) {
                return std::string_view(g.text().toPtr() ? g.text().toPtr() : "", g.text().size());
            };

            bool dnsPermittedSeen = false, ipPermittedSeen = false;
            std::vector<bool> dnsOk(dns.size(), false), ipOk(ips.size(), false);

            for (const certpp::x509::CGeneralSubtree& st : nc->permittedSubtrees()) {
                const certpp::x509::CGeneralName& base = st.base();
                if (base.type() == certpp::x509::EGNAME_DNS) {
                    dnsPermittedSeen = true;
                    for (size_t i = 0; i < dns.size(); ++i) {
                        dnsOk[i] = dnsOk[i] || dnsWithin(dns[i], text(base));
                    }
                }
                else if (base.type() == certpp::x509::EGNAME_IP_ADDRESS) {
                    ipPermittedSeen = true;
                    for (size_t i = 0; i < ips.size(); ++i) {
                        ipOk[i] = ipOk[i] || ipWithin(ips[i], base.raw());
                    }
                }
            }

            for (size_t i = 0; i < dns.size(); ++i) {
                if (dnsPermittedSeen && !dnsOk[i]) {
                    reason = "name '" + dns[i] + "' is outside the permitted name constraints";
                    return false;
                }
            }

            for (size_t i = 0; i < ips.size(); ++i) {
                if (ipPermittedSeen && !ipOk[i]) {
                    reason = "an IP address is outside the permitted name constraints";
                    return false;
                }
            }

            for (const certpp::x509::CGeneralSubtree& st : nc->excludedSubtrees()) {
                const certpp::x509::CGeneralName& base = st.base();
                if (base.type() == certpp::x509::EGNAME_DNS) {
                    for (const std::string& n : dns) {
                        if (dnsWithin(n, text(base))) {
                            reason = "name '" + n + "' is excluded by name constraints";
                            return false;
                        }
                    }
                }
                else if (base.type() == certpp::x509::EGNAME_IP_ADDRESS) {
                    for (const auto& ip : ips) {
                        if (ipWithin(ip, base.raw())) {
                            reason = "an IP address is excluded by name constraints";
                            return false;
                        }
                    }
                }
            }

            return true;
        }

        /* State of one path search. */
        struct Search {
            std::vector<Node>& nodes;
            const CTrustStore::SImpl& trust;
            int64_t now;
            std::vector<bool> used;
            std::vector<size_t> path;               // --> Node indices, leaf first.
            std::vector<std::string> leafDns;
            std::vector<std::vector<uint8_t>> leafIps;
            std::string reason;                     // --> Most specific failure seen.
            uint8_t alert = AD_UNKNOWN_CA;

            /* Records a failure unless a more specific one is already known. */
            void note(const std::string& why, uint8_t ad) {
                if (alert == AD_UNKNOWN_CA) {
                    reason = why;
                    alert = ad;
                }
            }

            /* Checks a would-be issuer: CA flag, path length, key usage, EKU. */
            bool issuerUsable(const CCert& cert, bool anchor, size_t below) {
                auto bc = cert.extension<certpp::x509::CBasicConstraintsExtension>();
                if (!bc) {
                    // --> Old v1 roots carry no BasicConstraints; an explicitly trusted anchor is
                    // still accepted, an intermediate is not.
                    if (!anchor) {
                        note("intermediate certificate is not a CA (no basicConstraints)", AD_BAD_CERTIFICATE);
                        return false;
                    }
                }
                else {
                    if (!bc->isCa()) {
                        note("issuer certificate is not a CA", AD_BAD_CERTIFICATE);
                        return false;
                    }

                    if (bc->hasPathLenConstraint() && int64_t(below) > bc->pathLenConstraint()) {
                        note("path length constraint exceeded", AD_BAD_CERTIFICATE);
                        return false;
                    }
                }

                auto ku = cert.extension<certpp::x509::CKeyUsagesExtension>();
                if (ku && !(ku->bits() & certpp::x509::EKUSE_KEY_CERT_SIGN)) {
                    note("issuer key usage lacks keyCertSign", AD_BAD_CERTIFICATE);
                    return false;
                }

                if (!serverAuthAllowed(cert)) {
                    note("issuer extended key usage excludes serverAuth", AD_BAD_CERTIFICATE);
                    return false;
                }

                return true;
            }

            /* Checks the validity window. */
            bool current(const CCert& cert, int64_t notBefore, int64_t notAfter, const char* what) {
                (void)cert;
                if (now < notBefore) {
                    note(std::string(what) + " certificate is not yet valid", AD_BAD_CERTIFICATE);
                    return false;
                }

                if (now > notAfter) {
                    note(std::string(what) + " certificate has expired", AD_CERTIFICATE_EXPIRED);
                    return false;
                }

                return true;
            }

            /* Name constraints of every issuer on the path (and the anchor). */
            bool constraintsHold(const CCert* anchor) {
                std::string why;
                for (size_t i = 1; i < path.size(); ++i) {
                    if (!nameConstraintsHold(nodes[path[i]].cert, leafDns, leafIps, why)) {
                        note(why, AD_BAD_CERTIFICATE);
                        return false;
                    }
                }

                if (anchor && !nameConstraintsHold(*anchor, leafDns, leafIps, why)) {
                    note(why, AD_BAD_CERTIFICATE);
                    return false;
                }

                return true;
            }

            /* Depth-first path building from node `idx` (already on the path). */
            bool build(size_t idx) {
                Node& cur = nodes[idx];
                size_t below = path.size() - 1;     // --> Intermediates under cur's issuer.

                // --> A certificate that is itself an anchor ends the path (a pinned
                // self-signed registry certificate, or an intermediate that is also trusted).
                std::string der(reinterpret_cast<const char*>(cur.der->data()), cur.der->size());
                if (trust.contains(der)) {
                    return constraintsHold(nullptr);
                }

                if (weakSignature(cur.cert)) {
                    note("certificate is signed with MD5 or SHA-1", AD_BAD_CERTIFICATE);
                    return false;
                }

                std::vector<const Anchor*> anchors;
                trust.find(cur.issuer, anchors);
                for (const Anchor* a : anchors) {
                    if (cur.cert.verifyBy(*a->cert) != certpp::ERET_OK) {
                        continue;
                    }

                    int64_t nb = unixTime(a->cert->notBefore()), na = unixTime(a->cert->notAfter());
                    if (!current(*a->cert, nb, na, "root") || !issuerUsable(*a->cert, true, below)) {
                        continue;
                    }

                    if (constraintsHold(a->cert.get())) {
                        return true;
                    }
                }

                if (below >= MAX_PATH_DEPTH) {
                    note("certificate path is too long", AD_BAD_CERTIFICATE);
                    return false;
                }

                for (size_t j = 1; j < nodes.size(); ++j) {
                    Node& cand = nodes[j];
                    if (used[j] || cand.subject != cur.issuer) {
                        continue;
                    }

                    if (cur.cert.verifyBy(cand.cert) != certpp::ERET_OK) {
                        continue;
                    }

                    if (!current(cand.cert, cand.notBefore, cand.notAfter, "intermediate")
                        || !issuerUsable(cand.cert, false, below)) {
                        continue;
                    }

                    if (!criticalExtensionsKnown(BytesOf(*cand.der))) {
                        note("intermediate certificate has an unsupported critical extension", AD_UNSUPPORTED_CERTIFICATE);
                        continue;
                    }

                    if (weakKey(cand.cert)) {
                        note("intermediate certificate has an RSA key below 2048 bits", AD_INSUFFICIENT_SECURITY);
                        continue;
                    }

                    used[j] = true;
                    path.push_back(j);
                    if (build(j)) {
                        return true;
                    }

                    path.pop_back();
                    used[j] = false;
                }

                return false;
            }
        };

    }

    /* Parses an IP literal. */
    bool ParseIpLiteral(std::string_view host, std::vector<uint8_t>& out) {
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
            host = host.substr(1, host.size() - 2);
        }

        if (host.empty() || host.size() > 64) {
            return false;
        }

        std::string text(host);
        uint8_t buf[16];

        if (::inet_pton(AF_INET, text.c_str(), buf) == 1) {
            out.assign(buf, buf + 4);
            return true;
        }

        if (::inet_pton(AF_INET6, text.c_str(), buf) == 1) {
            out.assign(buf, buf + 16);
            return true;
        }

        return false;
    }

    /* Matches one dNSName pattern. */
    bool MatchDnsName(std::string_view pattern, std::string_view host) {
        std::vector<uint8_t> ip;
        if (ParseIpLiteral(host, ip)) {
            return false;
        }

        std::string p = normalizeName(pattern);
        std::string h = normalizeName(host);
        if (!plausibleDnsName(p) || !plausibleDnsName(h)) {
            return false;
        }

        size_t star = p.find('*');
        if (star == std::string::npos) {
            return p == h;
        }

        // --> Only "*." as the whole first label; no partial ("f*o.") or inner wildcards.
        if (star != 0 || p.size() < 3 || p[1] != '.' || p.find('*', 1) != std::string::npos) {
            return false;
        }

        std::string_view suffix = std::string_view(p).substr(2);
        // --> At least two labels after the wildcard: "*.com" must not cover a whole TLD.
        if (suffix.find('.') == std::string_view::npos) {
            return false;
        }

        size_t dot = h.find('.');
        if (dot == std::string::npos || dot == 0) {
            return false;
        }

        return std::string_view(h).substr(dot + 1) == suffix;
    }

    /* Matches a certificate's subjectAltName against a host. */
    bool MatchCertificateHost(const SReadOnlyByteSpan& certDer, std::string_view host) {
        CCert cert;
        if (cert.importDer(certpp::COctet(certDer.data, certDer.size)) != certpp::ERET_OK) {
            return false;
        }

        std::vector<std::string> dns;
        std::vector<std::vector<uint8_t>> ips;
        sanNames(cert, dns, ips);

        std::vector<uint8_t> ip;
        if (ParseIpLiteral(host, ip)) {
            for (const auto& candidate : ips) {
                if (candidate == ip) {
                    return true;
                }
            }

            return false;
        }

        for (const std::string& pattern : dns) {
            if (MatchDnsName(pattern, host)) {
                return true;
            }
        }

        return false;
    }

    /* Chain verification with an alert. */
    int32_t VerifyChainWithAlert(const std::vector<std::vector<uint8_t>>& chain, const CTrustStore& trust,
                                 const STlsVerifyParams& params, std::string& reason, uint8_t& alert) {
        alert = AD_BAD_CERTIFICATE;

        if (chain.empty()) {
            reason = "the server sent no certificate";
            return -EINVAL;
        }

        if (params.host.empty()) {
            reason = "no host name to verify the certificate against";
            return -EINVAL;
        }

        if (chain.size() > MAX_CHAIN) {
            reason = "the certificate chain is too long";
            return -EKEYREJECTED;
        }

        std::vector<Node> nodes(chain.size());
        for (size_t i = 0; i < chain.size(); ++i) {
            if (!parseNode(chain[i], nodes[i])) {
                reason = i == 0 ? "the server certificate cannot be parsed" : "a chain certificate cannot be parsed";
                if (i == 0) {
                    return -EKEYREJECTED;
                }

                // --> An unparsable extra certificate is only an unusable path candidate.
                nodes[i].der = &chain[i];
                nodes[i].subject.clear();
            }
        }

        int64_t now = params.nowSeconds > 0 ? params.nowSeconds : int64_t(std::time(nullptr));
        Node& leaf = nodes[0];

        if (!criticalExtensionsKnown(BytesOf(chain[0]))) {
            reason = "the server certificate has an unsupported critical extension";
            alert = AD_UNSUPPORTED_CERTIFICATE;
            return -EKEYREJECTED;
        }

        if (now < leaf.notBefore) {
            reason = "the server certificate is not yet valid";
            return -EKEYREJECTED;
        }

        if (now > leaf.notAfter) {
            reason = "the server certificate has expired";
            alert = AD_CERTIFICATE_EXPIRED;
            return -EKEYREJECTED;
        }

        if (!serverAuthAllowed(leaf.cert)) {
            reason = "the server certificate is not valid for TLS server authentication (extendedKeyUsage)";
            alert = AD_UNSUPPORTED_CERTIFICATE;
            return -EKEYREJECTED;
        }

        if (weakKey(leaf.cert)) {
            reason = "the server certificate has an RSA key below 2048 bits";
            alert = AD_INSUFFICIENT_SECURITY;
            return -EKEYREJECTED;
        }

        if (!MatchCertificateHost(BytesOf(chain[0]), params.host)) {
            reason = "the server certificate does not match host '" + std::string(params.host) + "'";
            alert = AD_BAD_CERTIFICATE;
            return -EKEYREJECTED;
        }

        Search s{ nodes, *trust.impl(), now, std::vector<bool>(nodes.size(), false), { 0 }, {}, {}, {}, AD_UNKNOWN_CA };
        sanNames(leaf.cert, s.leafDns, s.leafIps);
        s.used[0] = true;

        if (s.build(0)) {
            reason.clear();
            return SBOX_OK;
        }

        if (s.reason.empty()) {
            s.reason = "unable to find a trusted issuer for the certificate chain (unknown CA)";
        }

        reason = s.reason;
        alert = s.alert;
        return -EKEYREJECTED;
    }

    /* Public chain verification. */
    int32_t VerifyServerChain(const std::vector<std::vector<uint8_t>>& chain, const CTrustStore& trust,
                              const STlsVerifyParams& params, std::string* reason) {
        std::string why;
        uint8_t alert = 0;
        int32_t rc = VerifyChainWithAlert(chain, trust, params, why, alert);
        if (reason) {
            *reason = why;
        }

        return rc;
    }

}
}
