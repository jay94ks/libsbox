#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/core/file.hpp>
#include "crypto.hpp"
#include <cerrno>

namespace sbox {
namespace vpn {

    namespace {

        /* Records the first error. */
        int32_t fail(std::string* error, const std::string& what) {
            if (error && error->empty()) {
                *error = what;
            }

            return -EINVAL;
        }

        /* Resolves a path relative to the configuration directory. */
        std::string resolve(const std::string& baseDir, const std::string& path) {
            if (path.empty() || path[0] == '/' || baseDir.empty()) {
                return path;
            }

            return CFile::join(baseDir, path);
        }

        /* Reads a string or the contents of a file. */
        int32_t pemOf(const CJson& value, const std::string& baseDir, std::string& out) {
            const std::string& text = value.asString();
            if (text.find("-----BEGIN") != std::string::npos) {
                out = text;
                return SBOX_OK;
            }

            return CFile::readAll(resolve(baseDir, text), out);
        }

        /* Reads a list of strings (a single string is a one-element list). */
        std::vector<std::string> strings(const CJson& value) {
            if (value.isString()) {
                return { value.asString() };
            }

            return value.asStrings();
        }

    }

    /* Parses the JSON configuration. */
    int32_t ParseIkeServerConfig(const CJson& json, SIkeServerConfig& out, std::string* error, const std::string& baseDir) {
        if (!json.isObject()) {
            return fail(error, "configuration must be a JSON object");
        }

        SIkeServerConfig c;

        static const char* KNOWN[] = {
            "listen", "port", "natPort", "ipv6", "netns", "serverId", "certificate", "key", "ca", "users", "psk",
            "eapIdentity", "strictCertificateId", "pool", "dns", "nbns", "dnsDomain", "routes", "remoteSubnets",
            "ike", "esp", "dataPath", "interface", "mtu", "bridge", "forwarding", "dpd", "ikeLifetime",
            "halfOpenTimeout", "cookieThreshold", "retransmitTries", "retransmitBase", "maxSessions", "fragmentSize",
            "forceEncap", "mobike", "comment",
        };

        for (size_t i = 0; i < json.size(); ++i) {
            bool known = false;
            for (const char* k : KNOWN) {
                known = known || json.keyAt(i) == k;
            }

            if (!known) {
                return fail(error, "unknown key '" + json.keyAt(i) + "'");
            }
        }

        c.listenAddress = json.get("listen").asString();
        c.port = uint16_t(json.get("port").asInt(500));
        c.natPort = uint16_t(json.get("natPort").asInt(4500));
        c.ipv6 = json.get("ipv6").asBool(false);
        c.netnsPath = json.get("netns").asString();
        c.serverId = json.get("serverId").asString();
        c.eapIdentity = json.get("eapIdentity").asBool(true);
        c.strictCertificateId = json.get("strictCertificateId").asBool(true);

        if (const CJson* cert = json.find("certificate")) {
            std::string certPem;
            std::string keyPem;
            if (pemOf(*cert, baseDir, certPem) != SBOX_OK) {
                return fail(error, "cannot read certificate '" + cert->asString() + "'");
            }

            if (const CJson* key = json.find("key")) {
                if (pemOf(*key, baseDir, keyPem) != SBOX_OK) {
                    return fail(error, "cannot read key '" + key->asString() + "'");
                }
            }

            int32_t r = CIkeCertificate::fromPem(certPem, c.certificate, keyPem);
            std::fill(keyPem.begin(), keyPem.end(), '\0');
            if (r != SBOX_OK) {
                return fail(error, "invalid certificate or key (" + std::to_string(r) + ")");
            }
        }

        for (const std::string& ca : strings(json.get("ca"))) {
            std::string pem;
            CJson value(ca);
            if (pemOf(value, baseDir, pem) != SBOX_OK) {
                return fail(error, "cannot read CA '" + ca + "'");
            }

            std::vector<CIkeCertificate> bundle;
            if (CIkeCertificate::loadBundle(pem, bundle) != SBOX_OK) {
                return fail(error, "invalid CA bundle '" + ca + "'");
            }

            c.caCertificates.insert(c.caCertificates.end(), bundle.begin(), bundle.end());
        }

        const CJson& users = json.get("users");
        for (size_t i = 0; i < users.size(); ++i) {
            const CJson& u = users.at(i);
            SIkeUser user;
            user.name = u.get("name").asString();
            user.password = u.get("password").asString();
            user.address = u.get("address").asString();
            if (const CJson* h = u.find("ntHash")) {
                if (!ipsec::FromHex(h->asString(), user.ntHash) || user.ntHash.size() != 16) {
                    return fail(error, "user '" + user.name + "': ntHash must be 32 hex digits");
                }
            }

            if (user.name.empty() || (user.password.empty() && user.ntHash.empty())) {
                return fail(error, "every user needs a name and a password (or ntHash)");
            }

            net::SIpAddress fixed;
            if (!user.address.empty() && net::SIpAddress::parse(user.address, fixed) != SBOX_OK) {
                return fail(error, "user '" + user.name + "': bad address");
            }

            c.users.push_back(std::move(user));
        }

        const CJson& psk = json.get("psk");
        if (psk.isString()) {
            SIkePsk p;
            p.secret = psk.asString();
            c.psks.push_back(p);
        }
        else {
            for (size_t i = 0; i < psk.size(); ++i) {
                SIkePsk p;
                p.id = psk.at(i).get("id").asString();
                p.secret = psk.at(i).get("secret").asString();
                if (p.secret.empty()) {
                    return fail(error, "psk entries need a secret");
                }

                c.psks.push_back(p);
            }
        }

        if (const CJson* pool = json.find("pool")) {
            if (net::SIpPrefix::parse(pool->asString(), c.pool) != SBOX_OK || !c.pool.address.isV4()) {
                return fail(error, "pool must be an IPv4 prefix");
            }
        }

        for (const std::string& d : strings(json.get("dns"))) {
            net::SIpAddress a;
            if (net::SIpAddress::parse(d, a) != SBOX_OK) {
                return fail(error, "bad dns address '" + d + "'");
            }

            c.dns.push_back(a);
        }

        for (const std::string& d : strings(json.get("nbns"))) {
            net::SIpAddress a;
            if (net::SIpAddress::parse(d, a) != SBOX_OK) {
                return fail(error, "bad nbns address '" + d + "'");
            }

            c.nbns.push_back(a);
        }

        c.dnsDomain = json.get("dnsDomain").asString();

        for (const std::string& r : strings(json.get("routes"))) {
            net::SIpPrefix p;
            if (net::SIpPrefix::parse(r, p) != SBOX_OK) {
                return fail(error, "bad route '" + r + "'");
            }

            c.routes.push_back(p.network());
        }

        for (const std::string& r : strings(json.get("remoteSubnets"))) {
            net::SIpPrefix p;
            if (net::SIpPrefix::parse(r, p) != SBOX_OK) {
                return fail(error, "bad remote subnet '" + r + "'");
            }

            c.remoteSubnets.push_back(p.network());
        }

        for (const std::string& text : strings(json.get("ike"))) {
            SIkeProposal p;
            if (ParseIkeProposal(text, EIKE_PROTO_IKE, p) != SBOX_OK) {
                return fail(error, "bad IKE proposal '" + text + "'");
            }

            c.ikeProposals.push_back(p);
        }

        for (const std::string& text : strings(json.get("esp"))) {
            SIkeProposal p;
            if (ParseIkeProposal(text, EIKE_PROTO_ESP, p) != SBOX_OK) {
                return fail(error, "bad ESP proposal '" + text + "'");
            }

            c.espProposals.push_back(p);
        }

        std::string kind = json.get("dataPath").asString();
        if (kind.empty() || kind == "auto") {
            c.dataPath.kind = EIDP_AUTO;
        }
        else if (kind == "kernel" || kind == "xfrm") {
            c.dataPath.kind = EIDP_KERNEL;
        }
        else if (kind == "user" || kind == "userspace") {
            c.dataPath.kind = EIDP_USER;
        }
        else {
            return fail(error, "dataPath must be auto, kernel or user");
        }

        if (const CJson* name = json.find("interface")) {
            c.dataPath.interfaceName = name->asString();
        }

        c.dataPath.mtu = uint32_t(json.get("mtu").asInt(1400));
        c.bridge = json.get("bridge").asString();
        c.forwarding = json.get("forwarding").asBool(true);
        c.dpdSeconds = uint32_t(json.get("dpd").asInt(30));
        c.ikeLifetimeSeconds = uint32_t(json.get("ikeLifetime").asInt(86400));
        c.halfOpenSeconds = uint32_t(json.get("halfOpenTimeout").asInt(60));
        c.cookieThreshold = uint32_t(json.get("cookieThreshold").asInt(64));
        c.retransmitTries = uint32_t(json.get("retransmitTries").asInt(5));
        c.retransmitBaseMs = uint32_t(json.get("retransmitBase").asInt(2000));
        c.maxSessions = uint32_t(json.get("maxSessions").asInt(1024));
        c.fragmentSize = size_t(json.get("fragmentSize").asInt(1280));
        c.forceEncap = json.get("forceEncap").asBool(false);
        c.mobike = json.get("mobike").asBool(true);

        if (c.fragmentSize < 576 || c.fragmentSize > 65000) {
            return fail(error, "fragmentSize must be between 576 and 65000");
        }

        if (!c.users.empty() && !c.certificate.hasPrivateKey()) {
            return fail(error, "EAP users need 'certificate' and 'key'");
        }

        if (c.users.empty() && c.psks.empty() && c.caCertificates.empty()) {
            return fail(error, "configure at least one of users, psk or ca");
        }

        out = std::move(c);
        return SBOX_OK;
    }

}
}
