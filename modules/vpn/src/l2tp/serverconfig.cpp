#include <sbox/vpn/l2tp/server.hpp>
#include "ipsec/crypto.hpp"
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

        /* A string or a list of strings. */
        std::vector<std::string> strings(const CJson& value) {
            if (value.isString()) {
                return { value.asString() };
            }

            return value.asStrings();
        }

        /* Reads a non-negative integer with bounds. */
        bool number(const CJson& json, const char* key, int64_t fallback, int64_t lo, int64_t hi, int64_t& out) {
            const CJson* v = json.find(key);
            if (!v) {
                out = fallback;
                return true;
            }

            if (!v->isNumber()) {
                return false;
            }

            out = v->asInt(fallback);
            return out >= lo && out <= hi;
        }

    }

    /* Parses the JSON configuration. */
    int32_t ParseL2tpServerConfig(const CJson& json, SL2tpServerConfig& out, std::string* error, const std::string& baseDir) {
        (void)baseDir;
        if (!json.isObject()) {
            return fail(error, "configuration must be a JSON object");
        }

        static const char* KNOWN[] = {
            "listen", "ikePort", "natPort", "l2tpPort", "ipv6", "netns", "dataPath", "psk", "ike", "esp", "forceEncap", "dpd",
            "phase1Lifetime", "phase2Lifetime", "hostName", "tunnelSecret", "hello", "users", "auth", "mru", "echo", "pool", "dns",
            "nbns", "interface", "mtu", "routes", "bridge", "forwarding", "idleTimeout", "maxSessions", "maxTunnels", "comment",
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

        SL2tpServerConfig c;
        c.listenAddress = json.get("listen").asString();
        c.ipv6 = json.get("ipv6").asBool(false);
        c.netnsPath = json.get("netns").asString();

        int64_t v = 0;
        if (!number(json, "ikePort", 500, 0, 65535, v)) {
            return fail(error, "ikePort must be a port number");
        }

        c.ikePort = uint16_t(v);
        if (!number(json, "natPort", 4500, 0, 65535, v)) {
            return fail(error, "natPort must be a port number");
        }

        c.natPort = uint16_t(v);
        if (!number(json, "l2tpPort", 1701, 0, 65535, v)) {
            return fail(error, "l2tpPort must be a port number");
        }

        c.l2tpPort = uint16_t(v);

        if (const CJson* dp = json.find("dataPath")) {
            if (!ParseL2tpTransportKind(dp->asString(), c.dataPath)) {
                return fail(error, "dataPath must be auto, kernel, user or none");
            }
        }

        // -- IPsec.
        const CJson& psk = json.get("psk");
        if (psk.isString()) {
            SIkePsk p;
            p.secret = psk.asString();
            c.ike.psks.push_back(p);
        }
        else {
            for (size_t i = 0; i < psk.size(); ++i) {
                SIkePsk p;
                p.id = psk.at(i).get("id").asString();
                p.secret = psk.at(i).get("secret").asString();
                if (p.secret.empty()) {
                    return fail(error, "psk entries need a secret");
                }

                c.ike.psks.push_back(p);
            }
        }

        for (const SIkePsk& p : c.ike.psks) {
            if (p.secret.empty()) {
                return fail(error, "the pre-shared key must not be empty");
            }
        }

        for (const std::string& text : strings(json.get("ike"))) {
            if (ParseIkev1Proposal(text, c.ike.suites) != SBOX_OK) {
                return fail(error, "bad IKE proposal '" + text + "'");
            }
        }

        for (const std::string& text : strings(json.get("esp"))) {
            if (ParseIkev1EspProposal(text, c.ike.esp) != SBOX_OK) {
                return fail(error, "bad ESP proposal '" + text + "'");
            }
        }

        c.ike.forceEncap = json.get("forceEncap").asBool(false);
        if (!number(json, "dpd", 30, 0, 3600, v)) {
            return fail(error, "dpd must be 0..3600 seconds");
        }

        c.ike.dpdSeconds = uint32_t(v);
        if (!number(json, "phase1Lifetime", 28800, 60, 604800, v)) {
            return fail(error, "phase1Lifetime must be 60..604800 seconds");
        }

        c.ike.phase1LifeSeconds = uint32_t(v);
        if (!number(json, "phase2Lifetime", 3600, 60, 86400, v)) {
            return fail(error, "phase2Lifetime must be 60..86400 seconds");
        }

        c.ike.phase2LifeSeconds = uint32_t(v);

        // -- L2TP.
        if (const CJson* h = json.find("hostName")) {
            c.tunnel.hostName = h->asString();
        }

        c.tunnel.secret = json.get("tunnelSecret").asString();
        if (!number(json, "hello", 60, 0, 3600, v)) {
            return fail(error, "hello must be 0..3600 seconds");
        }

        c.tunnel.helloSeconds = uint32_t(v);

        // -- PPP.
        const CJson& users = json.get("users");
        for (size_t i = 0; i < users.size(); ++i) {
            const CJson& u = users.at(i);
            SPppUser user;
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
            if (!user.address.empty() && (net::SIpAddress::parse(user.address, fixed) != SBOX_OK || !fixed.isV4())) {
                return fail(error, "user '" + user.name + "': bad address");
            }

            c.users.push_back(std::move(user));
        }

        if (c.users.empty()) {
            return fail(error, "configure at least one user");
        }

        if (json.find("auth")) {
            c.auth.clear();
            for (const std::string& a : strings(json.get("auth"))) {
                EPppAuth method;
                if (!ParsePppAuth(a, method)) {
                    return fail(error, "auth must list mschapv2, chap or pap");
                }

                c.auth.push_back(method);
            }

            if (c.auth.empty()) {
                return fail(error, "auth must not be empty");
            }
        }

        for (EPppAuth a : c.auth) {
            if (a != EPPPA_CHAP_MD5) {
                continue;
            }

            for (const SPppUser& u : c.users) {
                if (u.password.empty()) {
                    return fail(error, "CHAP-MD5 needs clear-text passwords (user '" + u.name + "' has only ntHash)");
                }
            }
        }

        if (!number(json, "mru", 1400, 576, 1500, v)) {
            return fail(error, "mru must be 576..1500");
        }

        c.mru = uint16_t(v);
        if (!number(json, "echo", 30, 0, 3600, v)) {
            return fail(error, "echo must be 0..3600 seconds");
        }

        c.echoSeconds = uint32_t(v);

        if (net::SIpPrefix::parse(json.get("pool").asString(), c.pool) != SBOX_OK || !c.pool.address.isV4() || c.pool.length > 30) {
            return fail(error, "pool must be an IPv4 prefix of /30 or larger");
        }

        c.pool = c.pool.network();
        for (const std::string& d : strings(json.get("dns"))) {
            net::SIpAddress a;
            if (net::SIpAddress::parse(d, a) != SBOX_OK || !a.isV4()) {
                return fail(error, "bad dns address '" + d + "'");
            }

            c.dns.push_back(a);
        }

        for (const std::string& d : strings(json.get("nbns"))) {
            net::SIpAddress a;
            if (net::SIpAddress::parse(d, a) != SBOX_OK || !a.isV4()) {
                return fail(error, "bad nbns address '" + d + "'");
            }

            c.nbns.push_back(a);
        }

        for (const SPppUser& u : c.users) {
            net::SIpAddress fixed;
            if (!u.address.empty() && net::SIpAddress::parse(u.address, fixed) == SBOX_OK && !c.pool.contains(fixed)) {
                return fail(error, "user '" + u.name + "': address outside the pool");
            }
        }

        // -- Network attachment.
        if (const CJson* name = json.find("interface")) {
            c.interfaceName = name->asString();
            if (c.interfaceName.empty() || c.interfaceName.size() > 15) {
                return fail(error, "interface must be 1..15 characters");
            }
        }

        if (!number(json, "mtu", 1400, 576, 1500, v)) {
            return fail(error, "mtu must be 576..1500");
        }

        c.mtu = uint32_t(v);
        for (const std::string& r : strings(json.get("routes"))) {
            net::SIpPrefix p;
            if (net::SIpPrefix::parse(r, p) != SBOX_OK) {
                return fail(error, "bad route '" + r + "'");
            }

            c.routes.push_back(p.network());
        }

        c.bridge = json.get("bridge").asString();
        c.forwarding = json.get("forwarding").asBool(true);
        if (!number(json, "idleTimeout", 0, 0, 86400 * 7, v)) {
            return fail(error, "idleTimeout must be 0..604800 seconds");
        }

        c.idleSeconds = uint32_t(v);
        if (!number(json, "maxSessions", 1024, 1, 65535, v)) {
            return fail(error, "maxSessions must be 1..65535");
        }

        c.maxSessions = uint32_t(v);
        if (!number(json, "maxTunnels", 1024, 1, 65535, v)) {
            return fail(error, "maxTunnels must be 1..65535");
        }

        c.maxTunnels = uint32_t(v);

        if (c.dataPath != EL2TK_PLAIN && c.ike.psks.empty()) {
            return fail(error, "psk is required (or dataPath \"none\" without IPsec)");
        }

        out = std::move(c);
        return SBOX_OK;
    }

}
}
