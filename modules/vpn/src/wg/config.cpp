#include <sbox/vpn/wg/config.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>

namespace sbox {
namespace vpn {

    namespace {

        /* Trims ASCII whitespace. */
        std::string_view trim(std::string_view s) {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
                s.remove_prefix(1);
            }

            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
                s.remove_suffix(1);
            }

            return s;
        }

        /* Lowercases ASCII. */
        std::string lower(std::string_view s) {
            std::string out(s);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

        /* Splits a comma separated list, dropping empty items. */
        std::vector<std::string> splitList(std::string_view value) {
            std::vector<std::string> out;
            while (!value.empty()) {
                size_t comma = value.find(',');
                std::string_view item = trim(value.substr(0, comma));
                if (!item.empty()) {
                    out.emplace_back(item);
                }

                if (comma == std::string_view::npos) {
                    break;
                }

                value.remove_prefix(comma + 1);
            }

            return out;
        }

        /* Parses an unsigned decimal (or 0x hex) number. */
        bool parseNumber(std::string_view text, uint64_t max, uint64_t& out) {
            if (text.empty()) {
                return false;
            }

            std::string s(text);
            char* end = nullptr;
            errno = 0;
            unsigned long long v = std::strtoull(s.c_str(), &end, 0);
            if (errno != 0 || end == s.c_str() || *end != 0 || v > max || s[0] == '-') {
                return false;
            }

            out = v;
            return true;
        }

        /* Parses a list of prefixes. */
        bool parsePrefixes(std::string_view value, std::vector<net::SIpPrefix>& out) {
            for (const std::string& item : splitList(value)) {
                net::SIpPrefix p;
                if (net::SIpPrefix::parse(item, p) != SBOX_OK) {
                    return false;
                }

                out.push_back(p);
            }

            return true;
        }

        /* Joins prefixes with ", ". */
        std::string joinPrefixes(const std::vector<net::SIpPrefix>& list) {
            std::string out;
            for (size_t i = 0; i < list.size(); ++i) {
                if (i) {
                    out += ", ";
                }

                out += list[i].toString();
            }

            return out;
        }

        /* Joins strings with ", ". */
        std::string joinStrings(const std::vector<std::string>& list) {
            std::string out;
            for (size_t i = 0; i < list.size(); ++i) {
                if (i) {
                    out += ", ";
                }

                out += list[i];
            }

            return out;
        }

        /* Formats a peer's endpoint as written in a configuration. */
        std::string endpointText(const SWgPeerConfig& peer) {
            if (peer.endpoint.isValid()) {
                return peer.endpoint.toString();
            }

            return peer.endpointHost;
        }

    }

    /* Parses "host:port", "[v6]:port" or "v4:port". */
    int32_t ParseWgEndpoint(std::string_view text, SWgPeerConfig& peer) {
        text = trim(text);
        size_t colon = text.rfind(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 >= text.size()) {
            return -EINVAL;
        }

        uint64_t port = 0;
        if (!parseNumber(text.substr(colon + 1), 65535, port)) {
            return -EINVAL;
        }

        std::string_view host = text.substr(0, colon);
        if (host.front() == '[') {
            if (host.back() != ']') {
                return -EINVAL;
            }

            host = host.substr(1, host.size() - 2);
        }
        else if (host.find(':') != std::string_view::npos) {
            // --> An IPv6 address needs brackets.
            return -EINVAL;
        }

        SEndpoint ep;
        if (SEndpoint::fromIp(host, uint16_t(port), ep) == SBOX_OK) {
            peer.endpoint = ep;
            peer.endpointHost.clear();
            return SBOX_OK;
        }

        for (char c : host) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
            if (!ok) {
                return -EINVAL;
            }
        }

        peer.endpoint = SEndpoint();
        peer.endpointHost = std::string(text);
        return SBOX_OK;
    }

    /* Parses an INI configuration. */
    int32_t ParseWgConfig(std::string_view text, SWgConfig& out, std::string* error) {
        out = SWgConfig();
        enum { NONE, INTERFACE, PEER } section = NONE;
        size_t lineNo = 0;

        auto fail = [&](const std::string& why) {
            if (error) {
                *error = "line " + std::to_string(lineNo) + ": " + why;
            }

            return -EINVAL;
        };

        while (!text.empty()) {
            size_t nl = text.find('\n');
            std::string_view line = text.substr(0, nl);
            text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
            ++lineNo;

            size_t hash = line.find('#');
            if (hash != std::string_view::npos) {
                line = line.substr(0, hash);
            }

            line = trim(line);
            if (line.empty()) {
                continue;
            }

            if (line.front() == '[') {
                std::string name = lower(line);
                if (name == "[interface]") {
                    section = INTERFACE;
                }
                else if (name == "[peer]") {
                    section = PEER;
                    out.peers.emplace_back();
                    out.peers.back().persistentKeepalive = 0;
                }
                else {
                    return fail("unknown section " + std::string(line));
                }

                continue;
            }

            size_t eq = line.find('=');
            if (eq == std::string_view::npos) {
                return fail("expected key = value");
            }

            std::string key = lower(trim(line.substr(0, eq)));
            std::string_view value = trim(line.substr(eq + 1));

            if (section == INTERFACE) {
                if (key == "privatekey") {
                    if (SWgKey::fromBase64(value, out.privateKey) != SBOX_OK) {
                        return fail("invalid PrivateKey");
                    }
                }
                else if (key == "listenport") {
                    uint64_t v = 0;
                    if (!parseNumber(value, 65535, v)) {
                        return fail("invalid ListenPort");
                    }

                    out.listenPort = int32_t(v);
                }
                else if (key == "fwmark") {
                    uint64_t v = 0;
                    if (lower(value) == "off") {
                        v = 0;
                    }
                    else if (!parseNumber(value, 0xffffffffull, v)) {
                        return fail("invalid FwMark");
                    }

                    out.fwmark = uint32_t(v);
                }
                else if (key == "address") {
                    if (!parsePrefixes(value, out.addresses)) {
                        return fail("invalid Address");
                    }
                }
                else if (key == "dns") {
                    for (const std::string& d : splitList(value)) {
                        out.dns.push_back(d);
                    }
                }
                else if (key == "mtu") {
                    uint64_t v = 0;
                    if (!parseNumber(value, 65535, v) || v < 576) {
                        return fail("invalid MTU");
                    }

                    out.mtu = uint32_t(v);
                }
                else if (key == "table") {
                    out.table = std::string(value);
                }
                else if (key == "preup") {
                    out.preUp.emplace_back(value);
                }
                else if (key == "postup") {
                    out.postUp.emplace_back(value);
                }
                else if (key == "predown") {
                    out.preDown.emplace_back(value);
                }
                else if (key == "postdown") {
                    out.postDown.emplace_back(value);
                }
                else if (key == "saveconfig") {
                    out.saveConfig = lower(value) == "true";
                }
                else {
                    return fail("unknown Interface key " + key);
                }
            }
            else if (section == PEER) {
                SWgPeerConfig& peer = out.peers.back();
                if (key == "publickey") {
                    if (SWgKey::fromBase64(value, peer.publicKey) != SBOX_OK) {
                        return fail("invalid PublicKey");
                    }
                }
                else if (key == "presharedkey") {
                    if (SWgKey::fromBase64(value, peer.presharedKey) != SBOX_OK) {
                        return fail("invalid PresharedKey");
                    }
                }
                else if (key == "allowedips") {
                    if (!parsePrefixes(value, peer.allowedIps)) {
                        return fail("invalid AllowedIPs");
                    }
                }
                else if (key == "endpoint") {
                    if (ParseWgEndpoint(value, peer) != SBOX_OK) {
                        return fail("invalid Endpoint");
                    }
                }
                else if (key == "persistentkeepalive") {
                    uint64_t v = 0;
                    if (lower(value) == "off") {
                        v = 0;
                    }
                    else if (!parseNumber(value, 65535, v)) {
                        return fail("invalid PersistentKeepalive");
                    }

                    peer.persistentKeepalive = int32_t(v);
                }
                else {
                    return fail("unknown Peer key " + key);
                }
            }
            else {
                return fail("key outside of a section");
            }
        }

        for (size_t i = 0; i < out.peers.size(); ++i) {
            if (!out.peers[i].publicKey.valid) {
                return fail("peer " + std::to_string(i + 1) + " has no PublicKey");
            }
        }

        return SBOX_OK;
    }

    /* Writes an INI configuration. */
    std::string WriteWgConfig(const SWgConfig& config, bool quick) {
        std::string out = "[Interface]\n";
        if (config.privateKey.valid) {
            out += "PrivateKey = " + config.privateKey.toBase64() + "\n";
        }

        if (config.listenPort >= 0) {
            out += "ListenPort = " + std::to_string(config.listenPort) + "\n";
        }

        if (config.fwmark) {
            out += "FwMark = " + std::to_string(config.fwmark) + "\n";
        }

        if (quick) {
            if (!config.addresses.empty()) {
                out += "Address = " + joinPrefixes(config.addresses) + "\n";
            }

            if (!config.dns.empty()) {
                out += "DNS = " + joinStrings(config.dns) + "\n";
            }

            if (config.mtu) {
                out += "MTU = " + std::to_string(config.mtu) + "\n";
            }

            if (!config.table.empty()) {
                out += "Table = " + config.table + "\n";
            }

            for (const std::string& s : config.preUp) {
                out += "PreUp = " + s + "\n";
            }

            for (const std::string& s : config.postUp) {
                out += "PostUp = " + s + "\n";
            }

            for (const std::string& s : config.preDown) {
                out += "PreDown = " + s + "\n";
            }

            for (const std::string& s : config.postDown) {
                out += "PostDown = " + s + "\n";
            }

            if (config.saveConfig) {
                out += "SaveConfig = true\n";
            }
        }

        for (const SWgPeerConfig& peer : config.peers) {
            out += "\n[Peer]\n";
            out += "PublicKey = " + peer.publicKey.toBase64() + "\n";
            if (peer.presharedKey.valid && !peer.presharedKey.isZero()) {
                out += "PresharedKey = " + peer.presharedKey.toBase64() + "\n";
            }

            if (!peer.allowedIps.empty()) {
                out += "AllowedIPs = " + joinPrefixes(peer.allowedIps) + "\n";
            }

            std::string ep = endpointText(peer);
            if (!ep.empty()) {
                out += "Endpoint = " + ep + "\n";
            }

            if (peer.persistentKeepalive > 0) {
                out += "PersistentKeepalive = " + std::to_string(peer.persistentKeepalive) + "\n";
            }
        }

        return out;
    }

    /* Resolves host-name endpoints. */
    TTask<int32_t> ResolveWgConfigEndpoints(SWgConfig& config) {
        for (SWgPeerConfig& peer : config.peers) {
            if (peer.endpoint.isValid() || peer.endpointHost.empty()) {
                continue;
            }

            size_t colon = peer.endpointHost.rfind(':');
            std::string host = peer.endpointHost.substr(0, colon);
            uint16_t port = uint16_t(std::strtoul(peer.endpointHost.c_str() + colon + 1, nullptr, 10));

            std::vector<SEndpoint> found;
            int32_t r = co_await ResolveEndpoints(host, port, found);
            if (r != SBOX_OK) {
                co_return r;
            }

            if (found.empty()) {
                co_return -EHOSTUNREACH;
            }

            peer.endpoint = found[0];
            for (const SEndpoint& ep : found) {
                if (ep.family() == AF_INET) {
                    peer.endpoint = ep;
                    break;
                }
            }
        }

        co_return SBOX_OK;
    }

    /* Builds a client configuration and the server's peer entry. */
    int32_t GenerateWgClientConfig(const SWgClientRequest& request, SWgClientBundle& out) {
        if (!request.serverPublicKey.valid || request.serverEndpoint.empty() || request.clientAddresses.empty()) {
            return -EINVAL;
        }

        out = SWgClientBundle();
        SWgConfig& c = out.client;
        c.privateKey = request.clientPrivateKey;
        if (!c.privateKey.valid) {
            int32_t r = GenerateWgPrivateKey(c.privateKey);
            if (r != SBOX_OK) {
                return r;
            }
        }

        SWgKey clientPublic;
        int32_t r = DeriveWgPublicKey(c.privateKey, clientPublic);
        if (r != SBOX_OK) {
            return r;
        }

        c.addresses = request.clientAddresses;
        c.dns = request.dns;
        c.mtu = request.mtu;

        SWgKey psk;
        if (request.presharedKey) {
            r = GenerateWgPresharedKey(psk);
            if (r != SBOX_OK) {
                return r;
            }
        }

        SWgPeerConfig server;
        server.publicKey = request.serverPublicKey;
        server.presharedKey = psk;
        r = ParseWgEndpoint(request.serverEndpoint, server);
        if (r != SBOX_OK) {
            return r;
        }

        server.allowedIps = request.allowedIps;
        if (server.allowedIps.empty()) {
            net::SIpPrefix all4, all6;
            net::SIpPrefix::parse("0.0.0.0/0", all4);
            net::SIpPrefix::parse("::/0", all6);
            server.allowedIps = { all4, all6 };
        }

        server.persistentKeepalive = request.persistentKeepalive;
        c.peers.push_back(server);

        // --> The server routes exactly the client's tunnel addresses to it.
        SWgPeerConfig& sp = out.serverPeer;
        sp.publicKey = clientPublic;
        sp.presharedKey = psk;
        sp.persistentKeepalive = 0;
        for (const net::SIpPrefix& a : request.clientAddresses) {
            sp.allowedIps.push_back(net::SIpPrefix(a.address, uint8_t(a.address.bits())));
        }

        out.text = WriteWgConfig(c, true);
        return SBOX_OK;
    }

}
}
