#include <sbox/http/proxy.hpp>
#include <sbox/http/headers.hpp>
#include "lex.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace sbox {
namespace http {

    namespace {

        /*
         * Returns the first non-empty environment variable of the two spellings.
         */
        std::string envOf(const char* lower, const char* upper) {
            const char* v = std::getenv(lower);
            if (v && *v) {
                return v;
            }

            v = std::getenv(upper);
            return (v && *v) ? std::string(v) : std::string();
        }

        /**
         * Parsed IP address of either family.
         */
        struct IpAddr {
            int family = 0;
            uint8_t bytes[16] = {};
        };

        bool parseIp(std::string_view text, IpAddr& out) {
            std::string s(text);
            if (::inet_pton(AF_INET, s.c_str(), out.bytes) == 1) {
                out.family = AF_INET;
                return true;
            }

            if (::inet_pton(AF_INET6, s.c_str(), out.bytes) == 1) {
                out.family = AF_INET6;
                return true;
            }

            return false;
        }

        /*
         * Compares the first `bits` bits of two addresses of the same family.
         */
        bool prefixMatch(const IpAddr& a, const IpAddr& b, uint32_t bits) {
            uint32_t total = a.family == AF_INET ? 32 : 128;
            if (a.family != b.family || bits > total) {
                return false;
            }

            uint32_t full = bits / 8;
            if (full > 0 && std::memcmp(a.bytes, b.bytes, full) != 0) {
                return false;
            }

            uint32_t rest = bits % 8;
            if (rest == 0) {
                return true;
            }

            uint8_t mask = uint8_t(0xff << (8 - rest));
            return (a.bytes[full] & mask) == (b.bytes[full] & mask);
        }

        /*
         * Matches one NO_PROXY entry (lower case, port already split off).
         */
        bool entryMatches(std::string_view entry, const std::string& host, const IpAddr* hostIp) {
            if (entry == "*") {
                return true;
            }

            size_t slash = entry.find('/');
            if (slash != std::string_view::npos) {
                IpAddr net;
                if (!hostIp || !parseIp(entry.substr(0, slash), net)) {
                    return false;
                }

                std::string_view bitsText = entry.substr(slash + 1);
                if (bitsText.empty() || bitsText.size() > 3) {
                    return false;
                }

                uint32_t bits = 0;
                for (char c : bitsText) {
                    if (c < '0' || c > '9') {
                        return false;
                    }

                    bits = bits * 10 + uint32_t(c - '0');
                }

                return prefixMatch(*hostIp, net, bits);
            }

            IpAddr ip;
            if (parseIp(entry, ip)) {
                return hostIp && hostIp->family == ip.family
                    && std::memcmp(hostIp->bytes, ip.bytes, ip.family == AF_INET ? 4 : 16) == 0;
            }

            if (entry.substr(0, 2) == "*.") {
                entry.remove_prefix(2);
            } else if (!entry.empty() && entry[0] == '.') {
                entry.remove_prefix(1);
            }

            if (entry.empty()) {
                return false;
            }

            if (host == entry) {
                return true;
            }

            return host.size() > entry.size() && host.compare(host.size() - entry.size(), entry.size(), entry) == 0
                && host[host.size() - entry.size() - 1] == '.';
        }

    }

    /* Reads proxy settings from the environment. */
    SProxyConfig SProxyConfig::fromEnvironment() {
        SProxyConfig cfg;
        std::string all = envOf("all_proxy", "ALL_PROXY");

        cfg.httpProxy = envOf("http_proxy", "HTTP_PROXY");
        cfg.httpsProxy = envOf("https_proxy", "HTTPS_PROXY");
        cfg.noProxy = envOf("no_proxy", "NO_PROXY");

        if (cfg.httpProxy.empty()) {
            cfg.httpProxy = all;
        }

        if (cfg.httpsProxy.empty()) {
            cfg.httpsProxy = all;
        }

        return cfg;
    }

    /* Checks NO_PROXY. */
    bool SProxyConfig::bypasses(std::string_view hostIn, uint16_t port) const {
        std::string host = lex::Lower(hostIn);
        while (!host.empty() && host.back() == '.') {
            host.pop_back();
        }

        IpAddr hostIp;
        bool isIp = parseIp(host, hostIp);

        size_t pos = 0;
        while (pos < noProxy.size()) {
            size_t end = noProxy.find_first_of(", \t", pos);
            if (end == std::string::npos) {
                end = noProxy.size();
            }

            std::string entry = lex::Lower(std::string_view(noProxy).substr(pos, end - pos));
            pos = end + 1;

            if (entry.empty()) {
                continue;
            }

            // --> Split an optional ":port" ("[v6]:port", "host:port"; a bare IPv6 has several colons).
            int32_t entryPort = -1;
            if (entry[0] == '[') {
                size_t close = entry.find(']');
                if (close == std::string::npos) {
                    continue;
                }

                std::string rest = entry.substr(close + 1);
                if (rest.size() > 1 && rest[0] == ':') {
                    entryPort = std::atoi(rest.c_str() + 1);
                }

                entry = entry.substr(1, close - 1);
            } else if (std::count(entry.begin(), entry.end(), ':') == 1) {
                size_t colon = entry.find(':');
                entryPort = std::atoi(entry.c_str() + colon + 1);
                entry.resize(colon);
            }

            if (entryPort >= 0 && entryPort != port) {
                continue;
            }

            if (entryMatches(entry, host, isIp ? &hostIp : nullptr)) {
                return true;
            }
        }

        return false;
    }

    /* Selects the proxy for a target. */
    std::string SProxyConfig::select(const SUrl& target) const {
        const std::string& proxy = target.scheme == "https" ? httpsProxy : (target.scheme == "http" ? httpProxy : std::string());
        if (proxy.empty() || target.host.empty()) {
            return {};
        }

        return bypasses(target.host, target.effectivePort()) ? std::string() : proxy;
    }

}
}
