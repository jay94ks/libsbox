#include <sbox/net/resolv.hpp>
#include <sbox/core/file.hpp>

namespace sbox {
namespace net {

    namespace {

        /* Splits a line into whitespace separated fields. */
        std::vector<std::string_view> fields(std::string_view line) {
            std::vector<std::string_view> out;
            size_t i = 0;

            while (i < line.size()) {
                while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
                    ++i;
                }

                size_t start = i;
                while (i < line.size() && line[i] != ' ' && line[i] != '\t') {
                    ++i;
                }

                if (i > start) {
                    out.push_back(line.substr(start, i - start));
                }
            }

            return out;
        }

    }

    /* Generates /etc/hosts. */
    std::string GenerateHosts(std::string_view hostname, const std::vector<SIpAddress>& addresses,
        const std::vector<SHostEntry>& extra, const std::vector<std::string>& aliases, bool ipv6)
    {
        std::string out = "127.0.0.1\tlocalhost\n";
        if (ipv6) {
            out += "::1\tlocalhost ip6-localhost ip6-loopback\n"
                   "fe00::0\tip6-localnet\n"
                   "ff00::0\tip6-mcastprefix\n"
                   "ff02::1\tip6-allnodes\n"
                   "ff02::2\tip6-allrouters\n";
        }

        for (const SHostEntry& e : extra) {
            if (!e.address.isValid() || e.names.empty()) {
                continue;
            }

            out += e.address.toString();
            out += '\t';
            for (size_t i = 0; i < e.names.size(); ++i) {
                if (i) {
                    out += ' ';
                }

                out += e.names[i];
            }

            out += '\n';
        }

        if (!hostname.empty()) {
            for (const SIpAddress& a : addresses) {
                if (!a.isValid() || (a.isV6() && !ipv6)) {
                    continue;
                }

                out += a.toString();
                out += '\t';
                out += hostname;
                for (const std::string& alias : aliases) {
                    if (alias != hostname) {
                        out += ' ';
                        out += alias;
                    }
                }

                out += '\n';
            }
        }

        return out;
    }

    /* Generates resolv.conf. */
    std::string GenerateResolvConf(const std::vector<SIpAddress>& nameservers, const std::vector<std::string>& search,
        const std::vector<std::string>& options)
    {
        std::string out;
        for (const SIpAddress& ns : nameservers) {
            if (ns.isValid()) {
                out += "nameserver " + ns.toString() + "\n";
            }
        }

        if (!search.empty()) {
            out += "search";
            for (const std::string& s : search) {
                out += " " + s;
            }

            out += "\n";
        }

        if (!options.empty()) {
            out += "options";
            for (const std::string& o : options) {
                out += " " + o;
            }

            out += "\n";
        }

        return out;
    }

    /* Parses resolv.conf. */
    SResolvConf ParseResolvConf(std::string_view text) {
        SResolvConf out;

        for (std::string_view line : CFile::splitLines(text)) {
            size_t hash = line.find_first_of("#;");
            if (hash != std::string_view::npos) {
                line = line.substr(0, hash);
            }

            std::vector<std::string_view> f = fields(line);
            if (f.empty()) {
                continue;
            }

            if (f[0] == "nameserver" && f.size() >= 2) {
                // --> Scoped IPv6 nameservers ("fe80::1%eth0") cannot be represented; skip them.
                SIpAddress a;
                if (SIpAddress::parse(f[1], a) == SBOX_OK) {
                    out.nameservers.push_back(a);
                }
            }
            else if (f[0] == "search" || f[0] == "domain") {
                // --> The last search/domain line wins, as in the resolver.
                out.search.clear();
                for (size_t i = 1; i < f.size(); ++i) {
                    out.search.emplace_back(f[i]);
                }
            }
            else if (f[0] == "options") {
                for (size_t i = 1; i < f.size(); ++i) {
                    out.options.emplace_back(f[i]);
                }
            }
        }

        return out;
    }

    /* Derives a container resolv.conf. */
    std::string ContainerResolvConf(std::string_view hostResolvConf, bool hostNetwork, bool ipv6,
        const std::vector<SIpAddress>& dns, const std::vector<std::string>& search, const std::vector<std::string>& options)
    {
        if (hostNetwork && dns.empty() && search.empty() && options.empty()) {
            return std::string(hostResolvConf);
        }

        SResolvConf host = ParseResolvConf(hostResolvConf);
        std::vector<SIpAddress> servers;

        if (!dns.empty()) {
            servers = dns;
        }
        else {
            for (const SIpAddress& a : host.nameservers) {
                if (hostNetwork || (!a.isLoopback() && (ipv6 || !a.isV6()))) {
                    servers.push_back(a);
                }
            }

            if (servers.empty()) {
                static const char* const V4[] = { "8.8.8.8", "8.8.4.4" };
                static const char* const V6[] = { "2001:4860:4860::8888", "2001:4860:4860::8844" };
                for (const char* s : V4) {
                    SIpAddress a;
                    SIpAddress::parse(s, a);
                    servers.push_back(a);
                }

                if (ipv6) {
                    for (const char* s : V6) {
                        SIpAddress a;
                        SIpAddress::parse(s, a);
                        servers.push_back(a);
                    }
                }
            }
        }

        return GenerateResolvConf(servers, search.empty() ? host.search : search, options.empty() ? host.options : options);
    }

}
}
