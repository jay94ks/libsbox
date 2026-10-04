#ifndef __INCLUDE_SBOX_NET_RESOLV_HPP__
#define __INCLUDE_SBOX_NET_RESOLV_HPP__

#include <sbox/common.hpp>
#include <sbox/net/address.hpp>

namespace sbox {
namespace net {

    /**
     * Extra /etc/hosts entry (docker run --add-host).
     */
    struct SHostEntry {
        SIpAddress address;
        std::vector<std::string> names;
    };

    /**
     * Generates a container's /etc/hosts the way Docker does: the localhost lines (IPv6 lines
     * only when `ipv6`), the extra entries, then each container address mapped to the host name
     * (and its aliases).
     */
    SBOX_API std::string GenerateHosts(std::string_view hostname, const std::vector<SIpAddress>& addresses,
        const std::vector<SHostEntry>& extra = std::vector<SHostEntry>(),
        const std::vector<std::string>& aliases = std::vector<std::string>(), bool ipv6 = true);

    /**
     * Generates a resolv.conf from its parts (nameserver lines, one search line, one options line).
     */
    SBOX_API std::string GenerateResolvConf(const std::vector<SIpAddress>& nameservers,
        const std::vector<std::string>& search = std::vector<std::string>(),
        const std::vector<std::string>& options = std::vector<std::string>());

    /**
     * Parsed resolv.conf.
     */
    struct SResolvConf {
        std::vector<SIpAddress> nameservers;
        std::vector<std::string> search;
        std::vector<std::string> options;
    };

    /**
     * Parses resolv.conf text (unknown lines are ignored).
     */
    SBOX_API SResolvConf ParseResolvConf(std::string_view text);

    /**
     * Derives a container's resolv.conf from the host's, like Docker: loopback nameservers
     * (127.0.0.53 of systemd-resolved, ::1) are unreachable from a private network namespace and
     * are dropped; when nothing is left, Google's public resolvers are used (IPv6 ones only when
     * `ipv6`). With `hostNetwork` the host file is kept as is. Explicit `dns`, `search` and
     * `options` replace the host's values (docker run --dns/--dns-search/--dns-option).
     */
    SBOX_API std::string ContainerResolvConf(std::string_view hostResolvConf, bool hostNetwork, bool ipv6 = false,
        const std::vector<SIpAddress>& dns = std::vector<SIpAddress>(),
        const std::vector<std::string>& search = std::vector<std::string>(),
        const std::vector<std::string>& options = std::vector<std::string>());

}
}

#endif
