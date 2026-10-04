#ifndef __INCLUDE_SBOX_HTTP_PROXY_HPP__
#define __INCLUDE_SBOX_HTTP_PROXY_HPP__

#include <sbox/common.hpp>
#include <sbox/http/url.hpp>

namespace sbox {
namespace http {

    /**
     * Forward proxy settings of a client.
     *
     * Plain http targets go through `httpProxy` with absolute-form request targets; https
     * targets are tunnelled through `httpsProxy` with CONNECT and the TLS session runs end to
     * end inside the tunnel. Proxies are reached over plain HTTP ("http://[user:pass@]host:port");
     * credentials in the proxy URL are sent as Proxy-Authorization: Basic.
     */
    struct SBOX_API SProxyConfig {
        std::string httpProxy;      // --> Proxy URL for http:// targets, empty for direct.
        std::string httpsProxy;     // --> Proxy URL for https:// targets, empty for direct.
        std::string noProxy;        // --> NO_PROXY list: hosts, domains, IPs, CIDRs, "*".

        /**
         * Reads http_proxy / HTTP_PROXY, https_proxy / HTTPS_PROXY, all_proxy / ALL_PROXY
         * (fallback for both) and no_proxy / NO_PROXY; the lower-case spelling wins.
         */
        static SProxyConfig fromEnvironment();

        /**
         * Returns true when `host` (a name or an IP literal without brackets) must be reached
         * directly according to `noProxy`.
         *
         * Entries are separated by commas or blanks. "*" matches everything; "example.com",
         * ".example.com" and "*.example.com" match that domain and its subdomains; IP literals
         * match exactly and "a.b.c.d/n" or "x::/n" match by prefix; an entry may carry ":port".
         */
        bool bypasses(std::string_view host, uint16_t port) const;

        /**
         * Returns the proxy URL to use for `target`, or an empty string for a direct connection.
         */
        std::string select(const SUrl& target) const;
    };

}
}

#endif
