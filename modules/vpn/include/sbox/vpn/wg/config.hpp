#ifndef __INCLUDE_SBOX_VPN_WG_CONFIG_HPP__
#define __INCLUDE_SBOX_VPN_WG_CONFIG_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/wg/engine.hpp>
#include <sbox/vpn/wg/key.hpp>

namespace sbox {
namespace vpn {

    /**
     * A WireGuard configuration in the INI format of `wg setconf` and `wg-quick` (the format the
     * official Windows, macOS, iOS and Android apps import, from a file or a QR code).
     *
     * `[Interface]` keys of `wg`: PrivateKey, ListenPort, FwMark. Keys only `wg-quick` and the apps
     * understand: Address, DNS, MTU, Table, PreUp, PostUp, PreDown, PostDown, SaveConfig.
     * `[Peer]` keys: PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive.
     */
    struct SWgConfig {
        SWgKey privateKey;
        int32_t listenPort = -1;            // --> -1: not given (random port).
        uint32_t fwmark = 0;                // --> 0: off.
        std::vector<net::SIpPrefix> addresses;
        std::vector<std::string> dns;       // --> Server addresses and search domains, as written.
        uint32_t mtu = 0;
        std::string table;
        std::vector<std::string> preUp;
        std::vector<std::string> postUp;
        std::vector<std::string> preDown;
        std::vector<std::string> postDown;
        bool saveConfig = false;
        std::vector<SWgPeerConfig> peers;   // --> persistentKeepalive is 0 when not given.
    };

    /**
     * Parses a configuration. Keys are case-insensitive, `#` starts a comment, list values are
     * comma separated and list keys may repeat.
     * @param error Receives "line N: reason" on failure when not null.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseWgConfig(std::string_view text, SWgConfig& out, std::string* error = nullptr);

    /**
     * Writes a configuration.
     * @param quick Include the wg-quick keys (Address, DNS, MTU, ...); false gives what
     *        `wg setconf` accepts.
     */
    SBOX_API std::string WriteWgConfig(const SWgConfig& config, bool quick = true);

    /**
     * Resolves peers whose endpoint is a host name (SWgPeerConfig::endpointHost) through
     * ResolveEndpoints, preferring IPv4. Must not run in a process that is about to fork.
     * @return SBOX_OK or the first resolution error.
     */
    SBOX_API TTask<int32_t> ResolveWgConfigEndpoints(SWgConfig& config);

    /**
     * Parses an endpoint as written in a configuration: "1.2.3.4:51820", "[fd00::1]:51820" or
     * "host.name:51820". Numeric endpoints land in `peer.endpoint`, names in `peer.endpointHost`.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseWgEndpoint(std::string_view text, SWgPeerConfig& peer);

    /**
     * What a server operator supplies to provision a road-warrior client.
     */
    struct SWgClientRequest {
        SWgKey serverPublicKey;
        std::string serverEndpoint;             // --> "vpn.example.com:51820" as the client should dial it.
        SWgKey clientPrivateKey;                // --> Unset: a new key is generated.
        std::vector<net::SIpPrefix> clientAddresses;    // --> Tunnel addresses of the client (/32, /128).
        std::vector<std::string> dns;
        std::vector<net::SIpPrefix> allowedIps; // --> Routed through the tunnel; empty: 0.0.0.0/0 and ::/0.
        bool presharedKey = true;               // --> Generate a preshared key for post-quantum hedging.
        uint16_t persistentKeepalive = 25;      // --> Keeps NAT mappings of mobile clients alive.
        uint32_t mtu = 0;
    };

    /**
     * The result of GenerateWgClientConfig().
     */
    struct SWgClientBundle {
        SWgConfig client;           // --> The client's configuration.
        SWgPeerConfig serverPeer;   // --> The [Peer] the server adds for this client.
        std::string text;           // --> The client configuration as compact text (fits a QR code).
    };

    /**
     * Builds a client configuration for the official WireGuard apps, plus the matching server-side
     * peer entry.
     * @return SBOX_OK, -EINVAL (missing server key, endpoint or client address) or a key error.
     */
    SBOX_API int32_t GenerateWgClientConfig(const SWgClientRequest& request, SWgClientBundle& out);

}
}

#endif
