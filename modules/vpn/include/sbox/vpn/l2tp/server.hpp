#ifndef __INCLUDE_SBOX_VPN_L2TP_SERVER_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_SERVER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <sbox/vpn/l2tp/l2tp.hpp>
#include <sbox/vpn/l2tp/ppp.hpp>
#include <sbox/vpn/l2tp/transport.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> L2TP/IPsec server for the clients built into Windows, macOS/iOS and Android: IKEv1 (PSK)
// negotiates ESP transport mode for UDP 1701, the L2TP LNS accepts tunnels and calls, PPP
// authenticates users (MS-CHAPv2 by default) and assigns addresses from a pool, and client IP
// traffic appears on one TUN device whose routes lead into the host or a container network.

namespace sbox {
namespace vpn {

    /**
     * Server configuration.
     */
    struct SL2tpServerConfig {
        // -- Transport.
        std::string listenAddress;              // --> Empty: all addresses.
        uint16_t ikePort = 500;
        uint16_t natPort = 4500;
        uint16_t l2tpPort = 1701;               // --> UDP port of L2TP (kernel/plain transports bind it).
        bool ipv6 = false;
        std::string netnsPath;                  // --> Namespace of the sockets, SAs and the TUN device.
        EL2tpTransportKind dataPath = EL2TK_AUTO;

        // -- IPsec.
        SIkev1Config ike;                       // --> PSKs, algorithms, DPD, lifetimes, forceEncap.

        // -- L2TP.
        SL2tpTunnelConfig tunnel;               // --> Host name, tunnel secret, HELLO interval.
        uint32_t maxTunnels = 1024;

        // -- PPP.
        std::vector<SPppUser> users;
        std::vector<EPppAuth> auth = { EPPPA_MSCHAPV2 };
        uint16_t mru = 1400;
        uint32_t echoSeconds = 30;
        net::SIpPrefix pool;                    // --> Client addresses; the first host is our PPP address.
        std::vector<net::SIpAddress> dns;
        std::vector<net::SIpAddress> nbns;

        // -- Network attachment.
        std::string interfaceName = "l2tp0";    // --> TUN device carrying client traffic.
        uint32_t mtu = 1400;
        std::vector<net::SIpPrefix> routes;     // --> Extra prefixes routed into the TUN device (rarely needed).
        std::string bridge;                     // --> Proxy ARP on this bridge for pool addresses.
        bool forwarding = true;                 // --> Enable net.ipv4.ip_forward in the namespace.
        uint32_t idleSeconds = 0;               // --> Disconnect sessions without traffic (0: never).
        uint32_t maxSessions = 1024;
    };

    /**
     * Parses a JSON configuration (schema in docs/vpn-l2tp.md); relative paths resolve against
     * `baseDir`.
     * @return SBOX_OK or -EINVAL (with `error`).
     */
    SBOX_API int32_t ParseL2tpServerConfig(const CJson& json, SL2tpServerConfig& out, std::string* error = nullptr,
                                           const std::string& baseDir = std::string());

    /**
     * Snapshot of one PPP session.
     */
    struct SL2tpSessionInfo {
        std::string user;
        std::string address;                // --> Assigned client address.
        std::string remote;                 // --> Outer peer address.
        std::string identity;               // --> IKE identity (empty without IPsec).
        std::string auth;
        uint16_t tunnelId = 0;
        uint16_t sessionId = 0;
        int64_t upMs = 0;                   // --> Monotonic time the link came up (0: negotiating).
        uint64_t inPackets = 0;
        uint64_t outPackets = 0;
        uint64_t inBytes = 0;
        uint64_t outBytes = 0;
    };

    /**
     * L2TP/IPsec server bound to the calling thread's event loop.
     */
    class SBOX_API CL2tpServer {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CL2tpServer(SL2tpServerConfig config);

        ~CL2tpServer();

        CL2tpServer(const CL2tpServer&) = delete;

        CL2tpServer& operator=(const CL2tpServer&) = delete;

        /** Installs the log sink. */
        void logger(std::function<void(EIkeLogLevel, const std::string&)> sink);

        /**
         * Starts serving.
         * @param shared An IKEv2 responder already listening on UDP 500/4500: IKEv1 arrives
         *        through its ikev1Handler() and replies leave through its sockets (null: open
         *        our own sockets).
         * @return SBOX_OK or a negated errno.
         */
        TTask<int32_t> start(CIkeServer* shared = nullptr);

        /** Disconnects everybody (CDN, StopCCN, DELETE) and stops. */
        TTask<void> stop();

        /** Returns the PPP sessions. */
        std::vector<SL2tpSessionInfo> sessions() const;

        /** Returns the ISAKMP SAs. */
        std::vector<SIkev1SessionInfo> ikeSessions() const;

        /**
         * Disconnects the sessions of a user name or client address.
         * @return Number of sessions closed.
         */
        int32_t disconnect(const std::string& userOrAddress);

        /** Returns the TUN device name (after start). */
        std::string interfaceName() const;

        /** Returns the transport kind ("kernel", "user", "plain"). */
        std::string dataPath() const;

        /** Returns the bound IKE port (0 when shared or not started). */
        uint16_t ikePort() const noexcept;

        /** Returns the bound NAT-T port. */
        uint16_t natPort() const noexcept;

        /** Returns the bound L2TP UDP port (kernel/plain transports). */
        uint16_t l2tpPort() const noexcept;
    };

}
}

#endif
