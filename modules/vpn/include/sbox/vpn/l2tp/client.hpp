#ifndef __INCLUDE_SBOX_VPN_L2TP_CLIENT_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_CLIENT_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <sbox/vpn/l2tp/ppp.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> L2TP/IPsec client (IKEv1 initiator + user-space ESP transport mode + L2TP LAC + PPP peer
// + TUN), used by the end-to-end tests and usable to connect a host to an L2TP/IPsec server.

namespace sbox {
namespace vpn {

    /**
     * Client configuration.
     */
    struct SL2tpClientConfig {
        std::string server;                     // --> Server IP address.
        uint16_t ikePort = 500;
        uint16_t natPort = 4500;
        uint16_t l2tpPort = 1701;
        uint16_t localIkePort = 0;              // --> 0: ephemeral.
        uint16_t localNatPort = 0;
        std::string netnsPath;                  // --> Namespace of the sockets and the TUN device.
        bool ipsec = true;                      // --> false: plain L2TP over UDP (tests).
        SIkev1Config ike;                       // --> psks[0] is our PSK; identity, suites, esp, pfs.
        std::string user;
        std::string password;
        std::vector<EPppAuth> auth = { EPPPA_MSCHAPV2, EPPPA_CHAP_MD5, EPPPA_PAP };
        std::string hostName = "sbox-l2tp-client";
        bool createInterface = true;            // --> Create a TUN device with the assigned address.
        std::string interfaceName = "l2tpc0";
        uint32_t mtu = 1400;
        std::vector<net::SIpPrefix> routes;     // --> Prefixes routed through the tunnel.
        uint32_t timeoutMs = 20000;
    };

    /**
     * L2TP/IPsec client bound to the calling thread's event loop.
     */
    class SBOX_API CL2tpClient {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CL2tpClient(SL2tpClientConfig config);

        ~CL2tpClient();

        CL2tpClient(const CL2tpClient&) = delete;

        CL2tpClient& operator=(const CL2tpClient&) = delete;

        /** Installs the log sink. */
        void logger(std::function<void(EIkeLogLevel, const std::string&)> sink);

        /**
         * Connects (IKEv1, L2TP, PPP) and, when configured, brings up the TUN device.
         * @return SBOX_OK, -ETIMEDOUT, -EACCES (authentication), -ECONNREFUSED, or another error.
         */
        TTask<int32_t> connect();

        /** Disconnects (PPP terminate, CDN, StopCCN, IKE DELETE) and releases everything. */
        TTask<void> disconnect();

        /** Returns true while the link is up. */
        bool isUp() const noexcept;

        /** Returns the negotiated PPP parameters. */
        SPppInfo info() const;

        /** Returns the TUN device name (empty without one). */
        std::string interfaceName() const;

        /** Returns a description of the last failure. */
        std::string lastError() const;

        /** Returns true when IKE runs over NAT-T. */
        bool natT() const noexcept;

        /**
         * Sends an IPv4 packet through the link (without a TUN device).
         */
        int32_t sendIp(const SReadOnlyByteSpan& packet);

        /** Receives IPv4 packets from the link when no TUN device is used. */
        void onIp(std::function<void(const SReadOnlyByteSpan&)> handler);
    };

}
}

#endif
