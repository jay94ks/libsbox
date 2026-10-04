#ifndef __INCLUDE_SBOX_VPN_WG_OVERLAY_HPP__
#define __INCLUDE_SBOX_VPN_WG_OVERLAY_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/network.hpp>
#include <sbox/vpn/wg/device.hpp>
#include <map>

namespace sbox {
namespace vpn {

    /** Name the overlay driver registers under. */
    constexpr const char* WG_OVERLAY_DRIVER = "wg-overlay";

    /** Network option carrying the overlay configuration (JSON text, see SWgOverlayConfig). */
    constexpr const char* WG_OVERLAY_OPTION = "sbox.wg.overlay";

    /** Network option naming a file with the overlay configuration instead. */
    constexpr const char* WG_OVERLAY_FILE_OPTION = "sbox.wg.overlay.file";

    /**
     * Another host of an overlay network: a WireGuard peer that owns one subnet of the network.
     */
    struct SBOX_API SWgOverlayHost {
        std::string name;               // --> Free-form label ("host-b").
        SWgKey publicKey;
        SWgKey presharedKey;            // --> Optional.
        std::string endpoint;           // --> "address:port" or "name:port" of its WireGuard socket.
        net::SIpPrefix subnet;          // --> Its container subnet (inside the network's subnet).
        uint16_t persistentKeepalive = 0;

        /** Serializes the host. */
        CJson toJson() const;

        /** Parses a host. @return SBOX_OK or -EINVAL. */
        static int32_t fromJson(const CJson& json, SWgOverlayHost& out);
    };

    /**
     * Static configuration of this host's part of an overlay network.
     *
     * JSON form (network option `sbox.wg.overlay`, or a file named by `sbox.wg.overlay.file`):
     * {"privateKey","listenPort","hostSubnet","interface","bridge","mode","mtu","nat",
     *  "peers":[{"name","publicKey","presharedKey","endpoint","subnet","persistentKeepalive"}]}
     */
    struct SBOX_API SWgOverlayConfig {
        SWgKey privateKey;
        uint16_t listenPort = WG_DEFAULT_PORT;
        net::SIpPrefix hostSubnet;          // --> This host's container subnet.
        std::string interfaceName;          // --> WireGuard interface; empty: "wgo-" + 8 id characters.
        std::string bridgeName;             // --> Container bridge; empty: "wgb-" + 8 id characters.
        EWgMode mode = EWGM_AUTO;
        uint32_t mtu = 0;                   // --> Tunnel MTU; 0: 1500 - WG_OVERHEAD.
        bool nat = true;                    // --> Masquerade container traffic leaving the overlay.
        std::vector<SWgOverlayHost> peers;

        /**
         * Serializes the configuration.
         * @param withPrivateKey False leaves the private key out (what the network object keeps).
         */
        CJson toJson(bool withPrivateKey = true) const;

        /** Parses a configuration. @return SBOX_OK or -EINVAL. */
        static int32_t fromJson(const CJson& json, SWgOverlayConfig& out);
    };

    /**
     * Fills a network creation request for an overlay: the network's subnet is the whole overlay
     * range, IPAM hands out addresses only from this host's subnet (`--ip-range`), and the
     * gateway is the first address of this host's subnet (the local bridge).
     * @return SBOX_OK or -EINVAL (host subnet missing or outside the overlay).
     */
    SBOX_API int32_t MakeWgOverlayNetwork(const std::string& name, const net::SIpPrefix& overlay, const SWgOverlayConfig& config,
        net::SNetworkCreate& out);

    /**
     * Options of the overlay driver.
     */
    struct SWgOverlayDriverOptions {
        std::string uapiDir = WG_UAPI_DIR;  // --> Where user-space devices serve their UAPI socket.
        SWgTimers timers;
    };

    /**
     * Network driver "wg-overlay": a network spanning several hosts, joined by WireGuard.
     *
     * Each host runs one WireGuard interface per overlay network in its host namespace (kernel
     * module or user space) whose peers are the other hosts, each owning a subnet of the network.
     * Local containers sit on a Linux bridge holding the gateway address of this host's subnet and
     * join with veth pairs like the bridge driver. Routes to the other hosts' subnets point at the
     * WireGuard interface, so container-to-container traffic is routed (not bridged) across hosts
     * and encrypted on the way. Optional NAT masquerades traffic leaving the overlay.
     *
     * The peer list is static configuration: given at network creation and changed at run time
     * with addHost()/removeHost(). Automatic discovery is not part of this driver.
     *
     * A user-space device lives on the event loop of the process that created (or restore()d)
     * the network; other processes reach it through its UAPI socket.
     */
    class SBOX_API CWgOverlayDriver : public net::INetworkDriver {
    private:
        SWgOverlayDriverOptions _options;
        std::map<std::string, std::unique_ptr<CWgDevice>> _devices;     // --> By network id.

    public:
        /**
         * Creates a driver (register it with CNetworkManager::registerDriver).
         */
        explicit CWgOverlayDriver(SWgOverlayDriverOptions options = SWgOverlayDriverOptions());

        ~CWgOverlayDriver() override;

        /** Returns "wg-overlay". */
        std::string name() const override;

        /** IPAM allocates container addresses (from this host's range). */
        bool usesIpam() const override { return true; }

        /** NAT lives in the driver's own nftables table. */
        bool usesFirewall() const override { return false; }

        /** The gateway is the bridge address. */
        bool usesGateway() const override { return true; }

        /**
         * Validates the configuration, creates the bridge, the WireGuard interface, the routes
         * and the NAT rule, and moves the private key into the driver's state file.
         */
        TTask<int32_t> createNetwork(net::SNetworkContext& ctx, net::SNetwork& network) override;

        /**
         * Removes the interface, the bridge, the NAT table and the state file.
         */
        TTask<int32_t> deleteNetwork(net::SNetworkContext& ctx, const net::SNetwork& network) override;

        /**
         * Creates a veth pair on the bridge; addresses must lie in this host's subnet.
         */
        TTask<int32_t> createEndpoint(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& endpoint) override;

        /**
         * Moves the veth end into the sandbox: addresses, a route to the whole overlay and the
         * default route via the bridge.
         */
        TTask<int32_t> join(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& endpoint,
            std::string netnsPath, std::string ifName) override;

        /**
         * Reports the overlay route as a static route for Docker-style joins.
         */
        TTask<int32_t> joinInfo(net::SNetworkContext& ctx, const net::SNetwork& network, const net::SNetworkEndpoint& endpoint,
            net::SJoinInfo& out) override;

        /**
         * Moves the interface back to the host namespace.
         */
        TTask<int32_t> leave(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& endpoint) override;

        /**
         * Deletes the veth pair.
         */
        TTask<int32_t> deleteEndpoint(net::SNetworkContext& ctx, const net::SNetwork& network, const net::SNetworkEndpoint& endpoint) override;

        // -- Run-time management.

        /**
         * Adds a host (or updates the one with the same public key) to a running overlay network.
         * @return SBOX_OK, -ENOENT (no such network), -EINVAL (bad host / subnet), -ENOTCONN (the
         *         user-space device runs nowhere reachable), or another error.
         */
        TTask<int32_t> addHost(net::CNetworkManager& manager, std::string network, SWgOverlayHost host);

        /**
         * Removes a host from a running overlay network.
         */
        TTask<int32_t> removeHost(net::CNetworkManager& manager, std::string network, SWgKey publicKey);

        /**
         * Reads the configuration of an overlay network (private key included).
         */
        TTask<int32_t> config(net::CNetworkManager& manager, std::string network, SWgOverlayConfig& out);

        /**
         * Reads the WireGuard device of an overlay network.
         */
        TTask<int32_t> status(net::CNetworkManager& manager, std::string network, SWgDeviceStatus& out);

        /**
         * Starts the WireGuard devices of every overlay network whose device is missing (after a
         * reboot, or when the process that ran a user-space device exited).
         * @return The number of devices started, or an error.
         */
        TTask<int32_t> restore(net::CNetworkManager& manager);

    private:
        /** Brings up (or adopts) the WireGuard device of a network and programs peers and routes. */
        TTask<int32_t> startDevice(const std::string& hostNetns, const net::SNetwork& network, const SWgOverlayConfig& config);

        /** Applies a device change wherever the device runs (this process, kernel, UAPI). */
        TTask<int32_t> applyDevice(const std::string& hostNetns, const std::string& networkId, const SWgOverlayConfig& config,
            SWgDeviceConfig change);
    };

}
}

#endif
