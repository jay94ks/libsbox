#ifndef __INCLUDE_SBOX_NET_NETWORK_HPP__
#define __INCLUDE_SBOX_NET_NETWORK_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/net/ipam.hpp>
#include <sbox/net/rtnl.hpp>
#include <map>

namespace sbox {
namespace net {

    /**
     * Published port (docker run -p [hostIp:]hostPort:containerPort[/proto]).
     */
    struct SBOX_API SPortMapping {
        uint8_t protocol = 6;       // --> IPPROTO_TCP (6), IPPROTO_UDP (17) or IPPROTO_SCTP (132).
        SIpAddress hostIp;          // --> Unset for every host address.
        uint16_t hostPort = 0;      // --> 0 asks for an ephemeral port (32768-60999).
        uint16_t containerPort = 0;

        /**
         * Parses "[hostIp:]hostPort:containerPort[/tcp|udp|sctp]" or "containerPort[/proto]".
         */
        static int32_t parse(std::string_view text, SPortMapping& out);

        /** Returns "tcp", "udp" or "sctp". */
        std::string protocolName() const;

        /** Serializes the mapping. */
        CJson toJson() const;

        /** Parses a mapping. */
        static int32_t fromJson(const CJson& json, SPortMapping& out);
    };

    /**
     * Subnet requested for a network (docker network create --subnet/--ip-range/--gateway/--aux-address).
     */
    struct SSubnetConfig {
        SIpPrefix subnet;           // --> Unset to let IPAM pick one (per family).
        uint8_t family = 4;         // --> Family to pick when the subnet is unset.
        SIpPrefix ipRange;
        SIpAddress rangeStart;
        SIpAddress rangeEnd;
        SIpAddress gateway;         // --> Unset: first host address (when the driver uses one).
        std::map<std::string, SIpAddress> auxAddresses;
    };

    /**
     * Subnet of an existing network.
     */
    struct SNetworkSubnet {
        SIpPrefix subnet;
        SIpAddress gateway;
        std::string poolId;         // --> IPAM pool; empty when addresses are managed outside.
    };

    /**
     * Request to create a network (docker network create).
     */
    struct SNetworkCreate {
        std::string id;             // --> Fixed id (Docker passes its own); empty for a random one.
        std::string name;
        std::string driver = "bridge";
        std::string ipamDriver = "sbox";    // --> "sbox": IPAM here; "external": caller assigns addresses.
        std::vector<SSubnetConfig> subnets;
        bool enableIpv6 = false;
        bool internal = false;
        std::map<std::string, std::string> options;     // --> Driver options (Docker -o key=value).
        std::map<std::string, std::string> labels;
    };

    /**
     * Network object as persisted in `<state>/networks/<id>.json`.
     */
    struct SBOX_API SNetwork {
        std::string id;
        std::string name;
        std::string driver;
        std::string ipamDriver;
        std::vector<SNetworkSubnet> subnets;
        bool enableIpv6 = false;
        bool internal = false;
        std::map<std::string, std::string> options;
        std::map<std::string, std::string> labels;
        int64_t created = 0;        // --> Unix seconds.
        CJson driverState;          // --> Driver-private data (object), e.g. the bridge name.

        /** Returns an option or `fallback`. */
        std::string option(const std::string& key, const std::string& fallback = std::string()) const;

        /** Returns a boolean option ("true"/"1"/"false"/"0") or `fallback`. */
        bool flag(const std::string& key, bool fallback) const;

        /** Returns the first subnet of a family, or nullptr. */
        const SNetworkSubnet* subnet(uint8_t family) const noexcept;

        /** Serializes the network (Docker-like field names). */
        CJson toJson() const;

        /** Parses a network. */
        static int32_t fromJson(const CJson& json, SNetwork& out);
    };

    /**
     * Request to create an endpoint on a network.
     */
    struct SEndpointCreate {
        std::string id;             // --> Fixed id (Docker EndpointID); empty for a random one.
        std::string containerId;    // --> Owner tag (also the IPAM owner).
        SIpPrefix ipv4;             // --> Requested IPv4 address (prefix ignored), or unset.
        SIpPrefix ipv6;             // --> Requested IPv6 address, or unset.
        SMacAddress mac;            // --> Requested MAC, or unset (derived from IPv4 like Docker).
        std::vector<SPortMapping> ports;
        std::vector<std::string> aliases;
        std::string hostname;       // --> Sent to DHCP servers (option 12).
    };

    /**
     * Endpoint as persisted in `<state>/endpoints/<id>.json`.
     */
    struct SBOX_API SNetworkEndpoint {
        std::string id;
        std::string networkId;
        std::string containerId;
        std::vector<SIpPrefix> addresses;   // --> Interface addresses with the subnet prefix length.
        std::vector<SIpAddress> gateways;   // --> Default gateways (one per family at most).
        SMacAddress mac;
        std::string hostIfName;     // --> Host-side interface (veth end) or the temporary name.
        std::string sandboxIfName;  // --> Name inside the sandbox once joined (eth0, ...).
        std::string netnsPath;      // --> Sandbox namespace once joined.
        std::vector<SPortMapping> ports;
        std::vector<std::string> aliases;
        uint32_t mtu = 0;
        bool joined = false;
        CJson driverState;          // --> Driver-private data (object), e.g. a DHCP lease.

        /** Returns the first address of a family, or an unset prefix. */
        SIpPrefix address(uint8_t family) const noexcept;

        /** Serializes the endpoint. */
        CJson toJson() const;

        /** Parses an endpoint. */
        static int32_t fromJson(const CJson& json, SNetworkEndpoint& out);
    };

    /**
     * What a sandbox needs to wire an endpoint itself (Docker's Join response).
     */
    struct SJoinInfo {
        std::string srcName;        // --> Interface to move into the sandbox.
        std::string dstPrefix = "eth";
        SIpAddress gateway;
        SIpAddress gateway6;
        std::vector<SRouteInfo> staticRoutes;
    };

    /**
     * Shared context handed to drivers by CNetworkManager.
     */
    struct SNetworkContext {
        std::string hostNetns;      // --> Namespace treated as "the host" (empty: current).
        std::string stateDir;
        CRtnl* host = nullptr;      // --> rtnetlink socket in the host namespace.
    };

    /**
     * Network driver: creates the host-side plumbing of networks and endpoints.
     *
     * The lifecycle follows Docker's remote driver: createNetwork, createEndpoint (interface
     * exists in the host namespace), join (interface moved into and configured inside the
     * sandbox namespace), leave, deleteEndpoint, deleteNetwork. Addresses are assigned by
     * CNetworkManager through IPAM before createEndpoint, unless the driver allocates them
     * itself (DHCP). New drivers (the vpn module's overlay) implement this interface and are
     * registered with CNetworkManager::registerDriver().
     */
    class SBOX_API INetworkDriver {
    public:
        virtual ~INetworkDriver() = default;

        /** Returns the driver name ("bridge", "macvlan", ...). */
        virtual std::string name() const = 0;

        /** Returns true when the manager should allocate subnets/addresses through IPAM. */
        virtual bool usesIpam() const { return true; }

        /** Returns true when the network's NAT/filter rules belong in the sbox firewall. */
        virtual bool usesFirewall() const { return false; }

        /** Returns true when the driver wants a gateway address reserved in each subnet. */
        virtual bool usesGateway() const { return true; }

        /**
         * Validates options and creates the network's host-side objects.
         */
        virtual TTask<int32_t> createNetwork(SNetworkContext& ctx, SNetwork& network) = 0;

        /**
         * Removes what createNetwork created.
         */
        virtual TTask<int32_t> deleteNetwork(SNetworkContext& ctx, const SNetwork& network) = 0;

        /**
         * Creates the endpoint's interface in the host namespace (addresses are already set,
         * unless the driver fills them).
         */
        virtual TTask<int32_t> createEndpoint(SNetworkContext& ctx, const SNetwork& network, SNetworkEndpoint& endpoint) = 0;

        /**
         * Moves the interface into `netnsPath` as `ifName` and configures addresses and routes.
         */
        virtual TTask<int32_t> join(SNetworkContext& ctx, const SNetwork& network, SNetworkEndpoint& endpoint,
            std::string netnsPath, std::string ifName) = 0;

        /**
         * Describes how a sandbox manager that moves interfaces itself joins (Docker).
         */
        virtual TTask<int32_t> joinInfo(SNetworkContext& ctx, const SNetwork& network, const SNetworkEndpoint& endpoint, SJoinInfo& out);

        /**
         * Undoes join (the sandbox may already be gone).
         */
        virtual TTask<int32_t> leave(SNetworkContext& ctx, const SNetwork& network, SNetworkEndpoint& endpoint) = 0;

        /**
         * Removes the endpoint's interfaces wherever they are.
         */
        virtual TTask<int32_t> deleteEndpoint(SNetworkContext& ctx, const SNetwork& network, const SNetworkEndpoint& endpoint) = 0;
    };

    using INetworkDriverPtr = std::shared_ptr<INetworkDriver>;

    /**
     * Creates the Linux bridge driver ("bridge").
     */
    SBOX_API INetworkDriverPtr CreateBridgeDriver();

    /**
     * Creates the macvlan driver ("macvlan").
     */
    SBOX_API INetworkDriverPtr CreateMacvlanDriver();

    /**
     * Creates the ipvlan driver ("ipvlan").
     */
    SBOX_API INetworkDriverPtr CreateIpvlanDriver();

    /**
     * Creates the host driver ("host"): the sandbox shares the host namespace.
     */
    SBOX_API INetworkDriverPtr CreateHostDriver();

    /**
     * Creates the null driver ("none"): loopback only.
     */
    SBOX_API INetworkDriverPtr CreateNoneDriver();

    /**
     * Options of CNetworkManager.
     */
    struct SNetworkManagerOptions {
        std::string stateDir;                   // --> Required. Networks, endpoints, IPAM state.
        std::string hostNetns;                  // --> Namespace acting as the host (tests); empty: current.
        std::vector<SAddressPool> pools = DefaultAddressPools();
        bool firewall = true;                   // --> Program the sbox nftables table.
        bool avoidHostRoutes = true;            // --> Dynamic subnets skip prefixes routed on the host.
        std::string firewallTable = "sbox";
    };

    /**
     * Returns the default state directory: /var/lib/sbox/net for root, else
     * $XDG_RUNTIME_DIR/sbox/net (or /tmp/sbox-<uid>/net).
     */
    SBOX_API std::string DefaultNetworkStateDir();

    /**
     * Networks, endpoints and their drivers, persisted Docker-style under a state directory.
     *
     * Every mutating call holds `<state>/net.lock` (flock) for its whole duration, so several
     * processes (CLI, CNI plugin invocations, the Docker plugin daemon) can share one state
     * directory. The firewall table is regenerated from the persisted state after each change.
     */
    class SBOX_API CNetworkManager {
    private:
        SNetworkManagerOptions _options;
        CIpam _ipam;
        std::map<std::string, INetworkDriverPtr> _drivers;
        CRtnl _host;
        bool _hostOpen;

    public:
        /**
         * Creates a manager with the built-in drivers registered.
         */
        explicit CNetworkManager(SNetworkManagerOptions options);

        /** Returns the options. */
        inline const SNetworkManagerOptions& options() const noexcept { return _options; }

        /** Returns the IPAM instance (state in `<state>/ipam`). */
        inline CIpam& ipam() noexcept { return _ipam; }

        /**
         * Registers (or replaces) a driver.
         */
        void registerDriver(INetworkDriverPtr driver);

        /**
         * Returns a driver by name, or nullptr.
         */
        INetworkDriverPtr driver(const std::string& name) const;

        /**
         * Creates a network: allocates subnets (unless ipamDriver is "external"), lets the driver
         * build it and persists it.
         * @return SBOX_OK, -EEXIST (name or id taken), -ENOTSUP (unknown driver), or an error.
         */
        TTask<int32_t> createNetwork(SNetworkCreate request, SNetwork& out);

        /**
         * Deletes a network by id, id prefix or name (-EBUSY while endpoints exist).
         */
        TTask<int32_t> deleteNetwork(std::string idOrName);

        /**
         * Reads a network by id, unique id prefix or name.
         */
        TTask<int32_t> getNetwork(std::string idOrName, SNetwork& out);

        /**
         * Reads every network.
         */
        TTask<int32_t> listNetworks(std::vector<SNetwork>& out);

        /**
         * Creates an endpoint: allocates addresses and the host-side interface.
         */
        TTask<int32_t> createEndpoint(std::string network, SEndpointCreate request, SNetworkEndpoint& out);

        /**
         * Moves an endpoint's interface into a sandbox namespace and configures it.
         * @param ifName Name inside the sandbox; empty picks the next free ethN.
         */
        TTask<int32_t> join(std::string endpointId, std::string netnsPath, std::string ifName, SNetworkEndpoint& out);

        /**
         * Returns the join information for sandboxes that move interfaces themselves (Docker).
         */
        TTask<int32_t> joinInfo(std::string endpointId, SJoinInfo& out);

        /**
         * Undoes join.
         */
        TTask<int32_t> leave(std::string endpointId);

        /**
         * Deletes an endpoint and releases its addresses.
         */
        TTask<int32_t> deleteEndpoint(std::string endpointId);

        /**
         * Reads an endpoint.
         */
        TTask<int32_t> getEndpoint(std::string endpointId, SNetworkEndpoint& out);

        /**
         * Reads the endpoints (of one network when `networkId` is not empty).
         */
        TTask<int32_t> listEndpoints(std::string networkId, std::vector<SNetworkEndpoint>& out);

        /**
         * Replaces the published ports of an endpoint and updates the firewall.
         * Host port 0 is replaced by a free ephemeral port.
         */
        TTask<int32_t> setPortMappings(std::string endpointId, std::vector<SPortMapping> ports);

        /**
         * createEndpoint + join in one call (what the box/oci layers use).
         */
        TTask<int32_t> connect(std::string network, std::string netnsPath, SEndpointCreate request, SNetworkEndpoint& out,
            std::string ifName = std::string());

        /**
         * Leaves and deletes every endpoint of `containerId` on `network` (all networks when empty).
         */
        TTask<int32_t> disconnect(std::string network, std::string containerId);

        /**
         * Regenerates the firewall table from the persisted state.
         */
        TTask<int32_t> syncFirewall();

    private:
        /** Opens the host rtnetlink socket on first use. */
        int32_t hostRtnl(CRtnl*& out) noexcept;

        /** Builds the driver context. */
        int32_t context(SNetworkContext& out) noexcept;

        /** Loads a network by id/prefix/name (lock held). */
        int32_t findNetwork(const std::string& idOrName, SNetwork& out) const;

        /** Loads all networks (lock held). */
        int32_t loadNetworks(std::vector<SNetwork>& out) const;

        /** Loads all endpoints (lock held). */
        int32_t loadEndpoints(std::vector<SNetworkEndpoint>& out) const;

        /** Loads one endpoint (lock held). */
        int32_t loadEndpoint(const std::string& id, SNetworkEndpoint& out) const;

        /** Persists a network. */
        int32_t saveNetwork(const SNetwork& network) const;

        /** Persists an endpoint. */
        int32_t saveEndpoint(const SNetworkEndpoint& endpoint) const;

        /** Releases an endpoint's IPAM addresses. */
        TTask<void> releaseAddresses(const SNetwork& network, const SNetworkEndpoint& endpoint);

        /** Assigns ephemeral host ports (lock held). */
        int32_t assignHostPorts(std::vector<SPortMapping>& ports, const std::string& exceptEndpoint) const;

        /** The bodies of the public calls, run with the lock held. */
        TTask<int32_t> createEndpointLocked(std::string network, SEndpointCreate request, SNetworkEndpoint& out);
        TTask<int32_t> joinLocked(std::string endpointId, std::string netnsPath, std::string ifName, SNetworkEndpoint& out);
        TTask<int32_t> leaveLocked(std::string endpointId);
        TTask<int32_t> deleteEndpointLocked(std::string endpointId);
        TTask<int32_t> syncFirewallLocked();
    };

}
}

#endif
