#ifndef __INCLUDE_SBOX_NET_RTNL_HPP__
#define __INCLUDE_SBOX_NET_RTNL_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/net/netlink.hpp>

namespace sbox {
namespace net {

    /**
     * Interface as reported by RTM_GETLINK.
     */
    struct SLinkInfo {
        int32_t index = 0;
        std::string name;
        std::string kind;           // --> IFLA_INFO_KIND ("bridge", "veth", "macvlan"), empty for physical.
        uint32_t flags = 0;         // --> IFF_* bits.
        uint32_t mtu = 0;
        SMacAddress mac;
        int32_t master = 0;         // --> Index of the bridge (or bond) the link is enslaved to.
        int32_t link = 0;           // --> IFLA_LINK: parent (macvlan) or peer (veth) index.
        int32_t linkNetnsId = -1;   // --> IFLA_LINK_NETNSID when the parent/peer lives elsewhere.
        uint8_t operState = 0;      // --> IF_OPER_* value.

        /** Returns true when IFF_UP is set. */
        bool isUp() const noexcept;
    };

    /**
     * Interface address as reported by RTM_GETADDR.
     */
    struct SAddressInfo {
        int32_t index = 0;
        SIpPrefix prefix;           // --> The address with its prefix length.
        uint8_t scope = 0;
        uint32_t flags = 0;         // --> IFA_F_* bits.
        std::string label;
    };

    /**
     * Route (RTM_NEWROUTE / RTM_GETROUTE). A destination with length 0 is the default route.
     */
    struct SRouteInfo {
        SIpPrefix destination;
        SIpAddress gateway;         // --> Unset for directly connected (link scope) routes.
        SIpAddress source;          // --> RTA_PREFSRC, optional.
        int32_t oif = 0;            // --> Output interface index, optional when a gateway is set.
        uint32_t table = 254;       // --> RT_TABLE_MAIN.
        uint32_t metric = 0;
        uint8_t protocol = 4;       // --> RTPROT_STATIC.
        uint8_t scope = 0;          // --> RT_SCOPE_UNIVERSE; link scope is chosen when no gateway.
        uint8_t type = 1;           // --> RTN_UNICAST.
        uint32_t mtu = 0;           // --> RTAX_MTU metric, optional.
    };

    /**
     * Neighbour (ARP / NDP) entry.
     */
    struct SNeighbourInfo {
        int32_t index = 0;
        SIpAddress address;
        SMacAddress mac;
        uint16_t state = 0;         // --> NUD_* bits.
    };

    /**
     * macvlan mode (IFLA_MACVLAN_MODE values).
     */
    enum EMacvlanMode : uint32_t {
        EMVM_PRIVATE  = 1,          // --> No traffic between macvlans on the same parent.
        EMVM_VEPA     = 2,          // --> Traffic between macvlans goes out to the switch.
        EMVM_BRIDGE   = 4,          // --> Macvlans on the same parent talk directly (Docker default).
        EMVM_PASSTHRU = 8,          // --> One macvlan takes over the parent.
    };

    /**
     * ipvlan mode (IFLA_IPVLAN_MODE values).
     */
    enum EIpvlanMode : uint16_t {
        EIVM_L2  = 0,
        EIVM_L3  = 1,
        EIVM_L3S = 2,
    };

    /**
     * Parameters of a VXLAN device.
     */
    struct SVxlanConfig {
        uint32_t vni = 0;
        SIpAddress local;           // --> Source address, optional.
        SIpAddress remote;          // --> Unicast remote or multicast group, optional.
        int32_t parentIndex = 0;    // --> Underlay device, optional.
        uint16_t port = 4789;
        uint8_t ttl = 0;
        bool learning = true;
        uint32_t mtu = 0;
    };

    /**
     * Generic description of a link to create; the typed helpers of CRtnl fill it.
     */
    struct SLinkSpec {
        std::string name;
        std::string kind;
        uint32_t mtu = 0;
        SMacAddress mac;
        int32_t parentIndex = 0;    // --> IFLA_LINK (macvlan/ipvlan parent).
        int netnsFd = -1;           // --> Create directly in this namespace (IFLA_NET_NS_FD).
        int32_t masterIndex = 0;
        bool up = false;
    };

    /**
     * rtnetlink client bound to one network namespace.
     *
     * Every operation is a coroutine on the calling thread's CEventLoop and returns SBOX_OK or a
     * negated errno; the kernel's extended ACK text of the last failure is in lastError().
     */
    class SBOX_API CRtnl {
    private:
        CNetlinkSocket _socket;

    public:
        CRtnl() = default;

        /**
         * Opens the NETLINK_ROUTE socket in `netnsPath` (empty: the current namespace).
         */
        int32_t open(const std::string& netnsPath = std::string()) noexcept;

        /**
         * Opens the socket in the namespace referred to by `netnsFd`.
         */
        int32_t openIn(int netnsFd) noexcept;

        /** Returns the underlying socket. */
        inline CNetlinkSocket& socket() noexcept { return _socket; }

        /** Returns the kernel's message for the last failure. */
        inline const std::string& lastError() const noexcept { return _socket.lastError(); }

        // -- Links.

        /**
         * Lists every link of the namespace.
         */
        TTask<int32_t> listLinks(std::vector<SLinkInfo>& out);

        /**
         * Looks a link up by name (-ENODEV when absent).
         */
        TTask<int32_t> getLink(std::string name, SLinkInfo& out);

        /**
         * Looks a link up by index (-ENODEV when absent).
         */
        TTask<int32_t> getLinkByIndex(int32_t index, SLinkInfo& out);

        /**
         * Returns the index of a link (> 0) or -ENODEV.
         */
        TTask<int32_t> linkIndex(std::string name);

        /**
         * Creates a link from a generic description.
         */
        TTask<int32_t> createLink(SLinkSpec spec);

        /**
         * Creates a Linux bridge.
         */
        TTask<int32_t> createBridge(std::string name, uint32_t mtu = 0, SMacAddress mac = SMacAddress());

        /**
         * Creates a veth pair. The peer can be created directly in another namespace.
         * @param peerNetnsFd Namespace for the peer, or -1 to keep it here.
         */
        TTask<int32_t> createVeth(std::string name, std::string peerName, int peerNetnsFd = -1, uint32_t mtu = 0);

        /**
         * Creates a macvlan device on `parentIndex` (optionally directly in another namespace).
         */
        TTask<int32_t> createMacvlan(std::string name, int32_t parentIndex, EMacvlanMode mode, int netnsFd = -1,
            uint32_t mtu = 0, SMacAddress mac = SMacAddress());

        /**
         * Creates an ipvlan device on `parentIndex` (optionally directly in another namespace).
         */
        TTask<int32_t> createIpvlan(std::string name, int32_t parentIndex, EIpvlanMode mode, int netnsFd = -1,
            uint32_t mtu = 0);

        /**
         * Creates a VXLAN device.
         */
        TTask<int32_t> createVxlan(std::string name, SVxlanConfig config);

        /**
         * Creates a dummy device (-EOPNOTSUPP when the kernel lacks it).
         */
        TTask<int32_t> createDummy(std::string name);

        /**
         * Sets the administrative state.
         */
        TTask<int32_t> setUp(int32_t index, bool up = true);

        /**
         * Sets the MTU.
         */
        TTask<int32_t> setMtu(int32_t index, uint32_t mtu);

        /**
         * Sets the MAC address.
         */
        TTask<int32_t> setMac(int32_t index, SMacAddress mac);

        /**
         * Enslaves a link to a bridge (`masterIndex` 0 releases it).
         */
        TTask<int32_t> setMaster(int32_t index, int32_t masterIndex);

        /**
         * Moves a link into the namespace referred to by `netnsFd`.
         * @param newName Name to give the link while it moves (empty: keep the name).
         */
        TTask<int32_t> moveToNetnsFd(int32_t index, int netnsFd, std::string newName = std::string());

        /**
         * Moves a link into the namespace of process `pid`.
         */
        TTask<int32_t> moveToNetnsPid(int32_t index, pid_t pid);

        /**
         * Renames a link (it must be down).
         */
        TTask<int32_t> rename(int32_t index, std::string name);

        /**
         * Deletes a link (deleting one veth end removes the pair).
         */
        TTask<int32_t> deleteLink(int32_t index);

        /**
         * Sets bridge port flags of an enslaved link (hairpin, isolated).
         */
        TTask<int32_t> setBridgePort(int32_t index, bool hairpin, bool isolated);

        // -- Addresses.

        /**
         * Adds an address. IPv6 addresses are added with IFA_F_NODAD so they work at once.
         * @param replace Replace an existing identical address instead of failing with -EEXIST.
         */
        TTask<int32_t> addAddress(int32_t index, SIpPrefix address, bool replace = false);

        /**
         * Removes an address.
         */
        TTask<int32_t> delAddress(int32_t index, SIpPrefix address);

        /**
         * Lists addresses, optionally only of one family (AF_INET/AF_INET6) and one link.
         */
        TTask<int32_t> listAddresses(std::vector<SAddressInfo>& out, int family = 0, int32_t index = 0);

        // -- Routes.

        /**
         * Adds a route (or replaces one when `replace`).
         */
        TTask<int32_t> addRoute(SRouteInfo route, bool replace = false);

        /**
         * Deletes a route.
         */
        TTask<int32_t> delRoute(SRouteInfo route);

        /**
         * Lists routes of one family in one table (0 for every table).
         */
        TTask<int32_t> listRoutes(std::vector<SRouteInfo>& out, int family, uint32_t table = 254);

        /**
         * Adds a default route via `gateway` (optionally pinned to `oif`).
         */
        TTask<int32_t> addDefaultRoute(SIpAddress gateway, int32_t oif = 0, bool replace = false);

        // -- Neighbours.

        /**
         * Adds or replaces a neighbour entry (permanent when `permanent`).
         */
        TTask<int32_t> setNeighbour(int32_t index, SIpAddress address, SMacAddress mac, bool permanent = true);

        /**
         * Lists neighbour entries of a family.
         */
        TTask<int32_t> listNeighbours(std::vector<SNeighbourInfo>& out, int family);

    private:
        /** Sends an RTM_NEWLINK change for an existing link. */
        TTask<int32_t> changeLink(CNlMessage& msg);
    };

    /**
     * Options of CreateTunTap().
     */
    struct STunTapOptions {
        bool tap = false;           // --> TAP (Ethernet frames) instead of TUN (IP packets).
        bool persistent = false;    // --> Keep the device after the descriptor closes.
        bool multiQueue = false;
        int64_t owner = -1;         // --> uid allowed to attach, or -1.
        int64_t group = -1;         // --> gid allowed to attach, or -1.
        std::string netnsPath;      // --> Namespace to create the device in (empty: current).
    };

    /**
     * Creates (or attaches to) a TUN/TAP device through /dev/net/tun.
     * @param name Requested name ("tun%d" style patterns allowed, empty for kernel default).
     * @param out Receives the descriptor (non-blocking) carrying the packets.
     * @param actualName Receives the name the kernel chose when not null.
     */
    SBOX_API int32_t CreateTunTap(const std::string& name, const STunTapOptions& options, CFd& out, std::string* actualName = nullptr) noexcept;

}
}

#endif
