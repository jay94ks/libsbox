#include <sbox/net/rtnl.hpp>
#include <sbox/net/netns.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace net {

    namespace {

        /* Builds an RTM_*LINK message with an ifinfomsg for `index`. */
        CNlMessage linkMessage(uint16_t type, uint16_t flags, int32_t index) {
            CNlMessage msg(type, flags);
            ifinfomsg ifi;
            std::memset(&ifi, 0, sizeof(ifi));
            ifi.ifi_family = AF_UNSPEC;
            ifi.ifi_index = index;
            msg.putHeader(&ifi, sizeof(ifi));
            return msg;
        }

        /* Parses an RTM_NEWLINK reply. */
        bool parseLink(const SNlReply& reply, SLinkInfo& out) {
            if (reply.type != RTM_NEWLINK || reply.payload.size() < sizeof(ifinfomsg)) {
                return false;
            }

            ifinfomsg ifi;
            std::memcpy(&ifi, reply.payload.data(), sizeof(ifi));

            SLinkInfo info;
            info.index = ifi.ifi_index;
            info.flags = ifi.ifi_flags;

            CNlAttrs attrs = reply.attrs(sizeof(ifinfomsg));
            info.name = attrs.str(IFLA_IFNAME);
            info.mtu = attrs.u32(IFLA_MTU);
            info.master = int32_t(attrs.u32(IFLA_MASTER));
            info.link = int32_t(attrs.u32(IFLA_LINK));

            if (const SNlAttr* a = attrs.find(IFLA_LINK_NETNSID)) {
                info.linkNetnsId = int32_t(a->u32());
            }

            if (const SNlAttr* a = attrs.find(IFLA_OPERSTATE)) {
                info.operState = a->u8();
            }

            if (const SNlAttr* a = attrs.find(IFLA_ADDRESS)) {
                if (a->length == 6) {
                    info.mac = SMacAddress::fromBytes(a->data);
                }
            }

            if (const SNlAttr* a = attrs.find(IFLA_LINKINFO)) {
                info.kind = CNlAttrs::nested(*a).str(IFLA_INFO_KIND);
            }

            out = std::move(info);
            return true;
        }

        /* Returns true when the name fits IFNAMSIZ. */
        bool validName(const std::string& name) noexcept {
            return !name.empty() && name.size() < IFNAMSIZ && name.find('/') == std::string::npos
                && name.find(' ') == std::string::npos;
        }

    }

    /* Returns true when the link is up. */
    bool SLinkInfo::isUp() const noexcept {
        return (flags & IFF_UP) != 0;
    }

    /* Opens the socket in a namespace given by path. */
    int32_t CRtnl::open(const std::string& netnsPath) noexcept {
        return _socket.open(NETLINK_ROUTE, netnsPath);
    }

    /* Opens the socket in a namespace given by descriptor. */
    int32_t CRtnl::openIn(int netnsFd) noexcept {
        return _socket.openIn(NETLINK_ROUTE, netnsFd);
    }

    /* Lists links. */
    TTask<int32_t> CRtnl::listLinks(std::vector<SLinkInfo>& out) {
        CNlMessage msg = linkMessage(RTM_GETLINK, 0, 0);
        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const SNlReply& reply : replies) {
            SLinkInfo info;
            if (parseLink(reply, info)) {
                out.push_back(std::move(info));
            }
        }

        co_return SBOX_OK;
    }

    /* Looks a link up by name. */
    TTask<int32_t> CRtnl::getLink(std::string name, SLinkInfo& out) {
        if (!validName(name)) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_GETLINK, 0, 0);
        msg.putString(IFLA_IFNAME, name);

        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.request(msg, &replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const SNlReply& reply : replies) {
            if (parseLink(reply, out)) {
                co_return SBOX_OK;
            }
        }

        co_return -ENODEV;
    }

    /* Looks a link up by index. */
    TTask<int32_t> CRtnl::getLinkByIndex(int32_t index, SLinkInfo& out) {
        CNlMessage msg = linkMessage(RTM_GETLINK, 0, index);
        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.request(msg, &replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const SNlReply& reply : replies) {
            if (parseLink(reply, out)) {
                co_return SBOX_OK;
            }
        }

        co_return -ENODEV;
    }

    /* Returns the index of a link. */
    TTask<int32_t> CRtnl::linkIndex(std::string name) {
        SLinkInfo info;
        int32_t r = co_await getLink(std::move(name), info);
        co_return r == SBOX_OK ? info.index : r;
    }

    /* Creates a link from a description. */
    TTask<int32_t> CRtnl::createLink(SLinkSpec spec) {
        if (!validName(spec.name) || spec.kind.empty()) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0);
        msg.putString(IFLA_IFNAME, spec.name);

        if (spec.mtu) {
            msg.putU32(IFLA_MTU, spec.mtu);
        }

        if (spec.mac.isValid()) {
            msg.put(IFLA_ADDRESS, spec.mac.bytes, 6);
        }

        if (spec.parentIndex) {
            msg.putU32(IFLA_LINK, uint32_t(spec.parentIndex));
        }

        if (spec.masterIndex) {
            msg.putU32(IFLA_MASTER, uint32_t(spec.masterIndex));
        }

        if (spec.netnsFd >= 0) {
            msg.putU32(IFLA_NET_NS_FD, uint32_t(spec.netnsFd));
        }

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, spec.kind);
        msg.endNested(info);

        int32_t r = co_await _socket.request(msg);
        if (r != SBOX_OK || !spec.up || spec.netnsFd >= 0) {
            co_return r;
        }

        int32_t index = co_await linkIndex(spec.name);
        if (index < 0) {
            co_return index;
        }

        co_return co_await setUp(index, true);
    }

    /* Creates a bridge. */
    TTask<int32_t> CRtnl::createBridge(std::string name, uint32_t mtu, SMacAddress mac) {
        SLinkSpec spec;
        spec.name = std::move(name);
        spec.kind = "bridge";
        spec.mtu = mtu;
        spec.mac = mac;
        co_return co_await createLink(std::move(spec));
    }

    /* Creates a veth pair. */
    TTask<int32_t> CRtnl::createVeth(std::string name, std::string peerName, int peerNetnsFd, uint32_t mtu) {
        if (!validName(name) || !validName(peerName)) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0);
        msg.putString(IFLA_IFNAME, name);
        if (mtu) {
            msg.putU32(IFLA_MTU, mtu);
        }

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, "veth");
        size_t data = msg.beginNested(IFLA_INFO_DATA);
        size_t peer = msg.beginNested(VETH_INFO_PEER);

        // --> The peer attribute starts with its own ifinfomsg, then the peer's attributes.
        ifinfomsg ifi;
        std::memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = AF_UNSPEC;
        msg.putHeader(&ifi, sizeof(ifi));
        msg.putString(IFLA_IFNAME, peerName);
        if (mtu) {
            msg.putU32(IFLA_MTU, mtu);
        }

        if (peerNetnsFd >= 0) {
            msg.putU32(IFLA_NET_NS_FD, uint32_t(peerNetnsFd));
        }

        msg.endNested(peer);
        msg.endNested(data);
        msg.endNested(info);

        co_return co_await _socket.request(msg);
    }

    /* Creates a macvlan device. */
    TTask<int32_t> CRtnl::createMacvlan(std::string name, int32_t parentIndex, EMacvlanMode mode, int netnsFd,
        uint32_t mtu, SMacAddress mac)
    {
        if (!validName(name) || parentIndex <= 0) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0);
        msg.putString(IFLA_IFNAME, name);
        msg.putU32(IFLA_LINK, uint32_t(parentIndex));
        if (mtu) {
            msg.putU32(IFLA_MTU, mtu);
        }

        if (mac.isValid()) {
            msg.put(IFLA_ADDRESS, mac.bytes, 6);
        }

        if (netnsFd >= 0) {
            msg.putU32(IFLA_NET_NS_FD, uint32_t(netnsFd));
        }

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, "macvlan");
        size_t data = msg.beginNested(IFLA_INFO_DATA);
        msg.putU32(IFLA_MACVLAN_MODE, uint32_t(mode));
        msg.endNested(data);
        msg.endNested(info);

        co_return co_await _socket.request(msg);
    }

    /* Creates an ipvlan device. */
    TTask<int32_t> CRtnl::createIpvlan(std::string name, int32_t parentIndex, EIpvlanMode mode, int netnsFd, uint32_t mtu) {
        if (!validName(name) || parentIndex <= 0) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0);
        msg.putString(IFLA_IFNAME, name);
        msg.putU32(IFLA_LINK, uint32_t(parentIndex));
        if (mtu) {
            msg.putU32(IFLA_MTU, mtu);
        }

        if (netnsFd >= 0) {
            msg.putU32(IFLA_NET_NS_FD, uint32_t(netnsFd));
        }

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, "ipvlan");
        size_t data = msg.beginNested(IFLA_INFO_DATA);
        msg.putU16(IFLA_IPVLAN_MODE, uint16_t(mode));
        msg.endNested(data);
        msg.endNested(info);

        co_return co_await _socket.request(msg);
    }

    /* Creates a VXLAN device. */
    TTask<int32_t> CRtnl::createVxlan(std::string name, SVxlanConfig config) {
        if (!validName(name) || config.vni == 0 || config.vni >= (1u << 24)) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0);
        msg.putString(IFLA_IFNAME, name);
        if (config.mtu) {
            msg.putU32(IFLA_MTU, config.mtu);
        }

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, "vxlan");
        size_t data = msg.beginNested(IFLA_INFO_DATA);
        msg.putU32(IFLA_VXLAN_ID, config.vni);

        if (config.parentIndex) {
            msg.putU32(IFLA_VXLAN_LINK, uint32_t(config.parentIndex));
        }

        if (config.local.isV4()) {
            msg.putAddress(IFLA_VXLAN_LOCAL, config.local);
        }
        else if (config.local.isV6()) {
            msg.putAddress(IFLA_VXLAN_LOCAL6, config.local);
        }

        if (config.remote.isV4()) {
            msg.putAddress(IFLA_VXLAN_GROUP, config.remote);
        }
        else if (config.remote.isV6()) {
            msg.putAddress(IFLA_VXLAN_GROUP6, config.remote);
        }

        msg.putBe16(IFLA_VXLAN_PORT, config.port);
        msg.putU8(IFLA_VXLAN_TTL, config.ttl);
        msg.putU8(IFLA_VXLAN_LEARNING, config.learning ? 1 : 0);
        msg.endNested(data);
        msg.endNested(info);

        co_return co_await _socket.request(msg);
    }

    /* Creates a dummy device. */
    TTask<int32_t> CRtnl::createDummy(std::string name) {
        SLinkSpec spec;
        spec.name = std::move(name);
        spec.kind = "dummy";
        co_return co_await createLink(std::move(spec));
    }

    /* Sends a link change. */
    TTask<int32_t> CRtnl::changeLink(CNlMessage& msg) {
        co_return co_await _socket.request(msg);
    }

    /* Sets the administrative state. */
    TTask<int32_t> CRtnl::setUp(int32_t index, bool up) {
        CNlMessage msg(RTM_NEWLINK, 0);
        ifinfomsg ifi;
        std::memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = AF_UNSPEC;
        ifi.ifi_index = index;
        ifi.ifi_change = IFF_UP;
        ifi.ifi_flags = up ? IFF_UP : 0;
        msg.putHeader(&ifi, sizeof(ifi));
        co_return co_await changeLink(msg);
    }

    /* Sets the MTU. */
    TTask<int32_t> CRtnl::setMtu(int32_t index, uint32_t mtu) {
        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.putU32(IFLA_MTU, mtu);
        co_return co_await changeLink(msg);
    }

    /* Sets the MAC address. */
    TTask<int32_t> CRtnl::setMac(int32_t index, SMacAddress mac) {
        if (!mac.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.put(IFLA_ADDRESS, mac.bytes, 6);
        co_return co_await changeLink(msg);
    }

    /* Enslaves a link. */
    TTask<int32_t> CRtnl::setMaster(int32_t index, int32_t masterIndex) {
        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.putU32(IFLA_MASTER, uint32_t(masterIndex));
        co_return co_await changeLink(msg);
    }

    /* Moves a link to a namespace given by descriptor. */
    TTask<int32_t> CRtnl::moveToNetnsFd(int32_t index, int netnsFd, std::string newName) {
        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.putU32(IFLA_NET_NS_FD, uint32_t(netnsFd));
        if (!newName.empty()) {
            if (!validName(newName)) {
                co_return -EINVAL;
            }

            msg.putString(IFLA_IFNAME, newName);
        }

        co_return co_await changeLink(msg);
    }

    /* Moves a link to a namespace given by pid. */
    TTask<int32_t> CRtnl::moveToNetnsPid(int32_t index, pid_t pid) {
        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.putU32(IFLA_NET_NS_PID, uint32_t(pid));
        co_return co_await changeLink(msg);
    }

    /* Renames a link. */
    TTask<int32_t> CRtnl::rename(int32_t index, std::string name) {
        if (!validName(name)) {
            co_return -EINVAL;
        }

        CNlMessage msg = linkMessage(RTM_NEWLINK, 0, index);
        msg.putString(IFLA_IFNAME, name);
        co_return co_await changeLink(msg);
    }

    /* Deletes a link. */
    TTask<int32_t> CRtnl::deleteLink(int32_t index) {
        CNlMessage msg = linkMessage(RTM_DELLINK, 0, index);
        co_return co_await _socket.request(msg);
    }

    /* Sets bridge port flags. */
    TTask<int32_t> CRtnl::setBridgePort(int32_t index, bool hairpin, bool isolated) {
        CNlMessage msg(RTM_NEWLINK, 0);
        ifinfomsg ifi;
        std::memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = AF_BRIDGE;
        ifi.ifi_index = index;
        msg.putHeader(&ifi, sizeof(ifi));

        size_t prot = msg.beginNested(IFLA_PROTINFO);
        msg.putU8(IFLA_BRPORT_MODE, hairpin ? 1 : 0);
        msg.putU8(IFLA_BRPORT_ISOLATED, isolated ? 1 : 0);
        msg.endNested(prot);
        co_return co_await changeLink(msg);
    }

    /* Adds an address. */
    TTask<int32_t> CRtnl::addAddress(int32_t index, SIpPrefix address, bool replace) {
        if (!address.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg(RTM_NEWADDR, uint16_t(NLM_F_CREATE | (replace ? NLM_F_REPLACE : NLM_F_EXCL)));
        ifaddrmsg ifa;
        std::memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = uint8_t(address.address.afamily());
        ifa.ifa_prefixlen = address.length;
        ifa.ifa_scope = address.address.isLoopback() ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
        ifa.ifa_index = uint32_t(index);
        msg.putHeader(&ifa, sizeof(ifa));

        msg.putAddress(IFA_LOCAL, address.address);
        msg.putAddress(IFA_ADDRESS, address.address);

        if (address.address.isV4() && address.length < 31) {
            msg.putAddress(IFA_BROADCAST, address.last());
        }

        if (address.address.isV6()) {
            msg.putU32(IFA_FLAGS, IFA_F_NODAD);
        }

        co_return co_await _socket.request(msg);
    }

    /* Removes an address. */
    TTask<int32_t> CRtnl::delAddress(int32_t index, SIpPrefix address) {
        if (!address.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg(RTM_DELADDR, 0);
        ifaddrmsg ifa;
        std::memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = uint8_t(address.address.afamily());
        ifa.ifa_prefixlen = address.length;
        ifa.ifa_index = uint32_t(index);
        msg.putHeader(&ifa, sizeof(ifa));
        msg.putAddress(IFA_LOCAL, address.address);
        msg.putAddress(IFA_ADDRESS, address.address);
        co_return co_await _socket.request(msg);
    }

    /* Lists addresses. */
    TTask<int32_t> CRtnl::listAddresses(std::vector<SAddressInfo>& out, int family, int32_t index) {
        CNlMessage msg(RTM_GETADDR, 0);
        ifaddrmsg ifa;
        std::memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = uint8_t(family);
        msg.putHeader(&ifa, sizeof(ifa));

        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const SNlReply& reply : replies) {
            if (reply.type != RTM_NEWADDR || reply.payload.size() < sizeof(ifaddrmsg)) {
                continue;
            }

            ifaddrmsg h;
            std::memcpy(&h, reply.payload.data(), sizeof(h));
            if (index && int32_t(h.ifa_index) != index) {
                continue;
            }

            if (family && h.ifa_family != family) {
                continue;
            }

            CNlAttrs attrs = reply.attrs(sizeof(ifaddrmsg));
            const SNlAttr* a = attrs.find(IFA_LOCAL);
            if (!a) {
                a = attrs.find(IFA_ADDRESS);
            }

            if (!a) {
                continue;
            }

            SAddressInfo info;
            info.index = int32_t(h.ifa_index);
            info.prefix = SIpPrefix(a->address(), h.ifa_prefixlen);
            info.scope = h.ifa_scope;
            info.flags = attrs.u32(IFA_FLAGS, h.ifa_flags);
            info.label = attrs.str(IFA_LABEL);
            out.push_back(std::move(info));
        }

        co_return SBOX_OK;
    }

    namespace {

        /* Builds an RTM_NEWROUTE / RTM_DELROUTE message. */
        CNlMessage routeMessage(uint16_t type, uint16_t flags, const SRouteInfo& route) {
            CNlMessage msg(type, flags);
            const SIpAddress& any = route.destination.address.isValid() ? route.destination.address : route.gateway;

            rtmsg rtm;
            std::memset(&rtm, 0, sizeof(rtm));
            rtm.rtm_family = uint8_t(any.afamily());
            rtm.rtm_dst_len = route.destination.length;
            rtm.rtm_table = route.table < 256 ? uint8_t(route.table) : uint8_t(RT_TABLE_UNSPEC);
            rtm.rtm_protocol = route.protocol;
            rtm.rtm_type = route.type;

            if (type == RTM_DELROUTE) {
                rtm.rtm_scope = RT_SCOPE_NOWHERE;
            }
            else if (route.scope) {
                rtm.rtm_scope = route.scope;
            }
            else {
                rtm.rtm_scope = route.gateway.isValid() ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
            }

            msg.putHeader(&rtm, sizeof(rtm));

            if (route.table >= 256) {
                msg.putU32(RTA_TABLE, route.table);
            }

            if (route.destination.address.isValid() && route.destination.length) {
                msg.putAddress(RTA_DST, route.destination.network().address);
            }

            if (route.gateway.isValid()) {
                msg.putAddress(RTA_GATEWAY, route.gateway);
            }

            if (route.source.isValid()) {
                msg.putAddress(RTA_PREFSRC, route.source);
            }

            if (route.oif) {
                msg.putU32(RTA_OIF, uint32_t(route.oif));
            }

            if (route.metric) {
                msg.putU32(RTA_PRIORITY, route.metric);
            }

            if (route.mtu && type == RTM_NEWROUTE) {
                size_t m = msg.beginNested(RTA_METRICS);
                msg.putU32(RTAX_MTU, route.mtu);
                msg.endNested(m);
            }

            return msg;
        }

    }

    /* Adds a route. */
    TTask<int32_t> CRtnl::addRoute(SRouteInfo route, bool replace) {
        if (!route.destination.address.isValid() && !route.gateway.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg = routeMessage(RTM_NEWROUTE, uint16_t(NLM_F_CREATE | (replace ? NLM_F_REPLACE : NLM_F_EXCL)), route);
        co_return co_await _socket.request(msg);
    }

    /* Deletes a route. */
    TTask<int32_t> CRtnl::delRoute(SRouteInfo route) {
        if (!route.destination.address.isValid() && !route.gateway.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg = routeMessage(RTM_DELROUTE, 0, route);
        co_return co_await _socket.request(msg);
    }

    /* Lists routes. */
    TTask<int32_t> CRtnl::listRoutes(std::vector<SRouteInfo>& out, int family, uint32_t table) {
        CNlMessage msg(RTM_GETROUTE, 0);
        rtmsg rtm;
        std::memset(&rtm, 0, sizeof(rtm));
        rtm.rtm_family = uint8_t(family);
        msg.putHeader(&rtm, sizeof(rtm));

        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const SNlReply& reply : replies) {
            if (reply.type != RTM_NEWROUTE || reply.payload.size() < sizeof(rtmsg)) {
                continue;
            }

            rtmsg h;
            std::memcpy(&h, reply.payload.data(), sizeof(h));
            CNlAttrs attrs = reply.attrs(sizeof(rtmsg));

            SRouteInfo info;
            info.table = attrs.u32(RTA_TABLE, h.rtm_table);
            if (table && info.table != table) {
                continue;
            }

            info.protocol = h.rtm_protocol;
            info.scope = h.rtm_scope;
            info.type = h.rtm_type;
            info.oif = int32_t(attrs.u32(RTA_OIF));
            info.metric = attrs.u32(RTA_PRIORITY);

            if (const SNlAttr* a = attrs.find(RTA_DST)) {
                info.destination = SIpPrefix(a->address(), h.rtm_dst_len);
            }
            else {
                SIpAddress zero;
                zero.family = h.rtm_family == AF_INET6 ? 6 : 4;
                info.destination = SIpPrefix(zero, 0);
            }

            if (const SNlAttr* a = attrs.find(RTA_GATEWAY)) {
                info.gateway = a->address();
            }

            if (const SNlAttr* a = attrs.find(RTA_PREFSRC)) {
                info.source = a->address();
            }

            out.push_back(std::move(info));
        }

        co_return SBOX_OK;
    }

    /* Adds a default route. */
    TTask<int32_t> CRtnl::addDefaultRoute(SIpAddress gateway, int32_t oif, bool replace) {
        if (!gateway.isValid()) {
            co_return -EINVAL;
        }

        SRouteInfo route;
        SIpAddress zero;
        zero.family = gateway.family;
        route.destination = SIpPrefix(zero, 0);
        route.gateway = gateway;
        route.oif = oif;
        co_return co_await addRoute(route, replace);
    }

    /* Adds or replaces a neighbour entry. */
    TTask<int32_t> CRtnl::setNeighbour(int32_t index, SIpAddress address, SMacAddress mac, bool permanent) {
        if (!address.isValid() || !mac.isValid()) {
            co_return -EINVAL;
        }

        CNlMessage msg(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE);
        ndmsg nd;
        std::memset(&nd, 0, sizeof(nd));
        nd.ndm_family = uint8_t(address.afamily());
        nd.ndm_ifindex = index;
        nd.ndm_state = uint16_t(permanent ? int(NUD_PERMANENT) : int(NUD_REACHABLE));
        msg.putHeader(&nd, sizeof(nd));
        msg.putAddress(NDA_DST, address);
        msg.put(NDA_LLADDR, mac.bytes, 6);
        co_return co_await _socket.request(msg);
    }

    /* Lists neighbour entries. */
    TTask<int32_t> CRtnl::listNeighbours(std::vector<SNeighbourInfo>& out, int family) {
        CNlMessage msg(RTM_GETNEIGH, 0);
        ndmsg nd;
        std::memset(&nd, 0, sizeof(nd));
        nd.ndm_family = uint8_t(family);
        msg.putHeader(&nd, sizeof(nd));

        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const SNlReply& reply : replies) {
            if (reply.type != RTM_NEWNEIGH || reply.payload.size() < sizeof(ndmsg)) {
                continue;
            }

            ndmsg h;
            std::memcpy(&h, reply.payload.data(), sizeof(h));
            CNlAttrs attrs = reply.attrs(sizeof(ndmsg));

            SNeighbourInfo info;
            info.index = h.ndm_ifindex;
            info.state = h.ndm_state;

            if (const SNlAttr* a = attrs.find(NDA_DST)) {
                info.address = a->address();
            }

            if (const SNlAttr* a = attrs.find(NDA_LLADDR)) {
                if (a->length == 6) {
                    info.mac = SMacAddress::fromBytes(a->data);
                }
            }

            out.push_back(std::move(info));
        }

        co_return SBOX_OK;
    }

    /* Creates a TUN/TAP device. */
    int32_t CreateTunTap(const std::string& name, const STunTapOptions& options, CFd& out, std::string* actualName) noexcept {
        if (name.size() >= IFNAMSIZ) {
            return -EINVAL;
        }

        CFd fd;
        ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = short((options.tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI | (options.multiQueue ? IFF_MULTI_QUEUE : 0));
        std::memcpy(ifr.ifr_name, name.data(), name.size());

        {
            // --> The device is created in the namespace of the thread doing TUNSETIFF.
            CNetnsScope scope(options.netnsPath);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            fd.reset(::open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK));
            if (!fd.isValid()) {
                return -errno;
            }

            if (::ioctl(fd.get(), TUNSETIFF, &ifr) < 0) {
                return -errno;
            }
        }

        if (options.owner >= 0 && ::ioctl(fd.get(), TUNSETOWNER, static_cast<unsigned long>(options.owner)) < 0) {
            return -errno;
        }

        if (options.group >= 0 && ::ioctl(fd.get(), TUNSETGROUP, static_cast<unsigned long>(options.group)) < 0) {
            return -errno;
        }

        if (options.persistent && ::ioctl(fd.get(), TUNSETPERSIST, 1UL) < 0) {
            return -errno;
        }

        if (actualName) {
            actualName->assign(ifr.ifr_name, ::strnlen(ifr.ifr_name, IFNAMSIZ));
        }

        out = std::move(fd);
        return SBOX_OK;
    }

}
}
