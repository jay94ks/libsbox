#include <sbox/net/network.hpp>
#include <sbox/net/dhcp.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/sysctl.hpp>
#include <cerrno>
#include <cstdlib>
#include <sys/socket.h>

namespace sbox {
namespace net {

    namespace {

        /* Returns the MTU option of a network (0 for the kernel default). */
        uint32_t networkMtu(const SNetwork& net) {
            std::string v = net.option("com.docker.network.driver.mtu");
            return v.empty() ? 0 : uint32_t(std::strtoul(v.c_str(), nullptr, 10));
        }

        /* Opens the host namespace descriptor (the configured one or the current). */
        int32_t openHostNs(const SNetworkContext& ctx, CFd& out) {
            return ctx.hostNetns.empty() ? CNetns::openCurrent(out) : CNetns::open(ctx.hostNetns, out);
        }

        /* Moves a host-side interface into the sandbox under `ifName`. */
        TTask<int32_t> moveIntoSandbox(SNetworkContext& ctx, const std::string& hostName, const std::string& netnsPath,
            const std::string& ifName)
        {
            int32_t index = co_await ctx.host->linkIndex(hostName);
            if (index < 0) {
                co_return index;
            }

            CFd ns;
            int32_t r = CNetns::open(netnsPath, ns);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_return co_await ctx.host->moveToNetnsFd(index, ns.get(), ifName);
        }

        /* Configures addresses, link state and routes of a joined interface. */
        TTask<int32_t> configureSandbox(const std::string& netnsPath, const std::string& ifName, const SNetworkEndpoint& ep,
            bool deviceRoute)
        {
            CRtnl sb;
            int32_t r = sb.open(netnsPath);
            if (r != SBOX_OK) {
                co_return r;
            }

            int32_t index = co_await sb.linkIndex(ifName);
            if (index < 0) {
                co_return index;
            }

            if (ep.mtu) {
                r = co_await sb.setMtu(index, ep.mtu);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            for (const SIpPrefix& a : ep.addresses) {
                r = co_await sb.addAddress(index, a, true);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            r = co_await sb.setUp(index, true);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_await sb.setUp(1, true);

            if (deviceRoute) {
                // --> ipvlan L3: no gateway on the link, everything leaves through the device.
                for (const SIpPrefix& a : ep.addresses) {
                    SRouteInfo route;
                    SIpAddress zero;
                    zero.family = a.address.family;
                    route.destination = SIpPrefix(zero, 0);
                    route.oif = index;
                    r = co_await sb.addRoute(route, true);
                    if (r != SBOX_OK) {
                        co_return r;
                    }
                }

                co_return SBOX_OK;
            }

            for (const SIpAddress& gw : ep.gateways) {
                r = co_await sb.addDefaultRoute(gw, index, true);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            co_return SBOX_OK;
        }

        /* Moves a joined interface back into the host namespace under `hostName`. */
        TTask<int32_t> moveBackToHost(SNetworkContext& ctx, const SNetworkEndpoint& ep, const std::string& hostName) {
            if (ep.netnsPath.empty() || ep.sandboxIfName.empty() || !CNetns::isNetns(ep.netnsPath)) {
                // --> The sandbox is gone, and its interfaces with it.
                co_return SBOX_OK;
            }

            CRtnl sb;
            int32_t r = sb.open(ep.netnsPath);
            if (r != SBOX_OK) {
                co_return SBOX_OK;
            }

            int32_t index = co_await sb.linkIndex(ep.sandboxIfName);
            if (index < 0) {
                co_return SBOX_OK;
            }

            co_await sb.setUp(index, false);

            CFd host;
            r = openHostNs(ctx, host);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_return co_await sb.moveToNetnsFd(index, host.get(), hostName);
        }

        /* Linux bridge driver. */
        class CBridgeDriver : public INetworkDriver {
        public:
            std::string name() const override { return "bridge"; }

            bool usesFirewall() const override { return true; }

            /* Creates (or adopts) the bridge and its gateway addresses. */
            TTask<int32_t> createNetwork(SNetworkContext& ctx, SNetwork& net) override {
                std::string br = net.option("com.docker.network.bridge.name", "br-" + net.id.substr(0, 12));
                if (br.size() >= 16) {
                    co_return -EINVAL;
                }

                uint32_t mtu = networkMtu(net);
                bool created = false;

                SLinkInfo existing;
                int32_t r = co_await ctx.host->getLink(br, existing);
                if (r == SBOX_OK) {
                    if (existing.kind != "bridge") {
                        co_return -EEXIST;
                    }
                }
                else if (r == -ENODEV) {
                    r = co_await ctx.host->createBridge(br, mtu);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    created = true;
                }
                else {
                    co_return r;
                }

                int32_t index = co_await ctx.host->linkIndex(br);
                r = index < 0 ? index : SBOX_OK;

                for (const SNetworkSubnet& s : net.subnets) {
                    if (r == SBOX_OK && s.gateway.isValid()) {
                        r = co_await ctx.host->addAddress(index, SIpPrefix(s.gateway, s.subnet.length), true);
                    }
                }

                if (r == SBOX_OK) {
                    r = co_await ctx.host->setUp(index, true);
                }

                if (r == SBOX_OK && !net.internal) {
                    r = SetIpForward(true, ctx.hostNetns);
                    // --> Loopback clients of published ports are DNATed onto the bridge.
                    SetRouteLocalnet(br, true, ctx.hostNetns);

                    if (net.subnet(6)) {
                        SetIpv6Forward(true, ctx.hostNetns);
                    }
                }

                if (r == SBOX_OK && !net.flag("com.docker.network.bridge.enable_icc", true)) {
                    // --> Filtering between ports of one bridge needs bridged traffic to pass
                    // the inet hooks.
                    SetBridgeNfCall(true, ctx.hostNetns);
                }

                if (r != SBOX_OK) {
                    if (created && index > 0) {
                        co_await ctx.host->deleteLink(index);
                    }

                    co_return r;
                }

                net.driverState.set("bridge", br);
                net.driverState.set("createdBridge", created);
                co_return SBOX_OK;
            }

            /* Deletes the bridge (or only our addresses on an adopted one). */
            TTask<int32_t> deleteNetwork(SNetworkContext& ctx, const SNetwork& net) override {
                std::string br = net.driverState.get("bridge").asString();
                if (br.empty()) {
                    co_return SBOX_OK;
                }

                int32_t index = co_await ctx.host->linkIndex(br);
                if (index == -ENODEV) {
                    co_return SBOX_OK;
                }

                if (index < 0) {
                    co_return index;
                }

                if (net.driverState.get("createdBridge").asBool()) {
                    co_return co_await ctx.host->deleteLink(index);
                }

                for (const SNetworkSubnet& s : net.subnets) {
                    if (s.gateway.isValid()) {
                        co_await ctx.host->delAddress(index, SIpPrefix(s.gateway, s.subnet.length));
                    }
                }

                co_return SBOX_OK;
            }

            /* Creates the veth pair and plugs the host end into the bridge. */
            TTask<int32_t> createEndpoint(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                std::string br = net.driverState.get("bridge").asString();
                int32_t bridge = co_await ctx.host->linkIndex(br);
                if (bridge < 0) {
                    co_return bridge;
                }

                std::string hostName = "veth" + RandomHex(7);
                std::string peer = "veth" + RandomHex(7);
                int32_t r = co_await ctx.host->createVeth(hostName, peer, -1, ep.mtu);
                if (r != SBOX_OK) {
                    co_return r;
                }

                int32_t hidx = co_await ctx.host->linkIndex(hostName);
                int32_t pidx = co_await ctx.host->linkIndex(peer);
                r = hidx < 0 ? hidx : (pidx < 0 ? pidx : SBOX_OK);

                if (r == SBOX_OK) {
                    r = co_await ctx.host->setMaster(hidx, bridge);
                }

                if (r == SBOX_OK) {
                    r = co_await ctx.host->setUp(hidx, true);
                }

                if (r == SBOX_OK && ep.mac.isValid()) {
                    r = co_await ctx.host->setMac(pidx, ep.mac);
                }

                if (r != SBOX_OK) {
                    if (hidx > 0) {
                        co_await ctx.host->deleteLink(hidx);
                    }

                    co_return r;
                }

                ep.hostIfName = hostName;
                ep.driverState.set("peer", peer);
                co_return SBOX_OK;
            }

            /* Moves the peer into the sandbox and configures it. */
            TTask<int32_t> join(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep, std::string netnsPath,
                std::string ifName) override
            {
                (void)net;
                std::string peer = ep.driverState.get("peer").asString();
                int32_t r = co_await moveIntoSandbox(ctx, peer, netnsPath, ifName);
                if (r != SBOX_OK) {
                    co_return r;
                }

                r = co_await configureSandbox(netnsPath, ifName, ep, false);
                if (r != SBOX_OK) {
                    SNetworkEndpoint joined = ep;
                    joined.netnsPath = netnsPath;
                    joined.sandboxIfName = ifName;
                    co_await moveBackToHost(ctx, joined, peer);
                }

                co_return r;
            }

            /* Moves the peer back to the host. */
            TTask<int32_t> leave(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                (void)net;
                co_return co_await moveBackToHost(ctx, ep, ep.driverState.get("peer").asString());
            }

            /* Deletes the veth pair. */
            TTask<int32_t> deleteEndpoint(SNetworkContext& ctx, const SNetwork& net, const SNetworkEndpoint& ep) override {
                (void)net;
                int32_t index = co_await ctx.host->linkIndex(ep.hostIfName);
                if (index == -ENODEV || index == -EINVAL) {
                    co_return SBOX_OK;
                }

                if (index < 0) {
                    co_return index;
                }

                int32_t r = co_await ctx.host->deleteLink(index);
                co_return r == -ENODEV ? SBOX_OK : r;
            }
        };

        /* macvlan / ipvlan driver ("physical" addresses on the parent's LAN). */
        class CVlanDriver : public INetworkDriver {
        private:
            bool _ipvlan;

        public:
            explicit CVlanDriver(bool ipvlan) : _ipvlan(ipvlan) {}

            std::string name() const override { return _ipvlan ? "ipvlan" : "macvlan"; }

            /* Parses the mode option. */
            bool parseMode(const SNetwork& net, uint32_t& mode) const {
                if (_ipvlan) {
                    std::string m = net.option("ipvlan_mode", "l2");
                    if (m == "l2") {
                        mode = EIVM_L2;
                    }
                    else if (m == "l3") {
                        mode = EIVM_L3;
                    }
                    else if (m == "l3s") {
                        mode = EIVM_L3S;
                    }
                    else {
                        return false;
                    }

                    return true;
                }

                std::string m = net.option("macvlan_mode", "bridge");
                if (m == "bridge") {
                    mode = EMVM_BRIDGE;
                }
                else if (m == "private") {
                    mode = EMVM_PRIVATE;
                }
                else if (m == "vepa") {
                    mode = EMVM_VEPA;
                }
                else if (m == "passthru") {
                    mode = EMVM_PASSTHRU;
                }
                else {
                    return false;
                }

                return true;
            }

            /* Validates the parent and mode. */
            TTask<int32_t> createNetwork(SNetworkContext& ctx, SNetwork& net) override {
                std::string parent = net.option("parent");
                if (parent.empty()) {
                    co_return -EINVAL;
                }

                uint32_t mode = 0;
                if (!parseMode(net, mode)) {
                    co_return -EINVAL;
                }

                if (_ipvlan && net.flag("sbox.dhcp", false)) {
                    // --> ipvlan slaves share the parent's MAC; DHCP servers key leases on it.
                    co_return -ENOTSUP;
                }

                int32_t index = co_await ctx.host->linkIndex(parent);
                if (index < 0) {
                    co_return index;
                }

                net.driverState.set("parent", parent);
                net.driverState.set("mode", mode);
                co_return SBOX_OK;
            }

            /* Nothing to remove: the parent belongs to the host. */
            TTask<int32_t> deleteNetwork(SNetworkContext& ctx, const SNetwork& net) override {
                (void)ctx;
                (void)net;
                co_return SBOX_OK;
            }

            /* Creates the slave device (and runs DHCP on it when asked). */
            TTask<int32_t> createEndpoint(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                int32_t parent = co_await ctx.host->linkIndex(net.driverState.get("parent").asString());
                if (parent < 0) {
                    co_return parent;
                }

                uint32_t mode = uint32_t(net.driverState.get("mode").asInt());
                std::string tmp = (_ipvlan ? "iv" : "mv") + RandomHex(7);
                uint32_t mtu = ep.mtu ? ep.mtu : networkMtu(net);

                int32_t r = _ipvlan
                    ? co_await ctx.host->createIpvlan(tmp, parent, EIpvlanMode(mode), -1, mtu)
                    : co_await ctx.host->createMacvlan(tmp, parent, EMacvlanMode(mode), -1, mtu, ep.mac);
                if (r != SBOX_OK) {
                    co_return r;
                }

                ep.hostIfName = tmp;
                ep.driverState.set("peer", tmp);

                if (_ipvlan) {
                    SLinkInfo info;
                    if (co_await ctx.host->getLink(tmp, info) == SBOX_OK) {
                        ep.mac = info.mac;
                    }
                }

                if (!net.flag("sbox.dhcp", false)) {
                    co_return SBOX_OK;
                }

                int32_t index = co_await ctx.host->linkIndex(tmp);
                r = index < 0 ? index : co_await ctx.host->setUp(index, true);

                SDhcpLease lease;
                if (r == SBOX_OK) {
                    CDhcpClient client;
                    r = client.open(tmp, ctx.hostNetns, ep.mac);
                    if (r == SBOX_OK) {
                        client.hostname(ep.driverState.get("hostname").asString());
                        std::string t = net.option("sbox.dhcp.timeout", "10000");
                        r = co_await client.acquire(lease, int64_t(std::strtoll(t.c_str(), nullptr, 10)));
                    }
                }

                if (r != SBOX_OK) {
                    if (index > 0) {
                        co_await ctx.host->deleteLink(index);
                    }

                    co_return r;
                }

                ep.addresses = { lease.prefix() };
                ep.gateways.clear();
                if (lease.router.isValid()) {
                    ep.gateways.push_back(lease.router);
                }

                if (lease.mtu && !ep.mtu) {
                    ep.mtu = lease.mtu;
                }

                ep.driverState.set("lease", lease.toJson());
                co_return SBOX_OK;
            }

            /* Moves the slave into the sandbox and configures it. */
            TTask<int32_t> join(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep, std::string netnsPath,
                std::string ifName) override
            {
                std::string tmp = ep.driverState.get("peer").asString();
                int32_t r = co_await moveIntoSandbox(ctx, tmp, netnsPath, ifName);
                if (r != SBOX_OK) {
                    co_return r;
                }

                bool l3 = _ipvlan && net.driverState.get("mode").asInt() != EIVM_L2;
                r = co_await configureSandbox(netnsPath, ifName, ep, l3);
                if (r != SBOX_OK) {
                    SNetworkEndpoint joined = ep;
                    joined.netnsPath = netnsPath;
                    joined.sandboxIfName = ifName;
                    co_await moveBackToHost(ctx, joined, tmp);
                }

                co_return r;
            }

            /* Moves the slave back to the host under its temporary name. */
            TTask<int32_t> leave(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                (void)net;
                co_return co_await moveBackToHost(ctx, ep, ep.driverState.get("peer").asString());
            }

            /* Releases a DHCP lease and deletes the slave. */
            TTask<int32_t> deleteEndpoint(SNetworkContext& ctx, const SNetwork& net, const SNetworkEndpoint& ep) override {
                (void)net;
                int32_t index = co_await ctx.host->linkIndex(ep.hostIfName);
                if (index == -ENODEV || index == -EINVAL) {
                    co_return SBOX_OK;
                }

                if (index < 0) {
                    co_return index;
                }

                const CJson& lj = ep.driverState.get("lease");
                SDhcpLease lease;
                if (lj.isObject() && SDhcpLease::fromJson(lj, lease) == SBOX_OK) {
                    // --> Best effort: tell the server, from the interface holding the lease.
                    co_await ctx.host->setUp(index, true);
                    CDhcpClient client;
                    if (client.open(ep.hostIfName, ctx.hostNetns, ep.mac) == SBOX_OK) {
                        client.release(lease);
                    }
                }

                int32_t r = co_await ctx.host->deleteLink(index);
                co_return r == -ENODEV ? SBOX_OK : r;
            }
        };

        /* host driver: the sandbox shares the host namespace, nothing to wire. */
        class CHostDriver : public INetworkDriver {
        public:
            std::string name() const override { return "host"; }

            bool usesIpam() const override { return false; }

            bool usesGateway() const override { return false; }

            TTask<int32_t> createNetwork(SNetworkContext& ctx, SNetwork& net) override {
                (void)ctx;
                (void)net;
                co_return SBOX_OK;
            }

            TTask<int32_t> deleteNetwork(SNetworkContext& ctx, const SNetwork& net) override {
                (void)ctx;
                (void)net;
                co_return SBOX_OK;
            }

            TTask<int32_t> createEndpoint(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                (void)ctx;
                (void)net;
                ep.mac = SMacAddress();
                co_return SBOX_OK;
            }

            TTask<int32_t> join(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep, std::string netnsPath,
                std::string ifName) override
            {
                (void)ctx;
                (void)net;
                (void)ep;
                (void)netnsPath;
                (void)ifName;
                co_return SBOX_OK;
            }

            TTask<int32_t> leave(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep) override {
                (void)ctx;
                (void)net;
                (void)ep;
                co_return SBOX_OK;
            }

            TTask<int32_t> deleteEndpoint(SNetworkContext& ctx, const SNetwork& net, const SNetworkEndpoint& ep) override {
                (void)ctx;
                (void)net;
                (void)ep;
                co_return SBOX_OK;
            }
        };

        /* none driver: loopback only. */
        class CNoneDriver : public CHostDriver {
        public:
            std::string name() const override { return "none"; }

            TTask<int32_t> join(SNetworkContext& ctx, const SNetwork& net, SNetworkEndpoint& ep, std::string netnsPath,
                std::string ifName) override
            {
                (void)ctx;
                (void)net;
                (void)ep;
                (void)ifName;
                CRtnl sb;
                int32_t r = sb.open(netnsPath);
                if (r != SBOX_OK) {
                    co_return r;
                }

                co_return co_await sb.setUp(1, true);
            }
        };

    }

    /* Creates the bridge driver. */
    INetworkDriverPtr CreateBridgeDriver() {
        return std::make_shared<CBridgeDriver>();
    }

    /* Creates the macvlan driver. */
    INetworkDriverPtr CreateMacvlanDriver() {
        return std::make_shared<CVlanDriver>(false);
    }

    /* Creates the ipvlan driver. */
    INetworkDriverPtr CreateIpvlanDriver() {
        return std::make_shared<CVlanDriver>(true);
    }

    /* Creates the host driver. */
    INetworkDriverPtr CreateHostDriver() {
        return std::make_shared<CHostDriver>();
    }

    /* Creates the none driver. */
    INetworkDriverPtr CreateNoneDriver() {
        return std::make_shared<CNoneDriver>();
    }

}
}
