#include <sbox/vpn/wg/overlay.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/net/lock.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/net/sysctl.hpp>
#include <sbox/vpn/wg/kernel.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace vpn {

    namespace {

        constexpr const char* MTU_OPTION = "com.docker.network.driver.mtu";

        /* Returns the mode's JSON name. */
        const char* modeName(EWgMode m) {
            return m == EWGM_KERNEL ? "kernel" : (m == EWGM_USERSPACE ? "userspace" : "auto");
        }

        /* Returns the first 8 characters of a network id. */
        std::string shortId(const std::string& id) {
            return id.substr(0, 8);
        }

        /* Returns the WireGuard interface name of a network. */
        std::string interfaceOf(const SWgOverlayConfig& c, const std::string& id) {
            return c.interfaceName.empty() ? "wgo-" + shortId(id) : c.interfaceName;
        }

        /* Returns the bridge name of a network. */
        std::string bridgeOf(const SWgOverlayConfig& c, const std::string& id) {
            return c.bridgeName.empty() ? "wgb-" + shortId(id) : c.bridgeName;
        }

        /* Returns the tunnel MTU of a configuration. */
        uint32_t mtuOf(const SWgOverlayConfig& c) {
            return c.mtu ? c.mtu : 1500 - WG_OVERHEAD;
        }

        /* Returns the nftables table name of a network. */
        std::string natTableOf(const std::string& id) {
            return "sboxwg_" + shortId(id);
        }

        /* Returns the driver's state directory. */
        std::string stateDirOf(const std::string& stateDir) {
            return CFile::join(stateDir, "wg-overlay");
        }

        /* Returns the configuration file of a network. */
        std::string configPathOf(const std::string& stateDir, const std::string& id) {
            return CFile::join(stateDirOf(stateDir), id + ".json");
        }

        /* Writes a configuration (with the private key) readable by root only. */
        int32_t saveConfig(const std::string& stateDir, const std::string& id, const SWgOverlayConfig& c) {
            int32_t r = CFile::makeDirs(stateDirOf(stateDir), 0700);
            if (r != SBOX_OK) {
                return r;
            }

            return CFile::writeAtomic(configPathOf(stateDir, id), c.toJson(true).dump(true), 0600);
        }

        /* Reads a configuration. */
        int32_t loadConfig(const std::string& stateDir, const std::string& id, SWgOverlayConfig& out) {
            std::string text;
            int32_t r = CFile::readAll(configPathOf(stateDir, id), text);
            if (r != SBOX_OK) {
                return r;
            }

            CJson json;
            r = CJson::parse(text, json);
            if (r != SBOX_OK) {
                return r;
            }

            return SWgOverlayConfig::fromJson(json, out);
        }

        /* Checks a host against the overlay and the other hosts. */
        int32_t validateHost(const SWgOverlayConfig& c, const net::SIpPrefix& overlay, const SWgOverlayHost& h) {
            if (!h.publicKey.valid || !h.subnet.isValid() || !h.subnet.address.isV4()) {
                return -EINVAL;
            }

            if (!overlay.contains(h.subnet.address) || h.subnet.length < overlay.length || h.subnet.overlaps(c.hostSubnet)) {
                return -EINVAL;
            }

            for (const SWgOverlayHost& o : c.peers) {
                if (o.publicKey != h.publicKey && o.subnet.overlaps(h.subnet)) {
                    return -EINVAL;
                }
            }

            return SBOX_OK;
        }

        /* Turns a host into a peer change, resolving its endpoint. */
        TTask<int32_t> peerOf(const SWgOverlayHost& h, SWgPeerConfig& out) {
            out = SWgPeerConfig();
            out.publicKey = h.publicKey;
            // --> An all-zero key clears a preshared key the peer had before.
            out.presharedKey = h.presharedKey;
            out.presharedKey.valid = true;
            out.allowedIps = { h.subnet.network() };
            out.persistentKeepalive = h.persistentKeepalive;
            out.replaceAllowedIps = true;

            if (!h.endpoint.empty()) {
                int32_t r = ParseWgEndpoint(h.endpoint, out);
                if (r != SBOX_OK) {
                    co_return r;
                }

                if (!out.endpoint.isValid()) {
                    SWgConfig tmp;
                    tmp.peers.push_back(out);
                    r = co_await ResolveWgConfigEndpoints(tmp);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    out.endpoint = tmp.peers[0].endpoint;
                }
            }

            co_return SBOX_OK;
        }

        /* Builds an nf_tables message with the nfgenmsg header. */
        net::CNlMessage nftMessage(uint16_t command, uint16_t flags) {
            net::CNlMessage msg(uint16_t((NFNL_SUBSYS_NFTABLES << 8) | command), flags);
            nfgenmsg g;
            std::memset(&g, 0, sizeof(g));
            g.nfgen_family = NFPROTO_INET;
            g.version = NFNETLINK_V0;
            msg.putHeader(&g, sizeof(g));
            return msg;
        }

        /* Builds the NAT table of a network: one masquerade rule in a postrouting chain. */
        std::vector<net::CNlMessage> natMessages(const std::string& table, const std::string& bridge, const net::SIpPrefix& local,
            const net::SIpPrefix& overlay)
        {
            std::vector<net::CNlMessage> out;

            // --> "add; delete; add" replaces the table atomically and tolerates a missing one.
            for (int i = 0; i < 3; ++i) {
                net::CNlMessage m = nftMessage(i == 1 ? NFT_MSG_DELTABLE : NFT_MSG_NEWTABLE, uint16_t(i == 1 ? NLM_F_ACK : NLM_F_CREATE | NLM_F_ACK));
                m.putString(NFTA_TABLE_NAME, table);
                if (i != 1) {
                    m.putBe32(NFTA_TABLE_FLAGS, 0);
                }

                out.push_back(std::move(m));
            }

            net::CNlMessage chain = nftMessage(NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK);
            chain.putString(NFTA_CHAIN_TABLE, table);
            chain.putString(NFTA_CHAIN_NAME, "postrouting");
            size_t hook = chain.beginNested(NFTA_CHAIN_HOOK);
            chain.putBe32(NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
            chain.putBe32(NFTA_HOOK_PRIORITY, uint32_t(NF_IP_PRI_NAT_SRC));
            chain.endNested(hook);
            chain.putBe32(NFTA_CHAIN_POLICY, NF_ACCEPT);
            chain.putString(NFTA_CHAIN_TYPE, "nat");
            out.push_back(std::move(chain));

            net::CNftRule rule;
            rule.matchFamily(4).matchSource(local).matchDestination(overlay, false).matchOifname(bridge, false).masquerade();
            net::CNlMessage add = nftMessage(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
            add.putString(NFTA_RULE_TABLE, table);
            add.putString(NFTA_RULE_CHAIN, "postrouting");
            std::vector<uint8_t> exprs = rule.expressions();
            add.put(uint16_t(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED), exprs.data(), exprs.size());
            out.push_back(std::move(add));
            return out;
        }

        /* Adds (or replaces) the route of a remote host's subnet through the WireGuard interface. */
        TTask<int32_t> addHostRoute(net::CRtnl& rtnl, int32_t wgIndex, const net::SIpPrefix& subnet, const net::SIpAddress& source) {
            net::SRouteInfo rt;
            rt.destination = subnet.network();
            rt.oif = wgIndex;
            // --> Host-originated traffic must leave with an address the far side routes back.
            rt.source = source;
            co_return co_await rtnl.addRoute(rt, true);
        }

        /* Deletes the route of a remote host's subnet. */
        TTask<int32_t> delHostRoute(net::CRtnl& rtnl, int32_t wgIndex, const net::SIpPrefix& subnet) {
            net::SRouteInfo rt;
            rt.destination = subnet.network();
            rt.oif = wgIndex;
            int32_t r = co_await rtnl.delRoute(rt);
            co_return r == -ESRCH || r == -ENOENT ? SBOX_OK : r;
        }

        /* Moves an interface of the host into a sandbox under a new name. */
        TTask<int32_t> moveIntoSandbox(net::SNetworkContext& ctx, const std::string& hostName, const std::string& netnsPath,
            const std::string& ifName)
        {
            int32_t index = co_await ctx.host->linkIndex(hostName);
            if (index < 0) {
                co_return index;
            }

            CFd ns;
            int32_t r = net::CNetns::open(netnsPath, ns);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_return co_await ctx.host->moveToNetnsFd(index, ns.get(), ifName);
        }

        /* Moves a joined interface back into the host namespace. */
        TTask<int32_t> moveBackToHost(net::SNetworkContext& ctx, const net::SNetworkEndpoint& ep, const std::string& hostName) {
            if (ep.netnsPath.empty() || ep.sandboxIfName.empty() || !net::CNetns::isNetns(ep.netnsPath)) {
                co_return SBOX_OK;
            }

            net::CRtnl sb;
            if (sb.open(ep.netnsPath) != SBOX_OK) {
                co_return SBOX_OK;
            }

            int32_t index = co_await sb.linkIndex(ep.sandboxIfName);
            if (index < 0) {
                co_return SBOX_OK;
            }

            co_await sb.setUp(index, false);

            CFd host;
            int32_t r = ctx.hostNetns.empty() ? net::CNetns::openCurrent(host) : net::CNetns::open(ctx.hostNetns, host);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_return co_await sb.moveToNetnsFd(index, host.get(), hostName);
        }

        /* Reads the overlay prefix, host subnet and gateway of a network. */
        bool networkLayout(const net::SNetwork& net, net::SIpPrefix& overlay, net::SIpPrefix& local, net::SIpAddress& gateway) {
            const net::SNetworkSubnet* s = net.subnet(4);
            if (!s) {
                return false;
            }

            overlay = s->subnet.network();
            gateway = s->gateway;
            net::SIpPrefix::parse(net.driverState.get("hostSubnet").asString(), local);
            return true;
        }

    }

    /* Serializes a host. */
    CJson SWgOverlayHost::toJson() const {
        CJson j = CJson::object();
        if (!name.empty()) {
            j.set("name", name);
        }

        j.set("publicKey", publicKey.toBase64());
        if (presharedKey.valid && !presharedKey.isZero()) {
            j.set("presharedKey", presharedKey.toBase64());
        }

        if (!endpoint.empty()) {
            j.set("endpoint", endpoint);
        }

        j.set("subnet", subnet.toString());
        if (persistentKeepalive) {
            j.set("persistentKeepalive", uint32_t(persistentKeepalive));
        }

        return j;
    }

    /* Parses a host. */
    int32_t SWgOverlayHost::fromJson(const CJson& json, SWgOverlayHost& out) {
        out = SWgOverlayHost();
        if (!json.isObject()) {
            return -EINVAL;
        }

        out.name = json.get("name").asString();
        if (SWgKey::fromBase64(json.get("publicKey").asString(), out.publicKey) != SBOX_OK) {
            return -EINVAL;
        }

        const std::string& psk = json.get("presharedKey").asString();
        if (!psk.empty() && SWgKey::fromBase64(psk, out.presharedKey) != SBOX_OK) {
            return -EINVAL;
        }

        out.endpoint = json.get("endpoint").asString();
        if (net::SIpPrefix::parse(json.get("subnet").asString(), out.subnet) != SBOX_OK) {
            return -EINVAL;
        }

        int64_t ka = json.get("persistentKeepalive").asInt(0);
        if (ka < 0 || ka > 65535) {
            return -EINVAL;
        }

        out.persistentKeepalive = uint16_t(ka);
        return SBOX_OK;
    }

    /* Serializes a configuration. */
    CJson SWgOverlayConfig::toJson(bool withPrivateKey) const {
        CJson j = CJson::object();
        if (withPrivateKey && privateKey.valid) {
            j.set("privateKey", privateKey.toBase64());
        }

        j.set("listenPort", uint32_t(listenPort));
        j.set("hostSubnet", hostSubnet.toString());
        if (!interfaceName.empty()) {
            j.set("interface", interfaceName);
        }

        if (!bridgeName.empty()) {
            j.set("bridge", bridgeName);
        }

        j.set("mode", modeName(mode));
        if (mtu) {
            j.set("mtu", mtu);
        }

        j.set("nat", nat);
        CJson list = CJson::array();
        for (const SWgOverlayHost& h : peers) {
            list.push(h.toJson());
        }

        j.set("peers", std::move(list));
        return j;
    }

    /* Parses a configuration. */
    int32_t SWgOverlayConfig::fromJson(const CJson& json, SWgOverlayConfig& out) {
        out = SWgOverlayConfig();
        if (!json.isObject()) {
            return -EINVAL;
        }

        const std::string& key = json.get("privateKey").asString();
        if (!key.empty() && SWgKey::fromBase64(key, out.privateKey) != SBOX_OK) {
            return -EINVAL;
        }

        int64_t port = json.get("listenPort").asInt(WG_DEFAULT_PORT);
        if (port < 0 || port > 65535) {
            return -EINVAL;
        }

        out.listenPort = uint16_t(port);
        if (net::SIpPrefix::parse(json.get("hostSubnet").asString(), out.hostSubnet) != SBOX_OK) {
            return -EINVAL;
        }

        out.interfaceName = json.get("interface").asString();
        out.bridgeName = json.get("bridge").asString();
        if (out.interfaceName.size() > 15 || out.bridgeName.size() > 15) {
            return -EINVAL;
        }

        std::string mode = json.get("mode").asString();
        if (mode.empty() || mode == "auto") {
            out.mode = EWGM_AUTO;
        }
        else if (mode == "kernel") {
            out.mode = EWGM_KERNEL;
        }
        else if (mode == "userspace") {
            out.mode = EWGM_USERSPACE;
        }
        else {
            return -EINVAL;
        }

        int64_t mtu = json.get("mtu").asInt(0);
        if (mtu != 0 && (mtu < 576 || mtu > 65535)) {
            return -EINVAL;
        }

        out.mtu = uint32_t(mtu);
        out.nat = json.get("nat").asBool(true);

        const CJson& peers = json.get("peers");
        if (!peers.isNull() && !peers.isArray()) {
            return -EINVAL;
        }

        for (size_t i = 0; i < peers.size(); ++i) {
            SWgOverlayHost h;
            int32_t r = SWgOverlayHost::fromJson(peers.at(i), h);
            if (r != SBOX_OK) {
                return r;
            }

            out.peers.push_back(std::move(h));
        }

        return SBOX_OK;
    }

    /* Builds the network creation request. */
    int32_t MakeWgOverlayNetwork(const std::string& name, const net::SIpPrefix& overlay, const SWgOverlayConfig& config,
        net::SNetworkCreate& out)
    {
        if (!overlay.isValid() || !config.hostSubnet.isValid() || !overlay.contains(config.hostSubnet.address)
            || config.hostSubnet.length < overlay.length || !overlay.address.isV4())
        {
            return -EINVAL;
        }

        out = net::SNetworkCreate();
        out.name = name;
        out.driver = WG_OVERLAY_DRIVER;

        net::SSubnetConfig s;
        s.subnet = overlay.network();
        // --> The host subnet is the containers' on-link prefix: its network and broadcast
        // addresses are not handed out (IPAM only skips those of the whole overlay).
        net::SIpPrefix local = config.hostSubnet.network();
        s.ipRange = local;
        s.rangeStart = local.address.add(1);
        s.rangeEnd = local.size() > 2 ? local.last().add(~uint64_t(0)) : local.last();
        s.gateway = local.address.add(1);
        out.subnets.push_back(s);

        out.options[WG_OVERLAY_OPTION] = config.toJson(true).dump();
        out.options[MTU_OPTION] = std::to_string(mtuOf(config));
        return SBOX_OK;
    }

    /* Creates a driver. */
    CWgOverlayDriver::CWgOverlayDriver(SWgOverlayDriverOptions options) : _options(std::move(options)) {
    }

    /* Stops the user-space devices of this process. */
    CWgOverlayDriver::~CWgOverlayDriver() = default;

    /* Returns the driver name. */
    std::string CWgOverlayDriver::name() const {
        return WG_OVERLAY_DRIVER;
    }

    /* Brings up the WireGuard device of a network. */
    TTask<int32_t> CWgOverlayDriver::startDevice(const std::string& hostNetns, const net::SNetwork& network, const SWgOverlayConfig& config) {
        net::SIpPrefix overlay, local;
        net::SIpAddress gateway;
        networkLayout(network, overlay, local, gateway);
        local = config.hostSubnet.network();

        net::CRtnl rtnl;
        int32_t r = rtnl.open(hostNetns);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::string ifName = interfaceOf(config, network.id);
        SWgDeviceConfig change;
        change.privateKey = config.privateKey;
        change.listenPort = config.listenPort;
        change.replacePeers = true;
        for (const SWgOverlayHost& h : config.peers) {
            SWgPeerConfig pc;
            r = co_await peerOf(h, pc);
            if (r != SBOX_OK) {
                co_return r;
            }

            change.peers.push_back(pc);
        }

        auto it = _devices.find(network.id);
        bool running = it != _devices.end() && it->second->isOpen();

        net::SLinkInfo existing;
        if (!running && co_await rtnl.getLink(ifName, existing) == SBOX_OK) {
            if (existing.kind != "wireguard") {
                // --> A TUN of this name is a user-space device of another process (or a stale
                // leftover): configure it through its UAPI socket when it answers.
                std::string sock = WgUapiSocketPath(ifName, _options.uapiDir);
                r = co_await WgUapiSet(sock, change);
                co_return r == SBOX_OK ? SBOX_OK : -EEXIST;
            }

            r = co_await applyDevice(hostNetns, network.id, config, change);
        }
        else if (!running) {
            std::unique_ptr<CWgDevice> dev(new CWgDevice());
            SWgDeviceOptions o;
            o.name = ifName;
            o.netnsPath = hostNetns;
            o.mode = config.mode;
            o.mtu = mtuOf(config);
            o.uapi = true;
            o.uapiDir = _options.uapiDir;
            o.timers = _options.timers;
            r = co_await dev->create(o);
            if (r != SBOX_OK) {
                co_return r;
            }

            r = co_await dev->configure(change);
            if (r != SBOX_OK) {
                co_await dev->close();
                co_return r;
            }

            _devices[network.id] = std::move(dev);
        }
        else {
            r = co_await it->second->configure(change);
        }

        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t index = co_await rtnl.linkIndex(ifName);
        if (index < 0) {
            co_return index;
        }

        for (const SWgOverlayHost& h : config.peers) {
            r = co_await addHostRoute(rtnl, index, h.subnet, gateway);
            if (r != SBOX_OK) {
                co_return r;
            }
        }

        co_return SBOX_OK;
    }

    /* Applies a change to the device wherever it runs. */
    TTask<int32_t> CWgOverlayDriver::applyDevice(const std::string& hostNetns, const std::string& networkId, const SWgOverlayConfig& config,
        SWgDeviceConfig change)
    {
        auto it = _devices.find(networkId);
        if (it != _devices.end() && it->second->isOpen()) {
            co_return co_await it->second->configure(std::move(change));
        }

        std::string ifName = interfaceOf(config, networkId);
        net::CRtnl rtnl;
        int32_t r = rtnl.open(hostNetns);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SLinkInfo link;
        if (co_await rtnl.getLink(ifName, link) != SBOX_OK) {
            co_return -ENOTCONN;
        }

        if (link.kind == "wireguard") {
            CWgKernelClient kc;
            r = co_await kc.open(hostNetns);
            if (r != SBOX_OK) {
                co_return r;
            }

            co_return co_await kc.setDevice(ifName, std::move(change));
        }

        std::string sock = WgUapiSocketPath(ifName, _options.uapiDir);
        if (!CFile::exists(sock)) {
            co_return -ENOTCONN;
        }

        co_return co_await WgUapiSet(sock, std::move(change));
    }

    /* Creates an overlay network on this host. */
    TTask<int32_t> CWgOverlayDriver::createNetwork(net::SNetworkContext& ctx, net::SNetwork& network) {
        const net::SNetworkSubnet* subnet = network.subnet(4);
        if (!subnet || !subnet->gateway.isValid()) {
            co_return -EINVAL;
        }

        // -- Configuration: inline JSON or a file.
        std::string text = network.option(WG_OVERLAY_OPTION);
        std::string file = network.option(WG_OVERLAY_FILE_OPTION);
        if (text.empty() && !file.empty()) {
            int32_t r = CFile::readAll(file, text);
            if (r != SBOX_OK) {
                co_return r;
            }
        }

        CJson json;
        SWgOverlayConfig config;
        if (text.empty() || CJson::parse(text, json) != SBOX_OK || SWgOverlayConfig::fromJson(json, config) != SBOX_OK) {
            co_return -EINVAL;
        }

        net::SIpPrefix overlay = subnet->subnet.network();
        net::SIpPrefix local = config.hostSubnet.network();
        net::SIpAddress gateway = subnet->gateway;
        if (!config.privateKey.valid || !local.address.isV4() || !overlay.contains(local.address) || local.length < overlay.length
            || !local.contains(gateway))
        {
            co_return -EINVAL;
        }

        SWgOverlayConfig check = config;
        check.peers.clear();
        for (const SWgOverlayHost& h : config.peers) {
            int32_t r = validateHost(check, overlay, h);
            if (r != SBOX_OK) {
                co_return r;
            }

            check.peers.push_back(h);
        }

        std::string bridge = bridgeOf(config, network.id);
        std::string ifName = interfaceOf(config, network.id);
        uint32_t mtu = mtuOf(config);
        if (bridge.size() > 15 || ifName.size() > 15) {
            co_return -EINVAL;
        }

        // --> The private key lives in the driver's 0600 state file, not in the network object.
        int32_t r = saveConfig(ctx.stateDir, network.id, config);
        if (r != SBOX_OK) {
            co_return r;
        }

        network.options.erase(WG_OVERLAY_FILE_OPTION);
        network.options[WG_OVERLAY_OPTION] = config.toJson(false).dump();
        network.options[MTU_OPTION] = std::to_string(mtu);
        network.driverState.set("bridge", bridge);
        network.driverState.set("interface", ifName);
        network.driverState.set("hostSubnet", local.toString());
        network.driverState.set("mtu", mtu);

        // -- Bridge with the gateway address of this host's subnet.
        bool createdBridge = false;
        int32_t bridgeIndex = co_await ctx.host->linkIndex(bridge);
        if (bridgeIndex == -ENODEV) {
            r = co_await ctx.host->createBridge(bridge, mtu);
            if (r == SBOX_OK) {
                createdBridge = true;
                bridgeIndex = co_await ctx.host->linkIndex(bridge);
            }
            else {
                bridgeIndex = r;
            }
        }

        r = bridgeIndex < 0 ? bridgeIndex : SBOX_OK;
        if (r == SBOX_OK) {
            r = co_await ctx.host->addAddress(bridgeIndex, net::SIpPrefix(gateway, local.length), true);
        }

        if (r == SBOX_OK) {
            r = co_await ctx.host->setUp(bridgeIndex, true);
        }

        if (r == SBOX_OK) {
            r = net::SetIpForward(true, ctx.hostNetns);
        }

        // -- WireGuard device, peers and routes.
        if (r == SBOX_OK) {
            r = co_await startDevice(ctx.hostNetns, network, config);
        }

        // -- NAT for traffic leaving the overlay.
        if (r == SBOX_OK && config.nat && !network.internal) {
            net::CFirewall fw;
            std::string table = natTableOf(network.id);
            r = fw.open(ctx.hostNetns, table);
            if (r == SBOX_OK) {
                r = co_await fw.send(natMessages(table, bridge, local, overlay));
            }

            if (r == SBOX_OK) {
                network.driverState.set("natTable", table);
            }
        }

        auto it = _devices.find(network.id);
        network.driverState.set("kernel", it != _devices.end() && it->second->isKernel());

        if (r != SBOX_OK) {
            if (it != _devices.end()) {
                co_await it->second->close();
                _devices.erase(it);
            }

            if (createdBridge && bridgeIndex > 0) {
                co_await ctx.host->deleteLink(bridgeIndex);
            }

            ::unlink(configPathOf(ctx.stateDir, network.id).c_str());
            co_return r;
        }

        co_return SBOX_OK;
    }

    /* Deletes an overlay network on this host. */
    TTask<int32_t> CWgOverlayDriver::deleteNetwork(net::SNetworkContext& ctx, const net::SNetwork& network) {
        auto it = _devices.find(network.id);
        if (it != _devices.end()) {
            co_await it->second->close();
            _devices.erase(it);
        }

        // --> A kernel interface (or one left by another process) is deleted by name.
        std::string ifName = network.driverState.get("interface").asString();
        if (!ifName.empty()) {
            int32_t idx = co_await ctx.host->linkIndex(ifName);
            if (idx > 0) {
                co_await ctx.host->deleteLink(idx);
            }
        }

        std::string bridge = network.driverState.get("bridge").asString();
        if (!bridge.empty()) {
            int32_t idx = co_await ctx.host->linkIndex(bridge);
            if (idx > 0) {
                co_await ctx.host->deleteLink(idx);
            }
        }

        std::string table = network.driverState.get("natTable").asString();
        if (!table.empty()) {
            net::CFirewall fw;
            if (fw.open(ctx.hostNetns, table) == SBOX_OK) {
                co_await fw.remove();
            }
        }

        ::unlink(configPathOf(ctx.stateDir, network.id).c_str());
        co_return SBOX_OK;
    }

    /* Creates the veth pair of a container. */
    TTask<int32_t> CWgOverlayDriver::createEndpoint(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& ep) {
        net::SIpPrefix overlay, local;
        net::SIpAddress gateway;
        if (!networkLayout(network, overlay, local, gateway) || !local.isValid()) {
            co_return -EINVAL;
        }

        // --> Addresses must come from this host's subnet, which is also the on-link prefix.
        for (net::SIpPrefix& a : ep.addresses) {
            if (a.address.isV4()) {
                if (!local.contains(a.address)) {
                    co_return -EADDRNOTAVAIL;
                }

                a.length = local.length;
            }
        }

        if (ep.mtu == 0) {
            ep.mtu = uint32_t(network.driverState.get("mtu").asInt(1500 - WG_OVERHEAD));
        }

        int32_t bridge = co_await ctx.host->linkIndex(network.driverState.get("bridge").asString());
        if (bridge < 0) {
            co_return bridge;
        }

        std::string hostName = "veth" + net::RandomHex(7);
        std::string peer = "veth" + net::RandomHex(7);
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

    /* Moves the container end into the sandbox and configures it. */
    TTask<int32_t> CWgOverlayDriver::join(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& ep,
        std::string netnsPath, std::string ifName)
    {
        net::SIpPrefix overlay, local;
        net::SIpAddress gateway;
        networkLayout(network, overlay, local, gateway);

        std::string peer = ep.driverState.get("peer").asString();
        int32_t r = co_await moveIntoSandbox(ctx, peer, netnsPath, ifName);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::CRtnl sb;
        r = sb.open(netnsPath);
        int32_t index = r == SBOX_OK ? co_await sb.linkIndex(ifName) : r;
        r = index < 0 ? index : SBOX_OK;

        if (r == SBOX_OK && ep.mtu) {
            r = co_await sb.setMtu(index, ep.mtu);
        }

        for (const net::SIpPrefix& a : ep.addresses) {
            if (r == SBOX_OK) {
                r = co_await sb.addAddress(index, a, true);
            }
        }

        if (r == SBOX_OK) {
            r = co_await sb.setUp(index, true);
        }

        if (r == SBOX_OK) {
            co_await sb.setUp(1, true);

            // --> The whole overlay is reached through the local bridge, even on internal networks.
            net::SRouteInfo rt;
            rt.destination = overlay;
            rt.gateway = gateway;
            rt.oif = index;
            r = co_await sb.addRoute(rt, true);
        }

        for (const net::SIpAddress& gw : ep.gateways) {
            if (r == SBOX_OK) {
                r = co_await sb.addDefaultRoute(gw, index, true);
            }
        }

        if (r != SBOX_OK) {
            net::SNetworkEndpoint joined = ep;
            joined.netnsPath = netnsPath;
            joined.sandboxIfName = ifName;
            co_await moveBackToHost(ctx, joined, peer);
        }

        co_return r;
    }

    /* Join description for sandboxes that move interfaces themselves. */
    TTask<int32_t> CWgOverlayDriver::joinInfo(net::SNetworkContext& ctx, const net::SNetwork& network, const net::SNetworkEndpoint& ep,
        net::SJoinInfo& out)
    {
        (void)ctx;
        net::SIpPrefix overlay, local;
        net::SIpAddress gateway;
        networkLayout(network, overlay, local, gateway);

        out = net::SJoinInfo();
        out.srcName = ep.driverState.get("peer").asString();
        if (!network.internal) {
            out.gateway = gateway;
        }

        net::SRouteInfo rt;
        rt.destination = overlay;
        rt.gateway = gateway;
        out.staticRoutes.push_back(rt);
        co_return SBOX_OK;
    }

    /* Moves the container end back to the host. */
    TTask<int32_t> CWgOverlayDriver::leave(net::SNetworkContext& ctx, const net::SNetwork& network, net::SNetworkEndpoint& ep) {
        (void)network;
        co_return co_await moveBackToHost(ctx, ep, ep.driverState.get("peer").asString());
    }

    /* Deletes the veth pair. */
    TTask<int32_t> CWgOverlayDriver::deleteEndpoint(net::SNetworkContext& ctx, const net::SNetwork& network, const net::SNetworkEndpoint& ep) {
        (void)network;
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

    /* Adds or updates a host at run time. */
    TTask<int32_t> CWgOverlayDriver::addHost(net::CNetworkManager& manager, std::string network, SWgOverlayHost host) {
        net::SNetwork net;
        int32_t r = co_await manager.getNetwork(network, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (net.driver != WG_OVERLAY_DRIVER) {
            co_return -EINVAL;
        }

        const std::string& stateDir = manager.options().stateDir;
        net::CFileLock lock;
        r = co_await lock.lock(CFile::join(stateDirOf(stateDir), net.id + ".lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SWgOverlayConfig config;
        r = loadConfig(stateDir, net.id, config);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SIpPrefix overlay, local;
        net::SIpAddress gateway;
        networkLayout(net, overlay, local, gateway);
        r = validateHost(config, overlay, host);
        if (r != SBOX_OK) {
            co_return r;
        }

        SWgPeerConfig pc;
        r = co_await peerOf(host, pc);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SIpPrefix oldSubnet;
        bool replaced = false;
        for (SWgOverlayHost& h : config.peers) {
            if (h.publicKey == host.publicKey) {
                oldSubnet = h.subnet;
                h = host;
                replaced = true;
            }
        }

        if (!replaced) {
            config.peers.push_back(host);
        }

        SWgDeviceConfig change;
        change.peers.push_back(pc);
        r = co_await applyDevice(manager.options().hostNetns, net.id, config, change);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = saveConfig(stateDir, net.id, config);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::CRtnl rtnl;
        r = rtnl.open(manager.options().hostNetns);
        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t index = co_await rtnl.linkIndex(interfaceOf(config, net.id));
        if (index < 0) {
            co_return index;
        }

        if (replaced && oldSubnet.isValid() && oldSubnet != host.subnet) {
            co_await delHostRoute(rtnl, index, oldSubnet);
        }

        co_return co_await addHostRoute(rtnl, index, host.subnet, gateway);
    }

    /* Removes a host at run time. */
    TTask<int32_t> CWgOverlayDriver::removeHost(net::CNetworkManager& manager, std::string network, SWgKey publicKey) {
        net::SNetwork net;
        int32_t r = co_await manager.getNetwork(network, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (net.driver != WG_OVERLAY_DRIVER) {
            co_return -EINVAL;
        }

        const std::string& stateDir = manager.options().stateDir;
        net::CFileLock lock;
        r = co_await lock.lock(CFile::join(stateDirOf(stateDir), net.id + ".lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SWgOverlayConfig config;
        r = loadConfig(stateDir, net.id, config);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SIpPrefix subnet;
        for (size_t i = 0; i < config.peers.size(); ++i) {
            if (config.peers[i].publicKey == publicKey) {
                subnet = config.peers[i].subnet;
                config.peers.erase(config.peers.begin() + ptrdiff_t(i));
                break;
            }
        }

        if (!subnet.isValid()) {
            co_return -ENOENT;
        }

        SWgDeviceConfig change;
        SWgPeerConfig pc;
        pc.publicKey = publicKey;
        pc.remove = true;
        change.peers.push_back(pc);
        r = co_await applyDevice(manager.options().hostNetns, net.id, config, change);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = saveConfig(stateDir, net.id, config);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::CRtnl rtnl;
        r = rtnl.open(manager.options().hostNetns);
        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t index = co_await rtnl.linkIndex(interfaceOf(config, net.id));
        if (index < 0) {
            co_return SBOX_OK;
        }

        co_return co_await delHostRoute(rtnl, index, subnet);
    }

    /* Reads the configuration of a network. */
    TTask<int32_t> CWgOverlayDriver::config(net::CNetworkManager& manager, std::string network, SWgOverlayConfig& out) {
        net::SNetwork net;
        int32_t r = co_await manager.getNetwork(network, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (net.driver != WG_OVERLAY_DRIVER) {
            co_return -EINVAL;
        }

        co_return loadConfig(manager.options().stateDir, net.id, out);
    }

    /* Reads the device of a network. */
    TTask<int32_t> CWgOverlayDriver::status(net::CNetworkManager& manager, std::string network, SWgDeviceStatus& out) {
        SWgOverlayConfig cfg;
        int32_t r = co_await config(manager, network, cfg);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SNetwork net;
        r = co_await manager.getNetwork(network, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        auto it = _devices.find(net.id);
        if (it != _devices.end() && it->second->isOpen()) {
            co_return co_await it->second->status(out);
        }

        std::string ifName = interfaceOf(cfg, net.id);
        CWgKernelClient kc;
        if (co_await kc.open(manager.options().hostNetns) == SBOX_OK && co_await kc.getDevice(ifName, out) == SBOX_OK) {
            co_return SBOX_OK;
        }

        std::string sock = WgUapiSocketPath(ifName, _options.uapiDir);
        if (!CFile::exists(sock)) {
            co_return -ENOTCONN;
        }

        r = co_await WgUapiGet(sock, out);
        out.name = ifName;
        co_return r;
    }

    /* Restarts missing devices. */
    TTask<int32_t> CWgOverlayDriver::restore(net::CNetworkManager& manager) {
        std::vector<net::SNetwork> networks;
        int32_t r = co_await manager.listNetworks(networks);
        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t started = 0;
        for (const net::SNetwork& net : networks) {
            if (net.driver != WG_OVERLAY_DRIVER) {
                continue;
            }

            auto it = _devices.find(net.id);
            if (it != _devices.end() && it->second->isOpen()) {
                continue;
            }

            SWgOverlayConfig cfg;
            r = loadConfig(manager.options().stateDir, net.id, cfg);
            if (r != SBOX_OK) {
                co_return r;
            }

            r = co_await startDevice(manager.options().hostNetns, net, cfg);
            if (r == -EEXIST) {
                continue;   // --> Running in another process.
            }

            if (r != SBOX_OK) {
                co_return r;
            }

            ++started;
        }

        co_return started;
    }

}
}
