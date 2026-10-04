#include <sbox/net/docker.hpp>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>

namespace sbox {
namespace net {

    namespace {

        /* Builds an error reply. */
        CJson errorReply(const std::string& what, int32_t error) {
            CJson j = CJson::object();
            std::string msg = what;
            if (error < 0) {
                msg += ": ";
                msg += std::strerror(-error);
            }

            j.set("Err", msg);
            return j;
        }

        /* Returns an empty success reply. */
        CJson ok() {
            return CJson::object();
        }

        /* Parses "ip/len" or a bare address. */
        bool parseCidr(const std::string& text, SIpPrefix& out) {
            return !text.empty() && SIpPrefix::parse(text, out) == SBOX_OK;
        }

        /* Collects the generic (driver -o) options as strings. */
        std::map<std::string, std::string> genericOptions(const CJson& options) {
            std::map<std::string, std::string> out;
            const CJson& generic = options.get("com.docker.network.generic");
            if (!generic.isObject()) {
                return out;
            }

            for (size_t i = 0; i < generic.size(); ++i) {
                const CJson& v = generic.at(i);
                if (v.isString()) {
                    out[generic.keyAt(i)] = v.asString();
                }
                else if (v.isBool()) {
                    out[generic.keyAt(i)] = v.asBool() ? "true" : "false";
                }
                else if (v.isNumber()) {
                    out[generic.keyAt(i)] = std::to_string(v.asInt());
                }
            }

            return out;
        }

        /* Converts Docker's IPv4Data/IPv6Data entries into subnets. */
        bool subnetsOf(const CJson& data, std::vector<SSubnetConfig>& out) {
            for (size_t i = 0; i < data.size(); ++i) {
                const CJson& d = data.at(i);
                SSubnetConfig s;
                if (!parseCidr(d.get("Pool").asString(), s.subnet)) {
                    return false;
                }

                s.subnet = s.subnet.network();
                SIpPrefix gw;
                if (parseCidr(d.get("Gateway").asString(), gw)) {
                    s.gateway = gw.address;
                }

                const CJson& aux = d.get("AuxAddresses");
                for (size_t k = 0; k < aux.size(); ++k) {
                    SIpPrefix a;
                    if (parseCidr(aux.at(k).asString(), a)) {
                        s.auxAddresses[aux.keyAt(k)] = a.address;
                    }
                }

                out.push_back(s);
            }

            return true;
        }

    }

    /* Returns the reply content type. */
    const char* CDockerPlugin::contentType() noexcept {
        return "application/vnd.docker.plugins.v1.2+json";
    }

    /* Returns true when the reply is an error. */
    bool CDockerPlugin::isError(const CJson& reply) noexcept {
        const CJson* err = reply.find("Err");
        return err && err->isString() && !err->asString().empty();
    }

    /* Dispatches a plugin call. */
    TTask<CJson> CDockerPlugin::handle(std::string path, CJson body) {
        if (path == "/Plugin.Activate") {
            CJson j = CJson::object();
            j.set("Implements", CJson::fromStrings({ "NetworkDriver", "IpamDriver" }));
            co_return j;
        }

        // -- Network driver.

        if (path == "/NetworkDriver.GetCapabilities") {
            CJson j = CJson::object();
            j.set("Scope", "local");
            j.set("ConnectivityScope", "local");
            co_return j;
        }

        if (path == "/NetworkDriver.CreateNetwork") {
            co_return co_await createNetwork(body);
        }

        if (path == "/NetworkDriver.DeleteNetwork") {
            int32_t r = co_await _manager.deleteNetwork(body.get("NetworkID").asString());
            co_return r == SBOX_OK || r == -ENOENT ? ok() : errorReply("cannot delete network", r);
        }

        if (path == "/NetworkDriver.CreateEndpoint") {
            co_return co_await createEndpoint(body);
        }

        if (path == "/NetworkDriver.EndpointOperInfo") {
            SNetworkEndpoint ep;
            int32_t r = co_await _manager.getEndpoint(body.get("EndpointID").asString(), ep);
            if (r != SBOX_OK) {
                co_return errorReply("unknown endpoint", r);
            }

            CJson value = CJson::object();
            value.set("hostInterface", ep.hostIfName);
            value.set("macAddress", ep.mac.isValid() ? ep.mac.toString() : std::string());
            CJson addrs = CJson::array();
            for (const SIpPrefix& a : ep.addresses) {
                addrs.push(a.toString());
            }

            value.set("addresses", std::move(addrs));
            CJson ports = CJson::array();
            for (const SPortMapping& p : ep.ports) {
                ports.push(p.toJson());
            }

            value.set("ports", std::move(ports));
            CJson j = CJson::object();
            j.set("Value", std::move(value));
            co_return j;
        }

        if (path == "/NetworkDriver.DeleteEndpoint") {
            int32_t r = co_await _manager.deleteEndpoint(body.get("EndpointID").asString());
            co_return r == SBOX_OK || r == -ENOENT ? ok() : errorReply("cannot delete endpoint", r);
        }

        if (path == "/NetworkDriver.Join") {
            co_return co_await join(body);
        }

        if (path == "/NetworkDriver.Leave" || path == "/NetworkDriver.DiscoverNew" || path == "/NetworkDriver.DiscoverDelete") {
            co_return ok();
        }

        if (path == "/NetworkDriver.ProgramExternalConnectivity") {
            co_return co_await programExternal(body);
        }

        if (path == "/NetworkDriver.RevokeExternalConnectivity") {
            int32_t r = co_await _manager.setPortMappings(body.get("EndpointID").asString(), std::vector<SPortMapping>());
            co_return r == SBOX_OK || r == -ENOENT ? ok() : errorReply("cannot revoke port mappings", r);
        }

        // -- IPAM driver.

        if (path == "/IpamDriver.GetCapabilities") {
            CJson j = CJson::object();
            j.set("RequiresMACAddress", false);
            j.set("RequiresRequestReplay", false);
            co_return j;
        }

        if (path == "/IpamDriver.GetDefaultAddressSpaces") {
            CJson j = CJson::object();
            j.set("LocalDefaultAddressSpace", "local");
            j.set("GlobalDefaultAddressSpace", "global");
            co_return j;
        }

        if (path == "/IpamDriver.RequestPool") {
            co_return co_await requestPool(body);
        }

        if (path == "/IpamDriver.ReleasePool") {
            int32_t r = co_await _manager.ipam().releasePool(body.get("PoolID").asString());
            co_return r == SBOX_OK || r == -ENOENT ? ok() : errorReply("cannot release pool", r);
        }

        if (path == "/IpamDriver.RequestAddress") {
            co_return co_await requestAddress(body);
        }

        if (path == "/IpamDriver.ReleaseAddress") {
            SIpPrefix a;
            if (!parseCidr(body.get("Address").asString(), a)) {
                co_return errorReply("invalid address", -EINVAL);
            }

            int32_t r = co_await _manager.ipam().releaseAddress(body.get("PoolID").asString(), a.address);
            co_return r == SBOX_OK || r == -ENOENT ? ok() : errorReply("cannot release address", r);
        }

        co_return errorReply("unsupported plugin call " + path, -ENOTSUP);
    }

    /* NetworkDriver.CreateNetwork. */
    TTask<CJson> CDockerPlugin::createNetwork(const CJson& body) {
        std::string id = body.get("NetworkID").asString();
        if (id.empty()) {
            co_return errorReply("missing NetworkID", -EINVAL);
        }

        const CJson& options = body.get("Options");
        SNetworkCreate req;
        req.id = id;
        req.name = id;
        req.ipamDriver = "external";
        req.options = genericOptions(options);
        req.enableIpv6 = options.get("com.docker.network.enable_ipv6").asBool(false);
        req.internal = options.get("com.docker.network.internal").asBool(false);

        auto drv = req.options.find("sbox.driver");
        req.driver = drv == req.options.end() ? "bridge" : drv->second;

        if (!subnetsOf(body.get("IPv4Data"), req.subnets) || !subnetsOf(body.get("IPv6Data"), req.subnets)) {
            co_return errorReply("invalid IPv4Data/IPv6Data", -EINVAL);
        }

        SNetwork net;
        int32_t r = co_await _manager.createNetwork(req, net);
        co_return r == SBOX_OK ? ok() : errorReply("cannot create network", r);
    }

    /* NetworkDriver.CreateEndpoint. */
    TTask<CJson> CDockerPlugin::createEndpoint(const CJson& body) {
        const CJson& iface = body.get("Interface");
        SEndpointCreate req;
        req.id = body.get("EndpointID").asString();
        req.containerId = req.id;

        std::string v4 = iface.get("Address").asString();
        std::string v6 = iface.get("AddressIPv6").asString();
        std::string mac = iface.get("MacAddress").asString();

        if ((!v4.empty() && !parseCidr(v4, req.ipv4)) || (!v6.empty() && !parseCidr(v6, req.ipv6))
            || (!mac.empty() && SMacAddress::parse(mac, req.mac) != SBOX_OK))
        {
            co_return errorReply("invalid Interface", -EINVAL);
        }

        SNetworkEndpoint ep;
        int32_t r = co_await _manager.createEndpoint(body.get("NetworkID").asString(), req, ep);
        if (r != SBOX_OK) {
            co_return errorReply("cannot create endpoint", r);
        }

        // --> Only report what Docker did not assign itself; echoing its values is an error.
        CJson out = CJson::object();
        if (mac.empty() && ep.mac.isValid()) {
            out.set("MacAddress", ep.mac.toString());
        }

        if (v4.empty() && ep.address(4).isValid()) {
            out.set("Address", ep.address(4).toString());
        }

        if (v6.empty() && ep.address(6).isValid()) {
            out.set("AddressIPv6", ep.address(6).toString());
        }

        CJson j = CJson::object();
        j.set("Interface", std::move(out));
        co_return j;
    }

    /* NetworkDriver.Join. */
    TTask<CJson> CDockerPlugin::join(const CJson& body) {
        SJoinInfo info;
        int32_t r = co_await _manager.joinInfo(body.get("EndpointID").asString(), info);
        if (r != SBOX_OK) {
            co_return errorReply("cannot join", r);
        }

        CJson name = CJson::object();
        name.set("SrcName", info.srcName);
        name.set("DstPrefix", info.dstPrefix);

        CJson routes = CJson::array();
        for (const SRouteInfo& rt : info.staticRoutes) {
            CJson rj = CJson::object();
            rj.set("Destination", rt.destination.toString());
            rj.set("RouteType", rt.gateway.isValid() ? 0 : 1);
            rj.set("NextHop", rt.gateway.isValid() ? rt.gateway.toString() : std::string());
            routes.push(std::move(rj));
        }

        CJson j = CJson::object();
        j.set("InterfaceName", std::move(name));
        j.set("Gateway", info.gateway.isValid() ? info.gateway.toString() : std::string());
        j.set("GatewayIPv6", info.gateway6.isValid() ? info.gateway6.toString() : std::string());
        j.set("StaticRoutes", std::move(routes));
        j.set("DisableGatewayService", false);
        co_return j;
    }

    /* NetworkDriver.ProgramExternalConnectivity. */
    TTask<CJson> CDockerPlugin::programExternal(const CJson& body) {
        const CJson& pm = body.get("Options").get("com.docker.network.portmap");
        std::vector<SPortMapping> ports;

        for (size_t i = 0; i < pm.size(); ++i) {
            const CJson& p = pm.at(i);
            SPortMapping m;
            int64_t proto = p.get("Proto").asInt(IPPROTO_TCP);
            if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_SCTP) {
                co_return errorReply("unsupported port protocol", -EINVAL);
            }

            m.protocol = uint8_t(proto);
            int64_t cp = p.get("Port").asInt(0);
            int64_t hp = p.get("HostPort").asInt(0);
            if (cp <= 0 || cp > 65535 || hp < 0 || hp > 65535) {
                co_return errorReply("invalid port mapping", -EINVAL);
            }

            m.containerPort = uint16_t(cp);
            m.hostPort = uint16_t(hp);
            std::string hostIp = p.get("HostIP").asString();
            if (!hostIp.empty() && SIpAddress::parse(hostIp, m.hostIp) != SBOX_OK) {
                co_return errorReply("invalid port mapping host IP", -EINVAL);
            }

            ports.push_back(m);
        }

        int32_t r = co_await _manager.setPortMappings(body.get("EndpointID").asString(), ports);
        co_return r == SBOX_OK ? ok() : errorReply("cannot program port mappings", r);
    }

    /* IpamDriver.RequestPool. */
    TTask<CJson> CDockerPlugin::requestPool(const CJson& body) {
        SIpamRequest req;
        req.space = body.get("AddressSpace").asString();
        if (req.space.empty()) {
            req.space = "local";
        }

        req.family = body.get("V6").asBool(false) ? 6 : 4;
        std::string pool = body.get("Pool").asString();
        std::string sub = body.get("SubPool").asString();

        if ((!pool.empty() && !parseCidr(pool, req.subnet)) || (!sub.empty() && !parseCidr(sub, req.range))) {
            co_return errorReply("invalid Pool/SubPool", -EINVAL);
        }

        if (!sub.empty() && pool.empty()) {
            co_return errorReply("SubPool without Pool", -EINVAL);
        }

        // --> Distinct ids for the same subnet with different sub-pools.
        if (req.subnet.isValid()) {
            req.id = req.space + "/" + req.subnet.network().toString() + (sub.empty() ? std::string() : "/" + req.range.toString());
        }

        SIpamPool out;
        int32_t r = co_await _manager.ipam().requestPool(req, out);
        if (r != SBOX_OK) {
            co_return errorReply("cannot allocate pool", r);
        }

        CJson j = CJson::object();
        j.set("PoolID", out.id);
        j.set("Pool", out.subnet.toString());
        j.set("Data", CJson::object());
        co_return j;
    }

    /* IpamDriver.RequestAddress. */
    TTask<CJson> CDockerPlugin::requestAddress(const CJson& body) {
        std::string poolId = body.get("PoolID").asString();
        SIpamPool pool;
        int32_t r = co_await _manager.ipam().getPool(poolId, pool);
        if (r != SBOX_OK) {
            co_return errorReply("unknown pool", r);
        }

        SIpAddress preferred;
        std::string text = body.get("Address").asString();
        if (!text.empty()) {
            SIpPrefix p;
            if (!parseCidr(text, p)) {
                co_return errorReply("invalid Address", -EINVAL);
            }

            preferred = p.address;
        }

        bool gateway = body.get("Options").get("RequestAddressType").asString() == "com.docker.network.gateway";
        if (gateway && !preferred.isValid() && pool.subnet.length + 1 < int32_t(pool.subnet.address.bits())) {
            // --> Docker's default gateway: the first host address of the pool.
            preferred = pool.subnet.at(1);
        }

        SIpAddress got;
        r = co_await _manager.ipam().requestAddress(poolId, preferred, gateway ? "gateway" : "docker", got);
        if (r != SBOX_OK) {
            co_return errorReply("cannot allocate address", r);
        }

        CJson j = CJson::object();
        j.set("Address", SIpPrefix(got, pool.subnet.length).toString());
        j.set("Data", CJson::object());
        co_return j;
    }

}
}
