#include <sbox/net/cni.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/network.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

namespace sbox {
namespace net {

    namespace {

        const char* const SUPPORTED_VERSIONS[] = { "0.3.0", "0.3.1", "0.4.0", "1.0.0" };

        /* CNI failure carried up to RunCni. */
        struct SCniFailure {
            int32_t code = 0;
            std::string msg;
            std::string details;
        };

        /* Parsed network configuration. */
        struct SCniConfig {
            std::string version;
            std::string name;
            std::string driver;
            std::string bridge;
            uint32_t mtu = 0;
            bool ipMasq = false;
            std::string master;
            std::string mode;
            std::string stateDir;
            std::string ipamType;
            std::vector<SSubnetConfig> subnets;
            std::vector<SIpPrefix> routes;
            std::vector<SPortMapping> ports;
            std::vector<SIpPrefix> staticIps;
            SMacAddress mac;
            CJson dns;
            CJson prevResult;
        };

        /* Returns true when `v` is a supported CNI version. */
        bool supportedVersion(const std::string& v) {
            for (const char* s : SUPPORTED_VERSIONS) {
                if (v == s) {
                    return true;
                }
            }

            return false;
        }

        /* Builds the error object. */
        std::string errorJson(const std::string& version, const SCniFailure& f) {
            CJson j = CJson::object();
            j.set("cniVersion", version.empty() ? std::string("1.0.0") : version);
            j.set("code", f.code);
            j.set("msg", f.msg);
            if (!f.details.empty()) {
                j.set("details", f.details);
            }

            return j.dump(true);
        }

        /* Makes a failure from an errno result. */
        SCniFailure failure(int32_t code, std::string msg, int32_t error = 0) {
            SCniFailure f;
            f.code = code;
            f.msg = std::move(msg);
            if (error < 0) {
                f.details = std::strerror(-error);
            }

            return f;
        }

        /* Parses one ipam range object into a subnet config. */
        bool parseRange(const CJson& r, SSubnetConfig& out) {
            if (SIpPrefix::parse(r.get("subnet").asString(), out.subnet) != SBOX_OK) {
                return false;
            }

            if (r.find("rangeStart") && SIpAddress::parse(r.get("rangeStart").asString(), out.rangeStart) != SBOX_OK) {
                return false;
            }

            if (r.find("rangeEnd") && SIpAddress::parse(r.get("rangeEnd").asString(), out.rangeEnd) != SBOX_OK) {
                return false;
            }

            if (r.find("gateway") && SIpAddress::parse(r.get("gateway").asString(), out.gateway) != SBOX_OK) {
                return false;
            }

            return true;
        }

        /* Parses the network configuration. */
        bool parseConfig(const CJson& j, SCniConfig& c, SCniFailure& f) {
            if (!j.isObject()) {
                f = failure(ECNI_DECODE_FAILURE, "network configuration is not a JSON object");
                return false;
            }

            c.version = j.get("cniVersion").asString();
            c.name = j.get("name").asString();
            if (c.name.empty()) {
                f = failure(ECNI_INVALID_CONFIG, "missing network name");
                return false;
            }

            c.driver = j.get("driver").asString();
            if (c.driver.empty()) {
                std::string type = j.get("type").asString();
                c.driver = (type == "macvlan" || type == "ipvlan") ? type : "bridge";
            }

            if (c.driver != "bridge" && c.driver != "macvlan" && c.driver != "ipvlan") {
                f = failure(ECNI_INVALID_CONFIG, "unsupported driver: " + c.driver);
                return false;
            }

            c.bridge = j.get("bridge").asString();
            c.mtu = uint32_t(j.get("mtu").asInt(0));
            c.ipMasq = j.get("ipMasq").asBool(false);
            c.master = j.get("master").asString();
            c.mode = j.get("mode").asString();
            c.stateDir = j.get("stateDir").asString();
            c.dns = j.get("dns");
            c.prevResult = j.get("prevResult");

            const CJson& ipam = j.get("ipam");
            c.ipamType = ipam.get("type").asString();
            if (c.stateDir.empty()) {
                c.stateDir = ipam.get("dataDir").asString();
            }

            if (c.ipamType != "dhcp") {
                if (!c.ipamType.empty() && c.ipamType != "sbox" && c.ipamType != "host-local") {
                    f = failure(ECNI_INVALID_CONFIG, "unsupported ipam type: " + c.ipamType);
                    return false;
                }

                if (ipam.find("subnet")) {
                    SSubnetConfig s;
                    if (!parseRange(ipam, s)) {
                        f = failure(ECNI_INVALID_CONFIG, "invalid ipam subnet/range");
                        return false;
                    }

                    c.subnets.push_back(s);
                }

                const CJson& ranges = ipam.get("ranges");
                for (size_t i = 0; i < ranges.size(); ++i) {
                    // --> One subnet per range set; further ranges of a set are not supported.
                    const CJson& set = ranges.at(i);
                    const CJson& first = set.isArray() ? set.at(0) : set;
                    SSubnetConfig s;
                    if (set.isArray() && set.size() == 0) {
                        continue;
                    }

                    if (!parseRange(first, s)) {
                        f = failure(ECNI_INVALID_CONFIG, "invalid ipam range");
                        return false;
                    }

                    c.subnets.push_back(s);
                }

                const CJson& routes = ipam.get("routes");
                for (size_t i = 0; i < routes.size(); ++i) {
                    SIpPrefix dst;
                    if (SIpPrefix::parse(routes.at(i).get("dst").asString(), dst) != SBOX_OK) {
                        f = failure(ECNI_INVALID_CONFIG, "invalid ipam route");
                        return false;
                    }

                    c.routes.push_back(dst);
                }
            }

            if ((c.driver == "macvlan" || c.driver == "ipvlan") && c.master.empty()) {
                f = failure(ECNI_INVALID_CONFIG, "\"master\" is required for " + c.driver);
                return false;
            }

            // --> Capabilities passed by the runtime.
            const CJson& rc = j.get("runtimeConfig");
            const CJson& pms = rc.get("portMappings");
            for (size_t i = 0; i < pms.size(); ++i) {
                const CJson& p = pms.at(i);
                SPortMapping m;
                std::string proto = p.get("protocol").asString();
                m.protocol = proto == "udp" ? IPPROTO_UDP : (proto == "sctp" ? IPPROTO_SCTP : IPPROTO_TCP);
                int64_t hp = p.get("hostPort").asInt(0);
                int64_t cp = p.get("containerPort").asInt(0);
                if (hp < 0 || hp > 65535 || cp <= 0 || cp > 65535) {
                    f = failure(ECNI_INVALID_CONFIG, "invalid port mapping");
                    return false;
                }

                m.hostPort = uint16_t(hp);
                m.containerPort = uint16_t(cp);
                std::string hostIp = p.get("hostIP").asString();
                if (!hostIp.empty() && SIpAddress::parse(hostIp, m.hostIp) != SBOX_OK) {
                    f = failure(ECNI_INVALID_CONFIG, "invalid port mapping host IP");
                    return false;
                }

                c.ports.push_back(m);
            }

            const CJson& ips = rc.get("ips");
            for (size_t i = 0; i < ips.size(); ++i) {
                SIpPrefix p;
                if (SIpPrefix::parse(ips.at(i).asString(), p) == SBOX_OK) {
                    c.staticIps.push_back(p);
                }
            }

            if (rc.find("mac")) {
                SMacAddress::parse(rc.get("mac").asString(), c.mac);
            }

            return true;
        }

        /* Applies CNI_ARGS (IP=..., MAC=...); unknown keys are ignored. */
        void applyArgs(const std::string& args, SCniConfig& c) {
            size_t at = 0;
            while (at <= args.size()) {
                size_t end = args.find(';', at);
                std::string kv = args.substr(at, end == std::string::npos ? std::string::npos : end - at);
                size_t eq = kv.find('=');
                if (eq != std::string::npos) {
                    std::string k = kv.substr(0, eq);
                    std::string v = kv.substr(eq + 1);
                    if (k == "IP") {
                        size_t from = 0;
                        while (from <= v.size()) {
                            size_t comma = v.find(',', from);
                            SIpPrefix p;
                            if (SIpPrefix::parse(v.substr(from, comma == std::string::npos ? std::string::npos : comma - from), p) == SBOX_OK) {
                                c.staticIps.push_back(p);
                            }

                            if (comma == std::string::npos) {
                                break;
                            }

                            from = comma + 1;
                        }
                    }
                    else if (k == "MAC") {
                        SMacAddress::parse(v, c.mac);
                    }
                }

                if (end == std::string::npos) {
                    break;
                }

                at = end + 1;
            }
        }

        /* Finds the endpoint of (container, ifname) on a network. */
        TTask<int32_t> findEndpoint(CNetworkManager& mgr, const std::string& network, const std::string& containerId,
            const std::string& ifName, SNetworkEndpoint& out)
        {
            std::vector<SNetworkEndpoint> eps;
            int32_t r = co_await mgr.listEndpoints(network, eps);
            if (r != SBOX_OK) {
                co_return r;
            }

            for (SNetworkEndpoint& e : eps) {
                if (e.containerId == containerId && e.labels["io.cni.ifname"] == ifName) {
                    out = std::move(e);
                    co_return SBOX_OK;
                }
            }

            co_return -ENOENT;
        }

        /* Builds a CNI result for an endpoint. */
        TTask<CJson> buildResult(const SCniConfig& c, const SNetwork& net, const SNetworkEndpoint& ep, const std::string& hostNetns) {
            bool legacy = c.version != "1.0.0";
            CJson result = CJson::object();
            result.set("cniVersion", c.version);

            CJson ifaces = CJson::array();
            CRtnl host;
            bool haveHost = host.open(hostNetns) == SBOX_OK;

            if (c.driver == "bridge" && haveHost) {
                std::string br = net.driverState.get("bridge").asString();
                SLinkInfo info;
                CJson b = CJson::object();
                b.set("name", br);
                if (co_await host.getLink(br, info) == SBOX_OK && info.mac.isValid()) {
                    b.set("mac", info.mac.toString());
                }

                ifaces.push(std::move(b));

                CJson v = CJson::object();
                v.set("name", ep.hostIfName);
                if (co_await host.getLink(ep.hostIfName, info) == SBOX_OK && info.mac.isValid()) {
                    v.set("mac", info.mac.toString());
                }

                ifaces.push(std::move(v));
            }

            CJson sb = CJson::object();
            sb.set("name", ep.sandboxIfName);
            if (ep.mac.isValid()) {
                sb.set("mac", ep.mac.toString());
            }

            sb.set("sandbox", ep.netnsPath);
            int32_t sandboxIndex = int32_t(ifaces.size());
            ifaces.push(std::move(sb));
            result.set("interfaces", std::move(ifaces));

            CJson ips = CJson::array();
            for (const SIpPrefix& a : ep.addresses) {
                CJson ipj = CJson::object();
                if (legacy) {
                    ipj.set("version", a.address.isV4() ? "4" : "6");
                }

                ipj.set("address", a.toString());
                for (const SIpAddress& g : ep.gateways) {
                    if (g.family == a.address.family) {
                        ipj.set("gateway", g.toString());
                        break;
                    }
                }

                ipj.set("interface", sandboxIndex);
                ips.push(std::move(ipj));
            }

            result.set("ips", std::move(ips));

            CJson routes = CJson::array();
            for (const SIpAddress& g : ep.gateways) {
                CJson rj = CJson::object();
                rj.set("dst", g.isV4() ? "0.0.0.0/0" : "::/0");
                rj.set("gw", g.toString());
                routes.push(std::move(rj));
            }

            for (const SIpPrefix& dst : c.routes) {
                if (dst.length == 0) {
                    continue;
                }

                CJson rj = CJson::object();
                rj.set("dst", dst.network().toString());
                routes.push(std::move(rj));
            }

            result.set("routes", std::move(routes));
            result.set("dns", c.dns.isObject() ? c.dns : CJson::object());
            co_return result;
        }

        /* Ensures the CNI network exists. */
        TTask<int32_t> ensureNetwork(CNetworkManager& mgr, const SCniConfig& c, SNetwork& out) {
            int32_t r = co_await mgr.getNetwork(c.name, out);
            if (r != -ENOENT) {
                co_return r;
            }

            SNetworkCreate req;
            req.name = c.name;
            req.driver = c.driver;
            req.subnets = c.subnets;

            if (c.mtu) {
                req.options["com.docker.network.driver.mtu"] = std::to_string(c.mtu);
            }

            if (c.driver == "bridge") {
                if (!c.bridge.empty()) {
                    req.options["com.docker.network.bridge.name"] = c.bridge;
                }

                req.options["com.docker.network.bridge.enable_ip_masquerade"] = c.ipMasq ? "true" : "false";
            }
            else {
                req.options["parent"] = c.master;
                if (!c.mode.empty()) {
                    req.options[c.driver == "macvlan" ? "macvlan_mode" : "ipvlan_mode"] = c.mode;
                }
            }

            if (c.ipamType == "dhcp") {
                req.options["sbox.dhcp"] = "true";
            }

            req.labels["io.cni.network"] = c.name;

            r = co_await mgr.createNetwork(req, out);
            if (r == -EEXIST) {
                // --> A concurrent ADD created it first.
                r = co_await mgr.getNetwork(c.name, out);
            }

            co_return r;
        }

        /* Programs the non-default routes of the configuration inside the sandbox. */
        TTask<int32_t> addConfigRoutes(const SCniConfig& c, const SNetworkEndpoint& ep) {
            CRtnl sb;
            int32_t r = sb.open(ep.netnsPath);
            if (r != SBOX_OK) {
                co_return r;
            }

            int32_t index = co_await sb.linkIndex(ep.sandboxIfName);
            if (index < 0) {
                co_return index;
            }

            for (const SIpPrefix& dst : c.routes) {
                if (dst.length == 0) {
                    continue;
                }

                SRouteInfo route;
                route.destination = dst.network();
                route.oif = index;
                for (const SIpAddress& g : ep.gateways) {
                    if (g.family == dst.address.family) {
                        route.gateway = g;
                    }
                }

                r = co_await sb.addRoute(route, true);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            co_return SBOX_OK;
        }

        /* ADD. */
        TTask<bool> cmdAdd(const SCniRequest& req, SCniConfig& c, std::string& output, SCniFailure& f) {
            if (req.containerId.empty() || req.netns.empty() || req.ifName.empty()) {
                f = failure(ECNI_INVALID_ENVIRONMENT, "CNI_CONTAINERID, CNI_NETNS and CNI_IFNAME are required");
                co_return false;
            }

            if (!CNetns::isNetns(req.netns)) {
                f = failure(ECNI_INVALID_ENVIRONMENT, "CNI_NETNS is not a network namespace: " + req.netns);
                co_return false;
            }

            SNetworkManagerOptions opts;
            opts.stateDir = c.stateDir;
            opts.hostNetns = req.hostNetns;
            CNetworkManager mgr(opts);

            SNetwork net;
            int32_t r = co_await ensureNetwork(mgr, c, net);
            if (r != SBOX_OK) {
                f = failure(ECNI_PLUGIN_FAILURE, "cannot create network " + c.name, r);
                co_return false;
            }

            SNetworkEndpoint ep;
            if (co_await findEndpoint(mgr, net.id, req.containerId, req.ifName, ep) == SBOX_OK) {
                if (ep.joined && ep.netnsPath == req.netns) {
                    output = (co_await buildResult(c, net, ep, req.hostNetns)).dump(true);
                    co_return true;
                }

                f = failure(ECNI_INVALID_ENVIRONMENT, "container " + req.containerId + " already has " + req.ifName);
                co_return false;
            }

            SEndpointCreate ec;
            ec.containerId = req.containerId;
            // --> DEL and CHECK find the endpoint again by (container, interface name).
            ec.labels["io.cni.ifname"] = req.ifName;
            ec.labels["io.cni.network"] = c.name;
            ec.ports = c.ports;
            ec.mac = c.mac;
            for (const SIpPrefix& p : c.staticIps) {
                (p.address.isV4() ? ec.ipv4 : ec.ipv6) = p;
            }

            SNetworkEndpoint created;
            r = co_await mgr.createEndpoint(net.id, ec, created);
            if (r != SBOX_OK) {
                f = failure(r == -ENOSPC ? int32_t(ECNI_TRY_AGAIN_LATER) : int32_t(ECNI_PLUGIN_FAILURE), "cannot create endpoint", r);
                co_return false;
            }

            r = co_await mgr.join(created.id, req.netns, req.ifName, ep);
            if (r == SBOX_OK) {
                r = co_await addConfigRoutes(c, ep);
            }

            if (r != SBOX_OK) {
                co_await mgr.deleteEndpoint(created.id);
                f = failure(ECNI_PLUGIN_FAILURE, "cannot attach " + req.ifName, r);
                co_return false;
            }

            output = (co_await buildResult(c, net, ep, req.hostNetns)).dump(true);
            co_return true;
        }

        /* DEL. */
        TTask<bool> cmdDel(const SCniRequest& req, SCniConfig& c, SCniFailure& f) {
            if (req.containerId.empty() || req.ifName.empty()) {
                f = failure(ECNI_INVALID_ENVIRONMENT, "CNI_CONTAINERID and CNI_IFNAME are required");
                co_return false;
            }

            SNetworkManagerOptions opts;
            opts.stateDir = c.stateDir;
            opts.hostNetns = req.hostNetns;
            CNetworkManager mgr(opts);

            SNetwork net;
            int32_t r = co_await mgr.getNetwork(c.name, net);
            if (r == -ENOENT) {
                co_return true;
            }

            if (r != SBOX_OK) {
                f = failure(ECNI_PLUGIN_FAILURE, "cannot read network " + c.name, r);
                co_return false;
            }

            SNetworkEndpoint ep;
            r = co_await findEndpoint(mgr, net.id, req.containerId, req.ifName, ep);
            if (r == -ENOENT) {
                co_return true;
            }

            if (r == SBOX_OK) {
                r = co_await mgr.deleteEndpoint(ep.id);
            }

            if (r != SBOX_OK && r != -ENOENT) {
                f = failure(ECNI_PLUGIN_FAILURE, "cannot delete endpoint", r);
                co_return false;
            }

            co_return true;
        }

        /* CHECK. */
        TTask<bool> cmdCheck(const SCniRequest& req, SCniConfig& c, SCniFailure& f) {
            if (req.containerId.empty() || req.netns.empty() || req.ifName.empty()) {
                f = failure(ECNI_INVALID_ENVIRONMENT, "CNI_CONTAINERID, CNI_NETNS and CNI_IFNAME are required");
                co_return false;
            }

            SNetworkManagerOptions opts;
            opts.stateDir = c.stateDir;
            opts.hostNetns = req.hostNetns;
            CNetworkManager mgr(opts);

            SNetwork net;
            SNetworkEndpoint ep;
            if (co_await mgr.getNetwork(c.name, net) != SBOX_OK
                || co_await findEndpoint(mgr, net.id, req.containerId, req.ifName, ep) != SBOX_OK)
            {
                f = failure(ECNI_UNKNOWN_CONTAINER, "no attachment for container " + req.containerId);
                co_return false;
            }

            CRtnl sb;
            SLinkInfo link;
            int32_t r = sb.open(req.netns);
            if (r == SBOX_OK) {
                r = co_await sb.getLink(req.ifName, link);
            }

            if (r != SBOX_OK) {
                f = failure(ECNI_CHECK_FAILED, "interface " + req.ifName + " missing in the sandbox", r);
                co_return false;
            }

            if (!link.isUp()) {
                f = failure(ECNI_CHECK_FAILED, "interface " + req.ifName + " is down");
                co_return false;
            }

            std::vector<SAddressInfo> addrs;
            co_await sb.listAddresses(addrs, 0, link.index);
            for (const SIpPrefix& want : ep.addresses) {
                bool found = false;
                for (const SAddressInfo& a : addrs) {
                    found = found || a.prefix == want;
                }

                if (!found) {
                    f = failure(ECNI_CHECK_FAILED, "address " + want.toString() + " missing on " + req.ifName);
                    co_return false;
                }
            }

            // --> The runtime's prevResult must agree with what we hold.
            const CJson& prevIps = c.prevResult.get("ips");
            for (size_t i = 0; i < prevIps.size(); ++i) {
                SIpPrefix p;
                SIpPrefix::parse(prevIps.at(i).get("address").asString(), p);
                bool found = false;
                for (const SIpPrefix& have : ep.addresses) {
                    found = found || have == p;
                }

                if (!found) {
                    f = failure(ECNI_CHECK_FAILED, "prevResult address " + p.toString() + " is not assigned");
                    co_return false;
                }
            }

            co_return true;
        }

    }

    /* Reads a request from the environment. */
    SCniRequest CniRequestFromEnvironment() {
        auto env = [](const char* name) {
            const char* v = std::getenv(name);
            return std::string(v ? v : "");
        };

        SCniRequest r;
        r.command = env("CNI_COMMAND");
        r.containerId = env("CNI_CONTAINERID");
        r.netns = env("CNI_NETNS");
        r.ifName = env("CNI_IFNAME");
        r.args = env("CNI_ARGS");
        r.path = env("CNI_PATH");
        return r;
    }

    /* Runs a CNI command. */
    TTask<int32_t> RunCni(SCniRequest request, std::string& output) {
        output.clear();
        SCniFailure f;
        std::string version = "1.0.0";

        CJson conf;
        bool parsed = CJson::parse(request.config, conf) == SBOX_OK;
        if (parsed && conf.get("cniVersion").isString()) {
            version = conf.get("cniVersion").asString();
        }

        if (request.command == "VERSION") {
            CJson v = CJson::object();
            v.set("cniVersion", "1.0.0");
            CJson list = CJson::array();
            for (const char* s : SUPPORTED_VERSIONS) {
                list.push(s);
            }

            v.set("supportedVersions", std::move(list));
            output = v.dump(true);
            co_return 0;
        }

        if (request.command != "ADD" && request.command != "DEL" && request.command != "CHECK") {
            f = failure(ECNI_INVALID_ENVIRONMENT, "unsupported CNI_COMMAND: " + request.command);
            output = errorJson(version, f);
            co_return 1;
        }

        if (!parsed) {
            f = failure(ECNI_DECODE_FAILURE, "cannot decode the network configuration");
            output = errorJson(version, f);
            co_return 1;
        }

        SCniConfig c;
        if (!parseConfig(conf, c, f)) {
            output = errorJson(version, f);
            co_return 1;
        }

        if (!supportedVersion(c.version)) {
            f = failure(ECNI_INCOMPATIBLE_VERSION, "unsupported cniVersion " + c.version);
            output = errorJson("1.0.0", f);
            co_return 1;
        }

        if (request.command == "CHECK" && c.version != "1.0.0" && c.version != "0.4.0") {
            f = failure(ECNI_INCOMPATIBLE_VERSION, "CHECK needs cniVersion 0.4.0 or later");
            output = errorJson(c.version, f);
            co_return 1;
        }

        applyArgs(request.args, c);
        if (c.stateDir.empty()) {
            c.stateDir = DefaultNetworkStateDir();
        }

        bool ok = false;
        if (request.command == "ADD") {
            ok = co_await cmdAdd(request, c, output, f);
        }
        else if (request.command == "DEL") {
            ok = co_await cmdDel(request, c, f);
        }
        else {
            ok = co_await cmdCheck(request, c, f);
        }

        if (!ok) {
            output = errorJson(c.version, f);
            co_return 1;
        }

        co_return 0;
    }

}
}
