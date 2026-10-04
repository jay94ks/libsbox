#include <sbox/net/network.hpp>
#include <sbox/net/lock.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace net {

    namespace {

        constexpr uint16_t EPHEMERAL_FIRST = 32768;
        constexpr uint16_t EPHEMERAL_LAST = 60999;

        /* Serializes a string map as an object. */
        CJson mapJson(const std::map<std::string, std::string>& m) {
            CJson j = CJson::object();
            for (const auto& [k, v] : m) {
                j.set(k, v);
            }

            return j;
        }

        /* Parses an object of strings. */
        std::map<std::string, std::string> jsonMap(const CJson& j) {
            std::map<std::string, std::string> out;
            if (!j.isObject()) {
                return out;
            }

            for (size_t i = 0; i < j.size(); ++i) {
                const CJson& v = j.at(i);
                if (v.isString()) {
                    out[j.keyAt(i)] = v.asString();
                }
                else if (v.isBool()) {
                    out[j.keyAt(i)] = v.asBool() ? "true" : "false";
                }
                else if (v.isNumber()) {
                    out[j.keyAt(i)] = std::to_string(v.asInt());
                }
            }

            return out;
        }

        /* Returns true for a Docker-compatible network name. */
        bool validNetworkName(const std::string& name) {
            if (name.empty() || name.size() > 128) {
                return false;
            }

            for (size_t i = 0; i < name.size(); ++i) {
                char c = name[i];
                bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                if (!alnum && (i == 0 || (c != '_' && c != '.' && c != '-'))) {
                    return false;
                }
            }

            return true;
        }

        /* Returns true for an id usable as a file name. */
        bool validId(const std::string& id) {
            if (id.empty() || id.size() > 128 || id[0] == '.') {
                return false;
            }

            for (char c : id) {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.';
                if (!ok) {
                    return false;
                }
            }

            return true;
        }

        /* Lists the .json files of a directory (names without the extension). */
        std::vector<std::string> listJson(const std::string& dir) {
            std::vector<std::string> out;
            DIR* d = ::opendir(dir.c_str());
            if (!d) {
                return out;
            }

            while (dirent* e = ::readdir(d)) {
                std::string name = e->d_name;
                if (name.size() > 5 && name.compare(name.size() - 5, 5, ".json") == 0) {
                    out.push_back(name.substr(0, name.size() - 5));
                }
            }

            ::closedir(d);
            return out;
        }

        /* Reads and parses a JSON file. */
        int32_t readJson(const std::string& path, CJson& out) {
            std::string text;
            int32_t r = CFile::readAll(path, text);
            if (r != SBOX_OK) {
                return r;
            }

            return CJson::parse(text, out) == SBOX_OK ? SBOX_OK : -EBADMSG;
        }

        /* Returns true when the port can be bound on the host (in `netns`). */
        bool portBindable(const std::string& netns, uint8_t protocol, const SIpAddress& hostIp, uint16_t port) {
            CNetnsScope scope(netns);
            if (scope.error() != SBOX_OK) {
                return false;
            }

            bool v6 = hostIp.isV6();
            int type = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
            CFd fd(::socket(v6 ? AF_INET6 : AF_INET, type | SOCK_CLOEXEC, protocol == IPPROTO_SCTP ? IPPROTO_SCTP : 0));
            if (!fd.isValid()) {
                // --> No socket for this protocol (SCTP missing): cannot probe, assume free.
                return true;
            }

            sockaddr_storage ss;
            std::memset(&ss, 0, sizeof(ss));
            socklen_t len;
            if (v6) {
                auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
                a->sin6_family = AF_INET6;
                a->sin6_port = htons(port);
                std::memcpy(&a->sin6_addr, hostIp.bytes, 16);
                len = sizeof(*a);
            }
            else {
                auto* a = reinterpret_cast<sockaddr_in*>(&ss);
                a->sin_family = AF_INET;
                a->sin_port = htons(port);
                if (hostIp.isV4()) {
                    std::memcpy(&a->sin_addr, hostIp.bytes, 4);
                }

                len = sizeof(*a);
            }

            return ::bind(fd.get(), reinterpret_cast<sockaddr*>(&ss), len) == 0;
        }

        /* Returns true when two host IPs may conflict on the same port. */
        bool hostIpsCollide(const SIpAddress& a, const SIpAddress& b) {
            if (!a.isValid() || !b.isValid() || a.isUnspecified() || b.isUnspecified()) {
                return true;
            }

            return a == b;
        }

    }

    /* Parses a port mapping. */
    int32_t SPortMapping::parse(std::string_view text, SPortMapping& out) {
        SPortMapping m;
        std::string_view spec = text;

        size_t slash = spec.rfind('/');
        if (slash != std::string_view::npos) {
            std::string_view proto = spec.substr(slash + 1);
            spec = spec.substr(0, slash);
            if (proto == "tcp") {
                m.protocol = IPPROTO_TCP;
            }
            else if (proto == "udp") {
                m.protocol = IPPROTO_UDP;
            }
            else if (proto == "sctp") {
                m.protocol = IPPROTO_SCTP;
            }
            else {
                return -EINVAL;
            }
        }

        auto number = [](std::string_view s, uint16_t& v) {
            if (s.empty() || s.size() > 5) {
                return false;
            }

            uint32_t n = 0;
            for (char c : s) {
                if (c < '0' || c > '9') {
                    return false;
                }

                n = n * 10 + uint32_t(c - '0');
            }

            if (n > 65535) {
                return false;
            }

            v = uint16_t(n);
            return true;
        };

        // --> Split off the container port (last ':'), then the host port, then the host IP
        // (which may be a bracketed IPv6 address containing ':').
        size_t last = spec.rfind(':');
        if (last == std::string_view::npos) {
            if (!number(spec, m.containerPort) || m.containerPort == 0) {
                return -EINVAL;
            }

            out = m;
            return SBOX_OK;
        }

        if (!number(spec.substr(last + 1), m.containerPort) || m.containerPort == 0) {
            return -EINVAL;
        }

        std::string_view rest = spec.substr(0, last);
        size_t hostSep = rest.rfind(':');
        std::string_view hostPort = hostSep == std::string_view::npos ? rest : rest.substr(hostSep + 1);

        if (!hostPort.empty() && !number(hostPort, m.hostPort)) {
            return -EINVAL;
        }

        if (hostSep != std::string_view::npos) {
            std::string_view host = rest.substr(0, hostSep);
            if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
                host = host.substr(1, host.size() - 2);
            }

            if (!host.empty() && SIpAddress::parse(host, m.hostIp) != SBOX_OK) {
                return -EINVAL;
            }
        }

        out = m;
        return SBOX_OK;
    }

    /* Returns the protocol name. */
    std::string SPortMapping::protocolName() const {
        return protocol == IPPROTO_UDP ? "udp" : (protocol == IPPROTO_SCTP ? "sctp" : "tcp");
    }

    /* Serializes a mapping. */
    CJson SPortMapping::toJson() const {
        CJson j = CJson::object();
        j.set("Proto", protocolName());
        j.set("HostIp", hostIp.isValid() ? hostIp.toString() : std::string());
        j.set("HostPort", int32_t(hostPort));
        j.set("ContainerPort", int32_t(containerPort));
        return j;
    }

    /* Parses a mapping. */
    int32_t SPortMapping::fromJson(const CJson& json, SPortMapping& out) {
        SPortMapping m;
        const std::string& proto = json.get("Proto").asString();
        m.protocol = proto == "udp" ? IPPROTO_UDP : (proto == "sctp" ? IPPROTO_SCTP : IPPROTO_TCP);
        if (!json.get("HostIp").asString().empty() && SIpAddress::parse(json.get("HostIp").asString(), m.hostIp) != SBOX_OK) {
            return -EINVAL;
        }

        int64_t hp = json.get("HostPort").asInt();
        int64_t cp = json.get("ContainerPort").asInt();
        if (hp < 0 || hp > 65535 || cp <= 0 || cp > 65535) {
            return -EINVAL;
        }

        m.hostPort = uint16_t(hp);
        m.containerPort = uint16_t(cp);
        out = m;
        return SBOX_OK;
    }

    /* Returns an option. */
    std::string SNetwork::option(const std::string& key, const std::string& fallback) const {
        auto it = options.find(key);
        return it == options.end() ? fallback : it->second;
    }

    /* Returns a boolean option. */
    bool SNetwork::flag(const std::string& key, bool fallback) const {
        auto it = options.find(key);
        if (it == options.end()) {
            return fallback;
        }

        const std::string& v = it->second;
        if (v == "true" || v == "1" || v == "yes" || v == "on") {
            return true;
        }

        if (v == "false" || v == "0" || v == "no" || v == "off") {
            return false;
        }

        return fallback;
    }

    /* Returns the first subnet of a family. */
    const SNetworkSubnet* SNetwork::subnet(uint8_t family) const noexcept {
        for (const SNetworkSubnet& s : subnets) {
            if (s.subnet.address.family == family) {
                return &s;
            }
        }

        return nullptr;
    }

    /* Serializes a network. */
    CJson SNetwork::toJson() const {
        CJson j = CJson::object();
        j.set("Id", id);
        j.set("Name", name);
        j.set("Driver", driver);
        j.set("Created", created);
        j.set("EnableIPv6", enableIpv6);
        j.set("Internal", internal);

        CJson config = CJson::array();
        for (const SNetworkSubnet& s : subnets) {
            CJson c = CJson::object();
            c.set("Subnet", s.subnet.toString());
            c.set("Gateway", s.gateway.isValid() ? s.gateway.toString() : std::string());
            c.set("PoolID", s.poolId);
            config.push(std::move(c));
        }

        CJson ipam = CJson::object();
        ipam.set("Driver", ipamDriver);
        ipam.set("Config", std::move(config));
        j.set("IPAM", std::move(ipam));
        j.set("Options", mapJson(options));
        j.set("Labels", mapJson(labels));
        j.set("DriverState", driverState.isObject() ? driverState : CJson::object());
        return j;
    }

    /* Parses a network. */
    int32_t SNetwork::fromJson(const CJson& json, SNetwork& out) {
        SNetwork n;
        n.id = json.get("Id").asString();
        n.name = json.get("Name").asString();
        n.driver = json.get("Driver").asString();
        if (n.id.empty() || n.driver.empty()) {
            return -EINVAL;
        }

        n.created = json.get("Created").asInt();
        n.enableIpv6 = json.get("EnableIPv6").asBool();
        n.internal = json.get("Internal").asBool();

        const CJson& ipam = json.get("IPAM");
        n.ipamDriver = ipam.get("Driver").asString();
        const CJson& config = ipam.get("Config");
        for (size_t i = 0; i < config.size(); ++i) {
            SNetworkSubnet s;
            if (SIpPrefix::parse(config.at(i).get("Subnet").asString(), s.subnet) != SBOX_OK) {
                return -EINVAL;
            }

            SIpAddress::parse(config.at(i).get("Gateway").asString(), s.gateway);
            s.poolId = config.at(i).get("PoolID").asString();
            n.subnets.push_back(s);
        }

        n.options = jsonMap(json.get("Options"));
        n.labels = jsonMap(json.get("Labels"));
        n.driverState = json.get("DriverState").isObject() ? json.get("DriverState") : CJson::object();
        out = std::move(n);
        return SBOX_OK;
    }

    /* Returns the first address of a family. */
    SIpPrefix SNetworkEndpoint::address(uint8_t family) const noexcept {
        for (const SIpPrefix& p : addresses) {
            if (p.address.family == family) {
                return p;
            }
        }

        return SIpPrefix();
    }

    /* Serializes an endpoint. */
    CJson SNetworkEndpoint::toJson() const {
        CJson j = CJson::object();
        j.set("Id", id);
        j.set("NetworkId", networkId);
        j.set("ContainerId", containerId);

        CJson addrs = CJson::array();
        for (const SIpPrefix& p : addresses) {
            addrs.push(p.toString());
        }

        j.set("Addresses", std::move(addrs));

        CJson gws = CJson::array();
        for (const SIpAddress& g : gateways) {
            gws.push(g.toString());
        }

        j.set("Gateways", std::move(gws));
        j.set("MacAddress", mac.isValid() ? mac.toString() : std::string());
        j.set("HostInterface", hostIfName);
        j.set("SandboxInterface", sandboxIfName);
        j.set("SandboxKey", netnsPath);

        CJson ps = CJson::array();
        for (const SPortMapping& p : ports) {
            ps.push(p.toJson());
        }

        j.set("Ports", std::move(ps));
        j.set("Aliases", CJson::fromStrings(aliases));
        j.set("Mtu", mtu);
        j.set("Joined", joined);
        j.set("Labels", mapJson(labels));
        j.set("DriverState", driverState.isObject() ? driverState : CJson::object());
        return j;
    }

    /* Parses an endpoint. */
    int32_t SNetworkEndpoint::fromJson(const CJson& json, SNetworkEndpoint& out) {
        SNetworkEndpoint e;
        e.id = json.get("Id").asString();
        e.networkId = json.get("NetworkId").asString();
        if (e.id.empty() || e.networkId.empty()) {
            return -EINVAL;
        }

        e.containerId = json.get("ContainerId").asString();
        const CJson& addrs = json.get("Addresses");
        for (size_t i = 0; i < addrs.size(); ++i) {
            SIpPrefix p;
            if (SIpPrefix::parse(addrs.at(i).asString(), p) == SBOX_OK) {
                e.addresses.push_back(p);
            }
        }

        const CJson& gws = json.get("Gateways");
        for (size_t i = 0; i < gws.size(); ++i) {
            SIpAddress g;
            if (SIpAddress::parse(gws.at(i).asString(), g) == SBOX_OK) {
                e.gateways.push_back(g);
            }
        }

        SMacAddress::parse(json.get("MacAddress").asString(), e.mac);
        e.hostIfName = json.get("HostInterface").asString();
        e.sandboxIfName = json.get("SandboxInterface").asString();
        e.netnsPath = json.get("SandboxKey").asString();

        const CJson& ps = json.get("Ports");
        for (size_t i = 0; i < ps.size(); ++i) {
            SPortMapping p;
            if (SPortMapping::fromJson(ps.at(i), p) == SBOX_OK) {
                e.ports.push_back(p);
            }
        }

        e.aliases = json.get("Aliases").asStrings();
        e.mtu = uint32_t(json.get("Mtu").asInt());
        e.joined = json.get("Joined").asBool();
        e.labels = jsonMap(json.get("Labels"));
        e.driverState = json.get("DriverState").isObject() ? json.get("DriverState") : CJson::object();
        out = std::move(e);
        return SBOX_OK;
    }

    /* Default join info: the host-side name and the gateways. */
    TTask<int32_t> INetworkDriver::joinInfo(SNetworkContext& ctx, const SNetwork& network, const SNetworkEndpoint& endpoint, SJoinInfo& out) {
        (void)ctx;
        (void)network;
        out = SJoinInfo();
        out.srcName = endpoint.driverState.get("peer").asString();
        if (out.srcName.empty()) {
            out.srcName = endpoint.hostIfName;
        }

        for (const SIpAddress& g : endpoint.gateways) {
            if (g.isV4()) {
                out.gateway = g;
            }
            else if (g.isV6()) {
                out.gateway6 = g;
            }
        }

        co_return SBOX_OK;
    }

    /* Returns the default state directory. */
    std::string DefaultNetworkStateDir() {
        if (::geteuid() == 0) {
            return "/var/lib/sbox/net";
        }

        const char* xdg = std::getenv("XDG_RUNTIME_DIR");
        if (xdg && *xdg) {
            return CFile::join(xdg, "sbox/net");
        }

        return "/tmp/sbox-" + std::to_string(::geteuid()) + "/net";
    }

    /* Creates the manager. */
    CNetworkManager::CNetworkManager(SNetworkManagerOptions options)
        : _options(std::move(options)), _ipam(CFile::join(_options.stateDir, "ipam"), _options.pools), _hostOpen(false)
    {
        registerDriver(CreateBridgeDriver());
        registerDriver(CreateMacvlanDriver());
        registerDriver(CreateIpvlanDriver());
        registerDriver(CreateHostDriver());
        registerDriver(CreateNoneDriver());
        // --> Docker calls the none driver "null".
        _drivers["null"] = _drivers["none"];
    }

    /* Registers a driver. */
    void CNetworkManager::registerDriver(INetworkDriverPtr driver) {
        if (driver) {
            _drivers[driver->name()] = std::move(driver);
        }
    }

    /* Returns a driver. */
    INetworkDriverPtr CNetworkManager::driver(const std::string& name) const {
        auto it = _drivers.find(name);
        return it == _drivers.end() ? nullptr : it->second;
    }

    /* Opens the host rtnetlink socket on first use. */
    int32_t CNetworkManager::hostRtnl(CRtnl*& out) noexcept {
        if (!_hostOpen) {
            int32_t r = _host.open(_options.hostNetns);
            if (r != SBOX_OK) {
                return r;
            }

            _hostOpen = true;
        }

        out = &_host;
        return SBOX_OK;
    }

    /* Builds the driver context. */
    int32_t CNetworkManager::context(SNetworkContext& out) noexcept {
        CRtnl* rt = nullptr;
        int32_t r = hostRtnl(rt);
        if (r != SBOX_OK) {
            return r;
        }

        out.hostNetns = _options.hostNetns;
        out.stateDir = _options.stateDir;
        out.host = rt;
        return SBOX_OK;
    }

    /* Loads all networks. */
    int32_t CNetworkManager::loadNetworks(std::vector<SNetwork>& out) const {
        out.clear();
        std::string dir = CFile::join(_options.stateDir, "networks");
        for (const std::string& id : listJson(dir)) {
            CJson j;
            SNetwork n;
            if (readJson(CFile::join(dir, id + ".json"), j) == SBOX_OK && SNetwork::fromJson(j, n) == SBOX_OK) {
                out.push_back(std::move(n));
            }
        }

        return SBOX_OK;
    }

    /* Finds a network by id, id prefix or name. */
    int32_t CNetworkManager::findNetwork(const std::string& idOrName, SNetwork& out) const {
        if (idOrName.empty()) {
            return -EINVAL;
        }

        std::vector<SNetwork> all;
        loadNetworks(all);

        for (SNetwork& n : all) {
            if (n.id == idOrName) {
                out = std::move(n);
                return SBOX_OK;
            }
        }

        for (SNetwork& n : all) {
            if (n.name == idOrName) {
                out = std::move(n);
                return SBOX_OK;
            }
        }

        const SNetwork* match = nullptr;
        for (const SNetwork& n : all) {
            if (n.id.compare(0, idOrName.size(), idOrName) == 0) {
                if (match) {
                    return -EINVAL;
                }

                match = &n;
            }
        }

        if (!match) {
            return -ENOENT;
        }

        out = *match;
        return SBOX_OK;
    }

    /* Loads all endpoints. */
    int32_t CNetworkManager::loadEndpoints(std::vector<SNetworkEndpoint>& out) const {
        out.clear();
        std::string dir = CFile::join(_options.stateDir, "endpoints");
        for (const std::string& id : listJson(dir)) {
            CJson j;
            SNetworkEndpoint e;
            if (readJson(CFile::join(dir, id + ".json"), j) == SBOX_OK && SNetworkEndpoint::fromJson(j, e) == SBOX_OK) {
                out.push_back(std::move(e));
            }
        }

        return SBOX_OK;
    }

    /* Loads one endpoint. */
    int32_t CNetworkManager::loadEndpoint(const std::string& id, SNetworkEndpoint& out) const {
        if (!validId(id)) {
            return -EINVAL;
        }

        CJson j;
        int32_t r = readJson(CFile::join(CFile::join(_options.stateDir, "endpoints"), id + ".json"), j);
        if (r != SBOX_OK) {
            return r;
        }

        return SNetworkEndpoint::fromJson(j, out);
    }

    /* Persists a network. */
    int32_t CNetworkManager::saveNetwork(const SNetwork& network) const {
        std::string dir = CFile::join(_options.stateDir, "networks");
        int32_t r = CFile::makeDirs(dir, 0700);
        if (r != SBOX_OK) {
            return r;
        }

        return CFile::writeAtomic(CFile::join(dir, network.id + ".json"), network.toJson().dump(true) + "\n", 0600);
    }

    /* Persists an endpoint. */
    int32_t CNetworkManager::saveEndpoint(const SNetworkEndpoint& endpoint) const {
        std::string dir = CFile::join(_options.stateDir, "endpoints");
        int32_t r = CFile::makeDirs(dir, 0700);
        if (r != SBOX_OK) {
            return r;
        }

        return CFile::writeAtomic(CFile::join(dir, endpoint.id + ".json"), endpoint.toJson().dump(true) + "\n", 0600);
    }

    /* Releases the IPAM addresses of an endpoint. */
    TTask<void> CNetworkManager::releaseAddresses(const SNetwork& network, const SNetworkEndpoint& endpoint) {
        for (const SNetworkSubnet& s : network.subnets) {
            if (!s.poolId.empty()) {
                co_await _ipam.releaseOwner(s.poolId, endpoint.id);
            }
        }
    }

    /* Assigns ephemeral host ports and checks explicit ones. */
    int32_t CNetworkManager::assignHostPorts(std::vector<SPortMapping>& ports, const std::string& exceptEndpoint) const {
        std::vector<SNetworkEndpoint> all;
        loadEndpoints(all);

        std::vector<SPortMapping> used;
        for (const SNetworkEndpoint& e : all) {
            if (e.id != exceptEndpoint) {
                used.insert(used.end(), e.ports.begin(), e.ports.end());
            }
        }

        auto taken = [&](const SPortMapping& p, uint16_t port) {
            for (const SPortMapping& u : used) {
                if (u.protocol == p.protocol && u.hostPort == port && hostIpsCollide(u.hostIp, p.hostIp)) {
                    return true;
                }
            }

            return false;
        };

        for (SPortMapping& p : ports) {
            if (p.containerPort == 0) {
                return -EINVAL;
            }

            if (p.hostPort != 0) {
                if (taken(p, p.hostPort)) {
                    return -EADDRINUSE;
                }

                used.push_back(p);
                continue;
            }

            uint32_t span = uint32_t(EPHEMERAL_LAST - EPHEMERAL_FIRST + 1);
            uint32_t start = 0;
            RandomBytes(reinterpret_cast<uint8_t*>(&start), sizeof(start));
            bool found = false;

            for (uint32_t i = 0; i < span && !found; ++i) {
                uint16_t port = uint16_t(EPHEMERAL_FIRST + (start + i) % span);
                if (!taken(p, port) && portBindable(_options.hostNetns, p.protocol, p.hostIp, port)) {
                    p.hostPort = port;
                    found = true;
                }
            }

            if (!found) {
                return -EADDRINUSE;
            }

            used.push_back(p);
        }

        return SBOX_OK;
    }

    /* Creates a network. */
    TTask<int32_t> CNetworkManager::createNetwork(SNetworkCreate request, SNetwork& out) {
        if (!validNetworkName(request.name) || (!request.id.empty() && !validId(request.id))) {
            co_return -EINVAL;
        }

        INetworkDriverPtr drv = driver(request.driver);
        if (!drv) {
            co_return -ENOTSUP;
        }

        int32_t r = CFile::makeDirs(_options.stateDir, 0700);
        if (r != SBOX_OK) {
            co_return r;
        }

        CFileLock lock;
        r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SNetwork> existing;
        loadNetworks(existing);
        for (const SNetwork& n : existing) {
            if (n.name == request.name || (!request.id.empty() && n.id == request.id)) {
                co_return -EEXIST;
            }
        }

        SNetwork net;
        net.id = request.id.empty() ? RandomHex(64) : request.id;
        net.name = request.name;
        net.driver = drv->name();
        net.ipamDriver = request.ipamDriver.empty() ? "sbox" : request.ipamDriver;
        net.enableIpv6 = request.enableIpv6;
        net.internal = request.internal;
        net.options = request.options;
        net.labels = request.labels;
        net.created = int64_t(::time(nullptr));
        net.driverState = CJson::object();

        std::vector<SSubnetConfig> configs = request.subnets;
        bool dhcp = net.flag("sbox.dhcp", false);

        if (drv->usesIpam() && !dhcp && net.ipamDriver == "sbox") {
            if (configs.empty()) {
                configs.push_back(SSubnetConfig());
            }

            bool haveV6 = false;
            for (const SSubnetConfig& c : configs) {
                haveV6 = haveV6 || (c.subnet.isValid() ? c.subnet.address.isV6() : c.family == 6);
            }

            if (request.enableIpv6 && !haveV6) {
                SSubnetConfig v6;
                v6.family = 6;
                configs.push_back(v6);
            }

            std::vector<SIpPrefix> avoid;
            if (_options.avoidHostRoutes) {
                for (int family : { AF_INET, AF_INET6 }) {
                    std::vector<SRouteInfo> routes;
                    if (co_await ctx.host->listRoutes(routes, family) == SBOX_OK) {
                        for (const SRouteInfo& rt : routes) {
                            if (rt.destination.length > 0) {
                                avoid.push_back(rt.destination);
                            }
                        }
                    }
                }
            }

            for (size_t i = 0; i < configs.size(); ++i) {
                const SSubnetConfig& c = configs[i];
                SIpamRequest req;
                req.id = net.id + "/" + std::to_string(i);
                req.space = "local";
                req.family = c.subnet.isValid() ? c.subnet.address.family : c.family;
                req.subnet = c.subnet;
                req.range = c.ipRange;
                req.rangeStart = c.rangeStart;
                req.rangeEnd = c.rangeEnd;
                req.gateway = c.gateway;
                req.reserveGateway = drv->usesGateway();
                for (const auto& kv : c.auxAddresses) {
                    req.reserved.push_back(kv.second);
                }

                req.avoid = avoid;

                SIpamPool pool;
                r = co_await _ipam.requestPool(req, pool);
                if (r != SBOX_OK) {
                    for (const SNetworkSubnet& done : net.subnets) {
                        co_await _ipam.releasePool(done.poolId);
                    }

                    co_return r;
                }

                SNetworkSubnet s;
                s.subnet = pool.subnet;
                s.gateway = pool.gateway;
                s.poolId = pool.id;
                net.subnets.push_back(s);
            }
        }
        else if (net.ipamDriver != "sbox" || dhcp) {
            for (const SSubnetConfig& c : configs) {
                if (!c.subnet.isValid()) {
                    continue;
                }

                SNetworkSubnet s;
                s.subnet = c.subnet.network();
                s.gateway = c.gateway;
                net.subnets.push_back(s);
            }
        }

        r = co_await drv->createNetwork(ctx, net);
        if (r == SBOX_OK) {
            r = saveNetwork(net);
            if (r != SBOX_OK) {
                co_await drv->deleteNetwork(ctx, net);
            }
        }

        if (r == SBOX_OK && drv->usesFirewall()) {
            r = co_await syncFirewallLocked();
            if (r != SBOX_OK) {
                co_await drv->deleteNetwork(ctx, net);
                ::unlink(CFile::join(CFile::join(_options.stateDir, "networks"), net.id + ".json").c_str());
                co_await syncFirewallLocked();
            }
        }

        if (r != SBOX_OK) {
            for (const SNetworkSubnet& s : net.subnets) {
                if (!s.poolId.empty()) {
                    co_await _ipam.releasePool(s.poolId);
                }
            }

            co_return r;
        }

        out = std::move(net);
        co_return SBOX_OK;
    }

    /* Deletes a network. */
    TTask<int32_t> CNetworkManager::deleteNetwork(std::string idOrName) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r == -ENOENT ? -ENOENT : r;
        }

        SNetwork net;
        r = findNetwork(idOrName, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SNetworkEndpoint> eps;
        loadEndpoints(eps);
        for (const SNetworkEndpoint& e : eps) {
            if (e.networkId == net.id) {
                co_return -EBUSY;
            }
        }

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        INetworkDriverPtr drv = driver(net.driver);
        if (drv) {
            r = co_await drv->deleteNetwork(ctx, net);
            if (r != SBOX_OK && r != -ENODEV) {
                co_return r;
            }
        }

        for (const SNetworkSubnet& s : net.subnets) {
            if (!s.poolId.empty()) {
                co_await _ipam.releasePool(s.poolId);
            }
        }

        if (::unlink(CFile::join(CFile::join(_options.stateDir, "networks"), net.id + ".json").c_str()) < 0 && errno != ENOENT) {
            co_return -errno;
        }

        if (drv && drv->usesFirewall()) {
            int32_t f = co_await syncFirewallLocked();
            if (f != SBOX_OK && f != -ENOTSUP) {
                co_return f;
            }
        }

        co_return SBOX_OK;
    }

    /* Reads a network. */
    TTask<int32_t> CNetworkManager::getNetwork(std::string idOrName, SNetwork& out) {
        if (!CFile::exists(_options.stateDir)) {
            co_return -ENOENT;
        }

        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return findNetwork(idOrName, out);
    }

    /* Reads every network. */
    TTask<int32_t> CNetworkManager::listNetworks(std::vector<SNetwork>& out) {
        out.clear();
        if (!CFile::exists(_options.stateDir)) {
            co_return SBOX_OK;
        }

        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return loadNetworks(out);
    }

    /* Creates an endpoint. */
    TTask<int32_t> CNetworkManager::createEndpoint(std::string network, SEndpointCreate request, SNetworkEndpoint& out) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await createEndpointLocked(std::move(network), std::move(request), out);
    }

    /* Creates an endpoint with the lock held. */
    TTask<int32_t> CNetworkManager::createEndpointLocked(std::string network, SEndpointCreate request, SNetworkEndpoint& out) {
        if (!request.id.empty() && !validId(request.id)) {
            co_return -EINVAL;
        }

        SNetwork net;
        int32_t r = findNetwork(network, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        INetworkDriverPtr drv = driver(net.driver);
        if (!drv) {
            co_return -ENOTSUP;
        }

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetworkEndpoint ep;
        ep.id = request.id.empty() ? RandomHex(64) : request.id;

        SNetworkEndpoint dup;
        if (loadEndpoint(ep.id, dup) == SBOX_OK) {
            co_return -EEXIST;
        }

        ep.networkId = net.id;
        ep.containerId = request.containerId;
        ep.aliases = request.aliases;
        ep.labels = request.labels;
        ep.ports = request.ports;
        ep.driverState = CJson::object();
        if (!request.hostname.empty()) {
            ep.driverState.set("hostname", request.hostname);
        }

        std::string mtu = net.option("com.docker.network.driver.mtu");
        ep.mtu = mtu.empty() ? 0 : uint32_t(std::strtoul(mtu.c_str(), nullptr, 10));

        for (const SNetworkSubnet& s : net.subnets) {
            uint8_t family = s.subnet.address.family;
            const SIpPrefix& wanted = family == 4 ? request.ipv4 : request.ipv6;

            if (s.poolId.empty()) {
                // --> Addresses managed outside (Docker's IPAM): take what the caller gave.
                if (wanted.isValid()) {
                    uint8_t len = wanted.length == wanted.address.bits() ? s.subnet.length : wanted.length;
                    ep.addresses.push_back(SIpPrefix(wanted.address, len));
                }
            }
            else {
                SIpAddress got;
                r = co_await _ipam.requestAddress(s.poolId, wanted.isValid() ? wanted.address : SIpAddress(), ep.id, got);
                if (r != SBOX_OK) {
                    co_await releaseAddresses(net, ep);
                    co_return r;
                }

                ep.addresses.push_back(SIpPrefix(got, s.subnet.length));
            }

            if (s.gateway.isValid() && !net.internal) {
                ep.gateways.push_back(s.gateway);
            }
        }

        // --> Requested addresses outside every subnet (external IPAM without subnets).
        if (net.subnets.empty()) {
            if (request.ipv4.isValid()) {
                ep.addresses.push_back(request.ipv4);
            }

            if (request.ipv6.isValid()) {
                ep.addresses.push_back(request.ipv6);
            }
        }

        if (request.mac.isValid()) {
            ep.mac = request.mac;
        }
        else if (ep.address(4).isValid() && net.driver == "bridge") {
            ep.mac = SMacAddress::fromIpv4(ep.address(4).address);
        }
        else {
            ep.mac = SMacAddress::random();
        }

        r = assignHostPorts(ep.ports, ep.id);
        if (r != SBOX_OK) {
            co_await releaseAddresses(net, ep);
            co_return r;
        }

        r = co_await drv->createEndpoint(ctx, net, ep);
        if (r != SBOX_OK) {
            co_await releaseAddresses(net, ep);
            co_return r;
        }

        r = saveEndpoint(ep);
        if (r != SBOX_OK) {
            co_await drv->deleteEndpoint(ctx, net, ep);
            co_await releaseAddresses(net, ep);
            co_return r;
        }

        if (!ep.ports.empty() && drv->usesFirewall()) {
            r = co_await syncFirewallLocked();
            if (r != SBOX_OK) {
                co_await drv->deleteEndpoint(ctx, net, ep);
                co_await releaseAddresses(net, ep);
                ::unlink(CFile::join(CFile::join(_options.stateDir, "endpoints"), ep.id + ".json").c_str());
                co_await syncFirewallLocked();
                co_return r;
            }
        }

        out = std::move(ep);
        co_return SBOX_OK;
    }

    /* Joins a sandbox. */
    TTask<int32_t> CNetworkManager::join(std::string endpointId, std::string netnsPath, std::string ifName, SNetworkEndpoint& out) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await joinLocked(std::move(endpointId), std::move(netnsPath), std::move(ifName), out);
    }

    /* Joins a sandbox with the lock held. */
    TTask<int32_t> CNetworkManager::joinLocked(std::string endpointId, std::string netnsPath, std::string ifName, SNetworkEndpoint& out) {
        SNetworkEndpoint ep;
        int32_t r = loadEndpoint(endpointId, ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (ep.joined) {
            co_return -EALREADY;
        }

        SNetwork net;
        r = findNetwork(ep.networkId, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        INetworkDriverPtr drv = driver(net.driver);
        if (!drv) {
            co_return -ENOTSUP;
        }

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (ifName.empty() && net.driver != "host" && net.driver != "none") {
            // --> Next free ethN inside the sandbox.
            CRtnl sandbox;
            r = sandbox.open(netnsPath);
            if (r != SBOX_OK) {
                co_return r;
            }

            std::vector<SLinkInfo> links;
            r = co_await sandbox.listLinks(links);
            if (r != SBOX_OK) {
                co_return r;
            }

            for (int32_t n = 0; ifName.empty(); ++n) {
                std::string candidate = "eth" + std::to_string(n);
                bool used = false;
                for (const SLinkInfo& l : links) {
                    used = used || l.name == candidate;
                }

                if (!used) {
                    ifName = candidate;
                }
            }
        }

        r = co_await drv->join(ctx, net, ep, netnsPath, ifName);
        if (r != SBOX_OK) {
            co_return r;
        }

        ep.joined = true;
        ep.netnsPath = netnsPath;
        ep.sandboxIfName = ifName;
        r = saveEndpoint(ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        out = std::move(ep);
        co_return SBOX_OK;
    }

    /* Returns join info. */
    TTask<int32_t> CNetworkManager::joinInfo(std::string endpointId, SJoinInfo& out) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetworkEndpoint ep;
        r = loadEndpoint(endpointId, ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetwork net;
        r = findNetwork(ep.networkId, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        INetworkDriverPtr drv = driver(net.driver);
        if (!drv) {
            co_return -ENOTSUP;
        }

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await drv->joinInfo(ctx, net, ep, out);
    }

    /* Leaves a sandbox. */
    TTask<int32_t> CNetworkManager::leave(std::string endpointId) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await leaveLocked(std::move(endpointId));
    }

    /* Leaves a sandbox with the lock held. */
    TTask<int32_t> CNetworkManager::leaveLocked(std::string endpointId) {
        SNetworkEndpoint ep;
        int32_t r = loadEndpoint(endpointId, ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (!ep.joined) {
            co_return SBOX_OK;
        }

        SNetwork net;
        r = findNetwork(ep.networkId, net);
        if (r != SBOX_OK) {
            co_return r;
        }

        INetworkDriverPtr drv = driver(net.driver);
        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (drv) {
            r = co_await drv->leave(ctx, net, ep);
            if (r != SBOX_OK) {
                co_return r;
            }
        }

        ep.joined = false;
        co_return saveEndpoint(ep);
    }

    /* Deletes an endpoint. */
    TTask<int32_t> CNetworkManager::deleteEndpoint(std::string endpointId) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await deleteEndpointLocked(std::move(endpointId));
    }

    /* Deletes an endpoint with the lock held. */
    TTask<int32_t> CNetworkManager::deleteEndpointLocked(std::string endpointId) {
        SNetworkEndpoint ep;
        int32_t r = loadEndpoint(endpointId, ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetwork net;
        bool haveNet = findNetwork(ep.networkId, net) == SBOX_OK;
        INetworkDriverPtr drv = haveNet ? driver(net.driver) : nullptr;

        SNetworkContext ctx;
        r = context(ctx);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (drv) {
            if (ep.joined) {
                // --> Best effort: the sandbox may be gone already.
                co_await drv->leave(ctx, net, ep);
            }

            r = co_await drv->deleteEndpoint(ctx, net, ep);
            if (r != SBOX_OK && r != -ENODEV && r != -ENOENT) {
                co_return r;
            }

            co_await releaseAddresses(net, ep);
        }

        if (::unlink(CFile::join(CFile::join(_options.stateDir, "endpoints"), ep.id + ".json").c_str()) < 0 && errno != ENOENT) {
            co_return -errno;
        }

        if (!ep.ports.empty() && drv && drv->usesFirewall()) {
            int32_t f = co_await syncFirewallLocked();
            if (f != SBOX_OK && f != -ENOTSUP) {
                co_return f;
            }
        }

        co_return SBOX_OK;
    }

    /* Reads an endpoint. */
    TTask<int32_t> CNetworkManager::getEndpoint(std::string endpointId, SNetworkEndpoint& out) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return loadEndpoint(endpointId, out);
    }

    /* Reads endpoints. */
    TTask<int32_t> CNetworkManager::listEndpoints(std::string networkId, std::vector<SNetworkEndpoint>& out) {
        out.clear();
        if (!CFile::exists(_options.stateDir)) {
            co_return SBOX_OK;
        }

        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SNetworkEndpoint> all;
        loadEndpoints(all);

        if (!networkId.empty()) {
            SNetwork net;
            if (findNetwork(networkId, net) == SBOX_OK) {
                networkId = net.id;
            }
        }

        for (SNetworkEndpoint& e : all) {
            if (networkId.empty() || e.networkId == networkId) {
                out.push_back(std::move(e));
            }
        }

        co_return SBOX_OK;
    }

    /* Replaces published ports. */
    TTask<int32_t> CNetworkManager::setPortMappings(std::string endpointId, std::vector<SPortMapping> ports) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetworkEndpoint ep;
        r = loadEndpoint(endpointId, ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = assignHostPorts(ports, ep.id);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SPortMapping> previous = ep.ports;
        ep.ports = std::move(ports);
        r = saveEndpoint(ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = co_await syncFirewallLocked();
        if (r != SBOX_OK) {
            ep.ports = previous;
            saveEndpoint(ep);
            co_await syncFirewallLocked();
        }

        co_return r;
    }

    /* Creates and joins in one step. */
    TTask<int32_t> CNetworkManager::connect(std::string network, std::string netnsPath, SEndpointCreate request,
        SNetworkEndpoint& out, std::string ifName)
    {
        int32_t r = CFile::makeDirs(_options.stateDir, 0700);
        if (r != SBOX_OK) {
            co_return r;
        }

        CFileLock lock;
        r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        SNetworkEndpoint ep;
        r = co_await createEndpointLocked(std::move(network), std::move(request), ep);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = co_await joinLocked(ep.id, std::move(netnsPath), std::move(ifName), out);
        if (r != SBOX_OK) {
            co_await deleteEndpointLocked(ep.id);
        }

        co_return r;
    }

    /* Leaves and deletes a container's endpoints. */
    TTask<int32_t> CNetworkManager::disconnect(std::string network, std::string containerId) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::string networkId;
        if (!network.empty()) {
            SNetwork net;
            r = findNetwork(network, net);
            if (r != SBOX_OK) {
                co_return r;
            }

            networkId = net.id;
        }

        std::vector<SNetworkEndpoint> all;
        loadEndpoints(all);
        int32_t result = SBOX_OK;
        int32_t removed = 0;

        for (const SNetworkEndpoint& e : all) {
            if (e.containerId != containerId || (!networkId.empty() && e.networkId != networkId)) {
                continue;
            }

            r = co_await deleteEndpointLocked(e.id);
            if (r != SBOX_OK && result == SBOX_OK) {
                result = r;
            }

            ++removed;
        }

        co_return result != SBOX_OK ? result : (removed ? SBOX_OK : -ENOENT);
    }

    /* Regenerates the firewall. */
    TTask<int32_t> CNetworkManager::syncFirewall() {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_options.stateDir, "net.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return co_await syncFirewallLocked();
    }

    /* Regenerates the firewall with the lock held. */
    TTask<int32_t> CNetworkManager::syncFirewallLocked() {
        if (!_options.firewall) {
            co_return SBOX_OK;
        }

        std::vector<SNetwork> nets;
        std::vector<SNetworkEndpoint> eps;
        loadNetworks(nets);
        loadEndpoints(eps);

        SFirewallState state;
        for (const SNetwork& n : nets) {
            INetworkDriverPtr drv = driver(n.driver);
            if (!drv || !drv->usesFirewall()) {
                continue;
            }

            SFirewallNetwork fn;
            fn.bridge = n.driverState.get("bridge").asString();
            if (fn.bridge.empty()) {
                continue;
            }

            for (const SNetworkSubnet& s : n.subnets) {
                fn.subnets.push_back(s.subnet);
            }

            fn.masquerade = n.flag("com.docker.network.bridge.enable_ip_masquerade", true);
            fn.icc = n.flag("com.docker.network.bridge.enable_icc", true);
            fn.internal = n.internal;
            state.networks.push_back(fn);

            SIpAddress defaultHostIp;
            std::string binding = n.option("com.docker.network.bridge.host_binding_ipv4");
            if (!binding.empty()) {
                SIpAddress::parse(binding, defaultHostIp);
            }

            for (const SNetworkEndpoint& e : eps) {
                if (e.networkId != n.id || n.internal) {
                    continue;
                }

                for (const SPortMapping& p : e.ports) {
                    SIpAddress hostIp = p.hostIp.isValid() ? p.hostIp : defaultHostIp;
                    for (const SIpPrefix& a : e.addresses) {
                        if (hostIp.isValid() && !hostIp.isUnspecified() && hostIp.family != a.address.family) {
                            continue;
                        }

                        SFirewallPortMap pm;
                        pm.bridge = fn.bridge;
                        pm.protocol = p.protocol;
                        pm.hostIp = hostIp;
                        pm.hostPort = p.hostPort;
                        pm.containerIp = a.address;
                        pm.containerPort = p.containerPort;
                        state.portMaps.push_back(pm);
                    }
                }
            }
        }

        CFirewall fw;
        int32_t r = fw.open(_options.hostNetns, _options.firewallTable);
        if (r == SBOX_OK) {
            r = state.networks.empty() ? co_await fw.remove() : co_await fw.apply(state);
        }

        if (r == -ENOTSUP && state.portMaps.empty()) {
            // --> Without nf_tables, networks still work (no NAT, no isolation); published
            // ports cannot, so only those turn the missing firewall into an error.
            co_return SBOX_OK;
        }

        co_return r;
    }

}
}
