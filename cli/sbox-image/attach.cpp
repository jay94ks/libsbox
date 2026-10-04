#include "attach.hpp"
#include <sbox/core/file.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/vol/store.hpp>
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace imagecli {

    namespace {

        /* Consumes "--name value" / "--name=value" (and a short alias); false when args[i] is neither. */
        bool takeValue(const std::vector<std::string>& args, size_t& i, const char* name, const char* shortName,
                       std::string& out, bool& missing) {
            const std::string& a = args[i];
            for (const char* n : { name, shortName }) {
                if (!n) {
                    continue;
                }

                std::string key = n;
                if (a == key) {
                    if (i + 1 >= args.size()) {
                        missing = true;
                        return true;
                    }

                    out = args[++i];
                    return true;
                }

                if (key.size() > 2 && a.compare(0, key.size() + 1, key + "=") == 0) {
                    out = a.substr(key.size() + 1);
                    return true;
                }
            }

            return false;
        }

        /* Reads a bundle's config.json. */
        int32_t readConfig(const std::string& bundle, CJson& out) {
            std::string text;
            int32_t r = CFile::readAll(CFile::join(bundle, "config.json"), text);
            if (r != SBOX_OK) {
                return r;
            }

            return CJson::parse(text, out) == SBOX_OK && out.isObject() ? SBOX_OK : -EINVAL;
        }

        /* Sets the path of the network namespace entry (added when the spec has none). */
        void setNetworkNamespace(CJson& config, const std::string& path) {
            CJson& namespaces = config["linux"]["namespaces"];
            if (!namespaces.isArray()) {
                namespaces = CJson::array();
            }

            for (size_t i = 0; i < namespaces.size(); ++i) {
                if (namespaces.at(i).get("type").asString() == "network") {
                    namespaces.at(i).set("path", path);
                    return;
                }
            }

            CJson entry = CJson::object();
            entry.set("type", "network");
            entry.set("path", path);
            namespaces.push(std::move(entry));
        }

        /* Returns true when the spec maps users (a rootless bundle). */
        bool hasUserNamespace(const CJson& config) {
            const CJson& namespaces = config.get("linux").get("namespaces");
            for (size_t i = 0; i < namespaces.size(); ++i) {
                if (namespaces.at(i).get("type").asString() == "user") {
                    return true;
                }
            }

            return false;
        }

    }

    /* Returns true when nothing is to be attached. */
    bool AttachRequest::empty() const noexcept {
        return mounts.empty() && network.empty() && netns.empty() && ports.empty();
    }

    /* Serializes the record. */
    CJson AttachRecord::toJson() const {
        CJson j = CJson::object();
        j.set("id", id);
        j.set("volumeRoot", volumeRoot);
        j.set("volumes", CJson::fromStrings(volumes));
        j.set("netStateDir", netStateDir);
        j.set("network", network);
        j.set("netns", netns);
        CJson p = CJson::array();
        for (const net::SPortMapping& m : ports) {
            p.push(m.toJson());
        }

        j.set("ports", std::move(p));
        j.set("address", address);
        return j;
    }

    /* Parses a record. */
    int32_t AttachRecord::fromJson(const CJson& json, AttachRecord& out) {
        if (!json.isObject()) {
            return -EINVAL;
        }

        AttachRecord r;
        r.id = json.get("id").asString();
        r.volumeRoot = json.get("volumeRoot").asString();
        r.volumes = json.get("volumes").asStrings();
        r.netStateDir = json.get("netStateDir").asString();
        r.network = json.get("network").asString();
        r.netns = json.get("netns").asString();
        r.address = json.get("address").asString();
        const CJson& p = json.get("ports");
        for (size_t i = 0; i < p.size(); ++i) {
            net::SPortMapping m;
            if (net::SPortMapping::fromJson(p.at(i), m) != SBOX_OK) {
                return -EINVAL;
            }

            r.ports.push_back(m);
        }

        if (r.id.empty()) {
            return -EINVAL;
        }

        out = std::move(r);
        return SBOX_OK;
    }

    /* Parses one attach option. */
    int32_t ParseAttachOption(const std::vector<std::string>& args, size_t& i, AttachRequest& out, std::string& error) {
        std::string v;
        bool missing = false;
        auto need = [&](const char* name) {
            error = std::string(name) + " needs a value";
            return -EINVAL;
        };

        if (takeValue(args, i, "--volume", "-v", v, missing)) {
            if (missing) {
                return need("--volume");
            }

            vol::SMountRequest m;
            if (vol::ParseVolumeFlag(v, m, &error) != SBOX_OK) {
                error = "--volume " + v + ": " + error;
                return -EINVAL;
            }

            out.mounts.push_back(std::move(m));
            return 1;
        }

        if (takeValue(args, i, "--mount", nullptr, v, missing)) {
            if (missing) {
                return need("--mount");
            }

            vol::SMountRequest m;
            if (vol::ParseMountFlag(v, m, &error) != SBOX_OK) {
                error = "--mount " + v + ": " + error;
                return -EINVAL;
            }

            out.mounts.push_back(std::move(m));
            return 1;
        }

        if (takeValue(args, i, "--tmpfs", nullptr, v, missing)) {
            if (missing) {
                return need("--tmpfs");
            }

            vol::SMountRequest m;
            if (vol::ParseTmpfsFlag(v, m, &error) != SBOX_OK) {
                error = "--tmpfs " + v + ": " + error;
                return -EINVAL;
            }

            out.mounts.push_back(std::move(m));
            return 1;
        }

        if (takeValue(args, i, "--publish", "-p", v, missing)) {
            if (missing) {
                return need("--publish");
            }

            net::SPortMapping m;
            if (net::SPortMapping::parse(v, m) != SBOX_OK) {
                error = "invalid --publish " + v + " (want [hostIp:]hostPort:containerPort[/tcp|udp|sctp])";
                return -EINVAL;
            }

            out.ports.push_back(m);
            return 1;
        }

        struct {
            const char* name;
            std::string* target;
        } plain[] = {
            { "--volume-root", &out.volumeRoot },
            { "--network", &out.network },
            { "--netns", &out.netns },
            { "--net-state-dir", &out.netStateDir },
            { "--netns-dir", &out.netnsDir },
        };

        for (auto& p : plain) {
            if (takeValue(args, i, p.name, nullptr, v, missing)) {
                if (missing || v.empty()) {
                    return need(p.name);
                }

                *p.target = v;
                return 1;
            }
        }

        return 0;
    }

    /* Prepares mounts and network and edits config.json. */
    TTask<int32_t> AttachContainer(AttachRequest request, std::string id, std::string bundle, std::string rootfs,
                                   AttachRecord& out, std::string& error) {
        out = AttachRecord();
        out.id = id;

        if (!request.network.empty() && !request.netns.empty()) {
            error = "--network and --netns are mutually exclusive";
            co_return -EINVAL;
        }

        if (!request.ports.empty() && request.network.empty()) {
            error = "--publish needs --network";
            co_return -EINVAL;
        }

        CJson config;
        int32_t r = readConfig(bundle, config);
        if (r != SBOX_OK) {
            error = "cannot read " + bundle + "/config.json";
            co_return r;
        }

        if (!request.network.empty() && (hasUserNamespace(config) || !net::CanManageHostNetwork())) {
            // --> A rootless container has no network of its own to connect (CAP_NET_ADMIN in
            // the initial namespace is needed for veth pairs and the host side).
            error = "--network needs root (rootless containers have loopback-only networking)";
            co_return -EPERM;
        }

        if (!request.netns.empty() && !net::CNetns::isNetns(request.netns)) {
            error = request.netns + " is not a network namespace";
            co_return -EINVAL;
        }

        std::unique_ptr<vol::CVolumeStore> store;
        std::unique_ptr<net::CNetworkManager> manager;

        // --> Undo whatever succeeded so far; a half-attached bundle is worse than none.
        auto rollback = [&]() -> TTask<void> {
            if (manager && !out.network.empty()) {
                co_await manager->disconnect(out.network, id);
            }

            if (!out.netns.empty()) {
                net::CNetns::remove(out.netns);
            }

            if (store && !out.volumes.empty()) {
                co_await store->releaseUser(id, true);
            }
        };

        // -- Volumes, binds and tmpfs.
        if (!request.mounts.empty()) {
            vol::SVolumeStoreOptions so;
            so.root = request.volumeRoot.empty() ? vol::DefaultVolumeRoot() : request.volumeRoot;
            store = std::make_unique<vol::CVolumeStore>(so);

            std::vector<CJson> mounts;
            std::string why;
            r = co_await vol::PrepareContainerMounts(*store, request.mounts, id, rootfs, mounts, &why);
            if (r != SBOX_OK) {
                error = why.empty() ? std::string("cannot prepare mounts: ") + std::strerror(-r) : why;
                co_return r;
            }

            out.volumeRoot = so.root;
            std::vector<vol::SVolume> all;
            store->list(all);
            for (const vol::SVolume& v : all) {
                for (const std::string& u : v.users) {
                    if (u == id) {
                        out.volumes.push_back(v.name);
                    }
                }
            }

            CJson& list = config["mounts"];
            if (!list.isArray()) {
                list = CJson::array();
            }

            for (CJson& m : mounts) {
                list.push(std::move(m));
            }
        }

        // -- Network.
        if (!request.network.empty()) {
            net::SNetworkManagerOptions mo;
            mo.stateDir = request.netStateDir.empty() ? net::DefaultNetworkStateDir() : request.netStateDir;
            out.netStateDir = mo.stateDir;
            manager = std::make_unique<net::CNetworkManager>(mo);

            std::string path;
            r = net::CNetns::createNamed(id, path, request.netnsDir.empty() ? net::CNetns::IPROUTE2_DIR : request.netnsDir);
            if (r != SBOX_OK) {
                error = std::string("cannot create the network namespace: ") + std::strerror(-r);
                co_await rollback();
                co_return r;
            }

            out.netns = path;
            net::SEndpointCreate ec;
            ec.containerId = id;
            ec.ports = request.ports;
            ec.hostname = config.get("hostname").asString();
            net::SNetworkEndpoint ep;
            r = co_await manager->connect(request.network, path, ec, ep);
            if (r != SBOX_OK) {
                error = "cannot connect to network " + request.network + ": " + std::strerror(-r);
                co_await rollback();
                co_return r;
            }

            out.network = request.network;
            out.ports = ep.ports;
            out.address = ep.address(4).isValid() ? ep.address(4).toString() : std::string();
            setNetworkNamespace(config, path);
        } else if (!request.netns.empty()) {
            setNetworkNamespace(config, request.netns);
        }

        r = CFile::writeAtomic(CFile::join(bundle, "config.json"), config.dump(true), 0644);
        if (r != SBOX_OK) {
            error = "cannot write config.json";
            co_await rollback();
            co_return r;
        }

        co_return SBOX_OK;
    }

    /* Undoes AttachContainer. */
    TTask<int32_t> DetachContainer(AttachRecord record, bool removeAnonymous, std::string& error) {
        int32_t result = SBOX_OK;
        if (!record.network.empty()) {
            net::SNetworkManagerOptions mo;
            mo.stateDir = record.netStateDir.empty() ? net::DefaultNetworkStateDir() : record.netStateDir;
            net::CNetworkManager manager(mo);
            int32_t r = co_await manager.disconnect(record.network, record.id);
            if (r != SBOX_OK && r != -ENOENT) {
                error = "cannot disconnect from network " + record.network + ": " + std::strerror(-r);
                result = r;
            }
        }

        if (!record.netns.empty()) {
            int32_t r = net::CNetns::remove(record.netns);
            if (r != SBOX_OK && result == SBOX_OK) {
                error = "cannot remove " + record.netns + ": " + std::strerror(-r);
                result = r;
            }
        }

        if (!record.volumeRoot.empty()) {
            vol::SVolumeStoreOptions so;
            so.root = record.volumeRoot;
            vol::CVolumeStore store(so);
            int32_t r = co_await store.releaseUser(record.id, removeAnonymous);
            if (r != SBOX_OK && r != -ENOENT && result == SBOX_OK) {
                error = "cannot release volumes: " + (store.lastError().empty() ? std::string(std::strerror(-r)) : store.lastError());
                result = r;
            }
        }

        co_return result;
    }

    /* Returns the record path. */
    std::string AttachRecordPath(const std::string& storeRoot, const std::string& id) {
        return CFile::join(CFile::join(storeRoot, "attachments"), id + ".json");
    }

    /* Writes a record. */
    int32_t SaveAttachRecord(const std::string& storeRoot, const AttachRecord& record) {
        int32_t r = CFile::makeDirs(CFile::join(storeRoot, "attachments"), 0700);
        if (r != SBOX_OK) {
            return r;
        }

        return CFile::writeAtomic(AttachRecordPath(storeRoot, record.id), record.toJson().dump(true), 0600);
    }

    /* Reads a record. */
    int32_t LoadAttachRecord(const std::string& storeRoot, const std::string& id, AttachRecord& out) {
        std::string text;
        int32_t r = CFile::readAll(AttachRecordPath(storeRoot, id), text);
        if (r != SBOX_OK) {
            return r;
        }

        CJson json;
        if (CJson::parse(text, json) != SBOX_OK) {
            return -EINVAL;
        }

        return AttachRecord::fromJson(json, out);
    }

}
