#include "convert.hpp"
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <sys/mount.h>
#include <sys/stat.h>

namespace sbox {
namespace oci {

    namespace {

        /**
         * Turns capability names into a bit mask (unknown names were reported by validation).
         */
        uint64_t capabilityMask(const std::vector<std::string>& names) {
            uint64_t mask = 0;
            for (const std::string& name : names) {
                int32_t cap = CapabilityFromName(name);
                if (cap >= 0 && cap < 64) {
                    mask |= uint64_t(1) << cap;
                }
            }

            return mask;
        }

        /**
         * Returns the last path component.
         */
        std::string baseName(const std::string& path) {
            size_t slash = path.find_last_of('/');
            return slash == std::string::npos ? path : path.substr(slash + 1);
        }

        /**
         * Appends the mounts that make up /sys/fs/cgroup for a cgroup v1 or hybrid host: a tmpfs
         * with the container's cgroup directory of each hierarchy bound under the hierarchy's
         * name (what runc does on v1).
         */
        void cgroupV1Mounts(const SMountSpec& base, const CCgroup* cgroup, SLaunchSpec& out, std::vector<std::string>& warnings) {
            bool readOnly = (base.flags & MS_RDONLY) != 0;
            uint64_t common = base.flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC);

            SMountSpec tmp;
            tmp.source = "tmpfs";
            tmp.destination = base.destination;
            tmp.type = "tmpfs";
            tmp.flags = common;
            tmp.data = "mode=755";
            out.mounts.push_back(tmp);

            if (!cgroup || !cgroup->isValid()) {
                warnings.push_back("no container cgroup: " + base.destination + " is an empty tmpfs");
            } else {
                for (const auto& [bits, dir] : cgroup->v1Dirs()) {
                    std::string mountPoint;
                    for (const auto& [mbits, mount] : cgroup->system().v1Mounts) {
                        if (mbits == bits) {
                            mountPoint = mount;
                        }
                    }

                    if (mountPoint.empty()) {
                        continue;
                    }

                    SMountSpec b;
                    b.source = dir;
                    b.destination = CFile::join(base.destination, baseName(mountPoint));
                    b.type = "bind";
                    b.flags = MS_BIND | MS_REC | common | (readOnly ? MS_RDONLY : 0);
                    out.mounts.push_back(b);
                }

                if (!cgroup->v2Dir().empty()) {
                    SMountSpec b;
                    b.source = cgroup->v2Dir();
                    b.destination = CFile::join(base.destination, "unified");
                    b.type = "bind";
                    b.flags = MS_BIND | MS_REC | common | (readOnly ? MS_RDONLY : 0);
                    out.mounts.push_back(b);
                }
            }

            if (readOnly) {
                // --> The tmpfs itself becomes read-only once everything is mounted under it.
                out.readonlyPaths.push_back(base.destination);
            }
        }

    }

    /* Converts an OCI propagation name to MS_* flags. */
    uint64_t PropagationFlags(const std::string& name) noexcept {
        if (name == "private") {
            return MS_PRIVATE;
        }

        if (name == "rprivate") {
            return MS_PRIVATE | MS_REC;
        }

        if (name == "slave") {
            return MS_SLAVE;
        }

        if (name == "rslave") {
            return MS_SLAVE | MS_REC;
        }

        if (name == "shared") {
            return MS_SHARED;
        }

        if (name == "rshared") {
            return MS_SHARED | MS_REC;
        }

        if (name == "unbindable") {
            return MS_UNBINDABLE;
        }

        if (name == "runbindable") {
            return MS_UNBINDABLE | MS_REC;
        }

        return 0;
    }

    /* Fills the process part of a launch spec. */
    int32_t ApplyProcess(const SProcessSpec& p, SLaunchSpec& out, std::string& error, std::vector<std::string>& warnings) {
        (void) warnings;
        out.args = p.args;
        out.env = p.env;
        out.cwd = p.cwd.empty() ? "/" : p.cwd;
        out.uid = p.user.uid;
        out.gid = p.user.gid;
        out.additionalGids = p.user.additionalGids;
        out.umask = p.user.umask;
        out.noNewPrivileges = p.noNewPrivileges;
        out.terminal = p.terminal;

        if (p.consoleSize) {
            out.terminalRows = uint16_t(std::min<uint32_t>(p.consoleSize->height, 0xffff));
            out.terminalColumns = uint16_t(std::min<uint32_t>(p.consoleSize->width, 0xffff));
        }

        out.capabilities = SCapabilities();
        if (p.capabilities) {
            out.capabilities.bounding = capabilityMask(p.capabilities->bounding);
            out.capabilities.effective = capabilityMask(p.capabilities->effective);
            out.capabilities.permitted = capabilityMask(p.capabilities->permitted);
            out.capabilities.inheritable = capabilityMask(p.capabilities->inheritable);
            out.capabilities.ambient = capabilityMask(p.capabilities->ambient);
        }

        out.rlimits.clear();
        for (const SRlimitSpec& l : p.rlimits) {
            int32_t res = RlimitFromName(l.type);
            if (res < 0) {
                error = "unknown rlimit type \"" + l.type + "\"";
                return -EINVAL;
            }

            out.rlimits.push_back(SRlimit{ res, l.soft, l.hard });
        }

        return SBOX_OK;
    }

    /* Builds the init's launch spec. */
    int32_t BuildInitSpec(const SSpec& spec, const InitContext& ctx, SLaunchSpec& out, std::string& error, std::vector<std::string>& warnings) {
        out = SLaunchSpec();
        const SLinuxSpec emptyLinux;
        const SLinuxSpec& l = spec.linux_ ? *spec.linux_ : emptyLinux;

        if (!spec.process) {
            error = "process must be set";
            return -EINVAL;
        }

        if (int32_t rc = ApplyProcess(*spec.process, out, error, warnings); rc != SBOX_OK) {
            return rc;
        }

        out.oomScoreAdj = spec.process->oomScoreAdj;

        // Namespaces.
        bool newNet = false, newCgroupNs = false;
        for (const SNamespaceEntry& ns : l.namespaces) {
            uint32_t bit = NamespaceFromName(ns.type);
            out.namespaces.push_back(SNamespaceSpec{ ENamespace(bit), ns.path });
            newNet = newNet || (bit == ENS_NET && ns.path.empty());
            newCgroupNs = newCgroupNs || (bit == ENS_CGROUP && ns.path.empty());
        }

        for (const SIdMapping& m : l.uidMappings) {
            out.uidMappings.push_back(SIdMap{ m.containerID, m.hostID, m.size });
        }

        for (const SIdMapping& m : l.gidMappings) {
            out.gidMappings.push_back(SIdMap{ m.containerID, m.hostID, m.size });
        }

        out.hostname = spec.hostname;
        out.domainname = spec.domainname;
        out.loopbackUp = newNet;

        // Root.
        out.rootfsMode = ERFS_DIRECTORY;
        out.rootfs = ctx.rootfs;
        out.rootReadOnly = spec.root && spec.root->readonly;
        out.rootPropagation = PropagationFlags(l.rootfsPropagation);
        out.noPivot = ctx.noPivot;

        // Mounts.
        bool devBound = false;
        for (size_t i = 0; i < spec.mounts.size(); ++i) {
            const SMountEntry& m = spec.mounts[i];
            std::string where = "mounts[" + std::to_string(i) + "] (" + m.destination + ")";

            if (!m.uidMappings.empty() || !m.gidMappings.empty()) {
                error = where + ": idmapped mounts are not supported";
                return -ENOTSUP;
            }

            std::vector<std::string> options;
            for (const std::string& o : m.options) {
                if (o == "idmap" || o == "ridmap") {
                    error = where + ": idmapped mounts are not supported";
                    return -ENOTSUP;
                }

                if (o == "tmpcopyup") {
                    warnings.push_back(where + ": option tmpcopyup is ignored");
                    continue;
                }

                if (o == "defaults") {
                    continue;
                }

                options.push_back(o);
            }

            SMountSpec ms;
            ms.destination = m.destination[0] == '/' ? m.destination : "/" + m.destination;
            ms.type = m.type;
            ms.source = m.source;
            if (int32_t rc = ParseMountOptions(options, ms); rc != SBOX_OK) {
                error = where + ": invalid options";
                return rc;
            }

            bool bind = m.type == "bind" || (ms.flags & MS_BIND);
            if (bind) {
                ms.flags |= MS_BIND;
                ms.type = "bind";
                if (!ms.source.empty() && ms.source[0] != '/') {
                    ms.source = CFile::join(ctx.bundle, ms.source);
                }
            }

            if (ms.destination == "/dev" && bind) {
                devBound = true;
            }

            if (m.type == "cgroup" || m.type == "cgroup2") {
                SCgroupSystem system;
                if (ctx.cgroup && ctx.cgroup->isValid()) {
                    system = ctx.cgroup->system();
                } else {
                    SCgroupSystem::detect(system);
                }

                if (system.layout == ECGL_V2) {
                    if (newCgroupNs) {
                        ms.type = "cgroup2";
                        ms.source = "cgroup2";
                        out.mounts.push_back(ms);
                    } else if (ctx.cgroup && !ctx.cgroup->v2Dir().empty()) {
                        ms.type = "bind";
                        ms.source = ctx.cgroup->v2Dir();
                        ms.flags |= MS_BIND | MS_REC;
                        out.mounts.push_back(ms);
                    } else {
                        warnings.push_back(where + ": no container cgroup and no cgroup namespace; mount skipped");
                    }
                } else if (system.layout != ECGL_NONE) {
                    cgroupV1Mounts(ms, ctx.cgroup, out, warnings);
                }

                continue;
            }

            out.mounts.push_back(ms);
        }

        // Devices: runc's defaults plus the configured nodes (configured ones win by path).
        if (!devBound) {
            std::vector<SDeviceNode> devices = DefaultDevices();
            for (const SDeviceEntry& d : l.devices) {
                if (d.type == "p") {
                    warnings.push_back("linux.devices: FIFO " + d.path + " is not supported; skipped");
                    continue;
                }

                SDeviceNode node;
                node.path = d.path;
                node.type = d.type == "b" ? 'b' : 'c';
                node.major = uint32_t(d.major);
                node.minor = uint32_t(d.minor);
                node.mode = d.fileMode.value_or(0666) & 07777;
                node.uid = d.uid.value_or(0);
                node.gid = d.gid.value_or(0);

                devices.erase(std::remove_if(devices.begin(), devices.end(), [&](const SDeviceNode& x) { return x.path == node.path; }),
                              devices.end());
                devices.push_back(node);
            }

            out.devices = std::move(devices);
            out.devSymlinks = true;
        }

        out.maskedPaths = l.maskedPaths;
        out.readonlyPaths.insert(out.readonlyPaths.end(), l.readonlyPaths.begin(), l.readonlyPaths.end());

        for (const auto& [key, value] : l.sysctl) {
            std::string k = key;
            std::replace(k.begin(), k.end(), '/', '.');
            out.sysctls.emplace_back(k, value);
        }

        if (!l.netDevices.isNull() && l.netDevices.size() > 0) {
            error = "linux.netDevices is not supported";
            return -ENOTSUP;
        }

        out.cgroup = ctx.cgroup && ctx.cgroup->isValid() ? ctx.cgroup : nullptr;
        return SBOX_OK;
    }

    /* Converts OCI resources to box resources. */
    void ToCgroupResources(const SResourcesSpec& res, SCgroupResources& out, std::vector<std::string>& warnings) {
        out = SCgroupResources();

        for (const SDeviceRuleSpec& d : res.devices) {
            SCgroupDeviceRule rule;
            rule.allow = d.allow;
            rule.type = d.type.empty() ? 'a' : d.type[0];
            rule.major = d.major.value_or(-1);
            rule.minor = d.minor.value_or(-1);
            rule.access = d.access.empty() ? "rwm" : d.access;
            out.devices.push_back(rule);
        }

        if (res.memory) {
            const SMemorySpec& m = *res.memory;
            out.memoryLimit = m.limit;
            out.memoryReservation = m.reservation;
            out.memorySwap = m.swap;
            if (m.kernel || m.kernelTCP) {
                warnings.push_back("linux.resources.memory.kernel/kernelTCP are ignored");
            }

            if (m.swappiness) {
                warnings.push_back("linux.resources.memory.swappiness is ignored");
            }

            if (m.disableOOMKiller && *m.disableOOMKiller) {
                warnings.push_back("linux.resources.memory.disableOOMKiller is ignored");
            }
        }

        if (res.cpu) {
            const SCpuSpec& c = *res.cpu;
            out.cpuShares = c.shares;
            out.cpuQuota = c.quota;
            out.cpuPeriod = c.period;
            out.cpusetCpus = c.cpus;
            out.cpusetMems = c.mems;
            if (c.burst || c.realtimePeriod || c.realtimeRuntime || c.idle) {
                warnings.push_back("linux.resources.cpu: burst, realtime and idle settings are ignored");
            }
        }

        if (res.pids && res.pids->limit) {
            // --> runc treats 0 and negative values as "no limit".
            out.pidsLimit = *res.pids->limit > 0 ? *res.pids->limit : -1;
        }

        if (res.blockIO) {
            const SBlockIoSpec& b = *res.blockIO;
            out.blkioWeight = b.weight;
            auto copy = [](const std::vector<SThrottleDeviceSpec>& from, std::vector<SCgroupThrottle>& to) {
                for (const SThrottleDeviceSpec& t : from) {
                    to.push_back(SCgroupThrottle{ t.major, t.minor, t.rate });
                }
            };

            copy(b.throttleReadBpsDevice, out.readBps);
            copy(b.throttleWriteBpsDevice, out.writeBps);
            copy(b.throttleReadIOPSDevice, out.readIops);
            copy(b.throttleWriteIOPSDevice, out.writeIops);
            if (b.leafWeight || !b.weightDevice.empty()) {
                warnings.push_back("linux.resources.blockIO: leafWeight and weightDevice are ignored");
            }
        }

        if (!res.hugepageLimits.empty()) {
            warnings.push_back("linux.resources.hugepageLimits are ignored");
        }

        if (!res.network.isNull()) {
            warnings.push_back("linux.resources.network is ignored");
        }

        if (!res.rdma.isNull()) {
            warnings.push_back("linux.resources.rdma is ignored");
        }

        out.unified = res.unified;
    }

    /* Returns runc's always-allowed device rules. */
    std::vector<SCgroupDeviceRule> DefaultDeviceRules(const SSpec& spec) {
        std::vector<SCgroupDeviceRule> rules = {
            { true, 'c', -1, -1, "m" }, { true, 'b', -1, -1, "m" },
            { true, 'c', 1, 3, "rwm" }, { true, 'c', 1, 8, "rwm" }, { true, 'c', 1, 7, "rwm" },
            { true, 'c', 5, 0, "rwm" }, { true, 'c', 1, 5, "rwm" }, { true, 'c', 1, 9, "rwm" },
            { true, 'c', 5, 1, "rwm" }, { true, 'c', 136, -1, "rwm" }, { true, 'c', 5, 2, "rwm" },
            { true, 'c', 10, 200, "rwm" },
        };

        if (spec.linux_) {
            for (const SDeviceEntry& d : spec.linux_->devices) {
                if (d.type == "c" || d.type == "u" || d.type == "b") {
                    rules.push_back(SCgroupDeviceRule{ true, d.type == "b" ? 'b' : 'c', d.major, d.minor, "rwm" });
                }
            }
        }

        return rules;
    }

    /* Expands a systemd cgroupsPath. */
    int32_t ExpandSystemdCgroupPath(const std::string& path, bool rootless, std::string& out) {
        size_t a = path.find(':');
        size_t b = a == std::string::npos ? std::string::npos : path.find(':', a + 1);
        if (a == std::string::npos || b == std::string::npos || path.find(':', b + 1) != std::string::npos) {
            return -EINVAL;
        }

        std::string slice = path.substr(0, a);
        std::string prefix = path.substr(a + 1, b - a - 1);
        std::string name = path.substr(b + 1);

        if (name.empty()) {
            return -EINVAL;
        }

        if (slice.empty()) {
            slice = rootless ? "user.slice" : "system.slice";
        }

        if (slice.size() < 6 || slice.compare(slice.size() - 6, 6, ".slice") != 0 || slice.find('/') != std::string::npos) {
            return -EINVAL;
        }

        // --> "a-b-c.slice" lives at "a.slice/a-b.slice/a-b-c.slice" ("-.slice" is the root).
        std::string dir;
        if (slice != "-.slice") {
            std::string stem = slice.substr(0, slice.size() - 6);
            if (stem.empty() || stem.front() == '-' || stem.back() == '-' || stem.find("--") != std::string::npos) {
                return -EINVAL;
            }

            size_t pos = 0;
            while (true) {
                size_t dash = stem.find('-', pos);
                std::string part = stem.substr(0, dash);
                if (part.empty()) {
                    return -EINVAL;
                }

                dir += (dir.empty() ? "" : "/") + part + ".slice";
                if (dash == std::string::npos) {
                    break;
                }

                pos = dash + 1;
            }
        }

        std::string unit;
        if (name.size() > 6 && name.compare(name.size() - 6, 6, ".slice") == 0) {
            unit = name;
        } else {
            unit = (prefix.empty() ? "" : prefix + "-") + name + ".scope";
        }

        out = dir.empty() ? unit : dir + "/" + unit;
        return SBOX_OK;
    }

}
}
