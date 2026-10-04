#include <sbox/oci/spec.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/core/file.hpp>
#include "jsonread.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/resource.h>

namespace sbox {
namespace oci {

    namespace {

        /**
         * Capability names by number (kernel order).
         */
        const char* const CAPABILITY_NAMES[] = {
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
            "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
            "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        };

        /**
         * OCI rlimit names and their RLIMIT_* numbers.
         */
        const std::pair<const char*, int> RLIMITS[] = {
            { "RLIMIT_CPU", RLIMIT_CPU }, { "RLIMIT_FSIZE", RLIMIT_FSIZE }, { "RLIMIT_DATA", RLIMIT_DATA },
            { "RLIMIT_STACK", RLIMIT_STACK }, { "RLIMIT_CORE", RLIMIT_CORE }, { "RLIMIT_RSS", RLIMIT_RSS },
            { "RLIMIT_NPROC", RLIMIT_NPROC }, { "RLIMIT_NOFILE", RLIMIT_NOFILE },
            { "RLIMIT_MEMLOCK", RLIMIT_MEMLOCK }, { "RLIMIT_AS", RLIMIT_AS }, { "RLIMIT_LOCKS", RLIMIT_LOCKS },
            { "RLIMIT_SIGPENDING", RLIMIT_SIGPENDING }, { "RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE },
            { "RLIMIT_NICE", RLIMIT_NICE }, { "RLIMIT_RTPRIO", RLIMIT_RTPRIO }, { "RLIMIT_RTTIME", RLIMIT_RTTIME },
        };

        /**
         * Namespace type names, box bits and /proc/<pid>/ns file names.
         */
        struct NamespaceName {
            const char* type;
            uint32_t bit;
            const char* proc;
        };

        const NamespaceName NAMESPACES[] = {
            { "pid", ENS_PID, "pid" }, { "network", ENS_NET, "net" }, { "mount", ENS_MOUNT, "mnt" },
            { "ipc", ENS_IPC, "ipc" }, { "uts", ENS_UTS, "uts" }, { "user", ENS_USER, "user" },
            { "cgroup", ENS_CGROUP, "cgroup" }, { "time", ENS_TIME, "time" },
        };

        const char* const PROPAGATIONS[] = {
            "", "private", "rprivate", "slave", "rslave", "shared", "rshared", "unbindable", "runbindable",
        };

        const char* const SECCOMP_ACTIONS[] = {
            "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP",
            "SCMP_ACT_ERRNO", "SCMP_ACT_TRACE", "SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_NOTIFY",
        };

        const char* const SECCOMP_OPERATORS[] = {
            "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_EQ", "SCMP_CMP_GE", "SCMP_CMP_GT",
            "SCMP_CMP_MASKED_EQ",
        };

        /**
         * Returns true when `value` is one of `list`.
         */
        template<size_t N>
        bool oneOf(std::string_view value, const char* const (&list)[N]) {
            for (const char* item : list) {
                if (value == item) {
                    return true;
                }
            }

            return false;
        }

        // ---------------------------------------------------------------- parsing

        bool parseIdMappings(JsonReader& r, const CJson& obj, std::string_view key, std::vector<SIdMapping>& out, const std::string& path) {
            const CJson* arr = obj.find(key);
            if (!arr || arr->isNull()) {
                return true;
            }

            std::string here = path + "." + std::string(key);
            if (!r.expectArray(*arr, here)) {
                return false;
            }

            for (size_t i = 0; i < arr->size(); ++i) {
                const CJson& m = arr->at(i);
                std::string p = here + "[" + std::to_string(i) + "]";
                if (!r.expectObject(m, p)) {
                    return false;
                }

                SIdMapping map;
                if (!r.u32(m, "containerID", map.containerID, p) || !r.u32(m, "hostID", map.hostID, p) || !r.u32(m, "size", map.size, p)) {
                    return false;
                }

                r.unknown(m, p, { "containerID", "hostID", "size" });
                out.push_back(map);
            }

            return true;
        }

        bool parseHooks(JsonReader& r, const CJson& obj, std::string_view key, std::vector<SHook>& out, const std::string& path) {
            const CJson* arr = obj.find(key);
            if (!arr || arr->isNull()) {
                return true;
            }

            std::string here = path + "." + std::string(key);
            if (!r.expectArray(*arr, here)) {
                return false;
            }

            for (size_t i = 0; i < arr->size(); ++i) {
                const CJson& h = arr->at(i);
                std::string p = here + "[" + std::to_string(i) + "]";
                if (!r.expectObject(h, p)) {
                    return false;
                }

                SHook hook;
                if (!r.str(h, "path", hook.path, p) || !r.strings(h, "args", hook.args, p) || !r.strings(h, "env", hook.env, p) ||
                    !r.optI32(h, "timeout", hook.timeout, p)) {
                    return false;
                }

                r.unknown(h, p, { "path", "args", "env", "timeout" });
                out.push_back(std::move(hook));
            }

            return true;
        }

        bool parseThrottles(JsonReader& r, const CJson& obj, std::string_view key, std::vector<SThrottleDeviceSpec>& out, const std::string& path) {
            const CJson* arr = obj.find(key);
            if (!arr || arr->isNull()) {
                return true;
            }

            std::string here = path + "." + std::string(key);
            if (!r.expectArray(*arr, here)) {
                return false;
            }

            for (size_t i = 0; i < arr->size(); ++i) {
                const CJson& d = arr->at(i);
                std::string p = here + "[" + std::to_string(i) + "]";
                if (!r.expectObject(d, p)) {
                    return false;
                }

                SThrottleDeviceSpec t;
                if (!r.i64(d, "major", t.major, p) || !r.i64(d, "minor", t.minor, p) || !r.u64(d, "rate", t.rate, p)) {
                    return false;
                }

                r.unknown(d, p, { "major", "minor", "rate" });
                out.push_back(t);
            }

            return true;
        }

        bool parseStringMap(JsonReader& r, const CJson& obj, std::string_view key, std::vector<std::pair<std::string, std::string>>& out, const std::string& path) {
            const CJson* m = obj.find(key);
            if (!m || m->isNull()) {
                return true;
            }

            std::string here = path.empty() ? std::string(key) : path + "." + std::string(key);
            if (!r.expectObject(*m, here)) {
                return false;
            }

            for (size_t i = 0; i < m->size(); ++i) {
                if (!m->at(i).isString()) {
                    return r.fail(here + "." + m->keyAt(i), "expected a string");
                }

                out.emplace_back(m->keyAt(i), m->at(i).asString());
            }

            return true;
        }

        bool parseRaw(const CJson& obj, std::string_view key, CJson& out) {
            const CJson* v = obj.find(key);
            if (v) {
                out = *v;
            }

            return true;
        }

        bool parseCapabilities(JsonReader& r, const CJson& c, SCapabilitySets& out, const std::string& p) {
            if (!r.expectObject(c, p)) {
                return false;
            }

            if (!r.strings(c, "bounding", out.bounding, p) || !r.strings(c, "effective", out.effective, p) ||
                !r.strings(c, "inheritable", out.inheritable, p) || !r.strings(c, "permitted", out.permitted, p) ||
                !r.strings(c, "ambient", out.ambient, p)) {
                return false;
            }

            r.unknown(c, p, { "bounding", "effective", "inheritable", "permitted", "ambient" });
            return true;
        }

        bool parseProcessObject(JsonReader& r, const CJson& doc, SProcessSpec& out, const std::string& p) {
            if (!r.expectObject(doc, p)) {
                return false;
            }

            if (!r.boolean(doc, "terminal", out.terminal, p)) {
                return false;
            }

            if (const CJson* cs = doc.find("consoleSize"); cs && !cs->isNull()) {
                std::string q = p + ".consoleSize";
                if (!r.expectObject(*cs, q)) {
                    return false;
                }

                SConsoleSize size;
                if (!r.u32(*cs, "height", size.height, q) || !r.u32(*cs, "width", size.width, q)) {
                    return false;
                }

                r.unknown(*cs, q, { "height", "width" });
                out.consoleSize = size;
            }

            if (const CJson* u = doc.find("user"); u && !u->isNull()) {
                std::string q = p + ".user";
                if (!r.expectObject(*u, q)) {
                    return false;
                }

                if (!r.u32(*u, "uid", out.user.uid, q) || !r.u32(*u, "gid", out.user.gid, q) ||
                    !r.optU32(*u, "umask", out.user.umask, q) || !r.u32s(*u, "additionalGids", out.user.additionalGids, q) ||
                    !r.str(*u, "username", out.user.username, q)) {
                    return false;
                }

                r.unknown(*u, q, { "uid", "gid", "umask", "additionalGids", "username" });
            }

            if (!r.strings(doc, "args", out.args, p) || !r.str(doc, "commandLine", out.commandLine, p) ||
                !r.strings(doc, "env", out.env, p) || !r.str(doc, "cwd", out.cwd, p)) {
                return false;
            }

            if (const CJson* c = doc.find("capabilities"); c && !c->isNull()) {
                SCapabilitySets caps;
                if (!parseCapabilities(r, *c, caps, p + ".capabilities")) {
                    return false;
                }

                out.capabilities = std::move(caps);
            }

            if (const CJson* rl = doc.find("rlimits"); rl && !rl->isNull()) {
                std::string q = p + ".rlimits";
                if (!r.expectArray(*rl, q)) {
                    return false;
                }

                for (size_t i = 0; i < rl->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& item = rl->at(i);
                    if (!r.expectObject(item, e)) {
                        return false;
                    }

                    SRlimitSpec lim;
                    if (!r.str(item, "type", lim.type, e) || !r.u64(item, "hard", lim.hard, e) || !r.u64(item, "soft", lim.soft, e)) {
                        return false;
                    }

                    r.unknown(item, e, { "type", "hard", "soft" });
                    out.rlimits.push_back(lim);
                }
            }

            if (!r.boolean(doc, "noNewPrivileges", out.noNewPrivileges, p) || !r.str(doc, "apparmorProfile", out.apparmorProfile, p) ||
                !r.optI32(doc, "oomScoreAdj", out.oomScoreAdj, p) || !r.str(doc, "selinuxLabel", out.selinuxLabel, p)) {
                return false;
            }

            parseRaw(doc, "scheduler", out.scheduler);
            parseRaw(doc, "ioPriority", out.ioPriority);
            parseRaw(doc, "execCPUAffinity", out.execCPUAffinity);

            r.unknown(doc, p, { "terminal", "consoleSize", "user", "args", "commandLine", "env", "cwd", "capabilities",
                                "rlimits", "noNewPrivileges", "apparmorProfile", "oomScoreAdj", "selinuxLabel",
                                "scheduler", "ioPriority", "execCPUAffinity" });
            return true;
        }

        bool parseResourcesObject(JsonReader& r, const CJson& doc, SResourcesSpec& out, const std::string& p) {
            if (!r.expectObject(doc, p)) {
                return false;
            }

            if (const CJson* devs = doc.find("devices"); devs && !devs->isNull()) {
                std::string q = p + ".devices";
                if (!r.expectArray(*devs, q)) {
                    return false;
                }

                for (size_t i = 0; i < devs->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& d = devs->at(i);
                    if (!r.expectObject(d, e)) {
                        return false;
                    }

                    SDeviceRuleSpec rule;
                    if (!r.boolean(d, "allow", rule.allow, e) || !r.str(d, "type", rule.type, e) || !r.optI64(d, "major", rule.major, e) ||
                        !r.optI64(d, "minor", rule.minor, e) || !r.str(d, "access", rule.access, e)) {
                        return false;
                    }

                    r.unknown(d, e, { "allow", "type", "major", "minor", "access" });
                    out.devices.push_back(rule);
                }
            }

            if (const CJson* m = doc.find("memory"); m && !m->isNull()) {
                std::string q = p + ".memory";
                if (!r.expectObject(*m, q)) {
                    return false;
                }

                SMemorySpec mem;
                if (!r.optI64(*m, "limit", mem.limit, q) || !r.optI64(*m, "reservation", mem.reservation, q) ||
                    !r.optI64(*m, "swap", mem.swap, q) || !r.optI64(*m, "kernel", mem.kernel, q) ||
                    !r.optI64(*m, "kernelTCP", mem.kernelTCP, q) || !r.optU64(*m, "swappiness", mem.swappiness, q) ||
                    !r.optBool(*m, "disableOOMKiller", mem.disableOOMKiller, q) || !r.optBool(*m, "useHierarchy", mem.useHierarchy, q) ||
                    !r.optBool(*m, "checkBeforeUpdate", mem.checkBeforeUpdate, q)) {
                    return false;
                }

                r.unknown(*m, q, { "limit", "reservation", "swap", "kernel", "kernelTCP", "swappiness", "disableOOMKiller",
                                   "useHierarchy", "checkBeforeUpdate" });
                out.memory = mem;
            }

            if (const CJson* c = doc.find("cpu"); c && !c->isNull()) {
                std::string q = p + ".cpu";
                if (!r.expectObject(*c, q)) {
                    return false;
                }

                SCpuSpec cpu;
                if (!r.optU64(*c, "shares", cpu.shares, q) || !r.optI64(*c, "quota", cpu.quota, q) || !r.optU64(*c, "burst", cpu.burst, q) ||
                    !r.optU64(*c, "period", cpu.period, q) || !r.optI64(*c, "realtimeRuntime", cpu.realtimeRuntime, q) ||
                    !r.optU64(*c, "realtimePeriod", cpu.realtimePeriod, q) || !r.str(*c, "cpus", cpu.cpus, q) ||
                    !r.str(*c, "mems", cpu.mems, q) || !r.optI64(*c, "idle", cpu.idle, q)) {
                    return false;
                }

                r.unknown(*c, q, { "shares", "quota", "burst", "period", "realtimeRuntime", "realtimePeriod", "cpus", "mems", "idle" });
                out.cpu = cpu;
            }

            if (const CJson* pi = doc.find("pids"); pi && !pi->isNull()) {
                std::string q = p + ".pids";
                if (!r.expectObject(*pi, q)) {
                    return false;
                }

                SPidsSpec pids;
                if (!r.optI64(*pi, "limit", pids.limit, q)) {
                    return false;
                }

                r.unknown(*pi, q, { "limit" });
                out.pids = pids;
            }

            if (const CJson* b = doc.find("blockIO"); b && !b->isNull()) {
                std::string q = p + ".blockIO";
                if (!r.expectObject(*b, q)) {
                    return false;
                }

                SBlockIoSpec bio;
                if (!r.optU16(*b, "weight", bio.weight, q) || !r.optU16(*b, "leafWeight", bio.leafWeight, q)) {
                    return false;
                }

                if (const CJson* wd = b->find("weightDevice"); wd && !wd->isNull()) {
                    std::string e = q + ".weightDevice";
                    if (!r.expectArray(*wd, e)) {
                        return false;
                    }

                    for (size_t i = 0; i < wd->size(); ++i) {
                        std::string f = e + "[" + std::to_string(i) + "]";
                        const CJson& d = wd->at(i);
                        if (!r.expectObject(d, f)) {
                            return false;
                        }

                        SWeightDeviceSpec w;
                        if (!r.i64(d, "major", w.major, f) || !r.i64(d, "minor", w.minor, f) || !r.optU16(d, "weight", w.weight, f) ||
                            !r.optU16(d, "leafWeight", w.leafWeight, f)) {
                            return false;
                        }

                        r.unknown(d, f, { "major", "minor", "weight", "leafWeight" });
                        bio.weightDevice.push_back(w);
                    }
                }

                if (!parseThrottles(r, *b, "throttleReadBpsDevice", bio.throttleReadBpsDevice, q) ||
                    !parseThrottles(r, *b, "throttleWriteBpsDevice", bio.throttleWriteBpsDevice, q) ||
                    !parseThrottles(r, *b, "throttleReadIOPSDevice", bio.throttleReadIOPSDevice, q) ||
                    !parseThrottles(r, *b, "throttleWriteIOPSDevice", bio.throttleWriteIOPSDevice, q)) {
                    return false;
                }

                r.unknown(*b, q, { "weight", "leafWeight", "weightDevice", "throttleReadBpsDevice", "throttleWriteBpsDevice",
                                   "throttleReadIOPSDevice", "throttleWriteIOPSDevice" });
                out.blockIO = std::move(bio);
            }

            if (const CJson* h = doc.find("hugepageLimits"); h && !h->isNull()) {
                std::string q = p + ".hugepageLimits";
                if (!r.expectArray(*h, q)) {
                    return false;
                }

                for (size_t i = 0; i < h->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& item = h->at(i);
                    if (!r.expectObject(item, e)) {
                        return false;
                    }

                    SHugepageLimitSpec lim;
                    if (!r.str(item, "pageSize", lim.pageSize, e) || !r.u64(item, "limit", lim.limit, e)) {
                        return false;
                    }

                    r.unknown(item, e, { "pageSize", "limit" });
                    out.hugepageLimits.push_back(lim);
                }
            }

            parseRaw(doc, "network", out.network);
            parseRaw(doc, "rdma", out.rdma);

            if (!parseStringMap(r, doc, "unified", out.unified, p)) {
                return false;
            }

            r.unknown(doc, p, { "devices", "memory", "cpu", "pids", "blockIO", "hugepageLimits", "network", "rdma", "unified" });
            return true;
        }

        bool parseSeccomp(JsonReader& r, const CJson& doc, SSeccompSpec& out, const std::string& p) {
            if (!r.expectObject(doc, p)) {
                return false;
            }

            if (!r.str(doc, "defaultAction", out.defaultAction, p) || !r.optU32(doc, "defaultErrnoRet", out.defaultErrnoRet, p) ||
                !r.strings(doc, "architectures", out.architectures, p) || !r.strings(doc, "flags", out.flags, p) ||
                !r.str(doc, "listenerPath", out.listenerPath, p) || !r.str(doc, "listenerMetadata", out.listenerMetadata, p)) {
                return false;
            }

            if (const CJson* calls = doc.find("syscalls"); calls && !calls->isNull()) {
                std::string q = p + ".syscalls";
                if (!r.expectArray(*calls, q)) {
                    return false;
                }

                for (size_t i = 0; i < calls->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& c = calls->at(i);
                    if (!r.expectObject(c, e)) {
                        return false;
                    }

                    SSyscallSpec sc;
                    if (!r.strings(c, "names", sc.names, e) || !r.str(c, "action", sc.action, e) || !r.optU32(c, "errnoRet", sc.errnoRet, e)) {
                        return false;
                    }

                    if (const CJson* args = c.find("args"); args && !args->isNull()) {
                        std::string f = e + ".args";
                        if (!r.expectArray(*args, f)) {
                            return false;
                        }

                        for (size_t j = 0; j < args->size(); ++j) {
                            std::string g = f + "[" + std::to_string(j) + "]";
                            const CJson& a = args->at(j);
                            if (!r.expectObject(a, g)) {
                                return false;
                            }

                            SSeccompArgSpec arg;
                            if (!r.u32(a, "index", arg.index, g) || !r.u64(a, "value", arg.value, g) ||
                                !r.u64(a, "valueTwo", arg.valueTwo, g) || !r.str(a, "op", arg.op, g)) {
                                return false;
                            }

                            r.unknown(a, g, { "index", "value", "valueTwo", "op" });
                            sc.args.push_back(arg);
                        }
                    }

                    r.unknown(c, e, { "names", "action", "errnoRet", "args" });
                    out.syscalls.push_back(std::move(sc));
                }
            }

            r.unknown(doc, p, { "defaultAction", "defaultErrnoRet", "architectures", "flags", "listenerPath",
                                "listenerMetadata", "syscalls" });
            return true;
        }

        bool parseLinux(JsonReader& r, const CJson& doc, SLinuxSpec& out) {
            const std::string p = "linux";
            if (!r.expectObject(doc, p)) {
                return false;
            }

            if (!parseIdMappings(r, doc, "uidMappings", out.uidMappings, p) || !parseIdMappings(r, doc, "gidMappings", out.gidMappings, p) ||
                !parseStringMap(r, doc, "sysctl", out.sysctl, p)) {
                return false;
            }

            if (const CJson* res = doc.find("resources"); res && !res->isNull()) {
                SResourcesSpec resources;
                if (!parseResourcesObject(r, *res, resources, p + ".resources")) {
                    return false;
                }

                out.resources = std::move(resources);
            }

            if (!r.str(doc, "cgroupsPath", out.cgroupsPath, p)) {
                return false;
            }

            if (const CJson* ns = doc.find("namespaces"); ns && !ns->isNull()) {
                std::string q = p + ".namespaces";
                if (!r.expectArray(*ns, q)) {
                    return false;
                }

                for (size_t i = 0; i < ns->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& n = ns->at(i);
                    if (!r.expectObject(n, e)) {
                        return false;
                    }

                    SNamespaceEntry entry;
                    if (!r.str(n, "type", entry.type, e) || !r.str(n, "path", entry.path, e)) {
                        return false;
                    }

                    r.unknown(n, e, { "type", "path" });
                    out.namespaces.push_back(std::move(entry));
                }
            }

            if (const CJson* devs = doc.find("devices"); devs && !devs->isNull()) {
                std::string q = p + ".devices";
                if (!r.expectArray(*devs, q)) {
                    return false;
                }

                for (size_t i = 0; i < devs->size(); ++i) {
                    std::string e = q + "[" + std::to_string(i) + "]";
                    const CJson& d = devs->at(i);
                    if (!r.expectObject(d, e)) {
                        return false;
                    }

                    SDeviceEntry dev;
                    if (!r.str(d, "type", dev.type, e) || !r.str(d, "path", dev.path, e) || !r.i64(d, "major", dev.major, e) ||
                        !r.i64(d, "minor", dev.minor, e) || !r.optU32(d, "fileMode", dev.fileMode, e) || !r.optU32(d, "uid", dev.uid, e) ||
                        !r.optU32(d, "gid", dev.gid, e)) {
                        return false;
                    }

                    r.unknown(d, e, { "type", "path", "major", "minor", "fileMode", "uid", "gid" });
                    out.devices.push_back(std::move(dev));
                }
            }

            if (const CJson* sc = doc.find("seccomp"); sc && !sc->isNull()) {
                SSeccompSpec seccomp;
                if (!parseSeccomp(r, *sc, seccomp, p + ".seccomp")) {
                    return false;
                }

                out.seccomp = std::move(seccomp);
            }

            if (!r.str(doc, "rootfsPropagation", out.rootfsPropagation, p) || !r.strings(doc, "maskedPaths", out.maskedPaths, p) ||
                !r.strings(doc, "readonlyPaths", out.readonlyPaths, p) || !r.str(doc, "mountLabel", out.mountLabel, p)) {
                return false;
            }

            parseRaw(doc, "intelRdt", out.intelRdt);
            parseRaw(doc, "personality", out.personality);
            parseRaw(doc, "timeOffsets", out.timeOffsets);
            parseRaw(doc, "netDevices", out.netDevices);
            parseRaw(doc, "memoryPolicy", out.memoryPolicy);

            r.unknown(doc, p, { "uidMappings", "gidMappings", "sysctl", "resources", "cgroupsPath", "namespaces", "devices",
                                "seccomp", "rootfsPropagation", "maskedPaths", "readonlyPaths", "mountLabel", "intelRdt",
                                "personality", "timeOffsets", "netDevices", "memoryPolicy" });
            return true;
        }

        // ---------------------------------------------------------------- writing

        CJson idMappingsJson(const std::vector<SIdMapping>& maps) {
            CJson arr = CJson::array();
            for (const SIdMapping& m : maps) {
                CJson o = CJson::object();
                o.set("containerID", m.containerID);
                o.set("hostID", m.hostID);
                o.set("size", m.size);
                arr.push(std::move(o));
            }

            return arr;
        }

        CJson stringMapJson(const std::vector<std::pair<std::string, std::string>>& map) {
            CJson o = CJson::object();
            for (const auto& [k, v] : map) {
                o.set(k, v);
            }

            return o;
        }

        CJson hooksJson(const std::vector<SHook>& hooks) {
            CJson arr = CJson::array();
            for (const SHook& h : hooks) {
                CJson o = CJson::object();
                o.set("path", h.path);
                if (!h.args.empty()) {
                    o.set("args", CJson::fromStrings(h.args));
                }

                if (!h.env.empty()) {
                    o.set("env", CJson::fromStrings(h.env));
                }

                if (h.timeout) {
                    o.set("timeout", *h.timeout);
                }

                arr.push(std::move(o));
            }

            return arr;
        }

        CJson throttlesJson(const std::vector<SThrottleDeviceSpec>& list) {
            CJson arr = CJson::array();
            for (const SThrottleDeviceSpec& t : list) {
                CJson o = CJson::object();
                o.set("major", t.major);
                o.set("minor", t.minor);
                o.set("rate", t.rate);
                arr.push(std::move(o));
            }

            return arr;
        }

        template<typename T>
        void setOpt(CJson& o, std::string_view key, const std::optional<T>& v) {
            if (v) {
                o.set(key, *v);
            }
        }

        void setStr(CJson& o, std::string_view key, const std::string& v) {
            if (!v.empty()) {
                o.set(key, v);
            }
        }

        void setStrings(CJson& o, std::string_view key, const std::vector<std::string>& v) {
            if (!v.empty()) {
                o.set(key, CJson::fromStrings(v));
            }
        }

        void setRaw(CJson& o, std::string_view key, const CJson& v) {
            if (!v.isNull()) {
                o.set(key, v);
            }
        }

        CJson seccompJson(const SSeccompSpec& s) {
            CJson o = CJson::object();
            o.set("defaultAction", s.defaultAction);
            setOpt(o, "defaultErrnoRet", s.defaultErrnoRet);
            setStrings(o, "architectures", s.architectures);
            setStrings(o, "flags", s.flags);
            setStr(o, "listenerPath", s.listenerPath);
            setStr(o, "listenerMetadata", s.listenerMetadata);

            if (!s.syscalls.empty()) {
                CJson arr = CJson::array();
                for (const SSyscallSpec& c : s.syscalls) {
                    CJson e = CJson::object();
                    e.set("names", CJson::fromStrings(c.names));
                    e.set("action", c.action);
                    setOpt(e, "errnoRet", c.errnoRet);

                    if (!c.args.empty()) {
                        CJson args = CJson::array();
                        for (const SSeccompArgSpec& a : c.args) {
                            CJson x = CJson::object();
                            x.set("index", a.index);
                            x.set("value", a.value);
                            if (a.valueTwo != 0) {
                                x.set("valueTwo", a.valueTwo);
                            }

                            x.set("op", a.op);
                            args.push(std::move(x));
                        }

                        e.set("args", std::move(args));
                    }

                    arr.push(std::move(e));
                }

                o.set("syscalls", std::move(arr));
            }

            return o;
        }

        /**
         * Returns true when the namespace list holds `type`.
         */
        const SNamespaceEntry* findNamespace(const SSpec& spec, std::string_view type) {
            if (!spec.linux_) {
                return nullptr;
            }

            for (const SNamespaceEntry& ns : spec.linux_->namespaces) {
                if (ns.type == type) {
                    return &ns;
                }
            }

            return nullptr;
        }

        /**
         * Checks one sysctl against the namespaces of the configuration (as runc does).
         */
        bool validSysctl(const SSpec& spec, const std::string& key, std::string& why) {
            static const char* const IPC[] = {
                "kernel.msgmax", "kernel.msgmnb", "kernel.msgmni", "kernel.sem", "kernel.shmall",
                "kernel.shmmax", "kernel.shmmni", "kernel.shm_rmid_forced",
            };

            std::string k = key;
            std::replace(k.begin(), k.end(), '/', '.');

            if (oneOf(k, IPC) || k.rfind("fs.mqueue.", 0) == 0) {
                if (!findNamespace(spec, "ipc")) {
                    why = "sysctl \"" + key + "\" is not allowed in the host's ipc namespace";
                    return false;
                }

                return true;
            }

            if (k.rfind("net.", 0) == 0) {
                if (!findNamespace(spec, "network")) {
                    why = "sysctl \"" + key + "\" is not allowed in the host network namespace";
                    return false;
                }

                return true;
            }

            if (k == "kernel.hostname" || k == "kernel.domainname") {
                if (!findNamespace(spec, "uts")) {
                    why = "sysctl \"" + key + "\" is not allowed in the host's uts namespace";
                    return false;
                }

                return true;
            }

            why = "sysctl \"" + key + "\" is not in a separate kernel namespace";
            return false;
        }

    }

    /* Parses config.json. */
    int32_t ParseSpec(const CJson& doc, SSpec& out, std::string& error, std::vector<std::string>* warnings) {
        out = SSpec();
        error.clear();
        JsonReader r(error, warnings);

        if (!doc.isObject()) {
            error = "config.json: expected a JSON object";
            return -EINVAL;
        }

        bool ok = r.str(doc, "ociVersion", out.ociVersion, "");

        if (ok) {
            if (const CJson* p = doc.find("process"); p && !p->isNull()) {
                SProcessSpec process;
                ok = parseProcessObject(r, *p, process, "process");
                out.process = std::move(process);
            }
        }

        if (ok) {
            if (const CJson* root = doc.find("root"); root && !root->isNull()) {
                SRootSpec rs;
                ok = r.expectObject(*root, "root") && r.str(*root, "path", rs.path, "root") && r.boolean(*root, "readonly", rs.readonly, "root");
                if (ok) {
                    r.unknown(*root, "root", { "path", "readonly" });
                }

                out.root = rs;
            }
        }

        ok = ok && r.str(doc, "hostname", out.hostname, "") && r.str(doc, "domainname", out.domainname, "");

        if (ok) {
            if (const CJson* mounts = doc.find("mounts"); mounts && !mounts->isNull()) {
                ok = r.expectArray(*mounts, "mounts");
                for (size_t i = 0; ok && i < mounts->size(); ++i) {
                    std::string e = "mounts[" + std::to_string(i) + "]";
                    const CJson& m = mounts->at(i);
                    SMountEntry entry;
                    ok = r.expectObject(m, e) && r.str(m, "destination", entry.destination, e) && r.str(m, "type", entry.type, e) &&
                         r.str(m, "source", entry.source, e) && r.strings(m, "options", entry.options, e) &&
                         parseIdMappings(r, m, "uidMappings", entry.uidMappings, e) && parseIdMappings(r, m, "gidMappings", entry.gidMappings, e);
                    if (ok) {
                        r.unknown(m, e, { "destination", "type", "source", "options", "uidMappings", "gidMappings" });
                        out.mounts.push_back(std::move(entry));
                    }
                }
            }
        }

        if (ok) {
            if (const CJson* hooks = doc.find("hooks"); hooks && !hooks->isNull()) {
                SHooks h;
                ok = r.expectObject(*hooks, "hooks") && parseHooks(r, *hooks, "prestart", h.prestart, "hooks") &&
                     parseHooks(r, *hooks, "createRuntime", h.createRuntime, "hooks") &&
                     parseHooks(r, *hooks, "createContainer", h.createContainer, "hooks") &&
                     parseHooks(r, *hooks, "startContainer", h.startContainer, "hooks") &&
                     parseHooks(r, *hooks, "poststart", h.poststart, "hooks") && parseHooks(r, *hooks, "poststop", h.poststop, "hooks");
                if (ok) {
                    r.unknown(*hooks, "hooks", { "prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop" });
                }

                out.hooks = std::move(h);
            }
        }

        ok = ok && parseStringMap(r, doc, "annotations", out.annotations, "");

        if (ok) {
            if (const CJson* lx = doc.find("linux"); lx && !lx->isNull()) {
                SLinuxSpec linuxSpec;
                ok = parseLinux(r, *lx, linuxSpec);
                out.linux_ = std::move(linuxSpec);
            }
        }

        if (ok) {
            r.unknown(doc, "", { "ociVersion", "process", "root", "hostname", "domainname", "mounts", "hooks", "annotations",
                                 "linux", "solaris", "windows", "vm", "zos" });
            for (const char* other : { "solaris", "windows", "vm", "zos" }) {
                if (doc.find(other) && warnings) {
                    warnings->push_back(std::string(other) + ": section is ignored on Linux");
                }
            }
        }

        return ok ? SBOX_OK : -EINVAL;
    }

    /* Parses config.json text. */
    int32_t ParseSpecText(std::string_view text, SSpec& out, std::string& error, std::vector<std::string>* warnings) {
        CJson doc;
        size_t offset = 0;
        if (CJson::parse(text, doc, &offset) != SBOX_OK) {
            error = "config.json: invalid JSON at offset " + std::to_string(offset);
            return -EINVAL;
        }

        return ParseSpec(doc, out, error, warnings);
    }

    /* Reads and parses config.json. */
    int32_t LoadSpec(const std::string& path, SSpec& out, std::string& error, std::vector<std::string>* warnings) {
        std::string text;
        if (int32_t rc = CFile::readAll(path, text); rc != SBOX_OK) {
            error = "open " + path + ": " + std::strerror(-rc);
            return rc;
        }

        return ParseSpecText(text, out, error, warnings);
    }

    /* Parses a process object. */
    int32_t ParseProcess(const CJson& doc, SProcessSpec& out, std::string& error, std::vector<std::string>* warnings, std::string_view path) {
        out = SProcessSpec();
        error.clear();
        JsonReader r(error, warnings);
        return parseProcessObject(r, doc, out, std::string(path)) ? SBOX_OK : -EINVAL;
    }

    /* Parses a resources object. */
    int32_t ParseResources(const CJson& doc, SResourcesSpec& out, std::string& error, std::vector<std::string>* warnings, std::string_view path) {
        out = SResourcesSpec();
        error.clear();
        JsonReader r(error, warnings);
        return parseResourcesObject(r, doc, out, std::string(path)) ? SBOX_OK : -EINVAL;
    }

    /* Serializes a process object. */
    CJson ProcessToJson(const SProcessSpec& p) {
        CJson o = CJson::object();
        if (p.terminal) {
            o.set("terminal", true);
        }

        if (p.consoleSize) {
            CJson cs = CJson::object();
            cs.set("height", p.consoleSize->height);
            cs.set("width", p.consoleSize->width);
            o.set("consoleSize", std::move(cs));
        }

        CJson user = CJson::object();
        user.set("uid", p.user.uid);
        user.set("gid", p.user.gid);
        setOpt(user, "umask", p.user.umask);
        if (!p.user.additionalGids.empty()) {
            CJson gids = CJson::array();
            for (uint32_t g : p.user.additionalGids) {
                gids.push(g);
            }

            user.set("additionalGids", std::move(gids));
        }

        setStr(user, "username", p.user.username);
        o.set("user", std::move(user));

        setStrings(o, "args", p.args);
        setStr(o, "commandLine", p.commandLine);
        setStrings(o, "env", p.env);
        o.set("cwd", p.cwd);

        if (p.capabilities) {
            CJson c = CJson::object();
            setStrings(c, "bounding", p.capabilities->bounding);
            setStrings(c, "effective", p.capabilities->effective);
            setStrings(c, "inheritable", p.capabilities->inheritable);
            setStrings(c, "permitted", p.capabilities->permitted);
            setStrings(c, "ambient", p.capabilities->ambient);
            o.set("capabilities", std::move(c));
        }

        if (!p.rlimits.empty()) {
            CJson arr = CJson::array();
            for (const SRlimitSpec& l : p.rlimits) {
                CJson e = CJson::object();
                e.set("type", l.type);
                e.set("hard", l.hard);
                e.set("soft", l.soft);
                arr.push(std::move(e));
            }

            o.set("rlimits", std::move(arr));
        }

        if (p.noNewPrivileges) {
            o.set("noNewPrivileges", true);
        }

        setStr(o, "apparmorProfile", p.apparmorProfile);
        setOpt(o, "oomScoreAdj", p.oomScoreAdj);
        setStr(o, "selinuxLabel", p.selinuxLabel);
        setRaw(o, "scheduler", p.scheduler);
        setRaw(o, "ioPriority", p.ioPriority);
        setRaw(o, "execCPUAffinity", p.execCPUAffinity);
        return o;
    }

    /* Serializes a resources object. */
    CJson ResourcesToJson(const SResourcesSpec& res) {
        CJson o = CJson::object();

        if (!res.devices.empty()) {
            CJson arr = CJson::array();
            for (const SDeviceRuleSpec& d : res.devices) {
                CJson e = CJson::object();
                e.set("allow", d.allow);
                setStr(e, "type", d.type);
                setOpt(e, "major", d.major);
                setOpt(e, "minor", d.minor);
                setStr(e, "access", d.access);
                arr.push(std::move(e));
            }

            o.set("devices", std::move(arr));
        }

        if (res.memory) {
            const SMemorySpec& m = *res.memory;
            CJson e = CJson::object();
            setOpt(e, "limit", m.limit);
            setOpt(e, "reservation", m.reservation);
            setOpt(e, "swap", m.swap);
            setOpt(e, "kernel", m.kernel);
            setOpt(e, "kernelTCP", m.kernelTCP);
            setOpt(e, "swappiness", m.swappiness);
            setOpt(e, "disableOOMKiller", m.disableOOMKiller);
            setOpt(e, "useHierarchy", m.useHierarchy);
            setOpt(e, "checkBeforeUpdate", m.checkBeforeUpdate);
            o.set("memory", std::move(e));
        }

        if (res.cpu) {
            const SCpuSpec& c = *res.cpu;
            CJson e = CJson::object();
            setOpt(e, "shares", c.shares);
            setOpt(e, "quota", c.quota);
            setOpt(e, "burst", c.burst);
            setOpt(e, "period", c.period);
            setOpt(e, "realtimeRuntime", c.realtimeRuntime);
            setOpt(e, "realtimePeriod", c.realtimePeriod);
            setStr(e, "cpus", c.cpus);
            setStr(e, "mems", c.mems);
            setOpt(e, "idle", c.idle);
            o.set("cpu", std::move(e));
        }

        if (res.pids) {
            CJson e = CJson::object();
            setOpt(e, "limit", res.pids->limit);
            o.set("pids", std::move(e));
        }

        if (res.blockIO) {
            const SBlockIoSpec& b = *res.blockIO;
            CJson e = CJson::object();
            setOpt(e, "weight", b.weight);
            setOpt(e, "leafWeight", b.leafWeight);

            if (!b.weightDevice.empty()) {
                CJson arr = CJson::array();
                for (const SWeightDeviceSpec& w : b.weightDevice) {
                    CJson x = CJson::object();
                    x.set("major", w.major);
                    x.set("minor", w.minor);
                    setOpt(x, "weight", w.weight);
                    setOpt(x, "leafWeight", w.leafWeight);
                    arr.push(std::move(x));
                }

                e.set("weightDevice", std::move(arr));
            }

            if (!b.throttleReadBpsDevice.empty()) {
                e.set("throttleReadBpsDevice", throttlesJson(b.throttleReadBpsDevice));
            }

            if (!b.throttleWriteBpsDevice.empty()) {
                e.set("throttleWriteBpsDevice", throttlesJson(b.throttleWriteBpsDevice));
            }

            if (!b.throttleReadIOPSDevice.empty()) {
                e.set("throttleReadIOPSDevice", throttlesJson(b.throttleReadIOPSDevice));
            }

            if (!b.throttleWriteIOPSDevice.empty()) {
                e.set("throttleWriteIOPSDevice", throttlesJson(b.throttleWriteIOPSDevice));
            }

            o.set("blockIO", std::move(e));
        }

        if (!res.hugepageLimits.empty()) {
            CJson arr = CJson::array();
            for (const SHugepageLimitSpec& h : res.hugepageLimits) {
                CJson x = CJson::object();
                x.set("pageSize", h.pageSize);
                x.set("limit", h.limit);
                arr.push(std::move(x));
            }

            o.set("hugepageLimits", std::move(arr));
        }

        setRaw(o, "network", res.network);
        setRaw(o, "rdma", res.rdma);

        if (!res.unified.empty()) {
            o.set("unified", stringMapJson(res.unified));
        }

        return o;
    }

    /* Serializes a configuration. */
    CJson SpecToJson(const SSpec& spec) {
        CJson o = CJson::object();
        o.set("ociVersion", spec.ociVersion);

        if (spec.process) {
            o.set("process", ProcessToJson(*spec.process));
        }

        if (spec.root) {
            CJson root = CJson::object();
            root.set("path", spec.root->path);
            if (spec.root->readonly) {
                root.set("readonly", true);
            }

            o.set("root", std::move(root));
        }

        setStr(o, "hostname", spec.hostname);
        setStr(o, "domainname", spec.domainname);

        if (!spec.mounts.empty()) {
            CJson arr = CJson::array();
            for (const SMountEntry& m : spec.mounts) {
                CJson e = CJson::object();
                e.set("destination", m.destination);
                setStr(e, "type", m.type);
                setStr(e, "source", m.source);
                setStrings(e, "options", m.options);
                if (!m.uidMappings.empty()) {
                    e.set("uidMappings", idMappingsJson(m.uidMappings));
                }

                if (!m.gidMappings.empty()) {
                    e.set("gidMappings", idMappingsJson(m.gidMappings));
                }

                arr.push(std::move(e));
            }

            o.set("mounts", std::move(arr));
        }

        if (spec.hooks) {
            const SHooks& h = *spec.hooks;
            CJson e = CJson::object();
            const std::pair<const char*, const std::vector<SHook>*> lists[] = {
                { "prestart", &h.prestart }, { "createRuntime", &h.createRuntime }, { "createContainer", &h.createContainer },
                { "startContainer", &h.startContainer }, { "poststart", &h.poststart }, { "poststop", &h.poststop },
            };

            for (const auto& [name, list] : lists) {
                if (!list->empty()) {
                    e.set(name, hooksJson(*list));
                }
            }

            o.set("hooks", std::move(e));
        }

        if (!spec.annotations.empty()) {
            o.set("annotations", stringMapJson(spec.annotations));
        }

        if (spec.linux_) {
            const SLinuxSpec& l = *spec.linux_;
            CJson e = CJson::object();

            if (!l.uidMappings.empty()) {
                e.set("uidMappings", idMappingsJson(l.uidMappings));
            }

            if (!l.gidMappings.empty()) {
                e.set("gidMappings", idMappingsJson(l.gidMappings));
            }

            if (!l.sysctl.empty()) {
                e.set("sysctl", stringMapJson(l.sysctl));
            }

            if (l.resources) {
                e.set("resources", ResourcesToJson(*l.resources));
            }

            setStr(e, "cgroupsPath", l.cgroupsPath);

            if (!l.namespaces.empty()) {
                CJson arr = CJson::array();
                for (const SNamespaceEntry& n : l.namespaces) {
                    CJson x = CJson::object();
                    x.set("type", n.type);
                    setStr(x, "path", n.path);
                    arr.push(std::move(x));
                }

                e.set("namespaces", std::move(arr));
            }

            if (!l.devices.empty()) {
                CJson arr = CJson::array();
                for (const SDeviceEntry& d : l.devices) {
                    CJson x = CJson::object();
                    x.set("path", d.path);
                    x.set("type", d.type);
                    x.set("major", d.major);
                    x.set("minor", d.minor);
                    setOpt(x, "fileMode", d.fileMode);
                    setOpt(x, "uid", d.uid);
                    setOpt(x, "gid", d.gid);
                    arr.push(std::move(x));
                }

                e.set("devices", std::move(arr));
            }

            if (l.seccomp) {
                e.set("seccomp", seccompJson(*l.seccomp));
            }

            setStr(e, "rootfsPropagation", l.rootfsPropagation);
            setStrings(e, "maskedPaths", l.maskedPaths);
            setStrings(e, "readonlyPaths", l.readonlyPaths);
            setStr(e, "mountLabel", l.mountLabel);
            setRaw(e, "intelRdt", l.intelRdt);
            setRaw(e, "personality", l.personality);
            setRaw(e, "timeOffsets", l.timeOffsets);
            setRaw(e, "netDevices", l.netDevices);
            setRaw(e, "memoryPolicy", l.memoryPolicy);
            o.set("linux", std::move(e));
        }

        return o;
    }

    /* Validates a configuration. */
    int32_t ValidateSpec(const SSpec& spec, std::string& error, std::vector<std::string>* warnings, const SValidateOptions& options) {
        auto fail = [&](std::string message) {
            error = std::move(message);
            return -EINVAL;
        };

        auto warn = [&](std::string message) {
            if (warnings) {
                warnings->push_back(std::move(message));
            }
        };

        error.clear();

        // Version.
        if (spec.ociVersion.empty()) {
            return fail("ociVersion must be set");
        }

        if (spec.ociVersion.rfind("1.", 0) != 0) {
            return fail("unsupported ociVersion \"" + spec.ociVersion + "\" (this runtime implements " + OCI_VERSION + ")");
        }

        // Root.
        if (!spec.root || spec.root->path.empty()) {
            return fail("root.path must be set");
        }

        // Process.
        if (options.requireProcess && !spec.process) {
            return fail("process must be set");
        }

        if (spec.process) {
            const SProcessSpec& p = *spec.process;
            if (p.args.empty()) {
                return fail("process.args must not be empty");
            }

            if (p.cwd.empty() || p.cwd[0] != '/') {
                return fail("process.cwd \"" + p.cwd + "\" must be an absolute path");
            }

            std::vector<std::string> seen;
            for (const SRlimitSpec& l : p.rlimits) {
                if (RlimitFromName(l.type) < 0) {
                    return fail("process.rlimits: unknown rlimit type \"" + l.type + "\"");
                }

                if (l.soft > l.hard) {
                    return fail("process.rlimits: " + l.type + " soft value is greater than the hard value");
                }

                if (std::find(seen.begin(), seen.end(), l.type) != seen.end()) {
                    return fail("process.rlimits: duplicate type " + l.type);
                }

                seen.push_back(l.type);
            }

            if (p.capabilities) {
                for (const std::vector<std::string>* set : { &p.capabilities->bounding, &p.capabilities->effective,
                                                             &p.capabilities->inheritable, &p.capabilities->permitted,
                                                             &p.capabilities->ambient }) {
                    for (const std::string& name : *set) {
                        if (CapabilityFromName(name) < 0) {
                            warn("process.capabilities: ignoring unknown capability \"" + name + "\"");
                        }
                    }
                }
            }

            if (p.oomScoreAdj && (*p.oomScoreAdj < -1000 || *p.oomScoreAdj > 1000)) {
                return fail("process.oomScoreAdj must be between -1000 and 1000");
            }

            if (!p.apparmorProfile.empty()) {
                warn("process.apparmorProfile is not enforced (AppArmor is not supported)");
            }

            if (!p.selinuxLabel.empty()) {
                warn("process.selinuxLabel is not enforced (SELinux is not supported)");
            }

            if (!p.scheduler.isNull()) {
                warn("process.scheduler is ignored");
            }

            if (!p.ioPriority.isNull()) {
                warn("process.ioPriority is ignored");
            }

            if (!p.execCPUAffinity.isNull()) {
                warn("process.execCPUAffinity is ignored");
            }

            if (!p.user.username.empty()) {
                warn("process.user.username is ignored on Linux");
            }
        }

        // Namespaces.
        std::vector<std::string> types;
        if (spec.linux_) {
            for (const SNamespaceEntry& ns : spec.linux_->namespaces) {
                if (NamespaceFromName(ns.type) == ENS_NONE) {
                    return fail("linux.namespaces: unknown namespace type \"" + ns.type + "\"");
                }

                if (std::find(types.begin(), types.end(), ns.type) != types.end()) {
                    return fail("linux.namespaces: duplicate namespace " + ns.type);
                }

                if (!ns.path.empty() && ns.path[0] != '/') {
                    return fail("linux.namespaces: path of the " + ns.type + " namespace must be absolute");
                }

                types.push_back(ns.type);
            }
        }

        auto has = [&](const char* type) { return std::find(types.begin(), types.end(), type) != types.end(); };

        if (!has("mount")) {
            return fail("a mount namespace is required (linux.namespaces has no \"mount\" entry)");
        }

        const SNamespaceEntry* user = findNamespace(spec, "user");
        if (spec.linux_ && (!spec.linux_->uidMappings.empty() || !spec.linux_->gidMappings.empty()) && !user) {
            return fail("linux.uidMappings/gidMappings are set but there is no user namespace");
        }

        if (user && user->path.empty() && (spec.linux_->uidMappings.empty() || spec.linux_->gidMappings.empty())) {
            return fail("a new user namespace needs linux.uidMappings and linux.gidMappings");
        }

        if (!spec.hostname.empty()) {
            const SNamespaceEntry* uts = findNamespace(spec, "uts");
            if (!uts) {
                return fail("unable to set hostname without a private UTS namespace");
            }

            if (!uts->path.empty()) {
                return fail("unable to set hostname in a joined UTS namespace");
            }
        }

        if (!spec.domainname.empty()) {
            const SNamespaceEntry* uts = findNamespace(spec, "uts");
            if (!uts || !uts->path.empty()) {
                return fail("unable to set domainname without a private UTS namespace");
            }
        }

        // Mounts.
        for (size_t i = 0; i < spec.mounts.size(); ++i) {
            const SMountEntry& m = spec.mounts[i];
            if (m.destination.empty()) {
                return fail("mounts[" + std::to_string(i) + "].destination must be set");
            }

            if (m.destination[0] != '/') {
                warn("mounts[" + std::to_string(i) + "].destination \"" + m.destination + "\" is relative; treated as /" + m.destination);
            }
        }

        if (spec.linux_) {
            const SLinuxSpec& l = *spec.linux_;

            for (size_t i = 0; i < l.devices.size(); ++i) {
                const SDeviceEntry& d = l.devices[i];
                std::string where = "linux.devices[" + std::to_string(i) + "]";
                if (d.path.empty() || d.path[0] != '/') {
                    return fail(where + ".path must be an absolute path");
                }

                if (d.type != "c" && d.type != "b" && d.type != "u" && d.type != "p") {
                    return fail(where + ".type \"" + d.type + "\" must be one of c, b, u, p");
                }

                if (d.major < 0 || d.minor < 0) {
                    return fail(where + ": negative device numbers");
                }
            }

            if (l.resources) {
                for (size_t i = 0; i < l.resources->devices.size(); ++i) {
                    const SDeviceRuleSpec& d = l.resources->devices[i];
                    std::string where = "linux.resources.devices[" + std::to_string(i) + "]";
                    if (!d.type.empty() && d.type != "a" && d.type != "c" && d.type != "b") {
                        return fail(where + ".type \"" + d.type + "\" must be one of a, c, b");
                    }

                    if (d.access.find_first_not_of("rwm") != std::string::npos) {
                        return fail(where + ".access \"" + d.access + "\" must be a combination of r, w, m");
                    }
                }
            }

            if (!oneOf(l.rootfsPropagation, PROPAGATIONS)) {
                return fail("linux.rootfsPropagation \"" + l.rootfsPropagation + "\" is not a valid propagation mode");
            }

            for (const auto& [key, value] : l.sysctl) {
                std::string why;
                if (!validSysctl(spec, key, why)) {
                    return fail(why);
                }
            }

            if (l.seccomp) {
                const SSeccompSpec& s = *l.seccomp;
                if (!oneOf(s.defaultAction, SECCOMP_ACTIONS)) {
                    return fail("linux.seccomp.defaultAction \"" + s.defaultAction + "\" is not a known action");
                }

                for (size_t i = 0; i < s.syscalls.size(); ++i) {
                    const SSyscallSpec& c = s.syscalls[i];
                    std::string where = "linux.seccomp.syscalls[" + std::to_string(i) + "]";
                    if (c.names.empty()) {
                        return fail(where + ".names must not be empty");
                    }

                    if (!oneOf(c.action, SECCOMP_ACTIONS)) {
                        return fail(where + ".action \"" + c.action + "\" is not a known action");
                    }

                    for (const SSeccompArgSpec& a : c.args) {
                        if (!oneOf(a.op, SECCOMP_OPERATORS)) {
                            return fail(where + ": unknown operator \"" + a.op + "\"");
                        }

                        if (a.index > 5) {
                            return fail(where + ": argument index " + std::to_string(a.index) + " is out of range");
                        }
                    }
                }
            }

            for (const std::string& path : l.maskedPaths) {
                if (path.empty() || path[0] != '/') {
                    return fail("linux.maskedPaths: \"" + path + "\" must be an absolute path");
                }
            }

            for (const std::string& path : l.readonlyPaths) {
                if (path.empty() || path[0] != '/') {
                    return fail("linux.readonlyPaths: \"" + path + "\" must be an absolute path");
                }
            }

            if (!l.mountLabel.empty()) {
                warn("linux.mountLabel is ignored (SELinux is not supported)");
            }

            if (!l.intelRdt.isNull()) {
                warn("linux.intelRdt is ignored");
            }

            if (!l.personality.isNull()) {
                warn("linux.personality is ignored");
            }

            if (!l.timeOffsets.isNull()) {
                warn("linux.timeOffsets is ignored");
            }

            if (!l.memoryPolicy.isNull()) {
                warn("linux.memoryPolicy is ignored");
            }
        }

        // Hooks.
        if (spec.hooks) {
            const SHooks& h = *spec.hooks;
            for (const std::vector<SHook>* list : { &h.prestart, &h.createRuntime, &h.createContainer, &h.startContainer,
                                                    &h.poststart, &h.poststop }) {
                for (const SHook& hook : *list) {
                    if (hook.path.empty() || hook.path[0] != '/') {
                        return fail("hooks: path \"" + hook.path + "\" must be absolute");
                    }

                    if (hook.timeout && *hook.timeout <= 0) {
                        return fail("hooks: timeout of " + hook.path + " must be positive");
                    }
                }
            }

            if (!h.prestart.empty()) {
                warn("hooks.prestart is deprecated; use createRuntime");
            }
        }

        (void) options;
        return SBOX_OK;
    }

    /* Returns runc's default configuration. */
    SSpec DefaultSpec(bool rootless, uint32_t uid, uint32_t gid, std::string_view hostname) {
        SSpec s;
        s.ociVersion = OCI_VERSION;

        SProcessSpec p;
        p.terminal = true;
        p.args = { "sh" };
        p.env = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm" };
        p.cwd = "/";
        SCapabilitySets caps;
        caps.bounding = { "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE" };
        caps.effective = caps.bounding;
        caps.permitted = caps.bounding;
        p.capabilities = caps;
        p.rlimits = { SRlimitSpec{ "RLIMIT_NOFILE", 1024, 1024 } };
        p.noNewPrivileges = true;
        s.process = p;

        s.root = SRootSpec{ "rootfs", true };
        s.hostname = hostname;

        s.mounts = {
            { "/proc", "proc", "proc", {}, {}, {} },
            { "/dev", "tmpfs", "tmpfs", { "nosuid", "strictatime", "mode=755", "size=65536k" }, {}, {} },
            { "/dev/pts", "devpts", "devpts", { "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5" }, {}, {} },
            { "/dev/shm", "tmpfs", "shm", { "nosuid", "noexec", "nodev", "mode=1777", "size=65536k" }, {}, {} },
            { "/dev/mqueue", "mqueue", "mqueue", { "nosuid", "noexec", "nodev" }, {}, {} },
            { "/sys", "sysfs", "sysfs", { "nosuid", "noexec", "nodev", "ro" }, {}, {} },
            { "/sys/fs/cgroup", "cgroup", "cgroup", { "nosuid", "noexec", "nodev", "relatime", "ro" }, {}, {} },
        };

        SLinuxSpec l;
        l.maskedPaths = { "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                          "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi" };
        l.readonlyPaths = { "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger" };

        if (!rootless) {
            SResourcesSpec res;
            res.devices = { SDeviceRuleSpec{ false, "", std::nullopt, std::nullopt, "rwm" } };
            l.resources = res;
            l.namespaces = { { "pid", "" }, { "network", "" }, { "ipc", "" }, { "uts", "" }, { "mount", "" } };
        } else {
            // --> runc's ToRootless: own ids mapped to root, no network namespace (no veth
            // without privileges), /sys bound from the host, no device cgroup.
            l.uidMappings = { SIdMapping{ 0, uid, 1 } };
            l.gidMappings = { SIdMapping{ 0, gid, 1 } };
            l.namespaces = { { "pid", "" }, { "ipc", "" }, { "uts", "" }, { "mount", "" }, { "user", "" } };

            for (SMountEntry& m : s.mounts) {
                if (m.destination == "/sys") {
                    m = SMountEntry{ "/sys", "none", "/sys", { "rbind", "nosuid", "noexec", "nodev", "ro" }, {}, {} };
                } else if (m.type == "devpts") {
                    m.options.erase(std::remove(m.options.begin(), m.options.end(), "gid=5"), m.options.end());
                }
            }
        }

        s.linux_ = l;
        return s;
    }

    /* Returns the RLIMIT_* number of a name. */
    int32_t RlimitFromName(std::string_view name) noexcept {
        for (const auto& [n, value] : RLIMITS) {
            if (name == n) {
                return value;
            }
        }

        return -ENOENT;
    }

    /* Returns the name of a capability number. */
    std::string CapabilityName(int32_t cap) {
        if (cap < 0 || size_t(cap) >= sizeof(CAPABILITY_NAMES) / sizeof(CAPABILITY_NAMES[0])) {
            return std::string();
        }

        return CAPABILITY_NAMES[cap];
    }

    /* Converts a namespace type name to its box bit. */
    uint32_t NamespaceFromName(std::string_view name) noexcept {
        for (const NamespaceName& n : NAMESPACES) {
            if (name == n.type) {
                return n.bit;
            }
        }

        return ENS_NONE;
    }

    /* Returns the /proc/<pid>/ns file name of a namespace type. */
    const char* NamespaceProcName(std::string_view type) noexcept {
        for (const NamespaceName& n : NAMESPACES) {
            if (type == n.type) {
                return n.proc;
            }
        }

        return nullptr;
    }

}
}
