#include <sbox/image/runtime.hpp>
#include "util.hpp"
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <sys/utsname.h>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        const char* const DEFAULT_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

        /* Every capability name runc knows (for "ALL"). */
        const char* const ALL_CAPS[] = {
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
            "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT",
            "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
            "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
            "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        };

        /* Splits a line of a colon separated database. */
        std::vector<std::string> splitColon(std::string_view line) {
            std::vector<std::string> out;
            size_t start = 0;
            while (true) {
                size_t c = line.find(':', start);
                out.emplace_back(line.substr(start, c == std::string_view::npos ? std::string_view::npos : c - start));
                if (c == std::string_view::npos) {
                    break;
                }

                start = c + 1;
            }

            return out;
        }

        /* Parses a non-negative 32-bit id. */
        bool parseId(std::string_view s, uint32_t& out) {
            if (s.empty() || s.size() > 10) {
                return false;
            }

            uint64_t v = 0;
            for (char c : s) {
                if (c < '0' || c > '9') {
                    return false;
                }

                v = v * 10 + uint64_t(c - '0');
            }

            if (v > 0xFFFFFFFEull) {
                return false;
            }

            out = uint32_t(v);
            return true;
        }

        /* Normalizes "net_admin" / "NET_ADMIN" / "CAP_NET_ADMIN" to "CAP_NET_ADMIN". */
        std::string capName(std::string_view s) {
            std::string up(s);
            for (char& c : up) {
                if (c >= 'a' && c <= 'z') {
                    c = char(c - 'a' + 'A');
                }
            }

            if (up == "ALL") {
                return up;
            }

            return up.compare(0, 4, "CAP_") == 0 ? up : "CAP_" + up;
        }

        /* Maps a Go architecture to the libseccomp name. */
        std::string seccompArch(std::string_view goArch) {
            if (goArch == "amd64") return "SCMP_ARCH_X86_64";
            if (goArch == "386") return "SCMP_ARCH_X86";
            if (goArch == "arm64") return "SCMP_ARCH_AARCH64";
            if (goArch == "arm") return "SCMP_ARCH_ARM";
            if (goArch == "ppc64le") return "SCMP_ARCH_PPC64LE";
            if (goArch == "ppc64") return "SCMP_ARCH_PPC64";
            if (goArch == "s390x") return "SCMP_ARCH_S390X";
            if (goArch == "s390") return "SCMP_ARCH_S390";
            if (goArch == "riscv64") return "SCMP_ARCH_RISCV64";
            if (goArch == "mips64") return "SCMP_ARCH_MIPS64";
            if (goArch == "mips64le") return "SCMP_ARCH_MIPSEL64";
            if (goArch == "loong64") return "SCMP_ARCH_LOONGARCH64";
            return std::string();
        }

        /* Returns true when the running kernel is at least "major.minor". */
        bool kernelAtLeast(std::string_view version) {
            struct utsname u{};
            if (::uname(&u) != 0) {
                return true;
            }

            int wantMajor = 0;
            int wantMinor = 0;
            int haveMajor = 0;
            int haveMinor = 0;
            std::sscanf(std::string(version).c_str(), "%d.%d", &wantMajor, &wantMinor);
            std::sscanf(u.release, "%d.%d", &haveMajor, &haveMinor);
            return haveMajor > wantMajor || (haveMajor == wantMajor && haveMinor >= wantMinor);
        }

        /* Returns true when `list` contains `value`. */
        bool contains(const std::vector<std::string>& list, std::string_view value) {
            return std::find(list.begin(), list.end(), value) != list.end();
        }

        /* Builds a mount entry. */
        CJson mountEntry(const char* destination, const char* type, const char* source, std::vector<std::string> options) {
            CJson m = CJson::object();
            m.set("destination", destination);
            m.set("type", type);
            m.set("source", source);
            m.set("options", CJson::fromStrings(options));
            return m;
        }

        /* Builds a device cgroup rule. */
        CJson deviceRule(bool allow, const char* type, int64_t major, int64_t minor, const char* access) {
            CJson d = CJson::object();
            d.set("allow", allow);
            if (type) {
                d.set("type", type);
            }

            if (major >= 0) {
                d.set("major", major);
            }

            if (minor >= 0) {
                d.set("minor", minor);
            }

            d.set("access", access);
            return d;
        }

        /* Sets NAME=value in an environment list (replacing an existing NAME). */
        void setEnv(std::vector<std::string>& env, const std::string& entry, bool overwrite = true) {
            size_t eq = entry.find('=');
            std::string name = entry.substr(0, eq);
            for (std::string& e : env) {
                if (e.compare(0, name.size(), name) == 0 && (e.size() == name.size() || e[name.size()] == '=')) {
                    if (overwrite) {
                        e = entry;
                    }

                    return;
                }
            }

            env.push_back(entry);
        }

        /* Returns true when NAME is set in an environment list. */
        bool hasEnv(const std::vector<std::string>& env, const std::string& name) {
            for (const std::string& e : env) {
                if (e.compare(0, name.size(), name) == 0 && e.size() > name.size() && e[name.size()] == '=') {
                    return true;
                }
            }

            return false;
        }

    }

    /* Resolves a user spec through the rootfs databases. */
    int32_t ResolveUser(const std::string& rootfs, std::string_view spec, SResolvedUser& out, std::string* error) {
        out = SResolvedUser();
        std::string_view userPart = spec;
        std::string_view groupPart;
        bool hasGroup = false;
        size_t colon = spec.find(':');
        if (colon != std::string_view::npos) {
            userPart = spec.substr(0, colon);
            groupPart = spec.substr(colon + 1);
            hasGroup = true;
        }

        if (userPart.empty()) {
            userPart = "0";
        }

        std::string passwd;
        std::string group;
        if (!rootfs.empty()) {
            ReadFileInRoot(rootfs, "/etc/passwd", passwd);
            ReadFileInRoot(rootfs, "/etc/group", group);
        }

        uint32_t numeric = 0;
        bool isNumeric = parseId(userPart, numeric);
        bool found = false;
        for (std::string_view line : CFile::splitLines(passwd)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }

            std::vector<std::string> f = splitColon(line);
            if (f.size() < 7) {
                continue;
            }

            uint32_t uid = 0;
            uint32_t gid = 0;
            if (!parseId(f[2], uid) || !parseId(f[3], gid)) {
                continue;
            }

            if ((isNumeric && uid == numeric) || (!isNumeric && f[0] == userPart)) {
                out.uid = uid;
                out.gid = gid;
                out.name = f[0];
                out.home = f[5].empty() ? "/" : f[5];
                found = true;
                break;
            }
        }

        if (!found) {
            if (!isNumeric) {
                if (error) {
                    *error = "unable to find user " + std::string(userPart) + ": no matching entries in passwd file";
                }

                return -ENOENT;
            }

            out.uid = numeric;
            out.gid = 0;
        }

        if (hasGroup) {
            if (groupPart.empty()) {
                if (error) {
                    *error = "invalid user specification " + std::string(spec);
                }

                return -EINVAL;
            }

            uint32_t gnum = 0;
            if (parseId(groupPart, gnum)) {
                out.gid = gnum;
            } else {
                bool gfound = false;
                for (std::string_view line : CFile::splitLines(group)) {
                    std::vector<std::string> f = splitColon(line);
                    uint32_t gid = 0;
                    if (f.size() >= 3 && f[0] == groupPart && parseId(f[2], gid)) {
                        out.gid = gid;
                        gfound = true;
                        break;
                    }
                }

                if (!gfound) {
                    if (error) {
                        *error = "unable to find group " + std::string(groupPart) + ": no matching entries in group file";
                    }

                    return -ENOENT;
                }
            }
        }

        // --> Supplementary groups: every /etc/group entry listing the user by name.
        if (!out.name.empty()) {
            for (std::string_view line : CFile::splitLines(group)) {
                std::vector<std::string> f = splitColon(line);
                uint32_t gid = 0;
                if (f.size() < 4 || !parseId(f[2], gid) || gid == out.gid) {
                    continue;
                }

                size_t start = 0;
                const std::string& members = f[3];
                while (start <= members.size()) {
                    size_t comma = members.find(',', start);
                    std::string m = members.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
                    if (m == out.name && std::find(out.additionalGids.begin(), out.additionalGids.end(), gid) == out.additionalGids.end()) {
                        out.additionalGids.push_back(gid);
                    }

                    if (comma == std::string::npos) {
                        break;
                    }

                    start = comma + 1;
                }
            }
        }

        return SBOX_OK;
    }

    /* Returns Docker's default capabilities. */
    std::vector<std::string> DefaultCapabilities() {
        return { "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
                 "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT",
                 "CAP_KILL", "CAP_AUDIT_WRITE" };
    }

    /* Converts a Docker seccomp profile into the OCI form. */
    int32_t SeccompProfileToOci(const CJson& profile, std::string_view goArch, const std::vector<std::string>& capabilities,
                                CJson& out) {
        out = CJson::object();
        if (!profile.isObject()) {
            return -EINVAL;
        }

        out.set("defaultAction", profile.get("defaultAction").asString());
        const CJson* errnoRet = profile.find("defaultErrnoRet");
        if (errnoRet) {
            out.set("defaultErrnoRet", errnoRet->asInt());
        }

        std::string native = seccompArch(goArch);
        CJson arches = CJson::array();
        const CJson& archMap = profile.get("archMap");
        for (size_t i = 0; i < archMap.size(); ++i) {
            if (archMap.at(i).get("architecture").asString() == native) {
                arches.push(native);
                for (const std::string& sub : archMap.at(i).get("subArchitectures").asStrings()) {
                    arches.push(sub);
                }
            }
        }

        out.set("architectures", std::move(arches));
        CJson calls = CJson::array();
        const CJson& syscalls = profile.get("syscalls");
        if (!syscalls.isArray()) {
            return -EINVAL;
        }

        for (size_t i = 0; i < syscalls.size(); ++i) {
            const CJson& call = syscalls.at(i);
            const CJson& inc = call.get("includes");
            const CJson& exc = call.get("excludes");
            std::vector<std::string> excArches = exc.get("arches").asStrings();
            std::vector<std::string> excCaps = exc.get("caps").asStrings();
            std::vector<std::string> incArches = inc.get("arches").asStrings();
            std::vector<std::string> incCaps = inc.get("caps").asStrings();
            bool keep = true;
            if (!excArches.empty() && contains(excArches, goArch)) {
                keep = false;
            }

            for (const std::string& c : excCaps) {
                keep = keep && !contains(capabilities, c);
            }

            if (exc.find("minKernel") && kernelAtLeast(exc.get("minKernel").asString())) {
                keep = false;
            }

            if (!incArches.empty() && !contains(incArches, goArch)) {
                keep = false;
            }

            for (const std::string& c : incCaps) {
                keep = keep && contains(capabilities, c);
            }

            if (inc.find("minKernel") && !kernelAtLeast(inc.get("minKernel").asString())) {
                keep = false;
            }

            if (!keep) {
                continue;
            }

            CJson rule = CJson::object();
            std::vector<std::string> names = call.get("names").asStrings();
            if (names.empty() && call.get("name").isString()) {
                names.push_back(call.get("name").asString());
            }

            rule.set("names", CJson::fromStrings(names));
            rule.set("action", call.get("action").asString());
            if (call.find("errnoRet")) {
                rule.set("errnoRet", call.get("errnoRet").asInt());
            }

            const CJson& args = call.get("args");
            if (args.isArray() && args.size() > 0) {
                CJson outArgs = CJson::array();
                for (size_t a = 0; a < args.size(); ++a) {
                    CJson arg = CJson::object();
                    arg.set("index", args.at(a).get("index").asInt());
                    arg.set("value", args.at(a).get("value"));
                    arg.set("valueTwo", args.at(a).find("valueTwo") ? args.at(a).get("valueTwo") : CJson(int64_t(0)));
                    arg.set("op", args.at(a).get("op").asString());
                    outArgs.push(std::move(arg));
                }

                rule.set("args", std::move(outArgs));
            }

            calls.push(std::move(rule));
        }

        out.set("syscalls", std::move(calls));
        return SBOX_OK;
    }

    /* Builds an OCI runtime spec from an image config. */
    int32_t GenerateRuntimeSpec(const SImageConfig& config, const std::string& rootfs, const SBundleOptions& options,
                                CJson& out, std::string* error) {
        out = CJson::object();
        std::vector<std::string> args = options.hasEntrypoint ? options.entrypoint : config.entrypoint;
        // --> Like docker run: a new entrypoint drops the image's Cmd.
        std::vector<std::string> cmd = !options.args.empty() ? options.args : (options.hasEntrypoint ? std::vector<std::string>() : config.cmd);
        args.insert(args.end(), cmd.begin(), cmd.end());
        if (args.empty()) {
            if (error) {
                *error = "no command specified: the image has neither Entrypoint nor Cmd";
            }

            return -EINVAL;
        }

        std::string userSpec = options.user.empty() ? config.user : options.user;
        SResolvedUser user;
        int32_t r = ResolveUser(rootfs, userSpec, user, error);
        if (r != SBOX_OK) {
            return r;
        }

        std::string hostname = options.hostname.empty() ? RandomHex(6) : options.hostname;
        std::vector<std::string> env;
        env.push_back(DEFAULT_PATH);
        env.push_back("HOSTNAME=" + hostname);
        for (const std::string& e : config.env) {
            setEnv(env, e);
        }

        for (const std::string& e : options.env) {
            setEnv(env, e.find('=') == std::string::npos ? e + "=" : e);
        }

        if (!hasEnv(env, "HOME")) {
            env.push_back("HOME=" + user.home);
        }

        if (options.terminal && !hasEnv(env, "TERM")) {
            env.push_back("TERM=xterm");
        }

        std::string cwd = options.workingDir.empty() ? config.workingDir : options.workingDir;
        if (cwd.empty()) {
            cwd = "/";
        } else if (cwd[0] != '/') {
            cwd = "/" + cwd;
        }

        // --> Capabilities: Docker's defaults, then --cap-add / --cap-drop.
        std::vector<std::string> caps = DefaultCapabilities();
        for (const std::string& c : options.capAdd) {
            std::string n = capName(c);
            if (n == "ALL") {
                caps.assign(std::begin(ALL_CAPS), std::end(ALL_CAPS));
            } else if (!contains(caps, n)) {
                caps.push_back(n);
            }
        }

        for (const std::string& c : options.capDrop) {
            std::string n = capName(c);
            if (n == "ALL") {
                caps.clear();
            } else {
                caps.erase(std::remove(caps.begin(), caps.end(), n), caps.end());
            }
        }

        out.set("ociVersion", "1.2.0");
        CJson process = CJson::object();
        process.set("terminal", options.terminal);
        CJson u = CJson::object();
        u.set("uid", user.uid);
        u.set("gid", user.gid);
        if (!user.additionalGids.empty()) {
            CJson g = CJson::array();
            for (uint32_t gid : user.additionalGids) {
                g.push(gid);
            }

            u.set("additionalGids", std::move(g));
        }

        process.set("user", std::move(u));
        process.set("args", CJson::fromStrings(args));
        process.set("env", CJson::fromStrings(env));
        process.set("cwd", cwd);
        CJson capSet = CJson::object();
        capSet.set("bounding", CJson::fromStrings(caps));
        capSet.set("effective", CJson::fromStrings(caps));
        capSet.set("permitted", CJson::fromStrings(caps));
        process.set("capabilities", std::move(capSet));
        process.set("noNewPrivileges", options.noNewPrivileges);
        out.set("process", std::move(process));

        CJson root = CJson::object();
        root.set("path", options.rootPath);
        root.set("readonly", options.readOnlyRoot);
        out.set("root", std::move(root));
        out.set("hostname", hostname);

        CJson mounts = CJson::array();
        mounts.push(mountEntry("/proc", "proc", "proc", { "nosuid", "noexec", "nodev" }));
        mounts.push(mountEntry("/dev", "tmpfs", "tmpfs", { "nosuid", "strictatime", "mode=755", "size=65536k" }));
        if (options.rootless) {
            mounts.push(mountEntry("/dev/pts", "devpts", "devpts", { "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620" }));
        } else {
            mounts.push(mountEntry("/dev/pts", "devpts", "devpts", { "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5" }));
        }

        if (options.rootless) {
            // --> sysfs cannot be mounted without the network namespace's owner: bind it.
            mounts.push(mountEntry("/sys", "none", "/sys", { "rbind", "nosuid", "noexec", "nodev", "ro" }));
        } else {
            mounts.push(mountEntry("/sys", "sysfs", "sysfs", { "nosuid", "noexec", "nodev", "ro" }));
            mounts.push(mountEntry("/sys/fs/cgroup", "cgroup", "cgroup", { "ro", "nosuid", "noexec", "nodev" }));
        }

        mounts.push(mountEntry("/dev/mqueue", "mqueue", "mqueue", { "nosuid", "noexec", "nodev" }));
        mounts.push(mountEntry("/dev/shm", "tmpfs", "shm", { "nosuid", "noexec", "nodev", "mode=1777", "size=65536k" }));
        out.set("mounts", std::move(mounts));

        // --> Annotations: labels, then the image-spec conversion keys.
        CJson ann = CJson::object();
        for (const auto& [k, v] : config.labels) {
            ann.set(k, v);
        }

        ann.set("org.opencontainers.image.os", config.os);
        ann.set("org.opencontainers.image.architecture", config.architecture);
        if (!config.variant.empty()) {
            ann.set("org.opencontainers.image.variant", config.variant);
        }

        if (!config.author.empty()) {
            ann.set("org.opencontainers.image.author", config.author);
        }

        if (!config.created.empty()) {
            ann.set("org.opencontainers.image.created", config.created);
        }

        if (!config.stopSignal.empty()) {
            ann.set("org.opencontainers.image.stopSignal", config.stopSignal);
        }

        auto joined = [](const std::vector<std::string>& v) {
            std::string s;
            for (const std::string& e : v) {
                s += (s.empty() ? "" : ",") + e;
            }

            return s;
        };

        if (!config.exposedPorts.empty()) {
            ann.set("org.opencontainers.image.exposedPorts", joined(config.exposedPorts));
        }

        if (!config.volumes.empty()) {
            ann.set("org.sbox.image.volumes", joined(config.volumes));
        }

        for (const auto& [k, v] : options.annotations) {
            ann.set(k, v);
        }

        out.set("annotations", std::move(ann));

        CJson lnx = CJson::object();
        CJson ns = CJson::array();
        std::vector<std::string> kinds = { "pid", "ipc", "uts", "mount", "cgroup" };
        if (!options.rootless) {
            kinds.insert(kinds.begin() + 1, "network");
        } else {
            kinds.push_back("user");
        }

        for (const std::string& k : kinds) {
            CJson n = CJson::object();
            n.set("type", k);
            ns.push(std::move(n));
        }

        lnx.set("namespaces", std::move(ns));
        if (options.rootless) {
            auto mapping = [](uint32_t host) {
                CJson arr = CJson::array();
                CJson m = CJson::object();
                m.set("containerID", 0);
                m.set("hostID", host);
                m.set("size", 1);
                arr.push(std::move(m));
                return arr;
            };

            lnx.set("uidMappings", mapping(::getuid()));
            lnx.set("gidMappings", mapping(::getgid()));
        } else {
            CJson devices = CJson::array();
            devices.push(deviceRule(false, nullptr, -1, -1, "rwm"));
            devices.push(deviceRule(true, "c", -1, -1, "m"));
            devices.push(deviceRule(true, "b", -1, -1, "m"));
            devices.push(deviceRule(true, "c", 1, 3, "rwm"));      // --> /dev/null
            devices.push(deviceRule(true, "c", 1, 8, "rwm"));      // --> /dev/random
            devices.push(deviceRule(true, "c", 1, 7, "rwm"));      // --> /dev/full
            devices.push(deviceRule(true, "c", 5, 0, "rwm"));      // --> /dev/tty
            devices.push(deviceRule(true, "c", 1, 5, "rwm"));      // --> /dev/zero
            devices.push(deviceRule(true, "c", 1, 9, "rwm"));      // --> /dev/urandom
            devices.push(deviceRule(true, "c", 136, -1, "rwm"));   // --> /dev/pts/*
            devices.push(deviceRule(true, "c", 5, 2, "rwm"));      // --> /dev/ptmx
            CJson res = CJson::object();
            res.set("devices", std::move(devices));
            lnx.set("resources", std::move(res));
        }

        lnx.set("maskedPaths", CJson::fromStrings({ "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore",
                                                      "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
                                                      "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
                                                      "/sys/firmware", "/sys/devices/virtual/powercap" }));
        lnx.set("readonlyPaths", CJson::fromStrings({ "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger" }));
        if (options.seccomp) {
            CJson profile;
            if (CJson::parse(DockerDefaultSeccompProfile(), profile) != SBOX_OK) {
                return -EINVAL;
            }

            std::string arch = config.architecture.empty() ? HostPlatform().architecture : SPlatform{ "linux", config.architecture }.normalized().architecture;
            CJson sec;
            r = SeccompProfileToOci(profile, arch, caps, sec);
            if (r != SBOX_OK) {
                return r;
            }

            lnx.set("seccomp", std::move(sec));
        }

        out.set("linux", std::move(lnx));
        return SBOX_OK;
    }

    /* Writes an OCI bundle for an image. */
    int32_t CreateBundle(CSnapshotter& snapshotter, const SImageInfo& image, const std::string& dir, const SBundleOptions& options,
                         ESnapshotMode mode, std::string* containerId, std::string* error) {
        int32_t r = CFile::makeDirs(dir, 0755);
        if (r != SBOX_OK) {
            if (error) {
                *error = "cannot create " + dir;
            }

            return r;
        }

        if (CFile::exists(CFile::join(dir, "config.json"))) {
            if (error) {
                *error = dir + " already holds a bundle (config.json exists)";
            }

            return -EEXIST;
        }

        std::string rootfs = CFile::join(dir, options.rootPath);
        r = CFile::makeDirs(rootfs, 0755);
        if (r != SBOX_OK) {
            return r;
        }

        SContainerInfo info;
        r = snapshotter.prepare(std::string(), image, mode, info, true, rootfs);
        if (r != SBOX_OK) {
            if (error) {
                *error = snapshotter.lastError();
            }

            return r;
        }

        if (containerId) {
            *containerId = info.id;
        }

        CJson spec;
        std::string why;
        r = GenerateRuntimeSpec(image.config, rootfs, options, spec, &why);
        if (r == SBOX_OK) {
            CJson ann = spec.get("annotations");
            ann.set("org.sbox.image.container", info.id);
            ann.set("org.sbox.image.id", image.id);
            if (!image.repoTags.empty()) {
                ann.set("org.opencontainers.image.ref.name", image.repoTags.front());
            }

            spec.set("annotations", std::move(ann));
            r = WriteJsonFile(CFile::join(dir, "config.json"), spec, true);
        }

        if (r != SBOX_OK) {
            if (error) {
                *error = why.empty() ? "cannot write config.json" : why;
            }

            snapshotter.remove(info.id);
            return r;
        }

        return SBOX_OK;
    }

}
}
