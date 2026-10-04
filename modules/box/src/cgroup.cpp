#include <sbox/box/cgroup.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include "devicefilter.hpp"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace sbox {

    namespace {

        struct ControllerName {
            const char* name;
            uint32_t bit;
        };

        const ControllerName CONTROLLERS[] = {
            { "cpu", ECGC_CPU }, { "cpuacct", ECGC_CPUACCT }, { "cpuset", ECGC_CPUSET },
            { "memory", ECGC_MEMORY }, { "pids", ECGC_PIDS }, { "io", ECGC_IO }, { "blkio", ECGC_IO },
            { "freezer", ECGC_FREEZER }, { "devices", ECGC_DEVICES }, { "hugetlb", ECGC_HUGETLB },
        };

        /**
         * Undoes the octal escapes of /proc/self/mountinfo (\040 for a space, ...).
         */
        std::string unescape(std::string_view s) {
            std::string out;
            out.reserve(s.size());

            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\\' && i + 3 < s.size() &&
                    s[i + 1] >= '0' && s[i + 1] <= '7') {
                    out.push_back(char((s[i + 1] - '0') * 64 + (s[i + 2] - '0') * 8 + (s[i + 3] - '0')));
                    i += 3;
                } else {
                    out.push_back(s[i]);
                }
            }

            return out;
        }

        std::vector<std::string_view> split(std::string_view s, char sep) {
            std::vector<std::string_view> out;
            size_t start = 0;

            while (start <= s.size()) {
                size_t end = s.find(sep, start);
                if (end == std::string_view::npos) {
                    end = s.size();
                }

                if (end > start) {
                    out.push_back(s.substr(start, end - start));
                }

                start = end + 1;
            }

            return out;
        }

        std::string trim(std::string s) {
            while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) {
                s.pop_back();
            }

            return s;
        }

        /**
         * Reads a small knob (trimmed); empty string on failure.
         */
        int32_t readKnob(const std::string& dir, const char* name, std::string& out) {
            int32_t rc = CFile::readAll(CFile::join(dir, name), out, 1 << 20);
            if (rc == SBOX_OK) {
                out = trim(std::move(out));
            }

            return rc;
        }

        int32_t writeKnob(const std::string& dir, const std::string& name, std::string_view value) {
            return CFile::writeSome(CFile::join(dir, name), value);
        }

        bool knobExists(const std::string& dir, const char* name) {
            return ::access(CFile::join(dir, name).c_str(), F_OK) == 0;
        }

        /**
         * Parses "key value" lines and returns the value of `key` (or `fallback`).
         */
        uint64_t keyed(const std::string& text, std::string_view key, uint64_t fallback = 0) {
            for (std::string_view line : CFile::splitLines(text)) {
                if (line.size() > key.size() && line.substr(0, key.size()) == key && line[key.size()] == ' ') {
                    return std::strtoull(std::string(line.substr(key.size() + 1)).c_str(), nullptr, 10);
                }
            }

            return fallback;
        }

        uint64_t number(const std::string& text) {
            return std::strtoull(text.c_str(), nullptr, 10);
        }

        /**
         * Validates and normalizes a relative cgroup path (no "..", no empty result).
         */
        int32_t normalize(const std::string& path, std::string& out) {
            std::string result;

            for (std::string_view part : split(path, '/')) {
                if (part == "." ) {
                    continue;
                }

                if (part == "..") {
                    return -EINVAL;
                }

                if (!result.empty()) {
                    result.push_back('/');
                }

                result.append(part);
            }

            if (result.empty()) {
                return -EINVAL;
            }

            out = std::move(result);
            return SBOX_OK;
        }

        std::string limitText(int64_t value, const char* unlimited) {
            return value < 0 ? std::string(unlimited) : std::to_string(value);
        }

        /**
         * Copies cpuset.cpus/mems from the parent when empty (a v1 cpuset cgroup cannot take
         * processes before both are set).
         */
        void inheritCpuset(const std::string& dir) {
            for (const char* knob : { "cpuset.cpus", "cpuset.mems" }) {
                std::string mine;
                if (readKnob(dir, knob, mine) == SBOX_OK && mine.empty()) {
                    std::string parentValue;
                    std::string parent = dir.substr(0, dir.rfind('/'));
                    if (readKnob(parent, knob, parentValue) == SBOX_OK) {
                        writeKnob(dir, knob, parentValue);
                    }
                }
            }
        }

        /**
         * Enables v2 controllers for the children of `dir` (each one separately, so one refusal
         * does not block the others).
         */
        void enableSubtree(const std::string& dir, uint32_t wanted) {
            std::string enabled;
            readKnob(dir, "cgroup.subtree_control", enabled);
            std::vector<std::string_view> have = split(enabled, ' ');

            for (const ControllerName& c : CONTROLLERS) {
                if (!(wanted & c.bit) || std::strcmp(c.name, "blkio") == 0 || std::strcmp(c.name, "cpuacct") == 0 ||
                    std::strcmp(c.name, "freezer") == 0 || std::strcmp(c.name, "devices") == 0) {
                    continue;
                }

                bool on = false;
                for (std::string_view h : have) {
                    on = on || h == c.name;
                }

                if (!on) {
                    writeKnob(dir, "cgroup.subtree_control", std::string("+") + c.name);
                }
            }
        }

        uint32_t parseControllerList(const std::string& text) {
            uint32_t bits = 0;
            for (std::string_view name : split(text, ' ')) {
                bits |= SCgroupSystem::controllerFromName(name);
            }

            return bits;
        }

        std::string throttleLine(const SCgroupThrottle& t) {
            return std::to_string(t.major) + ":" + std::to_string(t.minor);
        }

    }

    /* Maps a controller name to its bit. */
    uint32_t SCgroupSystem::controllerFromName(std::string_view name) noexcept {
        for (const ControllerName& c : CONTROLLERS) {
            if (name == c.name) {
                return c.bit;
            }
        }

        return ECGC_NONE;
    }

    /* Finds the v1 hierarchy of a controller. */
    std::string SCgroupSystem::v1MountOf(uint32_t controller) const {
        for (const auto& [bits, mount] : v1Mounts) {
            if (bits & controller) {
                return mount;
            }
        }

        return std::string();
    }

    /* Parses /proc/self/mountinfo and /proc/self/cgroup. */
    int32_t SCgroupSystem::detect(SCgroupSystem& out) {
        out = SCgroupSystem();

        std::string info;
        if (int32_t rc = CFile::readAll("/proc/self/mountinfo", info); rc != SBOX_OK) {
            return rc;
        }

        for (std::string_view line : CFile::splitLines(info)) {
            size_t dash = line.find(" - ");
            if (dash == std::string_view::npos) {
                continue;
            }

            std::vector<std::string_view> left = split(line.substr(0, dash), ' ');
            std::vector<std::string_view> right = split(line.substr(dash + 3), ' ');
            if (left.size() < 5 || right.size() < 3) {
                continue;
            }

            std::string mountPoint = unescape(left[4]);

            if (right[0] == "cgroup2") {
                if (out.unifiedMount.empty()) {
                    out.unifiedMount = mountPoint;
                }
            } else if (right[0] == "cgroup") {
                uint32_t bits = 0;
                for (std::string_view opt : split(right[2], ',')) {
                    bits |= controllerFromName(opt);
                }

                if (bits == 0) {
                    continue;   // --> name=systemd and other named hierarchies.
                }

                bool known = false;
                for (const auto& m : out.v1Mounts) {
                    known = known || m.first == bits;
                }

                if (!known) {
                    out.v1Mounts.emplace_back(bits, mountPoint);
                }
            }
        }

        if (!out.unifiedMount.empty()) {
            std::string ctl;
            if (readKnob(out.unifiedMount, "cgroup.controllers", ctl) == SBOX_OK) {
                out.v2Controllers = parseControllerList(ctl);
            }
        }

        if (out.unifiedMount.empty()) {
            out.layout = out.v1Mounts.empty() ? ECGL_NONE : ECGL_V1;
        } else {
            out.layout = out.v1Mounts.empty() ? ECGL_V2 : ECGL_HYBRID;
        }

        std::string self;
        if (CFile::readAll("/proc/self/cgroup", self) == SBOX_OK) {
            for (std::string_view line : CFile::splitLines(self)) {
                if (line.substr(0, 3) == "0::") {
                    out.selfV2Path = std::string(line.substr(3));
                }
            }
        }

        return SBOX_OK;
    }

    /* Returns true when nothing is set. */
    bool SCgroupResources::empty() const noexcept {
        return !memoryLimit && !memoryReservation && !memorySwap && !pidsLimit && !cpuShares && !cpuWeight &&
            !cpuQuota && !cpuPeriod && cpusetCpus.empty() && cpusetMems.empty() && !blkioWeight &&
            readBps.empty() && writeBps.empty() && readIops.empty() && writeIops.empty() && devices.empty() &&
            unified.empty();
    }

    /* Creates the cgroup in every hierarchy. */
    int32_t CCgroup::create(const std::string& path, CCgroup& out, uint32_t controllers) {
        CCgroup cg;
        if (int32_t rc = SCgroupSystem::detect(cg._system); rc != SBOX_OK) {
            return rc;
        }

        if (cg._system.layout == ECGL_NONE) {
            return -ENOENT;
        }

        if (int32_t rc = normalize(path, cg._path); rc != SBOX_OK) {
            return rc;
        }

        std::vector<std::string_view> parts = split(cg._path, '/');
        int32_t firstError = SBOX_OK;
        uint32_t v2Wanted = controllers & cg._system.v2Controllers;

        if (!cg._system.unifiedMount.empty()) {
            std::string dir = cg._system.unifiedMount;
            bool ok = true;

            for (std::string_view part : parts) {
                enableSubtree(dir, v2Wanted);
                dir = CFile::join(dir, part);

                if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
                    firstError = -errno;
                    ok = false;
                    break;
                }
            }

            if (ok) {
                cg._v2Fd.reset(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
                if (!cg._v2Fd.isValid()) {
                    firstError = -errno;
                } else {
                    cg._v2Dir = dir;
                    std::string ctl;
                    readKnob(dir, "cgroup.controllers", ctl);
                    cg._controllers |= parseControllerList(ctl);
                }
            }
        }

        // --> v1 hierarchies serve what v2 does not; the freezer always (for killAll).
        uint32_t v1Wanted = (controllers & ~cg._system.v2Controllers) | ECGC_FREEZER;
        if (controllers & ECGC_CPU) {
            v1Wanted |= ECGC_CPUACCT;
        }

        for (const auto& [bits, mount] : cg._system.v1Mounts) {
            if (!(bits & v1Wanted)) {
                continue;
            }

            std::string dir = mount;
            bool ok = true;

            for (std::string_view part : parts) {
                dir = CFile::join(dir, part);

                if (::mkdir(dir.c_str(), 0755) != 0) {
                    if (errno != EEXIST) {
                        if (firstError == SBOX_OK) {
                            firstError = -errno;
                        }

                        ok = false;
                        break;
                    }
                } else if (bits & ECGC_CPUSET) {
                    inheritCpuset(dir);
                }
            }

            if (ok) {
                if (bits & ECGC_CPUSET) {
                    inheritCpuset(dir);
                }

                cg._v1Dirs.emplace_back(bits, dir);
                cg._controllers |= bits;
            }
        }

        if (cg._v2Dir.empty() && cg._v1Dirs.empty()) {
            return firstError != SBOX_OK ? firstError : -ENOENT;
        }

        out = std::move(cg);
        return SBOX_OK;
    }

    /* Opens an existing cgroup. */
    int32_t CCgroup::open(const std::string& path, CCgroup& out) {
        CCgroup cg;
        if (int32_t rc = SCgroupSystem::detect(cg._system); rc != SBOX_OK) {
            return rc;
        }

        if (int32_t rc = normalize(path, cg._path); rc != SBOX_OK) {
            return rc;
        }

        if (!cg._system.unifiedMount.empty()) {
            std::string dir = CFile::join(cg._system.unifiedMount, cg._path);
            cg._v2Fd.reset(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (cg._v2Fd.isValid()) {
                cg._v2Dir = dir;
                std::string ctl;
                readKnob(dir, "cgroup.controllers", ctl);
                cg._controllers |= parseControllerList(ctl);
            }
        }

        for (const auto& [bits, mount] : cg._system.v1Mounts) {
            std::string dir = CFile::join(mount, cg._path);
            struct stat st{};
            if (::stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                cg._v1Dirs.emplace_back(bits, dir);
                cg._controllers |= bits;
            }
        }

        if (cg._v2Dir.empty() && cg._v1Dirs.empty()) {
            return -ENOENT;
        }

        out = std::move(cg);
        return SBOX_OK;
    }

    /* Picks the parent for new cgroups. */
    int32_t CCgroup::defaultParent(std::string& out) {
        if (::geteuid() == 0) {
            out = "sbox";
            return SBOX_OK;
        }

        SCgroupSystem sys;
        if (int32_t rc = SCgroupSystem::detect(sys); rc != SBOX_OK) {
            return rc;
        }

        if (sys.unifiedMount.empty() || sys.selfV2Path.empty()) {
            return -EACCES;
        }

        // --> Walk up from our own cgroup; keep the topmost directory we own and may write.
        std::string rel = sys.selfV2Path;
        std::string best;
        bool found = false;

        while (true) {
            std::string dir = sys.unifiedMount + (rel == "/" ? "" : rel);
            struct stat st{};

            bool owned = rel != "/" && ::stat(dir.c_str(), &st) == 0 && st.st_uid == ::geteuid() &&
                ::access(dir.c_str(), W_OK) == 0 &&
                ::access(CFile::join(dir, "cgroup.procs").c_str(), W_OK) == 0;

            if (owned) {
                best = rel;
                found = true;
            } else if (found) {
                break;
            }

            if (rel == "/" || rel.empty()) {
                break;
            }

            size_t slash = rel.rfind('/');
            rel = slash == 0 ? "/" : rel.substr(0, slash);
        }

        if (!found) {
            return -EACCES;
        }

        out = best.substr(1) + "/sbox";
        return SBOX_OK;
    }

    /* Writes the configured limits. */
    int32_t CCgroup::apply(const SCgroupResources& res, std::vector<std::string>* skipped) {
        int32_t firstError = SBOX_OK;

        auto note = [&](const char* what) {
            if (skipped) {
                skipped->push_back(what);
            }
        };

        auto check = [&](int32_t rc) {
            if (rc != SBOX_OK && firstError == SBOX_OK) {
                firstError = rc;
            }
        };

        auto v1Dir = [&](uint32_t bit) -> std::string {
            for (const auto& [bits, dir] : _v1Dirs) {
                if (bits & bit) {
                    return dir;
                }
            }

            return std::string();
        };

        bool v2Has = [&]() { return !_v2Dir.empty(); }();
        auto onV2 = [&](uint32_t bit) {
            return v2Has && (_system.v2Controllers & bit) && (_controllers & bit) && v1Dir(bit).empty();
        };

        // Memory.
        if (res.memoryLimit || res.memoryReservation || res.memorySwap) {
            if (onV2(ECGC_MEMORY)) {
                if (res.memoryLimit) {
                    check(writeKnob(_v2Dir, "memory.max", limitText(*res.memoryLimit, "max")));
                }

                if (res.memoryReservation) {
                    check(writeKnob(_v2Dir, "memory.low", limitText(*res.memoryReservation, "max")));
                }

                if (res.memorySwap) {
                    if (!knobExists(_v2Dir, "memory.swap.max")) {
                        note("memory.swap");
                    } else if (*res.memorySwap < 0) {
                        check(writeKnob(_v2Dir, "memory.swap.max", "max"));
                    } else {
                        // --> OCI's value is memory + swap; v2 limits swap alone.
                        int64_t mem = res.memoryLimit && *res.memoryLimit >= 0 ? *res.memoryLimit : 0;
                        int64_t swap = *res.memorySwap - mem;
                        check(writeKnob(_v2Dir, "memory.swap.max", std::to_string(swap < 0 ? 0 : swap)));
                    }
                }
            } else if (std::string dir = v1Dir(ECGC_MEMORY); !dir.empty()) {
                if (res.memoryReservation) {
                    check(writeKnob(dir, "memory.soft_limit_in_bytes", limitText(*res.memoryReservation, "-1")));
                }

                bool hasSwap = knobExists(dir, "memory.memsw.limit_in_bytes");
                if (res.memorySwap && !hasSwap) {
                    note("memory.swap");
                }

                if (res.memoryLimit) {
                    std::string limit = limitText(*res.memoryLimit, "-1");
                    int32_t rc = writeKnob(dir, "memory.limit_in_bytes", limit);

                    if (rc == -EINVAL && res.memorySwap && hasSwap) {
                        // --> memsw must stay >= limit: raise memsw first, then the limit.
                        check(writeKnob(dir, "memory.memsw.limit_in_bytes", limitText(*res.memorySwap, "-1")));
                        rc = writeKnob(dir, "memory.limit_in_bytes", limit);
                    }

                    check(rc);
                }

                if (res.memorySwap && hasSwap) {
                    check(writeKnob(dir, "memory.memsw.limit_in_bytes", limitText(*res.memorySwap, "-1")));
                }
            } else {
                note("memory");
            }
        }

        // Pids.
        if (res.pidsLimit) {
            std::string value = *res.pidsLimit <= 0 ? std::string("max") : std::to_string(*res.pidsLimit);

            if (onV2(ECGC_PIDS)) {
                check(writeKnob(_v2Dir, "pids.max", value));
            } else if (std::string dir = v1Dir(ECGC_PIDS); !dir.empty()) {
                check(writeKnob(dir, "pids.max", value));
            } else {
                note("pids");
            }
        }

        // CPU.
        if (res.cpuQuota || res.cpuPeriod || res.cpuShares || res.cpuWeight) {
            uint64_t period = res.cpuPeriod ? *res.cpuPeriod : 100000;

            if (onV2(ECGC_CPU)) {
                if (res.cpuQuota || res.cpuPeriod) {
                    std::string quota = res.cpuQuota && *res.cpuQuota > 0 ? std::to_string(*res.cpuQuota) : "max";
                    check(writeKnob(_v2Dir, "cpu.max", quota + " " + std::to_string(period)));
                }

                if (res.cpuWeight || res.cpuShares) {
                    uint64_t weight;
                    if (res.cpuWeight) {
                        weight = *res.cpuWeight;
                    } else {
                        // --> The conversion runc and crun use: [2, 262144] -> [1, 10000].
                        uint64_t shares = *res.cpuShares < 2 ? 2 : (*res.cpuShares > 262144 ? 262144 : *res.cpuShares);
                        weight = 1 + ((shares - 2) * 9999) / 262142;
                    }

                    check(writeKnob(_v2Dir, "cpu.weight", std::to_string(weight)));
                }
            } else if (std::string dir = v1Dir(ECGC_CPU); !dir.empty()) {
                if (res.cpuQuota || res.cpuPeriod) {
                    check(writeKnob(dir, "cpu.cfs_period_us", std::to_string(period)));
                    std::string quota = res.cpuQuota && *res.cpuQuota > 0 ? std::to_string(*res.cpuQuota) : "-1";
                    check(writeKnob(dir, "cpu.cfs_quota_us", quota));
                }

                if (res.cpuShares) {
                    check(writeKnob(dir, "cpu.shares", std::to_string(*res.cpuShares)));
                } else if (res.cpuWeight) {
                    // --> Inverse of the shares -> weight mapping.
                    uint64_t shares = 2 + ((*res.cpuWeight - 1) * 262142) / 9999;
                    check(writeKnob(dir, "cpu.shares", std::to_string(shares)));
                }
            } else {
                note("cpu");
            }
        }

        // Cpuset.
        if (!res.cpusetCpus.empty() || !res.cpusetMems.empty()) {
            std::string dir = onV2(ECGC_CPUSET) ? _v2Dir : v1Dir(ECGC_CPUSET);

            if (dir.empty()) {
                note("cpuset");
            } else {
                if (!res.cpusetCpus.empty()) {
                    check(writeKnob(dir, "cpuset.cpus", res.cpusetCpus));
                }

                if (!res.cpusetMems.empty()) {
                    check(writeKnob(dir, "cpuset.mems", res.cpusetMems));
                }
            }
        }

        // Block I/O.
        bool anyThrottle = !res.readBps.empty() || !res.writeBps.empty() || !res.readIops.empty() || !res.writeIops.empty();
        if (anyThrottle || res.blkioWeight) {
            if (onV2(ECGC_IO)) {
                auto put = [&](const std::vector<SCgroupThrottle>& list, const char* key) {
                    for (const SCgroupThrottle& t : list) {
                        check(writeKnob(_v2Dir, "io.max", throttleLine(t) + " " + key + "=" + std::to_string(t.rate)));
                    }
                };

                put(res.readBps, "rbps");
                put(res.writeBps, "wbps");
                put(res.readIops, "riops");
                put(res.writeIops, "wiops");

                if (res.blkioWeight) {
                    if (knobExists(_v2Dir, "io.bfq.weight")) {
                        check(writeKnob(_v2Dir, "io.bfq.weight", std::to_string(*res.blkioWeight)));
                    } else if (knobExists(_v2Dir, "io.weight")) {
                        // --> blkio weight [10, 1000] -> io.weight [1, 10000].
                        uint64_t w = 1 + ((uint64_t(*res.blkioWeight) - 10) * 9999) / 990;
                        check(writeKnob(_v2Dir, "io.weight", "default " + std::to_string(w)));
                    } else {
                        note("io.weight");
                    }
                }
            } else if (std::string dir = v1Dir(ECGC_IO); !dir.empty()) {
                auto put = [&](const std::vector<SCgroupThrottle>& list, const char* knob) {
                    for (const SCgroupThrottle& t : list) {
                        check(writeKnob(dir, knob, throttleLine(t) + " " + std::to_string(t.rate)));
                    }
                };

                put(res.readBps, "blkio.throttle.read_bps_device");
                put(res.writeBps, "blkio.throttle.write_bps_device");
                put(res.readIops, "blkio.throttle.read_iops_device");
                put(res.writeIops, "blkio.throttle.write_iops_device");

                if (res.blkioWeight) {
                    if (knobExists(dir, "blkio.weight")) {
                        check(writeKnob(dir, "blkio.weight", std::to_string(*res.blkioWeight)));
                    } else if (knobExists(dir, "blkio.bfq.weight")) {
                        check(writeKnob(dir, "blkio.bfq.weight", std::to_string(*res.blkioWeight)));
                    } else {
                        note("blkio.weight");
                    }
                }
            } else {
                note("io");
            }
        }

        // Devices.
        if (!res.devices.empty()) {
            if (!DeviceFilter::validate(res.devices)) {
                check(-EINVAL);
            } else if (std::string dir = v1Dir(ECGC_DEVICES); !dir.empty()) {
                for (const SCgroupDeviceRule& r : res.devices) {
                    std::string rule(1, r.type);
                    if (r.type != 'a') {
                        rule += " " + (r.major < 0 ? std::string("*") : std::to_string(r.major)) + ":" +
                            (r.minor < 0 ? std::string("*") : std::to_string(r.minor)) + " " + r.access;
                    }

                    check(writeKnob(dir, r.allow ? "devices.allow" : "devices.deny", rule));
                }
            } else if (_v2Fd.isValid()) {
                CFd program;
                int32_t rc = DeviceFilter::attach(_v2Fd.get(), res.devices, program);

                if (rc == SBOX_OK && _deviceProgram.isValid()) {
                    // --> Replace the previous filter: with ALLOW_MULTI both would apply.
                    union bpf_attr det;
                    std::memset(&det, 0, sizeof(det));
                    det.target_fd = uint32_t(_v2Fd.get());
                    det.attach_bpf_fd = uint32_t(_deviceProgram.get());
                    det.attach_type = BPF_CGROUP_DEVICE;
                    ::syscall(SYS_bpf, BPF_PROG_DETACH, &det, sizeof(det));
                }

                if (rc == SBOX_OK) {
                    _deviceProgram = std::move(program);
                } else if (rc == -EPERM || rc == -EACCES) {
                    note("devices");
                } else {
                    check(rc);
                }
            } else {
                note("devices");
            }
        }

        // Raw v2 knobs.
        for (const auto& [key, value] : res.unified) {
            if (key.find('/') != std::string::npos || key.empty() || key[0] == '.') {
                check(-EINVAL);
            } else if (_v2Dir.empty()) {
                note("unified");
            } else {
                check(writeKnob(_v2Dir, key, value));
            }
        }

        return firstError;
    }

    /* Reads statistics. */
    int32_t CCgroup::stats(SCgroupStats& out) const {
        out = SCgroupStats();
        std::string text;

        auto v1Dir = [&](uint32_t bit) -> std::string {
            for (const auto& [bits, dir] : _v1Dirs) {
                if (bits & bit) {
                    return dir;
                }
            }

            return std::string();
        };

        // Memory.
        if (std::string dir = v1Dir(ECGC_MEMORY); !dir.empty()) {
            if (readKnob(dir, "memory.usage_in_bytes", text) == SBOX_OK) {
                out.hasMemory = true;
                out.memoryCurrent = number(text);
            }

            if (readKnob(dir, "memory.max_usage_in_bytes", text) == SBOX_OK) {
                out.memoryPeak = number(text);
            }

            if (readKnob(dir, "memory.failcnt", text) == SBOX_OK) {
                out.oomEvents = number(text);
            }

            if (readKnob(dir, "memory.oom_control", text) == SBOX_OK) {
                out.oomKills = keyed(text, "oom_kill");
            }
        } else if (!_v2Dir.empty() && (_controllers & ECGC_MEMORY)) {
            if (readKnob(_v2Dir, "memory.current", text) == SBOX_OK) {
                out.hasMemory = true;
                out.memoryCurrent = number(text);
            }

            if (readKnob(_v2Dir, "memory.peak", text) == SBOX_OK) {
                out.memoryPeak = number(text);
            } else {
                // --> memory.peak appeared in 5.19; the current value is the best lower bound.
                out.memoryPeak = out.memoryCurrent;
            }

            if (readKnob(_v2Dir, "memory.events", text) == SBOX_OK) {
                out.oomEvents = keyed(text, "oom");
                out.oomKills = keyed(text, "oom_kill");
            }
        }

        // CPU: v1 cpuacct when mounted, else the v2 cpu.stat every v2 cgroup has.
        if (std::string dir = v1Dir(ECGC_CPUACCT); !dir.empty()) {
            if (readKnob(dir, "cpuacct.usage", text) == SBOX_OK) {
                out.hasCpu = true;
                out.cpuUsageUs = number(text) / 1000;

                if (readKnob(dir, "cpuacct.usage_user", text) == SBOX_OK) {
                    out.cpuUserUs = number(text) / 1000;
                }

                if (readKnob(dir, "cpuacct.usage_sys", text) == SBOX_OK) {
                    out.cpuSystemUs = number(text) / 1000;
                }
            }
        } else if (!_v2Dir.empty() && readKnob(_v2Dir, "cpu.stat", text) == SBOX_OK) {
            out.hasCpu = true;
            out.cpuUsageUs = keyed(text, "usage_usec");
            out.cpuUserUs = keyed(text, "user_usec");
            out.cpuSystemUs = keyed(text, "system_usec");
        }

        // Pids.
        std::string pidsDir = v1Dir(ECGC_PIDS);
        if (pidsDir.empty() && !_v2Dir.empty() && (_controllers & ECGC_PIDS)) {
            pidsDir = _v2Dir;
        }

        if (!pidsDir.empty() && readKnob(pidsDir, "pids.current", text) == SBOX_OK) {
            out.hasPids = true;
            out.pidsCurrent = number(text);
        }

        return SBOX_OK;
    }

    /* Moves a process into the cgroup. */
    int32_t CCgroup::addProcess(pid_t pid, bool v1Only) const {
        std::string text = std::to_string(pid);
        int32_t firstError = SBOX_OK;

        if (!v1Only && !_v2Dir.empty()) {
            firstError = writeKnob(_v2Dir, "cgroup.procs", text);
        }

        for (const auto& [bits, dir] : _v1Dirs) {
            int32_t rc = writeKnob(dir, "cgroup.procs", text);
            if (rc != SBOX_OK && firstError == SBOX_OK) {
                firstError = rc;
            }
        }

        return firstError;
    }

    /* Lists member processes. */
    int32_t CCgroup::processes(std::vector<pid_t>& out) const {
        out.clear();
        std::string dir = !_v2Dir.empty() ? _v2Dir : (_v1Dirs.empty() ? std::string() : _v1Dirs.front().second);
        if (dir.empty()) {
            return -ENOENT;
        }

        std::string text;
        if (int32_t rc = readKnob(dir, "cgroup.procs", text); rc != SBOX_OK) {
            return rc;
        }

        for (std::string_view line : CFile::splitLines(text)) {
            if (!line.empty()) {
                out.push_back(pid_t(std::strtol(std::string(line).c_str(), nullptr, 10)));
            }
        }

        return SBOX_OK;
    }

    /* Returns true while processes remain. */
    bool CCgroup::isPopulated() const {
        std::string text;

        if (!_v2Dir.empty() && readKnob(_v2Dir, "cgroup.events", text) == SBOX_OK) {
            return keyed(text, "populated") != 0;
        }

        for (const auto& [bits, dir] : _v1Dirs) {
            if (readKnob(dir, "cgroup.procs", text) == SBOX_OK && !text.empty()) {
                return true;
            }
        }

        return false;
    }

    /* Signals every member. */
    int32_t CCgroup::signalAll(int sig) const {
        if (sig == SIGKILL && !_v2Dir.empty() && knobExists(_v2Dir, "cgroup.kill")) {
            return writeKnob(_v2Dir, "cgroup.kill", "1");
        }

        // --> Without freezing, a forking process may slip through; repeat a few rounds.
        for (int round = 0; round < 4; ++round) {
            std::vector<pid_t> pids;
            if (int32_t rc = processes(pids); rc != SBOX_OK) {
                return rc;
            }

            if (pids.empty()) {
                break;
            }

            for (pid_t p : pids) {
                ::kill(p, sig);
            }
        }

        return SBOX_OK;
    }

    /* Freezes or thaws, waiting for the state change. */
    TTask<int32_t> CCgroup::freeze(bool frozen, int64_t timeoutMs) const {
        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;

        std::string freezerDir;
        for (const auto& [bits, dir] : _v1Dirs) {
            if (bits & ECGC_FREEZER) {
                freezerDir = dir;
            }
        }

        if (!_v2Dir.empty() && knobExists(_v2Dir, "cgroup.freeze") && freezerDir.empty()) {
            if (int32_t rc = writeKnob(_v2Dir, "cgroup.freeze", frozen ? "1" : "0"); rc != SBOX_OK) {
                co_return rc;
            }

            while (true) {
                std::string text;
                readKnob(_v2Dir, "cgroup.events", text);
                if ((keyed(text, "frozen") != 0) == frozen) {
                    co_return SBOX_OK;
                }

                if (CEventLoop::nowMs() >= deadline) {
                    co_return -ETIMEDOUT;
                }

                co_await loop->sleepFor(1);
            }
        }

        if (freezerDir.empty()) {
            co_return -ENOTSUP;
        }

        const char* want = frozen ? "FROZEN" : "THAWED";

        while (true) {
            // --> v1 may stay FREEZING while a task is busy; rewriting the state retries it.
            if (int32_t rc = writeKnob(freezerDir, "freezer.state", want); rc != SBOX_OK) {
                co_return rc;
            }

            std::string text;
            readKnob(freezerDir, "freezer.state", text);
            if (text == want) {
                co_return SBOX_OK;
            }

            if (CEventLoop::nowMs() >= deadline) {
                co_return -ETIMEDOUT;
            }

            co_await loop->sleepFor(1);
        }
    }

    /* Waits until empty. */
    TTask<int32_t> CCgroup::waitEmpty(int64_t timeoutMs) const {
        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        int64_t delay = 1;

        while (isPopulated()) {
            if (CEventLoop::nowMs() >= deadline) {
                co_return -ETIMEDOUT;
            }

            co_await loop->sleepFor(delay);
            delay = delay < 16 ? delay * 2 : 16;
        }

        co_return SBOX_OK;
    }

    /* Kills everything and waits until empty. */
    TTask<int32_t> CCgroup::killAll(int64_t timeoutMs) const {
        if (!_v2Dir.empty() && knobExists(_v2Dir, "cgroup.kill")) {
            if (int32_t rc = writeKnob(_v2Dir, "cgroup.kill", "1"); rc != SBOX_OK) {
                co_return rc;
            }
        } else {
            // --> Freeze, kill each member, thaw: nothing can fork between listing and killing.
            int32_t frozen = co_await freeze(true, timeoutMs);
            signalAll(SIGKILL);

            if (frozen == SBOX_OK) {
                co_await freeze(false, timeoutMs);
            }
        }

        co_return co_await waitEmpty(timeoutMs);
    }

    /* Removes the cgroup directories. */
    int32_t CCgroup::destroy() {
        int32_t firstError = SBOX_OK;

        auto remove = [&](const std::string& dir) {
            if (::rmdir(dir.c_str()) != 0 && errno != ENOENT && firstError == SBOX_OK) {
                firstError = -errno;
            }
        };

        _deviceProgram.reset();
        _v2Fd.reset();

        if (!_v2Dir.empty()) {
            remove(_v2Dir);
        }

        for (const auto& [bits, dir] : _v1Dirs) {
            remove(dir);
        }

        if (firstError == SBOX_OK) {
            _v2Dir.clear();
            _v1Dirs.clear();
            _path.clear();
            _controllers = ECGC_NONE;
        }

        return firstError;
    }

} // namespace sbox
