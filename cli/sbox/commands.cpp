// Lifecycle commands of sbox / sboxrun (runc's command set and output formats).
#include "cli.hpp"
#include <sbox/box/seccomp.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/oci/seccomp.hpp>
#include <sbox/oci/spec.hpp>
#include <sbox/version.hpp>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace sboxcli {

    namespace {

        /**
         * Prints text to standard output.
         */
        void print(const std::string& text) {
            std::fwrite(text.data(), 1, text.size(), stdout);
        }

        /**
         * Checks the positional argument count.
         */
        bool needId(const Flags& f, const std::string& cmd, std::string& id) {
            if (f.positional.empty()) {
                Fail("\"" + cmd + "\" requires a container id");
                return false;
            }

            id = f.positional[0];
            return true;
        }

        /**
         * Parses an unsigned decimal flag value.
         */
        bool parseUnsigned(const std::string& text, uint64_t& out) {
            if (text.empty()) {
                return false;
            }

            char* end = nullptr;
            errno = 0;
            unsigned long long v = std::strtoull(text.c_str(), &end, 10);
            if (errno != 0 || *end != '\0' || text[0] == '-') {
                return false;
            }

            out = v;
            return true;
        }

        /**
         * Parses a signed decimal flag value.
         */
        bool parseSigned(const std::string& text, int64_t& out) {
            if (text.empty()) {
                return false;
            }

            char* end = nullptr;
            errno = 0;
            long long v = std::strtoll(text.c_str(), &end, 10);
            if (errno != 0 || *end != '\0') {
                return false;
            }

            out = v;
            return true;
        }

        /**
         * Parses a byte size like docker/runc ("512m", "1G", "1024", "-1").
         */
        bool parseBytes(const std::string& text, int64_t& out) {
            if (text == "-1") {
                out = -1;
                return true;
            }

            std::string num = text;
            int64_t mult = 1;
            if (!num.empty()) {
                char unit = char(std::tolower(static_cast<unsigned char>(num.back())));
                if (unit == 'b' && num.size() > 1) {
                    num.pop_back();
                    unit = char(std::tolower(static_cast<unsigned char>(num.back())));
                }

                const std::pair<char, int64_t> units[] = { { 'k', 1LL << 10 }, { 'm', 1LL << 20 }, { 'g', 1LL << 30 }, { 't', 1LL << 40 } };
                for (const auto& [c, m] : units) {
                    if (unit == c) {
                        mult = m;
                        num.pop_back();
                    }
                }
            }

            uint64_t v = 0;
            if (!parseUnsigned(num, v)) {
                return false;
            }

            out = int64_t(v) * mult;
            return true;
        }

        /**
         * Returns the user name of a uid from /etc/passwd ("#uid" when unknown).
         */
        std::string userName(uint32_t uid) {
            std::string text;
            if (CFile::readAll("/etc/passwd", text) == SBOX_OK) {
                for (std::string_view line : CFile::splitLines(text)) {
                    size_t a = line.find(':');
                    size_t b = a == std::string_view::npos ? a : line.find(':', a + 1);
                    size_t c = b == std::string_view::npos ? b : line.find(':', b + 1);
                    if (c != std::string_view::npos && line.substr(b + 1, c - b - 1) == std::to_string(uid)) {
                        return std::string(line.substr(0, a));
                    }
                }
            }

            return "#" + std::to_string(uid);
        }

        /**
         * Formats rows like Go's tabwriter(minwidth 12, padding 3): every column but the last is
         * padded to the widest cell plus 3, at least 12.
         */
        std::string table(const std::vector<std::vector<std::string>>& rows) {
            std::vector<size_t> width;
            for (const auto& row : rows) {
                for (size_t i = 0; i + 1 < row.size(); ++i) {
                    if (width.size() <= i) {
                        width.push_back(0);
                    }

                    width[i] = std::max(width[i], std::max<size_t>(row[i].size() + 3, 12));
                }
            }

            std::string out;
            for (const auto& row : rows) {
                for (size_t i = 0; i < row.size(); ++i) {
                    out += row[i];
                    if (i + 1 < row.size()) {
                        out.append(width[i] - row[i].size(), ' ');
                    }
                }

                out += "\n";
            }

            return out;
        }

        /**
         * Common flags of create and run.
         */
        std::vector<FlagSpec> createFlags(bool run) {
            std::vector<FlagSpec> f = {
                { "bundle", 'b', true }, { "console-socket", 0, true }, { "pidfd-socket", 0, true }, { "pid-file", 0, true },
                { "no-pivot", 0, false }, { "no-new-keyring", 0, false }, { "preserve-fds", 0, true },
            };

            if (run) {
                f.push_back({ "detach", 'd', false });
                f.push_back({ "keep", 0, false });
                f.push_back({ "no-subreaper", 0, false });
            }

            return f;
        }

        /**
         * Fills create options from flags.
         */
        bool createOptions(const Flags& f, oci::SCreateOptions& o) {
            o.bundle = f.get("bundle", ".");
            o.consoleSocket = f.get("console-socket");
            o.pidFile = f.get("pid-file");
            o.noPivot = f.flag("no-pivot");
            o.noNewKeyring = f.flag("no-new-keyring");

            if (f.has("pidfd-socket")) {
                Log(oci::ELOG_WARNING, "--pidfd-socket is not supported and ignored");
            }

            if (f.has("preserve-fds")) {
                uint64_t n = 0;
                if (!parseUnsigned(f.get("preserve-fds"), n) || n > 1024) {
                    Fail("invalid --preserve-fds value");
                    return false;
                }

                o.preserveFds = uint32_t(n);
            }

            return true;
        }

        /**
         * Builds the stats event of runc's `events` ("type":"stats").
         */
        CJson statsEvent(const std::string& id, const SCgroupStats& s) {
            CJson data = CJson::object();

            CJson cpu = CJson::object();
            CJson usage = CJson::object();
            usage.set("total", s.cpuUsageUs * 1000);
            usage.set("kernel", s.cpuSystemUs * 1000);
            usage.set("user", s.cpuUserUs * 1000);
            cpu.set("usage", std::move(usage));
            cpu.set("throttling", CJson::object());
            data.set("cpu", std::move(cpu));

            CJson memory = CJson::object();
            CJson mu = CJson::object();
            mu.set("usage", s.memoryCurrent);
            mu.set("max", s.memoryPeak);
            mu.set("failcnt", s.oomEvents);
            memory.set("usage", std::move(mu));
            data.set("memory", std::move(memory));

            CJson pids = CJson::object();
            pids.set("current", s.pidsCurrent);
            data.set("pids", std::move(pids));
            data.set("blkio", CJson::object());

            CJson ev = CJson::object();
            ev.set("type", "stats");
            ev.set("id", id);
            ev.set("data", std::move(data));
            return ev;
        }

    }

    /* create */
    TTask<int> CmdCreate(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, createFlags(false), f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "create", id)) {
            co_return 1;
        }

        oci::SCreateOptions o;
        if (!createOptions(f, o)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.create(id, o) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* run */
    TTask<int> CmdRun(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, createFlags(true), f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "run", id)) {
            co_return 1;
        }

        oci::SCreateOptions o;
        if (!createOptions(f, o)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        bool detach = f.flag("detach");

        if (detach) {
            if (co_await rt.create(id, o) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            if (co_await rt.start(id) != SBOX_OK) {
                std::string msg = rt.lastError();
                co_await rt.remove(id, true);
                co_return Fail(msg);
            }

            co_return 0;
        }

        oci::CContainerProcess proc;
        if (co_await rt.create(id, o, &proc) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        oci::SSpec spec;
        co_await rt.config(id, spec);
        bool terminal = spec.process && spec.process->terminal && o.consoleSocket.empty();

        if (co_await rt.start(id) != SBOX_OK) {
            std::string msg = rt.lastError();
            co_await rt.remove(id, true);
            co_return Fail(msg);
        }

        int code = co_await Supervise(proc, terminal);

        if (!f.flag("keep")) {
            if (co_await rt.remove(id, true) != SBOX_OK) {
                Log(oci::ELOG_WARNING, rt.lastError());
            }
        }

        co_return code;
    }

    /* start */
    TTask<int> CmdStart(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, {}, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "start", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.start(id) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* state */
    TTask<int> CmdState(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, {}, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "state", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        oci::SState st;
        if (co_await rt.state(id, st) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        print(st.toJson().dump(true));
        co_return 0;
    }

    /* kill */
    TTask<int> CmdKill(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "all", 'a', false } }, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "kill", id)) {
            co_return 1;
        }

        int sig = SIGTERM;
        if (f.positional.size() > 1) {
            int32_t s = oci::ParseSignal(f.positional[1]);
            if (s < 0) {
                co_return Fail("unknown signal \"" + f.positional[1] + "\"");
            }

            sig = s;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.kill(id, sig, f.flag("all")) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* delete */
    TTask<int> CmdDelete(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "force", 'f', false } }, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "delete", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.remove(id, f.flag("force")) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* exec */
    TTask<int> CmdExec(const std::vector<std::string>& args, size_t start) {
        Flags f;
        std::string err = ParseFlags(args, start, {
            { "console-socket", 0, true }, { "pidfd-socket", 0, true }, { "cwd", 0, true }, { "env", 'e', true },
            { "tty", 't', false }, { "user", 'u', true }, { "additional-gids", 'g', true }, { "process", 'p', true },
            { "detach", 'd', false }, { "pid-file", 0, true }, { "process-label", 0, true }, { "apparmor", 0, true },
            { "no-new-privs", 0, false }, { "cap", 'c', true }, { "preserve-fds", 0, true }, { "cgroup", 0, true },
            { "ignore-paused", 0, false },
        }, f);

        if (!err.empty()) {
            co_return Fail(err);
        }

        std::string id;
        if (!needId(f, "exec", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        oci::SExecOptions o;
        o.consoleSocket = f.get("console-socket");
        o.pidFile = f.get("pid-file");
        o.detach = f.flag("detach");
        o.ignorePaused = f.flag("ignore-paused");

        if (f.has("preserve-fds")) {
            uint64_t n = 0;
            if (!parseUnsigned(f.get("preserve-fds"), n) || n > 1024) {
                co_return Fail("invalid --preserve-fds value");
            }

            o.preserveFds = uint32_t(n);
        }

        if (f.has("cgroup")) {
            Log(oci::ELOG_WARNING, "--cgroup is not supported; the process joins the container cgroup");
        }

        if (f.has("process-label") || f.has("apparmor")) {
            Log(oci::ELOG_WARNING, "--process-label/--apparmor are not enforced");
        }

        if (f.has("process")) {
            std::string text;
            if (int32_t rc = ReadInput(f.get("process"), text); rc != SBOX_OK) {
                co_return Fail("cannot read process file " + f.get("process") + ": " + std::strerror(-rc));
            }

            CJson doc;
            if (CJson::parse(text, doc) != SBOX_OK) {
                co_return Fail("invalid process JSON in " + f.get("process"));
            }

            std::vector<std::string> warnings;
            if (oci::ParseProcess(doc, o.process, err, &warnings) != SBOX_OK) {
                co_return Fail(err);
            }

            for (const std::string& w : warnings) {
                Log(oci::ELOG_WARNING, w);
            }
        } else {
            if (f.positional.size() < 2) {
                co_return Fail("exec: process args cannot be empty");
            }

            oci::SSpec spec;
            if (co_await rt.config(id, spec) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            // --> As runc: the container's process is the template, the flags override it.
            o.process = spec.process.value_or(oci::SProcessSpec());
            o.process.args.assign(f.positional.begin() + 1, f.positional.end());
            o.process.terminal = f.flag("tty");
            o.process.consoleSize.reset();

            if (f.has("cwd")) {
                o.process.cwd = f.get("cwd");
            }

            for (const std::string& e : f.all("env")) {
                o.process.env.push_back(e);
            }

            if (f.has("user")) {
                std::string u = f.get("user");
                size_t colon = u.find(':');
                uint64_t uid = 0, gid = 0;
                if (!parseUnsigned(u.substr(0, colon), uid) || (colon != std::string::npos && !parseUnsigned(u.substr(colon + 1), gid))) {
                    co_return Fail("invalid --user \"" + u + "\" (numeric uid[:gid] expected)");
                }

                o.process.user.uid = uint32_t(uid);
                if (colon != std::string::npos) {
                    o.process.user.gid = uint32_t(gid);
                }
            }

            for (const std::string& g : f.all("additional-gids")) {
                uint64_t gid = 0;
                if (!parseUnsigned(g, gid)) {
                    co_return Fail("invalid --additional-gids value \"" + g + "\"");
                }

                o.process.user.additionalGids.push_back(uint32_t(gid));
            }

            if (f.flag("no-new-privs")) {
                o.process.noNewPrivileges = true;
            }

            std::vector<std::string> caps = f.all("cap");
            if (!caps.empty()) {
                if (!o.process.capabilities) {
                    o.process.capabilities = oci::SCapabilitySets();
                }

                for (const std::string& c : caps) {
                    o.process.capabilities->bounding.push_back(c);
                    o.process.capabilities->effective.push_back(c);
                    o.process.capabilities->permitted.push_back(c);
                }
            }
        }

        if (o.detach) {
            if (co_await rt.exec(id, o) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            co_return 0;
        }

        oci::CContainerProcess proc;
        if (co_await rt.exec(id, o, &proc) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return co_await Supervise(proc, o.process.terminal && o.consoleSocket.empty());
    }

    /* ps */
    TTask<int> CmdPs(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "format", 'f', true } }, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "ps", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        std::vector<pid_t> pids;
        if (co_await rt.processes(id, pids) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        std::string format = f.get("format", "table");
        if (format == "json") {
            CJson arr = CJson::array();
            for (pid_t p : pids) {
                arr.push(int64_t(p));
            }

            print(arr.dump() + "\n");
            co_return 0;
        }

        if (format != "table") {
            co_return Fail("invalid format option");
        }

        std::vector<std::string> options(f.positional.begin() + 1, f.positional.end());
        if (options.empty()) {
            options.push_back("-ef");
        }

        co_return co_await PrintPsTable(pids, options);
    }

    /* pause */
    TTask<int> CmdPause(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, {}, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "pause", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.pause(id) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* resume */
    TTask<int> CmdResume(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, {}, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "resume", id)) {
            co_return 1;
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.resume(id) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* update */
    TTask<int> CmdUpdate(const std::vector<std::string>& args, size_t start) {
        Flags f;
        std::string err = ParseFlags(args, start, {
            { "resources", 'r', true }, { "blkio-weight", 0, true }, { "cpu-period", 0, true }, { "cpu-quota", 0, true },
            { "cpu-share", 0, true }, { "cpu-rt-period", 0, true }, { "cpu-rt-runtime", 0, true }, { "cpuset-cpus", 0, true },
            { "cpuset-mems", 0, true }, { "cpu-idle", 0, true }, { "kernel-memory", 0, true }, { "kernel-memory-tcp", 0, true },
            { "memory", 0, true }, { "memory-reservation", 0, true }, { "memory-swap", 0, true }, { "pids-limit", 0, true },
            { "l3-cache-schema", 0, true }, { "mem-bw-schema", 0, true },
        }, f);

        if (!err.empty()) {
            co_return Fail(err);
        }

        std::string id;
        if (!needId(f, "update", id)) {
            co_return 1;
        }

        oci::SResourcesSpec res;
        if (f.has("resources")) {
            std::string text;
            if (int32_t rc = ReadInput(f.get("resources"), text); rc != SBOX_OK) {
                co_return Fail("cannot read resources: " + std::string(std::strerror(-rc)));
            }

            CJson doc;
            if (CJson::parse(text, doc) != SBOX_OK) {
                co_return Fail("invalid resources JSON");
            }

            std::vector<std::string> warnings;
            if (oci::ParseResources(doc, res, err, &warnings, "resources") != SBOX_OK) {
                co_return Fail(err);
            }
        }

        auto bytes = [&](const char* name, std::optional<int64_t>& slot) -> bool {
            if (!f.has(name)) {
                return true;
            }

            int64_t v = 0;
            if (!parseBytes(f.get(name), v)) {
                Fail(std::string("invalid value for --") + name + ": " + f.get(name));
                return false;
            }

            slot = v;
            return true;
        };

        oci::SMemorySpec mem = res.memory.value_or(oci::SMemorySpec());
        if (!bytes("memory", mem.limit) || !bytes("memory-reservation", mem.reservation) || !bytes("memory-swap", mem.swap) ||
            !bytes("kernel-memory", mem.kernel) || !bytes("kernel-memory-tcp", mem.kernelTCP)) {
            co_return 1;
        }

        if (mem.limit || mem.reservation || mem.swap || mem.kernel || mem.kernelTCP) {
            res.memory = mem;
        }

        oci::SCpuSpec cpu = res.cpu.value_or(oci::SCpuSpec());
        bool cpuSet = res.cpu.has_value();
        auto unsignedFlag = [&](const char* name, std::optional<uint64_t>& slot) -> bool {
            if (!f.has(name)) {
                return true;
            }

            uint64_t v = 0;
            if (!parseUnsigned(f.get(name), v)) {
                Fail(std::string("invalid value for --") + name + ": " + f.get(name));
                return false;
            }

            slot = v;
            cpuSet = true;
            return true;
        };

        auto signedFlag = [&](const char* name, std::optional<int64_t>& slot) -> bool {
            if (!f.has(name)) {
                return true;
            }

            int64_t v = 0;
            if (!parseSigned(f.get(name), v)) {
                Fail(std::string("invalid value for --") + name + ": " + f.get(name));
                return false;
            }

            slot = v;
            cpuSet = true;
            return true;
        };

        if (!unsignedFlag("cpu-period", cpu.period) || !signedFlag("cpu-quota", cpu.quota) || !unsignedFlag("cpu-share", cpu.shares) ||
            !unsignedFlag("cpu-rt-period", cpu.realtimePeriod) || !signedFlag("cpu-rt-runtime", cpu.realtimeRuntime) ||
            !signedFlag("cpu-idle", cpu.idle)) {
            co_return 1;
        }

        if (f.has("cpuset-cpus")) {
            cpu.cpus = f.get("cpuset-cpus");
            cpuSet = true;
        }

        if (f.has("cpuset-mems")) {
            cpu.mems = f.get("cpuset-mems");
            cpuSet = true;
        }

        if (cpuSet) {
            res.cpu = cpu;
        }

        if (f.has("pids-limit")) {
            int64_t v = 0;
            if (!parseSigned(f.get("pids-limit"), v)) {
                co_return Fail("invalid value for --pids-limit: " + f.get("pids-limit"));
            }

            res.pids = oci::SPidsSpec{ v };
        }

        if (f.has("blkio-weight")) {
            uint64_t v = 0;
            if (!parseUnsigned(f.get("blkio-weight"), v) || v > 1000) {
                co_return Fail("invalid value for --blkio-weight: " + f.get("blkio-weight"));
            }

            oci::SBlockIoSpec b = res.blockIO.value_or(oci::SBlockIoSpec());
            b.weight = uint16_t(v);
            res.blockIO = b;
        }

        if (f.has("l3-cache-schema") || f.has("mem-bw-schema")) {
            Log(oci::ELOG_WARNING, "Intel RDT is not supported; --l3-cache-schema/--mem-bw-schema ignored");
        }

        oci::CRuntime rt(RuntimeOptions());
        if (co_await rt.update(id, res) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        co_return 0;
    }

    /* list */
    TTask<int> CmdList(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "format", 'f', true }, { "quiet", 'q', false } }, f); !e.empty()) {
            co_return Fail(e);
        }

        oci::CRuntime rt(RuntimeOptions());
        std::vector<oci::SState> all;
        if (co_await rt.list(all) != SBOX_OK) {
            co_return Fail(rt.lastError());
        }

        for (oci::SState& s : all) {
            if (!s.owner.empty()) {
                s.owner = userName(uint32_t(std::strtoul(s.owner.c_str(), nullptr, 10)));
            }
        }

        if (f.flag("quiet")) {
            for (const oci::SState& s : all) {
                print(s.id + "\n");
            }

            co_return 0;
        }

        std::string format = f.get("format", "table");
        if (format == "json") {
            CJson arr = CJson::array();
            for (const oci::SState& s : all) {
                arr.push(s.toJson());
            }

            print(arr.dump() + "\n");
            co_return 0;
        }

        if (format != "table") {
            co_return Fail("invalid format option");
        }

        std::vector<std::vector<std::string>> rows = { { "ID", "PID", "STATUS", "BUNDLE", "CREATED", "OWNER" } };
        for (const oci::SState& s : all) {
            rows.push_back({ s.id, std::to_string(s.pid), oci::StatusName(s.status), s.bundle, s.created, s.owner });
        }

        print(table(rows));
        co_return 0;
    }

    /* events */
    TTask<int> CmdEvents(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "stats", 0, false }, { "interval", 0, true } }, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string id;
        if (!needId(f, "events", id)) {
            co_return 1;
        }

        int64_t intervalMs = 5000;
        if (f.has("interval")) {
            std::string v = f.get("interval");
            int64_t mult = 1000;
            if (v.size() > 2 && v.compare(v.size() - 2, 2, "ms") == 0) {
                mult = 1;
                v.resize(v.size() - 2);
            } else if (!v.empty() && v.back() == 's') {
                v.pop_back();
            } else if (!v.empty() && v.back() == 'm') {
                mult = 60000;
                v.pop_back();
            }

            int64_t n = 0;
            if (!parseSigned(v, n) || n <= 0) {
                co_return Fail("invalid --interval value");
            }

            intervalMs = n * mult;
        }

        oci::CRuntime rt(RuntimeOptions());
        SCgroupStats stats;
        if (f.flag("stats")) {
            if (co_await rt.stats(id, stats) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            print(statsEvent(id, stats).dump() + "\n");
            co_return 0;
        }

        // --> Streaming: a stats event every interval, an "oom" event when the OOM killer acted,
        // until the container stops.
        uint64_t lastOom = 0;
        bool first = true;
        while (true) {
            oci::SState st;
            if (co_await rt.state(id, st) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            if (st.status == oci::ECST_STOPPED) {
                co_return 0;
            }

            if (co_await rt.stats(id, stats) != SBOX_OK) {
                co_return Fail(rt.lastError());
            }

            if (!first && stats.oomKills > lastOom) {
                CJson ev = CJson::object();
                ev.set("type", "oom");
                ev.set("id", id);
                print(ev.dump() + "\n");
            }

            lastOom = stats.oomKills;
            first = false;
            print(statsEvent(id, stats).dump() + "\n");
            std::fflush(stdout);
            co_await CEventLoop::current()->sleepFor(intervalMs);
        }
    }

    /* features */
    TTask<int> CmdFeatures(const std::vector<std::string>& args, size_t start) {
        (void) args;
        (void) start;

        CJson o = CJson::object();
        o.set("ociVersionMin", oci::OCI_VERSION_MIN);
        o.set("ociVersionMax", oci::OCI_VERSION);
        o.set("hooks", CJson::fromStrings({ "prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop" }));
        o.set("mountOptions", CJson::fromStrings({
            "async", "atime", "bind", "defaults", "dev", "diratime", "dirsync", "exec", "lazytime", "loud", "mand",
            "noatime", "nodev", "nodiratime", "noexec", "nolazytime", "nomand", "norelatime", "nostrictatime",
            "nosuid", "nosymfollow", "private", "rbind", "relatime", "remount", "ro", "rprivate", "rro", "rshared",
            "rslave", "runbindable", "rw", "shared", "silent", "slave", "strictatime", "suid", "symfollow", "sync",
            "unbindable" }));

        CJson lx = CJson::object();
        lx.set("namespaces", CJson::fromStrings({ "cgroup", "ipc", "mount", "network", "pid", "time", "user", "uts" }));

        CJson caps = CJson::array();
        int32_t last = CapabilityLast();
        for (int32_t c = 0; c <= last; ++c) {
            std::string name = oci::CapabilityName(c);
            if (!name.empty()) {
                caps.push(name);
            }
        }

        lx.set("capabilities", std::move(caps));

        CJson cg = CJson::object();
        cg.set("v1", true);
        cg.set("v2", true);
        cg.set("systemd", false);
        cg.set("systemdUser", false);
        cg.set("rdma", false);
        lx.set("cgroup", std::move(cg));

        CJson sc = CJson::object();
        sc.set("enabled", true);
        sc.set("actions", CJson::fromStrings({ "SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS",
                                               "SCMP_ACT_KILL_THREAD", "SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_TRAP" }));
        sc.set("operators", CJson::fromStrings({ "SCMP_CMP_EQ", "SCMP_CMP_GE", "SCMP_CMP_GT", "SCMP_CMP_LE", "SCMP_CMP_LT",
                                                 "SCMP_CMP_MASKED_EQ", "SCMP_CMP_NE" }));
        sc.set("archs", CJson::fromStrings({ "SCMP_ARCH_AARCH64", "SCMP_ARCH_X32", "SCMP_ARCH_X86", "SCMP_ARCH_X86_64" }));
        sc.set("knownFlags", CJson::fromStrings({ "SECCOMP_FILTER_FLAG_TSYNC", "SECCOMP_FILTER_FLAG_SPEC_ALLOW", "SECCOMP_FILTER_FLAG_LOG" }));
        sc.set("supportedFlags", CJson::fromStrings({ "SECCOMP_FILTER_FLAG_TSYNC", "SECCOMP_FILTER_FLAG_SPEC_ALLOW", "SECCOMP_FILTER_FLAG_LOG" }));
        lx.set("seccomp", std::move(sc));

        CJson disabled = CJson::object();
        disabled.set("enabled", false);
        lx.set("apparmor", disabled);
        lx.set("selinux", disabled);
        lx.set("intelRdt", disabled);

        CJson me = CJson::object();
        me.set("idmap", disabled);
        lx.set("mountExtensions", std::move(me));
        o.set("linux", std::move(lx));

        CJson ann = CJson::object();
        ann.set("io.github.jay94ks.libsbox.version", std::to_string(HEADER_VERSION.major) + "." + std::to_string(HEADER_VERSION.minor) +
                "." + std::to_string(HEADER_VERSION.patch));
        o.set("annotations", std::move(ann));

        print(o.dump(true) + "\n");
        co_return 0;
    }

    /* spec */
    TTask<int> CmdSpec(const std::vector<std::string>& args, size_t start) {
        Flags f;
        if (std::string e = ParseFlags(args, start, { { "bundle", 'b', true }, { "rootless", 0, false } }, f); !e.empty()) {
            co_return Fail(e);
        }

        std::string bundle = f.get("bundle", ".");
        std::string path = CFile::join(bundle, "config.json");
        if (CFile::exists(path)) {
            co_return Fail("File " + path + " exists. Remove it first");
        }

        oci::SSpec spec = oci::DefaultSpec(f.flag("rootless"), uint32_t(::geteuid()), uint32_t(::getegid()));
        if (int32_t rc = CFile::writeAtomic(path, oci::SpecToJson(spec).dump(true) + "\n", 0666 & ~0022); rc != SBOX_OK) {
            co_return Fail("cannot write " + path + ": " + std::strerror(-rc));
        }

        co_return 0;
    }

}
