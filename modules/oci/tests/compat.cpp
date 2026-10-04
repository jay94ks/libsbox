#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "clitest.hpp"
#include <sbox/box/cgroup.hpp>
#include <sbox/oci/seccomp.hpp>
#include <sbox/oci/spec.hpp>
#include <sys/ioctl.h>
#include <poll.h>
#include <termios.h>

// Replays the command lines dockerd's containerd shim (io.containerd.runc.v2 through go-runc)
// sends to a runc-compatible runtime, against `sboxrun`, and checks behaviour, output formats
// and exit codes.

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

namespace {

    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root; skipping container test");
            return false;
        }

        return true;
    }

    /**
     * A configuration shaped like the one dockerd generates for `docker run busybox sleep`:
     * Docker's capability set and seccomp profile, its masked/read-only paths and mounts, a
     * cgroupfs cgroupsPath, annotations and a prestart hook in place of libnetwork-setkey.
     */
    SSpec dockerLikeSpec(const std::string& id, const std::string& cgroupParent, const std::string& hookLog) {
        SSpec s = DefaultSpec(false, 0, 0, id.substr(0, 12));
        s.process->terminal = false;
        s.process->args = { "sleep", "1000" };
        s.process->env = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME=" + id.substr(0, 12) };
        s.process->rlimits.clear();
        s.process->noNewPrivileges = false;
        s.process->oomScoreAdj = 0;
        std::vector<std::string> caps = DockerDefaultCapabilities();
        s.process->capabilities = SCapabilitySets{ caps, caps, {}, caps, {} };
        s.root->readonly = false;

        s.mounts = {
            { "/proc", "proc", "proc", { "nosuid", "noexec", "nodev" }, {}, {} },
            { "/dev", "tmpfs", "tmpfs", { "nosuid", "strictatime", "mode=755", "size=65536k" }, {}, {} },
            { "/dev/pts", "devpts", "devpts", { "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5" }, {}, {} },
            { "/sys", "sysfs", "sysfs", { "nosuid", "noexec", "nodev", "ro" }, {}, {} },
            { "/sys/fs/cgroup", "cgroup", "cgroup", { "ro", "nosuid", "noexec", "nodev" }, {}, {} },
            { "/dev/mqueue", "mqueue", "mqueue", { "nosuid", "noexec", "nodev" }, {}, {} },
            { "/dev/shm", "tmpfs", "shm", { "nosuid", "noexec", "nodev", "mode=1777", "size=67108864" }, {}, {} },
        };

        s.linux_->cgroupsPath = "/" + cgroupParent + "/" + id;
        s.linux_->sysctl = { { "net.ipv4.ip_unprivileged_port_start", "0" }, { "net.ipv4.ping_group_range", "0 2147483647" } };
        s.linux_->maskedPaths = { "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                                  "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware",
                                  "/sys/devices/virtual/powercap" };
        s.linux_->readonlyPaths = { "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger" };
        s.linux_->namespaces = { { "mount", "" }, { "network", "" }, { "uts", "" }, { "pid", "" }, { "ipc", "" }, { "cgroup", "" } };
        s.linux_->resources->devices = { { false, "", std::nullopt, std::nullopt, "rwm" } };
        s.linux_->resources->blockIO = SBlockIoSpec();
        s.annotations = { { "com.example.compat", "yes" } };

        std::string text;
        REQUIRE(CFile::readAll(dataFile("docker-default-seccomp.json"), text) == SBOX_OK);
        CJson profile;
        REQUIRE(CJson::parse(text, profile) == SBOX_OK);
        SSeccompSpec seccomp;
        std::string err;
        REQUIRE(SeccompSpecFromDockerProfile(profile, SDockerSeccompContext::host(caps), seccomp, err) == SBOX_OK);
        s.linux_->seccomp = seccomp;

        SHooks hooks;
        SHook setkey;
        setkey.path = "/bin/sh";
        setkey.args = { "libnetwork-setkey", "-c", "cat > " + hookLog };
        hooks.prestart.push_back(setkey);
        s.hooks = hooks;
        return s;
    }

    /**
     * Removes a cgroup parent left by the test from every hierarchy.
     */
    void removeCgroup(const std::string& path) {
        CCgroup cg;
        if (CCgroup::open(path, cg) == SBOX_OK) {
            cg.destroy();
        }
    }

    std::string slurp(const std::string& path) {
        std::string text;
        CFile::readAll(path, text);
        return text;
    }

}

TEST_CASE("dockerd/containerd command lines against sboxrun") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    std::string root = tmp / "runtime-runc/moby";
    CFile::makeDirs(bundle, 0755);
    REQUIRE(makeRootfs(bundle + "/rootfs"));

    std::string id = "c0ffee" + randomSuffix() + randomSuffix();
    std::string cgroupParent = "sboxcompat-" + randomSuffix();
    REQUIRE(writeSpec(bundle, dockerLikeSpec(id, cgroupParent, tmp / "setkey.json")));

    std::string log = bundle + "/log.json";
    std::vector<std::string> g = { "--root", root, "--log", log, "--log-format", "json" };
    std::string bin = tool("sboxrun");
    auto run = [&](std::vector<std::string> args, const std::string& input = std::string()) {
        std::vector<std::string> all = g;
        all.insert(all.end(), args.begin(), args.end());
        return runTool(tmp.path, bin, all, input);
    };

    // create --bundle <dir> --pid-file <dir>/init.pid <id>
    ToolResult r = run({ "create", "--bundle", bundle, "--pid-file", bundle + "/init.pid", id });
    REQUIRE_MESSAGE(r.code == 0, r.err << slurp(log));
    std::string initPid = slurp(bundle + "/init.pid");
    CHECK(std::atoi(initPid.c_str()) > 0);

    // --> The prestart hook got the state on stdin, with the pid (libnetwork needs it).
    CJson hookState = parseJson(slurp(tmp / "setkey.json"));
    CHECK(hookState.get("id").asString() == id);
    CHECK(hookState.get("pid").asInt() == std::atoi(initPid.c_str()));
    CHECK(hookState.get("bundle").asString() == bundle);
    CHECK(hookState.get("annotations").get("com.example.compat").asString() == "yes");

    // state <id>
    r = run({ "state", id });
    REQUIRE(r.code == 0);
    CJson st = parseJson(r.out);
    CHECK(st.get("status").asString() == "created");
    CHECK(st.get("pid").asInt() == std::atoi(initPid.c_str()));
    for (const char* key : { "ociVersion", "id", "pid", "status", "bundle", "rootfs", "created", "owner", "annotations" }) {
        CHECK_MESSAGE(st.find(key) != nullptr, key);
    }

    // start <id>
    r = run({ "start", id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    CHECK(parseJson(run({ "state", id }).out).get("status").asString() == "running");

    // exec --process <file> --detach --pid-file <file> <id>
    CJson process = CJson::object();
    process.set("terminal", false);
    CJson user = CJson::object();
    user.set("uid", 0);
    user.set("gid", 0);
    process.set("user", user);
    process.set("args", CJson::fromStrings({ "sleep", "777" }));
    process.set("env", CJson::fromStrings({ "PATH=/bin" }));
    process.set("cwd", "/");
    CJson caps = CJson::object();
    caps.set("bounding", CJson::fromStrings(DockerDefaultCapabilities()));
    caps.set("effective", CJson::fromStrings(DockerDefaultCapabilities()));
    caps.set("permitted", CJson::fromStrings(DockerDefaultCapabilities()));
    process.set("capabilities", caps);
    REQUIRE(CFile::writeAtomic(tmp / "process.json", process.dump(), 0600) == SBOX_OK);

    r = run({ "exec", "--process", tmp / "process.json", "--detach", "--pid-file", tmp / "exec.pid", id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    int execPid = std::atoi(slurp(tmp / "exec.pid").c_str());
    CHECK(execPid > 0);
    CHECK(capture("readlink /proc/" + std::to_string(execPid) + "/ns/pid") ==
          capture("readlink /proc/" + initPid + "/ns/pid"));

    // ps --format json <id>
    r = run({ "ps", "--format", "json", id });
    REQUIRE(r.code == 0);
    CJson pids = parseJson(r.out);
    bool sawInit = false, sawExec = false;
    for (size_t i = 0; i < pids.size(); ++i) {
        sawInit = sawInit || pids.at(i).asInt() == std::atoi(initPid.c_str());
        sawExec = sawExec || pids.at(i).asInt() == execPid;
    }

    CHECK(sawInit);
    CHECK(sawExec);

    // update --resources - <id>
    r = run({ "update", "--resources", "-", id }, R"({"memory":{"limit":50331648},"pids":{"limit":40},"cpu":{"shares":512}})");
    REQUIRE_MESSAGE(r.code == 0, r.err);
    CCgroup cg;
    REQUIRE(CCgroup::open(cgroupParent + "/" + id, cg) == SBOX_OK);
    for (const auto& [bits, dir] : cg.v1Dirs()) {
        if (bits & ECGC_MEMORY) {
            CHECK(slurp(dir + "/memory.limit_in_bytes") == "50331648\n");
        }

        if (bits & ECGC_PIDS) {
            CHECK(slurp(dir + "/pids.max") == "40\n");
        }
    }

    // pause / resume
    CHECK(run({ "pause", id }).code == 0);
    CHECK(parseJson(run({ "state", id }).out).get("status").asString() == "paused");
    CHECK(run({ "resume", id }).code == 0);
    CHECK(parseJson(run({ "state", id }).out).get("status").asString() == "running");

    // events --stats <id>
    r = run({ "events", "--stats", id });
    CHECK(r.code == 0);
    CHECK(parseJson(r.out).get("type").asString() == "stats");

    // kill <id> 15: a pid 1 without a handler ignores SIGTERM, like under runc.
    CHECK(run({ "kill", id, "15" }).code == 0);
    // kill --all <id> 9
    CHECK(run({ "kill", "--all", id, "9" }).code == 0);
    CHECK(waitToolStatus(tmp.path, bin, g, id, "stopped") == "stopped");
    CHECK(::kill(execPid, 0) != 0);

    // delete <id>; delete again is "does not exist" in the JSON log (containerd matches it).
    r = run({ "delete", id });
    CHECK_MESSAGE(r.code == 0, r.err);
    r = run({ "delete", id });
    CHECK(r.code == 1);
    CHECK(r.err == "container does not exist\n");
    CJson last = lastLogLine(log);
    CHECK(last.get("level").asString() == "error");
    CHECK(last.get("msg").asString() == "container does not exist");
    CHECK(!last.get("time").asString().empty());

    // --> Every log line is JSON.
    std::string logText = slurp(log);
    for (std::string_view line : CFile::splitLines(logText)) {
        CHECK_MESSAGE(parseJson(std::string(line)).isObject(), line);
    }

    CHECK(CCgroup::open(cgroupParent + "/" + id, cg) == -ENOENT);
    removeCgroup(cgroupParent);
}

TEST_CASE("containerd's terminal flow: create --console-socket, exec --console-socket, delete --force") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    std::string root = tmp / "state";
    CFile::makeDirs(bundle, 0755);
    REQUIRE(makeRootfs(bundle + "/rootfs"));

    SSpec spec = testSpec({ "sh" });
    spec.process->terminal = true;
    REQUIRE(writeSpec(bundle, spec));

    std::string id = "tty-" + randomSuffix();
    std::string sock = tmp / "pty.sock";
    int listenFd = listenUnix(sock);
    REQUIRE(listenFd >= 0);

    std::vector<std::string> g = { "--root", root, "--log", bundle + "/log.json", "--log-format", "json" };
    std::string bin = tool("sboxrun");
    auto run = [&](std::vector<std::string> args) {
        std::vector<std::string> all = g;
        all.insert(all.end(), args.begin(), args.end());
        return runTool(tmp.path, bin, all);
    };

    ToolResult r = run({ "create", "--bundle", bundle, "--pid-file", bundle + "/init.pid", "--console-socket", sock, id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    int master = receiveFd(listenFd);
    REQUIRE(master >= 0);

    REQUIRE(run({ "start", id }).code == 0);

    // --> The shell reads commands from the pty.
    std::string cmd = "echo $((6*7))-answer\n";
    REQUIRE(::write(master, cmd.data(), cmd.size()) == ssize_t(cmd.size()));
    std::string seen;
    for (int i = 0; i < 200 && seen.find("42-answer") == std::string::npos; ++i) {
        char buf[512];
        struct pollfd pfd{ master, POLLIN, 0 };
        if (::poll(&pfd, 1, 50) > 0) {
            ssize_t n = ::read(master, buf, sizeof(buf));
            if (n > 0) {
                seen.append(buf, size_t(n));
            }
        }
    }

    CHECK_MESSAGE(seen.find("42-answer") != std::string::npos, seen);

    // exec --process with a terminal and its own console socket.
    CJson process = CJson::object();
    process.set("terminal", true);
    process.set("args", CJson::fromStrings({ "sh", "-c", "test -t 1 && echo exec-tty" }));
    process.set("env", CJson::fromStrings({ "PATH=/bin" }));
    process.set("cwd", "/");
    REQUIRE(CFile::writeAtomic(tmp / "p.json", process.dump(), 0600) == SBOX_OK);
    r = run({ "exec", "--process", tmp / "p.json", "--detach", "--console-socket", sock, "--pid-file", tmp / "e.pid", id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    int execMaster = receiveFd(listenFd);
    REQUIRE(execMaster >= 0);
    std::string execOut;
    for (int i = 0; i < 100; ++i) {
        char buf[256];
        struct pollfd pfd{ execMaster, POLLIN, 0 };
        if (::poll(&pfd, 1, 50) <= 0) {
            if (execOut.find("exec-tty") != std::string::npos) {
                break;
            }

            continue;
        }

        ssize_t n = ::read(execMaster, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }

        execOut.append(buf, size_t(n));
    }

    CHECK_MESSAGE(execOut.find("exec-tty") != std::string::npos, execOut);
    ::close(execMaster);

    // delete --force <id> on a running container.
    r = run({ "delete", "--force", id });
    CHECK_MESSAGE(r.code == 0, r.err);
    CHECK(run({ "state", id }).code == 1);

    ::close(master);
    ::close(listenFd);
}

TEST_CASE("--systemd-cgroup maps slice:prefix:name to a cgroupfs path") {
    if (!canRun()) {
        return;
    }

    SCgroupSystem sys;
    if (SCgroupSystem::detect(sys) != SBOX_OK || sys.layout == ECGL_NONE) {
        MESSAGE("no cgroup filesystem; skipping");
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    CFile::makeDirs(bundle, 0755);
    REQUIRE(makeRootfs(bundle + "/rootfs"));

    std::string id = "sd-" + randomSuffix();
    std::string slice = "sboxcompat" + randomSuffix() + ".slice";
    SSpec spec = testSpec({ "sleep", "100" });
    spec.linux_->cgroupsPath = slice + ":sboxtest:" + id;
    REQUIRE(writeSpec(bundle, spec));

    std::vector<std::string> g = { "--root", tmp / "state", "--systemd-cgroup" };
    std::vector<std::string> args = g;
    args.insert(args.end(), { "create", "--bundle", bundle, id });
    ToolResult r = runTool(tmp.path, tool("sboxrun"), args);
    REQUIRE_MESSAGE(r.code == 0, r.err);

    CCgroup cg;
    CHECK(CCgroup::open(slice + "/sboxtest-" + id + ".scope", cg) == SBOX_OK);

    args = g;
    args.insert(args.end(), { "delete", "--force", id });
    CHECK(runTool(tmp.path, tool("sboxrun"), args).code == 0);
    CHECK(CCgroup::open(slice + "/sboxtest-" + id + ".scope", cg) == -ENOENT);
    removeCgroup(slice);

    // --> Malformed systemd paths are refused.
    spec.linux_->cgroupsPath = "/not/systemd";
    REQUIRE(writeSpec(bundle, spec));
    args = g;
    args.insert(args.end(), { "create", "--bundle", bundle, id });
    r = runTool(tmp.path, tool("sboxrun"), args);
    CHECK(r.code == 1);
    CHECK(r.err.find("slice:prefix:name") != std::string::npos);
}

TEST_CASE("create failures are reported in the JSON log with exit status 1") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    CFile::makeDirs(bundle, 0755);
    REQUIRE(makeRootfs(bundle + "/rootfs"));
    REQUIRE(writeSpec(bundle, testSpec({ "missing-binary" })));

    std::string log = tmp / "log.json";
    ToolResult r = runTool(tmp.path, tool("sboxrun"), { "--root", tmp / "state", "--log", log, "--log-format", "json", "create", "--bundle", bundle, "x1" });
    CHECK(r.code == 1);
    CJson last = lastLogLine(log);
    CHECK(last.get("level").asString() == "error");
    CHECK(last.get("msg").asString().find("executable file not found") != std::string::npos);

    // --> Accepted global flags of runc that change nothing here.
    r = runTool(tmp.path, tool("sboxrun"), { "--root", tmp / "state", "--debug", "--criu", "/usr/sbin/criu", "--rootless", "false", "list" });
    CHECK(r.code == 0);
}
