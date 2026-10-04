#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "ocitest.hpp"
#include <sbox/box/cgroup.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/oci/runtime.hpp>
#include <csignal>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <grp.h>
#include <algorithm>

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

namespace {

    struct SIgnorePipe {
        SIgnorePipe() { ::signal(SIGPIPE, SIG_IGN); }
    } ignorePipe;

    /**
     * A bundle with a minimal rootfs and a runtime over a private state root.
     */
    struct Env {
        TempDir tmp;
        std::string bundle;
        std::string rootfs;
        std::string root;
        std::vector<std::string> logs;
        std::unique_ptr<CRuntime> runtime;
        std::string id;

        explicit Env(bool rootless = false) {
            bundle = tmp / "bundle";
            rootfs = bundle + "/rootfs";
            root = tmp / "state";
            CFile::makeDirs(bundle, 0755);
            REQUIRE(makeRootfs(rootfs));

            SRuntimeOptions o;
            o.root = root;
            o.rootless = rootless;
            o.log = [this](ELogLevel level, const std::string& msg) {
                if (level >= ELOG_WARNING) {
                    logs.push_back(msg);
                }
            };

            runtime = std::make_unique<CRuntime>(o);
            id = "ocitest-" + randomSuffix();
        }

        void write(const SSpec& spec) {
            REQUIRE(writeSpec(bundle, spec));
        }
    };

    /**
     * Returns true when the tests that run real containers can run here.
     */
    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root; skipping container test");
            return false;
        }

        return true;
    }

    /**
     * Polls the state until it reaches `want` (or 5 s pass).
     */
    TTask<EContainerStatus> waitStatus(CRuntime& rt, const std::string& id, EContainerStatus want) {
        SState st;
        for (int i = 0; i < 500; ++i) {
            if (co_await rt.state(id, st) != SBOX_OK) {
                co_return ECST_INVALID;
            }

            if (st.status == want) {
                break;
            }

            co_await CEventLoop::current()->sleepFor(10);
        }

        co_return st.status;
    }

    /**
     * Reads a stream to EOF (bounded).
     */
    TTask<std::string> readAll(CStream& s, int64_t timeoutMs = 10000) {
        std::vector<uint8_t> out;
        co_await s.recvAll(out, size_t(1) << 20, timeoutMs);
        co_return std::string(out.begin(), out.end());
    }

    std::string readFile(const std::string& path) {
        std::string text;
        CFile::readAll(path, text);
        return text;
    }

    std::string trim(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) {
            s.pop_back();
        }

        return s;
    }

}

TEST_CASE("lifecycle through the library: create, state, start, kill, delete") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sleep", "1000" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        o.pidFile = e.tmp / "init.pid";
        REQUIRE_MESSAGE(co_await rt.create(e.id, o) == SBOX_OK, rt.lastError());

        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.status == ECST_CREATED);
        CHECK(st.pid > 0);
        CHECK(st.bundle == e.bundle);
        CHECK(st.rootfs == e.rootfs);
        CHECK(st.id == e.id);
        CHECK(readFile(e.tmp / "init.pid") == std::to_string(st.pid));
        CHECK(CFile::exists(e.root + "/" + e.id + "/state.json"));
        CHECK(CFile::exists(e.root + "/" + e.id + "/exec.fifo"));

        // --> Waiting at the gate: the program has not been executed yet.
        CHECK(trim(readFile("/proc/" + std::to_string(st.pid) + "/comm")) != "sleep");

        // --> Same id again.
        CHECK(co_await rt.create(e.id, o) == -EEXIST);
        CHECK(rt.lastError() == "container with id exists: " + e.id);

        std::vector<SState> all;
        REQUIRE(co_await rt.list(all) == SBOX_OK);
        REQUIRE(all.size() == 1);
        CHECK(all[0].status == ECST_CREATED);

        REQUIRE_MESSAGE(co_await rt.start(e.id) == SBOX_OK, rt.lastError());
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.status == ECST_RUNNING);
        CHECK(!CFile::exists(e.root + "/" + e.id + "/exec.fifo"));

        // --> start only releases the exec fifo, like runc; the execve itself happens right after
        // in the container process, so under load the old comm can still be visible briefly.
        std::string comm;
        for (int32_t i = 0; i < 200; ++i) {
            comm = trim(readFile("/proc/" + std::to_string(st.pid) + "/comm"));
            if (comm == "sleep") {
                break;
            }

            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(comm == "sleep");

        CHECK(co_await rt.start(e.id) == -EBUSY);
        CHECK(rt.lastError() == "cannot start an already running container");

        std::vector<pid_t> pids;
        REQUIRE(co_await rt.processes(e.id, pids) == SBOX_OK);
        CHECK(std::find(pids.begin(), pids.end(), st.pid) != pids.end());

        CHECK(co_await rt.remove(e.id) == -EBUSY);
        CHECK(rt.lastError() == "cannot delete container " + e.id + " that is not stopped: running");

        REQUIRE(co_await rt.kill(e.id, SIGKILL) == SBOX_OK);
        CHECK(co_await waitStatus(rt, e.id, ECST_STOPPED) == ECST_STOPPED);
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.pid == 0);

        CHECK(co_await rt.kill(e.id, SIGTERM) == -ESRCH);
        CHECK(rt.lastError() == "container not running");
        CHECK(co_await rt.start(e.id) == -ESRCH);

        SContainerRecord rec;
        std::string text = readFile(e.root + "/" + e.id + "/state.json");
        CJson doc;
        REQUIRE(CJson::parse(text, doc) == SBOX_OK);
        std::string err;
        REQUIRE(SContainerRecord::fromJson(doc, rec, err) == SBOX_OK);

        REQUIRE_MESSAGE(co_await rt.remove(e.id) == SBOX_OK, rt.lastError());
        CHECK(co_await rt.state(e.id, st) == -ENOENT);
        CHECK(rt.lastError() == "container does not exist");
        CHECK(co_await rt.remove(e.id) == -ENOENT);
        CHECK(!CFile::exists(e.root + "/" + e.id));

        // --> The cgroup is gone too.
        if (!rec.cgroupPath.empty()) {
            CCgroup cg;
            CHECK(CCgroup::open(rec.cgroupPath, cg) == -ENOENT);
        }
    }(env));
}

TEST_CASE("the container runs as real root without a user namespace and sees its own output") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sh", "-c", "id -u; cat /proc/self/uid_map; hostname; echo $$" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        CStream out;
        CFd outChild;
        REQUIRE(CPipe::createForChild(out, outChild, true) == SBOX_OK);

        SCreateOptions o;
        o.bundle = e.bundle;
        o.stdio = { { outChild.get(), 1 }, { outChild.get(), 2 } };
        CContainerProcess proc;
        REQUIRE_MESSAGE(co_await rt.create(e.id, o, &proc) == SBOX_OK, rt.lastError());
        outChild.reset();

        REQUIRE(co_await rt.start(e.id) == SBOX_OK);
        std::string text = co_await readAll(out);
        SExitStatus st;
        REQUIRE(co_await proc.wait(st, 10000) == SBOX_OK);
        CHECK(st.exitCode == 0);

        std::vector<std::string> lines;
        for (std::string_view l : CFile::splitLines(text)) {
            lines.emplace_back(l);
        }

        REQUIRE(lines.size() == 4);
        CHECK(lines[0] == "0");
        CHECK(lines[1].find("4294967295") != std::string::npos);
        CHECK(lines[2] == "ocitest");
        CHECK(lines[3] == "1");

        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);
    }(env));
}

TEST_CASE("a foreground container reports its exit status") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sh", "-c", "exit 5" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        CContainerProcess proc;
        REQUIRE(co_await rt.create(e.id, o, &proc) == SBOX_OK);
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);
        SExitStatus st;
        REQUIRE(co_await proc.wait(st, 10000) == SBOX_OK);
        CHECK(st.exited);
        CHECK(st.exitCode == 5);
        CHECK(co_await waitStatus(rt, e.id, ECST_STOPPED) == ECST_STOPPED);
        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);
    }(env));
}

TEST_CASE("create reports a missing program and leaves nothing behind") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "no-such-program" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        CHECK(co_await rt.create(e.id, o) == -ENOENT);
        CHECK(rt.lastError() == "exec: \"no-such-program\": executable file not found in $PATH");
        CHECK(!CFile::exists(e.root + "/" + e.id));

        // --> Invalid configuration and id.
        SSpec bad = testSpec({ "sh" });
        bad.process->cwd = "relative";
        e.write(bad);
        CHECK(co_await rt.create(e.id, o) == -EINVAL);
        CHECK(rt.lastError().find("must be an absolute path") != std::string::npos);
        CHECK(co_await rt.create("bad/id", o) == -EINVAL);

        SCreateOptions missing;
        missing.bundle = e.tmp / "nope";
        CHECK(co_await rt.create(e.id, missing) == -ENOENT);
    }(env));
}

TEST_CASE("exec joins the namespaces and cgroup of the init") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sleep", "1000" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        REQUIRE(co_await rt.create(e.id, o) == SBOX_OK);
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);

        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        std::string initPidNs = trim(capture("readlink /proc/" + std::to_string(st.pid) + "/ns/pid"));
        std::string initMntNs = trim(capture("readlink /proc/" + std::to_string(st.pid) + "/ns/mnt"));

        SSpec spec;
        REQUIRE(co_await rt.config(e.id, spec) == SBOX_OK);

        // Foreground exec with captured output.
        {
            CStream out;
            CFd outChild;
            REQUIRE(CPipe::createForChild(out, outChild, true) == SBOX_OK);
            SExecOptions x;
            x.process = *spec.process;
            x.process.args = { "sh", "-c", "readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt; cat /proc/1/comm; exit 3" };
            x.stdio = { { outChild.get(), 1 } };
            CContainerProcess proc;
            REQUIRE_MESSAGE(co_await rt.exec(e.id, x, &proc) == SBOX_OK, rt.lastError());
            outChild.reset();

            std::string text = co_await readAll(out);
            SExitStatus es;
            REQUIRE(co_await proc.wait(es, 10000) == SBOX_OK);
            CHECK(es.exitCode == 3);

            std::vector<std::string> lines;
            for (std::string_view l : CFile::splitLines(text)) {
                lines.emplace_back(l);
            }

            REQUIRE(lines.size() == 3);
            CHECK(lines[0] == initPidNs);
            CHECK(lines[1] == initMntNs);
            CHECK(lines[2] == "sleep");
        }

        // Detached exec: the pid file names a process inside the container.
        {
            SExecOptions x;
            x.process = *spec.process;
            x.process.args = { "sleep", "999" };
            x.detach = true;
            x.pidFile = e.tmp / "exec.pid";
            REQUIRE_MESSAGE(co_await rt.exec(e.id, x) == SBOX_OK, rt.lastError());

            pid_t pid = pid_t(std::atoi(readFile(x.pidFile).c_str()));
            REQUIRE(pid > 0);
            CHECK(trim(capture("readlink /proc/" + std::to_string(pid) + "/ns/pid")) == initPidNs);

            std::vector<pid_t> pids;
            REQUIRE(co_await rt.processes(e.id, pids) == SBOX_OK);
            CHECK(std::find(pids.begin(), pids.end(), pid) != pids.end());
            CHECK(std::find(pids.begin(), pids.end(), st.pid) != pids.end());
        }

        // A missing program fails the exec itself.
        {
            SExecOptions x;
            x.process = *spec.process;
            x.process.args = { "no-such-program" };
            CContainerProcess proc;
            CHECK(co_await rt.exec(e.id, x, &proc) == -ENOENT);
            CHECK(rt.lastError().find("no-such-program") != std::string::npos);
        }

        // --> kill --all reaches the exec'd process too.
        REQUIRE(co_await rt.kill(e.id, SIGKILL, true) == SBOX_OK);
        CHECK(co_await waitStatus(rt, e.id, ECST_STOPPED) == ECST_STOPPED);

        SExecOptions late;
        late.process = *spec.process;
        CHECK(co_await rt.exec(e.id, late) == -ESRCH);
        CHECK(rt.lastError() == "cannot exec in a stopped container");

        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);
    }(env));
}

TEST_CASE("pause and resume freeze the container cgroup") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sleep", "1000" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        REQUIRE(co_await rt.create(e.id, o) == SBOX_OK);
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);

        REQUIRE_MESSAGE(co_await rt.pause(e.id) == SBOX_OK, rt.lastError());
        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.status == ECST_PAUSED);
        CHECK(co_await rt.pause(e.id) == -EINVAL);

        SProcStat ps;
        REQUIRE(ReadProcStat(st.pid, ps) == SBOX_OK);
        CHECK((ps.state == 'D' || ps.state == 'S' || ps.state == 'T'));

        SExecOptions x;
        SSpec spec;
        REQUIRE(co_await rt.config(e.id, spec) == SBOX_OK);
        x.process = *spec.process;
        CHECK(co_await rt.exec(e.id, x) == -EBUSY);
        CHECK(co_await rt.start(e.id) == -EBUSY);

        REQUIRE(co_await rt.resume(e.id) == SBOX_OK);
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.status == ECST_RUNNING);
        CHECK(co_await rt.resume(e.id) == -EINVAL);
        CHECK(rt.lastError() == "container not paused");

        // --> A paused container can be force-deleted.
        REQUIRE(co_await rt.pause(e.id) == SBOX_OK);
        REQUIRE_MESSAGE(co_await rt.remove(e.id, true) == SBOX_OK, rt.lastError());
        CHECK(!ProcessAlive(st.pid, ps.startTime));
    }(env));
}

TEST_CASE("hooks run in order, with the state on stdin, in the right namespaces") {
    if (!canRun()) {
        return;
    }

    Env env;
    SSpec spec = testSpec({ "sh", "-c", "echo program >> /hooks.log" });
    SHooks hooks;
    // --> Runtime-namespace hooks write to the rootfs from the host; container-namespace hooks
    // see the rootfs as "/".
    std::string hostLog = env.rootfs + "/hooks.log";
    auto hook = [](const std::string& name, const std::string& log) {
        SHook h;
        h.path = "/bin/sh";
        h.args = { "sh", "-c", "read -r s; echo \"" + name + " $(hostname) $s\" >> " + log };
        h.timeout = 10;
        return h;
    };

    hooks.prestart.push_back(hook("prestart", hostLog));
    hooks.createRuntime.push_back(hook("createRuntime", hostLog));
    hooks.createContainer.push_back(hook("createContainer", "/hooks.log"));
    hooks.startContainer.push_back(hook("startContainer", "/hooks.log"));
    hooks.poststart.push_back(hook("poststart", hostLog));
    hooks.poststop.push_back(hook("poststop", hostLog));
    spec.hooks = hooks;
    env.write(spec);

    CEventLoop loop;
    loop.run([](Env& e, std::string log) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        CContainerProcess proc;
        REQUIRE_MESSAGE(co_await rt.create(e.id, o, &proc) == SBOX_OK, rt.lastError());
        REQUIRE_MESSAGE(co_await rt.start(e.id) == SBOX_OK, rt.lastError());
        SExitStatus st;
        REQUIRE(co_await proc.wait(st, 10000) == SBOX_OK);
        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);

        std::vector<std::string> lines;
        std::string text = readFile(log);
        for (std::string_view l : CFile::splitLines(text)) {
            lines.emplace_back(l);
        }

        REQUIRE_MESSAGE(lines.size() == 7, text);

        // --> The program runs concurrently with the poststart hooks (the spec only orders
        // poststart after the program was executed and before start returns), so its line
        // may land before or after the poststart line. It must come after startContainer and
        // before poststop; the hooks themselves are strictly ordered.
        auto program = std::find(lines.begin(), lines.end(), "program");
        REQUIRE_MESSAGE(program != lines.end(), text);
        size_t programAt = size_t(program - lines.begin());
        CHECK_MESSAGE(programAt >= 4, text);
        CHECK_MESSAGE(programAt <= 5, text);
        lines.erase(program);

        const char* order[] = { "prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop" };
        const char* status[] = { "creating", "creating", "creating", "created", "running", "stopped" };
        std::string host = trim(capture("hostname"));
        for (size_t i = 0; i < 6; ++i) {
            CHECK_MESSAGE(lines[i].rfind(order[i], 0) == 0, lines[i]);
            CHECK(lines[i].find("\"status\":\"" + std::string(status[i]) + "\"") != std::string::npos);
            CHECK(lines[i].find("\"id\":\"" + e.id + "\"") != std::string::npos);
            // --> createContainer/startContainer run in the container's UTS namespace.
            std::string where = (i == 2 || i == 3) ? "ocitest" : host;
            CHECK_MESSAGE(lines[i].find(std::string(order[i]) + " " + where + " ") == 0, lines[i]);
        }
    }(env, hostLog));
}

TEST_CASE("a failing hook aborts create and cleans up") {
    if (!canRun()) {
        return;
    }

    Env env;
    SSpec spec = testSpec({ "sleep", "1000" });
    SHooks hooks;
    SHook h;
    h.path = "/bin/sh";
    h.args = { "sh", "-c", "echo on-stdout; echo on-stderr >&2; exit 4" };
    hooks.createRuntime.push_back(h);
    spec.hooks = hooks;
    env.write(spec);

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        CHECK(co_await rt.create(e.id, o) == -ECHILD);
        std::string err = rt.lastError();
        CHECK(err.find("createRuntime hook") != std::string::npos);
        CHECK(err.find("exit status 4") != std::string::npos);
        CHECK(err.find("on-stdout") != std::string::npos);
        CHECK(err.find("on-stderr") != std::string::npos);
        CHECK(!CFile::exists(e.root + "/" + e.id));

        std::vector<SState> all;
        REQUIRE(co_await rt.list(all) == SBOX_OK);
        CHECK(all.empty());
    }(env));

    // --> A hook that hangs is killed after its timeout.
    SHooks slow;
    SHook s;
    s.path = "/bin/sleep";
    s.args = { "sleep", "100" };
    s.timeout = 1;
    slow.prestart.push_back(s);
    spec.hooks = slow;
    env.write(spec);

    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        int64_t t0 = CEventLoop::nowMs();
        CHECK(co_await rt.create(e.id, o) == -ETIMEDOUT);
        CHECK(CEventLoop::nowMs() - t0 < 5000);
        CHECK(rt.lastError().find("timeout") != std::string::npos);
        CHECK(!CFile::exists(e.root + "/" + e.id));
    }(env));
}

TEST_CASE("the console socket receives the pty master") {
    if (!canRun()) {
        return;
    }

    Env env;
    SSpec spec = testSpec({ "sh", "-c", "test -t 0 && test -t 1 && echo hello-pty" });
    spec.process->terminal = true;
    spec.process->consoleSize = SConsoleSize{ 40, 132 };
    env.write(spec);

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        std::string sockPath = e.tmp / "console.sock";
        SEndpoint ep;
        REQUIRE(SEndpoint::fromUnix(sockPath, ep) == SBOX_OK);
        CListener listener;
        REQUIRE(listener.listen(ep) == SBOX_OK);

        struct Received {
            std::vector<CFd> fds;
            bool done = false;
        };

        auto received = std::make_shared<Received>();
        CEventLoop::current()->spawn([](CListener& l, std::shared_ptr<Received> r) -> TTask<void> {
            CSocket conn;
            if (co_await l.accept(conn, 10000) == SBOX_OK) {
                uint8_t buf[16];
                co_await conn.recvFds(SByteSpan(buf, sizeof(buf)), r->fds, 10000);
            }

            r->done = true;
        }(listener, received));

        SCreateOptions o;
        o.bundle = e.bundle;
        o.consoleSocket = sockPath;
        REQUIRE_MESSAGE(co_await rt.create(e.id, o) == SBOX_OK, rt.lastError());

        for (int i = 0; i < 500 && !received->done; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        REQUIRE(received->fds.size() == 1);
        CStream master(std::move(received->fds[0]));

        struct winsize ws{};
        CHECK(::ioctl(master.nativeHandle(), TIOCGWINSZ, &ws) == 0);
        CHECK(ws.ws_row == 40);
        CHECK(ws.ws_col == 132);

        REQUIRE(co_await rt.start(e.id) == SBOX_OK);
        std::string text = co_await readAll(master);
        CHECK(text.find("hello-pty") != std::string::npos);
        CHECK(co_await waitStatus(rt, e.id, ECST_STOPPED) == ECST_STOPPED);
        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);

        // --> A terminal without a console socket cannot be detached.
        CHECK(co_await rt.create(e.id, SCreateOptions{ e.bundle }) == -EINVAL);
        CHECK(rt.lastError().find("console socket") != std::string::npos);
    }(env));
}

TEST_CASE("cgroup resources are applied (v1 hierarchies on hybrid hosts) and updated") {
    if (!canRun()) {
        return;
    }

    SCgroupSystem sys;
    if (SCgroupSystem::detect(sys) != SBOX_OK || sys.layout == ECGL_NONE) {
        MESSAGE("no cgroup filesystem; skipping");
        return;
    }

    Env env;
    std::string cgPath = "sbox-ocitest-" + randomSuffix();
    SSpec spec = testSpec({ "sleep", "1000" });
    SResourcesSpec res = *spec.linux_->resources;
    res.memory = SMemorySpec();
    res.memory->limit = 64 << 20;
    res.pids = SPidsSpec{ 32 };
    res.cpu = SCpuSpec();
    res.cpu->quota = 20000;
    res.cpu->period = 100000;
    spec.linux_->resources = res;
    spec.linux_->cgroupsPath = "/" + cgPath;
    env.write(spec);

    CEventLoop loop;
    loop.run([](Env& e, std::string path) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        REQUIRE_MESSAGE(co_await rt.create(e.id, o) == SBOX_OK, rt.lastError());
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);

        CCgroup cg;
        REQUIRE(CCgroup::open(path, cg) == SBOX_OK);

        auto knob = [&](uint32_t controller, const char* v1, const char* v2) -> std::string {
            for (const auto& [bits, dir] : cg.v1Dirs()) {
                if (bits & controller) {
                    return trim(readFile(dir + "/" + v1));
                }
            }

            return trim(readFile(cg.v2Dir() + "/" + v2));
        };

        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        std::vector<pid_t> procs;
        REQUIRE(cg.processes(procs) == SBOX_OK);
        CHECK(std::find(procs.begin(), procs.end(), st.pid) != procs.end());

        if (cg.controllers() & ECGC_MEMORY) {
            CHECK(knob(ECGC_MEMORY, "memory.limit_in_bytes", "memory.max") == std::to_string(64 << 20));
        }

        if (cg.controllers() & ECGC_PIDS) {
            CHECK(knob(ECGC_PIDS, "pids.max", "pids.max") == "32");
        }

        if (cg.controllers() & ECGC_CPU) {
            std::string quota = knob(ECGC_CPU, "cpu.cfs_quota_us", "cpu.max");
            CHECK(quota.rfind("20000", 0) == 0);
        }

        // --> The device cgroup applies the deny-all rule plus the defaults: /dev/null works,
        // an arbitrary device does not.
        SSpec cfg;
        REQUIRE(co_await rt.config(e.id, cfg) == SBOX_OK);
        {
            CStream out;
            CFd outChild;
            REQUIRE(CPipe::createForChild(out, outChild, true) == SBOX_OK);
            SExecOptions x;
            x.process = *cfg.process;
            x.process.args = { "sh", "-c", "echo x > /dev/null && echo null-ok; cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids.max" };
            x.stdio = { { outChild.get(), 1 } };
            CContainerProcess proc;
            REQUIRE_MESSAGE(co_await rt.exec(e.id, x, &proc) == SBOX_OK, rt.lastError());
            outChild.reset();
            std::string text = co_await readAll(out);
            SExitStatus es;
            co_await proc.wait(es, 10000);
            CHECK(text.find("null-ok") != std::string::npos);
            if (cg.controllers() & ECGC_PIDS) {
                // --> /sys/fs/cgroup shows the container's own cgroup.
                CHECK_MESSAGE(text.find("32") != std::string::npos, text);
            }
        }

        SResourcesSpec upd;
        upd.memory = SMemorySpec();
        upd.memory->limit = 32 << 20;
        upd.pids = SPidsSpec{ 16 };
        REQUIRE_MESSAGE(co_await rt.update(e.id, upd) == SBOX_OK, rt.lastError());

        if (cg.controllers() & ECGC_MEMORY) {
            CHECK(knob(ECGC_MEMORY, "memory.limit_in_bytes", "memory.max") == std::to_string(32 << 20));
        }

        if (cg.controllers() & ECGC_PIDS) {
            CHECK(knob(ECGC_PIDS, "pids.max", "pids.max") == "16");
        }

        REQUIRE(co_await rt.config(e.id, cfg) == SBOX_OK);
        CHECK(cfg.linux_->resources->memory->limit == (32 << 20));
        CHECK(cfg.linux_->resources->cpu->quota == 20000);    // --> Untouched fields stay.

        SCgroupStats stats;
        REQUIRE(co_await rt.stats(e.id, stats) == SBOX_OK);
        CHECK(stats.hasCpu);

        REQUIRE(co_await rt.remove(e.id, true) == SBOX_OK);
        CHECK(CCgroup::open(path, cg) == -ENOENT);
    }(env, cgPath));
}

TEST_CASE("state never mistakes a reused pid for the container") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sleep", "1000" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        REQUIRE(co_await rt.create(e.id, o) == SBOX_OK);
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);
        REQUIRE(co_await rt.kill(e.id, SIGKILL) == SBOX_OK);
        REQUIRE(co_await waitStatus(rt, e.id, ECST_STOPPED) == ECST_STOPPED);

        // --> Pretend the dead init's pid now belongs to this test process (another start
        // time): state stays "stopped", kill and delete leave the process alone.
        std::string path = e.root + "/" + e.id + "/state.json";
        CJson doc;
        REQUIRE(CJson::parse(readFile(path), doc) == SBOX_OK);
        doc.set("initProcessPid", int64_t(::getpid()));
        REQUIRE(CFile::writeAtomic(path, doc.dump(), 0600) == SBOX_OK);

        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        CHECK(st.status == ECST_STOPPED);
        CHECK(st.pid == 0);
        CHECK(co_await rt.kill(e.id, SIGKILL) == -ESRCH);
        CHECK(co_await rt.remove(e.id, true) == SBOX_OK);

        // --> Still here.
        CHECK(::kill(::getpid(), 0) == 0);
    }(env));
}

TEST_CASE("a network namespace path in config.json is joined") {
    if (!canRun()) {
        return;
    }

    Env env;
    std::string nsFile = env.tmp / "netns";
    REQUIRE(CFile::writeAtomic(nsFile, "", 0644) == SBOX_OK);

    pid_t child = ::fork();
    if (child == 0) {
        if (::unshare(CLONE_NEWNET) != 0 || ::mount("/proc/self/ns/net", nsFile.c_str(), nullptr, MS_BIND, nullptr) != 0) {
            ::_exit(1);
        }

        ::_exit(0);
    }

    int wst = 0;
    ::waitpid(child, &wst, 0);
    if (!WIFEXITED(wst) || WEXITSTATUS(wst) != 0) {
        MESSAGE("cannot create a persistent network namespace; skipping");
        return;
    }

    struct stat nsStat;
    REQUIRE(::stat(nsFile.c_str(), &nsStat) == 0);

    SSpec spec = testSpec({ "readlink", "/proc/self/ns/net" });
    for (SNamespaceEntry& ns : spec.linux_->namespaces) {
        if (ns.type == "network") {
            ns.path = nsFile;
        }
    }

    env.write(spec);

    CEventLoop loop;
    loop.run([](Env& e, uint64_t ino) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        CStream out;
        CFd outChild;
        REQUIRE(CPipe::createForChild(out, outChild, true) == SBOX_OK);
        SCreateOptions o;
        o.bundle = e.bundle;
        o.stdio = { { outChild.get(), 1 } };
        CContainerProcess proc;
        REQUIRE_MESSAGE(co_await rt.create(e.id, o, &proc) == SBOX_OK, rt.lastError());
        outChild.reset();
        REQUIRE(co_await rt.start(e.id) == SBOX_OK);
        std::string text = co_await readAll(out);
        SExitStatus st;
        co_await proc.wait(st, 10000);
        CHECK(trim(text) == "net:[" + std::to_string(ino) + "]");
        REQUIRE(co_await rt.remove(e.id) == SBOX_OK);
    }(env, uint64_t(nsStat.st_ino)));

    ::umount2(nsFile.c_str(), MNT_DETACH);
}

TEST_CASE("rootless: an unprivileged user runs a container in a user namespace") {
    if (!canRun()) {
        return;
    }

    if (!unprivilegedUserNamespaces()) {
        MESSAGE("unprivileged user namespaces are not available; skipping");
        return;
    }

    Env env(true);
    // --> The state root belongs to the unprivileged user; the bundle stays root-owned but
    // readable.
    CFile::makeDirs(env.root, 0700);
    REQUIRE(::chown(env.root.c_str(), 65534, 65534) == 0);
    SSpec spec = DefaultSpec(true, 65534, 65534, "rootless");
    spec.process->terminal = false;
    spec.process->args = { "sh", "-c", "id -u; cat /proc/self/uid_map; hostname" };
    env.write(spec);

    int fds[2];
    REQUIRE(::pipe(fds) == 0);
    pid_t child = ::fork();
    if (child == 0) {
        ::close(fds[0]);
        if (::setresgid(65534, 65534, 65534) != 0 || ::setgroups(0, nullptr) != 0 || ::setresuid(65534, 65534, 65534) != 0) {
            ::_exit(20);
        }

        ::setenv("XDG_RUNTIME_DIR", "/nonexistent", 1);
        int code = 0;
        {
            CEventLoop loop;
            code = loop.run([](Env& e, int outFd) -> TTask<int> {
                SRuntimeOptions ro;
                ro.root = e.root;
                ro.rootless = true;
                CRuntime rt(ro);
                SCreateOptions o;
                o.bundle = e.bundle;
                o.stdio = { { outFd, 1 }, { outFd, 2 } };
                CContainerProcess proc;
                if (co_await rt.create(e.id, o, &proc) != SBOX_OK) {
                    std::string msg = "create: " + rt.lastError() + "\n";
                    (void) !::write(outFd, msg.data(), msg.size());
                    co_return 21;
                }

                if (co_await rt.start(e.id) != SBOX_OK) {
                    co_return 22;
                }

                SExitStatus st;
                if (co_await proc.wait(st, 10000) != SBOX_OK || st.exitCode != 0) {
                    co_return 23;
                }

                co_return co_await rt.remove(e.id) == SBOX_OK ? 0 : 24;
            }(env, fds[1]));
        }

        ::_exit(code);
    }

    ::close(fds[1]);
    std::string text;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        text.append(buf, size_t(n));
    }

    ::close(fds[0]);
    int st = 0;
    ::waitpid(child, &st, 0);
    REQUIRE_MESSAGE(WIFEXITED(st), text);
    CHECK_MESSAGE(WEXITSTATUS(st) == 0, text);

    std::vector<std::string> lines;
    for (std::string_view l : CFile::splitLines(text)) {
        lines.emplace_back(l);
    }

    REQUIRE_MESSAGE(lines.size() >= 3, text);
    CHECK(lines[0] == "0");
    CHECK(lines[1].find("65534") != std::string::npos);
    CHECK(lines[2] == "rootless");
}

TEST_CASE("a created container is deleted without being started") {
    if (!canRun()) {
        return;
    }

    Env env;
    env.write(testSpec({ "sleep", "1000" }));

    CEventLoop loop;
    loop.run([](Env& e) -> TTask<void> {
        CRuntime& rt = *e.runtime;
        SCreateOptions o;
        o.bundle = e.bundle;
        REQUIRE(co_await rt.create(e.id, o) == SBOX_OK);
        SState st;
        REQUIRE(co_await rt.state(e.id, st) == SBOX_OK);
        SProcStat ps;
        REQUIRE(ReadProcStat(st.pid, ps) == SBOX_OK);

        // --> runc deletes a created container without --force (it kills the waiting init).
        REQUIRE_MESSAGE(co_await rt.remove(e.id) == SBOX_OK, rt.lastError());
        CHECK(!ProcessAlive(st.pid, ps.startTime));
        CHECK(co_await rt.state(e.id, st) == -ENOENT);
    }(env));
}
