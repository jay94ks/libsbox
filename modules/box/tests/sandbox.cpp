#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "testutil.hpp"
#include <sbox/box/sandbox.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <set>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using namespace sbox;

namespace {

    struct SIgnorePipe {
        SIgnorePipe() { ::signal(SIGPIPE, SIG_IGN); }
    } ignorePipe;

    const std::string HELPERS = SBOX_BOX_HELPERS;

    bool canRun() {
        if (!testutil::userNamespacesWork()) {
            MESSAGE("user namespaces unavailable; skipping");
            return false;
        }

        return true;
    }

    /**
     * A policy with the host's program directories and the test helpers.
     */
    SBoxPolicy basePolicy() {
        SBoxPolicy p;
        p.mounts = SBoxPolicy::systemMounts(true);
        p.mounts.push_back(SBoxMount{ HELPERS, "/helpers", EBMNT_READ_ONLY });
        return p;
    }

    struct SOutcome {
        SBoxResult result;
        std::string out;
        std::string err;
        bool valid = false;
    };

    /**
     * Runs a sandbox to the end, feeding `input` and collecting stdout/stderr concurrently.
     */
    TTask<SOutcome> runBox(SBoxPolicy policy, std::vector<std::string> args, std::string input = std::string()) {
        SOutcome o;
        CSandbox box = co_await CSandbox::spawn(std::move(policy), std::move(args));
        o.valid = box.isValid();

        if (o.valid) {
            if (!input.empty()) {
                co_await box.stdinPipe().send(BytesOf(input));
            }

            box.stdinPipe().close();

            std::vector<uint8_t> out, err;
            co_await box.stdoutPipe().recvAll(out);
            co_await box.stderrPipe().recvAll(err);
            o.out.assign(out.begin(), out.end());
            o.err.assign(err.begin(), err.end());
        }

        o.result = co_await box.wait();
        co_return o;
    }

    SOutcome run(SBoxPolicy policy, std::vector<std::string> args, std::string input = std::string()) {
        CEventLoop loop;
        return loop.run(runBox(std::move(policy), std::move(args), std::move(input)));
    }

    std::string makeTempDir(mode_t mode = 0777) {
        char tmpl[] = "/tmp/sbox-box-test-XXXXXX";
        REQUIRE(::mkdtemp(tmpl) != nullptr);
        ::chmod(tmpl, mode);
        return tmpl;
    }

    /**
     * Host pids of every descendant of `root`.
     */
    std::set<pid_t> descendants(pid_t root) {
        std::set<pid_t> found{ root };
        bool grew = true;

        while (grew) {
            grew = false;
            DIR* d = ::opendir("/proc");
            while (struct dirent* e = ::readdir(d)) {
                pid_t pid = pid_t(std::atoi(e->d_name));
                if (pid <= 0 || found.count(pid)) {
                    continue;
                }

                std::string stat;
                if (CFile::readAll("/proc/" + std::to_string(pid) + "/stat", stat) != SBOX_OK) {
                    continue;
                }

                size_t close = stat.rfind(')');
                if (close == std::string::npos) {
                    continue;
                }

                pid_t ppid = 0;
                char state = 0;
                std::sscanf(stat.c_str() + close + 1, " %c %d", &state, &ppid);
                if (found.count(ppid)) {
                    found.insert(pid);
                    grew = true;
                }
            }

            ::closedir(d);
        }

        return found;
    }

}

TEST_CASE("the documented example runs python with stdin and a writable job directory") {
    if (!canRun() || !testutil::exists("/usr/bin/python3")) {
        MESSAGE("python3 unavailable; skipping");
        return;
    }

    std::string job = makeTempDir();
    CFile::writeAtomic(job + "/main.py",
        "import sys\n"
        "data = sys.stdin.read()\n"
        "open('/work/out.txt', 'w').write(data.upper())\n"
        "print('got', len(data))\n");
    ::chmod((job + "/main.py").c_str(), 0644);

    CEventLoop loop;
    SOutcome o = loop.run([](std::string jobDir) -> TTask<SOutcome> {
        SBoxPolicy p;
        p.mounts = { { "/usr", "/usr", EBMNT_READ_ONLY }, { jobDir, "/work", EBMNT_READ_WRITE } };
        for (const char* link : { "/lib", "/lib64", "/bin", "/etc" }) {
            if (testutil::exists(link)) {
                p.mounts.push_back(SBoxMount{ link, link, EBMNT_READ_ONLY });
            }
        }

        p.memoryMax = 256 << 20;
        p.pidsMax = 64;
        p.wallTimeoutMs = 5000;
        p.network = EBNET_NONE;
        p.cwd = "/work";

        std::string input = "hello sandbox";
        CSandbox box = co_await CSandbox::spawn(p, { "/usr/bin/python3", "main.py" });
        REQUIRE_MESSAGE(box.isValid(), box.failedStep(), " ", box.error());
        co_await box.stdinPipe().send(BytesOf(input));
        box.stdinPipe().close();

        SOutcome out;
        std::vector<uint8_t> bytes;
        co_await box.stdoutPipe().recvAll(bytes);
        out.out.assign(bytes.begin(), bytes.end());
        bytes.clear();
        co_await box.stderrPipe().recvAll(bytes);
        out.err.assign(bytes.begin(), bytes.end());
        out.result = co_await box.wait();
        co_return out;
    }(job));

    CHECK_MESSAGE(o.result.reason == EBEXIT_NORMAL, o.err);
    CHECK(o.result.exitCode == 0);
    CHECK(o.out == "got 13\n");
    CHECK(o.result.cpuTimeUs > 0);
    CHECK(o.result.peakMemoryBytes > 1000000);
    CHECK(o.result.wallTimeMs >= 0);

    std::string written;
    CHECK(CFile::readAll(job + "/out.txt", written) == SBOX_OK);
    CHECK(written == "HELLO SANDBOX");
    CFile::removeTree(job);
}

TEST_CASE("binding only /usr on a merged-/usr host still runs dynamically linked programs") {
    struct stat st;
    if (!canRun() || ::lstat("/lib64", &st) != 0 || !S_ISLNK(st.st_mode)) {
        MESSAGE("not a merged-/usr host with /lib64 -> usr/lib64; skipping");
        return;
    }

    // --> Regression (README example): /lib64/ld-linux-x86-64.so.2 must resolve when only /usr is bound.
    SBoxPolicy p;
    p.mounts = { { "/usr", "/usr", EBMNT_READ_ONLY } };
    SOutcome o = run(p, { "/usr/bin/sh", "-c", "echo merged; /bin/true && ls -d /lib64" });
    CHECK_MESSAGE(o.result.reason == EBEXIT_NORMAL, o.err, " ", o.result.failedStep, " ", o.result.error);
    CHECK(o.result.exitCode == 0);
    CHECK(o.out == "merged\n/lib64\n");

    // --> A policy that mounts the path itself keeps its own mount.
    std::string dir = makeTempDir(0755);
    p.mounts.push_back({ dir, "/bin", EBMNT_READ_ONLY });
    o = run(p, { "/usr/bin/sh", "-c", "ls /bin | wc -l" });
    CHECK(o.out == "0\n");
    CFile::removeTree(dir);
}

TEST_CASE("exit codes, stdout and stderr") {
    if (!canRun()) {
        return;
    }

    SOutcome o = run(basePolicy(), { "/bin/sh", "-c", "read x; echo out:$x; echo err >&2; exit 42" }, "abc\n");
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.result.exitCode == 42);
    CHECK(o.out == "out:abc\n");
    CHECK(o.err == "err\n");
}

TEST_CASE("wall timeout kills the program and its descendants") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SBoxPolicy p = basePolicy();
        p.wallTimeoutMs = 3000;
        std::vector<std::string> args = { "/bin/sh", "-c", "sleep 100 & (sleep 200 &) ; echo ready; while true; do sleep 1; done" };
        CSandbox box = co_await CSandbox::spawn(p, args);
        REQUIRE(box.isValid());

        // --> Collect the tree once the shell started its children (a fixed delay is not
        // enough on a loaded machine): it reports "ready" after forking both sleeps, and the
        // loop's first `sleep 1` follows right after.
        uint8_t buf[16];
        SIoResult got = co_await box.stdoutPipe().recv(SByteSpan(buf, sizeof(buf)), 2500);
        CHECK(got.ok());
        std::set<pid_t> tree;
        for (int i = 0; i < 200 && tree.size() < 4; ++i) {
            tree = descendants(box.pid());
            if (tree.size() < 4) {
                co_await CEventLoop::current()->sleepFor(5);
            }
        }

        CHECK(tree.size() >= 4);

        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_WALL_TIMEOUT);
        CHECK(r.wallTimeMs >= 3000);
        CHECK(r.wallTimeMs < 10000);

        for (pid_t pid : tree) {
            CHECK_MESSAGE(::kill(pid, 0) != 0, "survivor ", pid);
        }
    }());
}

TEST_CASE("pids limit stops a fork bomb") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy p = basePolicy();
    p.pidsMax = 16;
    SOutcome o = run(p, { "/helpers/forkbomb" });
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_NORMAL);
    int made = std::atoi(o.out.c_str());
    CHECK(made > 0);
    CHECK(made < 16);

    if (!o.result.cgroupUsed) {
        MESSAGE("pids enforced by RLIMIT_NPROC (no cgroup)");
    }
}

TEST_CASE("memory limit ends with the memory reason") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy p = basePolicy();
    p.memoryMax = 64 << 20;
    SOutcome o = run(p, { "/helpers/memhog" });
    REQUIRE(o.valid);

    bool byCgroup = std::find(o.result.unenforced.begin(), o.result.unenforced.end(), "memory (RLIMIT_AS fallback)") == o.result.unenforced.end();
    if (byCgroup) {
        CHECK(o.result.reason == EBEXIT_MEMORY);
        CHECK(o.result.signal == SIGKILL);
        CHECK(o.result.oomKills >= 1);
        CHECK(o.result.memorySource == EBSTAT_CGROUP);
        CHECK(o.result.peakMemoryBytes >= (48u << 20));
        CHECK(o.result.peakMemoryBytes <= (80u << 20));
    } else {
        MESSAGE("memory limited by RLIMIT_AS (no memory cgroup)");
        CHECK(o.result.reason == EBEXIT_NORMAL);
        CHECK(o.result.exitCode == 3);
    }
}

TEST_CASE("seccomp violation: kill reports the reason, errno lets the program continue") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy kill = basePolicy();
    kill.seccompViolation = ESVIO_KILL;
    SOutcome o = run(kill, { "/helpers/badsyscall" });
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_SECCOMP);
    CHECK(o.result.signal == SIGSYS);

    SBoxPolicy deny = basePolicy();
    deny.seccompViolation = ESVIO_ERRNO;
    o = run(deny, { "/helpers/badsyscall" });
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.result.exitCode == 0);
    CHECK(o.out.find("-1 Operation not permitted") == 0);
}

TEST_CASE("python runs under the kill-on-violation profile") {
    if (!canRun() || !testutil::exists("/usr/bin/python3")) {
        return;
    }

    SBoxPolicy p = SBoxPolicy::strict();
    p.mounts = SBoxPolicy::systemMounts(true);
    SOutcome o = run(p, { "python3", "-c", "import os, json, subprocess, threading, tempfile; "
        "t = threading.Thread(target=lambda: None); t.start(); t.join(); "
        "print(subprocess.run(['echo', 'sub'], capture_output=True).stdout.decode().strip()); "
        "f = tempfile.NamedTemporaryFile(dir='/dev/shm'); print(json.dumps({'ok': True}))" });
    REQUIRE(o.valid);
    CHECK_MESSAGE(o.result.reason == EBEXIT_NORMAL, BoxExitReasonName(o.result.reason), " ", o.err);
    CHECK(o.out == "sub\n{\"ok\": true}\n");
}

TEST_CASE("no network: only loopback, and it is up") {
    if (!canRun()) {
        return;
    }

    SOutcome o = run(basePolicy(), { "/bin/sh", "-c", "grep : /proc/net/dev | cut -d: -f1 | tr -d ' '; cat /sys/class/net 2>/dev/null; true" });
    REQUIRE(o.valid);
    CHECK(o.out == "lo\n");

    if (testutil::exists("/usr/bin/python3")) {
        o = run(basePolicy(), { "python3", "-c",
            "import socket\n"
            "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); port = s.getsockname()[1]\n"
            "c = socket.create_connection(('127.0.0.1', port)); a, _ = s.accept(); c.send(b'x'); print(a.recv(1))\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 80), timeout=2); print('reached')\n"
            "except OSError as e:\n"
            "    print('unreachable')\n" });
        REQUIRE(o.valid);
        CHECK_MESSAGE(o.out == "b'x'\nunreachable\n", o.err);
    }
}

TEST_CASE("host files outside the mounts and host processes are invisible") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy p = basePolicy();
    p.mounts = SBoxPolicy::systemMounts(false);
    SOutcome o = run(p, { "/bin/sh", "-c",
        "for d in /home /root /srv /var /etc/passwd /run /sys; do test -e $d && echo visible $d; done; "
        "ls /proc | grep -c '^[0-9]'; echo $$; cat /proc/sys/kernel/hostname; "
        "echo x > /proc/sys/kernel/hostname 2>/dev/null && echo sys-writable; "
        "touch /newfile 2>/dev/null && echo root-writable; touch /usr/newfile 2>/dev/null && echo usr-writable; "
        "touch /tmp/ok && echo tmp-writable; ls /dev | tr '\\n' ' '" });
    REQUIRE(o.valid);
    CHECK(o.out.find("visible") == std::string::npos);
    CHECK(o.out.find("writable\n") == o.out.find("tmp-writable\n") + 4);
    // --> pid 1 (the init), sh, ls, grep at most.
    std::vector<std::string_view> lines = CFile::splitLines(o.out);
    REQUIRE(lines.size() >= 5);
    CHECK(std::atoi(std::string(lines[0]).c_str()) <= 4);
    CHECK(lines[1] == "2");
    CHECK(lines[2] == "sandbox");
    CHECK(lines[3] == "tmp-writable");
    CHECK(lines[4].find("null") != std::string_view::npos);
    CHECK(lines[4].find("urandom") != std::string_view::npos);
    CHECK(lines[4].find("pts") != std::string_view::npos);
    CHECK(lines[4].find("vda") == std::string_view::npos);
}

TEST_CASE("no capabilities, no_new_privs and seccomp are in force") {
    if (!canRun()) {
        return;
    }

    SOutcome o = run(basePolicy(), { "/bin/sh", "-c", "grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' /proc/self/status" });
    REQUIRE(o.valid);
    CHECK(o.out.find("CapEff:\t0000000000000000") != std::string::npos);
    CHECK(o.out.find("CapPrm:\t0000000000000000") != std::string::npos);
    CHECK(o.out.find("CapBnd:\t0000000000000000") != std::string::npos);
    CHECK(o.out.find("CapAmb:\t0000000000000000") != std::string::npos);
    CHECK(o.out.find("NoNewPrivs:\t1") != std::string::npos);
    CHECK(o.out.find("Seccomp:\t2") != std::string::npos);
}

TEST_CASE("tmp is size limited") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy p = basePolicy();
    p.tmpSize = 4 << 20;
    SOutcome o = run(p, { "/bin/sh", "-c", "dd if=/dev/zero of=/tmp/big bs=1M count=16 2>/dev/null; echo $?; du -k /tmp/big | cut -f1" });
    REQUIRE(o.valid);
    std::vector<std::string_view> lines = CFile::splitLines(o.out);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] != "0");
    CHECK(std::atoi(std::string(lines[1]).c_str()) <= 4096);
}

TEST_CASE("cpu time limit ends with the cpu reason") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy p = basePolicy();
    p.cpuTimeLimitMs = 1000;
    p.wallTimeoutMs = 20000;
    SOutcome o = run(p, { "/helpers/cpuburn" });
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_CPU_TIME);
    // --> The kernel checks RLIMIT_CPU against tick-sampled user+system time, while the
    // reported figure is the cgroup's exact runtime. On a contended CPU the tick sampling
    // overcharges a busy task (up to ~20% seen with 16 parallel runs on 4 cores), so the
    // figure only has to show that the limit was the cause, not reach the limit exactly.
    CHECK(o.result.cpuTimeUs >= 500000);
    CHECK(o.result.cpuTimeUs < 5000000);
}

TEST_CASE("resource figures come from the cgroup when there is one") {
    if (!canRun()) {
        return;
    }

    SOutcome o = run(basePolicy(), { "/bin/sh", "-c", "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done" });
    REQUIRE(o.valid);
    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.result.cpuTimeUs > 0);
    CHECK(o.result.peakMemoryBytes > 0);

    if (::geteuid() == 0) {
        CHECK(o.result.cgroupUsed);
        CHECK(o.result.cpuSource == EBSTAT_CGROUP);
    }
}

TEST_CASE("stdio can inherit descriptors or use /dev/null") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        CStream reader;
        CFd writer;
        REQUIRE(CPipe::createForChild(reader, writer, true) == SBOX_OK);

        SBoxPolicy p = basePolicy();
        p.stdinMode = SBoxStdio{ EBSTD_NULL, -1 };
        p.stdoutMode = SBoxStdio{ EBSTD_INHERIT, writer.get() };
        p.stderrMode = SBoxStdio{ EBSTD_NULL, -1 };

        CSandbox box = co_await CSandbox::spawn(p, { "/bin/sh", "-c", "cat; echo through; echo hidden >&2" });
        REQUIRE(box.isValid());
        writer.reset();
        CHECK(!box.stdoutPipe().isValid());

        std::vector<uint8_t> got;
        co_await reader.recvAll(got);
        CHECK(std::string(got.begin(), got.end()) == "through\n");

        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_NORMAL);
    }());
}

TEST_CASE("setup failures are reported, not thrown") {
    SBoxPolicy p = basePolicy();
    p.mounts.push_back(SBoxMount{ "/definitely/missing", "/x", EBMNT_READ_ONLY });
    SOutcome o = run(p, { "/bin/true" });
    CHECK(!o.valid);
    CHECK(o.result.reason == EBEXIT_SETUP_FAILURE);
    CHECK(o.result.error == -ENOENT);
    CHECK(o.result.failedStep.find("/definitely/missing") != std::string::npos);

    if (canRun()) {
        o = run(basePolicy(), { "/no/such/binary" });
        CHECK(!o.valid);
        CHECK(o.result.reason == EBEXIT_SETUP_FAILURE);
        CHECK(o.result.error == -ENOENT);
        CHECK(o.result.failedStep == "execve");

        p = basePolicy();
        p.mounts.push_back(SBoxMount{ "/definitely/missing", "/x", EBMNT_READ_ONLY, false, true });
        o = run(p, { "/bin/true" });
        CHECK(o.result.reason == EBEXIT_NORMAL);
    }
}

TEST_CASE("kill() ends the program with the signal reason") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        CSandbox box = co_await CSandbox::spawn(basePolicy(), { "/bin/sleep", "100" });
        REQUIRE(box.isValid());
        co_await CEventLoop::current()->sleepFor(50);
        CHECK(box.kill() == SBOX_OK);
        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_SIGNAL);
        CHECK(r.signal == SIGKILL);
        CHECK(r.wallTimeMs < 5000);
    }());
}

TEST_CASE("CSandbox::fork runs a lambda inside the sandbox") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        int base = 40;
        CSandbox box = co_await CSandbox::fork(basePolicy(), [base]() -> int32_t {
            char host[64] = {};
            ::gethostname(host, sizeof(host));
            std::printf("%s %d %d\n", host, int(::getpid()), int(::access("/home", F_OK) == 0));
            std::fflush(stdout);

            // --> The seccomp filter applies to the function too.
            if (::syscall(SYS_unshare, CLONE_NEWUSER) == 0) {
                return 1;
            }

            return base + 2;
        });
        REQUIRE_MESSAGE(box.isValid(), box.failedStep());

        box.stdinPipe().close();
        std::vector<uint8_t> out;
        co_await box.stdoutPipe().recvAll(out);
        CHECK(std::string(out.begin(), out.end()) == "sandbox 2 0\n");

        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_NORMAL);
        CHECK(r.exitCode == 42);
    }());
}

TEST_CASE("CSandbox::fork refuses to run while other threads exist") {
    std::atomic<bool> stop{ false };
    std::thread other([&]() {
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    CEventLoop loop;
    SBoxResult r = loop.run([]() -> TTask<SBoxResult> {
        CSandbox box = co_await CSandbox::fork(SBoxPolicy(), []() -> int32_t { return 0; });
        CHECK(!box.isValid());
        CHECK(box.error() == -EBUSY);
        co_return co_await box.wait();
    }());

    stop = true;
    other.join();
    CHECK(r.reason == EBEXIT_SETUP_FAILURE);
    CHECK(r.error == -EBUSY);
}

TEST_CASE("worker preset: own directory writable, listed unix sockets reachable") {
    if (!canRun()) {
        return;
    }

    std::string dir = makeTempDir();
    std::string sockDir = makeTempDir();
    std::string sockPath = sockDir + "/svc.sock";

    CEventLoop loop;
    loop.run([](std::string work, std::string sock) -> TTask<void> {
        CListener listener;
        SEndpoint ep;
        REQUIRE(SEndpoint::fromUnix(sock, ep) == SBOX_OK);
        REQUIRE(listener.listen(ep) == SBOX_OK);
        ::chmod(sock.c_str(), 0666);

        SBoxPolicy p = SBoxPolicy::worker(work, { sock });
        p.wallTimeoutMs = 10000;

        // --> The parent of the work directory is the sandbox's own /tmp, not the host's.
        std::string script = "echo data > " + work + "/f && cat " + work + "/f && "
            "touch " + work + "/../escape && echo contained; "
            "test -e " + sock + " && echo sock-visible";

        std::vector<std::string> args = { "/bin/sh", "-c", script };
        CSandbox box = co_await CSandbox::spawn(p, args);
        REQUIRE_MESSAGE(box.isValid(), box.failedStep());
        box.stdinPipe().close();

        std::vector<uint8_t> out;
        co_await box.stdoutPipe().recvAll(out);
        CHECK(std::string(out.begin(), out.end()) == "data\ncontained\nsock-visible\n");
        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_NORMAL);
        CHECK(!testutil::exists((work + "/../escape").c_str()));

        if (testutil::exists("/usr/bin/python3")) {
            // --> Built outside the co_await expression (GCC 13 ICEs on temporaries there).
            std::vector<std::string> clientArgs = { "python3", "-c",
                "import socket; s = socket.socket(socket.AF_UNIX); s.connect('" + sock + "'); s.sendall(b'hi'); s.close()" };
            CSandbox client = co_await CSandbox::spawn(p, clientArgs);
            REQUIRE(client.isValid());

            CSocket conn;
            REQUIRE(co_await listener.accept(conn, 10000) == SBOX_OK);
            std::vector<uint8_t> got;
            co_await conn.recvAll(got);
            CHECK(std::string(got.begin(), got.end()) == "hi");
            SBoxResult cr = co_await client.wait();
            CHECK(cr.reason == EBEXIT_NORMAL);
        }
    }(dir, sockPath));

    CFile::removeTree(dir);
    CFile::removeTree(sockDir);
}

TEST_CASE("strict and permissive presets") {
    if (!canRun()) {
        return;
    }

    SBoxPolicy strict = SBoxPolicy::strict();
    CHECK(strict.memoryMax > 0);
    CHECK(strict.seccompViolation == ESVIO_KILL);
    SOutcome o = run(strict, { "/bin/sh", "-c", "echo strict; test -e /etc/passwd || echo no-etc" });
    REQUIRE(o.valid);
    CHECK(o.out == "strict\nno-etc\n");

    SBoxPolicy permissive = SBoxPolicy::permissive();
    CHECK(permissive.network == EBNET_HOST);
    o = run(permissive, { "/bin/sh", "-c", "grep -c : /proc/net/dev" });
    REQUIRE(o.valid);
    CHECK(std::atoi(o.out.c_str()) >= 2);
}

TEST_CASE("rootless: an unprivileged user gets the same isolation") {
    if (!canRun()) {
        return;
    }

    if (::geteuid() != 0) {
        MESSAGE("already unprivileged; covered by the other cases");
        return;
    }

    int fds[2];
    REQUIRE(::pipe(fds) == 0);

    pid_t pid = ::fork();
    if (pid == 0) {
        ::close(fds[0]);
        ::setgroups(0, nullptr);
        if (::setresgid(65534, 65534, 65534) != 0 || ::setresuid(65534, 65534, 65534) != 0) {
            ::_exit(90);
        }

        // --> A process that changed its uid is not dumpable; a real user's shell is.
        ::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

        SBoxPolicy p = basePolicy();
        p.memoryMax = 64 << 20;
        p.pidsMax = 32;
        p.stagingDir = "/tmp";

        CEventLoop loop;
        SOutcome o = loop.run(runBox(p, { "/bin/sh", "-c", "id -u; cat /proc/self/uid_map; grep CapEff /proc/self/status; ls /proc | grep -c '^[0-9]'" }));

        std::string report = std::string(BoxExitReasonName(o.result.reason)) + "|" + o.result.failedStep + "|" +
            std::to_string(o.result.error) + "|" + (o.result.cgroupUsed ? "cgroup" : "nocgroup") + "|";
        for (const std::string& u : o.result.unenforced) {
            report += u + ",";
        }

        report += "|" + o.out;
        (void) ::write(fds[1], report.data(), report.size());
        ::_exit(0);
    }

    ::close(fds[1]);
    std::string report;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        report.append(buf, size_t(n));
    }

    ::close(fds[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status));

    MESSAGE("rootless report: ", report);
    CHECK(report.find("normal|") == 0);
    // --> Inside: uid 0 mapped to 65534; no capability; only the sandbox's processes.
    CHECK(report.find("|0\n         0      65534          1\n") != std::string::npos);
    CHECK(report.find("CapEff:\t0000000000000000") != std::string::npos);

    if (report.find("nocgroup") != std::string::npos) {
        CHECK(report.find("memory (RLIMIT_AS fallback)") != std::string::npos);
        CHECK(report.find("pids (RLIMIT_NPROC fallback)") != std::string::npos);
    }
}

TEST_CASE("network namespace mode joins a prepared namespace") {
    if (!canRun() || ::geteuid() != 0) {
        MESSAGE("needs root (joining a namespace the caller does not own); skipping");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        // --> A process holding a network namespace with a recognisable setting, standing in
        // for one the net module prepared.
        SLaunchSpec holder;
        holder.args = { "/bin/sleep", "30" };
        holder.namespaces = { { ENS_NET, "" } };
        holder.sysctls = { { "net.ipv4.ip_default_ttl", "77" } };
        holder.loopbackUp = true;

        CProcess proc;
        REQUIRE(co_await CProcess::spawn(holder, proc) == SBOX_OK);

        SBoxPolicy p = basePolicy();
        p.network = EBNET_NAMESPACE;
        p.netnsPath = "/proc/" + std::to_string(proc.pid()) + "/ns/net";

        std::vector<std::string> args = { "/bin/sh", "-c", "cat /proc/sys/net/ipv4/ip_default_ttl; echo $$; grep -c : /proc/net/dev" };
        CSandbox box = co_await CSandbox::spawn(p, args);
        REQUIRE_MESSAGE(box.isValid(), box.failedStep(), " ", box.error());
        box.stdinPipe().close();

        std::vector<uint8_t> out;
        co_await box.stdoutPipe().recvAll(out);
        CHECK(std::string(out.begin(), out.end()) == "77\n2\n1\n");
        SBoxResult r = co_await box.wait();
        CHECK(r.reason == EBEXIT_NORMAL);

        proc.kill(SIGKILL);
        SExitStatus st;
        co_await proc.wait(st);
    }());
}
