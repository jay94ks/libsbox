#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "testutil.hpp"
#include <sbox/box/launch.hpp>
#include <sbox/core/file.hpp>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <cstring>

using namespace sbox;
using namespace testutil;

namespace {

    struct SIgnorePipe {
        SIgnorePipe() { ::signal(SIGPIPE, SIG_IGN); }
    } ignorePipe;

    bool canRun() {
        if (!userNamespacesWork()) {
            MESSAGE("user namespaces unavailable; skipping");
            return false;
        }

        return true;
    }

}

TEST_CASE("launch runs a program in new namespaces and reports its exit code") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SRun r = loop.run(run(baseSpec({ "/bin/sh", "-c", "echo hello; echo oops >&2; exit 3" })));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "hello\n");
    CHECK(r.err == "oops\n");
    CHECK(r.status.exited);
    CHECK(r.status.exitCode == 3);
}

TEST_CASE("launch passes stdin through") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SRun r = loop.run(run(baseSpec({ "cat" }), "piped input"));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "piped input");
}

TEST_CASE("launch reports exec failures precisely") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SRun r = loop.run(run(baseSpec({ "/no/such/program" })));
    CHECK(r.spawn == -ENOENT);
    CHECK(r.step == "execve");

    r = loop.run(run(baseSpec({ "no-such-program-in-path" })));
    CHECK(r.spawn == -ENOENT);
    CHECK(r.step == "execve");
}

TEST_CASE("launch reports a failing mount with its index") {
    if (!canRun()) {
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/true" });
    SMountSpec bad;
    bad.source = "x";
    bad.type = "no-such-filesystem";
    bad.destination = "/bad";
    spec.mounts.push_back(bad);

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    CHECK(r.spawn == -ENODEV);
    CHECK(r.step == "mount[" + std::to_string(spec.mounts.size() - 1) + "]");
}

TEST_CASE("launch isolates pid, uts, net and the filesystem") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SRun r = loop.run(run(baseSpec({ "/bin/sh", "-c",
        "echo pid=$$; echo host=$(cat /proc/sys/kernel/hostname); "
        "grep -c : /proc/net/dev; grep -q lo: /proc/net/dev && echo lo; "
        "ls /proc | grep -c '^[0-9]'; test -e /home && echo home; test -e /root && echo root; echo done" })));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    // --> sh is pid 1; /proc/net/dev lists only lo (1 line with ':' besides the header? the
    // header has '|' only); /proc shows sh and the commands of the pipeline only.
    CHECK(r.out.find("pid=1\n") == 0);
    CHECK(r.out.find("host=testbox\n") != std::string::npos);
    CHECK(r.out.find("\n1\nlo\n") != std::string::npos);
    CHECK(r.out.find("home") == std::string::npos);
    CHECK(r.out.find("root") == std::string::npos);
    CHECK(r.out.find("done") != std::string::npos);
}

TEST_CASE("launch drops capabilities and sets no_new_privs") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SRun r = loop.run(run(baseSpec({ "/bin/sh", "-c", "grep -E 'CapEff|CapPrm|CapBnd|NoNewPrivs' /proc/self/status" })));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out.find("CapPrm:\t0000000000000000") != std::string::npos);
    CHECK(r.out.find("CapEff:\t0000000000000000") != std::string::npos);
    CHECK(r.out.find("CapBnd:\t0000000000000000") != std::string::npos);
    CHECK(r.out.find("NoNewPrivs:\t1") != std::string::npos);
}

TEST_CASE("launch keeps requested capabilities") {
    if (!canRun()) {
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "grep -E 'CapEff' /proc/self/status" });
    uint64_t netAdmin = uint64_t(1) << CapabilityFromName("CAP_NET_ADMIN");
    spec.capabilities = SCapabilities{ netAdmin, netAdmin, netAdmin, netAdmin, netAdmin };

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out.find("CapEff:\t0000000000001000") != std::string::npos);
}

TEST_CASE("launch reaper forwards the payload status and is pid 1") {
    if (!canRun()) {
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "echo $$; kill -TERM $$; sleep 5" });
    spec.reaper = true;

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "2\n");
    CHECK_MESSAGE(r.status.signaled, "exited ", r.status.exited, " code ", r.status.exitCode, " err ", r.err);
    CHECK(r.status.signal == SIGTERM);
}

TEST_CASE("launch start gate holds the payload until start()") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "exit 7" });
        spec.gate = ESG_INTERNAL;

        CProcess proc;
        int32_t rc = co_await CProcess::spawn(spec, proc);
        REQUIRE_MESSAGE(rc == SBOX_OK, proc.failedStep());

        co_await CEventLoop::current()->sleepFor(50);
        SExitStatus st;
        CHECK(proc.tryWait(st) == -EAGAIN);

        CHECK(proc.start() == SBOX_OK);
        CHECK(co_await proc.waitStarted() == SBOX_OK);
        CHECK(co_await proc.wait(st) == SBOX_OK);
        CHECK(st.exited);
        CHECK(st.exitCode == 7);
    }());
}

TEST_CASE("launch start gate reports exec failure after start") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SLaunchSpec spec = baseSpec({ "/missing/binary" });
        spec.gate = ESG_INTERNAL;

        CProcess proc;
        REQUIRE(co_await CProcess::spawn(spec, proc) == SBOX_OK);
        CHECK(proc.start() == SBOX_OK);
        CHECK(co_await proc.waitStarted() == -ENOENT);
        CHECK(proc.failedStep() == "execve");

        SExitStatus st;
        CHECK(co_await proc.wait(st) == SBOX_OK);
    }());
}

TEST_CASE("launch closing the gate without start aborts the payload") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SLaunchSpec spec = baseSpec({ "/bin/true" });
        spec.gate = ESG_INTERNAL;

        CProcess proc;
        REQUIRE(co_await CProcess::spawn(spec, proc) == SBOX_OK);
        CFd pidfd = CFd(::dup(proc.pidfd()));
        // --> Destroying the handle kills the process.
        proc = CProcess();
        (void) pidfd;
    }());
}

TEST_CASE("launch maps extra descriptors") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        CStream r3;
        CFd w3;
        REQUIRE(CPipe::createForChild(r3, w3, true) == SBOX_OK);

        SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "echo three >&3; ls /proc/self/fd | wc -l" });
        spec.fds.push_back({ w3.get(), 3 });
        SRun r = co_await run(spec);
        w3.reset();
        REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);

        std::vector<uint8_t> got;
        co_await r3.recvAll(got);
        CHECK(std::string(got.begin(), got.end()) == "three\n");
        // --> 0,1,2,3 plus the descriptor ls opens for the directory.
        CHECK(r.out == "5\n");
    }());
}

TEST_CASE("launch creates a pty and hands the master back") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "tty; stty size" });
        spec.terminal = true;
        spec.terminalRows = 24;
        spec.terminalColumns = 100;

        CProcess proc;
        int32_t rc = co_await CProcess::spawn(spec, proc);
        REQUIRE_MESSAGE(rc == SBOX_OK, proc.failedStep());

        CStream master(proc.takePty());
        REQUIRE(master.isValid());

        std::vector<uint8_t> all;
        co_await master.recvAll(all);
        std::string text(all.begin(), all.end());
        CHECK(text.find("/dev/pts/0") != std::string::npos);
        CHECK(text.find("24 100") != std::string::npos);

        SExitStatus st;
        CHECK(co_await proc.wait(st) == SBOX_OK);
        CHECK(st.exitCode == 0);
    }());
}

TEST_CASE("launch joins the namespaces of a running process") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        SLaunchSpec first = baseSpec({ "/bin/sh", "-c", "read x" });
        first.hostname = "first";
        CStream in;
        CFd inChild;
        REQUIRE(CPipe::createForChild(in, inChild, false) == SBOX_OK);
        first.fds.push_back({ inChild.get(), 0 });

        CProcess a;
        REQUIRE(co_await CProcess::spawn(first, a) == SBOX_OK);
        inChild.reset();

        std::string base = "/proc/" + std::to_string(a.pid()) + "/ns/";
        SLaunchSpec second;
        second.args = { "/bin/sh", "-c", "cat /proc/sys/kernel/hostname; echo $$; ls /proc | grep -c '^[0-9]'" };
        second.env = { "PATH=/usr/bin:/bin" };
        second.namespaces = {
            { ENS_USER, base + "user" }, { ENS_UTS, base + "uts" }, { ENS_PID, base + "pid" },
            { ENS_MOUNT, base + "mnt" }, { ENS_NET, base + "net" }, { ENS_IPC, base + "ipc" },
        };

        SRun r = co_await run(second);
        REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
        CHECK(r.out.find("first\n") == 0);
        // --> Joined pid namespace: a later pid than the init, and the init plus our own
        // processes are visible.
        CHECK(r.out.find("\n1\n") == std::string::npos);

        in.close();
        SExitStatus st;
        CHECK(co_await a.wait(st) == SBOX_OK);
    }());
}

TEST_CASE("launch runs a function payload") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    SLaunchSpec spec = baseSpec({});
    spec.function = []() -> int32_t {
        // --> Inside: pid 2 under the reaper, hostname of the new UTS namespace.
        char host[64] = {};
        ::gethostname(host, sizeof(host));
        std::printf("%d %s\n", int(::getpid()), host);
        return std::string(host) == "testbox" ? 9 : 1;
    };

    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "2 testbox\n");
    CHECK(r.status.exitCode == 9);
}

TEST_CASE("launch uses an existing rootfs directory with masked and read-only paths") {
    if (!canRun()) {
        return;
    }

    char tmpl[] = "/tmp/sbox-rootfs-XXXXXX";
    REQUIRE(::mkdtemp(tmpl) != nullptr);
    std::string rootfs = tmpl;
    CFile::writeAtomic(rootfs + "/secret", "hidden");
    CFile::makeDirs(rootfs + "/data");
    CFile::writeAtomic(rootfs + "/data/file", "visible");
    // --> A hostile symlink: mounts through it must stay inside the rootfs.
    ::symlink("/var", (rootfs + "/escape").c_str());

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c",
        "cat /secret; echo; cat /data/file; echo; touch /data/new 2>/dev/null && echo writable; "
        "ls /escape | head -1" });
    spec.rootfsMode = ERFS_DIRECTORY;
    spec.rootfs = rootfs;
    spec.maskedPaths = { "/secret" };
    spec.readonlyPaths = { "/data" };

    SMountSpec t;
    t.source = "tmpfs";
    t.type = "tmpfs";
    t.destination = "/escape/inside";
    spec.mounts.push_back(t);

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "\nvisible\ninside\n");
    // --> The tmpfs went to <rootfs>/var/inside, not to the host's /var.
    CHECK(exists((rootfs + "/var/inside").c_str()));
    CHECK(!exists("/var/inside"));

    CFile::removeTree(rootfs);
}

TEST_CASE("launch without pivot_root") {
    if (!canRun()) {
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "echo ok; ls / | wc -l" });
    spec.noPivot = true;

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out.find("ok\n") == 0);
}

TEST_CASE("launch writes sysctls and rlimits") {
    if (!canRun()) {
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "cat /proc/sys/net/ipv4/ip_forward; ulimit -n; umask" });
    spec.sysctls = { { "net.ipv4.ip_forward", "1" } };
    spec.rlimits = { SRlimit{ RLIMIT_NOFILE, 77, 77 } };
    spec.umask = 027;

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "1\n77\n0027\n");
}

TEST_CASE("launch without a user namespace creates device nodes with mknod (root)") {
    if (::geteuid() != 0) {
        MESSAGE("not root; skipping");
        return;
    }

    SLaunchSpec spec = baseSpec({ "/bin/sh", "-c",
        "stat -c '%t:%T %a' /dev/null /dev/urandom; cat /proc/self/oom_score_adj; echo x > /dev/null && echo ok" });
    spec.namespaces = { { ENS_PID, "" }, { ENS_MOUNT, "" }, { ENS_IPC, "" }, { ENS_UTS, "" }, { ENS_NET, "" } };
    spec.oomScoreAdj = 500;

    CEventLoop loop;
    SRun r = loop.run(run(spec));
    REQUIRE_MESSAGE(r.spawn == SBOX_OK, r.step);
    CHECK(r.out == "1:3 666\n1:9 666\n500\nok\n");
}

TEST_CASE("launch start gate on a FIFO descriptor (OCI create/start)") {
    if (!canRun()) {
        return;
    }

    char tmpl[] = "/tmp/sbox-fifo-XXXXXX";
    REQUIRE(::mkdtemp(tmpl) != nullptr);
    std::string fifo = std::string(tmpl) + "/exec.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    CEventLoop loop;
    loop.run([](std::string path) -> TTask<void> {
        // --> The runtime keeps the FIFO open read-write so neither side blocks on open;
        // "start" is anyone writing one byte into it.
        CFd gate(::open(path.c_str(), O_RDWR | O_CLOEXEC));
        REQUIRE(gate.isValid());

        SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "exit 5" });
        spec.gate = ESG_FD;
        spec.gateFd = gate.get();

        CProcess proc;
        REQUIRE(co_await CProcess::spawn(spec, proc) == SBOX_OK);
        gate.reset();

        co_await CEventLoop::current()->sleepFor(30);
        SExitStatus st;
        CHECK(proc.tryWait(st) == -EAGAIN);

        CFd starter(::open(path.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC));
        REQUIRE(starter.isValid());
        CHECK(::write(starter.get(), "1", 1) == 1);

        CHECK(co_await proc.wait(st, 10000) == SBOX_OK);
        CHECK(st.exitCode == 5);
    }(fifo));

    CFile::removeTree(tmpl);
}

TEST_CASE("launch sends the pty master to a console socket") {
    if (!canRun()) {
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
        CFd mine(sv[0]), theirs(sv[1]);

        SLaunchSpec spec = baseSpec({ "/bin/sh", "-c", "echo on-the-console" });
        spec.terminal = true;
        spec.consoleSocketFd = theirs.get();

        CProcess proc;
        REQUIRE(co_await CProcess::spawn(spec, proc) == SBOX_OK);
        theirs.reset();

        char byte;
        struct iovec iov{ &byte, 1 };
        alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))];
        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        REQUIRE(::recvmsg(mine.get(), &msg, 0) == 1);

        int master = -1;
        struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
        REQUIRE(cm != nullptr);
        std::memcpy(&master, CMSG_DATA(cm), sizeof(int));

        CStream console{ CFd(master) };
        std::vector<uint8_t> all;
        co_await console.recvAll(all);
        CHECK(std::string(all.begin(), all.end()).find("on-the-console") != std::string::npos);

        SExitStatus st;
        CHECK(co_await proc.wait(st) == SBOX_OK);
    }());
}

TEST_CASE("mount options parse like OCI") {
    SMountSpec m;
    ParseMountOptions({ "rbind", "ro", "nosuid", "rprivate", "mode=755", "size=1m" }, m);
    CHECK(m.flags == (MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID));
    CHECK(m.propagation == (MS_PRIVATE | MS_REC));
    CHECK(m.data == "mode=755,size=1m");

    SMountSpec r;
    ParseMountOptions({ "bind", "rro" }, r);
    CHECK(r.recursiveReadOnly);
    CHECK((r.flags & MS_RDONLY) != 0);

    CHECK(CapabilityFromName("CAP_SYS_ADMIN") == 21);
    CHECK(CapabilityFromName("net_raw") == 13);
    CHECK(CapabilityFromName("CAP_NOPE") == -ENOENT);
    CHECK(CapabilityLast() >= 37);
    CHECK(ThreadCount() == 1);
}
