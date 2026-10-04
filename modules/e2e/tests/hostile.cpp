// Hostile code under SBoxPolicy::strict(): each attempt to get out is blocked, and the result
// says how (an errno the program saw, or the SBoxResult reason the supervisor reports).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
#include <sbox/box/sandbox.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace sbox;
using namespace e2e;

namespace {

    struct Outcome {
        SBoxResult result;
        std::string out;
    };

    /**
     * The test's fixture: a helper directory the sandbox gets read-only, a host "secret" next to
     * it that the sandbox must not reach.
     */
    struct Fixture {
        TempDir tmp;
        std::string bin;
        std::string secret;

        Fixture() {
            bin = tmp / "bin";
            REQUIRE(copyFile(SBOX_E2E_HELPER, bin + "/e2ehelper"));
            ::chmod(bin.c_str(), 0755);
            secret = tmp / "secret.txt";
            CFile::writeAtomic(secret, "TOP SECRET\n", 0644);
        }

        /** strict() plus the helper directory. */
        SBoxPolicy policy() const {
            SBoxPolicy p = SBoxPolicy::strict();
            p.mounts.push_back(SBoxMount{ bin, "/sbx", EBMNT_READ_ONLY });
            return p;
        }
    };

    TTask<Outcome> runBox(SBoxPolicy p, std::vector<std::string> args) {
        Outcome o;
        CSandbox box = co_await CSandbox::spawn(std::move(p), std::move(args));
        if (box.isValid()) {
            box.stdinPipe().close();
            o.out = co_await readStream(box.stdoutPipe());
        }

        o.result = co_await box.wait();
        co_return o;
    }

    Outcome run(SBoxPolicy p, std::vector<std::string> helperArgs) {
        std::vector<std::string> args;
        args.push_back("/sbx/e2ehelper");
        args.insert(args.end(), helperArgs.begin(), helperArgs.end());
        CEventLoop loop;
        return loop.run(runBox(std::move(p), std::move(args)));
    }

    /**
     * True (with a MESSAGE) when the cgroup controller behind a limit was unavailable.
     */
    bool unenforced(const Outcome& o, const std::string& limit) {
        for (const std::string& name : o.result.unenforced) {
            if (name.compare(0, limit.size(), limit) == 0) {
                MESSAGE("the " << limit << " cgroup controller is unavailable here; skipping");
                return true;
            }
        }

        return false;
    }

    bool canRun() {
        if (::geteuid() != 0) {
            MESSAGE("not root: cgroup limits unavailable; skipping");
            return false;
        }

        return true;
    }

}

TEST_CASE("host files outside the mounts cannot be read") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    Outcome o = run(fx.policy(), { "read", fx.secret });
    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.result.exitCode == 1);
    CHECK(o.out == "error ENOENT\n");

    // --> strict() has no /etc at all; /etc/shadow is not there to be read.
    o = run(fx.policy(), { "read", "/etc/shadow" });
    CHECK(o.out == "error ENOENT\n");

    // --> /proc/1 is the sandbox's own init (pid namespace), which the program may not even
    // inspect; its root would be the sandbox root anyway.
    o = run(fx.policy(), { "read", "/proc/1/root" + fx.secret });
    CHECK((o.out == "error EACCES\n" || o.out == "error ENOENT\n"));

    // --> Climbing out of a bind mount stays in the sandbox root.
    o = run(fx.policy(), { "read", "/sbx/../../../.." + fx.secret });
    CHECK(o.out == "error ENOENT\n");

    // --> The mounts are read-only.
    o = run(fx.policy(), { "write", "/sbx/planted", "x" });
    CHECK(o.out == "error EROFS\n");
    CHECK_FALSE(CFile::exists(fx.bin + "/planted"));
    o = run(fx.policy(), { "write", "/usr/planted", "x" });
    CHECK(o.out == "error EROFS\n");
}

TEST_CASE("host processes are invisible") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    Outcome o = run(fx.policy(), { "pids" });
    CHECK(o.result.reason == EBEXIT_NORMAL);
    // --> Only the sandbox's init (1) and the program (2) exist in its pid namespace.
    CHECK(o.out == "2 1 2\n");
}

TEST_CASE("no network: neither the host's loopback nor outside addresses are reachable") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    // --> A listener on the host's loopback (bound to an ephemeral port, nothing else changes).
    CFd listener(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(sa);
    REQUIRE(::bind(listener.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
    REQUIRE(::listen(listener.get(), 8) == 0);
    REQUIRE(::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&sa), &len) == 0);
    std::string port = std::to_string(ntohs(sa.sin_port));

    // --> The sandbox's 127.0.0.1 is its own loopback: nothing listens there.
    Outcome o = run(fx.policy(), { "connect", "127.0.0.1", port });
    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.out == "error ECONNREFUSED\n");
    o = run(fx.policy(), { "connect", "192.0.2.1", "80" });
    CHECK(o.out == "error ENETUNREACH\n");

    // --> The host listener never saw a connection.
    int fd = ::accept4(listener.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(fd < 0);
}

TEST_CASE("a fork bomb hits the pids limit") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    SBoxPolicy p = fx.policy();
    p.pidsMax = 16;
    Outcome o = run(p, { "forkbomb" });
    if (unenforced(o, "pids")) {
        return;
    }

    CHECK(o.result.reason == EBEXIT_NORMAL);
    CHECK(o.result.exitCode == 3);
    CHECK(o.out.find("error EAGAIN") != std::string::npos);
    int forked = std::atoi(o.out.c_str() + 7);     // --> "forked N error EAGAIN"
    CHECK(forked > 0);
    CHECK(forked < 16);
    CHECK(o.result.cgroupUsed);
}

TEST_CASE("allocating beyond memoryMax ends with EBEXIT_MEMORY") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    SBoxPolicy p = fx.policy();
    p.memoryMax = 64ll << 20;
    Outcome o = run(p, { "memhog", "512" });
    if (unenforced(o, "memory")) {
        return;
    }

    CHECK_MESSAGE(o.result.reason == EBEXIT_MEMORY, BoxExitReasonName(o.result.reason), " ", o.out);
    CHECK(o.result.oomKills > 0);
    CHECK(o.out.find("allocated") == std::string::npos);
}

TEST_CASE("denied system calls kill the program under strict() and fail with EPERM under the errno profile") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    for (const char* call : { "ptrace", "mount", "unshare", "setns", "bpf", "keyctl" }) {
        CAPTURE(call);
        Outcome o = run(fx.policy(), { "syscall", call });
        CHECK(o.result.reason == EBEXIT_SECCOMP);
        CHECK(o.result.signal == SIGSYS);
        CHECK(o.out.empty());

        SBoxPolicy p = fx.policy();
        p.seccompViolation = ESVIO_ERRNO;
        o = run(p, { "syscall", call });
        CHECK(o.result.reason == EBEXIT_NORMAL);
        CHECK(o.out == "error EPERM\n");
    }
}

TEST_CASE("burning CPU ends with the CPU time or the wall clock limit") {
    if (!canRun()) {
        return;
    }

    Fixture fx;
    SBoxPolicy p = fx.policy();
    p.cpuTimeLimitMs = 1000;
    Outcome o = run(p, { "spin" });
    CHECK(o.result.reason == EBEXIT_CPU_TIME);

    p = fx.policy();
    p.cpuTimeLimitMs = 0;
    p.wallTimeoutMs = 1000;
    o = run(p, { "spin" });
    CHECK(o.result.reason == EBEXIT_WALL_TIMEOUT);
    CHECK(o.result.wallTimeMs >= 1000);
}
