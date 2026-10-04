#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/core/fd.hpp>
#include "testutil.hpp"
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// --> Interoperability with strongSwan (charon + swanctl) when it is installed: charon runs as
// an IKEv2 initiator in a separate namespace and must establish an IKE SA with our responder.
// Without strongSwan on the machine the test is skipped.

using namespace sbox;
using namespace sbox::vpn;
using namespace ipsectest;

namespace {

    /** Returns the first executable path of a list, or an empty string. */
    std::string findBinary(std::initializer_list<const char*> candidates) {
        for (const char* c : candidates) {
            if (::access(c, X_OK) == 0) {
                return c;
            }
        }

        return std::string();
    }

    /** Starts a program inside a namespace (fork, setns, exec) and returns its pid. */
    pid_t spawnIn(const std::string& netns, const std::vector<std::string>& argv, const std::vector<std::string>& env) {
        pid_t pid = ::fork();
        if (pid != 0) {
            return pid;
        }

        int fd = ::open(netns.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0 || ::setns(fd, CLONE_NEWNET) != 0) {
            ::_exit(127);
        }

        std::vector<char*> args;
        for (const std::string& a : argv) {
            args.push_back(const_cast<char*>(a.c_str()));
        }

        args.push_back(nullptr);
        std::vector<char*> envp;
        for (const std::string& e : env) {
            envp.push_back(const_cast<char*>(e.c_str()));
        }

        envp.push_back(nullptr);
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, 1);
            ::dup2(devnull, 2);
        }

        ::execve(args[0], args.data(), envp.data());
        ::_exit(127);
    }

    /** Waits for a child without blocking the loop (pidfd). */
    TTask<int32_t> waitChild(pid_t pid, int64_t timeoutMs) {
        CFd pfd(int(::syscall(SYS_pidfd_open, pid, 0)));
        if (!pfd.isValid()) {
            co_return -errno;
        }

        int32_t r = co_await CEventLoop::current()->waitFd(pfd.get(), EFDE_READ, timeoutMs);
        int status = 0;
        if (r < 0) {
            ::kill(pid, SIGKILL);
            co_await CEventLoop::current()->waitFd(pfd.get(), EFDE_READ, 2000);
            ::waitpid(pid, &status, WNOHANG);
            co_return r;
        }

        ::waitpid(pid, &status, WNOHANG);
        co_return WIFEXITED(status) ? WEXITSTATUS(status) : -ECHILD;
    }

}

TEST_CASE("strongSwan initiator interoperates with the responder (when installed)") {
    std::string swanctl = findBinary({ "/usr/sbin/swanctl", "/usr/bin/swanctl", "/usr/local/sbin/swanctl" });
    std::string charon = findBinary({ "/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", "/usr/libexec/strongswan/charon",
                                      "/usr/local/libexec/ipsec/charon", "/usr/sbin/charon-systemd" });
    if (swanctl.empty() || charon.empty()) {
        MESSAGE("strongSwan (swanctl + charon) not installed; interop test skipped");
        return;
    }

    if (!isRoot()) {
        MESSAGE("not root; interop test skipped");
        return;
    }

    TempDir dir;
    std::string srvNs = dir.netns("srv");
    std::string cliNs = dir.netns("cli");
    REQUIRE(!srvNs.empty());
    REQUIRE(!cliNs.empty());

    std::string vici = "unix://" + dir.join("charon.vici");
    std::string conf =
        "charon {\n"
        "  port = 500\n  port_nat_t = 4500\n"
        "  install_routes = no\n  install_virtual_ip = no\n"
        "  plugins { vici { socket = " + vici + " } }\n"
        "  filelog { log { path = " + dir.join("charon.log") + "\n default = 1\n ike = 2 } }\n"
        "}\n";
    std::string swan =
        "connections {\n"
        "  sbox {\n"
        "    version = 2\n    remote_addrs = 10.99.0.1\n    vips = 0.0.0.0\n"
        "    proposals = aes256gcm16-prfsha256-ecp256\n"
        "    local { auth = psk\n id = @interop.test }\n"
        "    remote { auth = psk\n id = %any }\n"
        "    children { net { remote_ts = 10.88.0.0/16\n esp_proposals = aes256gcm16 } }\n"
        "  }\n"
        "}\n"
        "secrets { ike-1 { id = @interop.test\n secret = interop-secret } }\n";
    REQUIRE(CFile::writeAtomic(dir.join("strongswan.conf"), conf, 0600) == SBOX_OK);
    REQUIRE(CFile::writeAtomic(dir.join("swanctl.conf"), swan, 0600) == SBOX_OK);

    CEventLoop loop;
    loop.run([](TempDir& d, std::string srv, std::string cli, std::string charonPath, std::string swanctlPath,
                std::string viciUri) -> TTask<void> {
        CFd cliFd;
        REQUIRE(net::CNetns::open(cli, cliFd) == SBOX_OK);
        net::CRtnl s;
        net::CRtnl c;
        REQUIRE(s.open(srv) == SBOX_OK);
        REQUIRE(c.open(cli) == SBOX_OK);
        REQUIRE(co_await s.createVeth("wan0", "wan1", cliFd.get()) == SBOX_OK);
        net::SIpPrefix a;
        net::SIpPrefix::parse("10.99.0.1/24", a);
        int32_t i0 = co_await s.linkIndex("wan0");
        REQUIRE(co_await s.addAddress(i0, a) == SBOX_OK);
        REQUIRE(co_await s.setUp(i0) == SBOX_OK);
        net::SIpPrefix::parse("10.99.0.2/24", a);
        int32_t i1 = co_await c.linkIndex("wan1");
        REQUIRE(co_await c.addAddress(i1, a) == SBOX_OK);
        REQUIRE(co_await c.setUp(i1) == SBOX_OK);

        SIkeServerConfig cfg;
        cfg.listenAddress = "10.99.0.1";
        cfg.netnsPath = srv;
        net::SIpPrefix::parse("10.77.0.0/24", cfg.pool);
        net::SIpPrefix route;
        net::SIpPrefix::parse("10.88.0.0/16", route);
        cfg.routes.push_back(route);
        cfg.dataPath.kind = EIDP_USER;
        SIkePsk psk;
        psk.secret = "interop-secret";
        cfg.psks.push_back(psk);
        CIkeServer server(cfg);
        REQUIRE(co_await server.start() == SBOX_OK);

        std::vector<std::string> env = { "STRONGSWAN_CONF=" + d.join("strongswan.conf"), "PATH=/usr/sbin:/usr/bin:/sbin:/bin" };
        pid_t daemon = spawnIn(cli, { charonPath }, env);
        REQUIRE(daemon > 0);
        co_await CEventLoop::current()->sleepFor(1500);

        pid_t load = spawnIn(cli, { swanctlPath, "--load-all", "--file", d.join("swanctl.conf"), "--uri", viciUri }, env);
        CHECK(co_await waitChild(load, 10000) == 0);
        pid_t up = spawnIn(cli, { swanctlPath, "--initiate", "--ike", "sbox", "--uri", viciUri, "--timeout", "10" }, env);
        co_await waitChild(up, 15000);

        bool established = false;
        for (int32_t i = 0; i < 100 && !established; ++i) {
            for (const SIkeSessionInfo& info : server.sessions()) {
                established = established || info.state == "established";
            }

            co_await CEventLoop::current()->sleepFor(50);
        }

        CHECK_MESSAGE(established, "charon log: " << d.join("charon.log"));
        ::kill(daemon, SIGTERM);
        co_await waitChild(daemon, 5000);
        co_await server.stop();
    }(dir, srvNs, cliNs, charon, swanctl, vici));
}
