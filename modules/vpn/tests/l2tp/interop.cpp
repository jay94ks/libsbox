#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/core/file.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/l2tp/server.hpp>
#include "testutil.hpp"
#include <csignal>
#include <spawn.h>
#include <sys/syscall.h>
#include <sys/wait.h>

using namespace sbox;
using namespace sbox::vpn;
using namespace l2tptest;

extern char** environ;

// --> Interoperability with the reference Linux implementations: xl2tpd + pppd as the LAC
// against our LNS (plain L2TP, so no IPsec stack is needed on the client side). strongSwan
// (IKEv1 transport mode) is detected and reported; the test is skipped when the tools or the
// kernel PPP driver (/dev/ppp) are missing, as on the development machine.

namespace {

    /* Finds an executable in the usual places. */
    std::string which(const char* name) {
        for (const char* dir : { "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin" }) {
            std::string p = std::string(dir) + "/" + name;
            if (::access(p.c_str(), X_OK) == 0) {
                return p;
            }
        }

        return std::string();
    }

    net::SIpPrefix prefix(const char* text) {
        net::SIpPrefix p;
        net::SIpPrefix::parse(text, p);
        return p;
    }

    /* Spawns a process inside a namespace; returns a pidfd. */
    int32_t spawnIn(const std::string& netns, const std::vector<std::string>& argv, CFd& pidfd, pid_t& pid) {
        net::CNetnsScope scope(netns);
        if (scope.error() != SBOX_OK) {
            return scope.error();
        }

        std::vector<char*> args;
        for (const std::string& a : argv) {
            args.push_back(const_cast<char*>(a.c_str()));
        }

        args.push_back(nullptr);
        if (::posix_spawn(&pid, args[0], nullptr, nullptr, args.data(), environ) != 0) {
            return -errno;
        }

        pidfd.reset(int(::syscall(SYS_pidfd_open, pid, 0)));
        return pidfd.isValid() ? SBOX_OK : -errno;
    }

}

TEST_CASE("xl2tpd + pppd LAC against the LNS (plain L2TP)") {
    std::string xl2tpd = which("xl2tpd");
    std::string pppd = which("pppd");
    std::string charon = which("charon");
    if (charon.empty()) {
        charon = which("ipsec");
    }

    MESSAGE("interop tools: xl2tpd=" << (xl2tpd.empty() ? "-" : xl2tpd) << " pppd=" << (pppd.empty() ? "-" : pppd)
                                     << " strongswan=" << (charon.empty() ? "-" : charon));
    if (xl2tpd.empty() || pppd.empty() || ::access("/dev/ppp", R_OK | W_OK) != 0 || !IsRoot()) {
        MESSAGE("skipped: needs root, xl2tpd, pppd and /dev/ppp");
        return;
    }

    CEventLoop loop;
    loop.run([xl2tpd]() -> TTask<void> {
        TempDir dir;
        std::string srvNs = dir.netns("srv");
        std::string cliNs = dir.netns("cli");
        REQUIRE(!srvNs.empty());
        CFd cliFd;
        REQUIRE(net::CNetns::open(cliNs, cliFd) == SBOX_OK);
        net::CRtnl srv;
        net::CRtnl cli;
        REQUIRE(srv.open(srvNs) == SBOX_OK);
        REQUIRE(cli.open(cliNs) == SBOX_OK);
        REQUIRE(co_await srv.createVeth("wan0", "wan1", cliFd.get()) == SBOX_OK);
        int32_t a = co_await srv.linkIndex("wan0");
        int32_t b = co_await cli.linkIndex("wan1");
        co_await srv.addAddress(a, prefix("10.98.0.1/24"));
        co_await cli.addAddress(b, prefix("10.98.0.2/24"));
        co_await srv.setUp(a);
        co_await cli.setUp(b);
        co_await cli.setUp(co_await cli.linkIndex("lo"));

        SL2tpServerConfig sc;
        sc.listenAddress = "10.98.0.1";
        sc.netnsPath = srvNs;
        sc.dataPath = EL2TK_PLAIN;
        SPppUser u;
        u.name = "alice";
        u.password = "Wonderland!";
        sc.users.push_back(u);
        sc.pool = prefix("10.62.0.0/24");
        CL2tpServer server(sc);
        REQUIRE(co_await server.start() == SBOX_OK);

        std::string options = dir.join("options.l2tpd.client");
        CFile::writeAtomic(options, "name alice\npassword Wonderland!\nnoauth\nrefuse-eap\nrefuse-pap\nrefuse-chap\nrefuse-mschap\n"
                                    "noipdefault\nnodefaultroute\nmtu 1400\nmru 1400\nnoccp\nnodeflate\nnobsdcomp\n", 0600);
        std::string conf = dir.join("xl2tpd.conf");
        CFile::writeAtomic(conf, "[global]\nport = 1701\n[lac sbox]\nlns = 10.98.0.1\nautodial = yes\nppp debug = no\npppoptfile = " + options +
                                     "\nlength bit = yes\n", 0600);
        CFd pidfd;
        pid_t pid = 0;
        std::vector<std::string> argv = { xl2tpd, "-D", "-c", conf, "-p", dir.join("xl2tpd.pid"), "-C", dir.join("control") };
        REQUIRE(spawnIn(cliNs, argv, pidfd, pid) == SBOX_OK);
        bool up = co_await WaitFor([&] { return !server.sessions().empty() && server.sessions()[0].upMs != 0; }, 15000);
        CHECK(up);
        if (up) {
            CHECK(server.sessions()[0].user == "alice");
            CHECK(server.sessions()[0].auth == "MS-CHAPv2");
        }

        ::kill(pid, SIGTERM);
        co_await CEventLoop::current()->waitFd(pidfd.get(), EFDE_READ, 5000);
        siginfo_t info;
        ::waitid(P_PIDFD, id_t(pidfd.get()), &info, WEXITED | WNOHANG);
        co_await server.stop();
    }());
}
