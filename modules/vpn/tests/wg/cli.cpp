#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/vpn/wg/config.hpp>
#include "testutil.hpp"

#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

using namespace sbox;
using namespace sbox::vpn;
using namespace wgtest;

#ifndef SBOX_TEST_BIN_DIR
#define SBOX_TEST_BIN_DIR ""
#endif

namespace {

    std::string tool() {
        return std::string(SBOX_TEST_BIN_DIR) + "/sbox-wg";
    }

    /* Runs a shell command line and returns its stdout. */
    std::string capture(const std::string& cmd, int* status = nullptr) {
        std::string out;
        FILE* f = ::popen(cmd.c_str(), "r");
        if (!f) {
            return out;
        }

        char buf[4096];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
            out.append(buf, n);
        }

        int st = ::pclose(f);
        if (status) {
            *status = st;
        }

        return out;
    }

    std::string trimmed(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) {
            s.pop_back();
        }

        return s;
    }

}

TEST_CASE("sbox-wg: genkey, pubkey, client-config") {
    if (::access(tool().c_str(), X_OK) != 0) {
        MESSAGE("skipped: sbox-wg is not built");
        return;
    }

    STempDir dir;
    std::string keyFile = dir.join("key");
    std::string priv = trimmed(capture(tool() + " genkey"));
    SWgKey k;
    REQUIRE(SWgKey::fromBase64(priv, k) == SBOX_OK);
    REQUIRE(CFile::writeAtomic(keyFile, priv + "\n", 0600) == SBOX_OK);

    std::string pub = trimmed(capture(tool() + " pubkey < " + keyFile));
    SWgKey expect;
    REQUIRE(DeriveWgPublicKey(k, expect) == SBOX_OK);
    CHECK(pub == expect.toBase64());

    std::string psk = trimmed(capture(tool() + " genpsk"));
    CHECK(SWgKey::fromBase64(psk, k) == SBOX_OK);

    int status = 0;
    capture("echo nonsense | " + tool() + " pubkey 2>/dev/null", &status);
    CHECK(status != 0);

    // --> A server configuration, a client for it, and the peer appended to the server file.
    std::string server = dir.join("wg0.conf");
    REQUIRE(CFile::writeAtomic(server, "[Interface]\nPrivateKey = " + priv + "\nListenPort = 51820\nAddress = 10.8.0.1/24\n", 0600) == SBOX_OK);
    std::string client = capture(tool() + " client-config --server-config " + server
        + " --endpoint vpn.example.com --address 10.8.0.2/32 --dns 10.8.0.1 --append-to " + server);

    SWgConfig cc;
    std::string err;
    REQUIRE_MESSAGE(ParseWgConfig(client, cc, &err) == SBOX_OK, err);
    REQUIRE(cc.peers.size() == 1);
    CHECK(cc.peers[0].publicKey == expect);
    CHECK(cc.peers[0].endpointHost == "vpn.example.com:51820");
    CHECK(cc.dns[0] == "10.8.0.1");

    std::string text;
    REQUIRE(CFile::readAll(server, text) == SBOX_OK);
    SWgConfig sc;
    REQUIRE_MESSAGE(ParseWgConfig(text, sc, &err) == SBOX_OK, err);
    REQUIRE(sc.peers.size() == 1);
    SWgKey clientPub;
    REQUIRE(DeriveWgPublicKey(cc.privateKey, clientPub) == SBOX_OK);
    CHECK(sc.peers[0].publicKey == clientPub);
    CHECK(sc.peers[0].allowedIps[0].toString() == "10.8.0.2/32");
    CHECK(sc.addresses[0].toString() == "10.8.0.1/24");
}

TEST_CASE("sbox-wg: up runs a user-space device in the foreground, show reads it") {
    if (::access(tool().c_str(), X_OK) != 0 || !canUseNetns()) {
        MESSAGE("skipped: needs the sbox-wg binary, root, namespaces and /dev/net/tun");
        return;
    }

    STempDir dir;
    std::string ns = dir.netns("up");
    REQUIRE_FALSE(ns.empty());
    std::string uapi = dir.join("uapi");

    SWgKey priv, peer;
    GenerateWgPrivateKey(priv);
    GenerateWgPrivateKey(peer);
    DeriveWgPublicKey(peer, peer);
    std::string conf = dir.join("wgt.conf");
    REQUIRE(CFile::writeAtomic(conf, "[Interface]\nPrivateKey = " + priv.toBase64() + "\nListenPort = 51830\nAddress = 10.30.0.1/24\n\n[Peer]\nPublicKey = "
        + peer.toBase64() + "\nAllowedIPs = 10.30.0.2/32, 10.31.0.0/16\nEndpoint = 192.0.2.1:51830\n", 0600) == SBOX_OK);

    pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        ::dup2(devnull, STDERR_FILENO);
        std::string t = tool();
        ::execl(t.c_str(), t.c_str(), "up", conf.c_str(), "--netns", ns.c_str(), "--mode", "userspace", "--uapi-dir", uapi.c_str(),
            static_cast<char*>(nullptr));
        ::_exit(127);
    }

    CFd pidfd(int(::syscall(SYS_pidfd_open, pid, 0)));
    REQUIRE(pidfd.isValid());

    CEventLoop loop;
    loop.run([&]() -> TTask<void> {
        // --> Wait for the UAPI socket to appear.
        std::string sock = CFile::join(uapi, "wgt.sock");
        for (int i = 0; i < 200 && !CFile::exists(sock); ++i) {
            co_await CEventLoop::current()->sleepFor(25);
        }

        REQUIRE(CFile::exists(sock));

        std::string out = capture(tool() + " show wgt --uapi-dir " + uapi);
        CHECK(out.find("interface: wgt (user space)") != std::string::npos);
        CHECK(out.find("listening port: 51830") != std::string::npos);
        CHECK(out.find("peer: " + peer.toBase64()) != std::string::npos);
        CHECK(out.find("10.31.0.0/16") != std::string::npos);

        std::string conf2 = capture(tool() + " showconf wgt --uapi-dir " + uapi);
        SWgConfig parsed;
        REQUIRE(ParseWgConfig(conf2, parsed) == SBOX_OK);
        CHECK(parsed.privateKey == priv);
        CHECK(parsed.listenPort == 51830);

        // --> The interface exists in the namespace with its address and the peer routes.
        net::CRtnl rt;
        REQUIRE(rt.open(ns) == SBOX_OK);
        int32_t index = co_await rt.linkIndex("wgt");
        CHECK(index > 0);

        ::kill(pid, SIGTERM);
        int32_t r = co_await CEventLoop::current()->waitFd(pidfd.get(), EFDE_READ, 10000);
        CHECK(r > 0);
        int st = 0;
        CHECK(::waitpid(pid, &st, WNOHANG) == pid);
        CHECK(WIFEXITED(st));
        CHECK(WEXITSTATUS(st) == 0);
        CHECK_FALSE(CFile::exists(sock));
        CHECK(co_await rt.linkIndex("wgt") == -ENODEV);
    }());
}
