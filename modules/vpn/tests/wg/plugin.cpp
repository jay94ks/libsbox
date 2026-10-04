// The wg-overlay driver behind the Docker network plugin: networks created through
// net::CDockerPlugin's handlers (what `docker network create -d sboxnet -o sbox.wg.overlay=...`
// sends) and through the sboxnet daemon, which registers the driver and restores user-space
// devices at startup.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sbox/http/client.hpp>
#include <sbox/net/docker.hpp>
#include <sbox/vpn/wg/overlay.hpp>
#include <sbox/vpn/wg/uapi.hpp>
#include "testutil.hpp"
#include <csignal>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef SBOX_TEST_BIN_DIR
#define SBOX_TEST_BIN_DIR ""
#endif

using namespace sbox;
using namespace sbox::vpn;
using namespace wgtest;

namespace {

    const char* NETWORK_ID = "0f5e2a7c9b1d4e3f8a6b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f";
    const char* ENDPOINT_ID = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    /* This host's overlay configuration with one (unreachable) remote host. */
    std::string overlayConfigText() {
        SWgOverlayConfig c;
        GenerateWgPrivateKey(c.privateKey);
        c.hostSubnet = prefix("10.210.1.0/24");
        c.mode = EWGM_USERSPACE;

        SWgOverlayHost b;
        b.name = "host-b";
        SWgKey bPriv;
        GenerateWgPrivateKey(bPriv);
        DeriveWgPublicKey(bPriv, b.publicKey);
        b.endpoint = "192.0.2.2:51820";
        b.subnet = prefix("10.210.2.0/24");
        c.peers.push_back(b);
        return c.toJson(true).dump();
    }

    /* The body dockerd sends for `docker network create -d sboxnet --subnet 10.210.0.0/16
       --ip-range 10.210.1.0/24 --gateway 10.210.1.1 -o sbox.wg.overlay=...`. */
    CJson createNetworkBody(const std::string& configText) {
        CJson generic = CJson::object();
        generic.set("sbox.wg.overlay", CJson(configText));
        CJson options = CJson::object();
        options.set("com.docker.network.generic", std::move(generic));
        options.set("com.docker.network.enable_ipv6", CJson(false));

        CJson v4 = CJson::object();
        v4.set("AddressSpace", CJson("LocalDefault"));
        v4.set("Pool", CJson("10.210.0.0/16"));
        v4.set("Gateway", CJson("10.210.1.1/16"));
        CJson v4s = CJson::array();
        v4s.push(std::move(v4));

        CJson body = CJson::object();
        body.set("NetworkID", CJson(NETWORK_ID));
        body.set("Options", std::move(options));
        body.set("IPv4Data", std::move(v4s));
        body.set("IPv6Data", CJson::array());
        return body;
    }

    /* {"NetworkID", "EndpointID"} plus one extra member. */
    CJson endpointBody(const char* key = nullptr, CJson value = CJson()) {
        CJson b = CJson::object();
        b.set("NetworkID", CJson(NETWORK_ID));
        b.set("EndpointID", CJson(ENDPOINT_ID));
        if (key) {
            b.set(key, std::move(value));
        }

        return b;
    }

    /* Returns the error text of a plugin reply (empty on success). */
    std::string errOf(const CJson& reply) {
        const CJson* e = reply.find("Err");
        return e && e->isString() ? e->asString() : std::string();
    }

    /* TCP echo from a child in `clientNs` to a listener in `serverNs` on `addr`. */
    TTask<int32_t> echoAcross(const std::string& clientNs, const std::string& serverNs, const char* addr) {
        CListener listener;
        int32_t r = listenIn(serverNs, addr, listener);
        if (r != SBOX_OK) {
            co_return r;
        }

        uint16_t port = listener.localEndpoint().port();
        std::string payload(1000, 'p');
        std::string target = addr;
        int64_t echoed = 0;
        r = co_await withChild(clientNs, [port, payload, target]() {
            return blockingEcho(target.c_str(), port, payload, 20);
        }, echoOnce(listener, 20000), echoed);

        co_return r == 0 && echoed != 1000 ? -EIO : r;
    }

    // -- Daemon helpers.

    std::string binary(const char* name) {
        return std::string(SBOX_TEST_BIN_DIR) + "/" + name;
    }

    /* Starts a program in the background with stdout/stderr on /dev/null. */
    pid_t startDaemon(std::vector<std::string> argv) {
        std::vector<char*> args;
        for (std::string& a : argv) {
            args.push_back(a.data());
        }

        args.push_back(nullptr);
        std::fflush(nullptr);
        pid_t pid = ::fork();
        if (pid == 0) {
            ::execv(args[0], args.data());
            ::_exit(127);
        }

        return pid;
    }

    /* Kills a daemon that is still running when a failed assertion leaves the test early
       (it would otherwise hold the test's output pipe open until ctest's timeout). */
    struct DaemonGuard {
        pid_t& pid;

        ~DaemonGuard() {
            if (pid > 0 && ::kill(pid, SIGKILL) == 0) {
                ::waitpid(pid, nullptr, 0);
            }
        }
    };

    /* Waits until `path` is a socket. */
    TTask<bool> waitForSocket(std::string path, int64_t timeoutMs = 30000) {
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        while (CEventLoop::nowMs() < deadline) {
            struct stat st{};
            if (::stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
                co_return true;
            }

            co_await CEventLoop::current()->sleepFor(10);
        }

        co_return false;
    }

    /* Stops a daemon with SIGINT and returns its wait status (-1 on failure). */
    TTask<int> stopDaemon(pid_t pid, int64_t timeoutMs = 30000) {
        int pidfd = int(::syscall(SYS_pidfd_open, pid, 0));
        if (pidfd < 0) {
            co_return -1;
        }

        ::kill(pid, SIGINT);
        if (co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, timeoutMs) == -ETIMEDOUT) {
            ::kill(pid, SIGKILL);
            co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, 10000);
        }

        siginfo_t info{};
        int status = -1;
        if (::waitid(idtype_t(P_PIDFD), id_t(pidfd), &info, WEXITED) == 0) {
            status = info.si_code == CLD_EXITED ? (info.si_status << 8) : (info.si_status & 0x7f);
        }

        ::close(pidfd);
        co_return status;
    }

    /* POSTs a plugin call over the daemon's socket. */
    TTask<CJson> pluginCall(http::CHttpClient& client, std::string socket, std::string path, CJson body) {
        http::SRequest req;
        req.method = "POST";
        req.unixSocket = socket;
        if (req.setUrl("http://plugin" + path) != SBOX_OK) {
            co_return CJson();
        }

        req.setJson(body, net::CDockerPlugin::contentType());
        http::SResponse res;
        std::string text;
        CJson out;
        int32_t rc = co_await client.fetch(std::move(req), res, text);
        if (rc != SBOX_OK || CJson::parse(text, out) != SBOX_OK) {
            MESSAGE("plugin call ", path, " failed: ", rc, " ", res.status, " ", text);
            co_return CJson();
        }

        co_return out;
    }

}

TEST_CASE("plugin: a wg-overlay network created through the Docker plugin handlers") {
    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        STempDir dir;
        std::string hostNs = dir.netns("host");
        std::string cNs = dir.netns("c1");
        REQUIRE_FALSE(hostNs.empty());
        REQUIRE_FALSE(cNs.empty());

        net::SNetworkManagerOptions o;
        o.stateDir = dir.join("state");
        o.hostNetns = hostNs;
        o.firewall = false;
        net::CNetworkManager mgr(o);
        SWgOverlayDriverOptions d;
        d.uapiDir = dir.join("uapi");
        auto overlay = std::make_shared<CWgOverlayDriver>(d);
        mgr.registerDriver(overlay);
        net::CDockerPlugin plugin(mgr);

        // --> The overlay option alone selects the driver (no sbox.driver).
        CJson reply = co_await plugin.handle("/NetworkDriver.CreateNetwork", createNetworkBody(overlayConfigText()));
        REQUIRE_MESSAGE(errOf(reply).empty(), errOf(reply));

        net::SNetwork network;
        REQUIRE(co_await mgr.getNetwork(NETWORK_ID, network) == SBOX_OK);
        CHECK(network.driver == WG_OVERLAY_DRIVER);
        CHECK(network.ipamDriver == "external");
        CHECK(network.option(WG_OVERLAY_OPTION).find("privateKey") == std::string::npos);
        std::string wgIf = network.driverState.get("interface").asString();
        std::string bridge = network.driverState.get("bridge").asString();
        CHECK(CFile::exists(WgUapiSocketPath(wgIf, d.uapiDir)));

        SWgDeviceStatus st;
        REQUIRE(co_await overlay->status(mgr, NETWORK_ID, st) == SBOX_OK);
        CHECK(st.peers.size() == 1);

        // --> Docker's IPAM picked the address from --ip-range.
        CJson iface = CJson::object();
        iface.set("Address", CJson("10.210.1.5/16"));
        reply = co_await plugin.handle("/NetworkDriver.CreateEndpoint", endpointBody("Interface", std::move(iface)));
        REQUIRE_MESSAGE(errOf(reply).empty(), errOf(reply));
        CHECK(!reply.get("Interface").get("MacAddress").asString().empty());
        CHECK(reply.get("Interface").get("Address").asString().empty());

        reply = co_await plugin.handle("/NetworkDriver.Join", endpointBody("SandboxKey", CJson(cNs)));
        REQUIRE_MESSAGE(errOf(reply).empty(), errOf(reply));
        CHECK(!reply.get("InterfaceName").get("SrcName").asString().empty());
        CHECK(reply.get("Gateway").asString() == "10.210.1.1");
        bool overlayRoute = false;
        const CJson& routes = reply.get("StaticRoutes");
        for (size_t i = 0; i < routes.size(); ++i) {
            overlayRoute = overlayRoute || routes.at(i).get("Destination").asString() == "10.210.0.0/16";
        }

        CHECK(overlayRoute);

        // --> Docker moves SrcName into the sandbox itself; the manager's join does the same here.
        net::SNetworkEndpoint ep;
        REQUIRE(co_await mgr.join(ENDPOINT_ID, cNs, "eth0", ep) == SBOX_OK);
        CHECK(ep.address(4).address.toString() == "10.210.1.5");

        // --> The container reaches this host's end of the overlay (the bridge gateway).
        CHECK(co_await echoAcross(cNs, hostNs, "10.210.1.1") == 0);

        // -- Teardown through the plugin: nothing is left on the host.
        CHECK(errOf(co_await plugin.handle("/NetworkDriver.Leave", endpointBody())).empty());
        CHECK(co_await mgr.leave(ENDPOINT_ID) == SBOX_OK);
        CHECK(errOf(co_await plugin.handle("/NetworkDriver.DeleteEndpoint", endpointBody())).empty());
        CJson del = CJson::object();
        del.set("NetworkID", CJson(NETWORK_ID));
        CHECK(errOf(co_await plugin.handle("/NetworkDriver.DeleteNetwork", del)).empty());

        net::CRtnl rt;
        REQUIRE(rt.open(hostNs) == SBOX_OK);
        CHECK(co_await rt.linkIndex(wgIf) == -ENODEV);
        CHECK(co_await rt.linkIndex(bridge) == -ENODEV);
    }());
}

TEST_CASE("sboxnet: the daemon serves wg-overlay networks and restores their devices after a restart") {
    if (::access(binary("sboxnet").c_str(), X_OK) != 0) {
        MESSAGE("skipped: sboxnet binary not built");
        return;
    }

    if (!canUseNetns()) {
        MESSAGE("skipped: needs root, network namespaces and /dev/net/tun");
        return;
    }

    STempDir dir;
    std::string hostNs = dir.netns("host");
    REQUIRE_FALSE(hostNs.empty());
    std::string sock = dir.join("sboxnet.sock");
    std::string uapi = dir.join("uapi");
    std::vector<std::string> argv = { binary("sboxnet"), "--socket", sock, "--state-dir", dir.join("state"), "--no-firewall",
                                      "--host-netns", hostNs, "--wg-uapi-dir", uapi };

    CEventLoop loop;
    pid_t pid = startDaemon(argv);
    DaemonGuard guard{ pid };
    REQUIRE(pid > 0);
    REQUIRE(loop.run(waitForSocket(sock)));

    std::string wgIf;
    loop.run([](std::string s, std::string stateDir, std::string& ifOut) -> TTask<void> {
        http::CHttpClient client;
        CJson reply = co_await pluginCall(client, s, "/NetworkDriver.CreateNetwork", createNetworkBody(overlayConfigText()));
        REQUIRE(reply.isObject());
        REQUIRE_MESSAGE(errOf(reply).empty(), errOf(reply));

        // --> Read the network the daemon persisted (the state directory is shared).
        net::SNetworkManagerOptions o;
        o.stateDir = stateDir;
        o.firewall = false;
        net::CNetworkManager reader(o);
        net::SNetwork network;
        REQUIRE(co_await reader.getNetwork(NETWORK_ID, network) == SBOX_OK);
        CHECK(network.driver == WG_OVERLAY_DRIVER);
        ifOut = network.driverState.get("interface").asString();
    }(sock, dir.join("state"), wgIf));

    REQUIRE_FALSE(wgIf.empty());
    std::string uapiSock = WgUapiSocketPath(wgIf, uapi);
    CHECK(loop.run(waitForSocket(uapiSock, 5000)));

    // --> The user-space device lives in the daemon: it goes away with it ...
    CHECK(loop.run(stopDaemon(pid)) == 0);
    pid = -1;
    auto linkGone = [](std::string ns, std::string name) -> TTask<bool> {
        net::CRtnl rt;
        if (rt.open(ns) != SBOX_OK) {
            co_return false;
        }

        co_return co_await rt.linkIndex(name) == -ENODEV;
    };

    CHECK(loop.run(linkGone(hostNs, wgIf)));

    // --> ... and the restarted daemon brings it back before serving.
    pid = startDaemon(argv);
    REQUIRE(pid > 0);
    REQUIRE(loop.run(waitForSocket(sock)));
    CHECK(loop.run(waitForSocket(uapiSock, 5000)));
    CHECK_FALSE(loop.run(linkGone(hostNs, wgIf)));

    loop.run([](std::string s) -> TTask<void> {
        http::CHttpClient client;
        CJson del = CJson::object();
        del.set("NetworkID", CJson(NETWORK_ID));
        CJson reply = co_await pluginCall(client, s, "/NetworkDriver.DeleteNetwork", del);
        REQUIRE(reply.isObject());
        CHECK_MESSAGE(errOf(reply).empty(), errOf(reply));
    }(sock));

    CHECK(loop.run(linkGone(hostNs, wgIf)));
    CHECK(loop.run(stopDaemon(pid)) == 0);
    pid = -1;
}
