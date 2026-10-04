// net -> oci and net -> CSandbox: a bridge network made by CNetworkManager in a throwaway "host"
// network namespace; containers joined to it through the network namespace path in config.json
// talk TCP to each other, the "host" reaches one through a port mapping (bridge address and
// 127.0.0.1), and a CSandbox with EBNET_NAMESPACE joins another endpoint's namespace.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
#include <sbox/box/sandbox.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/network.hpp>

using namespace sbox;
using namespace e2e;

namespace {

    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root (or no private mount namespace); skipping");
            return false;
        }

        if (!haveTools()) {
            MESSAGE("CLI tools were not built; skipping");
            return false;
        }

        TempDir probe;
        if (net::CNetns::create(probe / "ns") != SBOX_OK) {
            MESSAGE("cannot create network namespaces; skipping");
            return false;
        }

        net::CNetns::remove(probe / "ns");
        return true;
    }

    /**
     * Writes a bundle whose root is the shared rootfs and whose network namespace is `netns`.
     */
    void writeNetBundle(const std::string& bundle, const std::string& rootfs, const std::string& netns, std::vector<std::string> args) {
        CFile::makeDirs(bundle, 0755);
        CJson config = defaultConfig(std::move(args));
        config["root"].set("path", rootfs);
        setNamespacePath(config, "network", netns);
        REQUIRE(writeConfig(bundle, config));
    }

}

TEST_CASE("containers on a bridge network talk TCP, a port mapping reaches one from the host, a sandbox joins an endpoint") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string rootfs = tmp / "rootfs";
    REQUIRE(makeRootfs(rootfs));
    std::string sandboxBin = tmp / "sbx";
    REQUIRE(copyFile(SBOX_E2E_HELPER, sandboxBin + "/e2ehelper"));
    ::chmod(sandboxBin.c_str(), 0755);

    std::string hostNs = tmp / "host";
    REQUIRE(net::CNetns::create(hostNs) == SBOX_OK);
    std::vector<std::string> ns;
    for (const char* name : { "c1", "c2", "c3" }) {
        ns.push_back(tmp / name);
        REQUIRE(net::CNetns::create(ns.back()) == SBOX_OK);
    }

    CEventLoop loop;
    loop.run([](const TempDir& t, std::string root, std::string hostNetns, std::vector<std::string> nsPaths, std::string sbx) -> TTask<void> {
        net::SNetworkManagerOptions mo;
        mo.stateDir = t / "net";
        mo.hostNetns = hostNetns;
        net::CNetworkManager mgr(mo);
        // --> A real host has "lo" up; the throwaway "host" namespace needs it for 127.0.0.1.
        REQUIRE(co_await net::BringUpLoopback(hostNetns) == SBOX_OK);
        if (!co_await haveNftables(hostNetns)) {
            MESSAGE("nf_tables unavailable (port mappings need it); skipping");
            co_return;
        }

        net::SNetworkCreate req;
        req.name = "e2enet";
        net::SSubnetConfig sc;
        REQUIRE(net::SIpPrefix::parse("10.123.0.0/24", sc.subnet) == SBOX_OK);
        req.subnets.push_back(sc);
        net::SNetwork network;
        REQUIRE(co_await mgr.createNetwork(req, network) == SBOX_OK);
        std::string gateway = network.subnets[0].gateway.toString();
        CHECK(gateway == "10.123.0.1");

        // --> Container 1 publishes 8080 on an ephemeral host port.
        std::vector<net::SNetworkEndpoint> eps(3);
        for (size_t i = 0; i < 3; ++i) {
            net::SEndpointCreate ec;
            ec.containerId = "e2e-c" + std::to_string(i + 1);
            if (i == 0) {
                net::SPortMapping pm;
                REQUIRE(net::SPortMapping::parse("0:8080/tcp", pm) == SBOX_OK);
                ec.ports.push_back(pm);
            }

            REQUIRE(co_await mgr.connect("e2enet", nsPaths[i], ec, eps[i]) == SBOX_OK);
            CHECK(eps[i].sandboxIfName == "eth0");
        }

        std::string ip1 = eps[0].address(4).address.toString();
        REQUIRE(eps[0].ports.size() == 1);
        uint16_t hostPort = eps[0].ports[0].hostPort;
        CHECK(hostPort >= 32768);

        // --> Container 1 serves four clients: container 2, the host twice, the sandbox.
        std::string bundle1 = t / "bundle1";
        writeNetBundle(bundle1, root, nsPaths[0], { "/bin/e2ehelper", "serve", "8080", "hello-e2e", "4" });
        oci::SRuntimeOptions ro;
        ro.root = t / "state";
        oci::CRuntime rt(ro);
        CStream out1;
        CFd out1Child;
        REQUIRE(CPipe::createForChild(out1, out1Child, true) == SBOX_OK);
        oci::SCreateOptions co;
        co.bundle = bundle1;
        co.stdio = { { out1Child.get(), 1 }, { out1Child.get(), 2 } };
        oci::CContainerProcess server;
        std::string id1 = "e2e-net1-" + randomSuffix();
        REQUIRE_MESSAGE(co_await rt.create(id1, co, &server) == SBOX_OK, rt.lastError());
        out1Child.reset();
        REQUIRE(co_await rt.start(id1) == SBOX_OK);

        // --> The container sees its own address on eth0 (inside the namespace from config.json).
        std::string bundle2 = t / "bundle2";
        writeNetBundle(bundle2, root, nsPaths[1], { "/bin/e2ehelper", "fetch", ip1, "8080" });
        ContainerRun c2 = co_await runContainer(t / "state", bundle2, "e2e-net2-" + randomSuffix());
        REQUIRE_MESSAGE(c2.error == SBOX_OK, c2.message);
        CHECK(c2.code == 0);
        CHECK(c2.out == "hello-e2e");

        // --> From the "host": the published port on the bridge address and on 127.0.0.1.
        RunOptions inHost;
        inHost.netns = hostNetns;
        ToolResult viaBridge = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", gateway, std::to_string(hostPort)), inHost);
        CHECK_MESSAGE(viaBridge.code == 0, viaBridge.out, viaBridge.err);
        CHECK(viaBridge.out == "hello-e2e");
        ToolResult viaLoopback = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", "127.0.0.1", std::to_string(hostPort)), inHost);
        CHECK_MESSAGE(viaLoopback.code == 0, viaLoopback.out, viaLoopback.err);
        CHECK(viaLoopback.out == "hello-e2e");

        // --> A sandbox in the third endpoint's namespace (EBNET_NAMESPACE).
        SBoxPolicy p;
        p.mounts = SBoxPolicy::systemMounts(true);
        p.mounts.push_back(SBoxMount{ sbx, "/sbx", EBMNT_READ_ONLY });
        p.network = EBNET_NAMESPACE;
        p.netnsPath = nsPaths[2];
        p.wallTimeoutMs = 20000;
        std::vector<std::string> sargs;
        sargs.push_back("/sbx/e2ehelper");
        sargs.push_back("fetch");
        sargs.push_back(ip1);
        sargs.push_back("8080");
        CSandbox box = co_await CSandbox::spawn(p, sargs);
        REQUIRE_MESSAGE(box.isValid(), box.failedStep(), " ", box.error());
        box.stdinPipe().close();
        std::string sout = co_await readStream(box.stdoutPipe());
        SBoxResult sr = co_await box.wait();
        CHECK(sr.reason == EBEXIT_NORMAL);
        CHECK(sr.exitCode == 0);
        CHECK(sout == "hello-e2e");

        // --> Container 1 exits after its fourth client.
        std::string serverOut = co_await readStream(out1);
        SExitStatus es;
        REQUIRE(co_await server.wait(es, 20000) == SBOX_OK);
        CHECK(es.exited);
        CHECK(es.exitCode == 0);
        CHECK(serverOut == "listening\n");
        CHECK(co_await rt.remove(id1, true) == SBOX_OK);

        // --> A namespace that left the network cannot reach container 1 any more.
        CHECK(co_await mgr.disconnect("e2enet", "e2e-c3") == SBOX_OK);
        RunOptions inC3;
        inC3.netns = nsPaths[2];
        ToolResult cut = co_await runTool(t.path, SBOX_E2E_HELPER, Args("connect", ip1, "8080"), inC3);
        CHECK(cut.code != 0);

        CHECK(co_await mgr.disconnect("e2enet", "e2e-c1") == SBOX_OK);
        CHECK(co_await mgr.disconnect("e2enet", "e2e-c2") == SBOX_OK);
        CHECK(co_await mgr.deleteNetwork("e2enet") == SBOX_OK);
    }(tmp, rootfs, hostNs, ns, sandboxBin));

    for (const std::string& path : ns) {
        CHECK(net::CNetns::remove(path) == SBOX_OK);
    }

    CHECK(net::CNetns::remove(hostNs) == SBOX_OK);
}
