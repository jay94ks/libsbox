// sbox-cni -> oci: the CNI plugin binary ADDs a network namespace to a bridge (with a port
// mapping) the way a CNI runtime does, an OCI container then runs in that namespace and serves
// TCP; CHECK passes; DEL takes the interface away again.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
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
     * Runs sbox-cni in the "host" namespace with the CNI environment.
     */
    TTask<ToolResult> cni(const TempDir& t, std::string hostNs, std::string command, std::string id, std::string netns,
                          std::string config) {
        RunOptions o;
        o.netns = std::move(hostNs);
        o.input = std::move(config);
        o.env.push_back("CNI_COMMAND=" + command);
        o.env.push_back("CNI_CONTAINERID=" + id);
        o.env.push_back("CNI_NETNS=" + netns);
        o.env.push_back("CNI_IFNAME=eth0");
        o.env.push_back("CNI_PATH=" + std::string(SBOX_TEST_BIN_DIR));
        co_return co_await runTool(t.path, tool("sbox-cni"), std::vector<std::string>(), o);
    }

}

TEST_CASE("sbox-cni ADD prepares a namespace an OCI container then runs in") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    std::string bundle = tmp / "bundle";
    REQUIRE(makeRootfs(bundle + "/rootfs"));
    std::string hostNs = tmp / "host";
    std::string podNs = tmp / "pod";
    REQUIRE(net::CNetns::create(hostNs) == SBOX_OK);
    REQUIRE(net::CNetns::create(podNs) == SBOX_OK);

    CEventLoop loop;
    loop.run([](const TempDir& t, std::string bundleDir, std::string host, std::string pod) -> TTask<void> {
        REQUIRE(co_await net::BringUpLoopback(host) == SBOX_OK);
        std::string config = R"({"cniVersion":"1.0.0","name":"e2ecni","type":"sbox-cni","bridge":"cni-e2e0",
            "stateDir":")" + (t / "net") + R"(",
            "ipam":{"type":"sbox","ranges":[[{"subnet":"10.124.0.0/24","gateway":"10.124.0.1"}]]},
            "capabilities":{"portMappings":true},
            "runtimeConfig":{"portMappings":[{"hostPort":18080,"containerPort":8080,"protocol":"tcp"}]}})";
        std::string id = "e2e-cni-" + randomSuffix();

        ToolResult add = co_await cni(t, host, "ADD", id, pod, config);
        REQUIRE_MESSAGE(add.code == 0, add.out, add.err);
        CJson result = parseJson(add.out);
        REQUIRE(result.get("ips").size() == 1);
        std::string address = result.get("ips").at(0).get("address").asString();
        CHECK(address.compare(0, 9, "10.124.0.") == 0);
        std::string ip = address.substr(0, address.find('/'));
        std::string mac;
        const CJson& ifs = result.get("interfaces");
        for (size_t i = 0; i < ifs.size(); ++i) {
            if (ifs.at(i).get("name").asString() == "eth0" && ifs.at(i).find("sandbox")) {
                mac = ifs.at(i).get("mac").asString();
            }
        }

        CHECK_FALSE(mac.empty());

        // --> A container in the pod namespace sees exactly the interface CNI reported.
        CJson cfg = defaultConfig(Args("/bin/sh", "-c", "ls /sys/class/net; cat /sys/class/net/eth0/address"));
        setNamespacePath(cfg, "network", pod);
        REQUIRE(writeConfig(bundleDir, cfg));
        ToolResult look = co_await runTool(t.path, tool("sbox"), Args("--root", t / "state", "run", "--bundle", bundleDir, id + "-look"));
        CHECK_MESSAGE(look.code == 0, look.err);
        CHECK(look.out == "eth0\nlo\n" + mac + "\n");

        // --> A server in the pod, reached directly and through the CNI port mapping.
        cfg = defaultConfig(Args("/bin/e2ehelper", "serve", "8080", "cni-ok", "2"));
        setNamespacePath(cfg, "network", pod);
        REQUIRE(writeConfig(bundleDir, cfg));
        ToolResult created = co_await runTool(t.path, tool("sbox"), Args("--root", t / "state", "run", "--detach", "--bundle", bundleDir, id));
        REQUIRE_MESSAGE(created.code == 0, created.err);

        RunOptions inHost;
        inHost.netns = host;
        ToolResult direct = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", ip, "8080"), inHost);
        CHECK_MESSAGE(direct.out == "cni-ok", direct.err);
        ToolResult mapped = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", "10.124.0.1", "18080"), inHost);
        CHECK_MESSAGE(mapped.out == "cni-ok", mapped.err);

        // --> The server exits after two clients; delete it.
        std::string status;
        for (int i = 0; i < 400 && status != "stopped"; ++i) {
            ToolResult st = co_await runTool(t.path, tool("sbox"), Args("--root", t / "state", "state", id));
            status = parseJson(st.out).get("status").asString();
            if (status != "stopped") {
                co_await CEventLoop::current()->sleepFor(25);
            }
        }

        CHECK(status == "stopped");
        ToolResult del = co_await runTool(t.path, tool("sbox"), Args("--root", t / "state", "delete", id));
        CHECK_MESSAGE(del.code == 0, del.err);

        ToolResult check = co_await cni(t, host, "CHECK", id, pod, config);
        CHECK_MESSAGE(check.code == 0, check.out);

        ToolResult rm = co_await cni(t, host, "DEL", id, pod, config);
        CHECK_MESSAGE(rm.code == 0, rm.out);

        // --> After DEL the namespace has only lo again.
        cfg = defaultConfig(Args("/bin/ls", "/sys/class/net"));
        setNamespacePath(cfg, "network", pod);
        REQUIRE(writeConfig(bundleDir, cfg));
        ToolResult after = co_await runTool(t.path, tool("sbox"), Args("--root", t / "state", "run", "--bundle", bundleDir, id + "-after"));
        CHECK(after.out == "lo\n");

        // --> DEL is idempotent.
        ToolResult again = co_await cni(t, host, "DEL", id, pod, config);
        CHECK(again.code == 0);
    }(tmp, bundle, hostNs, podNs));

    CHECK(net::CNetns::remove(podNs) == SBOX_OK);
    CHECK(net::CNetns::remove(hostNs) == SBOX_OK);
}
