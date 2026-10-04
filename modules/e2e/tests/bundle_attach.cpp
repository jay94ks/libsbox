// image + vol + net -> oci through the CLI: `sbox-image bundle` with Docker-style -v / --tmpfs
// (vol::PrepareContainerMounts) and --network / --publish (net::CNetworkManager::connect into a
// new named netns), then `sbox run`, a published port reached from the throwaway "host"
// namespace, and `sbox-image rm -v` undoing the network, the namespace and the volumes.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
#include <sbox/net/netns.hpp>
#include <sbox/net/network.hpp>
#include <sbox/vol/store.hpp>
#include <algorithm>
#include <dirent.h>

using namespace sbox;
using namespace e2e;

namespace {

    const std::string TAG = "e2e/attach:1";

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

    /* Waits until a detached container stopped, then deletes it. */
    TTask<std::string> waitStoppedAndDelete(const TempDir& t, std::string state, std::string id) {
        std::string status;
        for (int i = 0; i < 800 && status != "stopped"; ++i) {
            ToolResult st = co_await runTool(t.path, tool("sbox"), Args("--root", state, "state", id));
            status = parseJson(st.out).get("status").asString();
            if (status != "stopped") {
                co_await CEventLoop::current()->sleepFor(25);
            }
        }

        co_await runTool(t.path, tool("sbox"), Args("--root", state, "delete", "--force", id));
        co_return status;
    }

}

TEST_CASE("sbox-image bundle -v/--tmpfs/--network/--publish, sbox run, and rm -v cleans up") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    ImageFixture img;
    REQUIRE(buildImage(tmp.path, img));
    std::string archivePath = tmp / "image.tar";
    REQUIRE(writeDockerSave(img, TAG, archivePath));

    std::string hostNs = tmp / "host";
    REQUIRE(net::CNetns::create(hostNs) == SBOX_OK);
    std::string spareNs = tmp / "spare";
    REQUIRE(net::CNetns::create(spareNs) == SBOX_OK);

    CEventLoop loop;
    loop.run([](const TempDir& t, std::string archive, std::string host, std::string spare) -> TTask<void> {
        REQUIRE(co_await net::BringUpLoopback(host) == SBOX_OK);
        if (!co_await haveNftables(host)) {
            MESSAGE("nf_tables unavailable (port mappings need it); skipping");
            co_return;
        }

        std::string store = t / "images";
        std::string volRoot = t / "volumes";
        std::string netState = t / "net";
        std::string netnsDir = t / "netns";
        std::string state = t / "state";

        ToolResult load = co_await runTool(t.path, tool("sbox-image"), Args("--root", store, "load", "-i", archive));
        REQUIRE_MESSAGE(load.code == 0, load.err);

        // --> The network is made first (`sboxnet network create`, like docker network create);
        // the "host" is a throwaway netns, so every tool runs inside it.
        RunOptions inHost;
        inHost.netns = host;
        ToolResult created = co_await runTool(t.path, tool("sboxnet"),
            Args("--state-dir", netState, "network", "create", "--subnet", "10.125.0.0/24", "e2eattach"), inHost);
        REQUIRE_MESSAGE(created.code == 0, created.err);
        ToolResult listed = co_await runTool(t.path, tool("sboxnet"), Args("--state-dir", netState, "network", "ls", "-q"), inHost);
        CHECK(listed.out == "e2eattach\n");
        ToolResult inspected = co_await runTool(t.path, tool("sboxnet"), Args("--state-dir", netState, "network", "inspect", "e2eattach"), inHost);
        CHECK(parseJson(inspected.out).at(0).get("Driver").asString() == "bridge");

        net::SNetworkManagerOptions mo;
        mo.stateDir = netState;
        mo.hostNetns = host;
        net::CNetworkManager mgr(mo);

        // -- Bundle with a named volume (copy-up of the image's /data), an anonymous volume, a
        // tmpfs, the network and an ephemeral published port.
        std::string bundle = t / "bundle";
        ToolResult b = co_await runTool(t.path, tool("sbox-image"),
            Args("--root", store, "--json", "bundle",
                 "-v", "e2edata:/data", "-v", "/anon", "--tmpfs", "/scratch:size=1m", "--volume-root", volRoot,
                 "--network", "e2eattach", "--publish", "0:8080/tcp", "--net-state-dir", netState, "--netns-dir", netnsDir,
                 TAG, bundle, "--",
                 "/bin/sh", "-c", "cat /data/seed.txt > /data/copy && echo tmp > /scratch/x && echo anon > /anon/y && "
                                  "exec /bin/e2ehelper serve 8080 hello-attach 2"),
            inHost);
        REQUIRE_MESSAGE(b.code == 0, b.err);
        CJson info = parseJson(b.out);
        std::string rootId = info.get("Id").asString();
        REQUIRE_FALSE(rootId.empty());
        std::string netnsPath = info.get("Netns").asString();
        CHECK(netnsPath == netnsDir + "/" + rootId);
        CHECK(net::CNetns::isNetns(netnsPath));
        const CJson& n = info.get("Network");
        CHECK(n.get("Name").asString() == "e2eattach");
        std::string address = n.get("Address").asString();
        CHECK(address.compare(0, 9, "10.125.0.") == 0);
        std::string ip = address.substr(0, address.find('/'));
        REQUIRE(n.get("Ports").size() == 1);
        int64_t hostPort = n.get("Ports").at(0).get("HostPort").asInt();
        CHECK(hostPort >= 32768);
        REQUIRE(info.get("Volumes").size() == 2);

        // --> config.json carries the namespace path and the three mounts.
        CJson cfg = readConfig(bundle);
        std::string nsInConfig;
        const CJson& namespaces = cfg.get("linux").get("namespaces");
        for (size_t i = 0; i < namespaces.size(); ++i) {
            if (namespaces.at(i).get("type").asString() == "network") {
                nsInConfig = namespaces.at(i).get("path").asString();
            }
        }

        CHECK(nsInConfig == netnsPath);
        std::vector<std::string> targets;
        const CJson& mounts = cfg.get("mounts");
        for (size_t i = 0; i < mounts.size(); ++i) {
            targets.push_back(mounts.at(i).get("destination").asString());
        }

        CHECK(std::find(targets.begin(), targets.end(), "/data") != targets.end());
        CHECK(std::find(targets.begin(), targets.end(), "/anon") != targets.end());
        CHECK(std::find(targets.begin(), targets.end(), "/scratch") != targets.end());

        // -- Run it detached and reach the server from the "host": the container address and
        // the published port on 127.0.0.1.
        std::string id = "e2e-attach-" + randomSuffix();
        ToolResult run = co_await runTool(t.path, tool("sbox"), Args("--root", state, "run", "--detach", "--bundle", bundle, id));
        REQUIRE_MESSAGE(run.code == 0, run.err);
        ToolResult direct = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", ip, "8080"), inHost);
        CHECK_MESSAGE(direct.out == "hello-attach", direct.err);
        ToolResult mapped = co_await runTool(t.path, SBOX_E2E_HELPER, Args("fetch", "127.0.0.1", std::to_string(hostPort)), inHost);
        CHECK_MESSAGE(mapped.out == "hello-attach", mapped.err);
        CHECK(co_await waitStoppedAndDelete(t, state, id) == "stopped");

        // --> The named volume got the image content and kept what the container wrote.
        vol::SVolumeStoreOptions so;
        so.root = volRoot;
        vol::CVolumeStore volumes(so);
        vol::SVolume data;
        REQUIRE(volumes.inspect("e2edata", data) == SBOX_OK);
        std::string copied;
        CHECK(CFile::readAll(data.mountpoint + "/copy", copied) == SBOX_OK);
        CHECK(copied == "seeded by the image\n");
        CHECK(data.users == std::vector<std::string>{ rootId });
        std::vector<vol::SVolume> all;
        REQUIRE(volumes.list(all) == SBOX_OK);
        CHECK(all.size() == 2);

        // -- rm -v: endpoint gone, namespace unpinned, volumes released, the anonymous one removed.
        ToolResult rm = co_await runTool(t.path, tool("sbox-image"), Args("--root", store, "rm", "-v", rootId), inHost);
        CHECK_MESSAGE(rm.code == 0, rm.err);
        std::vector<net::SNetworkEndpoint> eps;
        REQUIRE(co_await mgr.listEndpoints(std::string(), eps) == SBOX_OK);
        CHECK(eps.empty());
        CHECK_FALSE(CFile::exists(netnsPath));
        REQUIRE(volumes.inspect("e2edata", data) == SBOX_OK);
        CHECK(data.users.empty());
        all.clear();
        REQUIRE(volumes.list(all) == SBOX_OK);
        REQUIRE(all.size() == 1);
        CHECK(all[0].name == "e2edata");
        ToolResult ps = co_await runTool(t.path, tool("sbox-image"), Args("--root", store, "--json", "ps"));
        CHECK(parseJson(ps.out).size() == 0);

        // -- --netns joins an existing namespace and leaves it alone on rm.
        std::string bundle2 = t / "bundle-netns";
        ToolResult b2 = co_await runTool(t.path, tool("sbox-image"),
            Args("--root", store, "--json", "bundle", "--netns", spare, TAG, bundle2, "--", "/bin/ls", "/sys/class/net"));
        REQUIRE_MESSAGE(b2.code == 0, b2.err);
        ToolResult ls = co_await runTool(t.path, tool("sbox"), Args("--root", state, "run", "--bundle", bundle2, id + "-ns"));
        CHECK(ls.out == "lo\n");
        CHECK((co_await runTool(t.path, tool("sbox-image"), Args("--root", store, "rm", parseJson(b2.out).get("Id").asString()))).code == 0);
        CHECK(net::CNetns::isNetns(spare));

        // -- Invalid combinations fail before anything is left behind.
        std::string bundle3 = t / "bundle-bad";
        ToolResult bad = co_await runTool(t.path, tool("sbox-image"),
            Args("--root", store, "bundle", "--publish", "8080:80", TAG, bundle3), inHost);
        CHECK(bad.code == 1);
        CHECK(bad.err.find("--publish needs --network") != std::string::npos);
        CHECK_FALSE(CFile::exists(bundle3 + "/config.json"));
        ToolResult unknown = co_await runTool(t.path, tool("sbox-image"),
            Args("--root", store, "bundle", "--network", "missing", "--net-state-dir", netState, "--netns-dir", netnsDir, TAG, bundle3),
            inHost);
        CHECK(unknown.code == 1);
        CHECK_FALSE(CFile::exists(bundle3 + "/config.json"));
        ps = co_await runTool(t.path, tool("sbox-image"), Args("--root", store, "--json", "ps"));
        CHECK(parseJson(ps.out).size() == 0);
        // --> The namespace made for the failed connect was unpinned again.
        size_t pinned = 0;
        if (DIR* d = ::opendir(netnsDir.c_str())) {
            while (dirent* e = ::readdir(d)) {
                pinned += e->d_name[0] != '.';
            }

            ::closedir(d);
        }

        CHECK(pinned == 0);

        ToolResult removed = co_await runTool(t.path, tool("sboxnet"), Args("--state-dir", netState, "network", "rm", "e2eattach"), inHost);
        CHECK_MESSAGE(removed.code == 0, removed.err);
        std::vector<net::SNetwork> left;
        REQUIRE(co_await mgr.listNetworks(left) == SBOX_OK);
        CHECK(left.empty());
    }(tmp, archivePath, hostNs, spareNs));

    CHECK(net::CNetns::remove(spareNs) == SBOX_OK);
    CHECK(net::CNetns::remove(hostNs) == SBOX_OK);
}
