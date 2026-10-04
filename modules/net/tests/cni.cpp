#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/net/cni.hpp>
#include <sbox/net/network.hpp>
#include <sbox/net/rtnl.hpp>
#include "testutil.hpp"
#include <csignal>
#include <fcntl.h>
#include <sched.h>
#include <set>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;
using namespace sbox::net;

#ifndef SBOX_TEST_BIN_DIR
#define SBOX_TEST_BIN_DIR ""
#endif

namespace {

    struct SRun {
        int32_t status = -1;
        std::string out;
        CJson json;
    };

    /* Runs the sbox-cni binary inside `hostNs` with CNI environment and stdin. */
    TTask<SRun> runBinary(std::string hostNs, std::vector<std::string> env, std::string input) {
        SRun result;
        std::string bin = std::string(SBOX_TEST_BIN_DIR) + "/sbox-cni";

        CStream inParent, outParent;
        CFd inChild, outChild;
        REQUIRE(CPipe::createForChild(inParent, inChild, false) == SBOX_OK);
        REQUIRE(CPipe::createForChild(outParent, outChild, true) == SBOX_OK);

        CFd ns(::open(hostNs.c_str(), O_RDONLY | O_CLOEXEC));
        REQUIRE(ns.isValid());

        std::vector<char*> envp;
        for (std::string& e : env) {
            envp.push_back(e.data());
        }

        envp.push_back(nullptr);
        char* argv[] = { bin.data(), nullptr };

        pid_t pid = ::fork();
        REQUIRE(pid >= 0);
        if (pid == 0) {
            if (::setns(ns.get(), CLONE_NEWNET) < 0) {
                ::_exit(126);
            }

            ::dup2(inChild.get(), 0);
            ::dup2(outChild.get(), 1);
            ::execve(bin.c_str(), argv, envp.data());
            ::_exit(127);
        }

        inChild.reset();
        outChild.reset();
        int pidfd = int(::syscall(SYS_pidfd_open, pid, 0));

        co_await inParent.send(BytesOf(input));
        inParent.close();

        std::vector<uint8_t> all;
        co_await outParent.recvAll(all, 1 << 20, 60000);
        result.out.assign(all.begin(), all.end());

        co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, 60000);
        siginfo_t info{};
        ::waitid(idtype_t(P_PIDFD), id_t(pidfd), &info, WEXITED);
        ::close(pidfd);
        result.status = info.si_code == CLD_EXITED ? info.si_status : -1;
        CJson::parse(result.out, result.json);
        co_return result;
    }

    std::vector<std::string> cniEnv(const char* command, const std::string& cid, const std::string& netns, const char* ifname) {
        return {
            std::string("CNI_COMMAND=") + command,
            "CNI_CONTAINERID=" + cid,
            "CNI_NETNS=" + netns,
            std::string("CNI_IFNAME=") + ifname,
            "CNI_PATH=/opt/cni/bin",
            "CNI_ARGS=IgnoreUnknown=1;K8S_POD_NAME=x",
        };
    }

}

TEST_CASE("CNI VERSION and error reporting") {
    CEventLoop loop;
    std::string out;

    SCniRequest v;
    v.command = "VERSION";
    v.config = R"({"cniVersion":"1.0.0"})";
    CHECK(loop.run(RunCni(v, out)) == 0);
    CJson j;
    REQUIRE(CJson::parse(out, j) == SBOX_OK);
    CHECK(j.get("cniVersion").asString() == "1.0.0");
    CHECK(j.get("supportedVersions").size() == 4);

    SCniRequest bad;
    bad.command = "STATUS";
    bad.config = R"({"cniVersion":"1.0.0","name":"x","type":"sbox-cni"})";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    REQUIRE(CJson::parse(out, j) == SBOX_OK);
    CHECK(j.get("code").asInt() == ECNI_INVALID_ENVIRONMENT);

    bad.command = "ADD";
    bad.config = "{nope";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_DECODE_FAILURE);

    bad.config = R"({"cniVersion":"9.9.9","name":"x","type":"sbox-cni"})";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_INCOMPATIBLE_VERSION);

    bad.config = R"({"cniVersion":"1.0.0","type":"sbox-cni"})";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_INVALID_CONFIG);

    bad.config = R"({"cniVersion":"1.0.0","name":"x","type":"sbox-cni","driver":"macvlan"})";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_INVALID_CONFIG);

    bad.config = R"({"cniVersion":"1.0.0","name":"x","type":"sbox-cni"})";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_INVALID_ENVIRONMENT);

    bad.config = R"({"cniVersion":"0.3.1","name":"x","type":"sbox-cni"})";
    bad.command = "CHECK";
    CHECK(loop.run(RunCni(bad, out)) == 1);
    CJson::parse(out, j);
    CHECK(j.get("code").asInt() == ECNI_INCOMPATIBLE_VERSION);
}

TEST_CASE("sbox-cni binary ADD / CHECK / DEL round trip with bridge and macvlan configs") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    std::string bin = std::string(SBOX_TEST_BIN_DIR) + "/sbox-cni";
    if (!CFile::exists(bin)) {
        MESSAGE("skipped: sbox-cni was not built (SBOX_BUILD_CLI=OFF)");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string c1 = dir.netns("c1");
    std::string c2 = dir.netns("c2");
    std::string c3 = dir.netns("c3");
    REQUIRE(!c3.empty());
    std::string state = dir.join("state");

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        std::string conf = R"({"cniVersion":"1.0.0","name":"podnet","type":"sbox-cni","bridge":"cni-test0",
            "ipMasq":true,"mtu":1450,"stateDir":")" + state + R"(",
            "ipam":{"type":"host-local","ranges":[[{"subnet":"10.99.0.0/24","rangeStart":"10.99.0.10"}]],
                    "routes":[{"dst":"0.0.0.0/0"},{"dst":"192.0.2.0/24"}]},
            "dns":{"nameservers":["10.99.0.1"]}})";

        SRun add = co_await runBinary(host, cniEnv("ADD", "cid-one", c1, "eth0"), conf);
        REQUIRE_MESSAGE(add.status == 0, add.out);
        const CJson& r = add.json;
        CHECK(r.get("cniVersion").asString() == "1.0.0");
        REQUIRE(r.get("interfaces").size() == 3);
        CHECK(r.get("interfaces").at(0).get("name").asString() == "cni-test0");
        CHECK(r.get("interfaces").at(2).get("sandbox").asString() == c1);
        REQUIRE(r.get("ips").size() == 1);
        CHECK(r.get("ips").at(0).get("address").asString() == "10.99.0.10/24");
        CHECK(r.get("ips").at(0).get("gateway").asString() == "10.99.0.1");
        CHECK(r.get("ips").at(0).get("interface").asInt() == 2);
        CHECK(r.get("ips").at(0).find("version") == nullptr);
        CHECK(r.get("routes").size() == 2);
        CHECK(r.get("dns").get("nameservers").size() == 1);

        CRtnl rt1;
        rt1.open(c1);
        SLinkInfo eth;
        CHECK(co_await rt1.getLink("eth0", eth) == SBOX_OK);
        CHECK(eth.mtu == 1450);
        std::vector<SRouteInfo> routes;
        co_await rt1.listRoutes(routes, AF_INET);
        bool extra = false;
        for (const SRouteInfo& rt : routes) {
            extra = extra || rt.destination.toString() == "192.0.2.0/24";
        }

        CHECK(extra);

        // --> CHECK with the previous result.
        CJson withPrev;
        CJson::parse(conf, withPrev);
        withPrev.set("prevResult", add.json);
        SRun check = co_await runBinary(host, cniEnv("CHECK", "cid-one", c1, "eth0"), withPrev.dump());
        CHECK_MESSAGE(check.status == 0, check.out);

        // --> A second container, with the legacy result format and a static IP via CNI_ARGS.
        std::string legacy = conf;
        legacy.replace(legacy.find("1.0.0"), 5, "0.4.0");
        std::vector<std::string> env2 = cniEnv("ADD", "cid-two", c2, "net1");
        env2.back() = "CNI_ARGS=IgnoreUnknown=1;IP=10.99.0.77";
        SRun add2 = co_await runBinary(host, env2, legacy);
        REQUIRE_MESSAGE(add2.status == 0, add2.out);
        CHECK(add2.json.get("ips").at(0).get("version").asString() == "4");
        CHECK(add2.json.get("ips").at(0).get("address").asString() == "10.99.0.77/24");

        // --> CHECK notices a broken attachment.
        CRtnl rt2;
        rt2.open(c2);
        co_await rt2.setUp(co_await rt2.linkIndex("net1"), false);
        SRun broken = co_await runBinary(host, cniEnv("CHECK", "cid-two", c2, "net1"), legacy);
        CHECK(broken.status == 1);
        CHECK(broken.json.get("code").asInt() == ECNI_CHECK_FAILED);

        // --> DEL removes the interface and is idempotent.
        SRun del = co_await runBinary(host, cniEnv("DEL", "cid-one", c1, "eth0"), conf);
        CHECK_MESSAGE(del.status == 0, del.out);
        CHECK(co_await rt1.linkIndex("eth0") == -ENODEV);
        SRun del2 = co_await runBinary(host, cniEnv("DEL", "cid-one", c1, "eth0"), conf);
        CHECK(del2.status == 0);
        SRun del3 = co_await runBinary(host, cniEnv("DEL", "cid-two", "", "net1"), legacy);
        CHECK(del3.status == 0);

        // --> The address is free again: a new ADD gets the first address back.
        SRun again = co_await runBinary(host, cniEnv("ADD", "cid-three", c3, "eth0"), conf);
        REQUIRE_MESSAGE(again.status == 0, again.out);
        CHECK(again.json.get("ips").at(0).get("address").asString() == "10.99.0.11/24");
        SRun del4 = co_await runBinary(host, cniEnv("DEL", "cid-three", c3, "eth0"), conf);
        CHECK(del4.status == 0);

        // --> macvlan on a host uplink.
        CRtnl hrt;
        hrt.open(host);
        REQUIRE(co_await hrt.createVeth("uplink0", "uplink0p") == SBOX_OK);
        co_await hrt.setUp(co_await hrt.linkIndex("uplink0"));

        std::string mconf = R"({"cniVersion":"1.0.0","name":"lan","type":"sbox-cni","driver":"macvlan",
            "master":"uplink0","mode":"bridge","stateDir":")" + state + R"(",
            "ipam":{"type":"sbox","subnet":"192.168.77.0/24","gateway":"192.168.77.1",
                    "rangeStart":"192.168.77.200","rangeEnd":"192.168.77.210"}})";
        SRun madd = co_await runBinary(host, cniEnv("ADD", "cid-mv", c1, "eth0"), mconf);
        REQUIRE_MESSAGE(madd.status == 0, madd.out);
        CHECK(madd.json.get("interfaces").size() == 1);
        CHECK(madd.json.get("ips").at(0).get("address").asString() == "192.168.77.200/24");
        CHECK(madd.json.get("ips").at(0).get("interface").asInt() == 0);
        SLinkInfo mv;
        CHECK(co_await rt1.getLink("eth0", mv) == SBOX_OK);
        CHECK(mv.kind == "macvlan");
        SRun mdel = co_await runBinary(host, cniEnv("DEL", "cid-mv", c1, "eth0"), mconf);
        CHECK(mdel.status == 0);
        CHECK(co_await rt1.linkIndex("eth0") == -ENODEV);

        // --> Concurrent ADDs from separate processes get distinct addresses.
        std::vector<std::string> nss;
        for (int32_t i = 0; i < 4; ++i) {
            nss.push_back(dir.netns("par" + std::to_string(i)));
        }

        std::vector<SRun> runs(4);
        int32_t finished = 0;
        for (int32_t i = 0; i < 4; ++i) {
            CEventLoop::current()->spawn([](std::string h, std::vector<std::string> e, std::string c, SRun* out, int32_t* done) -> TTask<void> {
                *out = co_await runBinary(h, e, c);
                ++*done;
            }(host, cniEnv("ADD", "par-" + std::to_string(i), nss[size_t(i)], "eth0"), conf, &runs[size_t(i)], &finished));
        }

        while (finished < 4) {
            co_await CEventLoop::current()->sleepFor(5);
        }

        std::set<std::string> addrs;
        for (const SRun& run : runs) {
            CHECK_MESSAGE(run.status == 0, run.out);
            addrs.insert(run.json.get("ips").at(0).get("address").asString());
        }

        CHECK(addrs.size() == 4);

        for (int32_t i = 0; i < 4; ++i) {
            SRun d = co_await runBinary(host, cniEnv("DEL", "par-" + std::to_string(i), nss[size_t(i)], "eth0"), conf);
            CHECK(d.status == 0);
        }

        // --> The network (bridge) stays for future ADDs, like the reference bridge plugin.
        CHECK(co_await hrt.linkIndex("cni-test0") > 0);
    };

    loop.run(body());
}
