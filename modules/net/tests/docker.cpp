#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/docker.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/net/rtnl.hpp>
#include "testutil.hpp"

using namespace sbox;
using namespace sbox::net;

namespace {

    CJson parse(const char* text) {
        CJson j;
        REQUIRE(CJson::parse(text, j) == SBOX_OK);
        return j;
    }

}

TEST_CASE("plugin activation, capabilities and errors need no kernel access") {
    nettest::STempDir dir;
    SNetworkManagerOptions opts;
    opts.stateDir = dir.join("state");
    CNetworkManager mgr(opts);
    CDockerPlugin plugin(mgr);
    CEventLoop loop;

    CJson act = loop.run(plugin.handle("/Plugin.Activate", CJson()));
    REQUIRE(act.get("Implements").size() == 2);
    CHECK(act.get("Implements").at(0).asString() == "NetworkDriver");
    CHECK(act.get("Implements").at(1).asString() == "IpamDriver");

    CJson caps = loop.run(plugin.handle("/NetworkDriver.GetCapabilities", CJson::object()));
    CHECK(caps.get("Scope").asString() == "local");
    CHECK(caps.get("ConnectivityScope").asString() == "local");

    CJson ipamCaps = loop.run(plugin.handle("/IpamDriver.GetCapabilities", CJson::object()));
    CHECK(ipamCaps.get("RequiresMACAddress").asBool(true) == false);

    CJson spaces = loop.run(plugin.handle("/IpamDriver.GetDefaultAddressSpaces", CJson::object()));
    CHECK(spaces.get("LocalDefaultAddressSpace").asString() == "local");
    CHECK(spaces.get("GlobalDefaultAddressSpace").asString() == "global");

    CJson unknown = loop.run(plugin.handle("/NetworkDriver.AllocateNetwork", CJson::object()));
    CHECK(CDockerPlugin::isError(unknown));
    CHECK_FALSE(CDockerPlugin::isError(caps));
    CHECK(std::string(CDockerPlugin::contentType()) == "application/vnd.docker.plugins.v1.2+json");

    // --> IPAM flows are pure state and work without namespaces.
    CJson pool = loop.run(plugin.handle("/IpamDriver.RequestPool", parse(R"({"AddressSpace":"local","Pool":"","SubPool":"","Options":{},"V6":false})")));
    REQUIRE_FALSE(CDockerPlugin::isError(pool));
    CHECK(pool.get("Pool").asString() == "172.17.0.0/16");
    std::string poolId = pool.get("PoolID").asString();

    CJson gwReq = CJson::object();
    gwReq.set("PoolID", poolId);
    gwReq.set("Address", "");
    gwReq.set("Options", parse(R"({"RequestAddressType":"com.docker.network.gateway"})"));
    CJson gw = loop.run(plugin.handle("/IpamDriver.RequestAddress", gwReq));
    CHECK(gw.get("Address").asString() == "172.17.0.1/16");

    CJson addrReq = CJson::object();
    addrReq.set("PoolID", poolId);
    addrReq.set("Address", "");
    addrReq.set("Options", CJson::object());
    CJson a1 = loop.run(plugin.handle("/IpamDriver.RequestAddress", addrReq));
    CHECK(a1.get("Address").asString() == "172.17.0.2/16");

    addrReq.set("Address", "172.17.0.2");
    CHECK(CDockerPlugin::isError(loop.run(plugin.handle("/IpamDriver.RequestAddress", addrReq))));

    CJson sub = loop.run(plugin.handle("/IpamDriver.RequestPool", parse(R"({"AddressSpace":"local","Pool":"10.60.0.0/16","SubPool":"10.60.5.0/24","V6":false})")));
    REQUIRE_FALSE(CDockerPlugin::isError(sub));
    CJson subAddr = CJson::object();
    subAddr.set("PoolID", sub.get("PoolID").asString());
    CJson sa = loop.run(plugin.handle("/IpamDriver.RequestAddress", subAddr));
    CHECK(sa.get("Address").asString() == "10.60.5.0/16");

    CJson overlap = loop.run(plugin.handle("/IpamDriver.RequestPool", parse(R"({"AddressSpace":"local","Pool":"10.60.1.0/24"})")));
    CHECK(CDockerPlugin::isError(overlap));
    CJson badPool = loop.run(plugin.handle("/IpamDriver.RequestPool", parse(R"({"Pool":"nonsense"})")));
    CHECK(CDockerPlugin::isError(badPool));

    CJson rel = CJson::object();
    rel.set("PoolID", poolId);
    rel.set("Address", "172.17.0.2/16");
    CHECK_FALSE(CDockerPlugin::isError(loop.run(plugin.handle("/IpamDriver.ReleaseAddress", rel))));
    CHECK_FALSE(CDockerPlugin::isError(loop.run(plugin.handle("/IpamDriver.ReleasePool", rel))));
    CHECK_FALSE(CDockerPlugin::isError(loop.run(plugin.handle("/IpamDriver.ReleasePool", rel))));
}

TEST_CASE("Docker network driver flow: create, endpoint, join, ports, teardown") {
    if (!nettest::canCreateNetns()) {
        MESSAGE("skipped: needs root and network namespaces");
        return;
    }

    nettest::STempDir dir;
    std::string host = dir.netns("host");
    std::string sandbox = dir.netns("sandbox");
    REQUIRE(!sandbox.empty());

    SNetworkManagerOptions opts;
    opts.stateDir = dir.join("state");
    opts.hostNetns = host;

    CEventLoop loop;
    auto body = [&]() -> TTask<void> {
        CNetworkManager mgr(opts);
        CDockerPlugin plugin(mgr);

        CRtnl hrt;
        hrt.open(host);
        co_await hrt.setUp(1);

        std::string netId(64, 'a');
        std::string epId(64, 'b');

        CJson create = parse(R"({"NetworkID":"","Options":{"com.docker.network.enable_ipv6":false,
            "com.docker.network.generic":{"com.docker.network.bridge.name":"dk-test0","com.docker.network.driver.mtu":"1400"}},
            "IPv4Data":[{"AddressSpace":"local","Pool":"172.30.0.0/16","Gateway":"172.30.0.1/16","AuxAddresses":{}}],
            "IPv6Data":[]})");
        create.set("NetworkID", netId);
        CJson created = co_await plugin.handle("/NetworkDriver.CreateNetwork", create);
        REQUIRE_MESSAGE(!CDockerPlugin::isError(created), created.dump());
        CHECK(co_await hrt.linkIndex("dk-test0") > 0);

        CJson dupe = co_await plugin.handle("/NetworkDriver.CreateNetwork", create);
        CHECK(CDockerPlugin::isError(dupe));

        CJson cep = parse(R"({"Interface":{"Address":"172.30.0.2/16","AddressIPv6":"","MacAddress":""},"Options":{}})");
        cep.set("NetworkID", netId);
        cep.set("EndpointID", epId);
        CJson epReply = co_await plugin.handle("/NetworkDriver.CreateEndpoint", cep);
        REQUIRE_MESSAGE(!CDockerPlugin::isError(epReply), epReply.dump());
        CHECK(epReply.get("Interface").get("MacAddress").asString() == "02:42:ac:1e:00:02");
        CHECK(epReply.get("Interface").find("Address") == nullptr);

        CJson joinReq = CJson::object();
        joinReq.set("NetworkID", netId);
        joinReq.set("EndpointID", epId);
        joinReq.set("SandboxKey", sandbox);
        joinReq.set("Options", CJson::object());
        CJson joined = co_await plugin.handle("/NetworkDriver.Join", joinReq);
        REQUIRE_MESSAGE(!CDockerPlugin::isError(joined), joined.dump());
        std::string src = joined.get("InterfaceName").get("SrcName").asString();
        CHECK(joined.get("InterfaceName").get("DstPrefix").asString() == "eth");
        CHECK(joined.get("Gateway").asString() == "172.30.0.1");

        // --> What Docker does with the reply: move SrcName into the sandbox as eth0 and configure.
        int32_t idx = co_await hrt.linkIndex(src);
        REQUIRE(idx > 0);
        CFd sfd;
        CNetns::open(sandbox, sfd);
        REQUIRE(co_await hrt.moveToNetnsFd(idx, sfd.get(), "eth0") == SBOX_OK);
        CRtnl srt;
        srt.open(sandbox);
        int32_t eth0 = co_await srt.linkIndex("eth0");
        SIpPrefix addr;
        SIpPrefix::parse("172.30.0.2/16", addr);
        co_await srt.addAddress(eth0, addr);
        co_await srt.setUp(eth0);
        co_await srt.setUp(1);
        SIpAddress gw;
        SIpAddress::parse("172.30.0.1", gw);
        co_await srt.addDefaultRoute(gw);

        SLinkInfo link;
        co_await srt.getLink("eth0", link);
        CHECK(link.mac.toString() == "02:42:ac:1e:00:02");

        // --> Publish 80 -> host 18090 and reach it from the host loopback.
        CJson prog = parse(R"({"Options":{"com.docker.network.portmap":[{"Proto":6,"IP":"","Port":80,"HostIP":"","HostPort":18090,"HostPortEnd":18090}]}})");
        prog.set("NetworkID", netId);
        prog.set("EndpointID", epId);
        CJson progReply = co_await plugin.handle("/NetworkDriver.ProgramExternalConnectivity", prog);
        REQUIRE_MESSAGE(!CDockerPlugin::isError(progReply), progReply.dump());

        CListener listener;
        {
            CNetnsScope scope(sandbox);
            sbox::SEndpoint ep;
            sbox::SEndpoint::fromIp("172.30.0.2", 80, ep);
            REQUIRE(listener.listen(ep) == SBOX_OK);
        }

        bool accepted = false;
        CEventLoop::current()->spawn([](CListener* l, bool* flag) -> TTask<void> {
            CSocket conn;
            *flag = co_await l->accept(conn, 5000) == SBOX_OK;
        }(&listener, &accepted));

        int32_t c = co_await CNetns::run(host, []() {
            return nettest::blockingConnect("127.0.0.1", 18090, "docker");
        });
        CHECK(c == 0);
        for (int32_t i = 0; i < 300 && !accepted; ++i) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        CHECK(accepted);

        CJson info = CJson::object();
        info.set("NetworkID", netId);
        info.set("EndpointID", epId);
        CJson oper = co_await plugin.handle("/NetworkDriver.EndpointOperInfo", info);
        CHECK(oper.get("Value").get("addresses").at(0).asString() == "172.30.0.2/16");
        CHECK(oper.get("Value").get("ports").size() == 1);

        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.RevokeExternalConnectivity", info)));
        SNetworkEndpoint after;
        co_await mgr.getEndpoint(epId, after);
        CHECK(after.ports.empty());

        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.Leave", info)));
        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.DiscoverNew", CJson::object())));

        // --> Docker deletes the network only after the endpoint.
        CJson del = CJson::object();
        del.set("NetworkID", netId);
        CHECK(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.DeleteNetwork", del)));
        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.DeleteEndpoint", info)));
        CHECK(co_await srt.linkIndex("eth0") == -ENODEV);
        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.DeleteEndpoint", info)));
        CHECK_FALSE(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.DeleteNetwork", del)));
        CHECK(co_await hrt.linkIndex("dk-test0") == -ENODEV);

        CFirewall fw;
        if (fw.open(host) == SBOX_OK) {
            CHECK(co_await fw.exists() == 0);
        }

        CJson badEp = parse(R"({"NetworkID":"nope","EndpointID":"x","Interface":{"Address":"bad"}})");
        CHECK(CDockerPlugin::isError(co_await plugin.handle("/NetworkDriver.CreateEndpoint", badEp)));
    };

    loop.run(body());
}
