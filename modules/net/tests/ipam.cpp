#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/net/ipam.hpp>
#include <sbox/net/lock.hpp>
#include "testutil.hpp"
#include <set>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;
using namespace sbox::net;

namespace {

    SIpPrefix prefix(const char* text) {
        SIpPrefix p;
        SIpPrefix::parse(text, p);
        return p;
    }

    SIpAddress ip(const char* text) {
        SIpAddress a;
        SIpAddress::parse(text, a);
        return a;
    }

}

TEST_CASE("default pools hand out Docker's subnets and skip overlaps") {
    nettest::STempDir dir;
    CIpam ipam(dir.path);
    CEventLoop loop;

    auto body = [&]() -> TTask<void> {
        SIpamPool a, b, c;
        SIpamRequest req;
        req.reserveGateway = true;
        CHECK(co_await ipam.requestPool(req, a) == SBOX_OK);
        CHECK(a.subnet.toString() == "172.17.0.0/16");
        CHECK(a.id == "local/172.17.0.0/16");
        CHECK(a.gateway.toString() == "172.17.0.1");
        CHECK(a.dynamic);

        // --> A host route in 172.18/16 makes the allocator skip that subnet.
        req.avoid.push_back(prefix("172.18.4.0/24"));
        CHECK(co_await ipam.requestPool(req, b) == SBOX_OK);
        CHECK(b.subnet.toString() == "172.19.0.0/16");

        req.avoid.clear();
        CHECK(co_await ipam.requestPool(req, c) == SBOX_OK);
        CHECK(c.subnet.toString() == "172.18.0.0/16");

        // --> Explicit overlapping subnets are refused within a space, allowed in another.
        SIpamRequest dup;
        dup.subnet = prefix("172.17.5.0/24");
        SIpamPool d;
        CHECK(co_await ipam.requestPool(dup, d) == -EADDRINUSE);
        dup.space = "physical";
        CHECK(co_await ipam.requestPool(dup, d) == SBOX_OK);

        // --> Exhausting the pools: a single /24 pool split into /25s.
        nettest::STempDir small;
        std::vector<SAddressPool> pools(1);
        pools[0].base = prefix("10.250.0.0/24");
        pools[0].size = 25;
        CIpam tiny(small.path, pools);
        SIpamPool p1, p2, p3;
        CHECK(co_await tiny.requestPool(SIpamRequest(), p1) == SBOX_OK);
        CHECK(co_await tiny.requestPool(SIpamRequest(), p2) == SBOX_OK);
        CHECK(p2.subnet.toString() == "10.250.0.128/25");
        CHECK(co_await tiny.requestPool(SIpamRequest(), p3) == -ENOSPC);

        SIpamRequest v6;
        v6.family = 6;
        CHECK(co_await tiny.requestPool(v6, p3) == -ENOSPC);

        CHECK(co_await ipam.releasePool(a.id) == SBOX_OK);
        CHECK(co_await ipam.releasePool(a.id) == -ENOENT);
        SIpamPool again;
        CHECK(co_await ipam.requestPool(SIpamRequest(), again) == SBOX_OK);
        CHECK(again.subnet.toString() == "172.17.0.0/16");
    };

    loop.run(body());
}

TEST_CASE("addresses are allocated round robin, reserved addresses are skipped, state persists") {
    nettest::STempDir dir;
    CEventLoop loop;

    auto body = [&]() -> TTask<void> {
        std::string id;
        {
            CIpam ipam(dir.path);
            SIpamRequest req;
            req.subnet = prefix("10.9.0.0/29");
            req.gateway = ip("10.9.0.1");
            req.reserved.push_back(ip("10.9.0.3"));
            SIpamPool pool;
            REQUIRE(co_await ipam.requestPool(req, pool) == SBOX_OK);
            id = pool.id;

            SIpAddress a;
            CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep1", a) == SBOX_OK);
            CHECK(a.toString() == "10.9.0.2");
            CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep2", a) == SBOX_OK);
            CHECK(a.toString() == "10.9.0.4");
            CHECK(co_await ipam.requestAddress(id, ip("10.9.0.6"), "ep3", a) == SBOX_OK);
            CHECK(co_await ipam.requestAddress(id, ip("10.9.0.6"), "ep4", a) == -EADDRINUSE);
            CHECK(co_await ipam.requestAddress(id, ip("10.8.0.6"), "ep4", a) == -EINVAL);
            CHECK(co_await ipam.requestAddress("nope", SIpAddress(), "ep4", a) == -ENOENT);
        }

        // --> A fresh instance sees the persisted state.
        CIpam ipam(dir.path);
        SIpamPool pool;
        REQUIRE(co_await ipam.getPool(id, pool) == SBOX_OK);
        CHECK(pool.allocated.size() == 3);
        CHECK(pool.gateway.toString() == "10.9.0.1");

        SIpAddress a;
        CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep5", a) == SBOX_OK);
        CHECK(a.toString() == "10.9.0.5");

        // --> .7 is the broadcast address, so the pool is full now.
        CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep6", a) == -ENOSPC);

        // --> Release by address and by owner; allocation continues after the last one.
        CHECK(co_await ipam.releaseAddress(id, ip("10.9.0.2")) == SBOX_OK);
        CHECK(co_await ipam.releaseAddress(id, ip("10.9.0.2")) == SBOX_OK);
        CHECK(co_await ipam.releaseOwner(id, "ep2") == 1);

        std::vector<SIpAddress> owned;
        CHECK(co_await ipam.findOwner(id, "ep3", owned) == SBOX_OK);
        REQUIRE(owned.size() == 1);
        CHECK(owned[0].toString() == "10.9.0.6");

        CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep7", a) == SBOX_OK);
        CHECK(a.toString() == "10.9.0.2");
        CHECK(co_await ipam.requestAddress(id, SIpAddress(), "ep8", a) == SBOX_OK);
        CHECK(a.toString() == "10.9.0.4");
    };

    loop.run(body());
}

TEST_CASE("ranges and IPv6 pools") {
    nettest::STempDir dir;
    std::vector<SAddressPool> pools = DefaultAddressPools();
    SAddressPool v6;
    v6.base = prefix("fd00:abcd::/48");
    v6.size = 64;
    pools.push_back(v6);
    CIpam ipam(dir.path, pools);
    CEventLoop loop;

    auto body = [&]() -> TTask<void> {
        SIpamRequest req;
        req.subnet = prefix("192.168.10.0/24");
        req.range = prefix("192.168.10.128/28");
        req.gateway = ip("192.168.10.1");
        SIpamPool pool;
        REQUIRE(co_await ipam.requestPool(req, pool) == SBOX_OK);
        SIpAddress a;
        CHECK(co_await ipam.requestAddress(pool.id, SIpAddress(), "x", a) == SBOX_OK);
        CHECK(a.toString() == "192.168.10.128");

        SIpamRequest se;
        se.space = "lan";
        se.subnet = prefix("192.168.10.0/24");
        se.rangeStart = ip("192.168.10.200");
        se.rangeEnd = ip("192.168.10.201");
        SIpamPool lan;
        REQUIRE(co_await ipam.requestPool(se, lan) == SBOX_OK);
        CHECK(co_await ipam.requestAddress(lan.id, SIpAddress(), "x", a) == SBOX_OK);
        CHECK(a.toString() == "192.168.10.200");
        CHECK(co_await ipam.requestAddress(lan.id, SIpAddress(), "y", a) == SBOX_OK);
        CHECK(a.toString() == "192.168.10.201");
        CHECK(co_await ipam.requestAddress(lan.id, SIpAddress(), "z", a) == -ENOSPC);

        SIpamRequest badRange;
        badRange.subnet = prefix("10.1.0.0/24");
        badRange.range = prefix("10.2.0.0/28");
        CHECK(co_await ipam.requestPool(badRange, lan) == -EINVAL);

        SIpamRequest r6;
        r6.family = 6;
        r6.reserveGateway = true;
        SIpamPool p6;
        REQUIRE(co_await ipam.requestPool(r6, p6) == SBOX_OK);
        CHECK(p6.subnet.toString() == "fd00:abcd::/64");
        CHECK(p6.gateway.toString() == "fd00:abcd::1");
        CHECK(co_await ipam.requestAddress(p6.id, SIpAddress(), "x", a) == SBOX_OK);
        CHECK(a.toString() == "fd00:abcd::2");

        SIpamPool p6b;
        CHECK(co_await ipam.requestPool(r6, p6b) == SBOX_OK);
        CHECK(p6b.subnet.toString() == "fd00:abcd:0:1::/64");

        SIpamRequest named;
        named.id = "cni-net";
        named.subnet = prefix("10.77.0.0/24");
        SIpamPool np;
        CHECK(co_await ipam.requestPool(named, np) == SBOX_OK);
        CHECK(np.id == "cni-net");
        named.subnet = prefix("10.78.0.0/24");
        CHECK(co_await ipam.requestPool(named, np) == -EEXIST);
    };

    loop.run(body());
}

TEST_CASE("parse default-address-pools") {
    CJson j;
    REQUIRE(CJson::parse(R"([{"base":"10.10.0.0/16","size":24},{"base":"fd00::/56","size":64}])", j) == SBOX_OK);
    std::vector<SAddressPool> pools;
    REQUIRE(ParseAddressPools(j, pools) == SBOX_OK);
    REQUIRE(pools.size() == 2);
    CHECK(pools[0].size == 24);
    CHECK(pools[1].base.toString() == "fd00::/56");

    CJson bad;
    CJson::parse(R"([{"base":"10.10.0.0/16","size":8}])", bad);
    CHECK(ParseAddressPools(bad, pools) == -EINVAL);
}

TEST_CASE("concurrent processes never hand out the same address") {
    nettest::STempDir dir;
    std::string poolId;

    {
        CEventLoop loop;
        CIpam ipam(dir.path);
        SIpamRequest req;
        req.subnet = prefix("10.66.0.0/24");
        SIpamPool pool;
        REQUIRE(loop.run(ipam.requestPool(req, pool)) == SBOX_OK);
        poolId = pool.id;
    }

    constexpr int32_t WORKERS = 4;
    constexpr int32_t EACH = 25;
    std::vector<int> pidfds;

    for (int32_t w = 0; w < WORKERS; ++w) {
        pid_t pid = ::fork();
        REQUIRE(pid >= 0);

        if (pid == 0) {
            int32_t failures = 0;
            {
                CEventLoop childLoop;
                CIpam ipam(dir.path);
                auto work = [&]() -> TTask<void> {
                    for (int32_t i = 0; i < EACH; ++i) {
                        SIpAddress a;
                        if (co_await ipam.requestAddress(poolId, SIpAddress(), "w" + std::to_string(w), a) != SBOX_OK) {
                            ++failures;
                        }
                    }
                };

                childLoop.run(work());
            }

            ::_exit(failures == 0 ? 0 : 1);
        }

        pidfds.push_back(int(::syscall(SYS_pidfd_open, pid, 0)));
    }

    CEventLoop loop;
    auto waitAll = [&]() -> TTask<int32_t> {
        int32_t bad = 0;
        for (int fd : pidfds) {
            co_await CEventLoop::current()->waitFd(fd, EFDE_READ, 60000);
            siginfo_t info{};
            ::waitid(idtype_t(P_PIDFD), id_t(fd), &info, WEXITED);
            bad += info.si_status != 0 ? 1 : 0;
            ::close(fd);
        }

        co_return bad;
    };

    CHECK(loop.run(waitAll()) == 0);

    CIpam ipam(dir.path);
    SIpamPool pool;
    REQUIRE(loop.run(ipam.getPool(poolId, pool)) == SBOX_OK);
    CHECK(pool.allocated.size() == size_t(WORKERS * EACH));

    std::set<std::string> owners;
    for (const auto& kv : pool.allocated) {
        owners.insert(kv.second);
    }

    CHECK(owners.size() == size_t(WORKERS));
}

TEST_CASE("file lock excludes a second holder and times out") {
    nettest::STempDir dir;
    std::string path = dir.join("x.lock");
    CFileLock a, b;
    CHECK(a.tryLock(path) == SBOX_OK);
    CHECK(b.tryLock(path) == -EWOULDBLOCK);

    CEventLoop loop;
    CHECK(loop.run(b.lock(path, 30)) == -ETIMEDOUT);
    a.unlock();
    CHECK(loop.run(b.lock(path, 30)) == SBOX_OK);
    CHECK(b.isLocked());
}
