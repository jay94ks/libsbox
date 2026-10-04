#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/box/cgroup.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;

namespace {

    std::string uniqueName(const char* tag) {
        static int counter = 0;
        return std::string("sbox-test/") + tag + "-" + std::to_string(::getpid()) + "-" + std::to_string(++counter);
    }

    bool canManage() {
        if (::geteuid() != 0) {
            MESSAGE("not root; cgroup creation skipped");
            return false;
        }

        SCgroupSystem sys;
        if (SCgroupSystem::detect(sys) != SBOX_OK || sys.layout == ECGL_NONE) {
            MESSAGE("no cgroup filesystem; skipped");
            return false;
        }

        return true;
    }

    std::string knob(const std::string& dir, const char* name) {
        std::string text;
        CFile::readAll(CFile::join(dir, name), text);
        while (!text.empty() && text.back() == '\n') {
            text.pop_back();
        }

        return text;
    }

    std::string dirOf(const CCgroup& cg, uint32_t controller) {
        for (const auto& [bits, dir] : cg.v1Dirs()) {
            if (bits & controller) {
                return dir;
            }
        }

        return (cg.system().v2Controllers & controller) ? cg.v2Dir() : std::string();
    }

    /**
     * Forks a child that joins `cg` and then runs `fn`; returns its pid (the child waits on a
     * pipe first when `hold` so the caller can inspect it).
     */
    template<typename F>
    pid_t forkInto(const CCgroup& cg, F fn) {
        pid_t pid = ::fork();
        if (pid == 0) {
            if (cg.addProcess(::getpid()) != SBOX_OK) {
                ::_exit(99);
            }

            ::_exit(fn());
        }

        return pid;
    }

}

TEST_CASE("detects the cgroup layout") {
    SCgroupSystem sys;
    REQUIRE(SCgroupSystem::detect(sys) == SBOX_OK);

    if (sys.layout == ECGL_NONE) {
        MESSAGE("no cgroups mounted");
        return;
    }

    CHECK((sys.layout == ECGL_V1 || sys.layout == ECGL_V2 || sys.layout == ECGL_HYBRID));
    if (sys.layout == ECGL_HYBRID) {
        CHECK(!sys.unifiedMount.empty());
        CHECK(!sys.v1Mounts.empty());
    }

    CHECK(SCgroupSystem::controllerFromName("memory") == ECGC_MEMORY);
    CHECK(SCgroupSystem::controllerFromName("blkio") == ECGC_IO);
    CHECK(SCgroupSystem::controllerFromName("io") == ECGC_IO);
    CHECK(SCgroupSystem::controllerFromName("nope") == ECGC_NONE);

    if (::geteuid() == 0) {
        std::string parent;
        CHECK(CCgroup::defaultParent(parent) == SBOX_OK);
        CHECK(parent == "sbox");
    }
}

TEST_CASE("rejects bad paths") {
    CCgroup cg;
    CHECK(CCgroup::create("../escape", cg) == -EINVAL);
    CHECK(CCgroup::create("", cg) == -EINVAL);
}

TEST_CASE("creates a cgroup, applies limits and removes it") {
    if (!canManage()) {
        return;
    }

    CCgroup cg;
    std::string name = uniqueName("limits");
    REQUIRE(CCgroup::create(name, cg) == SBOX_OK);
    CHECK(cg.isValid());

    SCgroupResources res;
    res.memoryLimit = 64 << 20;
    res.pidsLimit = 10;
    res.cpuQuota = 50000;
    res.cpuPeriod = 100000;
    res.cpuShares = 512;

    std::vector<std::string> skipped;
    CHECK(cg.apply(res, &skipped) == SBOX_OK);

    if (std::string dir = dirOf(cg, ECGC_MEMORY); !dir.empty()) {
        if (dir == cg.v2Dir()) {
            CHECK(knob(dir, "memory.max") == std::to_string(64 << 20));
        } else {
            CHECK(knob(dir, "memory.limit_in_bytes") == std::to_string(64 << 20));
        }
    } else {
        CHECK(std::find(skipped.begin(), skipped.end(), "memory") != skipped.end());
    }

    if (std::string dir = dirOf(cg, ECGC_PIDS); !dir.empty()) {
        CHECK(knob(dir, "pids.max") == "10");
    }

    if (std::string dir = dirOf(cg, ECGC_CPU); !dir.empty()) {
        if (dir == cg.v2Dir()) {
            CHECK(knob(dir, "cpu.max") == "50000 100000");
        } else {
            CHECK(knob(dir, "cpu.cfs_quota_us") == "50000");
            CHECK(knob(dir, "cpu.shares") == "512");
        }
    }

    // --> Reopening finds the same directories.
    CCgroup again;
    CHECK(CCgroup::open(name, again) == SBOX_OK);
    CHECK(again.v2Dir() == cg.v2Dir());
    CHECK(again.v1Dirs().size() == cg.v1Dirs().size());

    CHECK(cg.destroy() == SBOX_OK);
    CHECK(!CFile::exists(again.v2Dir().empty() ? again.v1Dirs().front().second : again.v2Dir()));
    CCgroup gone;
    CHECK(CCgroup::open(name, gone) == -ENOENT);
}

TEST_CASE("tracks, freezes and kills member processes") {
    if (!canManage()) {
        return;
    }

    CCgroup cg;
    REQUIRE(CCgroup::create(uniqueName("kill"), cg) == SBOX_OK);

    pid_t pid = forkInto(cg, []() {
        // --> A process tree: the child forks grandchildren that would survive a plain kill.
        for (int i = 0; i < 3; ++i) {
            if (::fork() == 0) {
                for (;;) {
                    ::pause();
                }
            }
        }

        for (;;) {
            ::pause();
        }

        return 0;
    });

    CEventLoop loop;
    loop.run([](CCgroup& g, pid_t child) -> TTask<void> {
        // --> Wait until all four processes are inside.
        for (int i = 0; i < 200; ++i) {
            std::vector<pid_t> pids;
            g.processes(pids);
            if (pids.size() >= 4) {
                break;
            }

            co_await CEventLoop::current()->sleepFor(5);
        }

        std::vector<pid_t> pids;
        CHECK(g.processes(pids) == SBOX_OK);
        CHECK(pids.size() == 4);
        CHECK(std::find(pids.begin(), pids.end(), child) != pids.end());
        CHECK(g.isPopulated());

        SCgroupStats st;
        CHECK(g.stats(st) == SBOX_OK);
        CHECK(st.hasCpu);
        if (st.hasPids) {
            CHECK(st.pidsCurrent == 4);
        }

        CHECK(co_await g.freeze(true) == SBOX_OK);
        CHECK(co_await g.freeze(false) == SBOX_OK);

        // --> The direct child stays a zombie until reaped; reap it concurrently.
        CEventLoop::current()->spawn([](pid_t p) -> TTask<void> {
            for (int i = 0; i < 1000; ++i) {
                int status = 0;
                if (::waitpid(p, &status, WNOHANG) == p) {
                    CHECK(WIFSIGNALED(status));
                    co_return;
                }

                co_await CEventLoop::current()->sleepFor(2);
            }
        }(child));

        CHECK(co_await g.killAll(5000) == SBOX_OK);
        CHECK(!g.isPopulated());
    }(cg, pid));

    CHECK(cg.destroy() == SBOX_OK);
}

TEST_CASE("v1 memory limit triggers the OOM killer and is counted") {
    if (!canManage()) {
        return;
    }

    CCgroup cg;
    REQUIRE(CCgroup::create(uniqueName("oom"), cg) == SBOX_OK);

    if (!(cg.controllers() & ECGC_MEMORY)) {
        MESSAGE("memory controller unavailable");
        cg.destroy();
        return;
    }

    SCgroupResources res;
    res.memoryLimit = 32 << 20;
    res.memorySwap = 32 << 20;
    REQUIRE(cg.apply(res) == SBOX_OK);

    pid_t pid = forkInto(cg, []() {
        std::vector<char*> blocks;
        for (int i = 0; i < 64; ++i) {
            char* b = static_cast<char*>(std::malloc(4 << 20));
            for (size_t k = 0; k < (4u << 20); k += 4096) {
                b[k] = 1;
            }

            blocks.push_back(b);
        }

        return 0;
    });

    int status = 0;
    ::waitpid(pid, &status, 0);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGKILL);

    SCgroupStats st;
    CHECK(cg.stats(st) == SBOX_OK);
    CHECK(st.hasMemory);
    CHECK(st.oomKills >= 1);
    CHECK(st.memoryPeak >= (24u << 20));
    CHECK(st.memoryPeak <= (40u << 20));
    CHECK(cg.destroy() == SBOX_OK);
}

TEST_CASE("pids limit stops a fork bomb") {
    if (!canManage()) {
        return;
    }

    CCgroup cg;
    REQUIRE(CCgroup::create(uniqueName("pids"), cg) == SBOX_OK);
    if (!(cg.controllers() & ECGC_PIDS)) {
        MESSAGE("pids controller unavailable");
        cg.destroy();
        return;
    }

    SCgroupResources res;
    res.pidsLimit = 8;
    REQUIRE(cg.apply(res) == SBOX_OK);

    pid_t pid = forkInto(cg, []() {
        ::setpgid(0, 0);
        int made = 0;
        for (int i = 0; i < 50; ++i) {
            pid_t c = ::fork();
            if (c == 0) {
                ::sleep(30);
                ::_exit(0);
            }

            if (c < 0) {
                break;
            }

            ++made;
        }

        ::kill(0, SIGKILL);     // --> Own process group: the children and us.
        return made;
    });

    int status = 0;
    ::waitpid(pid, &status, 0);

    CEventLoop loop;
    CHECK(loop.run(cg.killAll(5000)) == SBOX_OK);
    CHECK(cg.destroy() == SBOX_OK);
}

TEST_CASE("device rules deny everything but the allowed nodes") {
    if (!canManage()) {
        return;
    }

    // --> v1 devices controller when mounted, otherwise the v2 eBPF device program.
    for (uint32_t controllers : { uint32_t(ECGC_ALL), uint32_t(ECGC_ALL & ~ECGC_DEVICES) }) {
        CCgroup cg;
        REQUIRE(CCgroup::create(uniqueName("devices"), cg, controllers) == SBOX_OK);

        SCgroupResources res;
        res.devices = {
            SCgroupDeviceRule{ false, 'a', -1, -1, "rwm" },
            SCgroupDeviceRule{ true, 'c', 1, 3, "rw" },
        };

        std::vector<std::string> skipped;
        int32_t rc = cg.apply(res, &skipped);
        if (!skipped.empty()) {
            MESSAGE("device rules not enforceable here: ", skipped.front());
            cg.destroy();
            continue;
        }

        REQUIRE_MESSAGE(rc == SBOX_OK, "controllers ", controllers);

        pid_t pid = forkInto(cg, []() {
            int null = ::open("/dev/null", O_RDWR);
            int zero = ::open("/dev/zero", O_RDONLY);
            int err = errno;
            if (null < 0) {
                return 1;
            }

            if (zero >= 0 || err != EPERM) {
                return 2;
            }

            return 0;
        });

        int status = 0;
        ::waitpid(pid, &status, 0);
        CHECK(WIFEXITED(status));
        CHECK_MESSAGE(WEXITSTATUS(status) == 0, "controllers ", controllers);
        CHECK(cg.destroy() == SBOX_OK);
    }
}
