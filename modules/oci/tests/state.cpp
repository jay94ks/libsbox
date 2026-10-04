#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "ocitest.hpp"
#include "convert.hpp"
#include <sbox/oci/runtime.hpp>
#include <sbox/oci/state.hpp>
#include <csignal>
#include <sys/mount.h>

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

TEST_CASE("state JSON has runc's members and order") {
    SState s;
    s.id = "abc";
    s.pid = 42;
    s.status = ECST_RUNNING;
    s.bundle = "/b";
    s.rootfs = "/b/rootfs";
    s.created = "2026-10-04T12:51:27.232160881Z";
    std::string text = s.toJson().dump();
    CHECK(text == R"({"ociVersion":"1.2.1","id":"abc","pid":42,"status":"running","bundle":"/b","rootfs":"/b/rootfs","created":"2026-10-04T12:51:27.232160881Z","owner":""})");

    s.annotations = { { "k", "v" } };
    SState back;
    REQUIRE(SState::fromJson(s.toJson(), back) == SBOX_OK);
    CHECK(back.status == ECST_RUNNING);
    CHECK(back.annotations.size() == 1);
    CHECK(back.toJson().dump() == s.toJson().dump());

    for (uint32_t i = ECST_CREATING; i <= ECST_STOPPED; ++i) {
        CHECK(StatusFromName(StatusName(EContainerStatus(i))) == EContainerStatus(i));
    }

    CHECK(StatusFromName("bogus") == ECST_INVALID);
}

TEST_CASE("container record round-trips with its configuration") {
    SContainerRecord r;
    r.id = "c1";
    r.bundle = "/srv/b";
    r.rootfs = "/srv/b/rootfs";
    r.created = NowRfc3339Nano();
    r.ownerUid = 1000;
    r.initPid = 1234;
    r.initStartTime = 987654321;
    r.cgroupPath = "sbox/c1";
    r.rootless = true;
    r.lastStatus = ECST_CREATED;
    r.config = DefaultSpec();

    SContainerRecord back;
    std::string err;
    REQUIRE_MESSAGE(SContainerRecord::fromJson(r.toJson(), back, err) == SBOX_OK, err);
    CHECK(back.toJson().dump() == r.toJson().dump());
    CHECK(back.initStartTime == 987654321u);
    CHECK(back.config.process->args[0] == "sh");

    CJson bad;
    REQUIRE(CJson::parse(R"({"id":"x","initProcessPid":"no"})", bad) == SBOX_OK);
    CHECK(SContainerRecord::fromJson(bad, back, err) == -EINVAL);
}

TEST_CASE("process liveness uses the start time (pid reuse guard)") {
    SProcStat me;
    REQUIRE(ReadProcStat(::getpid(), me) == SBOX_OK);
    CHECK(me.startTime > 0);
    CHECK(me.ppid == ::getppid());
    CHECK(me.state == 'R');
    CHECK(ProcessAlive(::getpid(), me.startTime));
    CHECK(!ProcessAlive(::getpid(), me.startTime + 1));
    CHECK(ReadProcStat(0, me) == -ESRCH);
    CHECK(ReadProcStat(0x3ffffff, me) == -ESRCH);

    // --> A zombie is not alive.
    pid_t child = ::fork();
    if (child == 0) {
        ::_exit(0);
    }

    SProcStat cs;
    for (int i = 0; i < 200; ++i) {
        REQUIRE(ReadProcStat(child, cs) == SBOX_OK);
        if (cs.state == 'Z') {
            break;
        }

        ::usleep(5000);
    }

    CHECK(cs.state == 'Z');
    CHECK(!ProcessAlive(child, cs.startTime));
    ::waitpid(child, nullptr, 0);
}

TEST_CASE("timestamps and ids") {
    std::string t = NowRfc3339Nano();
    REQUIRE(t.size() >= 20);
    CHECK(t[4] == '-');
    CHECK(t[10] == 'T');
    CHECK(t.back() == 'Z');
    if (t.size() > 20) {
        CHECK(t[19] == '.');
        CHECK(t[t.size() - 2] != '0');
    }

    CHECK(ValidContainerId("abc-1.2_3+x"));
    CHECK(ValidContainerId(std::string(64, 'a')));
    CHECK(!ValidContainerId(""));
    CHECK(!ValidContainerId("."));
    CHECK(!ValidContainerId(".."));
    CHECK(!ValidContainerId("a/b"));
    CHECK(!ValidContainerId("a b"));
    CHECK(!ValidContainerId(std::string(1025, 'a')));
}

TEST_CASE("signal names and numbers") {
    CHECK(ParseSignal("9") == SIGKILL);
    CHECK(ParseSignal("15") == SIGTERM);
    CHECK(ParseSignal("KILL") == SIGKILL);
    CHECK(ParseSignal("SIGKILL") == SIGKILL);
    CHECK(ParseSignal("sigterm") == SIGTERM);
    CHECK(ParseSignal("hup") == SIGHUP);
    CHECK(ParseSignal("WINCH") == SIGWINCH);
    CHECK(ParseSignal("RTMIN") == SIGRTMIN);
    CHECK(ParseSignal("RTMIN+2") == SIGRTMIN + 2);
    CHECK(ParseSignal("SIGRTMAX-1") == SIGRTMAX - 1);
    CHECK(ParseSignal("0") == -EINVAL);
    CHECK(ParseSignal("999") == -EINVAL);
    CHECK(ParseSignal("BOGUS") == -EINVAL);
    CHECK(ParseSignal("") == -EINVAL);
    CHECK(ParseSignal("9x") == -EINVAL);
}

TEST_CASE("systemd cgroupsPath maps to a cgroupfs path") {
    std::string out;
    REQUIRE(ExpandSystemdCgroupPath("system.slice:docker:abc", false, out) == SBOX_OK);
    CHECK(out == "system.slice/docker-abc.scope");
    REQUIRE(ExpandSystemdCgroupPath("machine-app-web.slice:cri:x", false, out) == SBOX_OK);
    CHECK(out == "machine.slice/machine-app.slice/machine-app-web.slice/cri-x.scope");
    REQUIRE(ExpandSystemdCgroupPath(":sbox:c1", true, out) == SBOX_OK);
    CHECK(out == "user.slice/sbox-c1.scope");
    REQUIRE(ExpandSystemdCgroupPath("-.slice::c1", false, out) == SBOX_OK);
    CHECK(out == "c1.scope");
    REQUIRE(ExpandSystemdCgroupPath("system.slice:p:sub.slice", false, out) == SBOX_OK);
    CHECK(out == "system.slice/sub.slice");
    CHECK(ExpandSystemdCgroupPath("/docker/abc", false, out) == -EINVAL);
    CHECK(ExpandSystemdCgroupPath("system:docker:abc", false, out) == -EINVAL);
    CHECK(ExpandSystemdCgroupPath("system.slice:docker:", false, out) == -EINVAL);
    CHECK(ExpandSystemdCgroupPath("a--b.slice:x:y", false, out) == -EINVAL);
}

TEST_CASE("propagation names") {
    CHECK(PropagationFlags("") == 0);
    CHECK(PropagationFlags("rslave") == (MS_SLAVE | MS_REC));
    CHECK(PropagationFlags("private") == MS_PRIVATE);
    CHECK(PropagationFlags("rshared") == (MS_SHARED | MS_REC));
    CHECK(PropagationFlags("runbindable") == (MS_UNBINDABLE | MS_REC));
}

TEST_CASE("resources convert to box cgroup limits") {
    SResourcesSpec r;
    r.memory = SMemorySpec{ 1 << 20, 1 << 19, 2 << 20, -1, std::nullopt, 10u };
    r.pids = SPidsSpec{ 0 };
    r.cpu = SCpuSpec();
    r.cpu->quota = 5000;
    r.cpu->period = 10000;
    r.cpu->cpus = "0";
    r.devices = { { false, "", std::nullopt, std::nullopt, "" }, { true, "c", 1, 3, "rw" } };
    r.unified = { { "memory.high", "max" } };

    SCgroupResources out;
    std::vector<std::string> warnings;
    ToCgroupResources(r, out, warnings);
    CHECK(out.memoryLimit == (1 << 20));
    CHECK(out.memorySwap == (2 << 20));
    CHECK(out.pidsLimit == -1);         // --> 0 means unlimited, as runc.
    CHECK(out.cpuQuota == 5000);
    CHECK(out.cpusetCpus == "0");
    REQUIRE(out.devices.size() == 2);
    CHECK(out.devices[0].type == 'a');
    CHECK(out.devices[0].major == -1);
    CHECK(out.devices[0].access == "rwm");
    CHECK(out.devices[1].minor == 3);
    CHECK(out.unified.size() == 1);
    CHECK(warnings.size() == 2);        // --> kernel and swappiness.

    SSpec spec = DefaultSpec();
    spec.linux_->devices.push_back({ "c", "/dev/fuse", 10, 229 });
    std::vector<SCgroupDeviceRule> rules = DefaultDeviceRules(spec);
    CHECK(rules.back().major == 10);
    CHECK(rules.back().minor == 229);
    CHECK(rules.back().allow);
}
