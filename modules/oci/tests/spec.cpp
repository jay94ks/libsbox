#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "ocitest.hpp"
#include <sbox/box/launch.hpp>
#include <sbox/oci/spec.hpp>
#include <algorithm>
#include <functional>
#include <sys/resource.h>

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

namespace {

    CJson parseFile(const std::string& path) {
        std::string text;
        REQUIRE(CFile::readAll(path, text) == SBOX_OK);
        CJson doc;
        REQUIRE(CJson::parse(text, doc) == SBOX_OK);
        return doc;
    }

    /**
     * A document using every field of the Linux runtime-spec 1.2.
     */
    const char* FULL = R"({
        "ociVersion": "1.2.1",
        "process": {
            "terminal": true,
            "consoleSize": { "height": 25, "width": 80 },
            "user": { "uid": 1000, "gid": 1000, "umask": 18, "additionalGids": [ 5, 6 ] },
            "args": [ "/bin/sh", "-c", "true" ],
            "env": [ "PATH=/bin", "A=b" ],
            "cwd": "/work",
            "capabilities": {
                "bounding": [ "CAP_KILL" ], "effective": [ "CAP_KILL" ], "inheritable": [ "CAP_KILL" ],
                "permitted": [ "CAP_KILL" ], "ambient": [ "CAP_KILL" ]
            },
            "rlimits": [ { "type": "RLIMIT_NOFILE", "hard": 1024, "soft": 512 } ],
            "noNewPrivileges": true,
            "apparmorProfile": "docker-default",
            "oomScoreAdj": 100,
            "selinuxLabel": "system_u:system_r:container_t:s0",
            "scheduler": { "policy": "SCHED_OTHER", "nice": 1 },
            "ioPriority": { "class": "IOPRIO_CLASS_BE", "priority": 4 },
            "execCPUAffinity": { "initial": "0", "final": "0-1" }
        },
        "root": { "path": "rootfs", "readonly": true },
        "hostname": "box",
        "domainname": "example.org",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/data", "type": "bind", "source": "/srv/data", "options": [ "rbind", "ro" ],
              "uidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
              "gidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ] }
        ],
        "hooks": {
            "prestart": [ { "path": "/usr/bin/a", "args": [ "a", "1" ], "env": [ "X=1" ], "timeout": 5 } ],
            "createRuntime": [ { "path": "/usr/bin/b" } ],
            "createContainer": [ { "path": "/usr/bin/c" } ],
            "startContainer": [ { "path": "/usr/bin/d" } ],
            "poststart": [ { "path": "/usr/bin/e" } ],
            "poststop": [ { "path": "/usr/bin/f" } ]
        },
        "annotations": { "org.example.key": "value", "com.docker.x": "y" },
        "linux": {
            "uidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
            "gidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
            "sysctl": { "net.ipv4.ip_forward": "1", "kernel.shmmax": "1000000" },
            "resources": {
                "devices": [ { "allow": false, "access": "rwm" }, { "allow": true, "type": "c", "major": 1, "minor": 3, "access": "rw" } ],
                "memory": { "limit": 536870912, "reservation": 268435456, "swap": 1073741824, "kernel": -1, "kernelTCP": -1,
                            "swappiness": 0, "disableOOMKiller": false, "useHierarchy": true, "checkBeforeUpdate": true },
                "cpu": { "shares": 1024, "quota": 50000, "burst": 0, "period": 100000, "realtimeRuntime": 0, "realtimePeriod": 0,
                         "cpus": "0-1", "mems": "0", "idle": 0 },
                "pids": { "limit": 100 },
                "blockIO": { "weight": 500, "leafWeight": 300,
                             "weightDevice": [ { "major": 8, "minor": 0, "weight": 400, "leafWeight": 200 } ],
                             "throttleReadBpsDevice": [ { "major": 8, "minor": 0, "rate": 1048576 } ],
                             "throttleWriteBpsDevice": [ { "major": 8, "minor": 0, "rate": 2097152 } ],
                             "throttleReadIOPSDevice": [ { "major": 8, "minor": 0, "rate": 100 } ],
                             "throttleWriteIOPSDevice": [ { "major": 8, "minor": 0, "rate": 200 } ] },
                "hugepageLimits": [ { "pageSize": "2MB", "limit": 209715200 } ],
                "network": { "classID": 1048577, "priorities": [ { "name": "eth0", "priority": 500 } ] },
                "rdma": { "mlx5_1": { "hcaHandles": 3, "hcaObjects": 10000 } },
                "unified": { "memory.high": "400000000" }
            },
            "cgroupsPath": "/sbox/full",
            "namespaces": [ { "type": "pid" }, { "type": "network", "path": "/var/run/netns/x" }, { "type": "mount" },
                            { "type": "ipc" }, { "type": "uts" }, { "type": "user" }, { "type": "cgroup" }, { "type": "time" } ],
            "devices": [ { "path": "/dev/fuse", "type": "c", "major": 10, "minor": 229, "fileMode": 438, "uid": 0, "gid": 0 } ],
            "seccomp": {
                "defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1,
                "architectures": [ "SCMP_ARCH_X86_64", "SCMP_ARCH_X86" ],
                "flags": [ "SECCOMP_FILTER_FLAG_LOG" ],
                "listenerPath": "/run/seccomp.sock", "listenerMetadata": "meta",
                "syscalls": [
                    { "names": [ "read", "write" ], "action": "SCMP_ACT_ALLOW" },
                    { "names": [ "personality" ], "action": "SCMP_ACT_ALLOW",
                      "args": [ { "index": 0, "value": 4294967295, "op": "SCMP_CMP_EQ" } ] },
                    { "names": [ "clone" ], "action": "SCMP_ACT_ERRNO", "errnoRet": 38,
                      "args": [ { "index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ" } ] }
                ]
            },
            "rootfsPropagation": "rslave",
            "maskedPaths": [ "/proc/kcore" ],
            "readonlyPaths": [ "/proc/sys" ],
            "mountLabel": "system_u:object_r:container_file_t:s0",
            "intelRdt": { "closID": "x", "l3CacheSchema": "L3:0=f" },
            "personality": { "domain": "LINUX32" },
            "timeOffsets": { "monotonic": { "secs": 1, "nanosecs": 2 } },
            "netDevices": { "eth1": { "name": "net1" } },
            "memoryPolicy": { "mode": "MPOL_BIND", "nodes": "0" }
        }
    })";

}

TEST_CASE("runc's default config.json round-trips and equals DefaultSpec") {
    CJson original = parseFile(dataFile("runc-default.json"));
    SSpec spec;
    std::string err;
    std::vector<std::string> warnings;
    REQUIRE_MESSAGE(ParseSpec(original, spec, err, &warnings) == SBOX_OK, err);
    CHECK(warnings.empty());
    CHECK(jsonEqual(SpecToJson(spec), original));

    // --> Our generated default is runc's, with our hostname.
    CJson mine = SpecToJson(DefaultSpec(false, 0, 0, "runc"));
    CHECK(jsonEqual(mine, original));

    std::vector<std::string> vw;
    CHECK(ValidateSpec(spec, err, &vw) == SBOX_OK);
}

TEST_CASE("runc's rootless config.json equals DefaultSpec(rootless)") {
    CJson original = parseFile(dataFile("runc-rootless.json"));
    SSpec spec;
    std::string err;
    REQUIRE(ParseSpec(original, spec, err) == SBOX_OK);
    CHECK(jsonEqual(SpecToJson(spec), original));
    CHECK(jsonEqual(SpecToJson(DefaultSpec(true, 0, 0, "runc")), original));

    SSpec rl = DefaultSpec(true, 1000, 1001);
    REQUIRE(rl.linux_);
    CHECK(rl.linux_->uidMappings[0].hostID == 1000);
    CHECK(rl.linux_->gidMappings[0].hostID == 1001);
    CHECK(!rl.linux_->resources);
}

TEST_CASE("every field of the Linux spec round-trips") {
    CJson doc;
    REQUIRE(CJson::parse(FULL, doc) == SBOX_OK);

    SSpec spec;
    std::string err;
    std::vector<std::string> warnings;
    REQUIRE_MESSAGE(ParseSpec(doc, spec, err, &warnings) == SBOX_OK, err);
    CHECK(warnings.empty());

    CJson out = SpecToJson(spec);
    CHECK_MESSAGE(jsonEqual(out, doc), out.dump(true));

    // Typed values.
    REQUIRE(spec.process);
    CHECK(spec.process->user.umask == 18u);
    CHECK(spec.process->user.additionalGids == std::vector<uint32_t>{ 5, 6 });
    CHECK(spec.process->consoleSize->width == 80);
    CHECK(spec.process->oomScoreAdj == 100);
    REQUIRE(spec.linux_);
    CHECK(spec.linux_->resources->memory->limit == 536870912);
    CHECK(spec.linux_->resources->cpu->cpus == "0-1");
    CHECK(spec.linux_->resources->pids->limit == 100);
    CHECK(spec.linux_->resources->blockIO->throttleWriteIOPSDevice[0].rate == 200);
    CHECK(spec.linux_->seccomp->syscalls[1].args[0].value == 4294967295ull);
    CHECK(spec.linux_->seccomp->syscalls[2].errnoRet == 38u);
    CHECK(spec.linux_->namespaces[1].path == "/var/run/netns/x");
    CHECK(spec.mounts[1].uidMappings[0].hostID == 100000);
    CHECK(spec.hooks->prestart[0].timeout == 5);
    CHECK(spec.annotations.size() == 2);
    CHECK(!spec.linux_->intelRdt.isNull());

    // --> Second generation is identical text.
    SSpec again;
    REQUIRE(ParseSpec(out, again, err) == SBOX_OK);
    CHECK(SpecToJson(again).dump() == out.dump());

    // --> Fields accepted but not enforced are reported.
    std::vector<std::string> vw;
    CHECK(ValidateSpec(spec, err, &vw) == SBOX_OK);
    std::string all;
    for (const std::string& w : vw) {
        all += w + "\n";
    }

    CHECK(all.find("apparmorProfile") != std::string::npos);
    CHECK(all.find("selinuxLabel") != std::string::npos);
    CHECK(all.find("scheduler") != std::string::npos);
    CHECK(all.find("ioPriority") != std::string::npos);
    CHECK(all.find("personality") != std::string::npos);
    CHECK(all.find("intelRdt") != std::string::npos);
    CHECK(all.find("mountLabel") != std::string::npos);
    CHECK(all.find("prestart is deprecated") != std::string::npos);
}

TEST_CASE("large unsigned values survive (seccomp masks, rlimits)") {
    const char* text = R"({"ociVersion":"1.0.2","process":{"args":["x"],"cwd":"/","rlimits":[{"type":"RLIMIT_CORE","hard":18446744073709551615,"soft":18446744073709551615}]},
        "root":{"path":"r"},"linux":{"namespaces":[{"type":"mount"}],"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["x"],"action":"SCMP_ACT_ERRNO","args":[{"index":1,"value":9223372036854775808,"op":"SCMP_CMP_GE"}]}]}}})";
    SSpec spec;
    std::string err;
    REQUIRE_MESSAGE(ParseSpecText(text, spec, err) == SBOX_OK, err);
    CHECK(spec.process->rlimits[0].hard == ~uint64_t(0));
    CHECK(spec.linux_->seccomp->syscalls[0].args[0].value == (uint64_t(1) << 63));
}

TEST_CASE("type errors name the field") {
    struct Case {
        const char* json;
        const char* expect;
    };

    const Case cases[] = {
        { R"({"ociVersion":1})", "ociVersion: expected a string" },
        { R"({"ociVersion":"1.2.0","process":{"args":"sh"}})", "process.args: expected an array of strings" },
        { R"({"ociVersion":"1.2.0","process":{"args":["sh",1]}})", "process.args[1]: expected a string" },
        { R"({"ociVersion":"1.2.0","process":{"user":{"uid":-1}}})", "process.user.uid: expected an unsigned 32-bit integer" },
        { R"({"ociVersion":"1.2.0","process":{"terminal":"yes"}})", "process.terminal: expected a boolean" },
        { R"({"ociVersion":"1.2.0","mounts":{}})", "mounts: expected an array" },
        { R"({"ociVersion":"1.2.0","mounts":[{"destination":5}]})", "mounts[0].destination: expected a string" },
        { R"({"ociVersion":"1.2.0","linux":{"resources":{"memory":{"limit":"1g"}}}})", "linux.resources.memory.limit: expected a 64-bit integer" },
        { R"({"ociVersion":"1.2.0","linux":{"namespaces":[{"type":true}]}})", "linux.namespaces[0].type: expected a string" },
        { R"({"ociVersion":"1.2.0","linux":{"seccomp":{"syscalls":[{"names":["a"],"args":[{"index":"0"}]}]}}})",
          "linux.seccomp.syscalls[0].args[0].index: expected an unsigned 32-bit integer" },
        { R"({"ociVersion":"1.2.0","annotations":{"a":1}})", "annotations.a: expected a string" },
        { R"([1,2])", "expected a JSON object" },
    };

    for (const Case& c : cases) {
        SSpec spec;
        std::string err;
        CHECK_MESSAGE(ParseSpecText(c.json, spec, err) == -EINVAL, c.json);
        CHECK_MESSAGE(err.find(c.expect) != std::string::npos, err);
    }

    SSpec spec;
    std::string err;
    CHECK(ParseSpecText("{\"ociVersion\": ", spec, err) == -EINVAL);
    CHECK(err.find("invalid JSON") != std::string::npos);
    CHECK(LoadSpec("/nonexistent/config.json", spec, err) == -ENOENT);
}

TEST_CASE("unknown fields are warnings, not errors") {
    SSpec spec;
    std::string err;
    std::vector<std::string> warnings;
    REQUIRE(ParseSpecText(R"({"ociVersion":"1.2.0","process":{"args":["a"],"cwd":"/","bogus":1},"windows":{},"extra":true})",
                          spec, err, &warnings) == SBOX_OK);
    std::string all;
    for (const std::string& w : warnings) {
        all += w + "\n";
    }

    CHECK(all.find("process.bogus: unknown field") != std::string::npos);
    CHECK(all.find("extra: unknown field") != std::string::npos);
    CHECK(all.find("windows: section is ignored") != std::string::npos);
}

TEST_CASE("validation refuses what a runtime must refuse") {
    auto base = []() {
        SSpec s = DefaultSpec();
        s.process->args = { "sh" };
        return s;
    };

    struct Case {
        const char* name;
        std::function<void(SSpec&)> mutate;
        const char* expect;
    };

    const std::vector<Case> cases = {
        { "no version", [](SSpec& s) { s.ociVersion.clear(); }, "ociVersion must be set" },
        { "version 2", [](SSpec& s) { s.ociVersion = "2.0.0"; }, "unsupported ociVersion" },
        { "no root", [](SSpec& s) { s.root.reset(); }, "root.path must be set" },
        { "no process", [](SSpec& s) { s.process.reset(); }, "process must be set" },
        { "empty args", [](SSpec& s) { s.process->args.clear(); }, "process.args must not be empty" },
        { "relative cwd", [](SSpec& s) { s.process->cwd = "work"; }, "must be an absolute path" },
        { "unknown rlimit", [](SSpec& s) { s.process->rlimits.push_back({ "RLIMIT_BOGUS", 1, 1 }); }, "unknown rlimit type" },
        { "soft > hard", [](SSpec& s) { s.process->rlimits[0].soft = 4096; }, "soft value is greater" },
        { "duplicate rlimit", [](SSpec& s) { s.process->rlimits.push_back(s.process->rlimits[0]); }, "duplicate type" },
        { "oom score", [](SSpec& s) { s.process->oomScoreAdj = 5000; }, "oomScoreAdj" },
        { "unknown namespace", [](SSpec& s) { s.linux_->namespaces.push_back({ "bogus", "" }); }, "unknown namespace type" },
        { "duplicate namespace", [](SSpec& s) { s.linux_->namespaces.push_back({ "pid", "" }); }, "duplicate namespace pid" },
        { "relative ns path", [](SSpec& s) { s.linux_->namespaces[1].path = "netns"; }, "must be absolute" },
        { "no mount ns", [](SSpec& s) {
              auto& ns = s.linux_->namespaces;
              ns.erase(std::remove_if(ns.begin(), ns.end(), [](const SNamespaceEntry& e) { return e.type == "mount"; }), ns.end());
          }, "a mount namespace is required" },
        { "maps without userns", [](SSpec& s) { s.linux_->uidMappings.push_back({ 0, 1000, 1 }); }, "there is no user namespace" },
        { "userns without maps", [](SSpec& s) { s.linux_->namespaces.push_back({ "user", "" }); }, "needs linux.uidMappings" },
        { "hostname without uts", [](SSpec& s) {
              auto& ns = s.linux_->namespaces;
              ns.erase(std::remove_if(ns.begin(), ns.end(), [](const SNamespaceEntry& e) { return e.type == "uts"; }), ns.end());
          }, "without a private UTS namespace" },
        { "hostname in joined uts", [](SSpec& s) {
              for (auto& n : s.linux_->namespaces) {
                  if (n.type == "uts") {
                      n.path = "/proc/1/ns/uts";
                  }
              }
          }, "joined UTS namespace" },
        { "device type", [](SSpec& s) { s.linux_->devices.push_back({ "x", "/dev/x", 1, 1 }); }, "must be one of c, b, u, p" },
        { "device path", [](SSpec& s) { s.linux_->devices.push_back({ "c", "dev/x", 1, 1 }); }, "must be an absolute path" },
        { "cgroup rule type", [](SSpec& s) { s.linux_->resources->devices[0].type = "z"; }, "must be one of a, c, b" },
        { "cgroup rule access", [](SSpec& s) { s.linux_->resources->devices[0].access = "rwx"; }, "combination of r, w, m" },
        { "propagation", [](SSpec& s) { s.linux_->rootfsPropagation = "sideways"; }, "not a valid propagation" },
        { "sysctl not namespaced", [](SSpec& s) { s.linux_->sysctl.push_back({ "vm.swappiness", "1" }); }, "is not in a separate kernel namespace" },
        { "net sysctl in host netns", [](SSpec& s) {
              auto& ns = s.linux_->namespaces;
              ns.erase(std::remove_if(ns.begin(), ns.end(), [](const SNamespaceEntry& e) { return e.type == "network"; }), ns.end());
              s.linux_->sysctl.push_back({ "net.ipv4.ip_forward", "1" });
          }, "host network namespace" },
        { "seccomp action", [](SSpec& s) { s.linux_->seccomp = SSeccompSpec{ "SCMP_ACT_NOPE" }; }, "is not a known action" },
        { "seccomp operator", [](SSpec& s) {
              SSeccompSpec sc;
              sc.defaultAction = "SCMP_ACT_ALLOW";
              SSyscallSpec call;
              call.names = { "read" };
              call.action = "SCMP_ACT_ERRNO";
              call.args.push_back({ 0, 1, 0, "SCMP_CMP_ALMOST" });
              sc.syscalls.push_back(call);
              s.linux_->seccomp = sc;
          }, "unknown operator" },
        { "seccomp arg index", [](SSpec& s) {
              SSeccompSpec sc;
              sc.defaultAction = "SCMP_ACT_ALLOW";
              SSyscallSpec call;
              call.names = { "read" };
              call.action = "SCMP_ACT_ERRNO";
              call.args.push_back({ 6, 1, 0, "SCMP_CMP_EQ" });
              sc.syscalls.push_back(call);
              s.linux_->seccomp = sc;
          }, "out of range" },
        { "masked relative", [](SSpec& s) { s.linux_->maskedPaths.push_back("proc/x"); }, "must be an absolute path" },
        { "hook relative", [](SSpec& s) {
              SHooks h;
              h.poststart.push_back({ "hook" });
              s.hooks = h;
          }, "must be absolute" },
        { "hook timeout", [](SSpec& s) {
              SHooks h;
              h.poststop.push_back({ "/bin/true", {}, {}, 0 });
              s.hooks = h;
          }, "timeout" },
        { "mount destination", [](SSpec& s) { s.mounts.push_back({ "", "tmpfs", "tmpfs" }); }, "destination must be set" },
    };

    for (const Case& c : cases) {
        SSpec s = base();
        c.mutate(s);
        std::string err;
        CHECK_MESSAGE(ValidateSpec(s, err) == -EINVAL, c.name);
        CHECK_MESSAGE(err.find(c.expect) != std::string::npos, c.name << ": " << err);
    }

    // --> Allowed variants.
    SSpec ok = base();
    ok.linux_->sysctl = { { "net.ipv4.ip_forward", "1" }, { "kernel.shmmax", "100" }, { "fs.mqueue.msg_max", "10" } };
    std::string err;
    std::vector<std::string> warnings;
    CHECK_MESSAGE(ValidateSpec(ok, err, &warnings) == SBOX_OK, err);

    ok.process->capabilities->bounding.push_back("CAP_BOGUS");
    ok.mounts.push_back({ "relative", "tmpfs", "tmpfs" });
    CHECK(ValidateSpec(ok, err, &warnings) == SBOX_OK);
    std::string all;
    for (const std::string& w : warnings) {
        all += w + "\n";
    }

    CHECK(all.find("CAP_BOGUS") != std::string::npos);
    CHECK(all.find("is relative") != std::string::npos);

    SValidateOptions noProc;
    noProc.requireProcess = false;
    SSpec np = base();
    np.process.reset();
    CHECK(ValidateSpec(np, err, nullptr, noProc) == SBOX_OK);
}

TEST_CASE("process and resources documents parse on their own") {
    CJson doc;
    REQUIRE(CJson::parse(R"({"user":{"uid":0,"gid":0},"args":["sh","-c","echo hi"],"env":["PATH=/bin"],"cwd":"/",
                             "capabilities":{"bounding":["CAP_KILL"]},"noNewPrivileges":true})", doc) == SBOX_OK);
    SProcessSpec p;
    std::string err;
    REQUIRE(ParseProcess(doc, p, err) == SBOX_OK);
    CHECK(p.args.size() == 3);
    CHECK(p.capabilities->bounding[0] == "CAP_KILL");
    CHECK(jsonEqual(ProcessToJson(p), doc));

    REQUIRE(CJson::parse(R"({"memory":{"limit":1048576},"pids":{"limit":10},"cpu":{"quota":1000,"period":10000}})", doc) == SBOX_OK);
    SResourcesSpec r;
    REQUIRE(ParseResources(doc, r, err) == SBOX_OK);
    CHECK(r.memory->limit == 1048576);
    CHECK(!r.memory->swap);
    CHECK(jsonEqual(ResourcesToJson(r), doc));

    REQUIRE(CJson::parse(R"({"memory":{"limit":true}})", doc) == SBOX_OK);
    CHECK(ParseResources(doc, r, err, nullptr, "resources") == -EINVAL);
    CHECK(err == "resources.memory.limit: expected a 64-bit integer");
}

TEST_CASE("name tables") {
    CHECK(RlimitFromName("RLIMIT_NOFILE") == RLIMIT_NOFILE);
    CHECK(RlimitFromName("RLIMIT_RTTIME") == RLIMIT_RTTIME);
    CHECK(RlimitFromName("NOFILE") == -ENOENT);

    CHECK(CapabilityName(0) == "CAP_CHOWN");
    CHECK(CapabilityName(21) == "CAP_SYS_ADMIN");
    CHECK(CapabilityName(40) == "CAP_CHECKPOINT_RESTORE");
    CHECK(CapabilityName(64).empty());
    for (int32_t c = 0; c <= 40; ++c) {
        CHECK(CapabilityFromName(CapabilityName(c)) == c);
    }

    CHECK(NamespaceFromName("network") == ENS_NET);
    CHECK(NamespaceFromName("time") == ENS_TIME);
    CHECK(NamespaceFromName("net") == ENS_NONE);
    CHECK(std::string(NamespaceProcName("mount")) == "mnt");
    CHECK(NamespaceProcName("bogus") == nullptr);
}
