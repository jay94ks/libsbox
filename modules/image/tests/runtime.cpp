#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "support.hpp"
#include <sbox/image/runtime.hpp>

using namespace sbox;
using namespace sbox::image;
using namespace testsupport;

namespace {

    const char* PASSWD = "root:x:0:0:root:/root:/bin/sh\n"
                         "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                         "# comment\n"
                         "app:x:1000:1000:App User:/home/app:/bin/sh\n"
                         "broken line\n";

    const char* GROUP = "root:x:0:\n"
                        "wheel:x:10:app,other\n"
                        "app:x:1000:\n"
                        "audio:x:29:app\n"
                        "staff:x:50:\n";

    /* Writes a tiny rootfs with user databases. */
    std::string makeRootfs(const TempDir& tmp) {
        std::string root = tmp.sub("rootfs");
        CFile::makeDirs(CFile::join(root, "etc"));
        CFile::writeAtomic(CFile::join(root, "etc/passwd"), PASSWD);
        CFile::writeAtomic(CFile::join(root, "etc/group"), GROUP);
        return root;
    }

    /* Returns true when a rule in the converted profile names `syscall`. */
    const CJson* findRule(const CJson& seccomp, const std::string& syscall) {
        const CJson& calls = seccomp.get("syscalls");
        for (size_t i = 0; i < calls.size(); ++i) {
            for (const std::string& n : calls.at(i).get("names").asStrings()) {
                if (n == syscall) {
                    return &calls.at(i);
                }
            }
        }

        return nullptr;
    }

}

TEST_CASE("users and groups resolve through the rootfs databases") {
    TempDir tmp;
    std::string root = makeRootfs(tmp);
    SResolvedUser u;
    REQUIRE(ResolveUser(root, "", u) == SBOX_OK);
    CHECK(u.uid == 0);
    CHECK(u.home == "/root");
    REQUIRE(ResolveUser(root, "app", u) == SBOX_OK);
    CHECK(u.uid == 1000);
    CHECK(u.gid == 1000);
    CHECK(u.home == "/home/app");
    CHECK(u.additionalGids == std::vector<uint32_t>{ 10, 29 });
    REQUIRE(ResolveUser(root, "app:staff", u) == SBOX_OK);
    CHECK(u.gid == 50);
    REQUIRE(ResolveUser(root, "1000:7", u) == SBOX_OK);
    CHECK(u.uid == 1000);
    CHECK(u.gid == 7);
    REQUIRE(ResolveUser(root, "4242", u) == SBOX_OK);
    CHECK(u.uid == 4242);
    CHECK(u.gid == 0);
    CHECK(u.home == "/");
    std::string error;
    CHECK(ResolveUser(root, "nobody", u, &error) == -ENOENT);
    CHECK(error.find("no matching entries in passwd") != std::string::npos);
    CHECK(ResolveUser(root, "app:nogroup", u) == -ENOENT);
    CHECK(ResolveUser(root, "app:", u) == -EINVAL);

    // --> /etc/passwd as a symlink pointing outside the rootfs is resolved inside it.
    std::string evil = tmp.sub("evil");
    CFile::makeDirs(CFile::join(evil, "etc"));
    REQUIRE(::symlink("/../../../../etc/passwd-not-here", CFile::join(evil, "etc/passwd").c_str()) == 0);
    CHECK(ResolveUser(evil, "root", u) == -ENOENT);
}

TEST_CASE("image config to OCI runtime spec") {
    TempDir tmp;
    std::string root = makeRootfs(tmp);
    SImageConfig cfg;
    cfg.architecture = HostPlatform().architecture;
    cfg.os = "linux";
    cfg.entrypoint = { "/entry.sh" };
    cfg.cmd = { "serve", "--port", "80" };
    cfg.env = { "PATH=/opt/bin:/usr/bin", "LANG=C.UTF-8" };
    cfg.workingDir = "/srv";
    cfg.user = "app";
    cfg.exposedPorts = { "80/tcp", "53/udp" };
    cfg.volumes = { "/data" };
    cfg.stopSignal = "SIGQUIT";
    cfg.labels = { { "org.example.team", "infra" } };

    SBundleOptions o;
    o.hostname = "box1";
    o.env = { "LANG=en_US.UTF-8", "EXTRA=1" };
    CJson spec;
    std::string error;
    REQUIRE(GenerateRuntimeSpec(cfg, root, o, spec, &error) == SBOX_OK);
    CHECK(spec.get("ociVersion").asString() == "1.2.0");
    const CJson& p = spec.get("process");
    CHECK(p.get("args").asStrings() == std::vector<std::string>{ "/entry.sh", "serve", "--port", "80" });
    CHECK(p.get("cwd").asString() == "/srv");
    CHECK(p.get("user").get("uid").asInt() == 1000);
    CHECK(p.get("user").get("gid").asInt() == 1000);
    CHECK(p.get("user").get("additionalGids").size() == 2);
    std::vector<std::string> env = p.get("env").asStrings();
    CHECK(env == std::vector<std::string>{ "PATH=/opt/bin:/usr/bin", "HOSTNAME=box1", "LANG=en_US.UTF-8", "EXTRA=1", "HOME=/home/app" });
    std::vector<std::string> caps = p.get("capabilities").get("bounding").asStrings();
    CHECK(caps.size() == 14);
    CHECK(std::find(caps.begin(), caps.end(), "CAP_NET_BIND_SERVICE") != caps.end());
    CHECK(std::find(caps.begin(), caps.end(), "CAP_SYS_ADMIN") == caps.end());
    CHECK(spec.get("hostname").asString() == "box1");
    CHECK(spec.get("root").get("path").asString() == "rootfs");

    std::vector<std::string> dests;
    const CJson& mounts = spec.get("mounts");
    for (size_t i = 0; i < mounts.size(); ++i) {
        dests.push_back(mounts.at(i).get("destination").asString());
    }

    CHECK(dests == std::vector<std::string>{ "/proc", "/dev", "/dev/pts", "/sys", "/sys/fs/cgroup", "/dev/mqueue", "/dev/shm" });
    const CJson& ann = spec.get("annotations");
    CHECK(ann.get("org.example.team").asString() == "infra");
    CHECK(ann.get("org.opencontainers.image.exposedPorts").asString() == "80/tcp,53/udp");
    CHECK(ann.get("org.opencontainers.image.stopSignal").asString() == "SIGQUIT");
    CHECK(ann.get("org.sbox.image.volumes").asString() == "/data");

    const CJson& lnx = spec.get("linux");
    CHECK(lnx.get("namespaces").size() == 6);
    CHECK(lnx.get("maskedPaths").size() > 5);
    CHECK(lnx.get("readonlyPaths").asStrings().front() == "/proc/bus");
    CHECK(lnx.get("resources").get("devices").at(0).get("allow").asBool(true) == false);
    const CJson& sec = lnx.get("seccomp");
    CHECK(sec.get("defaultAction").asString() == "SCMP_ACT_ERRNO");
    CHECK(sec.get("defaultErrnoRet").asInt() == 1);
    CHECK(findRule(sec, "read") != nullptr);
    CHECK(findRule(sec, "mount") == nullptr);       // --> Needs CAP_SYS_ADMIN.
    CHECK(findRule(sec, "reboot") == nullptr);
    const CJson* clone = findRule(sec, "clone");
    REQUIRE(clone != nullptr);
    CHECK(clone->get("args").at(0).get("op").asString() == "SCMP_CMP_MASKED_EQ");
    const CJson* clone3 = findRule(sec, "clone3");
    REQUIRE(clone3 != nullptr);
    CHECK(clone3->get("errnoRet").asInt() == 38);
    if (HostPlatform().architecture == "amd64") {
        CHECK(sec.get("architectures").asStrings() == std::vector<std::string>{ "SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32" });
        CHECK(findRule(sec, "arch_prctl") != nullptr);
    }

    // --> Overrides: entrypoint drops Cmd, cap-add/-drop, terminal, rootless.
    SBundleOptions o2;
    o2.hasEntrypoint = true;
    o2.entrypoint = { "/bin/sh", "-c" };
    o2.capAdd = { "sys_admin" };
    o2.capDrop = { "CAP_NET_RAW" };
    o2.terminal = true;
    o2.user = "0:0";
    o2.rootless = true;
    o2.readOnlyRoot = true;
    CJson spec2;
    REQUIRE(GenerateRuntimeSpec(cfg, root, o2, spec2) == SBOX_OK);
    CHECK(spec2.get("process").get("args").asStrings() == std::vector<std::string>{ "/bin/sh", "-c" });
    std::vector<std::string> caps2 = spec2.get("process").get("capabilities").get("effective").asStrings();
    CHECK(std::find(caps2.begin(), caps2.end(), "CAP_SYS_ADMIN") != caps2.end());
    CHECK(std::find(caps2.begin(), caps2.end(), "CAP_NET_RAW") == caps2.end());
    std::vector<std::string> env2 = spec2.get("process").get("env").asStrings();
    CHECK(std::find(env2.begin(), env2.end(), "TERM=xterm") != env2.end());
    CHECK(std::find(env2.begin(), env2.end(), "HOME=/root") != env2.end());
    CHECK(spec2.get("root").get("readonly").asBool());
    CHECK(spec2.get("linux").get("uidMappings").at(0).get("hostID").asInt() == int64_t(::getuid()));
    CHECK(!spec2.get("linux").find("resources"));
    const CJson& sec2 = spec2.get("linux").get("seccomp");
    CHECK(findRule(sec2, "mount") != nullptr);
    CHECK(findRule(sec2, "clone3")->get("action").asString() == "SCMP_ACT_ALLOW");

    // --> No command at all is an error; an unknown user too.
    SImageConfig empty;
    CHECK(GenerateRuntimeSpec(empty, root, SBundleOptions(), spec, &error) == -EINVAL);
    SImageConfig ghost = cfg;
    ghost.user = "ghost";
    CHECK(GenerateRuntimeSpec(ghost, root, SBundleOptions(), spec, &error) == -ENOENT);
}

TEST_CASE("Docker's default seccomp profile converts per architecture") {
    CJson profile;
    REQUIRE(CJson::parse(DockerDefaultSeccompProfile(), profile) == SBOX_OK);
    CHECK(profile.get("syscalls").size() > 20);
    CJson arm;
    REQUIRE(SeccompProfileToOci(profile, "arm64", DefaultCapabilities(), arm) == SBOX_OK);
    CHECK(arm.get("architectures").asStrings() == std::vector<std::string>{ "SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM" });
    CHECK(findRule(arm, "arch_prctl") == nullptr);
    CHECK(findRule(arm, "cacheflush") != nullptr);
    CJson s390;
    REQUIRE(SeccompProfileToOci(profile, "s390x", DefaultCapabilities(), s390) == SBOX_OK);
    const CJson* clone = findRule(s390, "clone");
    REQUIRE(clone != nullptr);
    CHECK(clone->get("args").at(0).get("index").asInt() == 1);
    CJson bad;
    CHECK(SeccompProfileToOci(CJson("x"), "amd64", {}, bad) == -EINVAL);
}

TEST_CASE("bundles: rootfs plus config.json") {
    TempDir tmp;
    CContentStorePtr store;
    REQUIRE(CContentStore::open(tmp.sub("store"), store) == SBOX_OK);
    TestImage img = BuildImage({ { Dir("etc"), File("etc/passwd", PASSWD), File("etc/group", GROUP), File("hello", "world") } }, "", false,
                               { "/hello" }, "app");
    REQUIRE(ImportImage(*store, img, "bundle/test:1") == SBOX_OK);
    SImageInfo info;
    REQUIRE(store->resolve("bundle/test:1", info) == SBOX_OK);
    CSnapshotter snap(store);
    std::string dir = tmp.sub("bundle");
    std::string id;
    std::string error;
    int32_t r = CreateBundle(snap, info, dir, SBundleOptions(), ESNAP_COPY, &id, &error);
    CAPTURE(error);
    REQUIRE(r == SBOX_OK);
    CHECK(ReadText(CFile::join(dir, "rootfs/hello")) == "world");
    CJson spec;
    REQUIRE(CJson::parse(ReadText(CFile::join(dir, "config.json")), spec) == SBOX_OK);
    CHECK(spec.get("process").get("user").get("uid").asInt() == 1000);
    CHECK(spec.get("annotations").get("org.sbox.image.container").asString() == id);
    CHECK(spec.get("annotations").get("org.opencontainers.image.ref.name").asString() == "docker.io/bundle/test:1");
    CHECK(CreateBundle(snap, info, dir, SBundleOptions(), ESNAP_COPY, nullptr, &error) == -EEXIST);
    SContainerInfo c;
    REQUIRE(snap.container(id, c) == SBOX_OK);
    CHECK(c.rootfs == CFile::join(dir, "rootfs"));
    REQUIRE(snap.remove(id) == SBOX_OK);
    CHECK(CFile::exists(CFile::join(dir, "rootfs/hello")));

    if (IsRoot() && snap.overlaySupported()) {
        std::string dir2 = tmp.sub("bundle2");
        std::string id2;
        REQUIRE(CreateBundle(snap, info, dir2, SBundleOptions(), ESNAP_OVERLAY, &id2, &error) == SBOX_OK);
        CHECK(ReadText(CFile::join(dir2, "rootfs/hello")) == "world");
        REQUIRE(snap.remove(id2) == SBOX_OK);
        CHECK(!CFile::exists(CFile::join(dir2, "rootfs/hello")));
    } else {
        MESSAGE("overlay bundle skipped: needs root and overlayfs");
    }
}
