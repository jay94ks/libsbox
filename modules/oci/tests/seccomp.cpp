#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "ocitest.hpp"
#include <sbox/box/seccomp.hpp>
#include <sbox/oci/seccomp.hpp>
#include <sbox/oci/spec.hpp>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

namespace {

    CJson dockerProfile() {
        std::string text;
        REQUIRE(CFile::readAll(dataFile("docker-default-seccomp.json"), text) == SBOX_OK);
        CJson doc;
        REQUIRE(CJson::parse(text, doc) == SBOX_OK);
        return doc;
    }

    SDockerSeccompContext context(std::vector<std::string> caps, uint32_t major = 6, uint32_t minor = 1) {
        SDockerSeccompContext c;
        c.capabilities = std::move(caps);
        c.goArch = "amd64";
        c.kernelMajor = major;
        c.kernelMinor = minor;
        return c;
    }

    bool hasName(const SSeccompSpec& s, const std::string& name) {
        for (const SSyscallSpec& c : s.syscalls) {
            for (const std::string& n : c.names) {
                if (n == name) {
                    return true;
                }
            }
        }

        return false;
    }

    uint32_t eval(const CSeccompFilter& f, const char* name, uint64_t a0 = 0, uint64_t a1 = 0) {
        uint64_t args[6] = { a0, a1, 0, 0, 0, 0 };
        return f.evaluate(AUDIT_ARCH_X86_64, SyscallNumber(name, ESARCH_X86_64), args);
    }

}

TEST_CASE("Docker's default seccomp profile resolves like dockerd and compiles") {
    CJson profile = dockerProfile();
    SSeccompSpec spec;
    std::string err;
    REQUIRE_MESSAGE(SeccompSpecFromDockerProfile(profile, context(DockerDefaultCapabilities()), spec, err) == SBOX_OK, err);

    CHECK(spec.defaultAction == "SCMP_ACT_ERRNO");
    CHECK(spec.defaultErrnoRet == 1u);
    // --> archMap: the native architecture with its sub-architectures.
    CHECK(spec.architectures == std::vector<std::string>{ "SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32" });

    // --> Capability-gated rules: mount needs CAP_SYS_ADMIN, which Docker's default set lacks.
    CHECK(hasName(spec, "read"));
    CHECK(hasName(spec, "arch_prctl"));         // --> includes.arches: amd64
    CHECK(!hasName(spec, "mount"));
    CHECK(!hasName(spec, "s390_pci_mmio_read"));  // --> includes.arches: s390

    // --> The resolved section is valid OCI and round-trips through config.json.
    SSpec full = DefaultSpec();
    full.linux_->seccomp = spec;
    std::vector<std::string> warnings;
    REQUIRE_MESSAGE(ValidateSpec(full, err, &warnings) == SBOX_OK, err);
    SSpec back;
    REQUIRE(ParseSpec(SpecToJson(full), back, err) == SBOX_OK);
    CHECK(jsonEqual(SpecToJson(back), SpecToJson(full)));

    CSeccompFilter filter;
    std::vector<std::string> unknown;
    REQUIRE_MESSAGE(CompileSeccompSpec(spec, filter, err, &warnings, &unknown) == SBOX_OK, err);
    CHECK(filter.isValid());

    // --> Verdicts of the compiled program.
    uint32_t allow = SECCOMP_RET_ALLOW;
    uint32_t eperm = SECCOMP_RET_ERRNO | EPERM;
    CHECK(eval(filter, "read") == allow);
    CHECK(eval(filter, "openat") == allow);
    CHECK(eval(filter, "mount") == eperm);
    CHECK(eval(filter, "kexec_load") == eperm);
    CHECK(eval(filter, "personality", 0) == allow);
    CHECK(eval(filter, "personality", 0xffffffff) == allow);
    CHECK(eval(filter, "personality", 0x1234) == eperm);
    CHECK(eval(filter, "clone", SIGCHLD) == allow);
    CHECK(eval(filter, "clone", CLONE_NEWUSER | SIGCHLD) == eperm);
    // --> clone3 fails with ENOSYS so that libc falls back to clone.
    CHECK(eval(filter, "clone3") == (SECCOMP_RET_ERRNO | ENOSYS));
    CHECK(eval(filter, "ptrace") == allow);     // --> minKernel 4.8

    // --> An old kernel loses the minKernel rule.
    SSeccompSpec old;
    REQUIRE(SeccompSpecFromDockerProfile(profile, context(DockerDefaultCapabilities(), 4, 4), old, err) == SBOX_OK);
    CSeccompFilter oldFilter;
    REQUIRE(CompileSeccompSpec(old, oldFilter, err) == SBOX_OK);
    CHECK(eval(oldFilter, "ptrace") == eperm);

    // --> CAP_SYS_ADMIN opens mount and friends.
    std::vector<std::string> admin = DockerDefaultCapabilities();
    admin.push_back("CAP_SYS_ADMIN");
    SSeccompSpec privileged;
    REQUIRE(SeccompSpecFromDockerProfile(profile, context(admin), privileged, err) == SBOX_OK);
    CSeccompFilter privFilter;
    REQUIRE(CompileSeccompSpec(privileged, privFilter, err) == SBOX_OK);
    CHECK(eval(privFilter, "mount") == allow);
    CHECK(eval(privFilter, "clone", CLONE_NEWUSER | SIGCHLD) == allow);

    // --> 32-bit calls are filtered too (sub-architecture).
    uint64_t none[6] = {};
    CHECK(filter.evaluate(AUDIT_ARCH_I386, SyscallNumber("read", ESARCH_X86), none) == allow);
    CHECK(filter.evaluate(AUDIT_ARCH_I386, SyscallNumber("mount", ESARCH_X86), none) == eperm);
}

TEST_CASE("the host context of a Docker profile") {
    SDockerSeccompContext c = SDockerSeccompContext::host({ "CAP_KILL" });
    CHECK(c.kernelMajor >= 5);
    CHECK(!c.goArch.empty());
    CHECK(c.capabilities.size() == 1);
}

TEST_CASE("Docker profile errors") {
    SSeccompSpec spec;
    std::string err;
    CJson doc;
    REQUIRE(CJson::parse(R"({"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],"archMap":[]})", doc) == SBOX_OK);
    CHECK(SeccompSpecFromDockerProfile(doc, context({}), spec, err) == -EINVAL);
    CHECK(err.find("cannot both be set") != std::string::npos);

    REQUIRE(CJson::parse(R"({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"a","names":["b"],"action":"SCMP_ACT_ALLOW"}]})", doc) == SBOX_OK);
    CHECK(SeccompSpecFromDockerProfile(doc, context({}), spec, err) == -EINVAL);

    REQUIRE(CJson::parse(R"({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"read","action":"SCMP_ACT_ALLOW","excludes":{"caps":["CAP_X"]}}]})", doc) == SBOX_OK);
    REQUIRE(SeccompSpecFromDockerProfile(doc, context({}), spec, err) == SBOX_OK);
    CHECK(spec.syscalls.size() == 1);
    REQUIRE(SeccompSpecFromDockerProfile(doc, context({ "CAP_X" }), spec, err) == SBOX_OK);
    CHECK(spec.syscalls.empty());
}

TEST_CASE("OCI seccomp semantics: actions, errno defaults, flags, architectures") {
    SSeccompSpec s;
    s.defaultAction = "SCMP_ACT_ALLOW";
    s.architectures = { "SCMP_ARCH_X86", "SCMP_ARCH_ARM" };
    s.flags = { "SECCOMP_FILTER_FLAG_LOG", "SECCOMP_FILTER_FLAG_TSYNC", "SECCOMP_FILTER_FLAG_SPEC_ALLOW" };
    s.syscalls = {
        { { "mkdir" }, "SCMP_ACT_ERRNO", std::nullopt, {} },
        { { "rmdir" }, "SCMP_ACT_ERRNO", 13u, {} },
        { { "getppid" }, "SCMP_ACT_KILL", std::nullopt, {} },
        { { "getpgid" }, "SCMP_ACT_TRACE", std::nullopt, {} },
        { { "sethostname" }, "SCMP_ACT_LOG", std::nullopt, {} },
        { { "no_such_call" }, "SCMP_ACT_ERRNO", std::nullopt, {} },
    };

    SSeccompProfile profile;
    std::string err;
    std::vector<std::string> warnings;
    REQUIRE(SeccompProfileFromSpec(s, profile, err, &warnings) == SBOX_OK);
    CHECK(profile.flags == (ESECF_LOG | ESECF_SPEC_ALLOW));
    // --> Native first (libseccomp always includes it), ARM skipped with a warning.
    REQUIRE(profile.architectures.size() == 2);
    CHECK(profile.architectures[0] == SeccompNativeArch());
    CHECK(profile.architectures[1] == ESARCH_X86);
    REQUIRE(warnings.size() == 1);
    CHECK(warnings[0].find("SCMP_ARCH_ARM") != std::string::npos);
    CHECK(profile.rules[0].errnoRet == uint32_t(EPERM));
    CHECK(profile.rules[1].errnoRet == 13u);
    CHECK(profile.rules[2].action == ESACT_KILL_THREAD);

    CSeccompFilter f;
    std::vector<std::string> unknown;
    REQUIRE(CompileSeccompSpec(s, f, err, nullptr, &unknown) == SBOX_OK);
    CHECK(unknown == std::vector<std::string>{ "no_such_call" });
    CHECK(eval(f, "mkdir") == (SECCOMP_RET_ERRNO | EPERM));
    CHECK(eval(f, "rmdir") == (SECCOMP_RET_ERRNO | 13));
    CHECK(eval(f, "getppid") == SECCOMP_RET_KILL_THREAD);
    CHECK(eval(f, "getpgid") == (SECCOMP_RET_TRACE | EPERM));
    CHECK(eval(f, "sethostname") == SECCOMP_RET_LOG);
    CHECK(eval(f, "read") == SECCOMP_RET_ALLOW);

    SSeccompSpec notify = s;
    notify.syscalls = { { { "read" }, "SCMP_ACT_NOTIFY", std::nullopt, {} } };
    CHECK(SeccompProfileFromSpec(notify, profile, err) == -ENOTSUP);
    CHECK(err.find("SCMP_ACT_NOTIFY") != std::string::npos);

    SSeccompSpec badFlag = s;
    badFlag.flags = { "SECCOMP_FILTER_FLAG_BOGUS" };
    CHECK(SeccompProfileFromSpec(badFlag, profile, err) == -EINVAL);

    SSeccompSpec badDefault = s;
    badDefault.defaultAction = "SCMP_ACT_MAYBE";
    CHECK(SeccompProfileFromSpec(badDefault, profile, err) == -EINVAL);
    CHECK(err.find("defaultAction") != std::string::npos);
}

TEST_CASE("a compiled Docker profile installs and denies in a child") {
    CJson profile = dockerProfile();
    SSeccompSpec spec;
    std::string err;
    REQUIRE(SeccompSpecFromDockerProfile(profile, SDockerSeccompContext::host(DockerDefaultCapabilities()), spec, err) == SBOX_OK);
    CSeccompFilter filter;
    REQUIRE(CompileSeccompSpec(spec, filter, err) == SBOX_OK);

    pid_t pid = ::fork();
    if (pid == 0) {
        ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (filter.install() != SBOX_OK) {
            ::_exit(10);
        }

        // --> unshare is denied without CAP_SYS_ADMIN; getpid works.
        if (::unshare(CLONE_NEWUTS) == 0 || errno != EPERM) {
            ::_exit(11);
        }

        if (::getpid() <= 0) {
            ::_exit(12);
        }

        ::_exit(0);
    }

    int st = 0;
    REQUIRE(::waitpid(pid, &st, 0) == pid);
    CHECK(WIFEXITED(st));
    CHECK(WEXITSTATUS(st) == 0);
}
