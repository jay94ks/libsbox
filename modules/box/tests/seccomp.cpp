#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/box/seccomp.hpp>
#include <cerrno>
#include <csignal>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;

namespace {

    const uint64_t NO_ARGS[6] = { 0, 0, 0, 0, 0, 0 };

    uint32_t eval(const CSeccompFilter& f, ESeccompArch arch, const char* name, uint64_t a0 = 0, uint64_t a1 = 0) {
        uint64_t args[6] = { a0, a1, 0, 0, 0, 0 };
        int32_t nr = SyscallNumber(name, arch);
        REQUIRE(nr >= 0);
        return f.evaluate(SeccompAuditArch(arch), nr, args);
    }

    bool compare(ESeccompCompare op, uint64_t arg, uint64_t value, uint64_t two) {
        switch (op) {
        case ESCMP_NE: return arg != value;
        case ESCMP_LT: return arg < value;
        case ESCMP_LE: return arg <= value;
        case ESCMP_EQ: return arg == value;
        case ESCMP_GE: return arg >= value;
        case ESCMP_GT: return arg > value;
        case ESCMP_MASKED_EQ: return (arg & value) == two;
        default: return false;
        }
    }

    /**
     * Runs `fn` in a forked child and returns its wait status.
     */
    template<typename F>
    int inChild(F fn) {
        pid_t pid = ::fork();
        if (pid == 0) {
            ::_exit(fn());
        }

        int st = 0;
        ::waitpid(pid, &st, 0);
        return st;
    }

}

TEST_CASE("syscall tables resolve names and numbers per ABI") {
    CHECK(SyscallNumber("read", ESARCH_X86_64) == 0);
    CHECK(SyscallNumber("execve", ESARCH_X86_64) == 59);
    CHECK(SyscallNumber("read", ESARCH_X86) == 3);
    CHECK(SyscallNumber("read", ESARCH_X32) == 0x40000000);
    CHECK(SyscallNumber("read", ESARCH_AARCH64) == 63);
    CHECK(SyscallNumber("openat", ESARCH_AARCH64) == 56);
    CHECK(SyscallNumber("open", ESARCH_AARCH64) == -ENOENT);
    CHECK(SyscallNumber("clone3", ESARCH_X86_64) == 435);
    CHECK(SyscallNumber("mseal", ESARCH_AARCH64) == 462);
    CHECK(SyscallNumber("no_such_call", ESARCH_X86_64) == -ENOENT);
    CHECK(std::string(SyscallName(59, ESARCH_X86_64)) == "execve");
    CHECK(SyscallName(99999, ESARCH_X86_64) == nullptr);

    CHECK(SeccompArchFromName("SCMP_ARCH_X86_64") == ESARCH_X86_64);
    CHECK(SeccompArchFromName("amd64") == ESARCH_X86_64);
    CHECK(SeccompArchFromName("SCMP_ARCH_AARCH64") == ESARCH_AARCH64);
    CHECK(SeccompArchFromName("arm64") == ESARCH_AARCH64);
    CHECK(SeccompArchFromName("SCMP_ARCH_X86") == ESARCH_X86);
    CHECK(SeccompArchFromName("SCMP_ARCH_X32") == ESARCH_X32);
    CHECK(SeccompArchFromName("SCMP_ARCH_MIPS") == ESARCH_INVALID);
    CHECK(SeccompNativeArch() != ESARCH_INVALID);
}

TEST_CASE("general profile allows ordinary calls and denies dangerous ones") {
    CSeccompFilter f;
    std::vector<std::string> unknown;
    REQUIRE(CSeccompFilter::compile(SSeccompProfile::general(ESVIO_ERRNO), f, &unknown) == SBOX_OK);
    CHECK(f.program().size() < 4096);

    ESeccompArch a = SeccompNativeArch();
    uint32_t eperm = SECCOMP_RET_ERRNO | EPERM;

    CHECK(eval(f, a, "read") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "openat") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "execve") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "exit_group") == SECCOMP_RET_ALLOW);

    for (const char* denied : { "ptrace", "mount", "umount2", "kexec_load", "bpf", "perf_event_open", "userfaultfd",
                                "keyctl", "add_key", "unshare", "setns", "io_uring_setup", "open_by_handle_at",
                                "init_module", "reboot", "pivot_root", "chroot", "process_vm_readv", "settimeofday" }) {
        if (SyscallNumber(denied, a) >= 0) {
            CHECK_MESSAGE(eval(f, a, denied) == eperm, denied);
        }
    }

    CHECK(eval(f, a, "clone", SIGCHLD) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "clone", CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "clone", CLONE_NEWUSER | SIGCHLD) == eperm);
    CHECK(eval(f, a, "clone", CLONE_NEWNS) == eperm);
    CHECK(eval(f, a, "clone", CLONE_NEWNET) == eperm);
    CHECK(eval(f, a, "clone3") == (SECCOMP_RET_ERRNO | ENOSYS));

    CHECK(eval(f, a, "socket", AF_INET) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "socket", AF_UNIX) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "socket", AF_VSOCK) == eperm);

    CHECK(eval(f, a, "personality", 0) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "personality", 0xffffffffu) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, a, "personality", 0x0400000) == eperm);

    // --> Another ABI (or the x32 bit on x86_64) is a bad arch.
    CHECK(f.evaluate(0x12345678, 0, NO_ARGS) == SECCOMP_RET_KILL_PROCESS);
    if (a == ESARCH_X86_64) {
        CHECK(f.evaluate(AUDIT_ARCH_X86_64, 0x40000000, NO_ARGS) == SECCOMP_RET_KILL_PROCESS);
        CHECK(f.evaluate(AUDIT_ARCH_I386, 3, NO_ARGS) == SECCOMP_RET_KILL_PROCESS);
    }

    SSeccompProfile kill = SSeccompProfile::general(ESVIO_KILL);
    CSeccompFilter k;
    REQUIRE(CSeccompFilter::compile(kill, k) == SBOX_OK);
    CHECK(eval(k, a, "ptrace") == SECCOMP_RET_KILL_PROCESS);
    CHECK(eval(k, a, "read") == SECCOMP_RET_ALLOW);
}

TEST_CASE("64-bit argument comparisons match their definition") {
    const uint64_t points[] = {
        0, 1, 2, 0x7fffffffull, 0x80000000ull, 0xfffffffeull, 0xffffffffull, 0x100000000ull,
        0x100000001ull, 0x1ffffffffull, 0xfffffffe00000000ull, 0xffffffff00000000ull,
        0xffffffffffffffffull, 0x8000000000000000ull, 0x123456789abcdefull,
    };

    const ESeccompCompare ops[] = { ESCMP_NE, ESCMP_LT, ESCMP_LE, ESCMP_EQ, ESCMP_GE, ESCMP_GT, ESCMP_MASKED_EQ };

    for (ESeccompCompare op : ops) {
        for (uint64_t value : points) {
            uint64_t two = value & 0xff00ff00ff00ff00ull;

            SSeccompProfile p;
            p.defaultAction = ESACT_ERRNO;
            p.defaultErrno = 1;
            p.architectures = { ESARCH_X86_64 };
            SSeccompRule r;
            r.names = { "read" };
            r.action = ESACT_ALLOW;
            r.args = { SSeccompArg{ 1, op, value, two } };
            p.rules.push_back(r);

            CSeccompFilter f;
            REQUIRE(CSeccompFilter::compile(p, f) == SBOX_OK);

            for (uint64_t arg : points) {
                uint64_t args[6] = { 0, arg, 0, 0, 0, 0 };
                uint32_t got = f.evaluate(AUDIT_ARCH_X86_64, 0, args);
                bool expect = compare(op, arg, value, two);
                CHECK_MESSAGE((got == SECCOMP_RET_ALLOW) == expect,
                              "op ", int(op), " value ", value, " arg ", arg);
            }
        }
    }
}

TEST_CASE("32-bit ABIs compare the low word only") {
    SSeccompProfile p;
    p.defaultAction = ESACT_ERRNO;
    p.architectures = { ESARCH_X86 };

    SSeccompRule lt;
    lt.names = { "read" };
    lt.args = { SSeccompArg{ 0, ESCMP_LT, 10, 0 } };
    p.rules.push_back(lt);

    SSeccompRule big;
    big.names = { "write" };
    big.args = { SSeccompArg{ 0, ESCMP_EQ, 0x100000000ull, 0 } };
    p.rules.push_back(big);

    CSeccompFilter f;
    REQUIRE(CSeccompFilter::compile(p, f) == SBOX_OK);

    uint64_t five[6] = { 5, 0, 0, 0, 0, 0 };
    uint64_t twenty[6] = { 20, 0, 0, 0, 0, 0 };
    CHECK(f.evaluate(AUDIT_ARCH_I386, 3, five) == SECCOMP_RET_ALLOW);
    CHECK(f.evaluate(AUDIT_ARCH_I386, 3, twenty) == (SECCOMP_RET_ERRNO | 1));
    CHECK(f.evaluate(AUDIT_ARCH_I386, 4, NO_ARGS) == (SECCOMP_RET_ERRNO | 1));
}

TEST_CASE("multi-architecture profiles (Docker style) dispatch per ABI") {
    SSeccompProfile p;
    p.defaultAction = ESACT_ERRNO;
    p.defaultErrno = EPERM;
    p.architectures = { ESARCH_X86_64, ESARCH_X86, ESARCH_X32, ESARCH_AARCH64 };

    SSeccompRule allow;
    allow.names = { "read", "write", "open", "openat", "not_a_syscall" };
    p.rules.push_back(allow);

    SSeccompRule logged;
    logged.names = { "getpid" };
    logged.action = ESACT_LOG;
    p.rules.push_back(logged);

    SSeccompRule trap;
    trap.names = { "kill" };
    trap.action = ESACT_TRAP;
    p.rules.push_back(trap);

    CSeccompFilter f;
    std::vector<std::string> unknown;
    REQUIRE(CSeccompFilter::compile(p, f, &unknown) == SBOX_OK);
    REQUIRE(unknown.size() == 1);
    CHECK(unknown[0] == "not_a_syscall");

    CHECK(eval(f, ESARCH_X86_64, "read") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_X86, "read") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_X32, "read") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_AARCH64, "read") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_X86_64, "open") == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_X86_64, "getpid") == SECCOMP_RET_LOG);
    CHECK(eval(f, ESARCH_AARCH64, "kill") == SECCOMP_RET_TRAP);
    CHECK(eval(f, ESARCH_X32, "mount") == (SECCOMP_RET_ERRNO | EPERM));
    CHECK(eval(f, ESARCH_X86, "mount") == (SECCOMP_RET_ERRNO | EPERM));
}

TEST_CASE("argument rules are tried before the unconditional rule") {
    SSeccompProfile p;
    p.defaultAction = ESACT_ALLOW;
    p.architectures = { ESARCH_X86_64 };

    SSeccompRule plain;
    plain.names = { "write" };
    plain.action = ESACT_ERRNO;
    plain.errnoRet = EACCES;
    p.rules.push_back(plain);

    SSeccompRule toStderr;
    toStderr.names = { "write" };
    toStderr.action = ESACT_ALLOW;
    toStderr.args = { SSeccompArg{ 0, ESCMP_EQ, 2, 0 } };
    p.rules.push_back(toStderr);

    CSeccompFilter f;
    REQUIRE(CSeccompFilter::compile(p, f) == SBOX_OK);
    CHECK(eval(f, ESARCH_X86_64, "write", 2) == SECCOMP_RET_ALLOW);
    CHECK(eval(f, ESARCH_X86_64, "write", 1) == (SECCOMP_RET_ERRNO | EACCES));
    CHECK(eval(f, ESARCH_X86_64, "read") == SECCOMP_RET_ALLOW);
}

TEST_CASE("invalid profiles are rejected") {
    CSeccompFilter f;
    SSeccompProfile p;
    p.defaultAction = ESACT_INVALID;
    CHECK(CSeccompFilter::compile(p, f) == -EINVAL);

    SSeccompProfile q;
    SSeccompRule r;
    r.names = { "read" };
    r.args = { SSeccompArg{ 6, ESCMP_EQ, 0, 0 } };
    q.rules.push_back(r);
    CHECK(CSeccompFilter::compile(q, f) == -EINVAL);

    SSeccompProfile big;
    big.architectures = { SeccompNativeArch() };
    SSeccompRule many;
    many.names = { "read" };
    for (int i = 0; i < 800; ++i) {
        many.args.push_back(SSeccompArg{ 1, ESCMP_NE, uint64_t(i), 0 });
    }

    big.rules.push_back(many);
    CHECK(CSeccompFilter::compile(big, f) == -E2BIG);
}

TEST_CASE("installed filter returns the errno and kills on violation") {
    // --> errno action: mkdir fails with EACCES, everything else works.
    int st = inChild([]() {
        SSeccompProfile p;
        p.defaultAction = ESACT_ALLOW;
        SSeccompRule r;
        r.names = { "mkdir", "mkdirat" };
        r.action = ESACT_ERRNO;
        r.errnoRet = EACCES;
        p.rules.push_back(r);

        CSeccompFilter f;
        if (CSeccompFilter::compile(p, f) != SBOX_OK) {
            return 10;
        }

        ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (f.install() != SBOX_OK) {
            return 11;
        }

        if (::mkdir("/tmp/sbox-seccomp-should-not-exist", 0700) == 0 || errno != EACCES) {
            return 12;
        }

        return ::getpid() > 0 ? 0 : 13;
    });

    CHECK(WIFEXITED(st));
    CHECK(WEXITSTATUS(st) == 0);

    // --> kill action: the process dies by SIGSYS.
    st = inChild([]() {
        SSeccompProfile p = SSeccompProfile::general(ESVIO_KILL);
        CSeccompFilter f;
        if (CSeccompFilter::compile(p, f) != SBOX_OK) {
            return 10;
        }

        ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (f.install() != SBOX_OK) {
            return 11;
        }

        ::syscall(SYS_ptrace, 0, 0, 0, 0);
        return 12;
    });

    CHECK(WIFSIGNALED(st));
    CHECK(WTERMSIG(st) == SIGSYS);

    // --> The general profile in errno mode keeps a normal program working.
    st = inChild([]() {
        CSeccompFilter f;
        if (CSeccompFilter::compile(SSeccompProfile::general(ESVIO_ERRNO), f) != SBOX_OK) {
            return 10;
        }

        ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (f.install() != SBOX_OK) {
            return 11;
        }

        if (::unshare(CLONE_NEWUSER) == 0 || errno != EPERM) {
            return 12;
        }

        pid_t pid = ::fork();
        if (pid == 0) {
            ::_exit(4);
        }

        int cst = 0;
        ::waitpid(pid, &cst, 0);
        return WEXITSTATUS(cst) == 4 ? 0 : 13;
    });

    CHECK(WIFEXITED(st));
    CHECK(WEXITSTATUS(st) == 0);
}
