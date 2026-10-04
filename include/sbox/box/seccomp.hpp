#ifndef __INCLUDE_SBOX_BOX_SECCOMP_HPP__
#define __INCLUDE_SBOX_BOX_SECCOMP_HPP__

#include <sbox/common.hpp>

namespace sbox {

    /**
     * System call ABI a seccomp filter section applies to.
     */
    enum ESeccompArch : uint32_t {
        ESARCH_INVALID = 0,
        ESARCH_X86_64,          // --> AUDIT_ARCH_X86_64, syscall numbers below 0x40000000.
        ESARCH_X86,             // --> AUDIT_ARCH_I386 (32-bit x86 programs on x86_64).
        ESARCH_X32,             // --> AUDIT_ARCH_X86_64 with the 0x40000000 x32 bit set.
        ESARCH_AARCH64,         // --> AUDIT_ARCH_AARCH64.
    };

    /**
     * What the kernel does when a filter rule (or the default) matches.
     */
    enum ESeccompAction : uint32_t {
        ESACT_INVALID = 0,
        ESACT_KILL_PROCESS,     // --> SECCOMP_RET_KILL_PROCESS: the whole process dies by SIGSYS.
        ESACT_KILL_THREAD,      // --> SECCOMP_RET_KILL_THREAD: only the calling thread dies.
        ESACT_TRAP,             // --> SECCOMP_RET_TRAP: a catchable SIGSYS is delivered.
        ESACT_ERRNO,            // --> SECCOMP_RET_ERRNO: the call fails with the rule's errno.
        ESACT_TRACE,            // --> SECCOMP_RET_TRACE: a ptracer is notified (errno = trace data).
        ESACT_LOG,              // --> SECCOMP_RET_LOG: allowed, but logged by the audit subsystem.
        ESACT_ALLOW,            // --> SECCOMP_RET_ALLOW.
    };

    /**
     * Argument comparison operators (the OCI / libseccomp SCMP_CMP_* set). All comparisons are
     * unsigned and 64 bits wide (32 bits on 32-bit ABIs, where the upper half is always zero).
     */
    enum ESeccompCompare : uint32_t {
        ESCMP_INVALID = 0,
        ESCMP_NE,
        ESCMP_LT,
        ESCMP_LE,
        ESCMP_EQ,
        ESCMP_GE,
        ESCMP_GT,
        ESCMP_MASKED_EQ,        // --> (arg & value) == valueTwo.
    };

    /**
     * Filter installation flags (SECCOMP_FILTER_FLAG_*).
     */
    enum ESeccompFlags : uint32_t {
        ESECF_NONE          = 0,
        ESECF_LOG           = 1u << 1,  // --> SECCOMP_FILTER_FLAG_LOG: log every non-allow action.
        ESECF_SPEC_ALLOW    = 1u << 2,  // --> SECCOMP_FILTER_FLAG_SPEC_ALLOW: keep SSB mitigation off.
    };

    /**
     * One argument condition of a rule. All conditions of a rule must hold for it to match.
     */
    struct SSeccompArg {
        uint32_t index = 0;                 // --> Argument number, 0..5.
        ESeccompCompare op = ESCMP_INVALID;
        uint64_t value = 0;                 // --> Operand, or the mask for ESCMP_MASKED_EQ.
        uint64_t valueTwo = 0;              // --> Expected masked value for ESCMP_MASKED_EQ.
    };

    /**
     * A rule: the listed system calls take `action` when every argument condition holds.
     *
     * For one system call, rules with argument conditions are tried first in the order they were
     * given, then the first rule without conditions; the first match wins. Names unknown on an
     * architecture are skipped for that architecture (as libseccomp does).
     */
    struct SSeccompRule {
        std::vector<std::string> names;
        ESeccompAction action = ESACT_ALLOW;
        uint32_t errnoRet = 1;              // --> errno for ESACT_ERRNO (EPERM), data for ESACT_TRACE.
        std::vector<SSeccompArg> args;
    };

    /**
     * Violation behaviour of the built-in sandbox profile.
     */
    enum ESeccompViolation : uint32_t {
        ESVIO_ERRNO = 0,        // --> Denied calls fail with EPERM.
        ESVIO_KILL,             // --> Denied calls kill the process with SIGSYS.
        ESVIO_LOG,              // --> Denied calls are only logged (debugging).
    };

    /**
     * Declarative seccomp policy: default action, architectures and rules. This is what the OCI
     * `linux.seccomp` section maps to one to one, and what the sandbox profiles are made of.
     */
    struct SSeccompProfile {
        ESeccompAction defaultAction = ESACT_ERRNO;
        uint32_t defaultErrno = 1;              // --> EPERM.
        std::vector<ESeccompArch> architectures; // --> Empty means the native architecture only.
        ESeccompAction badArchAction = ESACT_KILL_PROCESS;  // --> Calls from an ABI not listed.
        uint32_t flags = ESECF_NONE;            // --> ESeccompFlags.
        std::vector<SSeccompRule> rules;

        /**
         * Returns the built-in allowlist for general programs (what glibc, Python and
         * gcc-compiled programs need). It denies ptrace, mount and friends, kexec, bpf,
         * perf_event_open, userfaultfd, the keyring, unshare/setns, clone with namespace flags,
         * io_uring, open_by_handle_at, module loading, clock and host administration calls.
         * clone3 always fails with ENOSYS so that libc falls back to the filterable clone.
         * @param violation What happens on a denied call.
         */
        static SSeccompProfile general(ESeccompViolation violation = ESVIO_ERRNO);
    };

    /**
     * One classic BPF instruction (layout of struct sock_filter).
     */
    struct SBpfInstruction {
        uint16_t code;
        uint8_t jt;
        uint8_t jf;
        uint32_t k;
    };

    /**
     * Compiled seccomp filter: classic BPF generated directly (no libseccomp).
     *
     * The program checks the architecture first (unknown ABIs take the profile's bad-arch
     * action), then dispatches on the system call number with a linear jump table per ABI, and
     * evaluates the argument conditions of the matching rules.
     */
    class SBOX_API CSeccompFilter {
    private:
        std::vector<SBpfInstruction> _program;
        uint32_t _flags = ESECF_NONE;

    public:
        /**
         * Compiles a profile.
         * @param profile The policy.
         * @param out Receives the program.
         * @param unknown When not null, receives rule names unknown on every requested ABI.
         * @return SBOX_OK; -EINVAL for an invalid action/operator/argument index; -E2BIG when the
         *         program would exceed the kernel's 4096 instruction limit.
         */
        static int32_t compile(const SSeccompProfile& profile, CSeccompFilter& out, std::vector<std::string>* unknown = nullptr);

        /** Returns the instructions. */
        inline const std::vector<SBpfInstruction>& program() const noexcept { return _program; }

        /** Returns the SECCOMP_FILTER_FLAG_* bits to install with. */
        inline uint32_t flags() const noexcept { return _flags; }

        /** Returns true when a program was compiled. */
        inline bool isValid() const noexcept { return !_program.empty(); }

        /**
         * Installs the filter on the calling thread (seccomp(SECCOMP_SET_MODE_FILTER)).
         * The caller must have set no_new_privs or hold CAP_SYS_ADMIN. Async-signal-safe.
         * @return SBOX_OK or a negated errno.
         */
        int32_t install() const noexcept;

        /**
         * Runs the program on a synthetic seccomp_data, as the kernel would (for tests and
         * diagnostics).
         * @return The SECCOMP_RET_* value the kernel would act on.
         */
        uint32_t evaluate(uint32_t auditArch, int32_t nr, const uint64_t args[6]) const noexcept;
    };

    /**
     * Returns the ABI libsbox was compiled for.
     */
    SBOX_API ESeccompArch SeccompNativeArch() noexcept;

    /**
     * Returns the AUDIT_ARCH_* value of an ABI (0 for ESARCH_INVALID).
     */
    SBOX_API uint32_t SeccompAuditArch(ESeccompArch arch) noexcept;

    /**
     * Parses an architecture name: OCI (`SCMP_ARCH_X86_64`), Go/Docker (`amd64`, `arm64`, `386`)
     * or kernel style (`x86_64`, `aarch64`, `i386`, `x32`).
     */
    SBOX_API ESeccompArch SeccompArchFromName(std::string_view name) noexcept;

    /**
     * Returns the number of a system call on an ABI, or -ENOENT when it does not exist there.
     */
    SBOX_API int32_t SyscallNumber(std::string_view name, ESeccompArch arch = SeccompNativeArch()) noexcept;

    /**
     * Returns the name of a system call number on an ABI, or nullptr.
     */
    SBOX_API const char* SyscallName(int32_t nr, ESeccompArch arch = SeccompNativeArch()) noexcept;

    /**
     * Converts an action to the kernel's SECCOMP_RET_* value.
     * @param data errno for ESACT_ERRNO, trace data for ESACT_TRACE.
     */
    SBOX_API uint32_t SeccompActionValue(ESeccompAction action, uint32_t data) noexcept;

} // namespace sbox

#endif
