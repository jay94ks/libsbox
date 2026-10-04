#include <sbox/box/seccomp.hpp>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace sbox {

    namespace {

        struct SyscallEntry {
            const char* name;
            int32_t nr;
        };

#include "syscalls.inc"

        constexpr uint32_t X32_SYSCALL_BIT = 0x40000000u;
        constexpr size_t MAX_INSNS = 4096;              // --> BPF_MAXINSNS.
        constexpr size_t DISPATCH_BLOCK = 64;           // --> Keeps every conditional jump < 256.
        constexpr int32_t NEXT = -1;                    // --> "Fall through" jump target.

        constexpr uint32_t OFF_NR = 0;                  // --> offsetof(struct seccomp_data, nr)
        constexpr uint32_t OFF_ARCH = 4;                // --> offsetof(struct seccomp_data, arch)
        constexpr uint32_t OFF_ARGS = 16;               // --> offsetof(struct seccomp_data, args)

        /**
         * Returns the generated table of an ABI.
         */
        const SyscallEntry* tableOf(ESeccompArch arch, size_t& count) noexcept {
            switch (arch) {
            case ESARCH_X86_64:
                count = sizeof(SYSCALLS_X86_64) / sizeof(SYSCALLS_X86_64[0]);
                return SYSCALLS_X86_64;

            case ESARCH_X86:
                count = sizeof(SYSCALLS_X86) / sizeof(SYSCALLS_X86[0]);
                return SYSCALLS_X86;

            case ESARCH_X32:
                count = sizeof(SYSCALLS_X32) / sizeof(SYSCALLS_X32[0]);
                return SYSCALLS_X32;

            case ESARCH_AARCH64:
                count = sizeof(SYSCALLS_AARCH64) / sizeof(SYSCALLS_AARCH64[0]);
                return SYSCALLS_AARCH64;

            default:
                count = 0;
                return nullptr;
            }
        }

        /**
         * Tiny classic BPF assembler with symbolic forward labels.
         */
        class Assembler {
        private:
            struct Insn {
                uint16_t code;
                uint32_t k;
                int32_t jt;         // --> Label id or NEXT (conditional jumps), target (ja).
                int32_t jf;
            };

            std::vector<Insn> _code;
            std::vector<int32_t> _labels;

        public:
            int32_t label() {
                _labels.push_back(-1);
                return int32_t(_labels.size() - 1);
            }

            void bind(int32_t id) {
                _labels[size_t(id)] = int32_t(_code.size());
            }

            void load(uint32_t offset) {
                _code.push_back(Insn{ uint16_t(BPF_LD | BPF_W | BPF_ABS), offset, NEXT, NEXT });
            }

            void andK(uint32_t mask) {
                _code.push_back(Insn{ uint16_t(BPF_ALU | BPF_AND | BPF_K), mask, NEXT, NEXT });
            }

            void jump(uint16_t op, uint32_t k, int32_t jt, int32_t jf) {
                _code.push_back(Insn{ uint16_t(BPF_JMP | op | BPF_K), k, jt, jf });
            }

            void jumpAlways(int32_t target) {
                _code.push_back(Insn{ uint16_t(BPF_JMP | BPF_JA), 0, target, NEXT });
            }

            void ret(uint32_t value) {
                _code.push_back(Insn{ uint16_t(BPF_RET | BPF_K), value, NEXT, NEXT });
            }

            /**
             * Resolves labels into relative offsets.
             */
            int32_t finish(std::vector<SBpfInstruction>& out) const {
                if (_code.size() > MAX_INSNS) {
                    return -E2BIG;
                }

                out.clear();
                out.reserve(_code.size());

                for (size_t pc = 0; pc < _code.size(); ++pc) {
                    const Insn& in = _code[pc];
                    SBpfInstruction o{ in.code, 0, 0, in.k };

                    auto offsetTo = [&](int32_t id, int64_t& off) -> bool {
                        if (id == NEXT) {
                            off = 0;
                            return true;
                        }

                        int32_t target = _labels[size_t(id)];
                        off = int64_t(target) - int64_t(pc) - 1;
                        return target >= 0 && off >= 0;
                    };

                    if (BPF_CLASS(in.code) == BPF_JMP) {
                        int64_t t = 0, f = 0;
                        if (!offsetTo(in.jt, t)) {
                            return -EINVAL;
                        }

                        if (BPF_OP(in.code) == BPF_JA) {
                            o.k = uint32_t(t);
                        } else {
                            if (!offsetTo(in.jf, f) || t > 255 || f > 255) {
                                return -E2BIG;
                            }

                            o.jt = uint8_t(t);
                            o.jf = uint8_t(f);
                        }
                    }

                    out.push_back(o);
                }

                return SBOX_OK;
            }
        };

        /**
         * One resolved rule of one system call on one ABI.
         */
        struct ResolvedRule {
            const SSeccompRule* rule;
            uint32_t value;     // --> SECCOMP_RET_* value.
        };

        /**
         * Emits one argument condition. Falls through when it holds, jumps to `fail` otherwise.
         */
        void emitCondition(Assembler& as, const SSeccompArg& arg, bool wide, int32_t fail) {
            uint32_t lo = OFF_ARGS + arg.index * 8;
            uint32_t hi = lo + 4;           // --> Every supported ABI is little endian.

            uint64_t value = arg.value;
            uint32_t vlo = uint32_t(value), vhi = uint32_t(value >> 32);

            if (!wide) {
                // --> 32-bit ABIs: the upper half of an argument is always zero, so only the low
                // word is compared and an operand with upper bits set decides statically.
                bool upper = vhi != 0;

                switch (arg.op) {
                case ESCMP_EQ:
                    if (upper) { as.jumpAlways(fail); return; }
                    as.load(lo);
                    as.jump(BPF_JEQ, vlo, NEXT, fail);
                    return;

                case ESCMP_NE:
                    if (upper) { return; }
                    as.load(lo);
                    as.jump(BPF_JEQ, vlo, fail, NEXT);
                    return;

                case ESCMP_GT:
                    if (upper) { as.jumpAlways(fail); return; }
                    as.load(lo);
                    as.jump(BPF_JGT, vlo, NEXT, fail);
                    return;

                case ESCMP_GE:
                    if (upper) { as.jumpAlways(fail); return; }
                    as.load(lo);
                    as.jump(BPF_JGE, vlo, NEXT, fail);
                    return;

                case ESCMP_LT:
                    if (upper) { return; }
                    as.load(lo);
                    as.jump(BPF_JGE, vlo, fail, NEXT);
                    return;

                case ESCMP_LE:
                    if (upper) { return; }
                    as.load(lo);
                    as.jump(BPF_JGT, vlo, fail, NEXT);
                    return;

                case ESCMP_MASKED_EQ: {
                    uint64_t expect = arg.valueTwo & arg.value;
                    if (expect >> 32) { as.jumpAlways(fail); return; }
                    as.load(lo);
                    as.andK(uint32_t(arg.value));
                    as.jump(BPF_JEQ, uint32_t(expect), NEXT, fail);
                    return;
                }

                default:
                    return;
                }
            }

            int32_t pass = as.label();

            switch (arg.op) {
            case ESCMP_EQ:
                as.load(hi);
                as.jump(BPF_JEQ, vhi, NEXT, fail);
                as.load(lo);
                as.jump(BPF_JEQ, vlo, NEXT, fail);
                break;

            case ESCMP_NE:
                as.load(hi);
                as.jump(BPF_JEQ, vhi, NEXT, pass);
                as.load(lo);
                as.jump(BPF_JEQ, vlo, fail, NEXT);
                break;

            case ESCMP_GT:
                as.load(hi);
                as.jump(BPF_JGT, vhi, pass, NEXT);
                as.jump(BPF_JEQ, vhi, NEXT, fail);
                as.load(lo);
                as.jump(BPF_JGT, vlo, NEXT, fail);
                break;

            case ESCMP_GE:
                as.load(hi);
                as.jump(BPF_JGT, vhi, pass, NEXT);
                as.jump(BPF_JEQ, vhi, NEXT, fail);
                as.load(lo);
                as.jump(BPF_JGE, vlo, NEXT, fail);
                break;

            case ESCMP_LT:
                as.load(hi);
                as.jump(BPF_JGT, vhi, fail, NEXT);
                as.jump(BPF_JEQ, vhi, NEXT, pass);
                as.load(lo);
                as.jump(BPF_JGE, vlo, fail, NEXT);
                break;

            case ESCMP_LE:
                as.load(hi);
                as.jump(BPF_JGT, vhi, fail, NEXT);
                as.jump(BPF_JEQ, vhi, NEXT, pass);
                as.load(lo);
                as.jump(BPF_JGT, vlo, fail, NEXT);
                break;

            case ESCMP_MASKED_EQ: {
                uint64_t expect = arg.valueTwo & arg.value;
                as.load(hi);
                as.andK(uint32_t(arg.value >> 32));
                as.jump(BPF_JEQ, uint32_t(expect >> 32), NEXT, fail);
                as.load(lo);
                as.andK(uint32_t(arg.value));
                as.jump(BPF_JEQ, uint32_t(expect), NEXT, fail);
                break;
            }

            default:
                break;
            }

            as.bind(pass);
        }

        /**
         * Emits the dispatch table and rule bodies of one ABI. The number is already in A.
         */
        void emitSection(Assembler& as, ESeccompArch arch, const std::map<int32_t, std::vector<ResolvedRule>>& calls, uint32_t defaultValue) {
            bool wide = arch != ESARCH_X86;

            struct Entry {
                int32_t nr;
                const std::vector<ResolvedRule>* rules;
                bool simple;            // --> One unconditional rule: jump straight to its return.
                int32_t body;           // --> Body label when not simple.
            };

            std::vector<Entry> entries;
            for (const auto& [nr, rules] : calls) {
                Entry e{ nr, &rules, rules.size() == 1 && rules[0].rule->args.empty(), -1 };
                if (!e.simple) {
                    e.body = as.label();
                }

                entries.push_back(e);
            }

            int32_t sectionDefault = as.label();

            for (size_t start = 0; start < entries.size(); start += DISPATCH_BLOCK) {
                size_t end = std::min(entries.size(), start + DISPATCH_BLOCK);

                // --> Local return / trampoline labels, so each jt stays within this block.
                std::map<uint32_t, int32_t> rets;
                std::vector<std::pair<int32_t, int32_t>> trampolines;   // --> (label, body)

                for (size_t i = start; i < end; ++i) {
                    const Entry& e = entries[i];
                    int32_t target;

                    if (e.simple) {
                        uint32_t value = (*e.rules)[0].value;
                        auto it = rets.find(value);
                        if (it == rets.end()) {
                            it = rets.emplace(value, as.label()).first;
                        }

                        target = it->second;
                    } else {
                        target = as.label();
                        trampolines.emplace_back(target, e.body);
                    }

                    as.jump(BPF_JEQ, uint32_t(e.nr), target, NEXT);
                }

                // --> No match in this block: skip its returns and go on with the next block.
                int32_t nextBlock = end < entries.size() ? as.label() : sectionDefault;
                as.jumpAlways(nextBlock);

                for (const auto& [value, id] : rets) {
                    as.bind(id);
                    as.ret(value);
                }

                for (const auto& [id, body] : trampolines) {
                    as.bind(id);
                    as.jumpAlways(body);
                }

                if (nextBlock != sectionDefault) {
                    as.bind(nextBlock);
                }
            }

            as.bind(sectionDefault);
            as.ret(defaultValue);

            for (const Entry& e : entries) {
                if (e.simple) {
                    continue;
                }

                as.bind(e.body);
                bool finalUnconditional = false;

                for (const ResolvedRule& r : *e.rules) {
                    if (r.rule->args.empty()) {
                        as.ret(r.value);
                        finalUnconditional = true;
                        break;
                    }

                    int32_t nextRule = as.label();
                    for (const SSeccompArg& arg : r.rule->args) {
                        emitCondition(as, arg, wide, nextRule);
                    }

                    as.ret(r.value);
                    as.bind(nextRule);
                }

                if (!finalUnconditional) {
                    as.ret(defaultValue);
                }
            }
        }

        /**
         * Resolves the profile's rules for one ABI: number -> ordered rules.
         */
        int32_t resolve(const SSeccompProfile& profile, ESeccompArch arch, std::map<int32_t, std::vector<ResolvedRule>>& out, std::vector<std::vector<bool>>& seen) {
            std::map<int32_t, std::vector<ResolvedRule>> withArgs, plain;

            for (size_t ri = 0; ri < profile.rules.size(); ++ri) {
                const SSeccompRule& rule = profile.rules[ri];

                if (rule.action == ESACT_INVALID || rule.action > ESACT_ALLOW) {
                    return -EINVAL;
                }

                for (const SSeccompArg& arg : rule.args) {
                    if (arg.index > 5 || arg.op == ESCMP_INVALID || arg.op > ESCMP_MASKED_EQ) {
                        return -EINVAL;
                    }
                }

                uint32_t value = SeccompActionValue(rule.action, rule.errnoRet);

                for (size_t ni = 0; ni < rule.names.size(); ++ni) {
                    int32_t nr = SyscallNumber(rule.names[ni], arch);
                    if (nr < 0) {
                        continue;
                    }

                    seen[ri][ni] = true;
                    (rule.args.empty() ? plain : withArgs)[nr].push_back(ResolvedRule{ &rule, value });
                }
            }

            out = std::move(withArgs);
            for (auto& [nr, rules] : plain) {
                // --> Only the first unconditional rule can ever match; later ones are dead.
                out[nr].push_back(rules.front());
            }

            return SBOX_OK;
        }

    }

    /* Converts an action to SECCOMP_RET_*. */
    uint32_t SeccompActionValue(ESeccompAction action, uint32_t data) noexcept {
        switch (action) {
        case ESACT_KILL_PROCESS: return SECCOMP_RET_KILL_PROCESS;
        case ESACT_KILL_THREAD: return SECCOMP_RET_KILL_THREAD;
        case ESACT_TRAP: return SECCOMP_RET_TRAP;
        case ESACT_ERRNO: return SECCOMP_RET_ERRNO | (data & SECCOMP_RET_DATA);
        case ESACT_TRACE: return SECCOMP_RET_TRACE | (data & SECCOMP_RET_DATA);
        case ESACT_LOG: return SECCOMP_RET_LOG;
        case ESACT_ALLOW: return SECCOMP_RET_ALLOW;
        default: return SECCOMP_RET_KILL_PROCESS;
        }
    }

    /* Returns the compiled-for ABI. */
    ESeccompArch SeccompNativeArch() noexcept {
#if defined(__x86_64__) && defined(__ILP32__)
        return ESARCH_X32;
#elif defined(__x86_64__)
        return ESARCH_X86_64;
#elif defined(__i386__)
        return ESARCH_X86;
#elif defined(__aarch64__)
        return ESARCH_AARCH64;
#else
        return ESARCH_INVALID;
#endif
    }

    /* Returns AUDIT_ARCH_* of an ABI. */
    uint32_t SeccompAuditArch(ESeccompArch arch) noexcept {
        switch (arch) {
        case ESARCH_X86_64:
        case ESARCH_X32:
            return AUDIT_ARCH_X86_64;

        case ESARCH_X86:
            return AUDIT_ARCH_I386;

        case ESARCH_AARCH64:
            return AUDIT_ARCH_AARCH64;

        default:
            return 0;
        }
    }

    /* Parses an architecture name. */
    ESeccompArch SeccompArchFromName(std::string_view name) noexcept {
        if (name.substr(0, 10) == "SCMP_ARCH_") {
            name.remove_prefix(10);
        }

        std::string lower(name);
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') {
                c = char(c - 'A' + 'a');
            }
        }

        if (lower == "x86_64" || lower == "amd64") {
            return ESARCH_X86_64;
        }

        if (lower == "x86" || lower == "i386" || lower == "i686" || lower == "386") {
            return ESARCH_X86;
        }

        if (lower == "x32") {
            return ESARCH_X32;
        }

        if (lower == "aarch64" || lower == "arm64") {
            return ESARCH_AARCH64;
        }

        return ESARCH_INVALID;
    }

    /* Looks a system call number up by name. */
    int32_t SyscallNumber(std::string_view name, ESeccompArch arch) noexcept {
        size_t count = 0;
        const SyscallEntry* table = tableOf(arch, count);

        // --> The generated tables are sorted by name.
        const SyscallEntry* end = table + count;
        const SyscallEntry* it = std::lower_bound(table, end, name, [](const SyscallEntry& e, std::string_view n) {
            return std::string_view(e.name) < n;
        });

        if (it != end && std::string_view(it->name) == name) {
            return it->nr;
        }

        return -ENOENT;
    }

    /* Looks a system call name up by number. */
    const char* SyscallName(int32_t nr, ESeccompArch arch) noexcept {
        size_t count = 0;
        const SyscallEntry* table = tableOf(arch, count);

        for (size_t i = 0; i < count; ++i) {
            if (table[i].nr == nr) {
                return table[i].name;
            }
        }

        return nullptr;
    }

    /* Compiles a profile into classic BPF. */
    int32_t CSeccompFilter::compile(const SSeccompProfile& profile, CSeccompFilter& out, std::vector<std::string>* unknown) {
        if (profile.defaultAction == ESACT_INVALID || profile.defaultAction > ESACT_ALLOW ||
            profile.badArchAction == ESACT_INVALID || profile.badArchAction > ESACT_ALLOW) {
            return -EINVAL;
        }

        std::vector<ESeccompArch> arches = profile.architectures;
        if (arches.empty()) {
            arches.push_back(SeccompNativeArch());
        }

        std::sort(arches.begin(), arches.end());
        arches.erase(std::unique(arches.begin(), arches.end()), arches.end());

        for (ESeccompArch a : arches) {
            if (SeccompAuditArch(a) == 0) {
                return -EINVAL;
            }
        }

        auto has = [&](ESeccompArch a) {
            return std::find(arches.begin(), arches.end(), a) != arches.end();
        };

        uint32_t defaultValue = SeccompActionValue(profile.defaultAction, profile.defaultErrno);
        uint32_t badArch = SeccompActionValue(profile.badArchAction, profile.defaultErrno);

        std::vector<std::vector<bool>> seen(profile.rules.size());
        for (size_t ri = 0; ri < profile.rules.size(); ++ri) {
            seen[ri].assign(profile.rules[ri].names.size(), false);
        }

        std::map<ESeccompArch, std::map<int32_t, std::vector<ResolvedRule>>> perArch;
        for (ESeccompArch a : arches) {
            if (int32_t rc = resolve(profile, a, perArch[a], seen); rc != SBOX_OK) {
                return rc;
            }
        }

        if (unknown) {
            unknown->clear();
            for (size_t ri = 0; ri < profile.rules.size(); ++ri) {
                for (size_t ni = 0; ni < profile.rules[ri].names.size(); ++ni) {
                    if (!seen[ri][ni]) {
                        unknown->push_back(profile.rules[ri].names[ni]);
                    }
                }
            }
        }

        // --> Distinct AUDIT_ARCH values: x86_64 and x32 share one and are split by the x32 bit.
        std::vector<uint32_t> sections;
        for (ESeccompArch a : arches) {
            uint32_t audit = SeccompAuditArch(a);
            if (std::find(sections.begin(), sections.end(), audit) == sections.end()) {
                sections.push_back(audit);
            }
        }

        Assembler bpf;
        std::vector<int32_t> sectionLabels;
        for (size_t i = 0; i < sections.size(); ++i) {
            sectionLabels.push_back(bpf.label());
        }

        bpf.load(OFF_ARCH);
        for (size_t i = 0; i < sections.size(); ++i) {
            int32_t skip = bpf.label();
            // --> jeq + ja: the long jump keeps any section distance reachable.
            bpf.jump(BPF_JEQ, sections[i], NEXT, skip);
            bpf.jumpAlways(sectionLabels[i]);
            bpf.bind(skip);
        }

        bpf.ret(badArch);

        for (size_t i = 0; i < sections.size(); ++i) {
            bpf.bind(sectionLabels[i]);
            bpf.load(OFF_NR);

            if (sections[i] == AUDIT_ARCH_X86_64) {
                // --> BPF only jumps forward, so the x32 target is a fresh label after this code.
                int32_t x32Label = bpf.label();
                int32_t below = bpf.label();
                bpf.jump(BPF_JGE, X32_SYSCALL_BIT, NEXT, below);
                bpf.jumpAlways(x32Label);
                bpf.bind(below);

                if (has(ESARCH_X86_64)) {
                    emitSection(bpf, ESARCH_X86_64, perArch[ESARCH_X86_64], defaultValue);
                } else {
                    bpf.ret(badArch);
                }

                bpf.bind(x32Label);
                if (has(ESARCH_X32)) {
                    emitSection(bpf, ESARCH_X32, perArch[ESARCH_X32], defaultValue);
                } else {
                    bpf.ret(badArch);
                }

                continue;
            }

            for (ESeccompArch a : arches) {
                if (SeccompAuditArch(a) == sections[i]) {
                    emitSection(bpf, a, perArch[a], defaultValue);
                }
            }
        }

        out._flags = profile.flags;
        return bpf.finish(out._program);
    }

    /* Installs the filter on the calling thread. */
    int32_t CSeccompFilter::install() const noexcept {
        if (_program.empty()) {
            return -EINVAL;
        }

        struct sock_fprog prog;
        prog.len = (unsigned short) _program.size();
        prog.filter = (struct sock_filter*) (const void*) _program.data();

        static_assert(sizeof(SBpfInstruction) == sizeof(struct sock_filter), "layout mismatch");

        if (::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, (unsigned long) _flags, &prog) != 0) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Interprets the program on a synthetic seccomp_data. */
    uint32_t CSeccompFilter::evaluate(uint32_t auditArch, int32_t nr, const uint64_t args[6]) const noexcept {
        uint32_t data[16];
        data[0] = uint32_t(nr);
        data[1] = auditArch;
        data[2] = 0;
        data[3] = 0;
        for (size_t i = 0; i < 6; ++i) {
            data[4 + i * 2] = uint32_t(args[i]);
            data[5 + i * 2] = uint32_t(args[i] >> 32);
        }

        uint32_t a = 0;
        size_t pc = 0;

        while (pc < _program.size()) {
            const SBpfInstruction& in = _program[pc++];

            switch (BPF_CLASS(in.code)) {
            case BPF_LD:
                if (in.k % 4 != 0 || in.k / 4 >= 16) {
                    return SECCOMP_RET_KILL_PROCESS;
                }

                a = data[in.k / 4];
                break;

            case BPF_ALU:
                if (BPF_OP(in.code) == BPF_AND) {
                    a &= in.k;
                }

                break;

            case BPF_JMP: {
                bool cond = false;
                switch (BPF_OP(in.code)) {
                case BPF_JA:
                    pc += in.k;
                    continue;

                case BPF_JEQ: cond = a == in.k; break;
                case BPF_JGT: cond = a > in.k; break;
                case BPF_JGE: cond = a >= in.k; break;
                case BPF_JSET: cond = (a & in.k) != 0; break;
                default: break;
                }

                pc += cond ? in.jt : in.jf;
                break;
            }

            case BPF_RET:
                return in.k;

            default:
                return SECCOMP_RET_KILL_PROCESS;
            }
        }

        return SECCOMP_RET_KILL_PROCESS;
    }

    /* Built-in allowlist for general programs. */
    SSeccompProfile SSeccompProfile::general(ESeccompViolation violation) {
        SSeccompProfile p;
        p.defaultErrno = EPERM;

        switch (violation) {
        case ESVIO_KILL:
            p.defaultAction = ESACT_KILL_PROCESS;
            break;

        case ESVIO_LOG:
            p.defaultAction = ESACT_LOG;
            break;

        default:
            p.defaultAction = ESACT_ERRNO;
            break;
        }

        p.badArchAction = ESACT_KILL_PROCESS;

        // --> 32-bit x86 and x32 programs are rejected (bad arch): fewer ABIs, less surface.
        p.architectures = { SeccompNativeArch() };

        SSeccompRule allow;
        allow.action = ESACT_ALLOW;
        allow.names = {
            // File descriptors and file I/O.
            "read", "write", "readv", "writev", "pread64", "pwrite64", "preadv", "pwritev", "preadv2",
            "pwritev2", "open", "openat", "openat2", "creat", "close", "close_range", "lseek", "_llseek",
            "stat", "fstat", "lstat", "newfstatat", "fstatat64", "stat64", "fstat64", "lstat64", "statx",
            "statfs", "fstatfs", "statfs64", "fstatfs64", "access", "faccessat", "faccessat2", "readlink",
            "readlinkat", "getdents", "getdents64", "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
            "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat", "chmod", "fchmod",
            "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat", "truncate", "ftruncate",
            "fallocate", "fadvise64", "fsync", "fdatasync", "sync", "syncfs", "sync_file_range",
            "copy_file_range", "sendfile", "splice", "tee", "vmsplice", "dup", "dup2", "dup3", "fcntl",
            "flock", "ioctl", "umask", "utime", "utimes", "utimensat", "futimesat", "getcwd", "chdir",
            "fchdir", "mknod", "mknodat", "pipe", "pipe2", "select", "pselect6", "poll", "ppoll",
            "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
            "eventfd", "eventfd2", "signalfd", "signalfd4", "timerfd_create", "timerfd_settime",
            "timerfd_gettime", "inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
            "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "setxattr",
            "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "memfd_create",
            "cachestat", "fanotify_mark",
            // Memory.
            "brk", "mmap", "munmap", "mremap", "mprotect", "madvise", "mlock", "mlock2", "munlock",
            "mlockall", "munlockall", "msync", "mincore", "membarrier", "pkey_mprotect", "pkey_alloc",
            "pkey_free", "get_mempolicy", "mseal", "map_shadow_stack", "process_madvise",
            // Processes, threads and signals.
            "execve", "execveat", "exit", "exit_group", "fork", "vfork", "wait4", "waitid", "kill",
            "tkill", "tgkill", "getpid", "getppid", "gettid", "getpgid", "setpgid", "getpgrp", "getsid",
            "setsid", "getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid", "getgroups",
            "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
            "setfsuid", "setfsgid", "capget", "capset", "prctl", "arch_prctl", "set_tid_address",
            "set_robust_list", "get_robust_list", "futex", "futex_waitv", "futex_wait", "futex_wake",
            "futex_requeue", "rseq", "sched_yield", "sched_getaffinity", "sched_setaffinity",
            "sched_getparam", "sched_setparam", "sched_getscheduler", "sched_setscheduler",
            "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
            "sched_getattr", "sched_setattr", "getpriority", "setpriority", "ioprio_get", "ioprio_set",
            "getrlimit", "setrlimit", "prlimit64", "getrusage", "times", "uname", "sysinfo", "getcpu",
            "restart_syscall", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
            "rt_sigsuspend", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "sigaltstack",
            "pause", "alarm", "nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres",
            "gettimeofday", "time", "getitimer", "setitimer", "timer_create", "timer_settime",
            "timer_gettime", "timer_getoverrun", "timer_delete", "getrandom", "pidfd_open",
            "pidfd_send_signal", "seccomp", "landlock_create_ruleset", "landlock_add_rule",
            "landlock_restrict_self",
            // Sockets (reach is limited by the network namespace and the mounted sockets).
            "socketpair", "bind", "connect", "listen", "accept", "accept4", "getsockname",
            "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
            "shutdown", "setsockopt", "getsockopt",
            // System V and POSIX IPC (namespaced by the IPC namespace).
            "shmget", "shmat", "shmdt", "shmctl", "semget", "semop", "semtimedop", "semctl", "msgget",
            "msgsnd", "msgrcv", "msgctl", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
            "mq_notify", "mq_getsetattr",
        };
        p.rules.push_back(allow);

        // --> clone without namespace flags only: new namespaces would undo the sandbox's view.
        SSeccompRule clone;
        clone.action = ESACT_ALLOW;
        clone.names = { "clone" };
        clone.args = { SSeccompArg{ 0, ESCMP_MASKED_EQ,
            uint64_t(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP | 0x80 /* CLONE_NEWTIME */),
            0 } };
        p.rules.push_back(clone);

        // --> clone3 takes its flags in memory a filter cannot read; ENOSYS makes libc use clone.
        SSeccompRule clone3;
        clone3.action = ESACT_ERRNO;
        clone3.errnoRet = ENOSYS;
        clone3.names = { "clone3" };
        p.rules.push_back(clone3);

        // --> Every socket family but AF_VSOCK, which is not isolated by network namespaces.
        SSeccompRule socket;
        socket.action = ESACT_ALLOW;
        socket.names = { "socket" };
        socket.args = { SSeccompArg{ 0, ESCMP_NE, uint64_t(AF_VSOCK), 0 } };
        p.rules.push_back(socket);

        // --> personality: only the harmless personas (as Docker), no READ_IMPLIES_EXEC etc.
        for (uint64_t persona : { uint64_t(0x0), uint64_t(0x8), uint64_t(0x20000), uint64_t(0x20008), uint64_t(0xffffffff) }) {
            SSeccompRule r;
            r.action = ESACT_ALLOW;
            r.names = { "personality" };
            r.args = { SSeccompArg{ 0, ESCMP_EQ, persona, 0 } };
            p.rules.push_back(r);
        }

        return p;
    }

} // namespace sbox
