#include "devicefilter.hpp"
#include <cerrno>
#include <cstring>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace sbox {

    namespace {

        /**
         * Minimal eBPF emitter for the device program.
         */
        class Emitter {
        public:
            std::vector<bpf_insn> code;

            void emit(uint8_t op, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
                bpf_insn in{};
                in.code = op;
                in.dst_reg = dst & 0xf;
                in.src_reg = src & 0xf;
                in.off = off;
                in.imm = imm;
                code.push_back(in);
            }

            /** Load a 32-bit word of the context (r1) into `dst`. */
            void loadCtx(uint8_t dst, int16_t offset) {
                emit(BPF_LDX | BPF_MEM | BPF_W, dst, BPF_REG_1, offset, 0);
            }

            /** Returns the index of a "jump if dst != imm" whose offset is patched later. */
            size_t jumpNe(uint8_t dst, int32_t imm) {
                emit(BPF_JMP | BPF_JNE | BPF_K, dst, 0, 0, imm);
                return code.size() - 1;
            }

            void patchTo(size_t at, size_t target) {
                code[at].off = int16_t(int64_t(target) - int64_t(at) - 1);
            }
        };

        uint32_t accessBits(const std::string& access) noexcept {
            uint32_t bits = 0;
            for (char c : access) {
                if (c == 'm') {
                    bits |= BPF_DEVCG_ACC_MKNOD;
                } else if (c == 'r') {
                    bits |= BPF_DEVCG_ACC_READ;
                } else if (c == 'w') {
                    bits |= BPF_DEVCG_ACC_WRITE;
                }
            }

            return bits;
        }

    }

    /* Validates device rules. */
    bool DeviceFilter::validate(const std::vector<SCgroupDeviceRule>& rules) noexcept {
        for (const SCgroupDeviceRule& r : rules) {
            if (r.type != 'a' && r.type != 'c' && r.type != 'b') {
                return false;
            }

            for (char c : r.access) {
                if (c != 'r' && c != 'w' && c != 'm') {
                    return false;
                }
            }
        }

        return true;
    }

    /* Builds, loads and attaches the device program. */
    int32_t DeviceFilter::attach(int cgroupFd, const std::vector<SCgroupDeviceRule>& rules, CFd& program) {
        if (!validate(rules)) {
            return -EINVAL;
        }

        Emitter e;

        // --> ctx: struct bpf_cgroup_dev_ctx { u32 access_type; u32 major; u32 minor; }
        // r2 = type (low 16 bits), r3 = access (high 16 bits), r4 = major, r5 = minor.
        e.loadCtx(BPF_REG_2, 0);
        e.emit(BPF_ALU | BPF_AND | BPF_K, BPF_REG_2, 0, 0, 0xffff);
        e.loadCtx(BPF_REG_3, 0);
        e.emit(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_3, 0, 0, 16);
        e.loadCtx(BPF_REG_4, 4);
        e.loadCtx(BPF_REG_5, 8);

        // --> Last match wins: test the rules from the end; the first hit returns.
        bool unconditional = false;
        for (size_t i = rules.size(); i-- > 0;) {
            const SCgroupDeviceRule& r = rules[i];
            std::vector<size_t> toNext;

            if (r.type == 'c') {
                toNext.push_back(e.jumpNe(BPF_REG_2, BPF_DEVCG_DEV_CHAR));
            } else if (r.type == 'b') {
                toNext.push_back(e.jumpNe(BPF_REG_2, BPF_DEVCG_DEV_BLOCK));
            }

            uint32_t acc = accessBits(r.access);
            if (acc != (BPF_DEVCG_ACC_MKNOD | BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE)) {
                // --> Requested access must be a subset of the rule's: (r3 & ~acc) == 0.
                e.emit(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_3, 0, 0);
                e.emit(BPF_ALU | BPF_AND | BPF_K, BPF_REG_1, 0, 0, int32_t(~acc));
                toNext.push_back(e.jumpNe(BPF_REG_1, 0));
            }

            if (r.type != 'a' && r.major >= 0) {
                toNext.push_back(e.jumpNe(BPF_REG_4, int32_t(r.major)));
            }

            if (r.type != 'a' && r.minor >= 0) {
                toNext.push_back(e.jumpNe(BPF_REG_5, int32_t(r.minor)));
            }

            e.emit(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, r.allow ? 1 : 0);
            e.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

            if (toNext.empty()) {
                // --> Unconditional: earlier rules can never be reached (and the verifier
                // rejects unreachable instructions).
                unconditional = true;
                break;
            }

            for (size_t at : toNext) {
                e.patchTo(at, e.code.size());
            }

            // --> r1 was clobbered by the access test; later rules only use r2..r5.
        }

        if (!unconditional) {
            // --> Nothing matched: allow (the v1 controller's initial state).
            e.emit(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1);
            e.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        }

        static const char license[] = "Apache-2.0";
        union bpf_attr load;
        std::memset(&load, 0, sizeof(load));
        load.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
        load.insns = uint64_t(uintptr_t(e.code.data()));
        load.insn_cnt = uint32_t(e.code.size());
        load.license = uint64_t(uintptr_t(license));

        int fd = int(::syscall(SYS_bpf, BPF_PROG_LOAD, &load, sizeof(load)));
        if (fd < 0) {
            return -errno;
        }

        CFd prog(fd);

        union bpf_attr att;
        std::memset(&att, 0, sizeof(att));
        att.target_fd = uint32_t(cgroupFd);
        att.attach_bpf_fd = uint32_t(prog.get());
        att.attach_type = BPF_CGROUP_DEVICE;
        att.attach_flags = BPF_F_ALLOW_MULTI;

        if (::syscall(SYS_bpf, BPF_PROG_ATTACH, &att, sizeof(att)) != 0) {
            return -errno;
        }

        program = std::move(prog);
        return SBOX_OK;
    }

} // namespace sbox
