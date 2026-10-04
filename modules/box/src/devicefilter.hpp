#ifndef __SRC_BOX_DEVICEFILTER_HPP__
#define __SRC_BOX_DEVICEFILTER_HPP__

#include <sbox/box/cgroup.hpp>

namespace sbox {

    /**
     * Builds and attaches the eBPF program (BPF_PROG_TYPE_CGROUP_DEVICE) that enforces device
     * rules on a cgroup v2 directory, the v2 replacement of the v1 devices controller.
     */
    class DeviceFilter {
    public:
        /**
         * Loads a program for `rules` and attaches it to the cgroup directory `cgroupFd`.
         * @param program Receives the program descriptor (keep it to detach/replace later).
         * @return SBOX_OK or a negated errno (-EPERM without CAP_SYS_ADMIN/CAP_BPF).
         */
        static int32_t attach(int cgroupFd, const std::vector<SCgroupDeviceRule>& rules, CFd& program);

        /**
         * Validates the rules (type and access letters).
         */
        static bool validate(const std::vector<SCgroupDeviceRule>& rules) noexcept;
    };

} // namespace sbox

#endif
