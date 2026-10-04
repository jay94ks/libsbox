#ifndef __INCLUDE_SBOX_VPN_WG_DEVICE_HPP__
#define __INCLUDE_SBOX_VPN_WG_DEVICE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/wg/config.hpp>
#include <sbox/vpn/wg/engine.hpp>
#include <sbox/vpn/wg/uapi.hpp>

namespace sbox {
namespace vpn {

    /**
     * Which implementation backs a CWgDevice.
     */
    enum EWgMode {
        EWGM_AUTO = 0,      // --> The kernel module when it exists, else user space.
        EWGM_KERNEL,        // --> Only the kernel module (-ENOTSUP without it).
        EWGM_USERSPACE,     // --> Always the user-space engine on a TUN device.
    };

    /**
     * Options of CWgDevice::create().
     */
    struct SWgDeviceOptions {
        std::string name;                       // --> Interface name (required, at most 15 characters).
        std::string netnsPath;                  // --> Namespace of the interface and the UDP socket (empty: current).
        EWgMode mode = EWGM_AUTO;
        uint32_t mtu = WG_DEFAULT_MTU;
        std::vector<net::SIpPrefix> addresses;  // --> Interface addresses (wg-quick Address).
        bool up = true;                         // --> Bring the interface up.
        bool routeAllowedIps = false;           // --> Route each peer's allowed IPs (except /0) via the interface.
        bool uapi = false;                      // --> User space: serve the UAPI socket for `wg`.
        std::string uapiDir = WG_UAPI_DIR;
        SWgTimers timers;                       // --> User space only.
        size_t batch = 32;                      // --> User space: packets handled per wakeup.
    };

    /**
     * A WireGuard interface, backed by the kernel module (configured over generic netlink) when it
     * is available and by the user-space CWgEngine on a TUN device otherwise. Both expose the same
     * operations, so callers (the overlay driver, `sbox-wg`) do not care which one runs.
     *
     * The user-space backend runs as tasks on the creating thread's CEventLoop: it lives as long as
     * the loop runs and the object (or a close()) does not stop it. The kernel backend's interface
     * outlives the object; close() deletes it.
     */
    class SBOX_API CWgDevice {
    private:
        struct SImpl;
        std::shared_ptr<SImpl> _impl;

    public:
        CWgDevice();

        CWgDevice(const CWgDevice&) = delete;

        CWgDevice& operator=(const CWgDevice&) = delete;

        CWgDevice(CWgDevice&&) noexcept;

        CWgDevice& operator=(CWgDevice&&) noexcept;

        /**
         * Stops a user-space device (its TUN interface disappears). A kernel interface stays.
         */
        ~CWgDevice();

        /**
         * Returns true when the kernel module provides the `wireguard` link type and family in
         * `netnsPath` (the probe may load the module).
         */
        static TTask<bool> kernelAvailable(std::string netnsPath = std::string());

        /**
         * Creates the interface and configures MTU, addresses and link state.
         * @return SBOX_OK, -EEXIST (name taken), -ENOTSUP (EWGM_KERNEL without the module), or
         *         another negated errno.
         */
        TTask<int32_t> create(SWgDeviceOptions options);

        /** Returns true between create() and close(). */
        bool isOpen() const noexcept;

        /** Returns true when the kernel module backs the device. */
        bool isKernel() const noexcept;

        /** Returns the interface name. */
        const std::string& name() const noexcept;

        /** Returns the interface index in its namespace. */
        int32_t ifIndex() const noexcept;

        /** Returns the options the device was created with. */
        const SWgDeviceOptions& options() const noexcept;

        /**
         * Applies a device-level change (key, port, fwmark, peers), like `wg set`.
         */
        TTask<int32_t> configure(SWgDeviceConfig config);

        /**
         * Applies a whole configuration file like `wg setconf` (peers are replaced). Host-name
         * endpoints must have been resolved (ResolveWgConfigEndpoints).
         */
        TTask<int32_t> setConfig(SWgConfig config);

        /**
         * Adds or updates one peer (routes are added when routeAllowedIps is set).
         */
        TTask<int32_t> setPeer(SWgPeerConfig peer);

        /**
         * Removes one peer.
         */
        TTask<int32_t> removePeer(SWgKey publicKey);

        /**
         * Reads the device and its peers.
         */
        TTask<int32_t> status(SWgDeviceStatus& out);

        /**
         * Returns the UDP port the device listens on (0 before configuration).
         */
        uint16_t listenPort() const noexcept;

        /**
         * Returns the user-space engine, or nullptr for a kernel device.
         */
        CWgEngine* engine() noexcept;

        /**
         * Stops the device and deletes its interface.
         */
        TTask<int32_t> close();

        /**
         * Waits until the device is closed (from close(), another task, or the UAPI socket being
         * removed). For foreground daemons such as `sbox-wg up`.
         */
        TTask<void> wait();
    };

}
}

#endif
