#ifndef __INCLUDE_SBOX_VPN_WG_KERNEL_HPP__
#define __INCLUDE_SBOX_VPN_WG_KERNEL_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/netlink.hpp>
#include <sbox/vpn/wg/engine.hpp>

namespace sbox {
namespace vpn {

    // -- The `wireguard` generic netlink family (include/uapi/linux/wireguard.h), spelled out
    // so the library builds without the kernel header.

    /** Name of the generic netlink family. */
    constexpr const char* WG_GENL_NAME = "wireguard";

    /** Version of the generic netlink family. */
    constexpr uint8_t WG_GENL_VERSION = 1;

    /**
     * Commands of the family (WG_CMD_*).
     */
    enum EWgCmd : uint8_t {
        EWGC_GET_DEVICE = 0,
        EWGC_SET_DEVICE = 1,
    };

    /**
     * Device attributes (WGDEVICE_A_*).
     */
    enum EWgDeviceAttr : uint16_t {
        EWGDA_UNSPEC = 0,
        EWGDA_IFINDEX = 1,          // --> u32
        EWGDA_IFNAME = 2,           // --> string
        EWGDA_PRIVATE_KEY = 3,      // --> 32 bytes
        EWGDA_PUBLIC_KEY = 4,       // --> 32 bytes (get only)
        EWGDA_FLAGS = 5,            // --> u32, EWGDF_*
        EWGDA_LISTEN_PORT = 6,      // --> u16
        EWGDA_FWMARK = 7,           // --> u32
        EWGDA_PEERS = 8,            // --> nested list of peers
    };

    /**
     * Device flags (WGDEVICE_F_*).
     */
    enum EWgDeviceFlag : uint32_t {
        EWGDF_REPLACE_PEERS = 1u << 0,
    };

    /**
     * Peer attributes (WGPEER_A_*).
     */
    enum EWgPeerAttr : uint16_t {
        EWGPA_UNSPEC = 0,
        EWGPA_PUBLIC_KEY = 1,
        EWGPA_PRESHARED_KEY = 2,
        EWGPA_FLAGS = 3,                        // --> u32, EWGPF_*
        EWGPA_ENDPOINT = 4,                     // --> struct sockaddr_in / sockaddr_in6
        EWGPA_PERSISTENT_KEEPALIVE_INTERVAL = 5, // --> u16
        EWGPA_LAST_HANDSHAKE_TIME = 6,          // --> struct __kernel_timespec (get only)
        EWGPA_RX_BYTES = 7,                     // --> u64 (get only)
        EWGPA_TX_BYTES = 8,                     // --> u64 (get only)
        EWGPA_ALLOWEDIPS = 9,                   // --> nested list of allowed IPs
        EWGPA_PROTOCOL_VERSION = 10,            // --> u32
    };

    /**
     * Peer flags (WGPEER_F_*).
     */
    enum EWgPeerFlag : uint32_t {
        EWGPF_REMOVE_ME = 1u << 0,
        EWGPF_REPLACE_ALLOWEDIPS = 1u << 1,
        EWGPF_UPDATE_ONLY = 1u << 2,
    };

    /**
     * Allowed-IP attributes (WGALLOWEDIP_A_*).
     */
    enum EWgAllowedIpAttr : uint16_t {
        EWGAA_UNSPEC = 0,
        EWGAA_FAMILY = 1,           // --> u16 AF_INET / AF_INET6
        EWGAA_IPADDR = 2,           // --> 4 or 16 bytes
        EWGAA_CIDR_MASK = 3,        // --> u8
    };

    /**
     * Encodes a WG_CMD_SET_DEVICE change as one or more messages (large peer lists are split
     * the way `wg` splits them: later messages carry only peers, and a peer whose allowed IPs do
     * not fit continues with EWGPF_UPDATE_ONLY in the next message).
     * @param maxBytes Size budget of one message.
     */
    SBOX_API std::vector<net::CNlMessage> BuildWgSetDevice(uint16_t familyId, const std::string& ifName,
        const SWgDeviceConfig& config, size_t maxBytes = 16384);

    /**
     * Encodes a WG_CMD_GET_DEVICE request for a device name (sent as a dump).
     */
    SBOX_API net::CNlMessage BuildWgGetDevice(uint16_t familyId, const std::string& ifName);

    /**
     * Decodes the (possibly multi-part) WG_CMD_GET_DEVICE reply; peers split across messages
     * are merged.
     * @return SBOX_OK or -EBADMSG.
     */
    SBOX_API int32_t ParseWgGetDevice(const std::vector<net::SNlReply>& replies, SWgDeviceStatus& out);

    /**
     * Client of the kernel module's generic netlink family in one network namespace.
     */
    class SBOX_API CWgKernelClient {
    private:
        net::CNetlinkSocket _socket;
        net::SGenlFamily _family;

    public:
        CWgKernelClient() = default;

        /**
         * Opens a generic netlink socket in `netnsPath` and resolves the family.
         * @return SBOX_OK, -ENOENT when the wireguard module is not loaded, or another error.
         */
        TTask<int32_t> open(std::string netnsPath = std::string());

        /** Returns the resolved family id. */
        inline uint16_t familyId() const noexcept { return _family.id; }

        /** Returns the kernel's message for the last failure. */
        inline const std::string& lastError() const noexcept { return _socket.lastError(); }

        /**
         * Applies a change to a device.
         */
        TTask<int32_t> setDevice(std::string ifName, SWgDeviceConfig config);

        /**
         * Reads a device.
         */
        TTask<int32_t> getDevice(std::string ifName, SWgDeviceStatus& out);
    };

}
}

#endif
