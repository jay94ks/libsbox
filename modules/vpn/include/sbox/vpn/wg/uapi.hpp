#ifndef __INCLUDE_SBOX_VPN_WG_UAPI_HPP__
#define __INCLUDE_SBOX_VPN_WG_UAPI_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vpn/wg/engine.hpp>

namespace sbox {
namespace vpn {

    /**
     * The cross-platform userspace configuration protocol (wireguard.com/xplatform): what `wg`
     * speaks to user-space implementations such as wireguard-go over
     * `/var/run/wireguard/<interface>.sock`. A user-space CWgDevice can serve it, so the official
     * `wg show` / `wg set` work against it, and `sbox-wg show` reads devices the same way.
     *
     * Requests are "get=1\n\n" or "set=1\n" followed by key=value lines and an empty line; every
     * answer ends with "errno=N\n\n". Keys are lowercase hex.
     */

    /** Default directory of the UAPI sockets. */
    constexpr const char* WG_UAPI_DIR = "/var/run/wireguard";

    /**
     * Returns `<dir>/<name>.sock`.
     */
    SBOX_API std::string WgUapiSocketPath(const std::string& name, const std::string& dir = WG_UAPI_DIR);

    /**
     * Formats the body of a "get" answer (without the trailing errno line).
     */
    SBOX_API std::string FormatWgUapiGet(const SWgDeviceStatus& status);

    /**
     * Parses a "get" answer (the errno line is accepted and checked).
     * @return SBOX_OK, the negated errno the answer carried, or -EBADMSG.
     */
    SBOX_API int32_t ParseWgUapiGet(std::string_view text, SWgDeviceStatus& out);

    /**
     * Formats the key=value lines of a "set" request (without "set=1" and the empty line).
     */
    SBOX_API std::string FormatWgUapiSet(const SWgDeviceConfig& config);

    /**
     * Parses the key=value lines of a "set" request.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseWgUapiSet(std::string_view text, SWgDeviceConfig& out);

    /**
     * Reads a device through its UAPI socket.
     */
    SBOX_API TTask<int32_t> WgUapiGet(std::string socketPath, SWgDeviceStatus& out, int64_t timeoutMs = 5000);

    /**
     * Changes a device through its UAPI socket.
     */
    SBOX_API TTask<int32_t> WgUapiSet(std::string socketPath, SWgDeviceConfig config, int64_t timeoutMs = 5000);

}
}

#endif
