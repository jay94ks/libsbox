#ifndef __INCLUDE_SBOX_NET_SYSCTL_HPP__
#define __INCLUDE_SBOX_NET_SYSCTL_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace net {

    /**
     * Reads a sysctl under /proc/sys ("net/ipv4/ip_forward" or "net.ipv4.ip_forward").
     * @param netnsPath Namespace whose value is read (/proc/sys/net is per namespace and follows
     *        the namespace of the opening thread); empty for the current one.
     * @param out Receives the value without the trailing newline.
     */
    SBOX_API int32_t ReadSysctl(std::string_view name, std::string& out, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Writes a sysctl under /proc/sys (see ReadSysctl for naming and namespaces).
     */
    SBOX_API int32_t WriteSysctl(std::string_view name, std::string_view value, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Enables or disables IPv4 forwarding (net.ipv4.ip_forward).
     */
    SBOX_API int32_t SetIpForward(bool on, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Enables or disables IPv6 forwarding on all interfaces (net.ipv6.conf.all.forwarding).
     */
    SBOX_API int32_t SetIpv6Forward(bool on, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Allows routing of 127/8 sources on an interface (net.ipv4.conf.<if>.route_localnet), needed
     * for DNAT of loopback connections to a container.
     */
    SBOX_API int32_t SetRouteLocalnet(std::string_view ifname, bool on, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Makes bridged IPv4/IPv6 traffic traverse the inet hooks (net.bridge.bridge-nf-call-ip(6)tables).
     * Returns -ENOENT when bridge netfilter is not available.
     */
    SBOX_API int32_t SetBridgeNfCall(bool on, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Disables or enables IPv6 on an interface (net.ipv6.conf.<if>.disable_ipv6).
     */
    SBOX_API int32_t SetIpv6Disabled(std::string_view ifname, bool disabled, const std::string& netnsPath = std::string()) noexcept;

    /**
     * Sets router advertisement acceptance on an interface (net.ipv6.conf.<if>.accept_ra: 0, 1, 2).
     */
    SBOX_API int32_t SetAcceptRa(std::string_view ifname, int32_t value, const std::string& netnsPath = std::string()) noexcept;

}
}

#endif
