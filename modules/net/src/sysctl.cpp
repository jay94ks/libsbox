#include <sbox/net/sysctl.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/core/fd.hpp>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace sbox {
namespace net {

    namespace {

        /* Maps a dotted or slashed sysctl name to its /proc/sys path; empty when unsafe. */
        std::string sysctlPath(std::string_view name) {
            if (name.empty() || name.find("..") != std::string_view::npos) {
                return std::string();
            }

            std::string path = "/proc/sys/";
            bool slashed = name.find('/') != std::string_view::npos;

            for (char c : name) {
                // --> In the dotted form, interface names never contain '.', except VLAN names
                // like eth0.100; those callers use the slashed form.
                path.push_back(!slashed && c == '.' ? '/' : c);
            }

            return path;
        }

        /* Opens a sysctl file in a namespace. */
        int openIn(const std::string& path, int flags, const std::string& netnsPath, int32_t& error) noexcept {
            CNetnsScope scope(netnsPath);
            if (scope.error() != SBOX_OK) {
                error = scope.error();
                return -1;
            }

            int fd = ::open(path.c_str(), flags | O_CLOEXEC);
            error = fd < 0 ? -errno : SBOX_OK;
            return fd;
        }

        /* Builds "net/ipv4/conf/<if>/<key>" style names for interface sysctls. */
        std::string ifSysctl(std::string_view family, std::string_view ifname, std::string_view key) {
            std::string out = "net/";
            out.append(family);
            out.append("/conf/");
            out.append(ifname);
            out.push_back('/');
            out.append(key);
            return out;
        }

    }

    /* Reads a sysctl. */
    int32_t ReadSysctl(std::string_view name, std::string& out, const std::string& netnsPath) noexcept {
        std::string path = sysctlPath(name);
        if (path.empty()) {
            return -EINVAL;
        }

        int32_t error = SBOX_OK;
        CFd fd(openIn(path, O_RDONLY, netnsPath, error));
        if (!fd.isValid()) {
            return error;
        }

        char buffer[4096];
        ssize_t n;
        do {
            n = ::read(fd.get(), buffer, sizeof(buffer));
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            return -errno;
        }

        out.assign(buffer, size_t(n));
        while (!out.empty() && (out.back() == '\n' || out.back() == ' ')) {
            out.pop_back();
        }

        return SBOX_OK;
    }

    /* Writes a sysctl. */
    int32_t WriteSysctl(std::string_view name, std::string_view value, const std::string& netnsPath) noexcept {
        std::string path = sysctlPath(name);
        if (path.empty()) {
            return -EINVAL;
        }

        int32_t error = SBOX_OK;
        CFd fd(openIn(path, O_WRONLY, netnsPath, error));
        if (!fd.isValid()) {
            return error;
        }

        ssize_t n;
        do {
            n = ::write(fd.get(), value.data(), value.size());
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            return -errno;
        }

        return size_t(n) == value.size() ? SBOX_OK : -EIO;
    }

    /* Sets IPv4 forwarding. */
    int32_t SetIpForward(bool on, const std::string& netnsPath) noexcept {
        return WriteSysctl("net/ipv4/ip_forward", on ? "1" : "0", netnsPath);
    }

    /* Sets IPv6 forwarding. */
    int32_t SetIpv6Forward(bool on, const std::string& netnsPath) noexcept {
        return WriteSysctl("net/ipv6/conf/all/forwarding", on ? "1" : "0", netnsPath);
    }

    /* Sets route_localnet on an interface. */
    int32_t SetRouteLocalnet(std::string_view ifname, bool on, const std::string& netnsPath) noexcept {
        return WriteSysctl(ifSysctl("ipv4", ifname, "route_localnet"), on ? "1" : "0", netnsPath);
    }

    /* Sets bridge-nf-call-ip(6)tables. */
    int32_t SetBridgeNfCall(bool on, const std::string& netnsPath) noexcept {
        int32_t r = WriteSysctl("net/bridge/bridge-nf-call-iptables", on ? "1" : "0", netnsPath);
        if (r != SBOX_OK) {
            return r;
        }

        return WriteSysctl("net/bridge/bridge-nf-call-ip6tables", on ? "1" : "0", netnsPath);
    }

    /* Disables or enables IPv6 on an interface. */
    int32_t SetIpv6Disabled(std::string_view ifname, bool disabled, const std::string& netnsPath) noexcept {
        return WriteSysctl(ifSysctl("ipv6", ifname, "disable_ipv6"), disabled ? "1" : "0", netnsPath);
    }

    /* Sets accept_ra on an interface. */
    int32_t SetAcceptRa(std::string_view ifname, int32_t value, const std::string& netnsPath) noexcept {
        return WriteSysctl(ifSysctl("ipv6", ifname, "accept_ra"), std::to_string(value), netnsPath);
    }

}
}
