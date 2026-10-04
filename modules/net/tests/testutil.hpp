#ifndef __TESTS_NET_TESTUTIL_HPP__
#define __TESTS_NET_TESTUTIL_HPP__

#include <sbox/core/file.hpp>
#include <sbox/net/netns.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include <unistd.h>

namespace nettest {

    /**
     * Temporary directory removed (with any namespace pins in it) on destruction.
     */
    struct STempDir {
        std::string path;
        std::vector<std::string> pins;

        STempDir() {
            char tmpl[] = "/tmp/sbox-net-test-XXXXXX";
            char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
        }

        ~STempDir() {
            for (const std::string& pin : pins) {
                sbox::net::CNetns::remove(pin);
            }

            if (!path.empty()) {
                sbox::CFile::removeTree(path);
            }
        }

        std::string join(const std::string& leaf) const {
            return sbox::CFile::join(path, leaf);
        }

        /**
         * Creates a pinned namespace inside the directory; empty string on failure.
         */
        std::string netns(const std::string& name) {
            std::string p = join(name);
            if (sbox::net::CNetns::create(p) != sbox::SBOX_OK) {
                return std::string();
            }

            pins.push_back(p);
            return p;
        }
    };

    /**
     * Blocking TCP connect + send, for use inside a forked child (CNetns::run).
     * @return 0 on success or a negated errno.
     */
    inline int32_t blockingConnect(const char* address, uint16_t port, const char* payload, int32_t timeoutSec = 3) {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return -errno;
        }

        timeval tv{ timeoutSec, 0 };
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, address, &sa.sin_addr);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            int32_t err = -errno;
            ::close(fd);
            return err;
        }

        ssize_t n = ::send(fd, payload, std::strlen(payload), MSG_NOSIGNAL);
        ::close(fd);
        return n == ssize_t(std::strlen(payload)) ? 0 : -EIO;
    }

    /**
     * Returns true when the kernel has IPv6 (not booted with ipv6.disable=1).
     */
    inline bool haveIpv6() {
        return sbox::CFile::exists("/proc/net/if_inet6");
    }

    /**
     * Returns true when the tests may create network namespaces.
     */
    inline bool canCreateNetns() {
        if (::geteuid() != 0) {
            return false;
        }

        STempDir dir;
        return !dir.netns("probe").empty();
    }

}

#endif
