#ifndef __TESTS_NET_TESTUTIL_HPP__
#define __TESTS_NET_TESTUTIL_HPP__

#include <sbox/core/file.hpp>
#include <sbox/net/netns.hpp>
#include <cstdlib>
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
