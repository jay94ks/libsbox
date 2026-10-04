#ifndef __TESTS_VPN_L2TP_TESTUTIL_HPP__
#define __TESTS_VPN_L2TP_TESTUTIL_HPP__

#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/netns.hpp>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <unistd.h>
#include <vector>

namespace l2tptest {

    using namespace sbox;

    /** Lower-case hex of bytes. */
    inline std::string Hex(const std::vector<uint8_t>& v) {
        static const char* digits = "0123456789abcdef";
        std::string out;
        for (uint8_t b : v) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 15]);
        }

        return out;
    }

    /** Parses hex. */
    inline std::vector<uint8_t> Unhex(const std::string& text) {
        std::vector<uint8_t> out;
        for (size_t i = 0; i + 1 < text.size(); i += 2) {
            out.push_back(uint8_t(std::stoul(text.substr(i, 2), nullptr, 16)));
        }

        return out;
    }

    /** Span of a vector. */
    inline SReadOnlyByteSpan Bytes(const std::vector<uint8_t>& v) {
        return SReadOnlyByteSpan(v.data(), v.size());
    }

    /** Returns true when running as root. */
    inline bool IsRoot() {
        return ::geteuid() == 0;
    }

    /**
     * Temporary directory (with namespace pins) removed on destruction.
     */
    struct TempDir {
        std::string path;
        std::vector<std::string> pins;

        TempDir() {
            char tmpl[] = "/tmp/sbox-l2tp-test-XXXXXX";
            char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
        }

        ~TempDir() {
            for (const std::string& pin : pins) {
                net::CNetns::remove(pin);
            }

            if (!path.empty()) {
                CFile::removeTree(path);
            }
        }

        std::string join(const std::string& leaf) const {
            return CFile::join(path, leaf);
        }

        /** Creates a pinned namespace; empty string on failure. */
        std::string netns(const std::string& name) {
            std::string p = join(name);
            if (net::CNetns::create(p) != SBOX_OK) {
                return std::string();
            }

            pins.push_back(p);
            return p;
        }
    };

    /**
     * Collects log lines.
     */
    struct Log {
        std::vector<std::string> lines;
        bool echo = std::getenv("L2TP_TEST_LOG") != nullptr;

        template<typename L>
        void add(L, const std::string& m) {
            if (echo) {
                std::fprintf(stderr, "%s\n", m.c_str());
            }

            lines.push_back(m);
        }

        bool contains(const std::string& text) const {
            for (const std::string& l : lines) {
                if (l.find(text) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }
    };

    /** Runs the loop until `done` or the deadline. */
    inline TTask<bool> WaitFor(const std::function<bool()>& done, int64_t timeoutMs) {
        int64_t end = CEventLoop::nowMs() + timeoutMs;
        while (!done()) {
            if (CEventLoop::nowMs() > end) {
                co_return false;
            }

            co_await CEventLoop::current()->sleepFor(10);
        }

        co_return true;
    }

}

#endif
