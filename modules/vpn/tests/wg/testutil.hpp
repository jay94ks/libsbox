#ifndef __TESTS_VPN_WG_TESTUTIL_HPP__
#define __TESTS_VPN_WG_TESTUTIL_HPP__

#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace wgtest {

    /**
     * Temporary directory removed (with the namespace pins in it) on destruction.
     */
    struct STempDir {
        std::string path;
        std::vector<std::string> pins;

        STempDir() {
            char tmpl[] = "/tmp/sbox-wg-test-XXXXXX";
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

        /** Creates a pinned namespace; empty on failure. */
        std::string netns(const std::string& name) {
            std::string p = join(name);
            if (sbox::net::CNetns::create(p) != sbox::SBOX_OK) {
                return std::string();
            }

            pins.push_back(p);
            return p;
        }
    };

    /** Returns true when namespaces and TUN devices can be created. */
    inline bool canUseNetns() {
        if (::geteuid() != 0 || !sbox::CFile::exists("/dev/net/tun")) {
            return false;
        }

        STempDir dir;
        return !dir.netns("probe").empty();
    }

    /** Parses a prefix (test helper). */
    inline sbox::net::SIpPrefix prefix(const char* text) {
        sbox::net::SIpPrefix p;
        sbox::net::SIpPrefix::parse(text, p);
        return p;
    }

    /** Parses an address (test helper). */
    inline sbox::net::SIpAddress address(const char* text) {
        sbox::net::SIpAddress a;
        sbox::net::SIpAddress::parse(text, a);
        return a;
    }

    /**
     * Connects two namespaces with a veth pair (`ifA` in `nsA` with `addrA`, `ifB` in `nsB`)
     * and brings everything (and loopback) up.
     */
    inline sbox::TTask<int32_t> link(std::string nsA, std::string ifA, std::string addrA, std::string nsB, std::string ifB,
        std::string addrB)
    {
        using namespace sbox;
        net::CRtnl a, b;
        int32_t r = a.open(nsA);
        if (r == SBOX_OK) {
            r = b.open(nsB);
        }

        if (r != SBOX_OK) {
            co_return r;
        }

        CFd bfd;
        r = net::CNetns::open(nsB, bfd);
        if (r != SBOX_OK) {
            co_return r;
        }

        r = co_await a.createVeth(ifA, ifB, bfd.get());
        if (r != SBOX_OK) {
            co_return r;
        }

        int32_t ia = co_await a.linkIndex(ifA);
        int32_t ib = co_await b.linkIndex(ifB);
        if (ia < 0 || ib < 0) {
            co_return -ENODEV;
        }

        if (!addrA.empty() && (r = co_await a.addAddress(ia, prefix(addrA.c_str()))) != SBOX_OK) {
            co_return r;
        }

        if (!addrB.empty() && (r = co_await b.addAddress(ib, prefix(addrB.c_str()))) != SBOX_OK) {
            co_return r;
        }

        co_await a.setUp(1, true);
        co_await b.setUp(1, true);
        r = co_await a.setUp(ia, true);
        if (r == SBOX_OK) {
            r = co_await b.setUp(ib, true);
        }

        co_return r;
    }

    /**
     * Blocking TCP connect + send + receive of an echo, for a forked child (CNetns::run).
     * @return 0 when `payload` came back, or a negated errno.
     */
    inline int32_t blockingEcho(const char* addr, uint16_t port, const std::string& payload, int32_t timeoutSec = 10) {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return -errno;
        }

        timeval tv{ timeoutSec, 0 };
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, addr, &sa.sin_addr);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            int32_t err = -errno;
            ::close(fd);
            return err;
        }

        size_t sent = 0;
        while (sent < payload.size()) {
            ssize_t n = ::send(fd, payload.data() + sent, payload.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                ::close(fd);
                return -EIO;
            }

            sent += size_t(n);
        }

        ::shutdown(fd, SHUT_WR);
        std::string back;
        char buf[65536];
        for (;;) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0) {
                int32_t err = -errno;
                ::close(fd);
                return err;
            }

            if (n == 0) {
                break;
            }

            back.append(buf, size_t(n));
        }

        ::close(fd);
        return back == payload ? 0 : -EBADMSG;
    }

    /**
     * Opens a TCP listener on `addr`:0 inside `netnsPath`.
     */
    inline int32_t listenIn(const std::string& netnsPath, const char* addr, sbox::CListener& out) {
        using namespace sbox;
        net::CNetnsScope scope(netnsPath);
        if (scope.error() != SBOX_OK) {
            return scope.error();
        }

        SEndpoint ep;
        int32_t r = SEndpoint::fromIp(addr, 0, ep);
        return r == SBOX_OK ? out.listen(ep) : r;
    }

    /**
     * Accepts one connection, reads until EOF and echoes everything back.
     * @return Number of bytes echoed, or a negated errno.
     */
    inline sbox::TTask<int64_t> echoOnce(sbox::CListener& listener, int64_t timeoutMs = 20000) {
        using namespace sbox;
        CSocket sock;
        int32_t r = co_await listener.accept(sock, timeoutMs);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<uint8_t> data;
        SIoResult got = co_await sock.recvAll(data, size_t(16) << 20, timeoutMs);
        if (!got.ok()) {
            co_return got.error;
        }

        SIoResult w = co_await sock.send(SReadOnlyByteSpan(data.data(), data.size()), timeoutMs);
        if (!w.ok()) {
            co_return w.error;
        }

        sock.shutdownWrite();
        co_return int64_t(data.size());
    }

    /**
     * Runs `fn` in a child inside `netnsPath` while `server` runs here; returns the child's result
     * and stores the server's in `serverResult`.
     */
    inline sbox::TTask<int32_t> withChild(std::string netnsPath, std::function<int32_t()> fn, sbox::TTask<int64_t> server,
        int64_t& serverResult)
    {
        using namespace sbox;
        struct SState {
            bool done = false;
            int32_t child = -1;
        };

        auto state = std::make_shared<SState>();
        CEventLoop::current()->spawn([](std::string path, std::function<int32_t()> f, std::shared_ptr<SState> st) -> TTask<void> {
            st->child = co_await net::CNetns::run(path, std::move(f));
            st->done = true;
        }(netnsPath, std::move(fn), state));

        serverResult = co_await server;
        while (!state->done) {
            co_await CEventLoop::current()->sleepFor(10);
        }

        co_return state->child;
    }

}

#endif
