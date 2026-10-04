#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/netns.hpp>
#include <cerrno>
#include <cstring>
#include <map>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <linux/xfrm.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

namespace sbox {
namespace vpn {

    namespace {

        struct Sock {
            CFd fd;
            int family = AF_INET;
            bool natT = false;
            uint16_t port = 0;
        };

        /* Opens and binds one UDP socket. */
        int32_t openSocket(int family, const std::string& address, uint16_t port, Sock& out) {
            CFd fd(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (!fd.isValid()) {
                return -errno;
            }

            int one = 1;
            if (family == AF_INET6) {
                ::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
                ::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
            }
            else {
                ::setsockopt(fd.get(), IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
            }

            // --> IKE messages carrying certificates get large; a bigger buffer keeps bursts
            // of fragments from being dropped.
            int size = 1 << 20;
            ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

            SEndpoint local;
            std::string addr = address;
            if (addr.empty()) {
                addr = family == AF_INET6 ? "::" : "0.0.0.0";
            }

            int32_t r = SEndpoint::fromIp(addr, port, local);
            if (r != SBOX_OK) {
                return r;
            }

            if (local.family() != family) {
                return -EAFNOSUPPORT;
            }

            if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&local.storage), local.length) < 0) {
                return -errno;
            }

            sockaddr_storage bound;
            socklen_t len = sizeof(bound);
            if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
                return -errno;
            }

            out.fd = std::move(fd);
            out.family = family;
            out.port = family == AF_INET6 ? ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port)
                                          : ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
            return SBOX_OK;
        }

        /* Sends one datagram with an optional source address. */
        int32_t sendFrom(const Sock& s, const iovec* iov, size_t iovCount, const SEndpoint& local, const SEndpoint& remote) {
            msghdr msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.msg_name = const_cast<sockaddr_storage*>(&remote.storage);
            msg.msg_namelen = remote.length;
            msg.msg_iov = const_cast<iovec*>(iov);
            msg.msg_iovlen = iovCount;

            alignas(cmsghdr) uint8_t control[64];
            std::memset(control, 0, sizeof(control));

            if (local.isValid() && local.family() == s.family) {
                if (s.family == AF_INET) {
                    const auto* sin = reinterpret_cast<const sockaddr_in*>(&local.storage);
                    if (sin->sin_addr.s_addr != 0) {
                        msg.msg_control = control;
                        msg.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
                        cmsghdr* c = CMSG_FIRSTHDR(&msg);
                        c->cmsg_level = IPPROTO_IP;
                        c->cmsg_type = IP_PKTINFO;
                        c->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
                        in_pktinfo info;
                        std::memset(&info, 0, sizeof(info));
                        info.ipi_spec_dst = sin->sin_addr;
                        std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                    }
                }
                else {
                    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&local.storage);
                    if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                        msg.msg_control = control;
                        msg.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
                        cmsghdr* c = CMSG_FIRSTHDR(&msg);
                        c->cmsg_level = IPPROTO_IPV6;
                        c->cmsg_type = IPV6_PKTINFO;
                        c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
                        in6_pktinfo info;
                        std::memset(&info, 0, sizeof(info));
                        info.ipi6_addr = sin6->sin6_addr;
                        std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                    }
                }
            }

            ssize_t n = ::sendmsg(s.fd.get(), &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0) {
                return -errno;
            }

            return SBOX_OK;
        }

    }

    struct CIkeSocket::SState {
        std::vector<Sock> socks;
        FIkeDatagramHandler handler;
        FEspPacketHandler esp;
        std::map<uint32_t, FEspPacketHandler> espBySpi;
        CEventLoop* loop = nullptr;
        bool closed = false;
        uint16_t port = 0;
        uint16_t natPort = 0;

        /* Finds the socket of a family and port kind. */
        const Sock* find(int family, bool natT) const {
            for (const Sock& s : socks) {
                if (s.family == family && s.natT == natT && s.fd.isValid()) {
                    return &s;
                }
            }

            return nullptr;
        }
    };

    CIkeSocket::CIkeSocket() = default;

    CIkeSocket::~CIkeSocket() {
        close();
    }

    /* Opens the sockets. */
    int32_t CIkeSocket::open(const SIkeSocketOptions& options) {
        close();

        auto state = std::make_shared<SState>();
        net::CNetnsScope scope(options.netnsPath);
        if (scope.error() != SBOX_OK) {
            return scope.error();
        }

        std::vector<int> families;
        if (options.ipv4) {
            families.push_back(AF_INET);
        }

        if (options.ipv6) {
            families.push_back(AF_INET6);
        }

        if (families.empty()) {
            return -EINVAL;
        }

        uint16_t port = options.port;
        uint16_t natPort = options.natPort;

        for (int family : families) {
            std::string address;
            if (!options.address.empty()) {
                // --> A bind address only applies to its own family.
                SEndpoint probe;
                if (SEndpoint::fromIp(options.address, 0, probe) == SBOX_OK && probe.family() != family) {
                    continue;
                }

                address = options.address;
            }

            Sock ike;
            int32_t r = openSocket(family, address, port, ike);
            if (r != SBOX_OK) {
                return r;
            }

            Sock nat;
            nat.natT = true;
            r = openSocket(family, address, natPort, nat);
            if (r != SBOX_OK) {
                return r;
            }

            // --> With ephemeral ports both families share the first family's choice.
            port = ike.port;
            natPort = nat.port;
            state->socks.push_back(std::move(ike));
            state->socks.push_back(std::move(nat));
        }

        if (state->socks.empty()) {
            return -EAFNOSUPPORT;
        }

        state->port = port;
        state->natPort = natPort;
        _state = std::move(state);
        return SBOX_OK;
    }

    /* Starts the readers. */
    void CIkeSocket::start(FIkeDatagramHandler handler) {
        if (!_state) {
            return;
        }

        _state->handler = std::move(handler);
        _state->loop = CEventLoop::current();
        if (!_state->loop) {
            return;
        }

        struct Reader {
            /* Receive loop of one socket. */
            static TTask<void> run(std::shared_ptr<SState> st, size_t index) {
                std::vector<uint8_t> buffer(65536);
                alignas(cmsghdr) uint8_t control[256];

                while (!st->closed) {
                    int fd = st->socks[index].fd.get();
                    if (fd < 0) {
                        break;
                    }

                    sockaddr_storage from;
                    iovec iov;
                    iov.iov_base = buffer.data();
                    iov.iov_len = buffer.size();

                    msghdr msg;
                    std::memset(&msg, 0, sizeof(msg));
                    msg.msg_name = &from;
                    msg.msg_namelen = sizeof(from);
                    msg.msg_iov = &iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = control;
                    msg.msg_controllen = sizeof(control);

                    ssize_t n = ::recvmsg(fd, &msg, MSG_DONTWAIT);
                    if (n < 0) {
                        int err = errno;
                        if (err == EAGAIN || err == EWOULDBLOCK) {
                            int32_t r = co_await st->loop->waitFd(fd, EFDE_READ);
                            if (r < 0 && (st->closed || r == -ECANCELED)) {
                                break;
                            }

                            continue;
                        }

                        // --> ICMP errors (ECONNREFUSED) surface here; they are not fatal.
                        if (err == EBADF) {
                            break;
                        }

                        continue;
                    }

                    const Sock& s = st->socks[index];
                    SEndpoint remote;
                    std::memcpy(&remote.storage, &from, msg.msg_namelen);
                    remote.length = msg.msg_namelen;

                    SEndpoint local;
                    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
                        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                            in_pktinfo info;
                            std::memcpy(&info, CMSG_DATA(c), sizeof(info));
                            sockaddr_in sin;
                            std::memset(&sin, 0, sizeof(sin));
                            sin.sin_family = AF_INET;
                            sin.sin_addr = info.ipi_addr;
                            sin.sin_port = htons(s.port);
                            std::memcpy(&local.storage, &sin, sizeof(sin));
                            local.length = sizeof(sin);
                        }
                        else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                            in6_pktinfo info;
                            std::memcpy(&info, CMSG_DATA(c), sizeof(info));
                            sockaddr_in6 sin6;
                            std::memset(&sin6, 0, sizeof(sin6));
                            sin6.sin6_family = AF_INET6;
                            sin6.sin6_addr = info.ipi6_addr;
                            sin6.sin6_port = htons(s.port);
                            std::memcpy(&local.storage, &sin6, sizeof(sin6));
                            local.length = sizeof(sin6);
                        }
                    }

                    size_t length = size_t(n);
                    const uint8_t* data = buffer.data();

                    if (s.natT) {
                        if (length == 1 && data[0] == 0xff) {
                            continue;   // --> NAT keepalive.
                        }

                        if (length < 4) {
                            continue;
                        }

                        if (data[0] || data[1] || data[2] || data[3]) {
                            if (length >= 8 && !st->espBySpi.empty()) {
                                uint32_t spi = (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
                                auto it = st->espBySpi.find(spi);
                                if (it != st->espBySpi.end() && it->second) {
                                    // --> Copy: the handler may remove itself.
                                    FEspPacketHandler h = it->second;
                                    h(SReadOnlyByteSpan(data, length), remote, local);
                                    continue;
                                }
                            }

                            if (st->esp && length >= 8) {
                                st->esp(SReadOnlyByteSpan(data, length), remote, local);
                            }

                            continue;
                        }

                        data += 4;
                        length -= 4;
                    }

                    if (!st->handler) {
                        continue;
                    }

                    SIkeDatagram dg;
                    dg.data.assign(data, data + length);
                    dg.remote = remote;
                    dg.local = local;
                    dg.natT = s.natT;
                    st->handler(dg);
                }
            }
        };

        for (size_t i = 0; i < _state->socks.size(); ++i) {
            _state->loop->spawn(Reader::run(_state, i));
        }
    }

    /* Installs the ESP handler. */
    void CIkeSocket::espHandler(FEspPacketHandler handler) {
        if (_state) {
            _state->esp = std::move(handler);
        }
    }

    /* Installs a per-SPI ESP handler. */
    void CIkeSocket::espSpiHandler(uint32_t spi, FEspPacketHandler handler) {
        if (!_state) {
            return;
        }

        if (handler) {
            _state->espBySpi[spi] = std::move(handler);
        }
        else {
            _state->espBySpi.erase(spi);
        }
    }

    /* Enables kernel ESP-in-UDP decapsulation. */
    int32_t CIkeSocket::enableKernelEncap() {
        if (!_state) {
            return -EBADF;
        }

        for (const Sock& s : _state->socks) {
            // --> IKE itself must never be caught by the IPsec policies it negotiates (a
            // site-to-site selector can cover the peer's own address): per-socket bypass
            // policies, as every IKE daemon installs them.
            for (uint8_t dir : { uint8_t(XFRM_POLICY_IN), uint8_t(XFRM_POLICY_OUT) }) {
                xfrm_userpolicy_info policy;
                std::memset(&policy, 0, sizeof(policy));
                policy.action = XFRM_POLICY_ALLOW;
                policy.sel.family = uint16_t(s.family);
                policy.dir = dir;
                bool v6 = s.family == AF_INET6;
                if (::setsockopt(s.fd.get(), v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_XFRM_POLICY : IP_XFRM_POLICY, &policy,
                                 sizeof(policy)) < 0) {
                    return -errno;
                }
            }

            if (!s.natT) {
                continue;
            }

            int type = UDP_ENCAP_ESPINUDP;
            if (::setsockopt(s.fd.get(), IPPROTO_UDP, UDP_ENCAP, &type, sizeof(type)) < 0) {
                return -errno;
            }
        }

        return SBOX_OK;
    }

    /* Sends an IKE message. */
    int32_t CIkeSocket::send(const SReadOnlyByteSpan& message, const SEndpoint& local, const SEndpoint& remote, bool natT) {
        if (!_state || _state->closed) {
            return -EBADF;
        }

        const Sock* s = _state->find(remote.family(), natT);
        if (!s) {
            return -EAFNOSUPPORT;
        }

        static const uint8_t MARKER[4] = { 0, 0, 0, 0 };
        iovec iov[2];
        size_t count = 0;
        if (natT) {
            iov[count].iov_base = const_cast<uint8_t*>(MARKER);
            iov[count].iov_len = 4;
            ++count;
        }

        iov[count].iov_base = const_cast<uint8_t*>(message.data);
        iov[count].iov_len = message.size;
        ++count;
        return sendFrom(*s, iov, count, local, remote);
    }

    /* Sends ESP-in-UDP. */
    int32_t CIkeSocket::sendEsp(const SReadOnlyByteSpan& esp, const SEndpoint& local, const SEndpoint& remote) {
        if (!_state || _state->closed) {
            return -EBADF;
        }

        const Sock* s = _state->find(remote.family(), true);
        if (!s) {
            return -EAFNOSUPPORT;
        }

        iovec iov;
        iov.iov_base = const_cast<uint8_t*>(esp.data);
        iov.iov_len = esp.size;
        return sendFrom(*s, &iov, 1, local, remote);
    }

    /* Sends a NAT keepalive. */
    int32_t CIkeSocket::sendKeepalive(const SEndpoint& local, const SEndpoint& remote) {
        if (!_state || _state->closed) {
            return -EBADF;
        }

        const Sock* s = _state->find(remote.family(), true);
        if (!s) {
            return -EAFNOSUPPORT;
        }

        uint8_t byte = 0xff;
        iovec iov;
        iov.iov_base = &byte;
        iov.iov_len = 1;
        return sendFrom(*s, &iov, 1, local, remote);
    }

    /* IKE port. */
    uint16_t CIkeSocket::port() const noexcept {
        return _state ? _state->port : 0;
    }

    /* NAT-T port. */
    uint16_t CIkeSocket::natPort() const noexcept {
        return _state ? _state->natPort : 0;
    }

    /* Open state. */
    bool CIkeSocket::isValid() const noexcept {
        return _state && !_state->closed;
    }

    /* Closes everything. */
    void CIkeSocket::close() noexcept {
        if (!_state) {
            return;
        }

        // --> The handlers stay: close() may run from inside one of them, and the readers
        // release the whole state once they notice `closed`.
        _state->closed = true;
        CEventLoop* loop = _state->loop ? _state->loop : CEventLoop::current();
        for (Sock& s : _state->socks) {
            if (s.fd.isValid() && loop) {
                loop->cancelFd(s.fd.get());
            }
        }

        // --> Readers hold the state; the descriptors close now, the state when they exit.
        for (Sock& s : _state->socks) {
            s.fd.reset();
        }

        _state.reset();
    }

}
}
