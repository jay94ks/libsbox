#include <sbox/vpn/ipsec/datapath.hpp>
#include <sbox/vpn/ipsec/esp.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include "datapaths.hpp"
#include "crypto.hpp"
#include <cerrno>
#include <cstring>
#include <map>
#include <set>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace vpn {
namespace ipsec {

    namespace {

        /**
         * Shared state of the user-space data path (kept alive by its loops).
         */
        struct UserState {
            struct Policy {
                std::vector<SIkeTrafficSelector> localTs;
                std::vector<SIkeTrafficSelector> remoteTs;
                std::shared_ptr<CEspSa> out;
                SEndpoint local;
                SEndpoint remote;
                bool encap = false;
                EXfrmMode mode = EXMODE_TUNNEL;
            };

            struct Inbound {
                std::shared_ptr<CEspSa> sa;
                uint32_t reqid = 0;
            };

            SIpsecDataPathOptions options;
            CIkeSocket* socket = nullptr;
            CEventLoop* loop = nullptr;
            CFd tun;
            CFd raw4;
            CFd raw6;
            std::string ifName;
            bool closed = false;
            std::map<uint32_t, Policy> policies;     // --> By reqid.
            std::map<uint32_t, Inbound> inbound;     // --> By SPI.
            std::set<uint32_t> reserved;             // --> Allocated, not yet installed SPIs.

            /* Builds an endpoint from an address and port. */
            static SEndpoint endpoint(const net::SIpAddress& a, uint16_t port) {
                SEndpoint ep;
                SEndpoint::fromIp(a.toString(), port, ep);
                return ep;
            }

            /* Handles one decrypted-side packet read from the TUN device. */
            void outbound(const SReadOnlyByteSpan& packet) {
                if (packet.size < 20) {
                    return;
                }

                uint8_t version = packet[0] >> 4;
                for (auto& [reqid, p] : policies) {
                    (void)reqid;
                    if (!p.out || !PacketMatches(packet, p.localTs, p.remoteTs)) {
                        continue;
                    }

                    std::vector<uint8_t> esp;
                    uint8_t next = version == 6 ? ESP_NEXT_IPV6 : ESP_NEXT_IPV4;
                    if (p.out->encapsulate(packet, next, esp) != SBOX_OK) {
                        return;
                    }

                    send(p, BytesOf(esp));
                    return;
                }
            }

            /* Sends one ESP packet towards the peer. */
            void send(const Policy& p, const SReadOnlyByteSpan& esp) {
                if (p.encap) {
                    if (socket) {
                        socket->sendEsp(esp, p.local, p.remote);
                    }

                    return;
                }

                const CFd& raw = p.remote.family() == AF_INET6 ? raw6 : raw4;
                if (!raw.isValid()) {
                    return;
                }

                msghdr msg;
                std::memset(&msg, 0, sizeof(msg));
                SEndpoint to = p.remote;
                // --> Raw sockets use the port field as the protocol on some paths; keep it 0.
                if (to.family() == AF_INET) {
                    reinterpret_cast<sockaddr_in*>(&to.storage)->sin_port = 0;
                }
                else {
                    reinterpret_cast<sockaddr_in6*>(&to.storage)->sin6_port = 0;
                }

                msg.msg_name = &to.storage;
                msg.msg_namelen = to.length;
                iovec iov;
                iov.iov_base = const_cast<uint8_t*>(esp.data);
                iov.iov_len = esp.size;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                alignas(cmsghdr) uint8_t control[64];
                std::memset(control, 0, sizeof(control));
                if (p.local.family() == AF_INET) {
                    msg.msg_control = control;
                    msg.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
                    cmsghdr* c = CMSG_FIRSTHDR(&msg);
                    c->cmsg_level = IPPROTO_IP;
                    c->cmsg_type = IP_PKTINFO;
                    c->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
                    in_pktinfo info;
                    std::memset(&info, 0, sizeof(info));
                    info.ipi_spec_dst = reinterpret_cast<const sockaddr_in*>(&p.local.storage)->sin_addr;
                    std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                }
                else if (p.local.family() == AF_INET6) {
                    msg.msg_control = control;
                    msg.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
                    cmsghdr* c = CMSG_FIRSTHDR(&msg);
                    c->cmsg_level = IPPROTO_IPV6;
                    c->cmsg_type = IPV6_PKTINFO;
                    c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
                    in6_pktinfo info;
                    std::memset(&info, 0, sizeof(info));
                    info.ipi6_addr = reinterpret_cast<const sockaddr_in6*>(&p.local.storage)->sin6_addr;
                    std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                }

                ::sendmsg(raw.get(), &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
            }

            /* Handles one ESP packet from the network. */
            void inboundPacket(const SReadOnlyByteSpan& esp, const SEndpoint& remote) {
                uint32_t spi = CEspSa::packetSpi(esp);
                auto it = inbound.find(spi);
                if (it == inbound.end()) {
                    return;
                }

                std::vector<uint8_t> payload;
                uint8_t next = 0;
                if (it->second.sa->decapsulate(esp, payload, next) != SBOX_OK) {
                    return;
                }

                auto pit = policies.find(it->second.reqid);
                if (pit == policies.end()) {
                    return;
                }

                Policy& p = pit->second;

                // --> NAT mapping changes: follow the peer's new source (RFC 3948 / 7296 2.23).
                if (p.encap && remote.isValid() && remote.toString() != p.remote.toString()) {
                    p.remote = remote;
                }

                if (next == 59) {
                    return;     // --> Dummy (TFC) packet.
                }

                if (p.mode != EXMODE_TUNNEL || (next != ESP_NEXT_IPV4 && next != ESP_NEXT_IPV6)) {
                    return;
                }

                if (!PacketMatches(BytesOf(payload), p.remoteTs, p.localTs)) {
                    return;
                }

                if (tun.isValid()) {
                    ssize_t n = ::write(tun.get(), payload.data(), payload.size());
                    (void)n;
                }
            }
        };

        /* Reads the TUN device. */
        TTask<void> tunReader(std::shared_ptr<UserState> st) {
            std::vector<uint8_t> buffer(65536);
            while (!st->closed && st->tun.isValid()) {
                int fd = st->tun.get();
                ssize_t n = ::read(fd, buffer.data(), buffer.size());
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        int32_t r = co_await st->loop->waitFd(fd, EFDE_READ);
                        if (r < 0 && (st->closed || r == -ECANCELED)) {
                            break;
                        }

                        continue;
                    }

                    if (errno == EINTR) {
                        continue;
                    }

                    break;
                }

                st->outbound(SReadOnlyByteSpan(buffer.data(), size_t(n)));
            }
        }

        /* Reads a raw ESP socket. */
        TTask<void> rawReader(std::shared_ptr<UserState> st, bool v6) {
            std::vector<uint8_t> buffer(65536);
            while (!st->closed) {
                const CFd& raw = v6 ? st->raw6 : st->raw4;
                if (!raw.isValid()) {
                    break;
                }

                int fd = raw.get();
                sockaddr_storage from;
                socklen_t fromLen = sizeof(from);
                ssize_t n = ::recvfrom(fd, buffer.data(), buffer.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&from), &fromLen);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        int32_t r = co_await st->loop->waitFd(fd, EFDE_READ);
                        if (r < 0 && (st->closed || r == -ECANCELED)) {
                            break;
                        }

                        continue;
                    }

                    if (errno == EINTR) {
                        continue;
                    }

                    break;
                }

                SReadOnlyByteSpan packet(buffer.data(), size_t(n));
                if (!v6) {
                    // --> IPv4 raw sockets deliver the IP header too.
                    if (packet.size < 20) {
                        continue;
                    }

                    size_t ihl = size_t(packet[0] & 0x0f) * 4;
                    if (ihl < 20 || packet.size < ihl) {
                        continue;
                    }

                    packet = packet.slice(ihl);
                }

                SEndpoint remote;
                std::memcpy(&remote.storage, &from, fromLen);
                remote.length = fromLen;
                st->inboundPacket(packet, remote);
            }
        }

        /**
         * User-space ESP data path.
         */
        class UserDataPath : public IIpsecDataPath {
        private:
            std::shared_ptr<UserState> _state;

        public:
            explicit UserDataPath(const SIpsecDataPathOptions& options) : _state(std::make_shared<UserState>()) {
                _state->options = options;
            }

            ~UserDataPath() override {
                close();
            }

            const char* kind() const noexcept override {
                return "user";
            }

            void attachSocket(CIkeSocket* socket) override {
                _state->socket = socket;
            }

            bool supports(uint16_t encr, uint16_t keyBits, uint16_t integ) const noexcept override {
                const SIkeEncrInfo* info = IkeEncrInfo(encr);
                if (!info || !IkeEncrKeyBitsValid(encr, keyBits)) {
                    return false;
                }

                return info->aead ? integ == EIKE_INTEG_NONE : IkeIntegKeySize(integ) != 0;
            }

            std::string interfaceName() const override {
                return _state->ifName;
            }

            TTask<int32_t> start() override {
                UserState& st = *_state;
                st.loop = CEventLoop::current();
                st.closed = false;

                net::STunTapOptions tunOptions;
                tunOptions.netnsPath = st.options.netnsPath;
                std::string actual;
                int32_t r = net::CreateTunTap(st.options.interfaceName, tunOptions, st.tun, &actual);
                if (r != SBOX_OK) {
                    co_return r;
                }

                st.ifName = actual;
                r = co_await ConfigureInterface(st.options, actual);
                if (r != SBOX_OK) {
                    close();
                    co_return r;
                }

                {
                    net::CNetnsScope scope(st.options.netnsPath);
                    if (scope.error() != SBOX_OK) {
                        close();
                        co_return scope.error();
                    }

                    st.raw4.reset(::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ESP));
                    st.raw6.reset(::socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ESP));
                }

                if (st.socket) {
                    std::weak_ptr<UserState> weak = _state;
                    st.socket->espHandler([weak](const SReadOnlyByteSpan& esp, const SEndpoint& remote, const SEndpoint&) {
                        if (auto s = weak.lock()) {
                            if (!s->closed) {
                                s->inboundPacket(esp, remote);
                            }
                        }
                    });
                }

                st.loop->spawn(tunReader(_state));
                if (st.raw4.isValid()) {
                    st.loop->spawn(rawReader(_state, false));
                }

                if (st.raw6.isValid()) {
                    st.loop->spawn(rawReader(_state, true));
                }

                co_return SBOX_OK;
            }

            void close() {
                UserState& st = *_state;
                st.closed = true;
                CEventLoop* loop = st.loop ? st.loop : CEventLoop::current();
                for (CFd* fd : { &st.tun, &st.raw4, &st.raw6 }) {
                    if (fd->isValid()) {
                        if (loop) {
                            loop->cancelFd(fd->get());
                        }

                        fd->reset();
                    }
                }

                st.policies.clear();
                st.inbound.clear();
                st.reserved.clear();
            }

            TTask<void> stop() override {
                if (_state->socket) {
                    _state->socket->espHandler(nullptr);
                }

                close();
                co_return;
            }

            TTask<int32_t> allocateSpi(net::SIpAddress, net::SIpAddress, uint32_t, uint32_t& spi) override {
                for (int32_t attempt = 0; attempt < 64; ++attempt) {
                    uint32_t candidate = 0;
                    IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&candidate), sizeof(candidate)));
                    if (candidate < 0x100 || _state->inbound.count(candidate) || _state->reserved.count(candidate)) {
                        continue;
                    }

                    _state->reserved.insert(candidate);
                    spi = candidate;
                    co_return SBOX_OK;
                }

                co_return -EAGAIN;
            }

            TTask<int32_t> installChild(SIpsecChildSa child) override {
                if (child.mode != EXMODE_TUNNEL) {
                    co_return -ENOTSUP;
                }

                SEspKeys in;
                in.encr = child.encr;
                in.keyBits = child.keyBits;
                in.integ = child.integ;
                in.encKey = child.inEncKey;
                in.integKey = child.inIntegKey;

                SEspKeys out = in;
                out.encKey = child.outEncKey;
                out.integKey = child.outIntegKey;

                auto inSa = std::make_shared<CEspSa>();
                auto outSa = std::make_shared<CEspSa>();
                int32_t r = inSa->init(child.inboundSpi, true, in, child.replayWindow > 128 ? 128 : child.replayWindow);
                if (r == SBOX_OK) {
                    r = outSa->init(child.outboundSpi, false, out, 0);
                }

                IkeWipe(in.encKey);
                IkeWipe(in.integKey);
                IkeWipe(out.encKey);
                IkeWipe(out.integKey);
                if (r != SBOX_OK) {
                    co_return r;
                }

                _state->reserved.erase(child.inboundSpi);
                _state->inbound[child.inboundSpi] = UserState::Inbound{ inSa, child.reqid };

                UserState::Policy& p = _state->policies[child.reqid];
                p.localTs = child.localTs;
                p.remoteTs = child.remoteTs;
                p.out = outSa;
                p.encap = child.encap;
                p.mode = child.mode;
                p.local = UserState::endpoint(child.local, child.encap ? child.localPort : 0);
                p.remote = UserState::endpoint(child.remote, child.encap ? child.remotePort : 0);
                co_await RouteRemoteSelectors(_state->options, _state->ifName, child, true);
                co_return SBOX_OK;
            }

            TTask<int32_t> removeChild(SIpsecChildSa child, bool policies) override {
                _state->inbound.erase(child.inboundSpi);
                _state->reserved.erase(child.inboundSpi);

                auto it = _state->policies.find(child.reqid);
                if (it != _state->policies.end()) {
                    if (policies) {
                        for (auto i = _state->inbound.begin(); i != _state->inbound.end();) {
                            i = i->second.reqid == child.reqid ? _state->inbound.erase(i) : std::next(i);
                        }

                        _state->policies.erase(it);
                        co_await RouteRemoteSelectors(_state->options, _state->ifName, child, false);
                    }
                    else if (it->second.out && it->second.out->spi() == child.outboundSpi) {
                        // --> The child is replaced without a successor: stop sending.
                        it->second.out.reset();
                    }
                }

                co_return SBOX_OK;
            }

            TTask<int32_t> updateChild(SIpsecChildSa child) override {
                auto it = _state->policies.find(child.reqid);
                if (it == _state->policies.end()) {
                    co_return -ENOENT;
                }

                it->second.encap = child.encap;
                it->second.local = UserState::endpoint(child.local, child.encap ? child.localPort : 0);
                it->second.remote = UserState::endpoint(child.remote, child.encap ? child.remotePort : 0);
                co_return SBOX_OK;
            }

            TTask<int32_t> stats(SIpsecChildSa child, SIpsecChildStats& out) override {
                auto in = _state->inbound.find(child.inboundSpi);
                if (in == _state->inbound.end()) {
                    co_return -ENOENT;
                }

                out = SIpsecChildStats();
                out.inBytes = in->second.sa->bytes();
                out.inPackets = in->second.sa->packets();
                out.lastInbound = in->second.sa->lastUsed();

                auto p = _state->policies.find(child.reqid);
                if (p != _state->policies.end() && p->second.out && p->second.out->spi() == child.outboundSpi) {
                    out.outBytes = p->second.out->bytes();
                    out.outPackets = p->second.out->packets();
                }

                co_return SBOX_OK;
            }
        };

    }

    /* Creates the user-space data path. */
    IIpsecDataPathPtr MakeUserDataPath(const SIpsecDataPathOptions& options) {
        return std::make_shared<UserDataPath>(options);
    }

}
}
}
