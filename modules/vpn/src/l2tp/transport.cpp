#include <sbox/vpn/l2tp/transport.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/vpn/ipsec/esp.hpp>
#include <sbox/vpn/ipsec/xfrm.hpp>
#include "ipsec/crypto.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>
#include <map>
#include <set>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace vpn {

    using ipsec::GetBe16;
    using ipsec::PutBe16;

    /* Kind parser. */
    bool ParseL2tpTransportKind(std::string_view text, EL2tpTransportKind& out) noexcept {
        if (text == "auto") {
            out = EL2TK_AUTO;
        }
        else if (text == "kernel") {
            out = EL2TK_KERNEL;
        }
        else if (text == "user") {
            out = EL2TK_USER;
        }
        else if (text == "none" || text == "plain") {
            out = EL2TK_PLAIN;
        }
        else {
            return false;
        }

        return true;
    }

    /* UDP checksum. */
    uint16_t L2tpUdpChecksum(const net::SIpAddress& src, const net::SIpAddress& dst, const SReadOnlyByteSpan& segment) noexcept {
        uint64_t sum = 0;
        auto add = [&sum](const uint8_t* p, size_t n) {
            for (size_t i = 0; i + 1 < n; i += 2) {
                sum += uint32_t(p[i] << 8) | p[i + 1];
            }

            if (n & 1) {
                sum += uint32_t(p[n - 1]) << 8;
            }
        };

        add(src.bytes, src.length());
        add(dst.bytes, dst.length());
        sum += 17;
        sum += uint32_t(segment.size);
        add(segment.data, segment.size);
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        uint16_t r = uint16_t(~sum);
        return r == 0 ? 0xffff : r;
    }

    namespace {

        /* Address of an endpoint. */
        net::SIpAddress addressOf(const SEndpoint& ep) {
            net::SIpAddress a;
            if (ep.family() == AF_INET) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(&ep.storage)->sin_addr), 4, a);
            }
            else if (ep.family() == AF_INET6) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(&ep.storage)->sin6_addr), 16, a);
            }

            return a;
        }

        /* Endpoint of an address and port. */
        SEndpoint endpointOf(const net::SIpAddress& a, uint16_t port) {
            SEndpoint ep;
            SEndpoint::fromIp(a.toString(), port, ep);
            return ep;
        }

        /* Channel key of an SA: outer peer address plus the NAT-T port when encapsulated. */
        std::string channelKey(const SIkev1IpsecSa& sa) {
            return sa.remote.toString() + (sa.encap ? ":" + std::to_string(sa.remoteIkePort) : std::string());
        }

        // ------------------------------------------------------------------------------------
        // User-space ESP transport mode

        struct UserState {
            struct Channel {
                uint64_t id = 0;
                std::string key;
                SIkev1IpsecSa sa;               // --> Newest SA (outbound side and addresses).
                std::shared_ptr<CEspSa> out;
                SEndpoint local;                // --> Outer endpoints (ports only with encap).
                SEndpoint remote;
                std::set<uint32_t> inbound;
                uint64_t inPackets = 0;
                uint64_t outPackets = 0;
            };

            struct Inbound {
                std::shared_ptr<CEspSa> sa;
                uint64_t channel = 0;
                uint16_t localPort = 0;         // --> Selector ports (0: any).
                uint16_t remotePort = 0;
            };

            SL2tpTransportOptions options;
            CEventLoop* loop = nullptr;
            CFd raw4;
            CFd raw6;
            bool closed = false;
            uint64_t nextChannel = 1;
            std::map<uint64_t, Channel> channels;
            std::map<std::string, uint64_t> byKey;
            std::map<uint32_t, Inbound> inbound;
            FL2tpReceive receive;
            std::function<void(uint64_t)> channelDown;

            /* Handles one ESP packet (raw or UDP-encapsulated). */
            void input(const SReadOnlyByteSpan& esp, const SEndpoint& remote) {
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

                auto cit = channels.find(it->second.channel);
                if (cit == channels.end()) {
                    return;
                }

                Channel& ch = cit->second;
                ++ch.inPackets;
                if (next == 59) {
                    return;     // --> Dummy packet.
                }

                if (next != 17 || payload.size() < 8) {
                    return;     // --> Only UDP is negotiated (L2TP).
                }

                uint16_t srcPort = GetBe16(payload.data());
                uint16_t dstPort = GetBe16(payload.data() + 2);
                size_t udpLen = GetBe16(payload.data() + 4);
                if (udpLen < 8 || udpLen > payload.size()) {
                    return;
                }

                // --> Enforce the negotiated selectors (the checksum is not verified: with NAT it
                // covers addresses that changed on the way, RFC 3948 3.1.2, and ESP already
                // authenticated the segment).
                if ((it->second.localPort && dstPort != it->second.localPort) || (it->second.remotePort && srcPort != it->second.remotePort)) {
                    return;
                }

                if (ch.sa.encap && remote.isValid() && remote.port() != 0 && remote.toString() != ch.remote.toString()) {
                    // --> NAT mapping changed: follow the authenticated source.
                    ch.remote = remote;
                }

                if (receive) {
                    SL2tpPeer peer;
                    peer.channel = ch.id;
                    peer.remote = endpointOf(ch.sa.remote, srcPort);
                    receive(peer, SReadOnlyByteSpan(payload.data() + 8, udpLen - 8));
                }
            }

            /* Sends one ESP packet over the raw socket. */
            int32_t sendRaw(const Channel& ch, const std::vector<uint8_t>& esp) {
                const CFd& raw = ch.remote.family() == AF_INET6 ? raw6 : raw4;
                if (!raw.isValid()) {
                    return -EBADF;
                }

                SEndpoint to = ch.remote;
                to.port(0);
                msghdr msg;
                std::memset(&msg, 0, sizeof(msg));
                msg.msg_name = &to.storage;
                msg.msg_namelen = to.length;
                iovec iov;
                iov.iov_base = const_cast<uint8_t*>(esp.data());
                iov.iov_len = esp.size();
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                alignas(cmsghdr) uint8_t control[64];
                std::memset(control, 0, sizeof(control));
                if (ch.local.family() == AF_INET) {
                    msg.msg_control = control;
                    msg.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
                    cmsghdr* c = CMSG_FIRSTHDR(&msg);
                    c->cmsg_level = IPPROTO_IP;
                    c->cmsg_type = IP_PKTINFO;
                    c->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
                    in_pktinfo info;
                    std::memset(&info, 0, sizeof(info));
                    info.ipi_spec_dst = reinterpret_cast<const sockaddr_in*>(&ch.local.storage)->sin_addr;
                    std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                }

                if (::sendmsg(raw.get(), &msg, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
                    return -errno;
                }

                return SBOX_OK;
            }

            /* Builds and sends one datagram. */
            int32_t send(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) {
                auto it = channels.find(peer.channel);
                if (it == channels.end() || !it->second.out) {
                    return -ENOENT;
                }

                Channel& ch = it->second;
                std::vector<uint8_t> segment;
                segment.reserve(payload.size + 8);
                PutBe16(segment, ch.sa.localPort ? ch.sa.localPort : options.port);
                PutBe16(segment, peer.remote.port());
                PutBe16(segment, uint32_t(payload.size + 8));
                PutBe16(segment, 0);
                segment.insert(segment.end(), payload.data, payload.data + payload.size);

                // --> Checksum over the addresses the peer's stack will see after
                // decapsulation: our address as it knows it and its own original address.
                net::SIpAddress src = ch.sa.localOriginal.isValid() ? ch.sa.localOriginal : ch.sa.local;
                net::SIpAddress dst = ch.sa.remoteOriginal.isValid() ? ch.sa.remoteOriginal : ch.sa.remote;
                if (src.family == dst.family) {
                    ipsec::SetBe16(segment.data() + 6, L2tpUdpChecksum(src, dst, BytesOf(segment)));
                }

                std::vector<uint8_t> esp;
                int32_t r = ch.out->encapsulate(BytesOf(segment), 17, esp);
                if (r != SBOX_OK) {
                    return r;
                }

                ++ch.outPackets;
                if (ch.sa.encap) {
                    if (!options.ikeSocket) {
                        return -ENOTCONN;
                    }

                    return options.ikeSocket->sendEsp(BytesOf(esp), ch.local, ch.remote);
                }

                return sendRaw(ch, esp);
            }
        };

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
                st->input(packet, remote);
            }
        }

        /**
         * User-space ESP transport.
         */
        class UserTransport : public IL2tpTransport {
        private:
            std::shared_ptr<UserState> _state;

        public:
            explicit UserTransport(const SL2tpTransportOptions& options) : _state(std::make_shared<UserState>()) {
                _state->options = options;
            }

            ~UserTransport() override {
                close();
            }

            const char* kind() const noexcept override {
                return "user";
            }

            void receiver(FL2tpReceive handler) override {
                _state->receive = std::move(handler);
            }

            void onChannelDown(std::function<void(uint64_t)> handler) override {
                _state->channelDown = std::move(handler);
            }

            TTask<int32_t> start() override {
                UserState& st = *_state;
                st.loop = CEventLoop::current();
                st.closed = false;
                {
                    net::CNetnsScope scope(st.options.netnsPath);
                    if (scope.error() != SBOX_OK) {
                        co_return scope.error();
                    }

                    st.raw4.reset(::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ESP));
                    if (!st.raw4.isValid()) {
                        co_return -errno;
                    }

                    if (st.options.ipv6) {
                        st.raw6.reset(::socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ESP));
                    }
                }

                st.loop->spawn(rawReader(_state, false));
                if (st.raw6.isValid()) {
                    st.loop->spawn(rawReader(_state, true));
                }

                co_return SBOX_OK;
            }

            void close() {
                UserState& st = *_state;
                st.closed = true;
                CEventLoop* loop = st.loop ? st.loop : CEventLoop::current();
                for (CFd* fd : { &st.raw4, &st.raw6 }) {
                    if (fd->isValid()) {
                        if (loop) {
                            loop->cancelFd(fd->get());
                        }

                        fd->reset();
                    }
                }

                if (st.options.ikeSocket) {
                    for (auto& [spi, in] : st.inbound) {
                        (void)in;
                        st.options.ikeSocket->espSpiHandler(spi, nullptr);
                    }
                }

                st.inbound.clear();
                st.channels.clear();
                st.byKey.clear();
            }

            TTask<void> stop() override {
                close();
                co_return;
            }

            int32_t send(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) override {
                return _state->send(peer, payload);
            }

            TTask<int32_t> addSa(SIkev1IpsecSa sa) override {
                UserState& st = *_state;
                SEspKeys in;
                in.encr = sa.encr;
                in.keyBits = sa.keyBits;
                in.integ = sa.integ;
                in.encKey = sa.inEncKey;
                in.integKey = sa.inIntegKey;
                SEspKeys out = in;
                out.encKey = sa.outEncKey;
                out.integKey = sa.outIntegKey;
                auto inSa = std::make_shared<CEspSa>();
                auto outSa = std::make_shared<CEspSa>();
                int32_t r = inSa->init(sa.inboundSpi, true, in, 64);
                if (r == SBOX_OK) {
                    r = outSa->init(sa.outboundSpi, false, out, 0);
                }

                IkeWipe(in.encKey);
                IkeWipe(in.integKey);
                IkeWipe(out.encKey);
                IkeWipe(out.integKey);
                if (r != SBOX_OK) {
                    co_return r;
                }

                std::string key = channelKey(sa);
                uint64_t id;
                auto kit = st.byKey.find(key);
                if (kit == st.byKey.end()) {
                    id = st.nextChannel++;
                    st.byKey[key] = id;
                }
                else {
                    id = kit->second;
                }

                UserState::Channel& ch = st.channels[id];
                ch.id = id;
                ch.key = key;
                ch.sa = sa;
                IkeWipe(ch.sa.inEncKey);
                IkeWipe(ch.sa.inIntegKey);
                IkeWipe(ch.sa.outEncKey);
                IkeWipe(ch.sa.outIntegKey);
                ch.out = outSa;
                ch.local = endpointOf(sa.local, sa.encap ? sa.localIkePort : 0);
                ch.remote = endpointOf(sa.remote, sa.encap ? sa.remoteIkePort : 0);
                ch.inbound.insert(sa.inboundSpi);

                UserState::Inbound ib;
                ib.sa = inSa;
                ib.channel = id;
                ib.localPort = sa.localPort;
                ib.remotePort = sa.remotePort;
                st.inbound[sa.inboundSpi] = ib;
                if (sa.encap && st.options.ikeSocket) {
                    std::weak_ptr<UserState> weak = _state;
                    st.options.ikeSocket->espSpiHandler(sa.inboundSpi, [weak](const SReadOnlyByteSpan& esp, const SEndpoint& remote, const SEndpoint&) {
                        if (auto s = weak.lock()) {
                            if (!s->closed) {
                                s->input(esp, remote);
                            }
                        }
                    });
                }

                co_return SBOX_OK;
            }

            TTask<int32_t> removeSa(SIkev1IpsecSa sa) override {
                UserState& st = *_state;
                auto it = st.inbound.find(sa.inboundSpi);
                if (it == st.inbound.end()) {
                    co_return -ENOENT;
                }

                uint64_t id = it->second.channel;
                st.inbound.erase(it);
                if (st.options.ikeSocket) {
                    st.options.ikeSocket->espSpiHandler(sa.inboundSpi, nullptr);
                }

                auto cit = st.channels.find(id);
                if (cit == st.channels.end()) {
                    co_return SBOX_OK;
                }

                cit->second.inbound.erase(sa.inboundSpi);
                if (cit->second.out && cit->second.out->spi() == sa.outboundSpi) {
                    cit->second.out.reset();
                }

                if (cit->second.inbound.empty()) {
                    st.byKey.erase(cit->second.key);
                    st.channels.erase(cit);
                    if (st.channelDown) {
                        st.channelDown(id);
                    }
                }

                co_return SBOX_OK;
            }

            uint16_t port() const noexcept override {
                return 0;
            }

            uint64_t channelOf(const SIkev1IpsecSa& sa) const override {
                auto it = _state->byKey.find(channelKey(sa));
                return it != _state->byKey.end() ? it->second : 0;
            }

            std::vector<SL2tpChannelInfo> channels() const override {
                std::vector<SL2tpChannelInfo> out;
                for (const auto& [id, ch] : _state->channels) {
                    SL2tpChannelInfo i;
                    i.channel = id;
                    i.remote = ch.remote.toString();
                    i.encap = ch.sa.encap;
                    i.sas = ch.inbound.size();
                    i.inPackets = ch.inPackets;
                    i.outPackets = ch.outPackets;
                    out.push_back(i);
                }

                return out;
            }
        };

        // ------------------------------------------------------------------------------------
        // UDP socket (plain, or kernel XFRM transport mode)

        struct UdpState {
            SL2tpTransportOptions options;
            CEventLoop* loop = nullptr;
            CFd fd;
            uint16_t port = 0;
            bool closed = false;
            bool kernel = false;
            CXfrm xfrm;
            uint64_t nextChannel = 1;
            uint32_t nextReqid = 0;
            struct Channel {
                uint64_t id = 0;
                std::string key;                // --> Remote address text.
                uint32_t reqid = 0;
                std::vector<SIkev1IpsecSa> sas; // --> Installed SAs (keys wiped).
                std::vector<SXfrmPolicy> policies;
                uint64_t inPackets = 0;
                uint64_t outPackets = 0;
            };

            std::map<uint64_t, Channel> channels;
            std::map<std::string, uint64_t> byKey;
            FL2tpReceive receive;
            std::function<void(uint64_t)> channelDown;

            /* Channel of a remote address (created on first use for plain UDP). */
            uint64_t channelOf(const std::string& key, bool create) {
                auto it = byKey.find(key);
                if (it != byKey.end()) {
                    return it->second;
                }

                if (!create) {
                    return 0;
                }

                uint64_t id = nextChannel++;
                byKey[key] = id;
                Channel& ch = channels[id];
                ch.id = id;
                ch.key = key;
                return id;
            }
        };

        /* Reads the UDP socket. */
        TTask<void> udpReader(std::shared_ptr<UdpState> st) {
            std::vector<uint8_t> buffer(65536);
            while (!st->closed && st->fd.isValid()) {
                int fd = st->fd.get();
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

                    if (errno == EINTR || errno == ECONNREFUSED) {
                        continue;
                    }

                    break;
                }

                SEndpoint remote;
                std::memcpy(&remote.storage, &from, fromLen);
                remote.length = fromLen;
                // --> Kernel mode: only peers with SAs have channels (the policies guarantee
                // that what arrives was protected). Plain mode: every address is a channel.
                uint64_t ch = st->channelOf(addressOf(remote).toString(), !st->kernel);
                if (!ch) {
                    continue;
                }

                st->channels[ch].inPackets++;
                if (st->receive) {
                    SL2tpPeer peer;
                    peer.channel = ch;
                    peer.remote = remote;
                    st->receive(peer, SReadOnlyByteSpan(buffer.data(), size_t(n)));
                }
            }
        }

        /**
         * UDP transport (plain or kernel IPsec).
         */
        class UdpTransport : public IL2tpTransport {
        private:
            std::shared_ptr<UdpState> _state;

        public:
            UdpTransport(const SL2tpTransportOptions& options, bool kernel) : _state(std::make_shared<UdpState>()) {
                _state->options = options;
                _state->kernel = kernel;
                _state->nextReqid = options.reqidBase;
            }

            ~UdpTransport() override {
                close();
            }

            const char* kind() const noexcept override {
                return _state->kernel ? "kernel" : "plain";
            }

            void receiver(FL2tpReceive handler) override {
                _state->receive = std::move(handler);
            }

            void onChannelDown(std::function<void(uint64_t)> handler) override {
                _state->channelDown = std::move(handler);
            }

            TTask<int32_t> start() override {
                UdpState& st = *_state;
                st.loop = CEventLoop::current();
                st.closed = false;
                int family = st.options.ipv6 ? AF_INET6 : AF_INET;
                {
                    net::CNetnsScope scope(st.options.netnsPath);
                    if (scope.error() != SBOX_OK) {
                        co_return scope.error();
                    }

                    st.fd.reset(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
                    if (!st.fd.isValid()) {
                        co_return -errno;
                    }
                }

                int one = 1;
                ::setsockopt(st.fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (family == AF_INET6) {
                    int zero = 0;
                    ::setsockopt(st.fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
                }

                SEndpoint local;
                std::string addr = st.options.address.empty() ? (family == AF_INET6 ? "::" : "0.0.0.0") : st.options.address;
                int32_t r = SEndpoint::fromIp(addr, st.options.port, local);
                if (r != SBOX_OK) {
                    co_return r;
                }

                if (::bind(st.fd.get(), reinterpret_cast<const sockaddr*>(&local.storage), local.length) < 0) {
                    r = -errno;
                    st.fd.reset();
                    co_return r;
                }

                sockaddr_storage bound;
                socklen_t len = sizeof(bound);
                ::getsockname(st.fd.get(), reinterpret_cast<sockaddr*>(&bound), &len);
                SEndpoint b;
                std::memcpy(&b.storage, &bound, len);
                b.length = len;
                st.port = b.port();

                if (st.kernel) {
                    r = st.xfrm.open(st.options.netnsPath);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    SXfrmOwner owner;
                    owner.reqidMin = st.options.reqidBase;
                    owner.reqidMax = st.options.reqidBase + 0xffffu;
                    co_await st.xfrm.flushOwned(owner);
                    if (st.options.ikeSocket && st.options.kernelEncap) {
                        r = st.options.ikeSocket->enableKernelEncap();
                        if (r != SBOX_OK) {
                            co_return r;
                        }
                    }
                }

                st.loop->spawn(udpReader(_state));
                co_return SBOX_OK;
            }

            void close() {
                UdpState& st = *_state;
                st.closed = true;
                if (st.fd.isValid()) {
                    CEventLoop* loop = st.loop ? st.loop : CEventLoop::current();
                    if (loop) {
                        loop->cancelFd(st.fd.get());
                    }

                    st.fd.reset();
                }
            }

            TTask<void> stop() override {
                UdpState& st = *_state;
                if (st.kernel && st.xfrm.isValid()) {
                    SXfrmOwner owner;
                    owner.reqidMin = st.options.reqidBase;
                    owner.reqidMax = st.options.reqidBase + 0xffffu;
                    co_await st.xfrm.flushOwned(owner);
                }

                st.channels.clear();
                st.byKey.clear();
                close();
            }

            int32_t send(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) override {
                UdpState& st = *_state;
                if (!st.fd.isValid()) {
                    return -EBADF;
                }

                uint64_t channel = peer.channel;
                if (channel == 0 && !st.kernel) {
                    // --> Plain UDP: the first datagram towards an address opens its channel.
                    channel = st.channelOf(addressOf(peer.remote).toString(), true);
                }

                auto it = st.channels.find(channel);
                if (it == st.channels.end()) {
                    return -ENOENT;
                }

                ++it->second.outPackets;
                if (::sendto(st.fd.get(), payload.data, payload.size, MSG_DONTWAIT | MSG_NOSIGNAL,
                             reinterpret_cast<const sockaddr*>(&peer.remote.storage), peer.remote.length) < 0) {
                    return -errno;
                }

                return SBOX_OK;
            }

            /* Builds the XFRM SA of one direction. */
            static SXfrmSa makeSa(const SIkev1IpsecSa& c, bool inbound, uint32_t reqid) {
                SXfrmSa sa;
                sa.src = inbound ? c.remote : c.local;
                sa.dst = inbound ? c.local : c.remote;
                sa.spi = inbound ? c.inboundSpi : c.outboundSpi;
                sa.mode = EXMODE_TRANSPORT;
                sa.reqid = reqid;
                sa.replayWindow = inbound ? 64 : 0;
                const std::vector<uint8_t>& enc = inbound ? c.inEncKey : c.outEncKey;
                const std::vector<uint8_t>& integ = inbound ? c.inIntegKey : c.outIntegKey;
                const SIkeEncrInfo* info = IkeEncrInfo(c.encr);
                if (info && info->aead) {
                    sa.aead.name = CXfrm::encrAlgorithm(c.encr);
                    sa.aead.key = enc;
                    sa.aead.bits = uint32_t(info->icvSize * 8);
                }
                else {
                    sa.crypt.name = CXfrm::encrAlgorithm(c.encr);
                    sa.crypt.key = enc;
                    sa.auth.name = CXfrm::integAlgorithm(c.integ);
                    sa.auth.key = integ;
                    sa.auth.bits = uint32_t(IkeIntegIcvSize(c.integ) * 8);
                }

                if (c.encap) {
                    sa.encap = true;
                    sa.encapSport = inbound ? c.remoteIkePort : c.localIkePort;
                    sa.encapDport = inbound ? c.localIkePort : c.remoteIkePort;
                }

                return sa;
            }

            TTask<int32_t> addSa(SIkev1IpsecSa sa) override {
                UdpState& st = *_state;
                if (!st.kernel) {
                    co_return -ENOTSUP;
                }

                std::string key = sa.remote.toString();
                uint64_t id = st.channelOf(key, true);
                UdpState::Channel& ch = st.channels[id];
                if (!ch.reqid) {
                    ch.reqid = ++st.nextReqid;
                }

                int32_t r = co_await st.xfrm.addSa(makeSa(sa, true, ch.reqid), false);
                if (r == SBOX_OK) {
                    r = co_await st.xfrm.addSa(makeSa(sa, false, ch.reqid), false);
                    if (r != SBOX_OK) {
                        co_await st.xfrm.deleteSa(sa.remote, sa.local, sa.inboundSpi);
                    }
                }

                if (r != SBOX_OK) {
                    if (ch.sas.empty()) {
                        st.byKey.erase(key);
                        st.channels.erase(id);
                    }

                    co_return r;
                }

                if (ch.policies.empty()) {
                    // --> UDP between our L2TP port and the peer (any of its ports).
                    for (EXfrmDir dir : { EXDIR_OUT, EXDIR_IN }) {
                        bool out = dir == EXDIR_OUT;
                        SXfrmPolicy p;
                        p.dir = dir;
                        p.selector.src = net::SIpPrefix(out ? sa.local : sa.remote, uint8_t(sa.local.bits()));
                        p.selector.dst = net::SIpPrefix(out ? sa.remote : sa.local, uint8_t(sa.local.bits()));
                        p.selector.protocol = 17;
                        uint16_t ours = sa.localPort ? sa.localPort : st.port;
                        if (out) {
                            p.selector.srcPort = ours;
                            p.selector.srcPortMask = 0xffff;
                        }
                        else {
                            p.selector.dstPort = ours;
                            p.selector.dstPortMask = 0xffff;
                        }

                        p.family = sa.local.isV6() ? 6 : 4;
                        p.priority = 0x2000;
                        SXfrmTemplate t;
                        t.src = out ? sa.local : sa.remote;
                        t.dst = out ? sa.remote : sa.local;
                        t.mode = EXMODE_TRANSPORT;
                        t.reqid = ch.reqid;
                        p.templates.push_back(t);
                        r = co_await st.xfrm.addPolicy(p, true);
                        if (r != SBOX_OK) {
                            co_return r;
                        }

                        ch.policies.push_back(p);
                    }
                }

                IkeWipe(sa.inEncKey);
                IkeWipe(sa.inIntegKey);
                IkeWipe(sa.outEncKey);
                IkeWipe(sa.outIntegKey);
                ch.sas.push_back(sa);
                co_return SBOX_OK;
            }

            TTask<int32_t> removeSa(SIkev1IpsecSa sa) override {
                UdpState& st = *_state;
                if (!st.kernel) {
                    co_return -ENOTSUP;
                }

                uint64_t id = st.channelOf(sa.remote.toString(), false);
                auto it = st.channels.find(id);
                if (it == st.channels.end()) {
                    co_return -ENOENT;
                }

                co_await st.xfrm.deleteSa(sa.remote, sa.local, sa.inboundSpi);
                co_await st.xfrm.deleteSa(sa.local, sa.remote, sa.outboundSpi);
                auto& sas = it->second.sas;
                for (size_t i = 0; i < sas.size(); ++i) {
                    if (sas[i].inboundSpi == sa.inboundSpi) {
                        sas.erase(sas.begin() + long(i));
                        break;
                    }
                }

                if (sas.empty()) {
                    for (const SXfrmPolicy& p : it->second.policies) {
                        co_await st.xfrm.deletePolicy(p.selector, p.dir, p.mark, p.ifId, p.family);
                    }

                    st.byKey.erase(it->second.key);
                    st.channels.erase(it);
                    if (st.channelDown) {
                        st.channelDown(id);
                    }
                }

                co_return SBOX_OK;
            }

            uint16_t port() const noexcept override {
                return _state->port;
            }

            uint64_t channelOf(const SIkev1IpsecSa& sa) const override {
                auto it = _state->byKey.find(sa.remote.toString());
                return it != _state->byKey.end() ? it->second : 0;
            }

            std::vector<SL2tpChannelInfo> channels() const override {
                std::vector<SL2tpChannelInfo> out;
                for (const auto& [id, ch] : _state->channels) {
                    SL2tpChannelInfo i;
                    i.channel = id;
                    i.remote = ch.key;
                    i.encap = !ch.sas.empty() && ch.sas.back().encap;
                    i.sas = ch.sas.size();
                    i.inPackets = ch.inPackets;
                    i.outPackets = ch.outPackets;
                    out.push_back(i);
                }

                return out;
            }
        };

    }

    /* Transport factory. */
    TTask<int32_t> CreateL2tpTransport(SL2tpTransportOptions options, IL2tpTransportPtr& out) {
        EL2tpTransportKind kind = options.kind;
        if (kind == EL2TK_AUTO || kind == EL2TK_KERNEL) {
            CXfrm xfrm;
            SXfrmSupport support;
            bool esp = xfrm.open(options.netnsPath) == SBOX_OK && co_await xfrm.probe(support) == SBOX_OK && support.esp;
            if (kind == EL2TK_KERNEL && !esp) {
                co_return -ENOTSUP;
            }

            kind = esp ? EL2TK_KERNEL : EL2TK_USER;
        }

        if (kind == EL2TK_KERNEL) {
            out = std::make_shared<UdpTransport>(options, true);
        }
        else if (kind == EL2TK_PLAIN) {
            out = std::make_shared<UdpTransport>(options, false);
        }
        else {
            out = std::make_shared<UserTransport>(options);
        }

        co_return SBOX_OK;
    }

}
}
