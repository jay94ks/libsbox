#include <sbox/vpn/wg/device.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/wg/kernel.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <climits>
#include <cstring>
#include <netinet/in.h>
#include <set>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace sbox {
namespace vpn {

    namespace {

        /* Opens one UDP socket of `family` bound to `port` in the current namespace. */
        int32_t openUdp(int family, uint16_t port, uint32_t fwmark, CFd& out) noexcept {
            CFd fd(::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
            if (!fd.isValid()) {
                return -errno;
            }

            int one = 1;
            if (family == AF_INET6) {
                ::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
            }

            // --> Larger buffers absorb bursts between two event loop turns.
            int size = 1 << 20;
            ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
            ::setsockopt(fd.get(), SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

            if (fwmark && ::setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) < 0) {
                return -errno;
            }

            sockaddr_storage ss;
            std::memset(&ss, 0, sizeof(ss));
            socklen_t len = 0;
            if (family == AF_INET) {
                sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(&ss);
                sa->sin_family = AF_INET;
                sa->sin_port = htons(port);
                len = sizeof(*sa);
            }
            else {
                sockaddr_in6* sa = reinterpret_cast<sockaddr_in6*>(&ss);
                sa->sin6_family = AF_INET6;
                sa->sin6_port = htons(port);
                len = sizeof(*sa);
            }

            if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&ss), len) < 0) {
                return -errno;
            }

            out = std::move(fd);
            return SBOX_OK;
        }

        /* Returns the bound port of a socket. */
        uint16_t boundPort(int fd) noexcept {
            sockaddr_storage ss;
            socklen_t len = sizeof(ss);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) < 0) {
                return 0;
            }

            if (ss.ss_family == AF_INET) {
                return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
            }

            return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
        }

        /* Returns true for a prefix worth a route (not a default route). */
        bool routable(const net::SIpPrefix& p) noexcept {
            return p.isValid() && p.length > 0;
        }

    }

    /* Device internals; also the engine's output for the user-space backend. */
    struct CWgDevice::SImpl : IWgOutput, std::enable_shared_from_this<CWgDevice::SImpl> {
        SWgDeviceOptions options;
        bool open = false;
        bool kernel = false;
        bool stopped = false;
        int32_t ifIndex = 0;
        uint16_t port = 0;
        uint32_t fwmark = 0;
        CFd done;                       // --> eventfd signalled by close().
        net::CRtnl rtnl;
        std::set<std::string> routes;   // --> Routes we added ("prefix" strings).

        // -- Kernel backend.
        std::unique_ptr<CWgKernelClient> kc;

        // -- User-space backend.
        std::unique_ptr<CWgEngine> engine;
        CFd tun;
        CFd udp4;
        CFd udp6;
        CFd timer;
        int64_t armed = INT64_MAX;
        uint64_t generation = 0;        // --> Bumped when the UDP sockets are replaced.
        size_t bufferSize = 0;
        bool batching = false;
        struct Pending {
            SEndpoint to;
            const uint8_t* data;
            size_t length;
        };
        std::vector<Pending> pending;
        std::vector<mmsghdr> sendMsgs;
        std::vector<iovec> sendIov;
        CListener uapi;
        std::string uapiPath;

        ~SImpl() override {
            if (!uapiPath.empty()) {
                ::unlink(uapiPath.c_str());
            }
        }

        // -- IWgOutput.

        /* Sends now, or queues for the batch flush when the bytes stay valid. */
        void sendDatagram(const SEndpoint& to, const SReadOnlyByteSpan& bytes, bool stable) override {
            if (stable && batching) {
                pending.push_back(Pending{ to, bytes.data, bytes.size });
                return;
            }

            int fd = to.family() == AF_INET ? udp4.get() : (to.family() == AF_INET6 ? udp6.get() : -1);
            if (fd >= 0) {
                ::sendto(fd, bytes.data, bytes.size, MSG_DONTWAIT, reinterpret_cast<const sockaddr*>(&to.storage), to.length);
            }
        }

        /* Writes a decrypted packet to the TUN device. */
        void writePacket(const SReadOnlyByteSpan& packet) override {
            if (tun.isValid()) {
                ssize_t n = ::write(tun.get(), packet.data, packet.size);
                (void)n;
            }
        }

        /* Sends the queued datagrams with sendmmsg, per family. */
        void flush() {
            if (pending.empty()) {
                return;
            }

            for (int family : { AF_INET, AF_INET6 }) {
                int fd = family == AF_INET ? udp4.get() : udp6.get();
                sendMsgs.clear();
                sendIov.clear();
                sendIov.reserve(pending.size());
                for (const Pending& p : pending) {
                    if (p.to.family() != family) {
                        continue;
                    }

                    sendIov.push_back(iovec{ const_cast<uint8_t*>(p.data), p.length });
                    mmsghdr m;
                    std::memset(&m, 0, sizeof(m));
                    m.msg_hdr.msg_name = const_cast<sockaddr_storage*>(&p.to.storage);
                    m.msg_hdr.msg_namelen = p.to.length;
                    sendMsgs.push_back(m);
                }

                if (fd < 0 || sendMsgs.empty()) {
                    continue;
                }

                for (size_t i = 0; i < sendMsgs.size(); ++i) {
                    sendMsgs[i].msg_hdr.msg_iov = &sendIov[i];
                    sendMsgs[i].msg_hdr.msg_iovlen = 1;
                }

                size_t sent = 0;
                while (sent < sendMsgs.size()) {
                    int n = ::sendmmsg(fd, sendMsgs.data() + sent, unsigned(sendMsgs.size() - sent), MSG_DONTWAIT);
                    if (n <= 0) {
                        if (n < 0 && errno == EINTR) {
                            continue;
                        }

                        // --> A full socket buffer drops the rest, as a congested link would.
                        if (n < 0 && errno != EAGAIN) {
                            ++sent;
                            continue;
                        }

                        break;
                    }

                    sent += size_t(n);
                }
            }

            pending.clear();
        }

        /* Re-arms the timerfd to the engine's next deadline. */
        void armTimer() {
            if (!engine || !timer.isValid()) {
                return;
            }

            int64_t d = engine->nextDeadline();
            if (d == armed) {
                return;
            }

            armed = d;
            itimerspec its;
            std::memset(&its, 0, sizeof(its));
            if (d != INT64_MAX) {
                if (d < 1) {
                    d = 1;
                }

                its.it_value.tv_sec = time_t(d / 1000);
                its.it_value.tv_nsec = long((d % 1000) * 1000000);
            }

            ::timerfd_settime(timer.get(), TFD_TIMER_ABSTIME, &its, nullptr);
        }

        /* Work done after every batch: flush and re-arm. */
        void afterWork() {
            flush();
            armTimer();
        }

        /* Opens the UDP sockets on `wanted` (0: random) in the device's namespace. */
        int32_t openSockets(uint16_t wanted, CFd& v4, CFd& v6, uint16_t& actual) {
            net::CNetnsScope scope(options.netnsPath);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            for (int attempt = 0; attempt < 8; ++attempt) {
                CFd a, b;
                int32_t r = openUdp(AF_INET, wanted, fwmark, a);
                if (r != SBOX_OK) {
                    return r;
                }

                uint16_t p = boundPort(a.get());
                r = openUdp(AF_INET6, p, fwmark, b);
                if (r == -EADDRINUSE && wanted == 0) {
                    continue;   // --> The random IPv4 port is taken for IPv6: pick another.
                }

                // --> No IPv6 in this kernel/namespace: IPv4 only.
                if (r != SBOX_OK && r != -EAFNOSUPPORT && r != -EADDRNOTAVAIL && r != -EPROTONOSUPPORT) {
                    return r;
                }

                v4 = std::move(a);
                v6 = std::move(b);
                actual = p;
                return SBOX_OK;
            }

            return -EADDRINUSE;
        }

        /* Stops watching and closes the UDP sockets. */
        void closeSockets() {
            CEventLoop* loop = CEventLoop::current();
            for (CFd* fd : { &udp4, &udp6 }) {
                if (fd->isValid()) {
                    if (loop) {
                        loop->cancelFd(fd->get());
                    }

                    fd->reset();
                }
            }
        }

        /* Replaces the UDP sockets (listen port change) and starts their readers. */
        int32_t rebind(uint16_t wanted) {
            CFd v4, v6;
            uint16_t actual = 0;
            if (udp4.isValid() && wanted != 0 && wanted == port) {
                return SBOX_OK;
            }

            // --> Release the old port first so the same port can be taken again.
            closeSockets();
            int32_t r = openSockets(wanted, v4, v6, actual);
            if (r != SBOX_OK) {
                return r;
            }

            udp4 = std::move(v4);
            udp6 = std::move(v6);
            port = actual;
            ++generation;

            CEventLoop* loop = CEventLoop::current();
            loop->spawn(udpLoop(shared_from_this(), udp4.get(), generation));
            if (udp6.isValid()) {
                loop->spawn(udpLoop(shared_from_this(), udp6.get(), generation));
            }

            return SBOX_OK;
        }

        /* Applies SO_MARK to the sockets. */
        int32_t applyFwmark(uint32_t mark) {
            fwmark = mark;
            for (CFd* fd : { &udp4, &udp6 }) {
                if (fd->isValid() && ::setsockopt(fd->get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
                    return -errno;
                }
            }

            return SBOX_OK;
        }

        /* Reads datagrams in batches and feeds the engine. */
        static TTask<void> udpLoop(std::shared_ptr<SImpl> self, int fd, uint64_t gen) {
            CEventLoop* loop = CEventLoop::current();
            size_t n = self->options.batch ? self->options.batch : 1;
            size_t size = self->bufferSize;
            std::vector<uint8_t> storage(n * size);
            std::vector<mmsghdr> msgs(n);
            std::vector<iovec> iov(n);
            std::vector<sockaddr_storage> names(n);

            while (!self->stopped && self->generation == gen) {
                int32_t r = co_await loop->waitFd(fd, EFDE_READ);
                if (r < 0 || self->stopped || self->generation != gen) {
                    break;
                }

                for (int round = 0; round < 8; ++round) {
                    for (size_t i = 0; i < n; ++i) {
                        iov[i].iov_base = storage.data() + i * size;
                        iov[i].iov_len = size;
                        std::memset(&msgs[i], 0, sizeof(mmsghdr));
                        msgs[i].msg_hdr.msg_iov = &iov[i];
                        msgs[i].msg_hdr.msg_iovlen = 1;
                        msgs[i].msg_hdr.msg_name = &names[i];
                        msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
                    }

                    int got = ::recvmmsg(fd, msgs.data(), unsigned(n), MSG_DONTWAIT, nullptr);
                    if (got <= 0) {
                        break;
                    }

                    for (int i = 0; i < got && !self->stopped; ++i) {
                        if (msgs[size_t(i)].msg_hdr.msg_flags & MSG_TRUNC) {
                            continue;
                        }

                        SEndpoint from;
                        std::memcpy(&from.storage, &names[size_t(i)], msgs[size_t(i)].msg_hdr.msg_namelen);
                        from.length = msgs[size_t(i)].msg_hdr.msg_namelen;
                        self->engine->receiveDatagram(from, storage.data() + size_t(i) * size, msgs[size_t(i)].msg_len);
                    }

                    if (self->stopped || size_t(got) < n) {
                        break;
                    }
                }

                if (!self->stopped) {
                    self->afterWork();
                }
            }
        }

        /* Reads tunnel packets in batches, encrypts and sends them with sendmmsg. */
        static TTask<void> tunLoop(std::shared_ptr<SImpl> self) {
            CEventLoop* loop = CEventLoop::current();
            int fd = self->tun.get();
            size_t n = self->options.batch ? self->options.batch : 1;
            size_t size = self->bufferSize;
            std::vector<uint8_t> storage(n * size);
            std::vector<size_t> lengths(n);

            while (!self->stopped) {
                int32_t r = co_await loop->waitFd(fd, EFDE_READ);
                if (r < 0 || self->stopped) {
                    break;
                }

                for (int round = 0; round < 8; ++round) {
                    size_t count = 0;
                    bool gone = false;
                    for (; count < n; ++count) {
                        uint8_t* buf = storage.data() + count * size;
                        ssize_t got = ::read(fd, buf + WG_DATA_HEADROOM, size - WG_DATA_HEADROOM - WG_DATA_TAILROOM);
                        if (got < 0 && errno != EAGAIN && errno != EINTR) {
                            // --> The interface was deleted under us (EBADFD): the device is over.
                            gone = true;
                            break;
                        }

                        if (got <= 0) {
                            break;
                        }

                        lengths[count] = size_t(got);
                    }

                    if (gone) {
                        self->stopUser();
                        self->signalDone();
                        break;
                    }

                    self->batching = true;
                    for (size_t i = 0; i < count && !self->stopped; ++i) {
                        self->engine->sendPacket(storage.data() + i * size, lengths[i], size);
                    }

                    self->batching = false;
                    self->flush();
                    if (self->stopped || count < n) {
                        break;
                    }
                }

                if (!self->stopped) {
                    self->armTimer();
                }
            }
        }

        /* Runs the engine's timers when the timerfd fires. */
        static TTask<void> timerLoop(std::shared_ptr<SImpl> self) {
            CEventLoop* loop = CEventLoop::current();
            while (!self->stopped) {
                int32_t r = co_await loop->waitFd(self->timer.get(), EFDE_READ);
                if (r < 0 || self->stopped) {
                    break;
                }

                uint64_t expirations = 0;
                ssize_t got = ::read(self->timer.get(), &expirations, sizeof(expirations));
                (void)got;
                self->armed = INT64_MAX - 1;    // --> Force the next armTimer() to program it.
                self->engine->runTimers();
                self->afterWork();
            }
        }

        /* Serves one UAPI connection. */
        static TTask<void> uapiConnection(std::shared_ptr<SImpl> self, std::shared_ptr<CSocket> sock) {
            std::string buffer;
            uint8_t chunk[4096];

            while (!self->stopped) {
                size_t end = buffer.find("\n\n");
                if (end == std::string::npos) {
                    SIoResult got = co_await sock->recv(SByteSpan(chunk, sizeof(chunk)), 30000);
                    if (!got.ok() || got.bytes == 0 || buffer.size() > (1u << 20)) {
                        break;
                    }

                    buffer.append(reinterpret_cast<const char*>(chunk), got.bytes);
                    continue;
                }

                std::string request = buffer.substr(0, end + 1);
                buffer.erase(0, end + 2);

                std::string answer;
                if (request.rfind("get=1\n", 0) == 0) {
                    SWgDeviceStatus st;
                    self->userStatus(st);
                    answer = FormatWgUapiGet(st) + "errno=0\n\n";
                }
                else if (request.rfind("set=1\n", 0) == 0) {
                    SWgDeviceConfig cfg;
                    int32_t r = ParseWgUapiSet(std::string_view(request).substr(6), cfg);
                    if (r == SBOX_OK) {
                        r = co_await self->applyUser(std::move(cfg));
                    }

                    answer = "errno=" + std::to_string(r < 0 ? -r : 0) + "\n\n";
                }
                else {
                    answer = "errno=" + std::to_string(EINVAL) + "\n\n";
                }

                SIoResult w = co_await sock->send(BytesOf(answer), 30000);
                if (!w.ok()) {
                    break;
                }
            }

            sock->close();
        }

        /* Accepts UAPI connections. */
        static TTask<void> uapiLoop(std::shared_ptr<SImpl> self) {
            CEventLoop* loop = CEventLoop::current();
            while (!self->stopped) {
                std::shared_ptr<CSocket> sock = std::make_shared<CSocket>();
                int32_t r = co_await self->uapi.accept(*sock);
                if (r != SBOX_OK || self->stopped) {
                    break;
                }

                loop->spawn(uapiConnection(self, sock));
            }
        }

        /* Fills the status of a user-space device. */
        void userStatus(SWgDeviceStatus& out) const {
            out = SWgDeviceStatus();
            out.name = options.name;
            out.ifIndex = ifIndex;
            out.kernel = false;
            out.privateKey = engine->privateKey();
            out.publicKey = engine->publicKey();
            out.listenPort = port;
            out.fwmark = fwmark;
            out.peers = engine->peers();
        }

        /* Adds routes for every routable allowed IP and removes stale ones. */
        TTask<int32_t> syncRoutes(std::vector<SWgPeerStatus> peers) {
            if (!options.routeAllowedIps || ifIndex <= 0) {
                co_return SBOX_OK;
            }

            std::set<std::string> wanted;
            std::vector<net::SIpPrefix> toAdd;
            for (const SWgPeerStatus& p : peers) {
                for (const net::SIpPrefix& ip : p.allowedIps) {
                    if (routable(ip)) {
                        std::string key = ip.network().toString();
                        if (wanted.insert(key).second && routes.find(key) == routes.end()) {
                            toAdd.push_back(ip.network());
                        }
                    }
                }
            }

            for (auto it = routes.begin(); it != routes.end();) {
                if (wanted.find(*it) == wanted.end()) {
                    net::SRouteInfo rt;
                    net::SIpPrefix::parse(*it, rt.destination);
                    rt.oif = ifIndex;
                    co_await rtnl.delRoute(rt);
                    it = routes.erase(it);
                }
                else {
                    ++it;
                }
            }

            for (const net::SIpPrefix& p : toAdd) {
                net::SRouteInfo rt;
                rt.destination = p;
                rt.oif = ifIndex;
                int32_t r = co_await rtnl.addRoute(rt, true);
                if (r != SBOX_OK) {
                    co_return r;
                }

                routes.insert(p.toString());
            }

            co_return SBOX_OK;
        }

        /* Applies a change to the user-space engine. */
        TTask<int32_t> applyUser(SWgDeviceConfig config) {
            if (stopped) {
                co_return -EBADF;
            }

            if (config.privateKey.valid) {
                int32_t r = engine->privateKey(config.privateKey.isZero() ? SWgKey() : config.privateKey);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            if (config.fwmark >= 0) {
                int32_t r = applyFwmark(uint32_t(config.fwmark));
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            if (config.listenPort >= 0) {
                int32_t r = rebind(uint16_t(config.listenPort));
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            if (config.replacePeers) {
                engine->removeAllPeers();
            }

            for (const SWgPeerConfig& p : config.peers) {
                int32_t r = engine->setPeer(p);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            afterWork();
            co_return co_await syncRoutes(engine->peers());
        }

        /* Applies a change to the kernel device. */
        TTask<int32_t> applyKernel(SWgDeviceConfig config) {
            int32_t r = co_await kc->setDevice(options.name, config);
            if (r != SBOX_OK) {
                co_return r;
            }

            SWgDeviceStatus st;
            r = co_await kc->getDevice(options.name, st);
            if (r != SBOX_OK) {
                co_return r;
            }

            port = st.listenPort;
            fwmark = st.fwmark;
            co_return co_await syncRoutes(st.peers);
        }

        /* Stops the user-space machinery (synchronous part). */
        void stopUser() {
            CEventLoop* loop = CEventLoop::current();
            closeSockets();
            for (CFd* fd : { &tun, &timer }) {
                if (fd->isValid()) {
                    if (loop) {
                        loop->cancelFd(fd->get());
                    }

                    fd->reset();
                }
            }

            if (uapi.isValid()) {
                uapi.close();
            }

            if (!uapiPath.empty()) {
                ::unlink(uapiPath.c_str());
                uapiPath.clear();
            }
        }

        /* Marks the device closed and wakes wait(). */
        void signalDone() {
            stopped = true;
            open = false;
            if (done.isValid()) {
                uint64_t one = 1;
                ssize_t n = ::write(done.get(), &one, sizeof(one));
                (void)n;
            }
        }
    };

    /* Creates an empty device. */
    CWgDevice::CWgDevice() : _impl(std::make_shared<SImpl>()) {
    }

    /* Moves a device. */
    CWgDevice::CWgDevice(CWgDevice&& other) noexcept : _impl(std::move(other._impl)) {
    }

    /* Moves a device. */
    CWgDevice& CWgDevice::operator=(CWgDevice&& other) noexcept {
        if (this != &other) {
            if (_impl && _impl->open && !_impl->kernel) {
                _impl->stopUser();
                _impl->signalDone();
            }

            _impl = std::move(other._impl);
        }

        return *this;
    }

    /* Stops a user-space device. */
    CWgDevice::~CWgDevice() {
        if (_impl && _impl->open && !_impl->kernel) {
            _impl->stopUser();
            _impl->signalDone();
        }
    }

    /* Probes the kernel module. */
    TTask<bool> CWgDevice::kernelAvailable(std::string netnsPath) {
        CWgKernelClient kc;
        int32_t r = co_await kc.open(netnsPath);
        if (r == SBOX_OK) {
            co_return true;
        }

        if (r != -ENOENT) {
            co_return false;
        }

        // --> Creating a link of the type autoloads the module when it is installed.
        net::CRtnl rtnl;
        if (rtnl.open(netnsPath) != SBOX_OK) {
            co_return false;
        }

        net::SLinkSpec spec;
        spec.name = "wgprobe" + net::RandomHex(6);
        spec.kind = "wireguard";
        if (co_await rtnl.createLink(spec) != SBOX_OK) {
            co_return false;
        }

        int32_t index = co_await rtnl.linkIndex(spec.name);
        if (index > 0) {
            co_await rtnl.deleteLink(index);
        }

        CWgKernelClient again;
        co_return co_await again.open(netnsPath) == SBOX_OK;
    }

    /* Creates the interface. */
    TTask<int32_t> CWgDevice::create(SWgDeviceOptions options) {
        SImpl& m = *_impl;
        if (m.open) {
            co_return -EALREADY;
        }

        if (options.name.empty() || options.name.size() > 15 || options.name.find('/') != std::string::npos) {
            co_return -EINVAL;
        }

        if (options.mtu < 576 || options.mtu > 65535) {
            co_return -EINVAL;
        }

        m.options = options;
        m.stopped = false;
        int32_t r = m.rtnl.open(options.netnsPath);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::SLinkInfo existing;
        if (co_await m.rtnl.getLink(options.name, existing) == SBOX_OK) {
            co_return -EEXIST;
        }

        bool created = false;
        if (options.mode != EWGM_USERSPACE) {
            std::unique_ptr<CWgKernelClient> kc(new CWgKernelClient());
            r = co_await kc->open(options.netnsPath);

            net::SLinkSpec spec;
            spec.name = options.name;
            spec.kind = "wireguard";
            spec.mtu = options.mtu;

            if (r == SBOX_OK || r == -ENOENT) {
                // --> Creating the link may load the module, after which the family exists.
                int32_t lr = co_await m.rtnl.createLink(spec);
                if (lr == SBOX_OK) {
                    created = true;
                    if (r == -ENOENT) {
                        r = co_await kc->open(options.netnsPath);
                    }
                }
                else {
                    r = lr;
                }
            }

            if (created && r == SBOX_OK) {
                m.kernel = true;
                m.kc = std::move(kc);
            }
            else {
                if (created) {
                    int32_t idx = co_await m.rtnl.linkIndex(options.name);
                    if (idx > 0) {
                        co_await m.rtnl.deleteLink(idx);
                    }
                }

                if (options.mode == EWGM_KERNEL) {
                    co_return -ENOTSUP;
                }
            }
        }

        if (!m.kernel) {
            net::STunTapOptions tt;
            tt.netnsPath = options.netnsPath;
            CFd tun;
            r = net::CreateTunTap(options.name, tt, tun);
            if (r != SBOX_OK) {
                co_return r;
            }

            m.tun = std::move(tun);
            m.bufferSize = WG_DATA_HEADROOM + (options.mtu < 1500 ? 1500 : options.mtu) + WG_DATA_TAILROOM + 64;

            SWgEngineOptions eo;
            eo.timers = options.timers;
            eo.mtu = options.mtu;
            m.engine.reset(new CWgEngine(&m, eo));
        }

        int32_t index = co_await m.rtnl.linkIndex(options.name);
        if (index < 0) {
            co_return index;
        }

        m.ifIndex = index;

        auto fail = [&](int32_t code) -> TTask<int32_t> {
            if (m.kernel) {
                co_await m.rtnl.deleteLink(m.ifIndex);
            }
            else {
                m.stopUser();
            }

            m.engine.reset();
            m.kc.reset();
            m.kernel = false;
            co_return code;
        };

        if (!m.kernel || !created) {
            r = co_await m.rtnl.setMtu(index, options.mtu);
            if (r != SBOX_OK) {
                co_return co_await fail(r);
            }
        }

        for (const net::SIpPrefix& a : options.addresses) {
            r = co_await m.rtnl.addAddress(index, a, true);
            if (r != SBOX_OK) {
                co_return co_await fail(r);
            }
        }

        if (options.up) {
            r = co_await m.rtnl.setUp(index, true);
            if (r != SBOX_OK) {
                co_return co_await fail(r);
            }
        }

        m.done.reset(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));

        if (!m.kernel) {
            m.timer.reset(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
            if (!m.timer.isValid()) {
                co_return co_await fail(-errno);
            }

            r = m.rebind(0);
            if (r != SBOX_OK) {
                co_return co_await fail(r);
            }

            CEventLoop* loop = CEventLoop::current();
            loop->spawn(SImpl::tunLoop(_impl));
            loop->spawn(SImpl::timerLoop(_impl));

            if (options.uapi) {
                CFile::makeDirs(options.uapiDir, 0755);
                std::string path = WgUapiSocketPath(options.name, options.uapiDir);
                SEndpoint ep;
                r = SEndpoint::fromUnix(path, ep);
                if (r == SBOX_OK) {
                    mode_t old = ::umask(0077);
                    r = m.uapi.listen(ep);
                    ::umask(old);
                }

                if (r != SBOX_OK) {
                    co_return co_await fail(r);
                }

                m.uapiPath = path;
                loop->spawn(SImpl::uapiLoop(_impl));
            }
        }

        m.open = true;
        co_return SBOX_OK;
    }

    /* Returns true when open. */
    bool CWgDevice::isOpen() const noexcept {
        return _impl && _impl->open;
    }

    /* Returns true for a kernel device. */
    bool CWgDevice::isKernel() const noexcept {
        return _impl && _impl->kernel;
    }

    /* Returns the interface name. */
    const std::string& CWgDevice::name() const noexcept {
        return _impl->options.name;
    }

    /* Returns the interface index. */
    int32_t CWgDevice::ifIndex() const noexcept {
        return _impl->ifIndex;
    }

    /* Returns the options. */
    const SWgDeviceOptions& CWgDevice::options() const noexcept {
        return _impl->options;
    }

    /* Applies a change. */
    TTask<int32_t> CWgDevice::configure(SWgDeviceConfig config) {
        if (!_impl->open) {
            co_return -EBADF;
        }

        std::shared_ptr<SImpl> keep = _impl;
        if (keep->kernel) {
            co_return co_await keep->applyKernel(std::move(config));
        }

        co_return co_await keep->applyUser(std::move(config));
    }

    /* Applies a whole configuration. */
    TTask<int32_t> CWgDevice::setConfig(SWgConfig config) {
        SWgDeviceConfig dc;
        dc.privateKey = config.privateKey;
        if (!dc.privateKey.valid) {
            // --> setconf semantics: no key in the file means no identity.
            dc.privateKey.valid = true;
            std::memset(dc.privateKey.bytes, 0, WG_KEY_BYTES);
        }

        dc.listenPort = config.listenPort;
        dc.fwmark = config.fwmark;
        dc.replacePeers = true;
        for (SWgPeerConfig& p : config.peers) {
            if (!p.endpoint.isValid() && !p.endpointHost.empty()) {
                co_return -EDESTADDRREQ;
            }

            p.replaceAllowedIps = true;
            if (p.persistentKeepalive < 0) {
                p.persistentKeepalive = 0;
            }

            dc.peers.push_back(p);
        }

        co_return co_await configure(std::move(dc));
    }

    /* Adds or updates a peer. */
    TTask<int32_t> CWgDevice::setPeer(SWgPeerConfig peer) {
        SWgDeviceConfig dc;
        dc.peers.push_back(std::move(peer));
        co_return co_await configure(std::move(dc));
    }

    /* Removes a peer. */
    TTask<int32_t> CWgDevice::removePeer(SWgKey publicKey) {
        SWgDeviceConfig dc;
        SWgPeerConfig p;
        p.publicKey = publicKey;
        p.remove = true;
        dc.peers.push_back(p);
        co_return co_await configure(std::move(dc));
    }

    /* Reads the device. */
    TTask<int32_t> CWgDevice::status(SWgDeviceStatus& out) {
        if (!_impl->open) {
            co_return -EBADF;
        }

        std::shared_ptr<SImpl> keep = _impl;
        if (keep->kernel) {
            int32_t r = co_await keep->kc->getDevice(keep->options.name, out);
            out.kernel = true;
            co_return r;
        }

        keep->userStatus(out);
        co_return SBOX_OK;
    }

    /* Returns the listen port. */
    uint16_t CWgDevice::listenPort() const noexcept {
        return _impl->port;
    }

    /* Returns the engine. */
    CWgEngine* CWgDevice::engine() noexcept {
        return _impl ? _impl->engine.get() : nullptr;
    }

    /* Stops and deletes the interface. */
    TTask<int32_t> CWgDevice::close() {
        if (!_impl || !_impl->open) {
            co_return SBOX_OK;
        }

        std::shared_ptr<SImpl> keep = _impl;
        int32_t r = SBOX_OK;
        if (keep->kernel) {
            r = co_await keep->rtnl.deleteLink(keep->ifIndex);
            if (r == -ENODEV) {
                r = SBOX_OK;
            }
        }
        else {
            keep->stopUser();
        }

        keep->signalDone();
        co_return r;
    }

    /* Waits for close(). */
    TTask<void> CWgDevice::wait() {
        std::shared_ptr<SImpl> keep = _impl;
        if (!keep || !keep->done.isValid()) {
            co_return;
        }

        while (!keep->stopped) {
            int32_t r = co_await CEventLoop::current()->waitFd(keep->done.get(), EFDE_READ);
            if (r < 0) {
                break;
            }
        }
    }

}
}
