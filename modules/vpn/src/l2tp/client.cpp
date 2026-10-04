#include <sbox/vpn/l2tp/client.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/l2tp/l2tp.hpp>
#include <sbox/vpn/l2tp/transport.hpp>
#include "ipsec/datapaths.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace vpn {

    struct CL2tpClient::SState {
        SL2tpClientConfig config;
        std::function<void(EIkeLogLevel, const std::string&)> sink;
        std::function<void(const SReadOnlyByteSpan&)> ipHandler;
        CEventLoop* loop = nullptr;
        bool running = false;
        int32_t failure = 0;
        std::string error;

        net::SIpAddress local;
        net::SIpAddress serverAddress;
        CIkeSocket ikeSocket;
        std::shared_ptr<CIkev1Initiator> ike;
        IL2tpTransportPtr transport;
        SL2tpPeer peer;
        bool saUp = false;
        std::shared_ptr<CL2tpTunnel> tunnel;
        uint16_t session = 0;
        std::shared_ptr<CPppSession> ppp;
        bool up = false;
        SPppInfo info;
        CFd tun;
        std::string ifName;

        /* Logs. */
        void log(EIkeLogLevel level, const std::string& m) {
            if (sink) {
                sink(level, "client: " + m);
            }
        }

        /* Records the first failure. */
        void fail(int32_t code, const std::string& why) {
            if (failure == 0) {
                failure = code;
                error = why;
                log(EIKE_LOG_WARNING, why);
            }
        }

        /* Starts L2TP once the SA (or plain UDP) is ready. */
        void startL2tp() {
            if (tunnel) {
                return;
            }

            SL2tpTunnelConfig tc;
            tc.hostName = config.hostName;
            uint16_t id = 0;
            while (id == 0) {
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&id), sizeof(id)));
            }

            tunnel = std::make_shared<CL2tpTunnel>(tc, false, id);
            CL2tpTunnel& t = *tunnel;
            t.sender([this](const SReadOnlyByteSpan& p) {
                if (transport) {
                    transport->send(peer, p);
                }
            });
            t.logger([this](const std::string& m) { log(EIKE_LOG_DEBUG, m); });
            t.onEstablished([this]() {
                session = tunnel->openSession();
            });
            t.onSessionUp([this](uint16_t sid) {
                session = sid;
                startPpp();
            });
            t.onSessionData([this](uint16_t, const SReadOnlyByteSpan& frame) {
                if (ppp) {
                    std::shared_ptr<CPppSession> keep = ppp;
                    keep->input(frame);
                }
            });
            t.onSessionDown([this](uint16_t, const std::string& reason) {
                fail(-ECONNRESET, "L2TP session closed: " + reason);
                up = false;
            });
            t.onClosed([this](const std::string& reason) {
                fail(-ECONNRESET, "L2TP tunnel closed: " + reason);
                up = false;
            });
            t.start();
        }

        /* Starts PPP on the session. */
        void startPpp() {
            SPppConfig pc;
            pc.server = false;
            pc.auth = config.auth;
            pc.user = config.user;
            pc.password = config.password;
            pc.mru = uint16_t(config.mtu);
            ppp = std::make_shared<CPppSession>(pc);
            ppp->sender([this](const SReadOnlyByteSpan& f) {
                if (tunnel) {
                    tunnel->sendData(session, f);
                }
            });
            ppp->logger([this](const std::string& m) { log(EIKE_LOG_DEBUG, m); });
            ppp->onUp([this](const SPppInfo& i) {
                info = i;
                up = true;
                log(EIKE_LOG_INFO, "link up: " + i.localAddress.toString() + " <-> " + i.peerAddress.toString());
            });
            ppp->onDown([this](const std::string& reason) {
                int32_t code = reason.find("auth") != std::string::npos ? -EACCES : -ECONNRESET;
                fail(code, "PPP down: " + reason);
                up = false;
            });
            ppp->onIp([this](const SReadOnlyByteSpan& p) {
                if (tun.isValid()) {
                    ssize_t n = ::write(tun.get(), p.data, p.size);
                    (void)n;
                }
                else if (ipHandler) {
                    ipHandler(p);
                }
            });
            ppp->start();
        }

        /* Timers. */
        static TTask<void> ticker(std::shared_ptr<SState> st) {
            while (st->running) {
                co_await st->loop->sleepFor(100);
                if (!st->running) {
                    break;
                }

                int64_t now = CEventLoop::nowMs();
                if (st->ike) {
                    std::shared_ptr<CIkev1Initiator> keep = st->ike;
                    keep->tick(now);
                }

                if (st->tunnel) {
                    std::shared_ptr<CL2tpTunnel> keep = st->tunnel;
                    keep->tick(now);
                }

                if (st->ppp) {
                    std::shared_ptr<CPppSession> keep = st->ppp;
                    keep->tick(now);
                }
            }
        }

        /* TUN reader. */
        static TTask<void> tunReader(std::shared_ptr<SState> st) {
            std::vector<uint8_t> buffer(65536);
            while (st->running && st->tun.isValid()) {
                int fd = st->tun.get();
                ssize_t n = ::read(fd, buffer.data(), buffer.size());
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        int32_t r = co_await st->loop->waitFd(fd, EFDE_READ);
                        if (r < 0 && (!st->running || r == -ECANCELED)) {
                            break;
                        }

                        continue;
                    }

                    if (errno == EINTR) {
                        continue;
                    }

                    break;
                }

                if (st->ppp && st->up) {
                    st->ppp->sendIp(SReadOnlyByteSpan(buffer.data(), size_t(n)));
                }
            }
        }

        /* Finds our address towards the server. */
        int32_t localAddress() {
            net::CNetnsScope scope(config.netnsPath);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            SEndpoint to;
            int32_t r = SEndpoint::fromIp(config.server, config.ikePort ? config.ikePort : 500, to);
            if (r != SBOX_OK) {
                return r;
            }

            CFd fd(::socket(to.family(), SOCK_DGRAM | SOCK_CLOEXEC, 0));
            if (!fd.isValid()) {
                return -errno;
            }

            if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&to.storage), to.length) < 0) {
                return -errno;
            }

            sockaddr_storage me;
            socklen_t len = sizeof(me);
            if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&me), &len) < 0) {
                return -errno;
            }

            if (me.ss_family == AF_INET) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<sockaddr_in*>(&me)->sin_addr), 4, local);
            }
            else {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&reinterpret_cast<sockaddr_in6*>(&me)->sin6_addr), 16, local);
            }

            return net::SIpAddress::parse(config.server, serverAddress);
        }

        /* Creates and configures the TUN device. */
        TTask<int32_t> createTun() {
            net::STunTapOptions o;
            o.netnsPath = config.netnsPath;
            int32_t r = net::CreateTunTap(config.interfaceName, o, tun, &ifName);
            if (r != SBOX_OK) {
                co_return r;
            }

            SIpsecDataPathOptions ifo;
            ifo.netnsPath = config.netnsPath;
            ifo.mtu = config.mtu;
            ifo.addresses.push_back(net::SIpPrefix(info.localAddress, 32));
            ifo.routes.push_back(net::SIpPrefix(info.peerAddress, 32));
            for (const net::SIpPrefix& p : config.routes) {
                ifo.routes.push_back(p);
            }

            co_return co_await ipsec::ConfigureInterface(ifo, ifName);
        }

        /* Releases everything. */
        void closeAll() {
            running = false;
            if (tun.isValid()) {
                if (loop) {
                    loop->cancelFd(tun.get());
                }

                tun.reset();
            }

            ikeSocket.close();
        }
    };

    CL2tpClient::CL2tpClient(SL2tpClientConfig config) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
    }

    CL2tpClient::~CL2tpClient() {
        _state->closeAll();
    }

    /* Log sink. */
    void CL2tpClient::logger(std::function<void(EIkeLogLevel, const std::string&)> sink) {
        _state->sink = std::move(sink);
    }

    /* Connects. */
    TTask<int32_t> CL2tpClient::connect() {
        std::shared_ptr<SState> st = _state;
        SL2tpClientConfig& c = st->config;
        st->loop = CEventLoop::current();
        st->failure = 0;
        st->error.clear();
        int32_t r = st->localAddress();
        if (r != SBOX_OK) {
            st->error = "cannot reach " + c.server;
            co_return r;
        }

        SL2tpTransportOptions to;
        to.kind = c.ipsec ? EL2TK_USER : EL2TK_PLAIN;
        to.netnsPath = c.netnsPath;
        to.port = c.ipsec ? L2TP_PORT : 0;
        to.address = st->local.toString();

        if (c.ipsec) {
            SIkeSocketOptions o;
            o.address = st->local.toString();
            o.port = c.localIkePort;
            o.natPort = c.localNatPort;
            o.netnsPath = c.netnsPath;
            r = st->ikeSocket.open(o);
            if (r != SBOX_OK) {
                st->error = "cannot open IKE sockets";
                co_return r;
            }

            to.ikeSocket = &st->ikeSocket;
        }

        r = co_await CreateL2tpTransport(to, st->transport);
        if (r == SBOX_OK) {
            r = co_await st->transport->start();
        }

        if (r != SBOX_OK) {
            st->error = "cannot start the transport";
            st->closeAll();
            co_return r;
        }

        SState* raw = st.get();
        st->transport->receiver([raw](const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) {
            if (raw->tunnel && (raw->peer.channel == 0 || peer.channel == raw->peer.channel)) {
                std::shared_ptr<CL2tpTunnel> keep = raw->tunnel;
                keep->input(payload);
            }
        });
        st->transport->onChannelDown([raw](uint64_t) {
            raw->fail(-ECONNRESET, "IPsec SA deleted");
            raw->up = false;
        });

        st->running = true;
        st->loop->spawn(SState::ticker(st));
        SEndpoint l2tpServer;
        SEndpoint::fromIp(c.server, c.l2tpPort, l2tpServer);
        st->peer.remote = l2tpServer;

        if (c.ipsec) {
            SEndpoint server;
            SEndpoint::fromIp(c.server, c.ikePort, server);
            SIkev1Config ic = c.ike;
            ic.l2tpPort = c.l2tpPort;
            st->ike = std::make_shared<CIkev1Initiator>(ic, server, c.natPort);
            st->ike->sender([raw](const SReadOnlyByteSpan& m, const SEndpoint& local, const SEndpoint& remote, bool natT) {
                raw->ikeSocket.send(m, local, remote, natT);
            });
            st->ike->logger([raw](EIkeLogLevel l, const std::string& m) { raw->log(l, m); });
            st->ike->onFailed([raw](int32_t code, const std::string& why) { raw->fail(code, "IKE: " + why); });
            st->ike->onSaUp([raw](const SIkev1IpsecSa& sa) {
                raw->loop->spawn([](SState* self, SIkev1IpsecSa a) -> TTask<void> {
                    int32_t rr = co_await self->transport->addSa(a);
                    if (rr != SBOX_OK) {
                        self->fail(rr, "cannot install the SA");
                        co_return;
                    }

                    self->peer.channel = self->transport->channelOf(a);
                    self->saUp = true;
                    self->startL2tp();
                }(raw, sa));
            });
            st->ike->onSaDown([raw](const SIkev1IpsecSa& sa) {
                raw->loop->spawn([](SState* self, SIkev1IpsecSa a) -> TTask<void> {
                    if (self->transport) {
                        co_await self->transport->removeSa(a);
                    }
                }(raw, sa));
            });
            std::shared_ptr<CIkev1Initiator> ike = st->ike;
            st->ikeSocket.start([raw](SIkeDatagram& dg) {
                if (raw->ike) {
                    std::shared_ptr<CIkev1Initiator> keep = raw->ike;
                    keep->handle(dg);
                }
            });
            ike->start(st->local, st->ikeSocket.port(), st->ikeSocket.natPort());
        }
        else {
            st->startL2tp();
        }

        int64_t deadline = CEventLoop::nowMs() + c.timeoutMs;
        while (!st->up && st->failure == 0 && CEventLoop::nowMs() < deadline) {
            co_await st->loop->sleepFor(20);
        }

        if (!st->up) {
            int32_t code = st->failure ? st->failure : -ETIMEDOUT;
            if (st->error.empty()) {
                st->error = "timed out";
            }

            co_await disconnect();
            co_return code;
        }

        if (c.createInterface) {
            r = co_await st->createTun();
            if (r != SBOX_OK) {
                st->error = "cannot create the TUN device";
                co_await disconnect();
                co_return r;
            }

            st->loop->spawn(SState::tunReader(st));
        }

        co_return SBOX_OK;
    }

    /* Disconnects. */
    TTask<void> CL2tpClient::disconnect() {
        std::shared_ptr<SState> st = _state;
        if (st->ppp && !st->ppp->isDown()) {
            st->ppp->close("user disconnect");
            for (int32_t i = 0; i < 10 && !st->ppp->isDown(); ++i) {
                co_await st->loop->sleepFor(50);
            }
        }

        if (st->tunnel && st->tunnel->state() == EL2TS_ESTABLISHED) {
            if (st->session) {
                st->tunnel->closeSession(st->session, EL2TP_RES_CDN_ADMIN, "user disconnect");
            }

            st->tunnel->close(EL2TP_RES_STOP_GENERAL, "user disconnect");
            co_await st->loop->sleepFor(100);
        }

        if (st->ike) {
            std::shared_ptr<CIkev1Initiator> ike = st->ike;
            ike->onSaDown(nullptr);
            ike->shutdown();
        }

        if (st->transport) {
            co_await st->transport->stop();
        }

        st->up = false;
        st->closeAll();
        // --> Callbacks capture the state; drop the objects that hold them.
        st->ppp.reset();
        st->tunnel.reset();
        st->ike.reset();
        st->transport.reset();
    }

    /* Up state. */
    bool CL2tpClient::isUp() const noexcept {
        return _state->up;
    }

    /* PPP parameters. */
    SPppInfo CL2tpClient::info() const {
        return _state->info;
    }

    /* TUN name. */
    std::string CL2tpClient::interfaceName() const {
        return _state->ifName;
    }

    /* Last failure. */
    std::string CL2tpClient::lastError() const {
        return _state->error;
    }

    /* NAT-T. */
    bool CL2tpClient::natT() const noexcept {
        return _state->ike && _state->ike->natT();
    }

    /* IP output. */
    int32_t CL2tpClient::sendIp(const SReadOnlyByteSpan& packet) {
        if (!_state->ppp || !_state->up) {
            return -ENOTCONN;
        }

        return _state->ppp->sendIp(packet);
    }

    /* IP input handler. */
    void CL2tpClient::onIp(std::function<void(const SReadOnlyByteSpan&)> handler) {
        _state->ipHandler = std::move(handler);
    }

}
}
