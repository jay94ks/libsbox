#include <sbox/vpn/l2tp/server.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/net/sysctl.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include "ipsec/datapaths.hpp"
#include "ipsec/pool.hpp"
#include <cerrno>
#include <cstring>
#include <map>
#include <unistd.h>

namespace sbox {
namespace vpn {

    namespace {

        /**
         * One L2TP tunnel and where it came from.
         */
        struct TunnelRec {
            std::shared_ptr<CL2tpTunnel> tunnel;
            SL2tpPeer peer;
            uint16_t peerAssigned = 0;      // --> The LAC's tunnel ID (SCCRQ retransmissions).
        };

        /**
         * One PPP session.
         */
        struct SessionRec {
            std::shared_ptr<CPppSession> ppp;
            uint16_t tunnelId = 0;
            uint16_t sessionId = 0;
            net::SIpAddress address;
            std::string user;
            std::string remote;
            std::string identity;
            int64_t upMs = 0;
            int64_t lastTraffic = 0;
            uint64_t inPackets = 0;
            uint64_t outPackets = 0;
            uint64_t inBytes = 0;
            uint64_t outBytes = 0;
            bool dead = false;
        };

        /* Session key. */
        uint32_t sessionKey(uint16_t tunnelId, uint16_t sessionId) {
            return (uint32_t(tunnelId) << 16) | sessionId;
        }

    }

    struct CL2tpServer::SState : std::enable_shared_from_this<CL2tpServer::SState> {
        SL2tpServerConfig config;
        std::function<void(EIkeLogLevel, const std::string&)> sink;
        CEventLoop* loop = nullptr;
        bool running = false;
        bool stopping = false;

        CIkeSocket ownSocket;
        CIkeSocket* ikeSocket = nullptr;
        CIkeServer* shared = nullptr;
        std::shared_ptr<CIkev1Responder> ike;
        IL2tpTransportPtr transport;
        std::map<uint64_t, std::string> channelIdentity;

        CFd tun;
        std::string ifName;
        ipsec::AddressPool pool;

        std::map<uint16_t, TunnelRec> tunnels;
        std::map<uint32_t, SessionRec> sessions;
        std::map<uint32_t, uint32_t> byAddress;     // --> IPv4 (host order) -> session key.

        /* Logs. */
        void log(EIkeLogLevel level, const std::string& m) {
            if (sink) {
                sink(level, m);
            }
        }

        /* Allocates a tunnel ID. */
        uint16_t newTunnelId() {
            for (int32_t i = 0; i < 1024; ++i) {
                uint16_t id = 0;
                IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&id), sizeof(id)));
                if (id != 0 && !tunnels.count(id)) {
                    return id;
                }
            }

            return 0;
        }

        // -------------------------------------------------------------------------------
        // L2TP

        /* Dispatches one L2TP datagram from the transport. */
        void onL2tp(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) {
            if (stopping) {
                return;
            }

            SL2tpHeader h;
            if (ParseL2tpHeader(payload, h) != SBOX_OK) {
                return;
            }

            if (h.tunnelId != 0) {
                auto it = tunnels.find(h.tunnelId);
                if (it == tunnels.end()) {
                    return;
                }

                // --> A tunnel only accepts traffic from the SA pair (or address) it was set up on.
                if (it->second.peer.channel != peer.channel) {
                    return;
                }

                it->second.peer.remote = peer.remote;
                std::shared_ptr<CL2tpTunnel> t = it->second.tunnel;
                t->input(payload);
                return;
            }

            if (!h.control || h.payloadOffset >= h.packetSize) {
                return;
            }

            // --> New tunnel: SCCRQ. A retransmitted SCCRQ maps to the tunnel it created.
            std::vector<SL2tpAvp> avps;
            if (ParseL2tpAvps(SReadOnlyByteSpan(payload.data + h.payloadOffset, h.packetSize - h.payloadOffset), config.tunnel.secret, avps) !=
                    SBOX_OK ||
                avps.empty() || avps[0].u16() != EL2TP_SCCRQ) {
                return;
            }

            const SL2tpAvp* assigned = FindL2tpAvp(avps, EL2TP_AVP_ASSIGNED_TUNNEL_ID);
            if (!assigned || assigned->u16() == 0) {
                return;
            }

            for (auto& [id, rec] : tunnels) {
                if (rec.peer.channel == peer.channel && rec.peerAssigned == assigned->u16() &&
                    rec.peer.remote.toString() == peer.remote.toString()) {
                    (void)id;
                    std::shared_ptr<CL2tpTunnel> t = rec.tunnel;
                    t->input(payload);
                    return;
                }
            }

            if (tunnels.size() >= config.maxTunnels) {
                log(EIKE_LOG_WARNING, "l2tp: too many tunnels, SCCRQ from " + peer.remote.toString() + " dropped");
                return;
            }

            uint16_t id = newTunnelId();
            if (!id) {
                return;
            }

            TunnelRec rec;
            rec.peer = peer;
            rec.peerAssigned = assigned->u16();
            SL2tpTunnelConfig tc = config.tunnel;
            tc.maxSessions = std::max<uint32_t>(tc.maxSessions, 1);
            rec.tunnel = std::make_shared<CL2tpTunnel>(tc, true, id);
            wireTunnel(id, *rec.tunnel);
            tunnels[id] = rec;
            log(EIKE_LOG_INFO, "l2tp: tunnel " + std::to_string(id) + " from " + peer.remote.toString() +
                                   (channelIdentity.count(peer.channel) ? " (" + channelIdentity[peer.channel] + ")" : std::string()));
            std::shared_ptr<CL2tpTunnel> t = rec.tunnel;
            t->input(payload);
        }

        /* Connects a tunnel's callbacks. */
        void wireTunnel(uint16_t id, CL2tpTunnel& t) {
            std::weak_ptr<SState> weak = weak_from_this();
            t.sender([weak, id](const SReadOnlyByteSpan& p) {
                auto st = weak.lock();
                if (!st || !st->transport) {
                    return;
                }

                auto it = st->tunnels.find(id);
                if (it != st->tunnels.end()) {
                    st->transport->send(it->second.peer, p);
                }
            });
            t.logger([weak](const std::string& m) {
                if (auto st = weak.lock()) {
                    st->log(EIKE_LOG_DEBUG, m);
                }
            });
            t.onSessionUp([weak, id](uint16_t sid) {
                if (auto st = weak.lock()) {
                    st->sessionUp(id, sid);
                }
            });
            t.onSessionData([weak, id](uint16_t sid, const SReadOnlyByteSpan& frame) {
                auto st = weak.lock();
                if (!st) {
                    return;
                }

                auto it = st->sessions.find(sessionKey(id, sid));
                if (it != st->sessions.end() && !it->second.dead) {
                    std::shared_ptr<CPppSession> ppp = it->second.ppp;
                    ppp->input(frame);
                }
            });
            t.onSessionDown([weak, id](uint16_t sid, const std::string& reason) {
                if (auto st = weak.lock()) {
                    st->sessionGone(sessionKey(id, sid), reason, false);
                }
            });
            t.onClosed([weak, id](const std::string& reason) {
                if (auto st = weak.lock()) {
                    st->log(EIKE_LOG_INFO, "l2tp: tunnel " + std::to_string(id) + " closed: " + reason);
                }
            });
        }

        // -------------------------------------------------------------------------------
        // PPP

        /* A new L2TP session: start PPP. */
        void sessionUp(uint16_t tunnelId, uint16_t sid) {
            if (sessions.size() >= config.maxSessions) {
                auto t = tunnels.find(tunnelId);
                if (t != tunnels.end()) {
                    t->second.tunnel->closeSession(sid, EL2TP_RES_CDN_NO_RESOURCES, "too many sessions");
                }

                return;
            }

            SPppConfig pc;
            pc.server = true;
            pc.auth = config.auth;
            pc.users = config.users;
            pc.name = config.tunnel.hostName;
            pc.mru = config.mru;
            pc.localAddress = pool.gateway();
            pc.dns = config.dns;
            pc.nbns = config.nbns;
            pc.echoSeconds = config.echoSeconds;

            uint32_t key = sessionKey(tunnelId, sid);
            SessionRec rec;
            rec.ppp = std::make_shared<CPppSession>(pc);
            rec.tunnelId = tunnelId;
            rec.sessionId = sid;
            auto t = tunnels.find(tunnelId);
            if (t != tunnels.end()) {
                rec.remote = t->second.peer.remote.toString();
                auto ci = channelIdentity.find(t->second.peer.channel);
                rec.identity = ci != channelIdentity.end() ? ci->second : std::string();
            }

            std::weak_ptr<SState> weak = weak_from_this();
            CPppSession& ppp = *rec.ppp;
            ppp.sender([weak, tunnelId, sid](const SReadOnlyByteSpan& frame) {
                auto st = weak.lock();
                if (!st) {
                    return;
                }

                auto it = st->tunnels.find(tunnelId);
                if (it != st->tunnels.end()) {
                    std::shared_ptr<CL2tpTunnel> tt = it->second.tunnel;
                    tt->sendData(sid, frame);
                }
            });
            ppp.logger([weak, key](const std::string& m) {
                if (auto st = weak.lock()) {
                    st->log(EIKE_LOG_DEBUG, "session " + std::to_string(key >> 16) + "/" + std::to_string(key & 0xffff) + " " + m);
                }
            });
            ppp.allocator([weak, key](const std::string& user, const std::string& fixed, net::SIpAddress& out) {
                auto st = weak.lock();
                if (!st) {
                    return false;
                }

                net::SIpAddress want;
                if (!fixed.empty() && net::SIpAddress::parse(fixed, want) != SBOX_OK) {
                    return false;
                }

                // --> One address per user name: a reconnect gets its previous address back.
                if (!st->pool.allocate(user, key, want, net::SIpAddress(), out)) {
                    return false;
                }

                auto it = st->sessions.find(key);
                if (it != st->sessions.end()) {
                    it->second.address = out;
                    it->second.user = user;
                }

                return true;
            });
            ppp.onUp([weak, key](const SPppInfo& info) {
                auto st = weak.lock();
                if (!st) {
                    return;
                }

                auto it = st->sessions.find(key);
                if (it == st->sessions.end()) {
                    return;
                }

                // --> The same address may still be routed to a dead session of this user.
                auto old = st->byAddress.find(info.peerAddress.v4());
                if (old != st->byAddress.end() && old->second != key) {
                    st->closeSession(old->second, "replaced by a new session");
                }

                it->second.upMs = CEventLoop::nowMs();
                it->second.lastTraffic = it->second.upMs;
                st->byAddress[info.peerAddress.v4()] = key;
                st->log(EIKE_LOG_INFO, "ppp: '" + info.user + "' up as " + info.peerAddress.toString() + " (" + PppAuthName(info.auth) + ", " +
                                           it->second.remote + ")");
            });
            ppp.onIp([weak, key](const SReadOnlyByteSpan& packet) {
                auto st = weak.lock();
                if (!st) {
                    return;
                }

                auto it = st->sessions.find(key);
                if (it != st->sessions.end()) {
                    it->second.inPackets++;
                    it->second.inBytes += packet.size;
                    it->second.lastTraffic = CEventLoop::nowMs();
                }

                if (st->tun.isValid()) {
                    ssize_t n = ::write(st->tun.get(), packet.data, packet.size);
                    (void)n;
                }
            });
            ppp.onDown([weak, key](const std::string& reason) {
                if (auto st = weak.lock()) {
                    st->sessionGone(key, reason, true);
                }
            });

            sessions[key] = rec;
            std::shared_ptr<CPppSession> keep = rec.ppp;
            keep->start();
        }

        /* A session ended (from PPP or from L2TP). */
        void sessionGone(uint32_t key, const std::string& reason, bool fromPpp) {
            auto it = sessions.find(key);
            if (it == sessions.end() || it->second.dead) {
                return;
            }

            SessionRec& s = it->second;
            s.dead = true;
            log(EIKE_LOG_INFO, "ppp: session " + std::to_string(s.tunnelId) + "/" + std::to_string(s.sessionId) +
                                   (s.user.empty() ? std::string() : " ('" + s.user + "')") + " down: " + reason);
            if (s.address.isValid()) {
                auto b = byAddress.find(s.address.v4());
                if (b != byAddress.end() && b->second == key) {
                    byAddress.erase(b);
                }

                pool.release(s.address, key);
            }

            if (fromPpp) {
                auto t = tunnels.find(s.tunnelId);
                if (t != tunnels.end()) {
                    std::shared_ptr<CL2tpTunnel> tt = t->second.tunnel;
                    tt->closeSession(s.sessionId, EL2TP_RES_CDN_ADMIN, reason);
                    // --> Windows opens one call per tunnel: a tunnel without calls is closed.
                    if (tt->sessionCount() == 0) {
                        tt->close(EL2TP_RES_STOP_GENERAL, "no more sessions");
                    }
                }
            }
            else if (!s.ppp->isDown()) {
                // --> The L2TP session is gone: PPP cannot say goodbye any more.
                std::shared_ptr<CPppSession> ppp = s.ppp;
                ppp->sender(nullptr);
                ppp->close(reason);
            }
        }

        /* Closes a session (PPP terminate, then CDN). */
        void closeSession(uint32_t key, const std::string& reason) {
            auto it = sessions.find(key);
            if (it == sessions.end() || it->second.dead) {
                return;
            }

            std::shared_ptr<CPppSession> ppp = it->second.ppp;
            ppp->close(reason);
        }

        // -------------------------------------------------------------------------------
        // IKE

        /* Installs an SA pair negotiated by IKEv1. */
        TTask<void> installSa(SIkev1IpsecSa sa) {
            if (!transport) {
                co_return;
            }

            int32_t r = co_await transport->addSa(sa);
            IkeWipe(sa.inEncKey);
            IkeWipe(sa.outEncKey);
            IkeWipe(sa.inIntegKey);
            IkeWipe(sa.outIntegKey);
            if (r != SBOX_OK) {
                log(EIKE_LOG_ERROR, "ipsec: cannot install SA for " + sa.remote.toString() + ": " + std::strerror(-r));
                if (ike) {
                    ike->deleteIpsecSa(sa.inboundSpi);
                }

                co_return;
            }

            uint64_t channel = transport->channelOf(sa);
            if (channel) {
                channelIdentity[channel] = sa.identity;
            }
        }

        /* Removes an SA pair. */
        TTask<void> removeSa(SIkev1IpsecSa sa) {
            if (transport) {
                co_await transport->removeSa(sa);
            }
        }

        /* A channel lost its last SA: its tunnels are unreachable. */
        void channelDown(uint64_t channel) {
            channelIdentity.erase(channel);
            for (auto& [id, rec] : tunnels) {
                (void)id;
                if (rec.peer.channel == channel && rec.tunnel->state() != EL2TS_CLOSED) {
                    std::shared_ptr<CL2tpTunnel> t = rec.tunnel;
                    t->sender(nullptr);
                    t->close(EL2TP_RES_STOP_GENERAL, "IPsec SA gone");
                }
            }
        }

        // -------------------------------------------------------------------------------
        // Loops

        /* Periodic work. */
        void tick() {
            int64_t now = CEventLoop::nowMs();
            if (ike) {
                std::shared_ptr<CIkev1Responder> keep = ike;
                keep->tick(now);
            }

            std::vector<std::shared_ptr<CL2tpTunnel>> ts;
            for (auto& [id, rec] : tunnels) {
                (void)id;
                ts.push_back(rec.tunnel);
            }

            for (auto& t : ts) {
                t->tick(now);
            }

            std::vector<std::pair<uint32_t, std::shared_ptr<CPppSession>>> ps;
            for (auto& [key, s] : sessions) {
                ps.emplace_back(key, s.ppp);
            }

            for (auto& [key, p] : ps) {
                p->tick(now);
                auto it = sessions.find(key);
                if (it != sessions.end() && !it->second.dead && config.idleSeconds && it->second.upMs &&
                    now - it->second.lastTraffic > int64_t(config.idleSeconds) * 1000) {
                    closeSession(key, "idle timeout");
                }
            }

            // --> Drop finished sessions and tunnels.
            for (auto it = sessions.begin(); it != sessions.end();) {
                if (it->second.dead && it->second.ppp->isDown()) {
                    it = sessions.erase(it);
                }
                else {
                    ++it;
                }
            }

            for (auto it = tunnels.begin(); it != tunnels.end();) {
                if (it->second.tunnel->state() == EL2TS_CLOSED) {
                    uint16_t id = it->first;
                    for (auto& [key, s] : sessions) {
                        if (s.tunnelId == id && !s.dead) {
                            sessionGone(key, "tunnel closed", false);
                        }
                    }

                    it = tunnels.erase(it);
                }
                else {
                    ++it;
                }
            }
        }

        /* Ticker. */
        static TTask<void> ticker(std::shared_ptr<SState> st) {
            while (st->running) {
                co_await st->loop->sleepFor(200);
                if (st->running) {
                    st->tick();
                }
            }
        }

        /* Routes one packet from the TUN device to its session. */
        void fromTun(const SReadOnlyByteSpan& packet) {
            if (packet.size < 20 || (packet[0] >> 4) != 4) {
                return;
            }

            uint32_t dst = (uint32_t(packet[16]) << 24) | (uint32_t(packet[17]) << 16) | (uint32_t(packet[18]) << 8) | packet[19];
            auto b = byAddress.find(dst);
            if (b == byAddress.end()) {
                return;
            }

            auto it = sessions.find(b->second);
            if (it == sessions.end() || it->second.dead) {
                return;
            }

            if (it->second.ppp->sendIp(packet) == SBOX_OK) {
                it->second.outPackets++;
                it->second.outBytes += packet.size;
                it->second.lastTraffic = CEventLoop::nowMs();
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

                st->fromTun(SReadOnlyByteSpan(buffer.data(), size_t(n)));
            }
        }

        /* Closes descriptors. */
        void closeAll() {
            running = false;
            if (tun.isValid()) {
                if (loop) {
                    loop->cancelFd(tun.get());
                }

                tun.reset();
            }

            ownSocket.close();
        }
    };

    CL2tpServer::CL2tpServer(SL2tpServerConfig config) : _state(std::make_shared<SState>()) {
        _state->config = std::move(config);
    }

    CL2tpServer::~CL2tpServer() {
        _state->closeAll();
    }

    /* Log sink. */
    void CL2tpServer::logger(std::function<void(EIkeLogLevel, const std::string&)> sink) {
        _state->sink = std::move(sink);
    }

    /* Starts serving. */
    TTask<int32_t> CL2tpServer::start(CIkeServer* shared) {
        std::shared_ptr<SState> st = _state;
        SL2tpServerConfig& c = st->config;
        st->loop = CEventLoop::current();
        if (!st->loop || st->running) {
            co_return -EINVAL;
        }

        if (!c.pool.isValid() || !c.pool.address.isV4() || c.pool.length > 30) {
            co_return -EINVAL;
        }

        st->pool.reset(c.pool);
        bool ipsecOn = c.dataPath != EL2TK_PLAIN;

        // -- IKE sockets.
        if (ipsecOn) {
            if (shared) {
                st->shared = shared;
                st->ikeSocket = shared->socket();
            }
            else {
                SIkeSocketOptions o;
                o.address = c.listenAddress;
                o.port = c.ikePort;
                o.natPort = c.natPort;
                o.ipv6 = c.ipv6;
                o.netnsPath = c.netnsPath;
                int32_t r = st->ownSocket.open(o);
                if (r != SBOX_OK) {
                    st->log(EIKE_LOG_ERROR, "l2tp: cannot open IKE sockets: " + std::string(std::strerror(-r)));
                    co_return r;
                }

                st->ikeSocket = &st->ownSocket;
            }
        }

        // -- Transport.
        SL2tpTransportOptions to;
        to.kind = c.dataPath;
        to.netnsPath = c.netnsPath;
        to.address = c.listenAddress;
        to.port = c.l2tpPort;
        to.ipv6 = c.ipv6;
        to.ikeSocket = st->ikeSocket;
        if (shared && shared->dataPath()) {
            // --> Follow the IKEv2 responder: with its kernel path the NAT-T socket is already in
            // UDP_ENCAP mode (ESP never reaches user space), with its user path it is not.
            std::string kind = shared->dataPath()->kind();
            if (to.kind == EL2TK_AUTO) {
                to.kind = kind == "kernel" ? EL2TK_KERNEL : EL2TK_USER;
            }

            to.kernelEncap = false;
        }

        int32_t r = co_await CreateL2tpTransport(to, st->transport);
        if (r != SBOX_OK) {
            st->log(EIKE_LOG_ERROR, "l2tp: data path unavailable: " + std::string(std::strerror(-r)));
            st->closeAll();
            co_return r;
        }

        std::weak_ptr<SState> weak = st;
        st->transport->receiver([weak](const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) {
            if (auto s = weak.lock()) {
                s->onL2tp(peer, payload);
            }
        });
        st->transport->onChannelDown([weak](uint64_t channel) {
            if (auto s = weak.lock()) {
                s->channelDown(channel);
            }
        });
        r = co_await st->transport->start();
        if (r != SBOX_OK) {
            st->log(EIKE_LOG_ERROR, "l2tp: cannot start the " + std::string(st->transport->kind()) + " data path: " + std::strerror(-r));
            st->closeAll();
            co_return r;
        }

        // -- TUN device.
        net::STunTapOptions tunOptions;
        tunOptions.netnsPath = c.netnsPath;
        r = net::CreateTunTap(c.interfaceName, tunOptions, st->tun, &st->ifName);
        if (r != SBOX_OK) {
            st->log(EIKE_LOG_ERROR, "l2tp: cannot create TUN '" + c.interfaceName + "': " + std::strerror(-r));
            co_await st->transport->stop();
            st->closeAll();
            co_return r;
        }

        SIpsecDataPathOptions ifo;
        ifo.netnsPath = c.netnsPath;
        ifo.mtu = c.mtu;
        ifo.addresses.push_back(net::SIpPrefix(st->pool.gateway(), c.pool.length));
        ifo.routes = c.routes;
        r = co_await ipsec::ConfigureInterface(ifo, st->ifName);
        if (r != SBOX_OK) {
            st->log(EIKE_LOG_ERROR, "l2tp: cannot configure '" + st->ifName + "': " + std::strerror(-r));
            co_await st->transport->stop();
            st->closeAll();
            co_return r;
        }

        if (c.forwarding) {
            net::WriteSysctl("net.ipv4.ip_forward", "1", c.netnsPath);
        }

        if (!c.bridge.empty()) {
            net::WriteSysctl("net.ipv4.conf." + c.bridge + ".proxy_arp", "1", c.netnsPath);
        }

        // -- IKEv1.
        if (ipsecOn) {
            SIkev1Config ic = c.ike;
            ic.l2tpPort = c.l2tpPort ? c.l2tpPort : L2TP_PORT;
            st->ike = std::make_shared<CIkev1Responder>(ic);
            CIkeSocket* sock = st->ikeSocket;
            st->ike->sender([sock](const SReadOnlyByteSpan& m, const SEndpoint& local, const SEndpoint& remote, bool natT) {
                sock->send(m, local, remote, natT);
            });
            st->ike->logger([weak](EIkeLogLevel l, const std::string& m) {
                if (auto s = weak.lock()) {
                    s->log(l, m);
                }
            });
            st->ike->onSaUp([weak](const SIkev1IpsecSa& sa) {
                auto s = weak.lock();
                if (!s) {
                    return;
                }

                s->loop->spawn(s->installSa(sa));
            });
            st->ike->onSaDown([weak](const SIkev1IpsecSa& sa) {
                auto s = weak.lock();
                if (!s) {
                    return;
                }

                s->loop->spawn(s->removeSa(sa));
            });

            auto deliver = [weak](SIkeDatagram& dg) {
                auto s = weak.lock();
                if (!s || !s->ike || s->stopping) {
                    return;
                }

                std::shared_ptr<CIkev1Responder> keep = s->ike;
                keep->handle(dg);
            };

            if (shared) {
                shared->ikev1Handler(deliver);
            }
            else {
                st->ownSocket.start([deliver](SIkeDatagram& dg) {
                    // --> IKEv2 is not ours here.
                    if (dg.data.size() >= 18 && (dg.data[17] >> 4) == 1) {
                        deliver(dg);
                    }
                });
            }
        }

        st->running = true;
        st->loop->spawn(SState::ticker(st));
        st->loop->spawn(SState::tunReader(st));
        st->log(EIKE_LOG_INFO, std::string("l2tp: serving on ") + (c.listenAddress.empty() ? "*" : c.listenAddress) + ", data path " +
                                   st->transport->kind() + ", interface " + st->ifName + " " + st->pool.gateway().toString() + "/" +
                                   std::to_string(c.pool.length));

        co_return SBOX_OK;
    }

    /* Stops. */
    TTask<void> CL2tpServer::stop() {
        std::shared_ptr<SState> st = _state;
        if (!st->running) {
            co_return;
        }

        st->stopping = true;
        std::vector<uint32_t> keys;
        for (auto& [key, s] : st->sessions) {
            if (!s.dead) {
                keys.push_back(key);
            }
        }

        for (uint32_t key : keys) {
            st->closeSession(key, "server shutting down");
        }

        // --> Give PPP/L2TP a moment to say goodbye over the still-installed SAs.
        for (int32_t i = 0; i < 5; ++i) {
            co_await st->loop->sleepFor(100);
            st->tick();
        }

        for (auto& [id, rec] : st->tunnels) {
            (void)id;
            std::shared_ptr<CL2tpTunnel> t = rec.tunnel;
            t->close(EL2TP_RES_STOP_SHUTDOWN, "server shutting down");
        }

        co_await st->loop->sleepFor(100);
        if (st->ike) {
            std::shared_ptr<CIkev1Responder> ike = st->ike;
            ike->onSaDown(nullptr);
            ike->shutdown();
        }

        if (st->shared) {
            st->shared->ikev1Handler(nullptr);
        }

        if (st->transport) {
            co_await st->transport->stop();
        }

        st->closeAll();
        st->tunnels.clear();
        st->sessions.clear();
        st->byAddress.clear();
        st->stopping = false;
    }

    /* Sessions. */
    std::vector<SL2tpSessionInfo> CL2tpServer::sessions() const {
        std::vector<SL2tpSessionInfo> out;
        for (const auto& [key, s] : _state->sessions) {
            (void)key;
            if (s.dead) {
                continue;
            }

            SL2tpSessionInfo i;
            i.user = s.user;
            i.address = s.address.isValid() ? s.address.toString() : std::string();
            i.remote = s.remote;
            i.identity = s.identity;
            i.auth = PppAuthName(s.ppp->info().auth);
            i.tunnelId = s.tunnelId;
            i.sessionId = s.sessionId;
            i.upMs = s.upMs;
            i.inPackets = s.inPackets;
            i.outPackets = s.outPackets;
            i.inBytes = s.inBytes;
            i.outBytes = s.outBytes;
            out.push_back(i);
        }

        return out;
    }

    /* ISAKMP SAs. */
    std::vector<SIkev1SessionInfo> CL2tpServer::ikeSessions() const {
        return _state->ike ? _state->ike->sessions() : std::vector<SIkev1SessionInfo>();
    }

    /* Disconnect by user or address. */
    int32_t CL2tpServer::disconnect(const std::string& userOrAddress) {
        std::vector<uint32_t> keys;
        for (const auto& [key, s] : _state->sessions) {
            if (!s.dead && (s.user == userOrAddress || (s.address.isValid() && s.address.toString() == userOrAddress))) {
                keys.push_back(key);
            }
        }

        for (uint32_t key : keys) {
            _state->closeSession(key, "disconnected by administrator");
        }

        return int32_t(keys.size());
    }

    /* TUN name. */
    std::string CL2tpServer::interfaceName() const {
        return _state->ifName;
    }

    /* Transport kind. */
    std::string CL2tpServer::dataPath() const {
        return _state->transport ? _state->transport->kind() : std::string();
    }

    /* IKE port. */
    uint16_t CL2tpServer::ikePort() const noexcept {
        return _state->shared ? 0 : _state->ownSocket.port();
    }

    /* NAT-T port. */
    uint16_t CL2tpServer::natPort() const noexcept {
        return _state->shared ? 0 : _state->ownSocket.natPort();
    }

    /* L2TP port. */
    uint16_t CL2tpServer::l2tpPort() const noexcept {
        return _state->transport ? _state->transport->port() : 0;
    }

}
}
