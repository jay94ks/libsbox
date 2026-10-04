#include <sbox/vpn/ipsec/datapath.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/net/rtnl.hpp>
#include "datapaths.hpp"
#include "crypto.hpp"
#include <cerrno>
#include <map>
#include <set>
#include <unistd.h>

namespace sbox {
namespace vpn {

    namespace ipsec {

        /* Configures the data path interface. */
        TTask<int32_t> ConfigureInterface(const SIpsecDataPathOptions& options, std::string name) {
            net::CRtnl rtnl;
            int32_t r = rtnl.open(options.netnsPath);
            if (r != SBOX_OK) {
                co_return r;
            }

            int32_t index = co_await rtnl.linkIndex(name);
            if (index < 0) {
                co_return index;
            }

            if (options.mtu) {
                r = co_await rtnl.setMtu(index, options.mtu);
                if (r != SBOX_OK) {
                    co_return r;
                }
            }

            for (const net::SIpPrefix& addr : options.addresses) {
                r = co_await rtnl.addAddress(index, addr, true);
                if (r != SBOX_OK && r != -EEXIST) {
                    co_return r;
                }
            }

            r = co_await rtnl.setUp(index, true);
            if (r != SBOX_OK) {
                co_return r;
            }

            for (const net::SIpPrefix& prefix : options.routes) {
                net::SRouteInfo route;
                route.destination = prefix.network();
                route.oif = index;
                r = co_await rtnl.addRoute(route, true);
                if (r != SBOX_OK && r != -EEXIST) {
                    co_return r;
                }
            }

            co_return SBOX_OK;
        }

        /* Selector match of a raw IP packet. */
        bool PacketMatches(const SReadOnlyByteSpan& ip, const std::vector<SIkeTrafficSelector>& srcTs,
                           const std::vector<SIkeTrafficSelector>& dstTs) {
            if (ip.size < 20) {
                return false;
            }

            net::SIpAddress src;
            net::SIpAddress dst;
            uint8_t proto = 0;
            size_t l4 = 0;
            uint8_t version = ip[0] >> 4;

            if (version == 4) {
                size_t ihl = size_t(ip[0] & 0x0f) * 4;
                if (ihl < 20 || ip.size < ihl) {
                    return false;
                }

                net::SIpAddress::fromBytes(ip.data + 12, 4, src);
                net::SIpAddress::fromBytes(ip.data + 16, 4, dst);
                proto = ip[9];
                // --> Ports are only visible in the first fragment.
                bool firstFragment = (GetBe16(ip.data + 6) & 0x1fff) == 0;
                l4 = firstFragment ? ihl : 0;
            }
            else if (version == 6) {
                if (ip.size < 40) {
                    return false;
                }

                net::SIpAddress::fromBytes(ip.data + 8, 16, src);
                net::SIpAddress::fromBytes(ip.data + 24, 16, dst);
                proto = ip[6];
                l4 = 40;
            }
            else {
                return false;
            }

            bool hasPorts = l4 && (proto == 6 || proto == 17 || proto == 132) && ip.size >= l4 + 4;
            uint16_t sport = hasPorts ? GetBe16(ip.data + l4) : 0;
            uint16_t dport = hasPorts ? GetBe16(ip.data + l4 + 2) : 0;

            auto fits = [&](const std::vector<SIkeTrafficSelector>& list, const net::SIpAddress& addr, uint16_t port) {
                for (const SIkeTrafficSelector& ts : list) {
                    if (!ts.containsAddress(addr)) {
                        continue;
                    }

                    if (ts.protocol != 0 && ts.protocol != proto) {
                        continue;
                    }

                    bool allPorts = ts.startPort == 0 && ts.endPort == 65535;
                    if (!allPorts && (!hasPorts || port < ts.startPort || port > ts.endPort)) {
                        continue;
                    }

                    return true;
                }

                return false;
            };

            return fits(srcTs, src, sport) && fits(dstTs, dst, dport);
        }

        namespace {

            /* Ports of a selector as value/mask (ranges other than one port or all widen to all). */
            void portOf(const SIkeTrafficSelector& ts, uint16_t& port, uint16_t& mask) {
                if (ts.startPort == ts.endPort) {
                    port = ts.startPort;
                    mask = 0xffff;
                }
                else {
                    port = 0;
                    mask = 0;
                }
            }

            /**
             * XFRM data path.
             */
            class KernelDataPath : public IIpsecDataPath, public std::enable_shared_from_this<KernelDataPath> {
            private:
                SIpsecDataPathOptions _options;
                SXfrmSupport _support;
                CXfrm _xfrm;
                CIkeSocket* _socket = nullptr;
                uint32_t _ifId = 0;
                std::string _ifName;
                std::map<uint32_t, std::vector<SXfrmPolicy>> _policies;    // --> By reqid.

            public:
                KernelDataPath(const SIpsecDataPathOptions& options, const SXfrmSupport& support)
                    : _options(options), _support(support) {}

                const char* kind() const noexcept override {
                    return "kernel";
                }

                void attachSocket(CIkeSocket* socket) override {
                    _socket = socket;
                }

                bool supports(uint16_t encr, uint16_t keyBits, uint16_t integ) const noexcept override {
                    (void)keyBits;
                    switch (encr) {
                    case EIKE_ENCR_AES_CBC:
                        return integ != EIKE_INTEG_NONE;
                    case EIKE_ENCR_3DES:
                        return _support.des3 && integ != EIKE_INTEG_NONE;
                    case EIKE_ENCR_AES_GCM_12:
                    case EIKE_ENCR_AES_GCM_16:
                        return _support.gcm && integ == EIKE_INTEG_NONE;
                    case EIKE_ENCR_CHACHA20_POLY1305:
                        return _support.chacha && integ == EIKE_INTEG_NONE;
                    default:
                        return false;
                    }
                }

                std::string interfaceName() const override {
                    return _ifName;
                }

                SXfrmOwner owner() const {
                    SXfrmOwner o;
                    o.reqidMin = _options.reqidBase;
                    o.reqidMax = _options.reqidBase + 0x00ffffffu;
                    o.ifId = _ifId;
                    return o;
                }

                TTask<int32_t> start() override {
                    int32_t r = _xfrm.open(_options.netnsPath);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    if (_socket) {
                        r = _socket->enableKernelEncap();
                        if (r != SBOX_OK) {
                            co_return r;
                        }
                    }

                    if (_support.interfaces) {
                        _ifId = _options.ifId ? _options.ifId : (_options.reqidBase >> 8) | 1u;
                    }

                    if (_options.flushStale) {
                        co_await _xfrm.flushOwned(owner());
                    }

                    if (_support.interfaces && !_options.interfaceName.empty()) {
                        net::CRtnl rtnl;
                        if (rtnl.open(_options.netnsPath) == SBOX_OK) {
                            int32_t old = co_await rtnl.linkIndex(_options.interfaceName);
                            if (old > 0) {
                                co_await rtnl.deleteLink(old);
                            }
                        }

                        r = co_await _xfrm.createInterface(_options.interfaceName, _ifId);
                        if (r != SBOX_OK) {
                            co_return r;
                        }

                        _ifName = _options.interfaceName;
                        r = co_await ConfigureInterface(_options, _ifName);
                        if (r != SBOX_OK) {
                            co_return r;
                        }
                    }
                    else {
                        // --> Policy-based mode: decrypted traffic appears on the physical
                        // interface; an xfrm interface id only makes sense with interfaces.
                        _ifId = 0;
                    }

                    co_return SBOX_OK;
                }

                TTask<void> stop() override {
                    if (_xfrm.isValid()) {
                        co_await _xfrm.flushOwned(owner());
                    }

                    _policies.clear();
                    if (!_ifName.empty()) {
                        net::CRtnl rtnl;
                        if (rtnl.open(_options.netnsPath) == SBOX_OK) {
                            int32_t index = co_await rtnl.linkIndex(_ifName);
                            if (index > 0) {
                                co_await rtnl.deleteLink(index);
                            }
                        }

                        _ifName.clear();
                    }
                }

                TTask<int32_t> allocateSpi(net::SIpAddress local, net::SIpAddress remote, uint32_t reqid, uint32_t& spi) override {
                    co_return co_await _xfrm.allocSpi(remote, local, 50, reqid, SXfrmMark(), spi);
                }

                /* Builds the XFRM SA of one direction. */
                SXfrmSa makeSa(const SIpsecChildSa& c, bool inbound) const {
                    SXfrmSa sa;
                    sa.src = inbound ? c.remote : c.local;
                    sa.dst = inbound ? c.local : c.remote;
                    sa.spi = inbound ? c.inboundSpi : c.outboundSpi;
                    sa.mode = c.mode;
                    sa.reqid = c.reqid;
                    sa.esn = c.esn;
                    sa.replayWindow = inbound ? c.replayWindow : 0;
                    sa.lifetime = c.lifetime;
                    sa.ifId = _ifId;

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
                        sa.encapSport = inbound ? c.remotePort : c.localPort;
                        sa.encapDport = inbound ? c.localPort : c.remotePort;
                    }

                    if (c.mode == EXMODE_TUNNEL && !_ifId) {
                        // --> Policy-based tunnels need no SA selector; leave it "any".
                    }

                    return sa;
                }

                /* Builds the policies of a child. */
                std::vector<SXfrmPolicy> makePolicies(const SIpsecChildSa& c) const {
                    std::vector<SXfrmPolicy> out;
                    for (const SIkeTrafficSelector& l : c.localTs) {
                        for (const SIkeTrafficSelector& r : c.remoteTs) {
                            if (l.type != r.type) {
                                continue;
                            }

                            for (const net::SIpPrefix& lp : l.toPrefixes()) {
                                for (const net::SIpPrefix& rp : r.toPrefixes()) {
                                    uint8_t proto = l.protocol ? l.protocol : r.protocol;
                                    uint16_t lport, lmask, rport, rmask;
                                    portOf(l, lport, lmask);
                                    portOf(r, rport, rmask);

                                    for (EXfrmDir dir : { EXDIR_OUT, EXDIR_IN, EXDIR_FWD }) {
                                        if (dir == EXDIR_FWD && c.mode == EXMODE_TRANSPORT) {
                                            continue;
                                        }

                                        bool out_ = dir == EXDIR_OUT;
                                        SXfrmPolicy p;
                                        p.dir = dir;
                                        p.selector.src = out_ ? lp : rp;
                                        p.selector.dst = out_ ? rp : lp;
                                        p.selector.protocol = proto;
                                        p.selector.srcPort = out_ ? lport : rport;
                                        p.selector.srcPortMask = out_ ? lmask : rmask;
                                        p.selector.dstPort = out_ ? rport : lport;
                                        p.selector.dstPortMask = out_ ? rmask : lmask;
                                        p.family = lp.address.isV6() ? 6 : 4;
                                        p.priority = 0x3000u - uint32_t(lp.length) - uint32_t(rp.length);
                                        p.ifId = _ifId;

                                        SXfrmTemplate t;
                                        t.src = out_ ? c.local : c.remote;
                                        t.dst = out_ ? c.remote : c.local;
                                        t.mode = c.mode;
                                        t.reqid = c.reqid;
                                        p.templates.push_back(t);
                                        out.push_back(std::move(p));
                                    }
                                }
                            }
                        }
                    }

                    return out;
                }

                TTask<int32_t> installChild(SIpsecChildSa child) override {
                    int32_t r = co_await _xfrm.addSa(makeSa(child, true), true);
                    if (r == -ESRCH || r == -ENOENT) {
                        // --> No larval SA (the SPI did not come from allocateSpi()).
                        r = co_await _xfrm.addSa(makeSa(child, true), false);
                    }

                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    r = co_await _xfrm.addSa(makeSa(child, false), false);
                    if (r != SBOX_OK) {
                        co_await _xfrm.deleteSa(child.remote, child.local, child.inboundSpi);
                        co_return r;
                    }

                    if (_policies.count(child.reqid)) {
                        co_return SBOX_OK;
                    }

                    std::vector<SXfrmPolicy> policies = makePolicies(child);
                    for (const SXfrmPolicy& p : policies) {
                        r = co_await _xfrm.addPolicy(p, true);
                        if (r != SBOX_OK) {
                            for (const SXfrmPolicy& q : policies) {
                                co_await _xfrm.deletePolicy(q.selector, q.dir, q.mark, q.ifId, q.family);
                            }

                            co_await _xfrm.deleteSa(child.remote, child.local, child.inboundSpi);
                            co_await _xfrm.deleteSa(child.local, child.remote, child.outboundSpi);
                            co_return r;
                        }
                    }

                    _policies[child.reqid] = std::move(policies);
                    co_return SBOX_OK;
                }

                TTask<int32_t> removeChild(SIpsecChildSa child, bool policies) override {
                    int32_t r1 = co_await _xfrm.deleteSa(child.remote, child.local, child.inboundSpi);
                    int32_t r2 = co_await _xfrm.deleteSa(child.local, child.remote, child.outboundSpi);

                    if (policies) {
                        auto it = _policies.find(child.reqid);
                        if (it != _policies.end()) {
                            for (const SXfrmPolicy& p : it->second) {
                                co_await _xfrm.deletePolicy(p.selector, p.dir, p.mark, p.ifId, p.family);
                            }

                            _policies.erase(it);
                        }
                    }

                    co_return r1 != SBOX_OK && r1 != -ESRCH ? r1 : (r2 != SBOX_OK && r2 != -ESRCH ? r2 : SBOX_OK);
                }

                TTask<int32_t> updateChild(SIpsecChildSa child) override {
                    // --> SAs are keyed by destination address, so moving means replacing them.
                    std::vector<SXfrmSa> sas;
                    co_await _xfrm.listSas(sas);
                    for (const SXfrmSa& sa : sas) {
                        if (sa.reqid == child.reqid && (sa.spi == child.inboundSpi || sa.spi == child.outboundSpi)) {
                            co_await _xfrm.deleteSa(sa.src, sa.dst, sa.spi, sa.protocol, sa.mark);
                        }
                    }

                    int32_t r = co_await _xfrm.addSa(makeSa(child, true), false);
                    if (r == SBOX_OK) {
                        r = co_await _xfrm.addSa(makeSa(child, false), false);
                    }

                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    std::vector<SXfrmPolicy> policies = makePolicies(child);
                    for (const SXfrmPolicy& p : policies) {
                        co_await _xfrm.addPolicy(p, true);
                    }

                    _policies[child.reqid] = std::move(policies);
                    co_return SBOX_OK;
                }

                TTask<int32_t> stats(SIpsecChildSa child, SIpsecChildStats& out) override {
                    SXfrmSa in;
                    SXfrmSa outSa;
                    int32_t r = co_await _xfrm.getSa(child.local, child.inboundSpi, 50, in);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    r = co_await _xfrm.getSa(child.remote, child.outboundSpi, 50, outSa);
                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    out.inBytes = in.bytes;
                    out.inPackets = in.packets;
                    out.outBytes = outSa.bytes;
                    out.outPackets = outSa.packets;
                    out.lastInbound = 0;
                    co_return SBOX_OK;
                }
            };

        }

        /* Creates the kernel data path. */
        IIpsecDataPathPtr MakeKernelDataPath(const SIpsecDataPathOptions& options, const SXfrmSupport& support) {
            return std::make_shared<KernelDataPath>(options, support);
        }

    }

    /* Creates a data path. */
    TTask<int32_t> CreateIpsecDataPath(SIpsecDataPathOptions options, IIpsecDataPathPtr& out) {
        out.reset();

        if (options.kind == EIDP_USER) {
            out = ipsec::MakeUserDataPath(options);
            co_return SBOX_OK;
        }

        CXfrm xfrm;
        SXfrmSupport support;
        int32_t r = xfrm.open(options.netnsPath);
        if (r == SBOX_OK) {
            r = co_await xfrm.probe(support);
        }

        if (r != SBOX_OK && r != -ENOTSUP) {
            co_return r;
        }

        if (support.esp) {
            out = ipsec::MakeKernelDataPath(options, support);
            co_return SBOX_OK;
        }

        if (options.kind == EIDP_KERNEL) {
            co_return -ENOTSUP;
        }

        out = ipsec::MakeUserDataPath(options);
        co_return SBOX_OK;
    }

}
}
