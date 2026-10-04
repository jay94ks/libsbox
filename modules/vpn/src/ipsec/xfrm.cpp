#include <sbox/vpn/ipsec/xfrm.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/net/rtnl.hpp>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace sbox {
namespace vpn {

    namespace {

        /* Copies an address into xfrm_address_t. */
        void putAddr(xfrm_address_t& out, const net::SIpAddress& a) {
            std::memset(&out, 0, sizeof(out));
            if (a.isValid()) {
                std::memcpy(&out, a.bytes, a.length());
            }
        }

        /* Reads an address of `family` (AF_INET/AF_INET6). */
        net::SIpAddress getAddr(const xfrm_address_t& in, int family) {
            net::SIpAddress a;
            if (family == AF_INET) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&in), 4, a);
            }
            else if (family == AF_INET6) {
                net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&in), 16, a);
            }

            return a;
        }

        /* Fills an xfrm_selector. */
        void putSelector(xfrm_selector& out, const SXfrmSelector& s, int family) {
            std::memset(&out, 0, sizeof(out));
            if (s.src.isValid() || s.dst.isValid()) {
                out.family = uint16_t(family);
            }

            if (s.src.isValid()) {
                putAddr(out.saddr, s.src.network().address);
                out.prefixlen_s = s.src.length;
            }

            if (s.dst.isValid()) {
                putAddr(out.daddr, s.dst.network().address);
                out.prefixlen_d = s.dst.length;
            }

            out.sport = htons(s.srcPort);
            out.sport_mask = htons(s.srcPortMask);
            out.dport = htons(s.dstPort);
            out.dport_mask = htons(s.dstPortMask);
            out.proto = s.protocol;
            out.ifindex = s.ifindex;
        }

        /* Reads an xfrm_selector. */
        SXfrmSelector getSelector(const xfrm_selector& in) {
            SXfrmSelector s;
            if (in.family == AF_INET || in.family == AF_INET6) {
                s.src = net::SIpPrefix(getAddr(in.saddr, in.family), in.prefixlen_s);
                s.dst = net::SIpPrefix(getAddr(in.daddr, in.family), in.prefixlen_d);
            }

            s.srcPort = ntohs(in.sport);
            s.srcPortMask = ntohs(in.sport_mask);
            s.dstPort = ntohs(in.dport);
            s.dstPortMask = ntohs(in.dport_mask);
            s.protocol = in.proto;
            s.ifindex = in.ifindex;
            return s;
        }

        /* Fills a lifetime configuration. */
        void putLifetime(xfrm_lifetime_cfg& out, const SXfrmLifetime& l) {
            out.soft_byte_limit = l.softBytes;
            out.hard_byte_limit = l.hardBytes;
            out.soft_packet_limit = l.softPackets;
            out.hard_packet_limit = l.hardPackets;
            out.soft_add_expires_seconds = l.softAddSeconds;
            out.hard_add_expires_seconds = l.hardAddSeconds;
            out.soft_use_expires_seconds = l.softUseSeconds;
            out.hard_use_expires_seconds = l.hardUseSeconds;
        }

        /* Reads a lifetime configuration. */
        SXfrmLifetime getLifetime(const xfrm_lifetime_cfg& in) {
            SXfrmLifetime l;
            l.softBytes = in.soft_byte_limit;
            l.hardBytes = in.hard_byte_limit;
            l.softPackets = in.soft_packet_limit;
            l.hardPackets = in.hard_packet_limit;
            l.softAddSeconds = in.soft_add_expires_seconds;
            l.hardAddSeconds = in.hard_add_expires_seconds;
            l.softUseSeconds = in.soft_use_expires_seconds;
            l.hardUseSeconds = in.hard_use_expires_seconds;
            return l;
        }

        /* Address family of an SA/policy. */
        int familyOf(const net::SIpAddress& a, const net::SIpAddress& b) {
            const net::SIpAddress& x = a.isValid() ? a : b;
            return x.isV6() ? AF_INET6 : AF_INET;
        }

        /* Appends XFRMA_MARK when set. */
        void putMark(net::CNlMessage& msg, const SXfrmMark& mark) {
            if (mark.mask) {
                xfrm_mark m;
                m.v = mark.value;
                m.m = mark.mask;
                msg.put(XFRMA_MARK, &m, sizeof(m));
            }
        }

        /* Reads common SA attributes. */
        void parseSaAttrs(const net::CNlAttrs& attrs, SXfrmSa& sa) {
            for (const net::SNlAttr& a : attrs.items()) {
                switch (a.type) {
                case XFRMA_ALG_AEAD:
                    if (a.length >= sizeof(xfrm_algo_aead)) {
                        const auto* alg = reinterpret_cast<const xfrm_algo_aead*>(a.data);
                        sa.aead.name.assign(alg->alg_name, strnlen(alg->alg_name, sizeof(alg->alg_name)));
                        sa.aead.bits = alg->alg_icv_len;
                        size_t keyBytes = alg->alg_key_len / 8;
                        if (sizeof(xfrm_algo_aead) + keyBytes <= a.length) {
                            sa.aead.key.assign(a.data + sizeof(xfrm_algo_aead), a.data + sizeof(xfrm_algo_aead) + keyBytes);
                        }
                    }
                    break;

                case XFRMA_ALG_CRYPT:
                    if (a.length >= sizeof(xfrm_algo)) {
                        const auto* alg = reinterpret_cast<const xfrm_algo*>(a.data);
                        sa.crypt.name.assign(alg->alg_name, strnlen(alg->alg_name, sizeof(alg->alg_name)));
                        size_t keyBytes = alg->alg_key_len / 8;
                        if (sizeof(xfrm_algo) + keyBytes <= a.length) {
                            sa.crypt.key.assign(a.data + sizeof(xfrm_algo), a.data + sizeof(xfrm_algo) + keyBytes);
                        }
                    }
                    break;

                case XFRMA_ALG_AUTH_TRUNC:
                    if (a.length >= sizeof(xfrm_algo_auth)) {
                        const auto* alg = reinterpret_cast<const xfrm_algo_auth*>(a.data);
                        sa.auth.name.assign(alg->alg_name, strnlen(alg->alg_name, sizeof(alg->alg_name)));
                        sa.auth.bits = alg->alg_trunc_len;
                        size_t keyBytes = alg->alg_key_len / 8;
                        if (sizeof(xfrm_algo_auth) + keyBytes <= a.length) {
                            sa.auth.key.assign(a.data + sizeof(xfrm_algo_auth), a.data + sizeof(xfrm_algo_auth) + keyBytes);
                        }
                    }
                    break;

                case XFRMA_ENCAP:
                    if (a.length >= sizeof(xfrm_encap_tmpl)) {
                        const auto* e = reinterpret_cast<const xfrm_encap_tmpl*>(a.data);
                        sa.encap = true;
                        sa.encapType = e->encap_type;
                        sa.encapSport = ntohs(e->encap_sport);
                        sa.encapDport = ntohs(e->encap_dport);
                    }
                    break;

                case XFRMA_MARK:
                    if (a.length >= sizeof(xfrm_mark)) {
                        const auto* m = reinterpret_cast<const xfrm_mark*>(a.data);
                        sa.mark.value = m->v;
                        sa.mark.mask = m->m;
                    }
                    break;

                case XFRMA_IF_ID:
                    sa.ifId = a.u32();
                    break;

                case XFRMA_REPLAY_ESN_VAL:
                    if (a.length >= sizeof(xfrm_replay_state_esn)) {
                        const auto* esn = reinterpret_cast<const xfrm_replay_state_esn*>(a.data);
                        sa.replayWindow = esn->replay_window;
                    }
                    break;

                default:
                    break;
                }
            }
        }

        /* Parses an xfrm_usersa_info and its attributes. */
        bool parseSa(const uint8_t* data, size_t length, size_t attrOffset, SXfrmSa& sa) {
            if (length < sizeof(xfrm_usersa_info)) {
                return false;
            }

            xfrm_usersa_info info;
            std::memcpy(&info, data, sizeof(info));

            sa.src = getAddr(info.saddr, info.family);
            sa.dst = getAddr(info.id.daddr, info.family);
            sa.spi = ntohl(info.id.spi);
            sa.protocol = info.id.proto;
            sa.mode = EXfrmMode(info.mode);
            sa.reqid = info.reqid;
            sa.replayWindow = info.replay_window;
            sa.flags = info.flags;
            sa.esn = (info.flags & XFRM_STATE_ESN) != 0;
            sa.lifetime = getLifetime(info.lft);
            sa.selector = getSelector(info.sel);
            sa.bytes = info.curlft.bytes;
            sa.packets = info.curlft.packets;
            sa.addTime = info.curlft.add_time;
            sa.useTime = info.curlft.use_time;

            if (attrOffset <= length) {
                parseSaAttrs(net::CNlAttrs(data + attrOffset, length - attrOffset), sa);
            }

            return true;
        }

        /* Parses an xfrm_userpolicy_info and its attributes. */
        bool parsePolicy(const uint8_t* data, size_t length, size_t attrOffset, SXfrmPolicy& p) {
            if (length < sizeof(xfrm_userpolicy_info)) {
                return false;
            }

            xfrm_userpolicy_info info;
            std::memcpy(&info, data, sizeof(info));

            p.selector = getSelector(info.sel);
            p.dir = EXfrmDir(info.dir);
            p.action = EXfrmAction(info.action);
            p.priority = info.priority;
            p.index = info.index;
            p.lifetime = getLifetime(info.lft);
            p.family = info.sel.family == AF_INET6 ? 6 : 4;
            p.templates.clear();

            if (attrOffset > length) {
                return true;
            }

            net::CNlAttrs attrs(data + attrOffset, length - attrOffset);
            for (const net::SNlAttr& a : attrs.items()) {
                if (a.type == XFRMA_TMPL) {
                    size_t count = a.length / sizeof(xfrm_user_tmpl);
                    for (size_t i = 0; i < count; ++i) {
                        xfrm_user_tmpl t;
                        std::memcpy(&t, a.data + i * sizeof(t), sizeof(t));
                        SXfrmTemplate out;
                        out.src = getAddr(t.saddr, t.family);
                        out.dst = getAddr(t.id.daddr, t.family);
                        out.protocol = t.id.proto;
                        out.spi = ntohl(t.id.spi);
                        out.mode = EXfrmMode(t.mode);
                        out.reqid = t.reqid;
                        out.optional = t.optional != 0;
                        p.templates.push_back(out);
                    }
                }
                else if (a.type == XFRMA_MARK && a.length >= sizeof(xfrm_mark)) {
                    const auto* m = reinterpret_cast<const xfrm_mark*>(a.data);
                    p.mark.value = m->v;
                    p.mark.mask = m->m;
                }
                else if (a.type == XFRMA_IF_ID) {
                    p.ifId = a.u32();
                }
            }

            return true;
        }

        /* Whether an entry belongs to `owner`. */
        bool owned(const SXfrmOwner& owner, const SXfrmMark& mark, uint32_t ifId, uint32_t reqid) {
            if (owner.mark.mask && mark.mask == owner.mark.mask && mark.value == owner.mark.value) {
                return true;
            }

            if (owner.ifId && ifId == owner.ifId) {
                return true;
            }

            return owner.reqidMax && reqid >= owner.reqidMin && reqid <= owner.reqidMax;
        }

    }

    /* Kernel name of an encryption transform. */
    std::string CXfrm::encrAlgorithm(uint16_t encr) {
        switch (encr) {
        case EIKE_ENCR_AES_CBC: return "cbc(aes)";
        case EIKE_ENCR_3DES: return "cbc(des3_ede)";
        case EIKE_ENCR_AES_GCM_12:
        case EIKE_ENCR_AES_GCM_16: return "rfc4106(gcm(aes))";
        case EIKE_ENCR_CHACHA20_POLY1305: return "rfc7539esp(chacha20,poly1305)";
        default: return std::string();
        }
    }

    /* Kernel name of an integrity transform. */
    std::string CXfrm::integAlgorithm(uint16_t integ) {
        switch (integ) {
        case EIKE_INTEG_HMAC_SHA1_96: return "hmac(sha1)";
        case EIKE_INTEG_HMAC_SHA2_256_128: return "hmac(sha256)";
        case EIKE_INTEG_HMAC_SHA2_384_192: return "hmac(sha384)";
        case EIKE_INTEG_HMAC_SHA2_512_256: return "hmac(sha512)";
        default: return std::string();
        }
    }

    /* Opens the socket. */
    int32_t CXfrm::open(const std::string& netnsPath) noexcept {
        _netnsPath = netnsPath;
        return _socket.open(NETLINK_XFRM, netnsPath);
    }

    /* Allocates an SPI. */
    TTask<int32_t> CXfrm::allocSpi(net::SIpAddress src, net::SIpAddress dst, uint8_t protocol, uint32_t reqid,
                                   SXfrmMark mark, uint32_t& spi, uint32_t minSpi, uint32_t maxSpi) {
        if (!dst.isValid()) {
            co_return -EINVAL;
        }

        int family = familyOf(dst, src);
        xfrm_userspi_info req;
        std::memset(&req, 0, sizeof(req));
        req.info.family = uint16_t(family);
        req.info.id.proto = protocol;
        putAddr(req.info.id.daddr, dst);
        putAddr(req.info.saddr, src);
        req.info.mode = XFRM_MODE_TUNNEL;
        req.info.reqid = reqid;
        req.min = minSpi;
        req.max = maxSpi;

        net::CNlMessage msg(XFRM_MSG_ALLOCSPI, 0);
        msg.putHeader(&req, sizeof(req));
        putMark(msg, mark);

        std::vector<net::SNlReply> replies;
        int32_t r = co_await _socket.request(msg, &replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const net::SNlReply& reply : replies) {
            SXfrmSa sa;
            if (reply.type == XFRM_MSG_NEWSA && parseSa(reply.payload.data(), reply.payload.size(),
                                                        NLMSG_ALIGN(sizeof(xfrm_usersa_info)), sa)) {
                spi = sa.spi;
                co_return SBOX_OK;
            }
        }

        co_return -EIO;
    }

    /* Adds or updates an SA. */
    TTask<int32_t> CXfrm::addSa(SXfrmSa sa, bool update) {
        if (!sa.src.isValid() || !sa.dst.isValid() || sa.src.family != sa.dst.family) {
            co_return -EINVAL;
        }

        int family = familyOf(sa.dst, sa.src);
        xfrm_usersa_info info;
        std::memset(&info, 0, sizeof(info));
        putSelector(info.sel, sa.selector, family);
        info.id.proto = sa.protocol;
        info.id.spi = htonl(sa.spi);
        putAddr(info.id.daddr, sa.dst);
        putAddr(info.saddr, sa.src);
        putLifetime(info.lft, sa.lifetime);
        info.reqid = sa.reqid;
        info.family = uint16_t(family);
        info.mode = uint8_t(sa.mode);
        info.flags = sa.flags;

        bool esnAttr = sa.esn || sa.replayWindow > 32;
        info.replay_window = esnAttr ? 0 : uint8_t(sa.replayWindow);
        if (sa.esn) {
            info.flags |= XFRM_STATE_ESN;
        }

        net::CNlMessage msg(update ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA, 0);
        msg.putHeader(&info, sizeof(info));

        if (!sa.aead.name.empty()) {
            std::vector<uint8_t> buf(sizeof(xfrm_algo_aead) + sa.aead.key.size(), 0);
            auto* alg = reinterpret_cast<xfrm_algo_aead*>(buf.data());
            std::strncpy(alg->alg_name, sa.aead.name.c_str(), sizeof(alg->alg_name) - 1);
            alg->alg_key_len = uint32_t(sa.aead.key.size() * 8);
            alg->alg_icv_len = sa.aead.bits;
            if (!sa.aead.key.empty()) {
                std::memcpy(buf.data() + sizeof(xfrm_algo_aead), sa.aead.key.data(), sa.aead.key.size());
            }

            msg.put(XFRMA_ALG_AEAD, buf.data(), buf.size());
            IkeWipe(buf);
        }

        if (!sa.crypt.name.empty()) {
            std::vector<uint8_t> buf(sizeof(xfrm_algo) + sa.crypt.key.size(), 0);
            auto* alg = reinterpret_cast<xfrm_algo*>(buf.data());
            std::strncpy(alg->alg_name, sa.crypt.name.c_str(), sizeof(alg->alg_name) - 1);
            alg->alg_key_len = uint32_t(sa.crypt.key.size() * 8);
            if (!sa.crypt.key.empty()) {
                std::memcpy(buf.data() + sizeof(xfrm_algo), sa.crypt.key.data(), sa.crypt.key.size());
            }

            msg.put(XFRMA_ALG_CRYPT, buf.data(), buf.size());
            IkeWipe(buf);
        }

        if (!sa.auth.name.empty()) {
            std::vector<uint8_t> buf(sizeof(xfrm_algo_auth) + sa.auth.key.size(), 0);
            auto* alg = reinterpret_cast<xfrm_algo_auth*>(buf.data());
            std::strncpy(alg->alg_name, sa.auth.name.c_str(), sizeof(alg->alg_name) - 1);
            alg->alg_key_len = uint32_t(sa.auth.key.size() * 8);
            alg->alg_trunc_len = sa.auth.bits;
            if (!sa.auth.key.empty()) {
                std::memcpy(buf.data() + sizeof(xfrm_algo_auth), sa.auth.key.data(), sa.auth.key.size());
            }

            msg.put(XFRMA_ALG_AUTH_TRUNC, buf.data(), buf.size());
            IkeWipe(buf);
        }

        if (sa.encap) {
            xfrm_encap_tmpl e;
            std::memset(&e, 0, sizeof(e));
            e.encap_type = sa.encapType;
            e.encap_sport = htons(sa.encapSport);
            e.encap_dport = htons(sa.encapDport);
            msg.put(XFRMA_ENCAP, &e, sizeof(e));
        }

        if (esnAttr) {
            // --> One bitmap word per 32 packets of window (the kernel wants bmp_len words).
            uint32_t window = sa.replayWindow ? sa.replayWindow : 32;
            uint32_t words = (window + 31) / 32;
            std::vector<uint8_t> buf(sizeof(xfrm_replay_state_esn) + words * sizeof(uint32_t), 0);
            auto* esn = reinterpret_cast<xfrm_replay_state_esn*>(buf.data());
            esn->bmp_len = words;
            esn->replay_window = window;
            msg.put(XFRMA_REPLAY_ESN_VAL, buf.data(), buf.size());
        }

        putMark(msg, sa.mark);
        if (sa.ifId) {
            msg.putU32(XFRMA_IF_ID, sa.ifId);
        }

        co_return co_await _socket.request(msg);
    }

    /* Deletes an SA. */
    TTask<int32_t> CXfrm::deleteSa(net::SIpAddress src, net::SIpAddress dst, uint32_t spi, uint8_t protocol, SXfrmMark mark) {
        if (!dst.isValid()) {
            co_return -EINVAL;
        }

        xfrm_usersa_id id;
        std::memset(&id, 0, sizeof(id));
        putAddr(id.daddr, dst);
        id.spi = htonl(spi);
        id.family = uint16_t(familyOf(dst, src));
        id.proto = protocol;

        net::CNlMessage msg(XFRM_MSG_DELSA, 0);
        msg.putHeader(&id, sizeof(id));
        if (src.isValid()) {
            xfrm_address_t s;
            putAddr(s, src);
            msg.put(XFRMA_SRCADDR, &s, sizeof(s));
        }

        putMark(msg, mark);
        co_return co_await _socket.request(msg);
    }

    /* Reads one SA. */
    TTask<int32_t> CXfrm::getSa(net::SIpAddress dst, uint32_t spi, uint8_t protocol, SXfrmSa& out, SXfrmMark mark) {
        xfrm_usersa_id id;
        std::memset(&id, 0, sizeof(id));
        putAddr(id.daddr, dst);
        id.spi = htonl(spi);
        id.family = uint16_t(dst.isV6() ? AF_INET6 : AF_INET);
        id.proto = protocol;

        net::CNlMessage msg(XFRM_MSG_GETSA, 0);
        msg.putHeader(&id, sizeof(id));
        putMark(msg, mark);

        std::vector<net::SNlReply> replies;
        int32_t r = co_await _socket.request(msg, &replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const net::SNlReply& reply : replies) {
            if (reply.type == XFRM_MSG_NEWSA && parseSa(reply.payload.data(), reply.payload.size(),
                                                        NLMSG_ALIGN(sizeof(xfrm_usersa_info)), out)) {
                co_return SBOX_OK;
            }
        }

        co_return -ENOENT;
    }

    /* Lists SAs. */
    TTask<int32_t> CXfrm::listSas(std::vector<SXfrmSa>& out) {
        xfrm_usersa_id id;
        std::memset(&id, 0, sizeof(id));
        net::CNlMessage msg(XFRM_MSG_GETSA, 0);
        msg.putHeader(&id, sizeof(id));

        std::vector<net::SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const net::SNlReply& reply : replies) {
            SXfrmSa sa;
            if (reply.type == XFRM_MSG_NEWSA && parseSa(reply.payload.data(), reply.payload.size(),
                                                        NLMSG_ALIGN(sizeof(xfrm_usersa_info)), sa)) {
                out.push_back(std::move(sa));
            }
        }

        co_return SBOX_OK;
    }

    /* Adds a policy. */
    TTask<int32_t> CXfrm::addPolicy(SXfrmPolicy policy, bool update) {
        int family;
        if (policy.family) {
            family = policy.family == 6 ? AF_INET6 : AF_INET;
        }
        else {
            family = familyOf(policy.selector.dst.address, policy.selector.src.address);
        }

        xfrm_userpolicy_info info;
        std::memset(&info, 0, sizeof(info));
        putSelector(info.sel, policy.selector, family);
        info.sel.family = uint16_t(family);
        putLifetime(info.lft, policy.lifetime);
        info.priority = policy.priority;
        info.index = policy.index;
        info.dir = uint8_t(policy.dir);
        info.action = uint8_t(policy.action);
        info.share = XFRM_SHARE_ANY;

        net::CNlMessage msg(update ? XFRM_MSG_UPDPOLICY : XFRM_MSG_NEWPOLICY, 0);
        msg.putHeader(&info, sizeof(info));

        if (!policy.templates.empty()) {
            std::vector<xfrm_user_tmpl> tmpls(policy.templates.size());
            for (size_t i = 0; i < policy.templates.size(); ++i) {
                const SXfrmTemplate& t = policy.templates[i];
                xfrm_user_tmpl& k = tmpls[i];
                std::memset(&k, 0, sizeof(k));
                k.family = uint16_t(t.mode == EXMODE_TUNNEL ? familyOf(t.dst, t.src) : family);
                k.id.proto = t.protocol;
                k.id.spi = htonl(t.spi);
                putAddr(k.id.daddr, t.dst);
                putAddr(k.saddr, t.src);
                k.reqid = t.reqid;
                k.mode = uint8_t(t.mode);
                k.share = XFRM_SHARE_ANY;
                k.optional = t.optional ? 1 : 0;
                k.aalgos = ~0u;
                k.ealgos = ~0u;
                k.calgos = ~0u;
            }

            msg.put(XFRMA_TMPL, tmpls.data(), tmpls.size() * sizeof(xfrm_user_tmpl));
        }

        putMark(msg, policy.mark);
        if (policy.ifId) {
            msg.putU32(XFRMA_IF_ID, policy.ifId);
        }

        co_return co_await _socket.request(msg);
    }

    /* Deletes a policy. */
    TTask<int32_t> CXfrm::deletePolicy(SXfrmSelector selector, EXfrmDir dir, SXfrmMark mark, uint32_t ifId, uint8_t family) {
        int fam = family ? (family == 6 ? AF_INET6 : AF_INET) : familyOf(selector.dst.address, selector.src.address);

        xfrm_userpolicy_id id;
        std::memset(&id, 0, sizeof(id));
        putSelector(id.sel, selector, fam);
        id.sel.family = uint16_t(fam);
        id.dir = uint8_t(dir);

        net::CNlMessage msg(XFRM_MSG_DELPOLICY, 0);
        msg.putHeader(&id, sizeof(id));
        putMark(msg, mark);
        if (ifId) {
            msg.putU32(XFRMA_IF_ID, ifId);
        }

        co_return co_await _socket.request(msg);
    }

    /* Lists policies. */
    TTask<int32_t> CXfrm::listPolicies(std::vector<SXfrmPolicy>& out) {
        xfrm_userpolicy_id id;
        std::memset(&id, 0, sizeof(id));
        net::CNlMessage msg(XFRM_MSG_GETPOLICY, 0);
        msg.putHeader(&id, sizeof(id));

        std::vector<net::SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const net::SNlReply& reply : replies) {
            SXfrmPolicy p;
            if (reply.type == XFRM_MSG_NEWPOLICY && parsePolicy(reply.payload.data(), reply.payload.size(),
                                                                NLMSG_ALIGN(sizeof(xfrm_userpolicy_info)), p)) {
                out.push_back(std::move(p));
            }
        }

        co_return SBOX_OK;
    }

    /* Flushes entries of one owner. */
    TTask<int32_t> CXfrm::flushOwned(SXfrmOwner owner) {
        int32_t removed = 0;

        std::vector<SXfrmPolicy> policies;
        int32_t r = co_await listPolicies(policies);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const SXfrmPolicy& p : policies) {
            uint32_t reqid = p.templates.empty() ? 0 : p.templates[0].reqid;
            if (!owned(owner, p.mark, p.ifId, reqid)) {
                continue;
            }

            r = co_await deletePolicy(p.selector, p.dir, p.mark, p.ifId, p.family);
            if (r == SBOX_OK) {
                ++removed;
            }
        }

        std::vector<SXfrmSa> sas;
        r = co_await listSas(sas);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (const SXfrmSa& sa : sas) {
            if (!owned(owner, sa.mark, sa.ifId, sa.reqid)) {
                continue;
            }

            r = co_await deleteSa(sa.src, sa.dst, sa.spi, sa.protocol, sa.mark);
            if (r == SBOX_OK) {
                ++removed;
            }
        }

        co_return removed;
    }

    /* Creates an xfrm interface. */
    TTask<int32_t> CXfrm::createInterface(std::string name, uint32_t ifId, int32_t linkIndex) {
        if (name.empty() || name.size() >= IFNAMSIZ || ifId == 0) {
            co_return -EINVAL;
        }

        net::CNetlinkSocket route;
        int32_t r = route.open(NETLINK_ROUTE, _netnsPath);
        if (r != SBOX_OK) {
            co_return r;
        }

        net::CNlMessage msg(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
        ifinfomsg ifi;
        std::memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = AF_UNSPEC;
        msg.putHeader(&ifi, sizeof(ifi));
        msg.putString(IFLA_IFNAME, name);

        size_t info = msg.beginNested(IFLA_LINKINFO);
        msg.putString(IFLA_INFO_KIND, "xfrm");
        size_t data = msg.beginNested(IFLA_INFO_DATA);
        if (linkIndex > 0) {
            msg.putU32(IFLA_XFRM_LINK, uint32_t(linkIndex));
        }

        msg.putU32(IFLA_XFRM_IF_ID, ifId);
        msg.endNested(data);
        msg.endNested(info);

        r = co_await route.request(msg);
        if (r == -EOPNOTSUPP) {
            r = -ENOTSUP;
        }

        co_return r;
    }

    /* Probes kernel support. */
    TTask<int32_t> CXfrm::probe(SXfrmSupport& out) {
        out = SXfrmSupport();
        if (!isValid()) {
            int32_t r = open(_netnsPath);
            if (r != SBOX_OK) {
                co_return r == -ENOTSUP ? SBOX_OK : r;
            }
        }

        out.netlink = true;

        // --> Throwaway SAs between TEST-NET-1 addresses, scoped by a random mark so they can
        // never collide with real entries.
        uint32_t seed = 0;
        IkeRandom(SByteSpan(reinterpret_cast<uint8_t*>(&seed), sizeof(seed)));

        SXfrmSa sa;
        net::SIpAddress::parse("192.0.2.1", sa.src);
        net::SIpAddress::parse("192.0.2.2", sa.dst);
        sa.mark.value = seed | 1;
        sa.mark.mask = 0xffffffffu;
        sa.spi = 0x10000000u | (seed & 0x0fffff00u);

        auto attempt = [this](SXfrmSa candidate) -> TTask<bool> {
            int32_t r = co_await addSa(candidate);
            if (r != SBOX_OK) {
                co_return false;
            }

            co_await deleteSa(candidate.src, candidate.dst, candidate.spi, candidate.protocol, candidate.mark);
            co_return true;
        };

        SXfrmSa cbc = sa;
        cbc.crypt.name = "cbc(aes)";
        cbc.crypt.key.assign(16, 0x11);
        cbc.auth.name = "hmac(sha256)";
        cbc.auth.key.assign(32, 0x22);
        cbc.auth.bits = 128;
        out.esp = co_await attempt(cbc);

        if (out.esp) {
            SXfrmSa gcm = sa;
            gcm.spi += 1;
            gcm.aead.name = "rfc4106(gcm(aes))";
            gcm.aead.key.assign(20, 0x33);
            gcm.aead.bits = 128;
            out.gcm = co_await attempt(gcm);

            SXfrmSa chacha = sa;
            chacha.spi += 2;
            chacha.aead.name = "rfc7539esp(chacha20,poly1305)";
            chacha.aead.key.assign(36, 0x44);
            chacha.aead.bits = 128;
            out.chacha = co_await attempt(chacha);

            SXfrmSa des3 = sa;
            des3.spi += 3;
            des3.crypt.name = "cbc(des3_ede)";
            des3.crypt.key.assign(24, 0x55);
            des3.auth = cbc.auth;
            out.des3 = co_await attempt(des3);
        }

        std::string name = "sbxp" + std::to_string(seed % 100000);
        int32_t r = co_await createInterface(name, (seed & 0x7fffffffu) | 1);
        if (r == SBOX_OK) {
            out.interfaces = true;
            net::CRtnl rtnl;
            if (rtnl.open(_netnsPath) == SBOX_OK) {
                int32_t index = co_await rtnl.linkIndex(name);
                if (index > 0) {
                    co_await rtnl.deleteLink(index);
                }
            }
        }

        co_return SBOX_OK;
    }

    /* Parses a notification. */
    bool CXfrm::parseEvent(const net::SNlReply& msg, SXfrmEvent& out) {
        out = SXfrmEvent();
        const uint8_t* data = msg.payload.data();
        size_t length = msg.payload.size();

        switch (msg.type) {
        case XFRM_MSG_ACQUIRE: {
            if (length < sizeof(xfrm_user_acquire)) {
                return false;
            }

            xfrm_user_acquire acq;
            std::memcpy(&acq, data, sizeof(acq));
            out.type = EXEV_ACQUIRE;
            out.sa.dst = getAddr(acq.id.daddr, acq.policy.sel.family ? acq.policy.sel.family : AF_INET);
            out.sa.src = getAddr(acq.saddr, acq.policy.sel.family ? acq.policy.sel.family : AF_INET);
            out.sa.protocol = acq.id.proto;
            out.sa.selector = getSelector(acq.sel);
            parsePolicy(reinterpret_cast<const uint8_t*>(&acq.policy), sizeof(acq.policy), sizeof(acq.policy), out.policy);

            // --> The policy's templates and mark follow as attributes.
            size_t offset = NLMSG_ALIGN(sizeof(xfrm_user_acquire));
            if (offset <= length) {
                net::CNlAttrs attrs(data + offset, length - offset);
                for (const net::SNlAttr& a : attrs.items()) {
                    if (a.type == XFRMA_TMPL && a.length >= sizeof(xfrm_user_tmpl)) {
                        xfrm_user_tmpl t;
                        std::memcpy(&t, a.data, sizeof(t));
                        out.sa.reqid = t.reqid;
                        out.sa.mode = EXfrmMode(t.mode);
                    }
                    else if (a.type == XFRMA_MARK && a.length >= sizeof(xfrm_mark)) {
                        const auto* m = reinterpret_cast<const xfrm_mark*>(a.data);
                        out.policy.mark.value = m->v;
                        out.policy.mark.mask = m->m;
                    }
                    else if (a.type == XFRMA_IF_ID) {
                        out.policy.ifId = a.u32();
                    }
                }
            }

            return true;
        }

        case XFRM_MSG_EXPIRE: {
            if (length < sizeof(xfrm_user_expire)) {
                return false;
            }

            xfrm_user_expire exp;
            std::memcpy(&exp, data, sizeof(exp));
            out.type = EXEV_EXPIRE;
            out.hard = exp.hard != 0;
            parseSa(data, length, NLMSG_ALIGN(sizeof(xfrm_user_expire)), out.sa);
            return true;
        }

        case XFRM_MSG_POLEXPIRE: {
            if (length < sizeof(xfrm_user_polexpire)) {
                return false;
            }

            xfrm_user_polexpire exp;
            std::memcpy(&exp, data, sizeof(exp));
            out.type = EXEV_POLICY_EXPIRE;
            out.hard = exp.hard != 0;
            parsePolicy(data, length, NLMSG_ALIGN(sizeof(xfrm_user_polexpire)), out.policy);
            return true;
        }

        case XFRM_MSG_NEWSA:
        case XFRM_MSG_UPDSA:
            out.type = EXEV_SA_ADDED;
            return parseSa(data, length, NLMSG_ALIGN(sizeof(xfrm_usersa_info)), out.sa);

        case XFRM_MSG_DELSA: {
            // --> Deletion notifications carry xfrm_usersa_id followed by XFRMA_SA (the full SA).
            out.type = EXEV_SA_DELETED;
            size_t offset = NLMSG_ALIGN(sizeof(xfrm_usersa_id));
            if (length < offset) {
                return false;
            }

            net::CNlAttrs attrs(data + offset, length - offset);
            if (const net::SNlAttr* full = attrs.find(XFRMA_SA)) {
                parseSa(full->data, full->length, full->length, out.sa);
            }
            else {
                xfrm_usersa_id id;
                std::memcpy(&id, data, sizeof(id));
                out.sa.dst = getAddr(id.daddr, id.family);
                out.sa.spi = ntohl(id.spi);
                out.sa.protocol = id.proto;
            }

            return true;
        }

        case XFRM_MSG_NEWPOLICY:
        case XFRM_MSG_UPDPOLICY:
            out.type = EXEV_POLICY_ADDED;
            return parsePolicy(data, length, NLMSG_ALIGN(sizeof(xfrm_userpolicy_info)), out.policy);

        case XFRM_MSG_DELPOLICY: {
            out.type = EXEV_POLICY_DELETED;
            size_t offset = NLMSG_ALIGN(sizeof(xfrm_userpolicy_id));
            if (length < offset) {
                return false;
            }

            net::CNlAttrs attrs(data + offset, length - offset);
            if (const net::SNlAttr* full = attrs.find(XFRMA_POLICY)) {
                parsePolicy(full->data, full->length, full->length, out.policy);
            }
            else {
                xfrm_userpolicy_id id;
                std::memcpy(&id, data, sizeof(id));
                out.policy.selector = getSelector(id.sel);
                out.policy.dir = EXfrmDir(id.dir);
                out.policy.index = id.index;
            }

            return true;
        }

        case XFRM_MSG_MAPPING: {
            if (length < sizeof(xfrm_user_mapping)) {
                return false;
            }

            xfrm_user_mapping map;
            std::memcpy(&map, data, sizeof(map));
            out.type = EXEV_MAPPING;
            out.sa.dst = getAddr(map.id.daddr, map.id.family);
            out.sa.spi = ntohl(map.id.spi);
            out.sa.protocol = map.id.proto;
            out.sa.reqid = map.reqid;
            out.mappedAddress = getAddr(map.new_saddr, map.id.family);
            out.mappedPort = ntohs(map.new_sport);
            return true;
        }

        default:
            return false;
        }
    }

    // ---------------------------------------------------------------------------------------

    /* Opens the monitor. */
    int32_t CXfrmMonitor::open(const std::string& netnsPath, bool changes) noexcept {
        int32_t r = _socket.open(NETLINK_XFRM, netnsPath);
        if (r != SBOX_OK) {
            return r;
        }

        const uint32_t groups[] = { XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE, XFRMNLGRP_MAPPING };
        for (uint32_t g : groups) {
            r = _socket.joinGroup(g);
            if (r != SBOX_OK) {
                return r;
            }
        }

        if (changes) {
            r = _socket.joinGroup(XFRMNLGRP_SA);
            if (r == SBOX_OK) {
                r = _socket.joinGroup(XFRMNLGRP_POLICY);
            }
        }

        return r;
    }

    /* Waits for a notification. */
    TTask<int32_t> CXfrmMonitor::next(SXfrmEvent& out, int64_t timeoutMs) {
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        while (_pending.empty()) {
            int64_t left = -1;
            if (deadline >= 0) {
                left = deadline - CEventLoop::nowMs();
                if (left <= 0) {
                    co_return -ETIMEDOUT;
                }
            }

            std::vector<net::SNlReply> messages;
            int32_t r = co_await _socket.receive(messages, left);
            if (r != SBOX_OK) {
                co_return r;
            }

            for (const net::SNlReply& m : messages) {
                SXfrmEvent ev;
                if (CXfrm::parseEvent(m, ev)) {
                    _pending.push_back(std::move(ev));
                }
            }
        }

        out = std::move(_pending.front());
        _pending.erase(_pending.begin());
        co_return SBOX_OK;
    }

    /* Closes the monitor. */
    void CXfrmMonitor::close() noexcept {
        _socket.close();
    }

}
}
