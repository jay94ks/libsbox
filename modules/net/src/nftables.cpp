#include <sbox/net/nftables.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

namespace sbox {
namespace net {

    namespace {

        constexpr uint32_t REG1 = NFT_REG_1;
        constexpr uint32_t REG2 = NFT_REG_2;
        constexpr size_t IFNAME_LEN = 16;

        /* Builds an nf_tables message with the nfgenmsg header. */
        CNlMessage nftMessage(uint16_t command, uint16_t flags, uint8_t family = NFPROTO_INET) {
            CNlMessage msg(uint16_t((NFNL_SUBSYS_NFTABLES << 8) | command), flags);
            nfgenmsg g;
            std::memset(&g, 0, sizeof(g));
            g.nfgen_family = family;
            g.version = NFNETLINK_V0;
            g.res_id = 0;
            msg.putHeader(&g, sizeof(g));
            return msg;
        }

        /* Builds a batch begin/end marker. */
        CNlMessage batchMarker(uint16_t type) {
            CNlMessage msg(type, 0);
            nfgenmsg g;
            std::memset(&g, 0, sizeof(g));
            g.nfgen_family = AF_UNSPEC;
            g.version = NFNETLINK_V0;
            g.res_id = htons(NFNL_SUBSYS_NFTABLES);
            msg.putHeader(&g, sizeof(g));
            return msg;
        }

        /* Builds NEWTABLE. */
        CNlMessage newTable(std::string_view table) {
            CNlMessage msg = nftMessage(NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK);
            msg.putString(NFTA_TABLE_NAME, table);
            msg.putBe32(NFTA_TABLE_FLAGS, 0);
            return msg;
        }

        /* Builds DELTABLE. */
        CNlMessage delTable(std::string_view table) {
            CNlMessage msg = nftMessage(NFT_MSG_DELTABLE, NLM_F_ACK);
            msg.putString(NFTA_TABLE_NAME, table);
            return msg;
        }

        /* Builds NEWCHAIN; a non-empty type makes it a base chain on `hook`. */
        CNlMessage newChain(std::string_view table, std::string_view name, std::string_view type = std::string_view(),
            uint32_t hook = 0, int32_t priority = 0)
        {
            CNlMessage msg = nftMessage(NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK);
            msg.putString(NFTA_CHAIN_TABLE, table);
            msg.putString(NFTA_CHAIN_NAME, name);

            if (!type.empty()) {
                size_t h = msg.beginNested(NFTA_CHAIN_HOOK);
                msg.putBe32(NFTA_HOOK_HOOKNUM, hook);
                msg.putBe32(NFTA_HOOK_PRIORITY, uint32_t(priority));
                msg.endNested(h);
                msg.putBe32(NFTA_CHAIN_POLICY, NF_ACCEPT);
                msg.putString(NFTA_CHAIN_TYPE, type);
            }

            return msg;
        }

        /* Builds NEWRULE (appended). */
        CNlMessage newRule(std::string_view table, std::string_view chain, const CNftRule& rule) {
            CNlMessage msg = nftMessage(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
            msg.putString(NFTA_RULE_TABLE, table);
            msg.putString(NFTA_RULE_CHAIN, chain);
            std::vector<uint8_t> exprs = rule.expressions();
            msg.put(uint16_t(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED), exprs.data(), exprs.size());
            return msg;
        }

        /* Maps "not supported" style errors to -ENOTSUP. */
        int32_t mapUnsupported(int32_t r) noexcept {
            if (r == -EOPNOTSUPP || r == -EPROTONOSUPPORT || r == -EAFNOSUPPORT) {
                return -ENOTSUP;
            }

            return r;
        }

    }

    /* Constructs an empty rule. */
    CNftRule::CNftRule() : _exprs(0, 0), _count(0) {}

    /* Opens an expression. */
    std::pair<size_t, size_t> CNftRule::open(std::string_view name) {
        size_t elem = _exprs.beginNested(NFTA_LIST_ELEM);
        _exprs.putString(NFTA_EXPR_NAME, name);
        size_t data = _exprs.beginNested(NFTA_EXPR_DATA);
        ++_count;
        return { elem, data };
    }

    /* Closes an expression. */
    void CNftRule::close(std::pair<size_t, size_t> token) noexcept {
        _exprs.endNested(token.second);
        _exprs.endNested(token.first);
    }

    /* Adds a cmp on register 1. */
    void CNftRule::compare(bool equal, const void* data, size_t length) {
        auto t = open("cmp");
        _exprs.putBe32(NFTA_CMP_SREG, REG1);
        _exprs.putBe32(NFTA_CMP_OP, equal ? NFT_CMP_EQ : NFT_CMP_NEQ);
        size_t d = _exprs.beginNested(NFTA_CMP_DATA);
        _exprs.put(NFTA_DATA_VALUE, data, length);
        _exprs.endNested(d);
        close(t);
    }

    /* Adds a payload load. */
    void CNftRule::loadPayload(uint32_t base, uint32_t offset, uint32_t length) {
        auto t = open("payload");
        _exprs.putBe32(NFTA_PAYLOAD_DREG, REG1);
        _exprs.putBe32(NFTA_PAYLOAD_BASE, base);
        _exprs.putBe32(NFTA_PAYLOAD_OFFSET, offset);
        _exprs.putBe32(NFTA_PAYLOAD_LEN, length);
        close(t);
    }

    /* Adds a meta load. */
    void CNftRule::loadMeta(uint32_t key) {
        auto t = open("meta");
        _exprs.putBe32(NFTA_META_DREG, REG1);
        _exprs.putBe32(NFTA_META_KEY, key);
        close(t);
    }

    /* meta nfproto. */
    CNftRule& CNftRule::matchFamily(uint8_t family) {
        loadMeta(NFT_META_NFPROTO);
        uint8_t value = family == 6 ? NFPROTO_IPV6 : NFPROTO_IPV4;
        compare(true, &value, 1);
        return *this;
    }

    /* meta l4proto. */
    CNftRule& CNftRule::matchL4Proto(uint8_t protocol) {
        loadMeta(NFT_META_L4PROTO);
        compare(true, &protocol, 1);
        return *this;
    }

    /* iifname. */
    CNftRule& CNftRule::matchIifname(std::string_view name, bool equal) {
        loadMeta(NFT_META_IIFNAME);
        uint8_t buffer[IFNAME_LEN];
        std::memset(buffer, 0, sizeof(buffer));
        std::memcpy(buffer, name.data(), name.size() < IFNAME_LEN ? name.size() : IFNAME_LEN - 1);
        compare(equal, buffer, sizeof(buffer));
        return *this;
    }

    /* oifname. */
    CNftRule& CNftRule::matchOifname(std::string_view name, bool equal) {
        loadMeta(NFT_META_OIFNAME);
        uint8_t buffer[IFNAME_LEN];
        std::memset(buffer, 0, sizeof(buffer));
        std::memcpy(buffer, name.data(), name.size() < IFNAME_LEN ? name.size() : IFNAME_LEN - 1);
        compare(equal, buffer, sizeof(buffer));
        return *this;
    }

    /* Address prefix match. */
    void CNftRule::matchAddress(const SIpPrefix& prefix, uint32_t offset4, uint32_t offset6, bool equal) {
        bool v4 = prefix.address.isV4();
        uint32_t length = v4 ? 4 : 16;
        loadPayload(NFT_PAYLOAD_NETWORK_HEADER, v4 ? offset4 : offset6, length);

        SIpPrefix net = prefix.network();
        if (prefix.length < prefix.address.bits()) {
            // --> Mask the loaded address down to the prefix: reg1 = (reg1 & mask) ^ 0.
            SIpAddress mask = prefix.mask();
            uint8_t zero[16];
            std::memset(zero, 0, sizeof(zero));

            auto t = open("bitwise");
            _exprs.putBe32(NFTA_BITWISE_SREG, REG1);
            _exprs.putBe32(NFTA_BITWISE_DREG, REG1);
            _exprs.putBe32(NFTA_BITWISE_LEN, length);
            size_t m = _exprs.beginNested(NFTA_BITWISE_MASK);
            _exprs.put(NFTA_DATA_VALUE, mask.bytes, length);
            _exprs.endNested(m);
            size_t x = _exprs.beginNested(NFTA_BITWISE_XOR);
            _exprs.put(NFTA_DATA_VALUE, zero, length);
            _exprs.endNested(x);
            close(t);
        }

        compare(equal, net.address.bytes, length);
    }

    /* ip saddr. */
    CNftRule& CNftRule::matchSource(const SIpPrefix& prefix, bool equal) {
        matchAddress(prefix, 12, 8, equal);
        return *this;
    }

    /* ip daddr. */
    CNftRule& CNftRule::matchDestination(const SIpPrefix& prefix, bool equal) {
        matchAddress(prefix, 16, 24, equal);
        return *this;
    }

    /* th dport. */
    CNftRule& CNftRule::matchDestinationPort(uint16_t port) {
        loadPayload(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2);
        uint16_t be = htons(port);
        compare(true, &be, 2);
        return *this;
    }

    /* ct state. */
    CNftRule& CNftRule::matchCtState(uint32_t mask) {
        auto t = open("ct");
        _exprs.putBe32(NFTA_CT_DREG, REG1);
        _exprs.putBe32(NFTA_CT_KEY, NFT_CT_STATE);
        close(t);

        // --> The state is a host order bitmask in the register: (reg & mask) != 0.
        uint32_t zero = 0;
        auto b = open("bitwise");
        _exprs.putBe32(NFTA_BITWISE_SREG, REG1);
        _exprs.putBe32(NFTA_BITWISE_DREG, REG1);
        _exprs.putBe32(NFTA_BITWISE_LEN, 4);
        size_t m = _exprs.beginNested(NFTA_BITWISE_MASK);
        _exprs.put(NFTA_DATA_VALUE, &mask, 4);
        _exprs.endNested(m);
        size_t x = _exprs.beginNested(NFTA_BITWISE_XOR);
        _exprs.put(NFTA_DATA_VALUE, &zero, 4);
        _exprs.endNested(x);
        close(b);

        compare(false, &zero, 4);
        return *this;
    }

    /* fib daddr type local. */
    CNftRule& CNftRule::matchLocalDestination() {
        auto t = open("fib");
        _exprs.putBe32(NFTA_FIB_DREG, REG1);
        _exprs.putBe32(NFTA_FIB_RESULT, NFT_FIB_RESULT_ADDRTYPE);
        _exprs.putBe32(NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR);
        close(t);

        uint32_t local = RTN_LOCAL;
        compare(true, &local, 4);
        return *this;
    }

    /* counter. */
    CNftRule& CNftRule::counter() {
        close(open("counter"));
        return *this;
    }

    /* masquerade. */
    CNftRule& CNftRule::masquerade() {
        close(open("masq"));
        return *this;
    }

    /* dnat to address:port. */
    CNftRule& CNftRule::dnat(const SIpAddress& address, uint16_t port) {
        auto a = open("immediate");
        _exprs.putBe32(NFTA_IMMEDIATE_DREG, REG1);
        size_t d = _exprs.beginNested(NFTA_IMMEDIATE_DATA);
        _exprs.put(NFTA_DATA_VALUE, address.bytes, address.length());
        _exprs.endNested(d);
        close(a);

        if (port) {
            uint16_t be = htons(port);
            auto p = open("immediate");
            _exprs.putBe32(NFTA_IMMEDIATE_DREG, REG2);
            size_t pd = _exprs.beginNested(NFTA_IMMEDIATE_DATA);
            _exprs.put(NFTA_DATA_VALUE, &be, 2);
            _exprs.endNested(pd);
            close(p);
        }

        auto n = open("nat");
        _exprs.putBe32(NFTA_NAT_TYPE, NFT_NAT_DNAT);
        _exprs.putBe32(NFTA_NAT_FAMILY, address.isV6() ? NFPROTO_IPV6 : NFPROTO_IPV4);
        _exprs.putBe32(NFTA_NAT_REG_ADDR_MIN, REG1);
        if (port) {
            _exprs.putBe32(NFTA_NAT_REG_PROTO_MIN, REG2);
        }

        close(n);
        return *this;
    }

    /* Verdict. */
    CNftRule& CNftRule::verdict(ENftVerdict code, std::string_view chain) {
        auto t = open("immediate");
        _exprs.putBe32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        size_t d = _exprs.beginNested(NFTA_IMMEDIATE_DATA);
        size_t v = _exprs.beginNested(NFTA_DATA_VERDICT);
        _exprs.putBe32(NFTA_VERDICT_CODE, uint32_t(code));
        if (!chain.empty()) {
            _exprs.putString(NFTA_VERDICT_CHAIN, chain);
        }

        _exprs.endNested(v);
        _exprs.endNested(d);
        close(t);
        return *this;
    }

    /* Returns the expression stream. */
    std::vector<uint8_t> CNftRule::expressions() const {
        const std::vector<uint8_t>& b = _exprs.bytes();
        return std::vector<uint8_t>(b.begin() + NLMSG_HDRLEN, b.end());
    }

    /* Constructs a closed firewall handle. */
    CFirewall::CFirewall() : _table("sbox") {}

    /* Opens the netfilter socket. */
    int32_t CFirewall::open(const std::string& netnsPath, std::string table) noexcept {
        if (table.empty() || table.size() > 255) {
            return -EINVAL;
        }

        _table = std::move(table);
        return mapUnsupported(_socket.open(NETLINK_NETFILTER, netnsPath));
    }

    /* Builds the batch for a state. */
    std::vector<CNlMessage> CFirewall::build(const SFirewallState& state, std::string_view table) {
        std::vector<CNlMessage> out;

        // --> "add table; delete table; add table" empties an existing table and tolerates a
        // missing one, all inside the same transaction.
        out.push_back(newTable(table));
        out.push_back(delTable(table));
        out.push_back(newTable(table));

        out.push_back(newChain(table, "portmap"));
        out.push_back(newChain(table, "prerouting", "nat", NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST));
        out.push_back(newChain(table, "output", "nat", NF_INET_LOCAL_OUT, NF_IP_PRI_NAT_DST));
        out.push_back(newChain(table, "postrouting", "nat", NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC));
        out.push_back(newChain(table, "forward", "filter", NF_INET_FORWARD, NF_IP_PRI_FILTER));

        // --> Docker: -m addrtype --dst-type LOCAL -j DOCKER, for incoming and local traffic.
        out.push_back(newRule(table, "prerouting", CNftRule().matchLocalDestination().verdict(ENFV_JUMP, "portmap")));
        out.push_back(newRule(table, "output", CNftRule().matchLocalDestination().verdict(ENFV_JUMP, "portmap")));

        for (const SFirewallNetwork& n : state.networks) {
            for (const SIpPrefix& subnet : n.subnets) {
                if (!n.masquerade || n.internal || !subnet.isValid()) {
                    continue;
                }

                // --> Docker: -s <subnet> ! -o <bridge> -j MASQUERADE.
                out.push_back(newRule(table, "postrouting", CNftRule()
                    .matchFamily(subnet.address.family)
                    .matchSource(subnet)
                    .matchOifname(n.bridge, false)
                    .masquerade()));
            }

            if (n.localhostDnat && !n.internal) {
                // --> Loopback clients DNATed onto the bridge need a routable source address
                // (route_localnet is enabled on the bridge for this).
                SIpPrefix loop;
                SIpPrefix::parse("127.0.0.0/8", loop);
                out.push_back(newRule(table, "postrouting", CNftRule()
                    .matchFamily(4)
                    .matchSource(loop)
                    .matchOifname(n.bridge)
                    .masquerade()));
            }
        }

        for (const SFirewallPortMap& p : state.portMaps) {
            if (!p.containerIp.isValid() || p.hostPort == 0) {
                continue;
            }

            uint8_t family = p.containerIp.family;
            if (p.hostIp.isValid() && !p.hostIp.isUnspecified() && p.hostIp.family != family) {
                continue;
            }

            CNftRule rule;
            rule.matchFamily(family);
            if (p.hostIp.isValid() && !p.hostIp.isUnspecified()) {
                rule.matchDestination(SIpPrefix(p.hostIp, uint8_t(p.hostIp.bits())));
            }

            // --> Docker (with its userland proxy): ! -i <bridge>. Containers on the same bridge
            // reach each other directly, not through the published port.
            rule.matchIifname(p.bridge, false)
                .matchL4Proto(p.protocol)
                .matchDestinationPort(p.hostPort)
                .dnat(p.containerIp, p.containerPort ? p.containerPort : p.hostPort);
            out.push_back(newRule(table, "portmap", rule));
        }

        out.push_back(newRule(table, "forward", CNftRule().matchCtState(2 | 4).verdict(ENFV_ACCEPT)));

        for (const SFirewallNetwork& n : state.networks) {
            if (n.internal) {
                out.push_back(newRule(table, "forward", CNftRule()
                    .matchIifname(n.bridge).matchOifname(n.bridge, false).verdict(ENFV_DROP)));
                out.push_back(newRule(table, "forward", CNftRule()
                    .matchIifname(n.bridge, false).matchOifname(n.bridge).verdict(ENFV_DROP)));
            }

            if (!n.icc) {
                out.push_back(newRule(table, "forward", CNftRule()
                    .matchIifname(n.bridge).matchOifname(n.bridge).verdict(ENFV_DROP)));
            }

            if (!n.isolate) {
                continue;
            }

            for (const SFirewallNetwork& other : state.networks) {
                if (&other == &n || !other.isolate || other.bridge == n.bridge) {
                    continue;
                }

                // --> Docker's DOCKER-ISOLATION: no traffic between two different networks.
                out.push_back(newRule(table, "forward", CNftRule()
                    .matchIifname(n.bridge).matchOifname(other.bridge).verdict(ENFV_DROP)));
            }
        }

        return out;
    }

    /* Builds the batch removing the table. */
    std::vector<CNlMessage> CFirewall::buildRemove(std::string_view table) {
        std::vector<CNlMessage> out;
        out.push_back(newTable(table));
        out.push_back(delTable(table));
        return out;
    }

    /* Sends a batch wrapped in begin/end markers. */
    TTask<int32_t> CFirewall::send(std::vector<CNlMessage> messages) {
        if (!_socket.isValid()) {
            co_return -EBADF;
        }

        std::vector<CNlMessage> batch;
        batch.reserve(messages.size() + 2);
        batch.push_back(batchMarker(NFNL_MSG_BATCH_BEGIN));
        for (CNlMessage& m : messages) {
            batch.push_back(std::move(m));
        }

        batch.push_back(batchMarker(NFNL_MSG_BATCH_END));
        co_return mapUnsupported(co_await _socket.batch(batch));
    }

    /* Replaces the table. */
    TTask<int32_t> CFirewall::apply(SFirewallState state) {
        co_return co_await send(build(state, _table));
    }

    /* Removes the table. */
    TTask<int32_t> CFirewall::remove() {
        co_return co_await send(buildRemove(_table));
    }

    /* Checks whether the table exists. */
    TTask<int32_t> CFirewall::exists() {
        CNlMessage msg = nftMessage(NFT_MSG_GETTABLE, 0);
        msg.putString(NFTA_TABLE_NAME, _table);

        int32_t r = co_await _socket.request(msg, nullptr);
        if (r == -ENOENT) {
            co_return 0;
        }

        co_return r == SBOX_OK ? 1 : mapUnsupported(r);
    }

    /* Lists the table's rules. */
    TTask<int32_t> CFirewall::listRules(std::vector<SNftRuleInfo>& out) {
        CNlMessage msg = nftMessage(NFT_MSG_GETRULE, 0);
        msg.putString(NFTA_RULE_TABLE, _table);

        std::vector<SNlReply> replies;
        int32_t r = co_await _socket.dump(msg, replies);
        if (r != SBOX_OK) {
            co_return mapUnsupported(r);
        }

        out.clear();
        for (const SNlReply& reply : replies) {
            if ((reply.type & 0xff) != NFT_MSG_NEWRULE) {
                continue;
            }

            CNlAttrs attrs = reply.attrs(sizeof(nfgenmsg));
            if (attrs.str(NFTA_RULE_TABLE) != _table) {
                continue;
            }

            SNftRuleInfo info;
            info.chain = attrs.str(NFTA_RULE_CHAIN);
            if (const SNlAttr* h = attrs.find(NFTA_RULE_HANDLE)) {
                uint64_t be = h->u64();
                info.handle = (uint64_t(ntohl(uint32_t(be))) << 32) | ntohl(uint32_t(be >> 32));
            }

            if (const SNlAttr* e = attrs.find(NFTA_RULE_EXPRESSIONS)) {
                CNlAttrs list = CNlAttrs::nested(*e);
                for (const SNlAttr& elem : list.items()) {
                    info.expressions.push_back(CNlAttrs::nested(elem).str(NFTA_EXPR_NAME));
                }
            }

            out.push_back(std::move(info));
        }

        co_return SBOX_OK;
    }

}
}
