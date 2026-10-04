#ifndef __INCLUDE_SBOX_NET_NFTABLES_HPP__
#define __INCLUDE_SBOX_NET_NFTABLES_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/net/netlink.hpp>

namespace sbox {
namespace net {

    /**
     * nftables verdicts usable at the end of a rule.
     */
    enum ENftVerdict : int32_t {
        ENFV_DROP     = 0,      // --> NF_DROP.
        ENFV_ACCEPT   = 1,      // --> NF_ACCEPT.
        ENFV_CONTINUE = -1,     // --> NFT_CONTINUE.
        ENFV_RETURN   = -5,     // --> NFT_RETURN.
        ENFV_JUMP     = -3,     // --> NFT_JUMP (needs a chain name).
        ENFV_GOTO     = -4,     // --> NFT_GOTO (needs a chain name).
    };

    /**
     * Builder of one nftables rule: a list of expressions encoded as NFTA_RULE_EXPRESSIONS.
     *
     * The helpers mirror the nft syntax they produce (noted on each), always loading into
     * register 1 (and 2 for NAT ports), the way nft itself compiles simple rules.
     */
    class SBOX_API CNftRule {
    private:
        CNlMessage _exprs;      // --> Holds only the expression attributes (header unused).
        size_t _count;

    public:
        CNftRule();

        /** Returns the number of expressions. */
        inline size_t count() const noexcept { return _count; }

        /** `meta nfproto ipv4|ipv6` (family 4 or 6). */
        CNftRule& matchFamily(uint8_t family);

        /** `meta l4proto <proto>` (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP). */
        CNftRule& matchL4Proto(uint8_t protocol);

        /** `iifname [!=] <name>` (exact match). */
        CNftRule& matchIifname(std::string_view name, bool equal = true);

        /** `oifname [!=] <name>` (exact match). */
        CNftRule& matchOifname(std::string_view name, bool equal = true);

        /** `ip saddr <prefix>` / `ip6 saddr <prefix>` (needs matchFamily first). */
        CNftRule& matchSource(const SIpPrefix& prefix, bool equal = true);

        /** `ip daddr <prefix>` / `ip6 daddr <prefix>` (needs matchFamily first). */
        CNftRule& matchDestination(const SIpPrefix& prefix, bool equal = true);

        /** `th dport <port>` (needs matchL4Proto first). */
        CNftRule& matchDestinationPort(uint16_t port);

        /** `ct state <mask>` with NF_CT_STATE_BIT values (established = 2, related = 4, new = 8). */
        CNftRule& matchCtState(uint32_t mask);

        /** `fib daddr type local`. */
        CNftRule& matchLocalDestination();

        /** `counter`. */
        CNftRule& counter();

        /** `masquerade`. */
        CNftRule& masquerade();

        /** `dnat ip|ip6 to <address>:<port>` (port 0 keeps the original port). */
        CNftRule& dnat(const SIpAddress& address, uint16_t port);

        /** `accept` / `drop` / `return` / `jump <chain>` / `goto <chain>`. */
        CNftRule& verdict(ENftVerdict code, std::string_view chain = std::string_view());

        /** Returns the encoded expression list (a stream of NFTA_LIST_ELEM attributes). */
        std::vector<uint8_t> expressions() const;

    private:
        /** Opens an expression; returns the token for close(). */
        std::pair<size_t, size_t> open(std::string_view name);

        /** Closes an expression. */
        void close(std::pair<size_t, size_t> token) noexcept;

        /** Adds a cmp expression on register 1. */
        void compare(bool equal, const void* data, size_t length);

        /** Adds a payload load of the network header into register 1. */
        void loadPayload(uint32_t base, uint32_t offset, uint32_t length);

        /** Adds a meta load into register 1. */
        void loadMeta(uint32_t key);

        /** Adds an address prefix match on the network header at `offset`. */
        void matchAddress(const SIpPrefix& prefix, uint32_t offset4, uint32_t offset6, bool equal);
    };

    /**
     * One bridge network as seen by the firewall.
     */
    struct SFirewallNetwork {
        std::string bridge;                 // --> Bridge interface name.
        std::vector<SIpPrefix> subnets;     // --> IPv4 and IPv6 subnets of the network.
        bool masquerade = true;             // --> SNAT traffic leaving through another interface.
        bool icc = true;                    // --> Allow traffic between containers on the bridge.
        bool internal = false;              // --> No traffic in or out of the bridge.
        bool isolate = true;                // --> Drop traffic to other isolated sbox networks.
        bool localhostDnat = true;          // --> Masquerade 127/8 sources DNATed to the bridge.
    };

    /**
     * One published port (Docker -p hostIp:hostPort:containerPort/proto).
     */
    struct SFirewallPortMap {
        std::string bridge;                 // --> Bridge the container sits on.
        uint8_t protocol = 6;               // --> IPPROTO_TCP, IPPROTO_UDP or IPPROTO_SCTP.
        SIpAddress hostIp;                  // --> Host address to match, unset for any.
        uint16_t hostPort = 0;
        SIpAddress containerIp;
        uint16_t containerPort = 0;
    };

    /**
     * Desired firewall state; apply() makes the kernel match it atomically.
     */
    struct SFirewallState {
        std::vector<SFirewallNetwork> networks;
        std::vector<SFirewallPortMap> portMaps;
    };

    /**
     * Rule as read back from the kernel.
     */
    struct SNftRuleInfo {
        std::string chain;
        uint64_t handle = 0;
        std::vector<std::string> expressions;   // --> Expression names in order.
    };

    /**
     * Firewall of libsbox's networks, kept entirely in its own nftables table (inet family,
     * default name "sbox") and never touching other tables.
     *
     * apply() replaces the whole table in one nfnetlink batch ("add table; delete table; add
     * table; chains; rules"), so the update is atomic and idempotent: running it twice with the
     * same state leaves the same ruleset, and a failure leaves the previous ruleset in place.
     */
    class SBOX_API CFirewall {
    private:
        CNetlinkSocket _socket;
        std::string _table;

    public:
        CFirewall();

        /**
         * Opens the NETLINK_NETFILTER socket in `netnsPath` (empty: current namespace).
         * @return SBOX_OK, -ENOTSUP when nfnetlink is unavailable, or another error.
         */
        int32_t open(const std::string& netnsPath = std::string(), std::string table = "sbox") noexcept;

        /** Returns the table name. */
        inline const std::string& table() const noexcept { return _table; }

        /** Returns the kernel's message for the last failure. */
        inline const std::string& lastError() const noexcept { return _socket.lastError(); }

        /**
         * Builds the batch messages that make the table match `state` (exposed for tests and
         * dry runs; apply() sends them).
         */
        static std::vector<CNlMessage> build(const SFirewallState& state, std::string_view table = "sbox");

        /**
         * Builds the batch that removes the table if it exists.
         */
        static std::vector<CNlMessage> buildRemove(std::string_view table = "sbox");

        /**
         * Replaces the table with the ruleset for `state`.
         * @return SBOX_OK, -ENOTSUP when nf_tables (or a needed expression) is unavailable, or
         *         the kernel's error.
         */
        TTask<int32_t> apply(SFirewallState state);

        /**
         * Removes the table (no error when it does not exist).
         */
        TTask<int32_t> remove();

        /**
         * Returns true (1) when the table exists, 0 when not, or a negated errno.
         */
        TTask<int32_t> exists();

        /**
         * Reads the rules of the table.
         */
        TTask<int32_t> listRules(std::vector<SNftRuleInfo>& out);

        /**
         * Sends a prepared batch (messages without the batch begin/end markers).
         */
        TTask<int32_t> send(std::vector<CNlMessage> messages);
    };

}
}

#endif
