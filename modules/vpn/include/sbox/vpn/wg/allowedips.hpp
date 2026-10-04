#ifndef __INCLUDE_SBOX_VPN_WG_ALLOWEDIPS_HPP__
#define __INCLUDE_SBOX_VPN_WG_ALLOWEDIPS_HPP__

#include <sbox/common.hpp>
#include <sbox/net/address.hpp>

namespace sbox {
namespace vpn {

    /**
     * Cryptokey routing table: maps IPv4/IPv6 prefixes to an owner (a peer) and answers
     * longest-prefix-match lookups (WireGuard's "allowed IPs").
     *
     * One binary trie per family, nodes kept in a vector and recycled through a free list, so a
     * lookup walks at most 32/128 nodes and never allocates. A prefix has exactly one owner:
     * inserting a prefix that another owner holds moves it, as `wg set ... allowed-ips` does.
     * Owner values are opaque non-zero integers chosen by the caller.
     */
    class SBOX_API CWgAllowedIps {
    private:
        struct SNode {
            uint32_t child[2];      // --> Node indices, 0 for none (index 0 is never a child).
            uint64_t value;         // --> Owner, 0 when no prefix ends here.
        };

        std::vector<SNode> _nodes;
        std::vector<uint32_t> _free;
        uint32_t _root4;
        uint32_t _root6;
        size_t _count;

    public:
        CWgAllowedIps();

        /**
         * Adds (or moves) a prefix to `value`. Host bits are ignored.
         * @return SBOX_OK, or -EINVAL for an invalid prefix or a zero value.
         */
        int32_t insert(const net::SIpPrefix& prefix, uint64_t value);

        /**
         * Removes one prefix.
         * @return true when it existed.
         */
        bool remove(const net::SIpPrefix& prefix);

        /**
         * Removes every prefix of an owner.
         * @return How many were removed.
         */
        size_t removeValue(uint64_t value);

        /**
         * Returns the owner of the longest prefix containing `address`, or 0.
         */
        uint64_t lookup(const net::SIpAddress& address) const noexcept;

        /**
         * Same as lookup() on raw network order address bytes (4 or 16 of them).
         */
        uint64_t lookup(const uint8_t* address, uint8_t family) const noexcept;

        /**
         * Returns the prefixes of an owner (IPv4 first, then IPv6, in trie order).
         */
        std::vector<net::SIpPrefix> prefixes(uint64_t value) const;

        /** Returns the number of prefixes. */
        inline size_t size() const noexcept { return _count; }

        /**
         * Removes everything.
         */
        void clear();

    private:
        /** Allocates a node. */
        uint32_t allocate();

        /** Walks the trie collecting prefixes of `value`. */
        void collect(uint32_t node, uint8_t family, uint8_t* bits, uint32_t depth, uint64_t value,
            std::vector<net::SIpPrefix>& out) const;

        /** Removes values under `node` and prunes empty nodes; returns true when `node` is empty. */
        bool prune(uint32_t node, uint64_t value, size_t& removed);
    };

    /**
     * Sliding anti-replay window for transport counters (RFC 6479 bitmap): 8192 bits, of which
     * 8128 are usable, which comfortably exceeds the 2048 the whitepaper asks for.
     */
    class SBOX_API CWgReplayWindow {
    public:
        static constexpr uint64_t WORDS = 128;
        static constexpr uint64_t BITS_TOTAL = WORDS * 64;
        static constexpr uint64_t WINDOW = BITS_TOTAL - 64;

    private:
        uint64_t _top;          // --> One more than the greatest counter accepted (0: none yet).
        uint64_t _bitmap[WORDS];

    public:
        CWgReplayWindow() noexcept;

        /**
         * Accepts a counter that was not seen before and is inside the window, recording it.
         * @param limit Counters at or above this are refused (REJECT_AFTER_MESSAGES).
         * @return true when the counter is fresh.
         */
        bool accept(uint64_t counter, uint64_t limit = ~uint64_t(0)) noexcept;

        /**
         * Forgets every counter.
         */
        void reset() noexcept;
    };

}
}

#endif
