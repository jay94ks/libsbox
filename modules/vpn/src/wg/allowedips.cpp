#include <sbox/vpn/wg/allowedips.hpp>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    namespace {

        /* Returns bit `i` (0 = most significant) of a network order address. */
        inline uint32_t bitAt(const uint8_t* addr, uint32_t i) noexcept {
            return (addr[i >> 3] >> (7 - (i & 7))) & 1u;
        }

    }

    /* Creates an empty table: node 0 is a sentinel, 1 and 2 are the family roots. */
    CWgAllowedIps::CWgAllowedIps() : _root4(1), _root6(2), _count(0) {
        _nodes.resize(3, SNode{ { 0, 0 }, 0 });
    }

    /* Takes a node from the free list or grows the vector. */
    uint32_t CWgAllowedIps::allocate() {
        if (!_free.empty()) {
            uint32_t n = _free.back();
            _free.pop_back();
            _nodes[n] = SNode{ { 0, 0 }, 0 };
            return n;
        }

        _nodes.push_back(SNode{ { 0, 0 }, 0 });
        return uint32_t(_nodes.size() - 1);
    }

    /* Inserts or moves a prefix. */
    int32_t CWgAllowedIps::insert(const net::SIpPrefix& prefix, uint64_t value) {
        if (!prefix.isValid() || value == 0) {
            return -EINVAL;
        }

        net::SIpPrefix p = prefix.network();
        uint32_t node = p.address.isV4() ? _root4 : _root6;

        for (uint32_t i = 0; i < p.length; ++i) {
            uint32_t b = bitAt(p.address.bytes, i);
            if (_nodes[node].child[b] == 0) {
                // --> allocate() may reallocate the vector: take the index first.
                uint32_t n = allocate();
                _nodes[node].child[b] = n;
            }

            node = _nodes[node].child[b];
        }

        if (_nodes[node].value == 0) {
            ++_count;
        }

        _nodes[node].value = value;
        return SBOX_OK;
    }

    /* Removes one prefix and prunes the path. */
    bool CWgAllowedIps::remove(const net::SIpPrefix& prefix) {
        if (!prefix.isValid()) {
            return false;
        }

        net::SIpPrefix p = prefix.network();
        uint32_t path[129];
        uint32_t node = p.address.isV4() ? _root4 : _root6;
        path[0] = node;

        for (uint32_t i = 0; i < p.length; ++i) {
            node = _nodes[node].child[bitAt(p.address.bytes, i)];
            if (node == 0) {
                return false;
            }

            path[i + 1] = node;
        }

        if (_nodes[node].value == 0) {
            return false;
        }

        _nodes[node].value = 0;
        --_count;

        // --> Free childless, valueless nodes bottom-up (never the root).
        for (uint32_t depth = p.length; depth > 0; --depth) {
            uint32_t n = path[depth];
            const SNode& sn = _nodes[n];
            if (sn.value != 0 || sn.child[0] != 0 || sn.child[1] != 0) {
                break;
            }

            uint32_t parent = path[depth - 1];
            _nodes[parent].child[bitAt(p.address.bytes, depth - 1)] = 0;
            _free.push_back(n);
        }

        return true;
    }

    /* Recursively removes an owner's prefixes. */
    bool CWgAllowedIps::prune(uint32_t node, uint64_t value, size_t& removed) {
        SNode& sn = _nodes[node];
        if (value != 0 && sn.value == value) {
            sn.value = 0;
            ++removed;
        }

        for (uint32_t b = 0; b < 2; ++b) {
            uint32_t c = _nodes[node].child[b];
            if (c != 0 && prune(c, value, removed)) {
                _nodes[node].child[b] = 0;
                _free.push_back(c);
            }
        }

        const SNode& after = _nodes[node];
        return after.value == 0 && after.child[0] == 0 && after.child[1] == 0;
    }

    /* Removes all prefixes of an owner. */
    size_t CWgAllowedIps::removeValue(uint64_t value) {
        size_t removed = 0;
        if (value == 0) {
            return 0;
        }

        prune(_root4, value, removed);
        prune(_root6, value, removed);
        _count -= removed;
        return removed;
    }

    /* Longest prefix match. */
    uint64_t CWgAllowedIps::lookup(const net::SIpAddress& address) const noexcept {
        if (!address.isValid()) {
            return 0;
        }

        return lookup(address.bytes, address.family);
    }

    /* Longest prefix match on raw bytes. */
    uint64_t CWgAllowedIps::lookup(const uint8_t* address, uint8_t family) const noexcept {
        uint32_t node = family == 4 ? _root4 : _root6;
        uint32_t bits = family == 4 ? 32 : 128;
        uint64_t best = _nodes[node].value;

        for (uint32_t i = 0; i < bits; ++i) {
            node = _nodes[node].child[bitAt(address, i)];
            if (node == 0) {
                break;
            }

            if (_nodes[node].value != 0) {
                best = _nodes[node].value;
            }
        }

        return best;
    }

    /* Depth-first collection. */
    void CWgAllowedIps::collect(uint32_t node, uint8_t family, uint8_t* bits, uint32_t depth, uint64_t value,
        std::vector<net::SIpPrefix>& out) const
    {
        const SNode& sn = _nodes[node];
        if (sn.value == value) {
            net::SIpAddress addr;
            net::SIpAddress::fromBytes(bits, family == 4 ? 4 : 16, addr);
            out.push_back(net::SIpPrefix(addr, uint8_t(depth)));
        }

        for (uint32_t b = 0; b < 2; ++b) {
            uint32_t c = sn.child[b];
            if (c == 0) {
                continue;
            }

            uint8_t mask = uint8_t(0x80u >> (depth & 7));
            if (b) {
                bits[depth >> 3] |= mask;
            }
            else {
                bits[depth >> 3] &= uint8_t(~mask);
            }

            collect(c, family, bits, depth + 1, value, out);
            bits[depth >> 3] &= uint8_t(~mask);
        }
    }

    /* Lists an owner's prefixes. */
    std::vector<net::SIpPrefix> CWgAllowedIps::prefixes(uint64_t value) const {
        std::vector<net::SIpPrefix> out;
        if (value == 0) {
            return out;
        }

        uint8_t bits[16];
        std::memset(bits, 0, sizeof(bits));
        collect(_root4, 4, bits, 0, value, out);
        std::memset(bits, 0, sizeof(bits));
        collect(_root6, 6, bits, 0, value, out);
        return out;
    }

    /* Removes everything. */
    void CWgAllowedIps::clear() {
        _nodes.assign(3, SNode{ { 0, 0 }, 0 });
        _free.clear();
        _count = 0;
    }

    /* Empty window. */
    CWgReplayWindow::CWgReplayWindow() noexcept {
        reset();
    }

    /* Forgets everything. */
    void CWgReplayWindow::reset() noexcept {
        _top = 0;
        std::memset(_bitmap, 0, sizeof(_bitmap));
    }

    /* RFC 6479 check-and-set. */
    bool CWgReplayWindow::accept(uint64_t counter, uint64_t limit) noexcept {
        if (counter >= limit || counter == ~uint64_t(0)) {
            return false;
        }

        // --> Work 1-based so that _top == 0 means "nothing seen".
        uint64_t c = counter + 1;
        if (c + WINDOW < _top) {
            return false;
        }

        uint64_t index = c >> 6;
        if (c > _top) {
            uint64_t current = _top >> 6;
            uint64_t steps = index - current;
            if (steps > WORDS) {
                steps = WORDS;
            }

            for (uint64_t i = 1; i <= steps; ++i) {
                _bitmap[(current + i) & (WORDS - 1)] = 0;
            }

            _top = c;
        }

        uint64_t& word = _bitmap[index & (WORDS - 1)];
        uint64_t bit = uint64_t(1) << (c & 63);
        if (word & bit) {
            return false;
        }

        word |= bit;
        return true;
    }

}
}
