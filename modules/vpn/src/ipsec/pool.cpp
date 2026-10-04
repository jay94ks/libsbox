#include "pool.hpp"

namespace sbox {
namespace vpn {
namespace ipsec {

    /* Sets the prefix. */
    void AddressPool::reset(const net::SIpPrefix& prefix) {
        _prefix = prefix.isValid() ? prefix.network() : net::SIpPrefix();
        _used.clear();
        _last.clear();
        _cursor = 0;
    }

    /* Usable prefix. */
    bool AddressPool::valid() const noexcept {
        // --> At least a gateway and one client besides network/broadcast.
        return _prefix.isValid() && _prefix.address.isV4() && _prefix.length <= 30;
    }

    /* Gateway. */
    net::SIpAddress AddressPool::gateway() const {
        return _prefix.at(1);
    }

    /* Allocates an address. */
    bool AddressPool::allocate(const std::string& identity, uint64_t owner, const net::SIpAddress& fixed,
                               const net::SIpAddress& requested, net::SIpAddress& out) {
        if (!valid()) {
            return false;
        }

        uint64_t size = _prefix.size();
        auto usable = [&](const net::SIpAddress& a) {
            if (!a.isValid() || !_prefix.contains(a)) {
                return false;
            }

            uint64_t offset = a.distanceFrom(_prefix.address);
            return offset >= 2 && offset + 1 < size;
        };

        auto take = [&](const net::SIpAddress& a) {
            _used[a.toString()] = owner;
            _last[identity] = a.toString();
            out = a;
            return true;
        };

        if (fixed.isValid()) {
            auto it = _used.find(fixed.toString());
            if (it != _used.end() && it->second != owner) {
                return false;
            }

            return take(fixed);
        }

        if (usable(requested) && !_used.count(requested.toString())) {
            return take(requested);
        }

        auto last = _last.find(identity);
        if (last != _last.end() && !_used.count(last->second)) {
            net::SIpAddress a;
            if (net::SIpAddress::parse(last->second, a) == SBOX_OK && usable(a)) {
                return take(a);
            }
        }

        uint64_t hosts = size - 3;
        for (uint64_t i = 0; i < hosts; ++i) {
            uint64_t offset = 2 + (_cursor + i) % hosts;
            net::SIpAddress a = _prefix.at(offset);
            if (!_used.count(a.toString())) {
                _cursor = (_cursor + i + 1) % hosts;
                return take(a);
            }
        }

        return false;
    }

    /* Moves a lease. */
    void AddressPool::transfer(const net::SIpAddress& address, uint64_t owner) {
        auto it = _used.find(address.toString());
        if (it != _used.end()) {
            it->second = owner;
        }
    }

    /* Releases an address. */
    void AddressPool::release(const net::SIpAddress& address, uint64_t owner) {
        auto it = _used.find(address.toString());
        if (it != _used.end() && it->second == owner) {
            _used.erase(it);
        }
    }

}
}
}
