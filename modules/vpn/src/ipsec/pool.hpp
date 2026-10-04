#ifndef __SRC_VPN_IPSEC_POOL_HPP__
#define __SRC_VPN_IPSEC_POOL_HPP__

#include <sbox/net/address.hpp>
#include <map>
#include <string>

namespace sbox {
namespace vpn {
namespace ipsec {

    /**
     * In-memory virtual address pool: the first host of the prefix is the gateway, the rest go
     * to clients. An identity gets its previous address back when it is free (reconnects keep
     * their IP), and fixed per-user addresses are honoured.
     */
    class AddressPool {
    private:
        net::SIpPrefix _prefix;
        std::map<std::string, uint64_t> _used;          // --> Address text -> owner.
        std::map<std::string, std::string> _last;       // --> Identity -> last address text.
        uint64_t _cursor = 0;

    public:
        /** Sets the prefix (resets all leases). */
        void reset(const net::SIpPrefix& prefix);

        /** Returns true when a usable prefix is configured. */
        bool valid() const noexcept;

        /** Returns the gateway address (first host). */
        net::SIpAddress gateway() const;

        /**
         * Allocates an address for `owner`.
         * @param fixed Address that must be used (from the account), or invalid.
         * @param requested Address the client asked for, honoured when free, or invalid.
         * @return true on success.
         */
        bool allocate(const std::string& identity, uint64_t owner, const net::SIpAddress& fixed,
                      const net::SIpAddress& requested, net::SIpAddress& out);

        /** Moves a lease to a new owner (IKE SA rekey). */
        void transfer(const net::SIpAddress& address, uint64_t owner);

        /** Releases an address held by `owner`. */
        void release(const net::SIpAddress& address, uint64_t owner);

        /** Returns the number of leases. */
        inline size_t used() const noexcept { return _used.size(); }
    };

}
}
}

#endif
