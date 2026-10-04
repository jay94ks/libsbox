#ifndef __INCLUDE_SBOX_NET_IPAM_HPP__
#define __INCLUDE_SBOX_NET_IPAM_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <map>

namespace sbox {
namespace net {

    /**
     * One entry of Docker's `default-address-pools`: `base` is split into subnets of `size`.
     */
    struct SAddressPool {
        SIpPrefix base;
        uint8_t size = 0;
    };

    /**
     * Returns Docker's built-in default address pools: 172.17-19.0.0/16 and 172.20-31 (as /14s)
     * split into /16s, then 192.168.0.0/16 split into /20s.
     */
    SBOX_API std::vector<SAddressPool> DefaultAddressPools();

    /**
     * Parses Docker's daemon.json form: [{"base":"10.10.0.0/16","size":24}, ...].
     */
    SBOX_API int32_t ParseAddressPools(const CJson& json, std::vector<SAddressPool>& out);

    /**
     * Address pool (one subnet) managed by CIpam, as persisted in ipam.json.
     */
    struct SIpamPool {
        std::string id;                 // --> "<space>/<subnet>" unless the requester named it.
        std::string space;              // --> Address space ("local", "global", or any label).
        SIpPrefix subnet;
        SIpAddress rangeStart;          // --> First allocatable address (inclusive).
        SIpAddress rangeEnd;            // --> Last allocatable address (inclusive).
        SIpAddress gateway;             // --> Reserved gateway address, unset when none.
        std::vector<SIpAddress> reserved;               // --> Aux addresses never handed out.
        std::map<SIpAddress, std::string> allocated;    // --> Address -> owner (endpoint id).
        SIpAddress last;                // --> Last address handed out (allocation continues after it).
        bool dynamic = false;           // --> Subnet was carved out of the default pools.
        CJson labels;                   // --> Free-form data kept with the pool (object).

        /** Serializes the pool. */
        CJson toJson() const;

        /** Parses a pool. */
        static int32_t fromJson(const CJson& json, SIpamPool& out);
    };

    /**
     * Pool request (Docker RequestPool, CNI ipam ranges, sbox network create).
     */
    struct SIpamRequest {
        std::string id;                 // --> Pool id to use; empty for "<space>/<subnet>".
        std::string space = "local";
        uint8_t family = 4;             // --> 4 or 6 when no subnet is given.
        SIpPrefix subnet;               // --> Explicit subnet; unset to pick one from the pools.
        SIpPrefix range;                // --> Allocate only inside this sub-prefix (Docker --ip-range).
        SIpAddress rangeStart;          // --> Or explicit first address (CNI rangeStart).
        SIpAddress rangeEnd;            // --> Or explicit last address (CNI rangeEnd).
        SIpAddress gateway;             // --> Gateway to reserve; unset to leave none.
        bool reserveGateway = false;    // --> Reserve the first host address as gateway when no gateway is given.
        std::vector<SIpAddress> reserved;
        std::vector<SIpPrefix> avoid;   // --> Subnets a dynamic pool must not overlap (host routes).
        CJson labels;
    };

    /**
     * IP address management with persistent state.
     *
     * State lives in `<stateDir>/ipam.json` (replaced atomically with CFile::writeAtomic) and is
     * guarded by flock on `<stateDir>/ipam.lock`, so concurrent processes (CNI invocations, a
     * plugin daemon, the CLI) can share one directory. Every call is one locked
     * read-modify-write transaction.
     */
    class SBOX_API CIpam {
    private:
        std::string _dir;
        std::vector<SAddressPool> _pools4;
        std::vector<SAddressPool> _pools6;

    public:
        /**
         * Creates a manager over `stateDir` using `pools` (IPv4 and IPv6 entries mixed) for
         * subnets that are not requested explicitly.
         */
        explicit CIpam(std::string stateDir, std::vector<SAddressPool> pools = DefaultAddressPools());

        /** Returns the state directory. */
        inline const std::string& stateDir() const noexcept { return _dir; }

        /**
         * Allocates a pool: the requested subnet (checked for overlaps within the space) or the
         * first free subnet of the default pools.
         * @return SBOX_OK, -EEXIST when the id exists, -EADDRINUSE on overlap, -ENOSPC when the
         *         default pools are exhausted, -EINVAL for inconsistent input.
         */
        TTask<int32_t> requestPool(SIpamRequest request, SIpamPool& out);

        /**
         * Releases a pool and every address in it (-ENOENT when unknown).
         */
        TTask<int32_t> releasePool(std::string id);

        /**
         * Reads a pool (-ENOENT when unknown).
         */
        TTask<int32_t> getPool(std::string id, SIpamPool& out);

        /**
         * Reads every pool.
         */
        TTask<int32_t> listPools(std::vector<SIpamPool>& out);

        /**
         * Allocates an address from a pool.
         * @param preferred Specific address to take (must be free and inside the subnet), or unset.
         * @param owner Free-form owner tag (endpoint/container id) stored with the address.
         * @return SBOX_OK, -EADDRINUSE when `preferred` is taken, -ENOSPC when the pool is full.
         */
        TTask<int32_t> requestAddress(std::string poolId, SIpAddress preferred, std::string owner, SIpAddress& out);

        /**
         * Releases an address (no error when it was not allocated).
         */
        TTask<int32_t> releaseAddress(std::string poolId, SIpAddress address);

        /**
         * Releases every address of `owner` in a pool and returns how many were freed.
         */
        TTask<int32_t> releaseOwner(std::string poolId, std::string owner);

        /**
         * Returns the addresses `owner` holds in a pool.
         */
        TTask<int32_t> findOwner(std::string poolId, std::string owner, std::vector<SIpAddress>& out);

    private:
        /** Loads the state (empty when missing). */
        int32_t load(std::vector<SIpamPool>& pools) const;

        /** Saves the state atomically. */
        int32_t save(const std::vector<SIpamPool>& pools) const;
    };

}
}

#endif
