#ifndef __INCLUDE_SBOX_NET_ADDRESS_HPP__
#define __INCLUDE_SBOX_NET_ADDRESS_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace net {

    /**
     * IPv4 or IPv6 address (network byte order bytes).
     */
    struct SBOX_API SIpAddress {
        uint8_t family;         // --> 0 (none), 4 or 6.
        uint8_t bytes[16];      // --> Address bytes; IPv4 uses the first four.

        /**
         * Constructs an empty (invalid) address.
         */
        SIpAddress() noexcept;

        /** Returns true when an address is set. */
        inline bool isValid() const noexcept { return family == 4 || family == 6; }

        /** Returns true for IPv4. */
        inline bool isV4() const noexcept { return family == 4; }

        /** Returns true for IPv6. */
        inline bool isV6() const noexcept { return family == 6; }

        /** Returns the address length in bytes (4, 16 or 0). */
        inline size_t length() const noexcept { return family == 4 ? 4 : (family == 6 ? 16 : 0); }

        /** Returns the address width in bits (32, 128 or 0). */
        inline uint32_t bits() const noexcept { return uint32_t(length() * 8); }

        /** Returns the socket address family (AF_INET, AF_INET6 or AF_UNSPEC). */
        int afamily() const noexcept;

        /**
         * Parses a numeric IPv4 or IPv6 address (no prefix, no brackets).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SIpAddress& out) noexcept;

        /**
         * Builds an address from raw network order bytes (4 or 16 of them).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t fromBytes(const uint8_t* data, size_t length, SIpAddress& out) noexcept;

        /**
         * Builds an IPv4 address from a host order 32-bit value.
         */
        static SIpAddress fromV4(uint32_t hostOrder) noexcept;

        /**
         * Returns the IPv4 address as a host order value (0 for IPv6).
         */
        uint32_t v4() const noexcept;

        /**
         * Formats the address (RFC 5952 form for IPv6).
         */
        std::string toString() const;

        /**
         * Returns true for the unspecified address (0.0.0.0 / ::).
         */
        bool isUnspecified() const noexcept;

        /**
         * Returns true for loopback addresses (127/8, ::1).
         */
        bool isLoopback() const noexcept;

        /**
         * Returns this address plus `offset` (wrapping inside the address width).
         */
        SIpAddress add(uint64_t offset) const noexcept;

        /**
         * Returns the difference `this - base` when it fits 64 bits and both share a family,
         * otherwise UINT64_MAX.
         */
        uint64_t distanceFrom(const SIpAddress& base) const noexcept;

        /** Compares family then bytes. */
        int32_t compare(const SIpAddress& other) const noexcept;

        /** Returns true when both are equal. */
        inline bool operator==(const SIpAddress& other) const noexcept { return compare(other) == 0; }

        /** Returns true when both differ. */
        inline bool operator!=(const SIpAddress& other) const noexcept { return compare(other) != 0; }

        /** Orders addresses (family first). */
        inline bool operator<(const SIpAddress& other) const noexcept { return compare(other) < 0; }
    };

    /**
     * Address with a prefix length: either a subnet ("10.0.0.0/24") or an interface address
     * ("10.0.0.2/24"), depending on context.
     */
    struct SBOX_API SIpPrefix {
        SIpAddress address;
        uint8_t length;     // --> Prefix length in bits.

        /**
         * Constructs an empty prefix.
         */
        SIpPrefix() noexcept : length(0) {}

        /**
         * Constructs a prefix from an address and a length.
         */
        SIpPrefix(const SIpAddress& addr, uint8_t len) noexcept : address(addr), length(len) {}

        /** Returns true when an address is set and the length fits it. */
        inline bool isValid() const noexcept { return address.isValid() && length <= address.bits(); }

        /**
         * Parses "addr/len". A bare address yields a host prefix (/32 or /128).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SIpPrefix& out) noexcept;

        /**
         * Formats "addr/len".
         */
        std::string toString() const;

        /**
         * Returns the prefix with the host bits cleared.
         */
        SIpPrefix network() const noexcept;

        /**
         * Returns true when the host bits are all zero.
         */
        bool isNetwork() const noexcept;

        /**
         * Returns true when `addr` lies inside this subnet.
         */
        bool contains(const SIpAddress& addr) const noexcept;

        /**
         * Returns true when the two subnets share at least one address.
         */
        bool overlaps(const SIpPrefix& other) const noexcept;

        /**
         * Returns the last address of the subnet (IPv4 broadcast).
         */
        SIpAddress last() const noexcept;

        /**
         * Returns the number of addresses in the subnet, saturated at UINT64_MAX.
         */
        uint64_t size() const noexcept;

        /**
         * Returns the network address plus `offset` (no bounds check against the size).
         */
        SIpAddress at(uint64_t offset) const noexcept;

        /**
         * Builds the netmask address for this prefix length (e.g. 255.255.255.0).
         */
        SIpAddress mask() const noexcept;

        /** Compares address then length. */
        inline bool operator==(const SIpPrefix& other) const noexcept {
            return address == other.address && length == other.length;
        }

        /** Compares address then length. */
        inline bool operator!=(const SIpPrefix& other) const noexcept { return !(*this == other); }
    };

    /**
     * Ethernet MAC address.
     */
    struct SBOX_API SMacAddress {
        uint8_t bytes[6];
        bool valid;

        /**
         * Constructs an empty (invalid) MAC address.
         */
        SMacAddress() noexcept;

        /** Returns true when set. */
        inline bool isValid() const noexcept { return valid; }

        /**
         * Parses "aa:bb:cc:dd:ee:ff" (also accepts '-').
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SMacAddress& out) noexcept;

        /**
         * Builds an address from six raw bytes.
         */
        static SMacAddress fromBytes(const uint8_t* data) noexcept;

        /**
         * Returns a random locally administered unicast address.
         */
        static SMacAddress random() noexcept;

        /**
         * Returns Docker's address derived from an IPv4 address (02:42:a.b.c.d).
         */
        static SMacAddress fromIpv4(const SIpAddress& addr) noexcept;

        /**
         * Formats "aa:bb:cc:dd:ee:ff".
         */
        std::string toString() const;

        /** Compares bytes. */
        bool operator==(const SMacAddress& other) const noexcept;
    };

    /**
     * Fills `out` with random bytes from getrandom(2) (not for key material: libcertpp owns that).
     */
    SBOX_API void RandomBytes(uint8_t* out, size_t length) noexcept;

    /**
     * Returns `length` random lowercase hex characters (identifiers, interface names).
     */
    SBOX_API std::string RandomHex(size_t length);

}
}

#endif
