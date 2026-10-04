#ifndef __INCLUDE_SBOX_NET_DHCP_HPP__
#define __INCLUDE_SBOX_NET_DHCP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <map>

namespace sbox {
namespace net {

    /**
     * DHCP message types (option 53).
     */
    enum EDhcpType : uint8_t {
        EDHCP_INVALID  = 0,
        EDHCP_DISCOVER = 1,
        EDHCP_OFFER    = 2,
        EDHCP_REQUEST  = 3,
        EDHCP_DECLINE  = 4,
        EDHCP_ACK      = 5,
        EDHCP_NAK      = 6,
        EDHCP_RELEASE  = 7,
        EDHCP_INFORM   = 8,
    };

    /**
     * DHCPv4 message (RFC 2131 BOOTP layout plus RFC 2132 options).
     */
    struct SBOX_API SDhcpMessage {
        uint8_t op = 1;                 // --> 1 BOOTREQUEST, 2 BOOTREPLY.
        uint32_t xid = 0;
        uint16_t secs = 0;
        uint16_t flags = 0;             // --> 0x8000 asks the server to broadcast its reply.
        SIpAddress ciaddr;
        SIpAddress yiaddr;
        SIpAddress siaddr;
        SIpAddress giaddr;
        SMacAddress chaddr;
        std::map<uint8_t, std::vector<uint8_t>> options;    // --> Option code -> raw value.

        /** Returns the message type (option 53). */
        EDhcpType type() const noexcept;

        /** Sets the message type (option 53). */
        void type(EDhcpType value);

        /** Sets an option to raw bytes. */
        void setOption(uint8_t code, const void* data, size_t length);

        /** Sets an option to one IPv4 address. */
        void setAddress(uint8_t code, const SIpAddress& address);

        /** Sets an option to a big-endian u32. */
        void setU32(uint8_t code, uint32_t value);

        /** Returns an option's first IPv4 address, or an unset address. */
        SIpAddress address(uint8_t code) const noexcept;

        /** Returns every IPv4 address of a list option. */
        std::vector<SIpAddress> addresses(uint8_t code) const;

        /** Returns a big-endian u32 option, or `fallback`. */
        uint32_t u32(uint8_t code, uint32_t fallback = 0) const noexcept;

        /** Returns a string option. */
        std::string text(uint8_t code) const;

        /**
         * Encodes the message (minimum 300 bytes as BOOTP requires).
         */
        std::vector<uint8_t> encode() const;

        /**
         * Decodes a message.
         * @return SBOX_OK or -EBADMSG.
         */
        static int32_t decode(const uint8_t* data, size_t length, SDhcpMessage& out);
    };

    /**
     * Lease obtained from a DHCP server.
     */
    struct SBOX_API SDhcpLease {
        SIpAddress address;
        uint8_t prefixLength = 24;
        SIpAddress router;
        std::vector<SIpAddress> dns;
        std::string domain;
        SIpAddress server;              // --> Server identifier (option 54).
        SMacAddress serverMac;          // --> Link-layer source of the server's replies.
        uint32_t leaseTime = 0;         // --> Seconds.
        uint32_t renewTime = 0;         // --> T1 seconds (default lease / 2).
        uint32_t rebindTime = 0;        // --> T2 seconds (default lease * 7 / 8).
        uint32_t mtu = 0;
        int64_t acquiredAt = 0;         // --> Wall clock seconds when the lease was (re)acquired.

        /** Returns the address with its prefix. */
        inline SIpPrefix prefix() const noexcept { return SIpPrefix(address, prefixLength); }

        /** Serializes the lease. */
        CJson toJson() const;

        /** Parses a lease. */
        static int32_t fromJson(const CJson& json, SDhcpLease& out);
    };

    /**
     * DHCPv4 client for one interface (macvlan/ipvlan "physical IP" allocation).
     *
     * Uses an AF_PACKET datagram socket bound to the interface, so it works before the interface
     * has any address and without binding UDP port 68 (several containers may run clients at
     * once). IP and UDP headers are built here; requests are broadcast until the server is
     * known and unicast to its MAC afterwards (RENEW, RELEASE).
     *
     * Leases must be renewed by a long-lived owner (a daemon) calling renew() at renewTime;
     * one-shot callers (CNI ADD) acquire, and release on DEL.
     */
    class SBOX_API CDhcpClient {
    private:
        CFd _fd;
        int32_t _ifindex;
        SMacAddress _mac;
        std::string _hostname;
        std::string _clientId;

    public:
        CDhcpClient() noexcept;

        /**
         * Opens the client on `ifname` inside `netnsPath` (empty: current namespace).
         * @param mac Hardware address to use; unset reads the interface's.
         */
        int32_t open(const std::string& ifname, const std::string& netnsPath = std::string(), SMacAddress mac = SMacAddress()) noexcept;

        /** Sets the host name sent in option 12. */
        inline void hostname(std::string value) { _hostname = std::move(value); }

        /** Sets the client identifier (option 61); defaults to the hardware address. */
        inline void clientId(std::string value) { _clientId = std::move(value); }

        /** Returns the hardware address in use. */
        inline const SMacAddress& mac() const noexcept { return _mac; }

        /**
         * Runs DISCOVER / OFFER / REQUEST / ACK with retransmissions.
         * @return SBOX_OK, -ETIMEDOUT, or -ECONNREFUSED when every attempt was NAKed.
         */
        TTask<int32_t> acquire(SDhcpLease& out, int64_t timeoutMs = 10000);

        /**
         * Renews a lease with its server (unicast REQUEST in RENEWING state).
         * @return SBOX_OK (lease updated), -ECONNREFUSED on NAK, or -ETIMEDOUT.
         */
        TTask<int32_t> renew(SDhcpLease& lease, int64_t timeoutMs = 5000);

        /**
         * Extends a lease with any server (broadcast REQUEST in REBINDING state).
         */
        TTask<int32_t> rebind(SDhcpLease& lease, int64_t timeoutMs = 5000);

        /**
         * Gives the lease back (unicast RELEASE, no reply expected).
         */
        int32_t release(const SDhcpLease& lease) noexcept;

        /**
         * Closes the socket.
         */
        void close() noexcept;

    private:
        /** Builds a request skeleton. */
        SDhcpMessage makeRequest(EDhcpType type, uint32_t xid) const;

        /** Sends a message (broadcast when `to` is unset). */
        int32_t send(const SDhcpMessage& msg, const SIpAddress& from, const SIpAddress& to, const SMacAddress& toMac) noexcept;

        /** Waits for a reply of `xid` with one of the given types. */
        TTask<int32_t> receive(uint32_t xid, int64_t deadline, SDhcpMessage& out, SMacAddress& from);

        /** Runs one REQUEST exchange (selecting, renewing or rebinding). */
        TTask<int32_t> requestLease(SDhcpMessage request, SDhcpLease& lease, const SIpAddress& from,
            const SIpAddress& to, const SMacAddress& toMac, int64_t timeoutMs);
    };

}
}

#endif
