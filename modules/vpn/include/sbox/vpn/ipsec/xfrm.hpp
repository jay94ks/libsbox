#ifndef __INCLUDE_SBOX_VPN_IPSEC_XFRM_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_XFRM_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/net/netlink.hpp>
#include <string>
#include <vector>

// --> Kernel IPsec (XFRM) through NETLINK_XFRM: security associations, security policies,
// SPI allocation, owner-scoped flushing, xfrm interfaces (through rtnetlink) and the
// acquire/expire multicast notifications. Shared by the IKEv2 responder and the L2TP/IPsec
// (IKEv1) work stream.

namespace sbox {
namespace vpn {

    /**
     * IPsec mode of an SA or template.
     */
    enum EXfrmMode : uint8_t {
        EXMODE_TRANSPORT = 0,
        EXMODE_TUNNEL = 1,
    };

    /**
     * Policy direction.
     */
    enum EXfrmDir : uint8_t {
        EXDIR_IN = 0,
        EXDIR_OUT = 1,
        EXDIR_FWD = 2,
    };

    /**
     * Policy action.
     */
    enum EXfrmAction : uint8_t {
        EXACT_ALLOW = 0,
        EXACT_BLOCK = 1,
    };

    /**
     * Kind of an XFRM notification.
     */
    enum EXfrmEventType {
        EXEV_UNKNOWN = 0,
        EXEV_ACQUIRE,           // --> An outbound packet matched a policy without an SA.
        EXEV_EXPIRE,            // --> An SA reached a soft or hard lifetime.
        EXEV_POLICY_EXPIRE,     // --> A policy reached a lifetime.
        EXEV_SA_ADDED,
        EXEV_SA_DELETED,
        EXEV_POLICY_ADDED,
        EXEV_POLICY_DELETED,
        EXEV_MAPPING,           // --> NAT mapping of an encapsulated SA changed.
    };

    /** "No limit" value of XFRM byte/packet lifetimes. */
    constexpr uint64_t XFRM_LIFETIME_INFINITE = ~uint64_t(0);

    /** UDP encapsulation type for ESP-in-UDP (RFC 3948). */
    constexpr uint16_t XFRM_ENCAP_ESPINUDP = 2;

    /**
     * Traffic selector of an SA or policy.
     */
    struct SXfrmSelector {
        net::SIpPrefix src;             // --> Invalid address means "any" of the SA/policy family.
        net::SIpPrefix dst;
        uint16_t srcPort = 0;           // --> Host order; 0 with a zero mask means any.
        uint16_t srcPortMask = 0;
        uint16_t dstPort = 0;
        uint16_t dstPortMask = 0;
        uint8_t protocol = 0;
        int32_t ifindex = 0;
    };

    /**
     * Kernel algorithm specification.
     */
    struct SXfrmAlgorithm {
        std::string name;               // --> Empty: not present.
        std::vector<uint8_t> key;
        uint32_t bits = 0;              // --> Truncation (auth) or ICV (AEAD) length in bits.
    };

    /**
     * SA/policy lifetimes.
     */
    struct SXfrmLifetime {
        uint64_t softBytes = XFRM_LIFETIME_INFINITE;
        uint64_t hardBytes = XFRM_LIFETIME_INFINITE;
        uint64_t softPackets = XFRM_LIFETIME_INFINITE;
        uint64_t hardPackets = XFRM_LIFETIME_INFINITE;
        uint64_t softAddSeconds = 0;    // --> 0 means no limit.
        uint64_t hardAddSeconds = 0;
        uint64_t softUseSeconds = 0;
        uint64_t hardUseSeconds = 0;
    };

    /**
     * Netfilter mark match (value/mask).
     */
    struct SXfrmMark {
        uint32_t value = 0;
        uint32_t mask = 0;
    };

    /**
     * One security association.
     */
    struct SXfrmSa {
        net::SIpAddress src;
        net::SIpAddress dst;
        uint32_t spi = 0;               // --> Host order.
        uint8_t protocol = 50;          // --> IPPROTO_ESP.
        EXfrmMode mode = EXMODE_TUNNEL;
        uint32_t reqid = 0;
        SXfrmAlgorithm aead;            // --> rfc4106(gcm(aes)), rfc7539esp(chacha20,poly1305).
        SXfrmAlgorithm crypt;           // --> cbc(aes), cbc(des3_ede).
        SXfrmAlgorithm auth;            // --> hmac(sha1), hmac(sha256), ... (with truncation).
        bool encap = false;             // --> ESP-in-UDP.
        uint16_t encapType = XFRM_ENCAP_ESPINUDP;
        uint16_t encapSport = 4500;
        uint16_t encapDport = 4500;
        uint32_t replayWindow = 32;
        bool esn = false;
        SXfrmLifetime lifetime;
        SXfrmMark mark;
        uint32_t ifId = 0;              // --> xfrm interface id (0: none).
        SXfrmSelector selector;
        uint8_t flags = 0;              // --> XFRM_STATE_* flags.
        // -- Read back from the kernel.
        uint64_t bytes = 0;
        uint64_t packets = 0;
        uint64_t addTime = 0;
        uint64_t useTime = 0;
    };

    /**
     * One template of a policy.
     */
    struct SXfrmTemplate {
        net::SIpAddress src;            // --> Tunnel endpoints (ignored in transport mode).
        net::SIpAddress dst;
        uint8_t protocol = 50;
        EXfrmMode mode = EXMODE_TUNNEL;
        uint32_t reqid = 0;
        uint32_t spi = 0;
        bool optional = false;
    };

    /**
     * One security policy.
     */
    struct SXfrmPolicy {
        SXfrmSelector selector;
        EXfrmDir dir = EXDIR_OUT;
        EXfrmAction action = EXACT_ALLOW;
        uint32_t priority = 0;
        uint32_t index = 0;             // --> Assigned by the kernel.
        std::vector<SXfrmTemplate> templates;
        SXfrmMark mark;
        uint32_t ifId = 0;
        SXfrmLifetime lifetime;
        uint8_t family = 0;             // --> 4 or 6; derived from the selector when 0.
    };

    /**
     * Notification received from the XFRM multicast groups.
     */
    struct SXfrmEvent {
        EXfrmEventType type = EXEV_UNKNOWN;
        bool hard = false;              // --> Hard expiry (the SA/policy is gone).
        SXfrmSa sa;                     // --> EXPIRE, SA_*, ACQUIRE (id/addresses only), MAPPING.
        SXfrmPolicy policy;             // --> POLICY_*, ACQUIRE.
        net::SIpAddress mappedAddress;  // --> MAPPING: new remote address and port.
        uint16_t mappedPort = 0;
    };

    /**
     * Which entries a flush removes: an entry matches when any configured criterion matches.
     */
    struct SXfrmOwner {
        SXfrmMark mark;                 // --> Entries whose mark equals this (mask != 0 enables).
        uint32_t ifId = 0;              // --> Entries with this if_id (0 disables).
        uint32_t reqidMin = 0;          // --> Entries whose reqid is in [min, max] (max != 0 enables).
        uint32_t reqidMax = 0;
    };

    /**
     * What the running kernel supports (filled by CXfrm::probe()).
     */
    struct SXfrmSupport {
        bool netlink = false;           // --> NETLINK_XFRM is available.
        bool esp = false;               // --> ESP SAs can be installed (cbc(aes) + hmac(sha256)).
        bool gcm = false;               // --> rfc4106(gcm(aes)).
        bool chacha = false;            // --> rfc7539esp(chacha20,poly1305).
        bool des3 = false;              // --> cbc(des3_ede).
        bool interfaces = false;        // --> "xfrm" link type.
    };

    /**
     * XFRM netlink client bound to one network namespace.
     *
     * All requests run on the calling thread's CEventLoop and return SBOX_OK or a negated errno
     * (the kernel's extended ACK text of the last failure is in lastError()). A kernel without
     * XFRM yields -ENOTSUP from open().
     */
    class SBOX_API CXfrm {
    private:
        net::CNetlinkSocket _socket;
        std::string _netnsPath;

    public:
        CXfrm() = default;

        CXfrm(CXfrm&&) noexcept = default;

        CXfrm& operator=(CXfrm&&) noexcept = default;

        /**
         * Opens the NETLINK_XFRM socket in `netnsPath` (empty: current namespace).
         * @return SBOX_OK, -ENOTSUP without kernel XFRM, or another error.
         */
        int32_t open(const std::string& netnsPath = std::string()) noexcept;

        /** Returns true when open. */
        inline bool isValid() const noexcept { return _socket.isValid(); }

        /** Returns the kernel's message for the last failure. */
        inline const std::string& lastError() const noexcept { return _socket.lastError(); }

        /**
         * Probes ESP, AEAD algorithms and xfrm interfaces by installing and removing
         * throwaway entries (TEST-NET addresses, a random SPI and mark).
         */
        TTask<int32_t> probe(SXfrmSupport& out);

        /**
         * Allocates a free SPI for an inbound SA (XFRM_MSG_ALLOCSPI). The kernel keeps a
         * larval SA until addSa(..., update = true) completes it (or it times out).
         */
        TTask<int32_t> allocSpi(net::SIpAddress src, net::SIpAddress dst, uint8_t protocol, uint32_t reqid,
                                SXfrmMark mark, uint32_t& spi, uint32_t minSpi = 0x100, uint32_t maxSpi = 0xffffffffu);

        /**
         * Adds an SA (or updates a larval/existing one when `update`).
         */
        TTask<int32_t> addSa(SXfrmSa sa, bool update = false);

        /**
         * Deletes an SA by destination, SPI and protocol (plus source and mark).
         */
        TTask<int32_t> deleteSa(net::SIpAddress src, net::SIpAddress dst, uint32_t spi, uint8_t protocol = 50,
                                SXfrmMark mark = SXfrmMark());

        /**
         * Reads one SA (with its counters).
         */
        TTask<int32_t> getSa(net::SIpAddress dst, uint32_t spi, uint8_t protocol, SXfrmSa& out, SXfrmMark mark = SXfrmMark());

        /**
         * Lists all SAs of the namespace.
         */
        TTask<int32_t> listSas(std::vector<SXfrmSa>& out);

        /**
         * Adds (or with `update`, replaces) a policy.
         */
        TTask<int32_t> addPolicy(SXfrmPolicy policy, bool update = false);

        /**
         * Deletes a policy by selector, direction, mark and if_id.
         */
        TTask<int32_t> deletePolicy(SXfrmSelector selector, EXfrmDir dir, SXfrmMark mark = SXfrmMark(), uint32_t ifId = 0,
                                    uint8_t family = 0);

        /**
         * Lists all policies of the namespace.
         */
        TTask<int32_t> listPolicies(std::vector<SXfrmPolicy>& out);

        /**
         * Removes every SA and policy matching `owner`; entries of other owners stay.
         * @return Number of removed entries, or a negated errno.
         */
        TTask<int32_t> flushOwned(SXfrmOwner owner);

        /**
         * Creates an xfrm interface (link type "xfrm") with `ifId`, optionally bound to an
         * underlying device, in the namespace this object was opened in.
         * @return SBOX_OK, -ENOTSUP when the kernel lacks xfrm interfaces, or another error.
         */
        TTask<int32_t> createInterface(std::string name, uint32_t ifId, int32_t linkIndex = 0);

        /**
         * Parses an XFRM notification message (from CXfrmMonitor or a raw socket).
         * @return true when `msg` was an XFRM notification.
         */
        static bool parseEvent(const net::SNlReply& msg, SXfrmEvent& out);

        /**
         * Returns the kernel algorithm name for an IKE encryption or integrity transform
         * (empty when there is none).
         */
        static std::string encrAlgorithm(uint16_t encr);

        /** Returns the kernel name of an IKE integrity transform (empty when there is none). */
        static std::string integAlgorithm(uint16_t integ);
    };

    /**
     * Subscriber to XFRM multicast notifications (acquire, expire, SA/policy changes).
     */
    class SBOX_API CXfrmMonitor {
    private:
        net::CNetlinkSocket _socket;
        std::vector<SXfrmEvent> _pending;

    public:
        /**
         * Opens a socket in `netnsPath` and joins the acquire, expire and (optionally) SA and
         * policy change groups.
         */
        int32_t open(const std::string& netnsPath = std::string(), bool changes = false) noexcept;

        /** Returns true when open. */
        inline bool isValid() const noexcept { return _socket.isValid(); }

        /**
         * Waits for the next notification.
         * @return SBOX_OK, -ETIMEDOUT, -ECANCELED after close(), or another error.
         */
        TTask<int32_t> next(SXfrmEvent& out, int64_t timeoutMs = -1);

        /**
         * Closes the socket (wakes a pending next()).
         */
        void close() noexcept;
    };

}
}

#endif
