#ifndef __INCLUDE_SBOX_VPN_WG_ENGINE_HPP__
#define __INCLUDE_SBOX_VPN_WG_ENGINE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/wg/key.hpp>
#include <functional>
#include <memory>

namespace sbox {
namespace vpn {

    /** Bytes a data message adds in front of the plaintext (type, receiver, counter). */
    constexpr size_t WG_DATA_HEADROOM = 16;

    /** Room a data message needs after the plaintext: up to 15 padding bytes and the 16-byte tag. */
    constexpr size_t WG_DATA_TAILROOM = 32;

    /**
     * Worst-case encapsulation overhead on the underlay: IPv6 header (40) + UDP (8) + data
     * header (16) + tag (16). The tunnel MTU should be the underlay MTU minus this (1500 -> 1420).
     */
    constexpr uint32_t WG_OVERHEAD = 80;

    /** Default tunnel MTU (an Ethernet underlay minus WG_OVERHEAD). */
    constexpr uint32_t WG_DEFAULT_MTU = 1420;

    /** Default UDP port of WireGuard. */
    constexpr uint16_t WG_DEFAULT_PORT = 51820;

    /**
     * Protocol timing constants (whitepaper section 6.1). Exposed so tests can shorten them;
     * production code keeps the defaults, which interoperate with every other implementation.
     */
    struct SWgTimers {
        int64_t rekeyAfterTimeMs = 120000;
        int64_t rejectAfterTimeMs = 180000;
        int64_t rekeyAttemptTimeMs = 90000;
        int64_t rekeyTimeoutMs = 5000;
        int64_t keepaliveTimeoutMs = 10000;
        int64_t cookieRefreshMs = 120000;       // --> Lifetime of the cookie secret and of received cookies.
        uint64_t rekeyAfterMessages = uint64_t(1) << 60;
        uint64_t rejectAfterMessages = ~uint64_t(0) - (uint64_t(1) << 13);
    };

    /**
     * Configuration of one peer, used both for complete descriptions (configuration files) and
     * for partial updates (`wg set`, the UAPI, netlink). Unset fields leave the current value.
     */
    struct SWgPeerConfig {
        SWgKey publicKey;
        SWgKey presharedKey;            // --> Unset: unchanged (none for a new peer); all-zero removes it.
        SEndpoint endpoint;             // --> Unset: unchanged (unknown until the peer reaches us).
        std::string endpointHost;       // --> The endpoint as written ("vpn.example.com:51820") when it needs resolving.
        std::vector<net::SIpPrefix> allowedIps;
        int32_t persistentKeepalive = -1;   // --> Seconds; 0 disables; -1 leaves it unchanged.
        bool replaceAllowedIps = true;  // --> Replace the list instead of adding to it.
        bool remove = false;            // --> Remove the peer.
        bool updateOnly = false;        // --> Do not create the peer when it does not exist.
    };

    /**
     * Run-time view of a peer (`wg show`).
     */
    struct SWgPeerStatus {
        SWgKey publicKey;
        bool hasPresharedKey = false;
        SEndpoint endpoint;
        std::vector<net::SIpPrefix> allowedIps;
        uint16_t persistentKeepalive = 0;
        int64_t lastHandshakeSec = 0;   // --> Wall clock of the last completed handshake, 0 for never.
        int64_t lastHandshakeNsec = 0;
        uint64_t rxBytes = 0;
        uint64_t txBytes = 0;
        uint32_t protocolVersion = 1;
    };

    /**
     * Counters of the user-space engine (diagnostics and tests).
     */
    struct SWgEngineStats {
        uint64_t initiationsSent = 0;
        uint64_t responsesSent = 0;
        uint64_t sessionsDerived = 0;
        uint64_t cookieRepliesSent = 0;
        uint64_t cookieRepliesReceived = 0;
        uint64_t keepalivesSent = 0;
        uint64_t dataSent = 0;
        uint64_t dataReceived = 0;
        uint64_t invalidMac = 0;            // --> Handshake messages with a bad MAC1 or failed decryption.
        uint64_t replayed = 0;              // --> Data or initiations rejected as replays.
        uint64_t noRoute = 0;               // --> Packets from the tunnel interface without a peer.
        uint64_t invalidSource = 0;         // --> Decrypted packets whose source is not an allowed IP.
        uint64_t rateLimited = 0;
        uint64_t dropped = 0;               // --> Other drops (malformed, unknown index, expired keys).
    };

    /**
     * Where the engine's output goes. The user-space device implements it over a UDP socket and a
     * TUN device; tests implement it over an in-memory "network".
     */
    class SBOX_API IWgOutput {
    public:
        virtual ~IWgOutput() = default;

        /**
         * Sends one UDP datagram.
         * @param stable True when `bytes` lives in the buffer the caller passed to the engine
         *        call that produced it (valid until that caller's batch ends); false when it lives
         *        in engine-owned memory that is only valid during this call.
         */
        virtual void sendDatagram(const SEndpoint& to, const SReadOnlyByteSpan& bytes, bool stable) = 0;

        /**
         * Delivers one decrypted IP packet to the tunnel interface (valid during the call only).
         */
        virtual void writePacket(const SReadOnlyByteSpan& packet) = 0;
    };

    /**
     * Options of CWgEngine.
     */
    struct SWgEngineOptions {
        SWgTimers timers;
        std::function<int64_t()> clock;     // --> Monotonic milliseconds; empty: CEventLoop::nowMs.
        uint32_t mtu = WG_DEFAULT_MTU;      // --> Tunnel MTU; bounds the padding.
        size_t maxStagedPackets = 128;      // --> Per peer, while a handshake is in progress.
        uint32_t underLoadThreshold = 256;  // --> Handshake messages per second that switch cookies on.
        uint32_t handshakeRatePerSecond = 20;   // --> Per source address while under load.
        uint32_t handshakeBurst = 5;
    };

    /**
     * Fixed-size packet buffers recycled through a free list, so the data path does not allocate
     * per packet.
     */
    class SBOX_API CWgBufferPool {
    private:
        size_t _bufferSize;
        size_t _maxBuffers;
        size_t _allocated;
        std::vector<uint8_t*> _free;

    public:
        /**
         * Creates a pool of buffers of `bufferSize` bytes, at most `maxBuffers` of them.
         */
        CWgBufferPool(size_t bufferSize, size_t maxBuffers);

        CWgBufferPool(const CWgBufferPool&) = delete;

        CWgBufferPool& operator=(const CWgBufferPool&) = delete;

        ~CWgBufferPool();

        /** Returns the size of every buffer. */
        inline size_t bufferSize() const noexcept { return _bufferSize; }

        /** Returns how many buffers exist (free or in use). */
        inline size_t allocated() const noexcept { return _allocated; }

        /**
         * Takes a buffer; nullptr when the pool is exhausted.
         */
        uint8_t* acquire() noexcept;

        /**
         * Returns a buffer taken with acquire().
         */
        void release(uint8_t* buffer) noexcept;
    };

    /**
     * The WireGuard protocol in user space, free of I/O: the Noise_IKpsk2 handshake, cookies
     * under load, transport encryption with replay protection, cryptokey routing, roaming and the
     * timer state machine. It reacts to datagrams from the underlay, packets from the tunnel
     * interface and the passing of time, and emits through IWgOutput.
     *
     * Single-threaded. All times come from the clock in SWgEngineOptions; runTimers() must be
     * called once the clock reaches nextDeadline().
     */
    class SBOX_API CWgEngine {
    private:
        struct SImpl;
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates an engine emitting into `output` (which must outlive it).
         */
        explicit CWgEngine(IWgOutput* output, SWgEngineOptions options = SWgEngineOptions());

        CWgEngine(const CWgEngine&) = delete;

        CWgEngine& operator=(const CWgEngine&) = delete;

        ~CWgEngine();

        /**
         * Sets the private key. Existing sessions are dropped; a peer with the matching public key
         * is removed (a device never peers with itself).
         * @return SBOX_OK or -EINVAL. An unset key removes the identity.
         */
        int32_t privateKey(const SWgKey& key);

        /** Returns the private key (unset when none). */
        SWgKey privateKey() const;

        /** Returns the public key (unset when no private key). */
        SWgKey publicKey() const;

        /**
         * Adds, updates or removes a peer (see SWgPeerConfig for the partial update rules).
         * @return SBOX_OK, -EINVAL for an unset public key.
         */
        int32_t setPeer(const SWgPeerConfig& config);

        /**
         * Removes a peer.
         * @return SBOX_OK or -ENOENT.
         */
        int32_t removePeer(const SWgKey& publicKey);

        /**
         * Removes every peer.
         */
        void removeAllPeers();

        /**
         * Returns the status of every peer, in insertion order.
         */
        std::vector<SWgPeerStatus> peers() const;

        /**
         * Returns the status of one peer.
         * @return SBOX_OK or -ENOENT.
         */
        int32_t peer(const SWgKey& publicKey, SWgPeerStatus& out) const;

        /**
         * Handles a datagram from the underlay. The data is decrypted in place.
         */
        void receiveDatagram(const SEndpoint& from, uint8_t* data, size_t length);

        /**
         * Handles an IP packet from the tunnel interface, encrypting it in place.
         * @param buffer Start of the buffer; the packet starts at buffer + WG_DATA_HEADROOM.
         * @param length Packet length.
         * @param capacity Total buffer size (at least WG_DATA_HEADROOM + length + WG_DATA_TAILROOM
         *        for the packet to be sent).
         */
        void sendPacket(uint8_t* buffer, size_t length, size_t capacity);

        /**
         * Runs the timers that are due.
         */
        void runTimers();

        /**
         * Returns the earliest time (clock milliseconds) runTimers() has work to do; INT64_MAX
         * when idle. May be earlier than necessary, never later.
         */
        int64_t nextDeadline() const noexcept;

        /**
         * Starts a handshake with a peer now (subject to the one-per-REKEY_TIMEOUT rate limit).
         * @return SBOX_OK, -ENOENT, or -EDESTADDRREQ when the peer has no endpoint.
         */
        int32_t initiateHandshake(const SWgKey& publicKey);

        /**
         * Forces (or stops forcing) the under-load state in which handshakes need a cookie.
         */
        void forceUnderLoad(bool on) noexcept;

        /** Returns the tunnel MTU used for padding. */
        uint32_t mtu() const noexcept;

        /** Sets the tunnel MTU used for padding. */
        void mtu(uint32_t value) noexcept;

        /** Returns the counters. */
        const SWgEngineStats& stats() const noexcept;
    };

}
}

#endif
