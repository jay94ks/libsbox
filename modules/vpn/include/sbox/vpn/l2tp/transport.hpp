#ifndef __INCLUDE_SBOX_VPN_L2TP_TRANSPORT_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_TRANSPORT_HPP__

#include <sbox/common.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <functional>
#include <memory>
#include <string>

// --> How L2TP datagrams (UDP 1701) reach the L2TP code. With IPsec they travel in ESP
// transport mode: either the kernel decrypts them (XFRM transport SAs plus policies for UDP
// 1701, then an ordinary UDP socket) or, on kernels without ESP, user space does: ESP from a raw
// IPPROTO_ESP socket or from the NAT-T port (RFC 3948 UDP encapsulation) is decrypted with
// CEspSa, the UDP header is checked against the negotiated selectors, and the L2TP payload is
// delivered together with the channel (the SA pair) it came through. A plain UDP transport
// without IPsec exists for tests and for IPsec terminated elsewhere.

namespace sbox {
namespace vpn {

    /**
     * Transport implementations.
     */
    enum EL2tpTransportKind {
        EL2TK_AUTO = 0,         // --> Kernel when it can install ESP SAs, else user space.
        EL2TK_KERNEL,           // --> XFRM transport SAs + UDP socket on 1701.
        EL2TK_USER,             // --> User-space ESP transport mode.
        EL2TK_PLAIN,            // --> UDP 1701 without IPsec (tests, external IPsec).
    };

    /**
     * Parses "auto", "kernel", "user", "none"/"plain".
     */
    SBOX_API bool ParseL2tpTransportKind(std::string_view text, EL2tpTransportKind& out) noexcept;

    /**
     * Where an L2TP datagram came from / goes to.
     */
    struct SL2tpPeer {
        uint64_t channel = 0;       // --> SA pair (ESP) or remote address (UDP) the datagram used.
        SEndpoint remote;           // --> Peer's L2TP address and UDP port.
    };

    /**
     * Receives one L2TP datagram (UDP payload).
     */
    using FL2tpReceive = std::function<void(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload)>;

    /**
     * Transport options.
     */
    struct SL2tpTransportOptions {
        EL2tpTransportKind kind = EL2TK_AUTO;
        std::string netnsPath;
        std::string address;        // --> Bind address of the UDP socket (kernel/plain); empty: any.
        uint16_t port = 1701;       // --> Our L2TP port (0: ephemeral, plain tests only).
        bool ipv6 = false;
        CIkeSocket* ikeSocket = nullptr;    // --> NAT-T socket (ESP-in-UDP send/receive, kernel encap).
        bool kernelEncap = true;    // --> Kernel: enable UDP_ENCAP on the IKE socket (false when its owner did).
        uint32_t reqidBase = 0x5c000000u;   // --> Kernel: reqid range of this owner.
    };

    /**
     * Statistics of a channel.
     */
    struct SL2tpChannelInfo {
        uint64_t channel = 0;
        std::string remote;         // --> Outer peer address (and NAT-T port).
        bool encap = false;
        size_t sas = 0;
        uint64_t inPackets = 0;
        uint64_t outPackets = 0;
    };

    /**
     * An L2TP transport.
     */
    class SBOX_API IL2tpTransport {
    public:
        virtual ~IL2tpTransport() = default;

        /** Returns "kernel", "user" or "plain". */
        virtual const char* kind() const noexcept = 0;

        /** Installs the receive handler (before start). */
        virtual void receiver(FL2tpReceive handler) = 0;

        /** Called when the last SA of a channel is removed. */
        virtual void onChannelDown(std::function<void(uint64_t)> handler) = 0;

        /** Opens sockets and starts the readers on the current loop. */
        virtual TTask<int32_t> start() = 0;

        /** Removes every SA and closes everything. */
        virtual TTask<void> stop() = 0;

        /**
         * Sends one L2TP datagram to `peer` (through the channel's newest SA).
         * @return SBOX_OK, -ENOENT (channel gone), or a send error.
         */
        virtual int32_t send(const SL2tpPeer& peer, const SReadOnlyByteSpan& payload) = 0;

        /** Installs an SA pair negotiated by IKEv1 (plain: -ENOTSUP). */
        virtual TTask<int32_t> addSa(SIkev1IpsecSa sa) = 0;

        /** Removes an SA pair. */
        virtual TTask<int32_t> removeSa(SIkev1IpsecSa sa) = 0;

        /** Returns the channel an installed SA belongs to (0: none). */
        virtual uint64_t channelOf(const SIkev1IpsecSa& sa) const = 0;

        /** Returns the bound L2TP UDP port (0 for user space). */
        virtual uint16_t port() const noexcept = 0;

        /** Returns the channels. */
        virtual std::vector<SL2tpChannelInfo> channels() const = 0;
    };

    using IL2tpTransportPtr = std::shared_ptr<IL2tpTransport>;

    /**
     * Creates a transport; EL2TK_AUTO probes the kernel for ESP SA support first.
     * @return SBOX_OK, -ENOTSUP when the requested kind cannot run here.
     */
    SBOX_API TTask<int32_t> CreateL2tpTransport(SL2tpTransportOptions options, IL2tpTransportPtr& out);

    /**
     * Computes the UDP checksum of a segment for IPv4 or IPv6 pseudo-header addresses (the
     * checksum field inside `segment` must be zero).
     */
    SBOX_API uint16_t L2tpUdpChecksum(const net::SIpAddress& src, const net::SIpAddress& dst, const SReadOnlyByteSpan& segment) noexcept;

}
}

#endif
