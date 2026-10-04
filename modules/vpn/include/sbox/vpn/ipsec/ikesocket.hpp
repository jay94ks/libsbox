#ifndef __INCLUDE_SBOX_VPN_IPSEC_IKESOCKET_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_IKESOCKET_HPP__

#include <sbox/common.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/span.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> UDP transport of IKE (RFC 7296 2.11, RFC 3948): one socket pair per address family, the
// IKE port (500) and the NAT-T port (4500). On the NAT-T port, IKE messages carry a four-byte
// zero "non-ESP marker" and everything else is ESP-in-UDP, which is either decapsulated by the
// kernel (UDP_ENCAP_ESPINUDP, kernel data path) or handed to an ESP handler (user-space data
// path). The local address of every datagram is recovered with IP_PKTINFO so replies leave from
// the address the peer talked to (needed for NAT detection hashes and multi-homed servers).

namespace sbox {
namespace vpn {

    /**
     * One received IKE message.
     */
    struct SIkeDatagram {
        std::vector<uint8_t> data;      // --> IKE message (non-ESP marker removed).
        SEndpoint remote;
        SEndpoint local;                // --> Destination address and port the peer used.
        bool natT = false;              // --> Arrived on the NAT-T port.
    };

    /**
     * Socket options.
     */
    struct SIkeSocketOptions {
        std::string address;            // --> Bind address (empty: any).
        uint16_t port = 500;            // --> IKE port (0: ephemeral, tests).
        uint16_t natPort = 4500;        // --> NAT-T port (0: ephemeral, tests).
        bool ipv4 = true;
        bool ipv6 = false;
        std::string netnsPath;          // --> Namespace to open the sockets in (empty: current).
    };

    /**
     * Handler of received IKE messages (runs on the event loop).
     */
    using FIkeDatagramHandler = std::function<void(SIkeDatagram& datagram)>;

    /**
     * Handler of ESP-in-UDP packets received on the NAT-T port (user-space data path).
     */
    using FEspPacketHandler = std::function<void(const SReadOnlyByteSpan& esp, const SEndpoint& remote, const SEndpoint& local)>;

    /**
     * IKE UDP sockets (500/4500, IPv4 and optionally IPv6) driven by the calling thread's loop.
     */
    class SBOX_API CIkeSocket {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        CIkeSocket();

        ~CIkeSocket();

        CIkeSocket(const CIkeSocket&) = delete;

        CIkeSocket& operator=(const CIkeSocket&) = delete;

        /**
         * Opens and binds the sockets.
         * @return SBOX_OK or a negated errno (-EADDRINUSE when another IKE daemon runs).
         */
        int32_t open(const SIkeSocketOptions& options);

        /**
         * Starts receiving: spawns one reader per socket on CEventLoop::current().
         */
        void start(FIkeDatagramHandler handler);

        /**
         * Installs the handler for ESP-in-UDP packets (without it they are dropped).
         */
        void espHandler(FEspPacketHandler handler);

        /**
         * Prepares the sockets for the kernel data path: the kernel decapsulates ESP-in-UDP on
         * the NAT-T sockets (UDP_ENCAP_ESPINUDP; IKE messages keep arriving on the socket) and
         * every socket gets IPsec bypass policies so IKE traffic is never protected by the SAs
         * it negotiates.
         */
        int32_t enableKernelEncap();

        /**
         * Sends an IKE message. On the NAT-T port the non-ESP marker is prepended.
         * @param local Source address (and port selecting the socket); an unspecified address
         *        lets the kernel choose.
         */
        int32_t send(const SReadOnlyByteSpan& message, const SEndpoint& local, const SEndpoint& remote, bool natT);

        /**
         * Sends an ESP packet encapsulated in UDP from the NAT-T port (no marker).
         */
        int32_t sendEsp(const SReadOnlyByteSpan& esp, const SEndpoint& local, const SEndpoint& remote);

        /**
         * Sends a NAT keepalive (a single 0xff byte, RFC 3948 2.3) from the NAT-T port.
         */
        int32_t sendKeepalive(const SEndpoint& local, const SEndpoint& remote);

        /** Returns the bound IKE port. */
        uint16_t port() const noexcept;

        /** Returns the bound NAT-T port. */
        uint16_t natPort() const noexcept;

        /** Returns true when open. */
        bool isValid() const noexcept;

        /**
         * Closes the sockets and stops the readers.
         */
        void close() noexcept;
    };

}
}

#endif
