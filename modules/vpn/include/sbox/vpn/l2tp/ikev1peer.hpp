#ifndef __INCLUDE_SBOX_VPN_L2TP_IKEV1PEER_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_IKEV1PEER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/ikesocket.hpp>
#include <sbox/vpn/ipsec/server.hpp>
#include <sbox/vpn/l2tp/ikev1crypto.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> IKEv1 (RFC 2409) for L2TP/IPsec: Main Mode with pre-shared keys, Quick Mode for ESP
// transport-mode SAs protecting UDP 1701 (also UDP-encapsulated transport, RFC 3947/3948, with
// NAT-OA), informational exchanges (DELETE, DPD R-U-THERE/ACK of RFC 3706, INITIAL-CONTACT),
// retransmission handling and lifetimes. The responder serves the built-in Windows, macOS/iOS
// and Android L2TP/IPsec clients; the initiator exists for tests and host-side clients. Both are
// synchronous state machines: the owner feeds received datagrams and a periodic tick, and
// supplies a send function (normally CIkeSocket, possibly shared with CIkeServer).

namespace sbox {
namespace vpn {

    /**
     * One acceptable / proposed ESP transform of Quick Mode.
     */
    struct SIkev1EspSuite {
        uint8_t espId = EIKE1_ESP_AES;      // --> EIkev1EspId.
        uint16_t keyBits = 256;             // --> AES key length (0 for 3DES).
        uint16_t authAlg = EIKE1_AA_HMAC_SHA1;  // --> EIkev1AuthAlg.
    };

    /**
     * Returns the default Phase 1 suites (our preference order): AES-256/128 and 3DES with
     * SHA-256/SHA-1 (and SHA-384/512), groups 14, 19, 20 and 2 -- what Windows, Apple and
     * Android L2TP clients propose.
     */
    SBOX_API std::vector<SIkev1Suite> DefaultIkev1Suites();

    /**
     * Returns the default ESP suites: AES-256/192/128-CBC and 3DES with HMAC-SHA1, SHA2-256/384/512,
     * plus AES-GCM-16.
     */
    SBOX_API std::vector<SIkev1EspSuite> DefaultIkev1EspSuites();

    /**
     * IKEv1 configuration shared by the responder and the initiator.
     */
    struct SIkev1Config {
        std::vector<SIkePsk> psks;          // --> Responder: candidates (id = peer address/FQDN, empty = any). Initiator: first.
        std::vector<SIkev1Suite> suites;    // --> Acceptable (responder) / proposed (initiator); empty: defaults.
        std::vector<SIkev1EspSuite> esp;    // --> Acceptable / proposed ESP transforms; empty: defaults.
        std::string identity;               // --> Our Phase 1 ID; empty: our IP address.
        uint16_t l2tpPort = 1701;           // --> UDP port Quick Mode selectors must protect on our side.
        bool requireL2tp = true;            // --> Responder: refuse Quick Mode IDs that are not UDP/l2tpPort.
        bool forceEncap = false;            // --> Responder: fake a NAT so clients use UDP 4500 (RFC 3947).
        bool pfs = false;                   // --> Initiator: Quick Mode with KE (group of Phase 1).
        uint32_t phase1LifeSeconds = 28800; // --> Initiator proposal; responder maximum (longer offers are capped).
        uint32_t phase2LifeSeconds = 3600;
        uint32_t dpdSeconds = 30;           // --> Idle time before R-U-THERE (0: off; needs the peer's DPD VID).
        uint32_t dpdTries = 5;
        uint32_t retransmitMs = 1000;       // --> First retransmission delay (doubles).
        uint32_t retransmitTries = 5;
        uint32_t halfOpenSeconds = 30;      // --> Unfinished exchanges are dropped after this.
        uint32_t maxSas = 1024;             // --> ISAKMP SAs (responder).
    };

    /**
     * Log sink of the IKEv1 implementation.
     */
    using FIkev1Log = std::function<void(EIkeLogLevel level, const std::string& message)>;

    /**
     * Sends an IKE message (`natT` selects the NAT-T port and the non-ESP marker).
     */
    using FIkev1Send = std::function<void(const SReadOnlyByteSpan& message, const SEndpoint& local, const SEndpoint& remote, bool natT)>;

    /**
     * A negotiated ESP transport-mode SA pair (both directions) protecting L2TP.
     */
    struct SIkev1IpsecSa {
        uint64_t isakmpId = 0;              // --> Responder cookie of the ISAKMP SA that negotiated it.
        std::string identity;               // --> Peer's Phase 1 identity.
        net::SIpAddress local;              // --> Outer addresses.
        net::SIpAddress remote;
        uint16_t localIkePort = 500;        // --> IKE ports (the NAT-T ports when `encap`).
        uint16_t remoteIkePort = 500;
        bool encap = false;                 // --> UDP-encapsulated ESP (RFC 3948).
        net::SIpAddress localOriginal;      // --> NAT-OA: our address as the peer knows it.
        net::SIpAddress remoteOriginal;     // --> NAT-OA: the peer's own (private) address.
        uint32_t inboundSpi = 0;
        uint32_t outboundSpi = 0;
        uint16_t encr = 0;                  // --> EIkeEncr numbering (CIpsecCipher).
        uint16_t keyBits = 0;
        uint16_t integ = 0;                 // --> EIkeInteg numbering.
        std::vector<uint8_t> inEncKey;
        std::vector<uint8_t> inIntegKey;
        std::vector<uint8_t> outEncKey;
        std::vector<uint8_t> outIntegKey;
        uint8_t protocol = 17;              // --> Selector protocol (0: any).
        uint16_t localPort = 1701;          // --> Selector ports (0: any).
        uint16_t remotePort = 0;
        uint32_t lifeSeconds = 3600;
        std::string proposal;               // --> "ESP AES_CBC_256/HMAC_SHA1_96 transport".
    };

    /**
     * Snapshot of one ISAKMP SA.
     */
    struct SIkev1SessionInfo {
        uint64_t cookieI = 0;
        uint64_t cookieR = 0;
        std::string state;
        std::string identity;
        std::string remote;
        std::string suite;
        bool nat = false;
        size_t ipsecSas = 0;
    };

    /**
     * IKEv1 responder (Main Mode PSK + Quick Mode transport) bound to no socket: feed it
     * datagrams with handle() and call tick() periodically (every 100..1000 ms).
     */
    class SBOX_API CIkev1Responder {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CIkev1Responder(SIkev1Config config);

        ~CIkev1Responder();

        CIkev1Responder(const CIkev1Responder&) = delete;

        CIkev1Responder& operator=(const CIkev1Responder&) = delete;

        /** Installs the send function. */
        void sender(FIkev1Send send);

        /** Installs the log sink. */
        void logger(FIkev1Log log);

        /** Called when a Quick Mode completes (the SA should be installed now). */
        void onSaUp(std::function<void(const SIkev1IpsecSa&)> handler);

        /** Called when an IPsec SA is gone (peer DELETE, expiry, dead peer, replaced peer). */
        void onSaDown(std::function<void(const SIkev1IpsecSa&)> handler);

        /** Handles one received IKEv1 datagram. */
        void handle(const SIkeDatagram& datagram);

        /** Runs timers (retransmissions, DPD, lifetimes) at monotonic time `nowMs`. */
        void tick(int64_t nowMs);

        /**
         * Deletes the IPsec SA with inbound SPI `spi` (sends DELETE, reports it down).
         * @return true when it existed.
         */
        bool deleteIpsecSa(uint32_t inboundSpi);

        /** Sends DELETE for every SA and forgets everything (reports every SA down). */
        void shutdown();

        /** Returns a snapshot of the ISAKMP SAs. */
        std::vector<SIkev1SessionInfo> sessions() const;
    };

    /**
     * IKEv1 initiator: Main Mode PSK then one Quick Mode for UDP 1701 transport mode, with NAT-T
     * floating and DPD answers. For tests and host-side L2TP/IPsec clients.
     */
    class SBOX_API CIkev1Initiator {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        /**
         * @param server Responder address and IKE port.
         * @param serverNatPort Responder NAT-T port (used after floating).
         */
        CIkev1Initiator(SIkev1Config config, SEndpoint server, uint16_t serverNatPort);

        ~CIkev1Initiator();

        CIkev1Initiator(const CIkev1Initiator&) = delete;

        CIkev1Initiator& operator=(const CIkev1Initiator&) = delete;

        /** Installs the send function. */
        void sender(FIkev1Send send);

        /** Installs the log sink. */
        void logger(FIkev1Log log);

        /** Called when the Quick Mode SA is up. */
        void onSaUp(std::function<void(const SIkev1IpsecSa&)> handler);

        /** Called when the IPsec SA is gone. */
        void onSaDown(std::function<void(const SIkev1IpsecSa&)> handler);

        /** Called once when negotiation fails (negated errno and a reason). */
        void onFailed(std::function<void(int32_t, const std::string&)> handler);

        /**
         * Starts Main Mode.
         * @param localAddress Our address towards the server (IDs, NAT detection, NAT-OA).
         * @param localPort Our IKE port; @param localNatPort our NAT-T port.
         */
        void start(const net::SIpAddress& localAddress, uint16_t localPort, uint16_t localNatPort);

        /** Handles one received datagram. */
        void handle(const SIkeDatagram& datagram);

        /** Runs timers. */
        void tick(int64_t nowMs);

        /** Sends DELETE for the SAs and stops. */
        void shutdown();

        /** Returns true once Phase 1 completed. */
        bool phase1Done() const noexcept;

        /** Returns true once the Quick Mode SA is up. */
        bool established() const noexcept;

        /** Returns true when NAT traversal (UDP 4500) is in use. */
        bool natT() const noexcept;

        /** Returns the negotiated Phase 1 suite. */
        SIkev1Suite suite() const;

        /** Returns the last Notify type received from the responder (0: none). */
        uint16_t lastNotify() const noexcept;

        /**
         * Sends a DPD R-U-THERE now (tests).
         * @return The sequence number used, or 0 when not possible.
         */
        uint32_t sendDpd();

        /** Returns the highest R-U-THERE-ACK sequence received. */
        uint32_t dpdAcked() const noexcept;
    };

}
}

#endif
