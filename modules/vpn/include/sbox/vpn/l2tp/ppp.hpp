#ifndef __INCLUDE_SBOX_VPN_L2TP_PPP_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_PPP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/net/address.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> PPP (RFC 1661) in user space for L2TP sessions -- no pppd, no kernel PPP: LCP (MRU, magic
// number, authentication protocol, echo keepalive, termination, code/protocol reject),
// authentication (MS-CHAPv2 RFC 2759, CHAP-MD5 RFC 1994, PAP RFC 1334) as authenticator or
// peer, and IPCP (RFC 1332) with RFC 1877 DNS/NBNS options. CCP and IPv6CP are refused with
// Protocol-Reject: IPsec already protects the tunnel, so no MPPE is negotiated. One session is
// a synchronous state machine fed with frames and ticks; IP packets leave through a callback.

namespace sbox {
namespace vpn {

    /**
     * PPP protocol numbers.
     */
    enum EPppProtocol : uint16_t {
        EPPP_IP = 0x0021,
        EPPP_IPV6 = 0x0057,
        EPPP_IPCP = 0x8021,
        EPPP_IPV6CP = 0x8057,
        EPPP_CCP = 0x80fd,
        EPPP_LCP = 0xc021,
        EPPP_PAP = 0xc023,
        EPPP_CHAP = 0xc223,
    };

    /**
     * Authentication methods.
     */
    enum EPppAuth {
        EPPPA_NONE = 0,
        EPPPA_PAP,
        EPPPA_CHAP_MD5,
        EPPPA_MSCHAPV2,
    };

    /**
     * Returns "MS-CHAPv2", "CHAP-MD5", "PAP" or "none".
     */
    SBOX_API const char* PppAuthName(EPppAuth auth) noexcept;

    /**
     * Parses "mschapv2", "chap", "pap" (case-insensitive).
     * @return true on success.
     */
    SBOX_API bool ParsePppAuth(std::string_view text, EPppAuth& out) noexcept;

    /**
     * One account of the authenticator.
     */
    struct SPppUser {
        std::string name;
        std::string password;           // --> Clear text (needed by CHAP-MD5; PAP and MS-CHAPv2 also accept ntHash).
        std::vector<uint8_t> ntHash;    // --> MD4(UTF-16LE(password)).
        std::string address;            // --> Fixed IPv4 address (optional).
    };

    /**
     * Session settings.
     */
    struct SPppConfig {
        bool server = true;                     // --> Authenticator and address assigner.
        std::vector<EPppAuth> auth = { EPPPA_MSCHAPV2 };  // --> Server: allowed, in preference order. Client: acceptable.
        std::vector<SPppUser> users;            // --> Server accounts.
        std::string user;                       // --> Client credentials.
        std::string password;
        std::string name = "sbox";              // --> CHAP name of the authenticator.
        uint16_t mru = 1400;
        net::SIpAddress localAddress;           // --> Server: our IPCP address (the gateway).
        std::vector<net::SIpAddress> dns;       // --> Server: RFC 1877 DNS servers (up to two).
        std::vector<net::SIpAddress> nbns;      // --> Server: WINS servers (up to two).
        uint32_t echoSeconds = 30;              // --> LCP echo interval when the link is idle (0: off).
        uint32_t echoFailures = 4;
        uint32_t restartMs = 3000;              // --> Configure/terminate/challenge retransmission.
        uint32_t maxConfigure = 10;
        uint32_t maxFailure = 5;
        uint32_t maxTerminate = 2;
        uint32_t setupSeconds = 60;             // --> The link must be up within this time.
    };

    /**
     * Negotiated link parameters.
     */
    struct SPppInfo {
        std::string user;                       // --> Authenticated user (server) / our user (client).
        EPppAuth auth = EPPPA_NONE;
        net::SIpAddress localAddress;
        net::SIpAddress peerAddress;
        std::vector<net::SIpAddress> dns;       // --> Client: what the server handed out.
        uint16_t peerMru = 1500;
    };

    /**
     * Assigns the peer's address after authentication (server): user and fixed account address.
     */
    using FPppAllocate = std::function<bool(const std::string& user, const std::string& fixed, net::SIpAddress& out)>;

    /**
     * One PPP link.
     */
    class SBOX_API CPppSession {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CPppSession(SPppConfig config);

        ~CPppSession();

        CPppSession(const CPppSession&) = delete;

        CPppSession& operator=(const CPppSession&) = delete;

        /** Installs the frame sender (address/control FF 03 included). */
        void sender(std::function<void(const SReadOnlyByteSpan&)> send);

        /** Installs the log sink. */
        void logger(std::function<void(const std::string&)> log);

        /** Installs the address allocator (server). */
        void allocator(FPppAllocate allocate);

        /** Called once IPCP is open. */
        void onUp(std::function<void(const SPppInfo&)> handler);

        /** Called once when the link goes down (after being up or failing to come up). */
        void onDown(std::function<void(const std::string&)> handler);

        /** Called for every IPv4 packet received from the peer (after the source check). */
        void onIp(std::function<void(const SReadOnlyByteSpan&)> handler);

        /** Starts LCP negotiation. */
        void start();

        /** Handles one PPP frame (with or without FF 03, compressed protocol field allowed). */
        void input(const SReadOnlyByteSpan& frame);

        /** Runs timers. */
        void tick(int64_t nowMs);

        /**
         * Sends an IPv4 packet to the peer.
         * @return SBOX_OK, -ENOTCONN before IPCP is open, -EMSGSIZE above the peer's MRU.
         */
        int32_t sendIp(const SReadOnlyByteSpan& packet);

        /** Terminates the link (LCP Terminate-Request). */
        void close(const std::string& reason);

        /** Returns true while IPCP is open. */
        bool isUp() const noexcept;

        /** Returns true once the link is finished. */
        bool isDown() const noexcept;

        /** Returns the negotiated parameters. */
        SPppInfo info() const;

        /** Returns the monotonic time (ms) of the last frame received. */
        int64_t lastActivity() const noexcept;
    };

}
}

#endif
