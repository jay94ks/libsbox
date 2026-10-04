#ifndef __INCLUDE_SBOX_VPN_IPSEC_SERVER_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_SERVER_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/datapath.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// --> IKEv2 responder (RFC 7296) for the VPN clients built into Windows, macOS/iOS and Android:
// certificate + EAP-MSCHAPv2, PSK and certificate authentication, configuration payloads with
// an address pool, traffic selector narrowing, CHILD SAs through a data path (XFRM or user-space
// ESP), rekeying, DPD, DELETE, NAT traversal, IKE fragmentation (RFC 7383) and MOBIKE address
// updates (RFC 4555).

namespace sbox {
namespace vpn {

    /**
     * One EAP-MSCHAPv2 account.
     */
    struct SIkeUser {
        std::string name;
        std::string password;               // --> Clear text, or empty when ntHash is set.
        std::vector<uint8_t> ntHash;        // --> MD4(UTF-16LE(password)), 16 bytes.
        std::string address;                // --> Fixed virtual IPv4 address (optional).
    };

    /**
     * One pre-shared key.
     */
    struct SIkePsk {
        std::string id;                     // --> Peer identity it applies to; empty: any peer.
        std::string secret;
    };

    /**
     * Log severities of server events.
     */
    enum EIkeLogLevel {
        EIKE_LOG_DEBUG = 0,
        EIKE_LOG_INFO,
        EIKE_LOG_WARNING,
        EIKE_LOG_ERROR,
    };

    /**
     * Responder configuration.
     */
    struct SIkeServerConfig {
        // -- Transport.
        std::string listenAddress;          // --> Empty: all addresses.
        uint16_t port = 500;
        uint16_t natPort = 4500;
        bool ipv6 = false;                  // --> Also listen on IPv6.
        std::string netnsPath;              // --> Namespace of the sockets and the data path.

        // -- Authentication.
        std::string serverId;               // --> IDr; empty: the certificate's first DNS SAN or subject.
        CIkeCertificate certificate;        // --> Server certificate and key (needed for EAP and cert auth).
        std::vector<CIkeCertificate> caCertificates;    // --> Trust anchors for client certificates.
        std::vector<SIkeUser> users;        // --> EAP-MSCHAPv2 accounts.
        std::vector<SIkePsk> psks;
        bool eapIdentity = true;            // --> Ask EAP-Identity first (Windows sends its IP as IDi).
        bool strictCertificateId = true;    // --> IDi must be bound to the client certificate.

        // -- Addressing.
        net::SIpPrefix pool;                // --> Virtual addresses; the first host is the gateway.
        std::vector<net::SIpAddress> dns;
        std::vector<net::SIpAddress> nbns;
        std::string dnsDomain;
        std::vector<net::SIpPrefix> routes; // --> Split tunnel prefixes; empty: everything (0.0.0.0/0).
        std::vector<net::SIpPrefix> remoteSubnets;  // --> Allowed initiator selectors without CP (site-to-site).

        // -- Algorithms.
        std::vector<SIkeProposal> ikeProposals;     // --> Empty: DefaultIkeProposals().
        std::vector<SIkeProposal> espProposals;     // --> Empty: DefaultEspProposals().

        // -- Data path and network attachment.
        SIpsecDataPathOptions dataPath;     // --> Interface addresses/routes are derived from the pool.
        std::string bridge;                 // --> Answer ARP on this bridge for pool addresses (proxy ARP).
        bool forwarding = true;             // --> Enable net.ipv4.ip_forward in the namespace.

        // -- Timers and limits.
        uint32_t dpdSeconds = 30;           // --> Liveness check after this much silence (0: off).
        uint32_t ikeLifetimeSeconds = 86400;    // --> Hard limit when the client never rekeys.
        uint32_t halfOpenSeconds = 60;
        uint32_t cookieThreshold = 64;      // --> Half-open SAs before COOKIE is demanded.
        uint32_t retransmitTries = 5;
        uint32_t retransmitBaseMs = 2000;
        uint32_t maxSessions = 1024;
        size_t fragmentSize = 1280;         // --> Largest IKE message before RFC 7383 fragmentation.
        bool forceEncap = false;            // --> Pretend a NAT so clients always use UDP 4500.
        bool mobike = true;
    };

    /**
     * Parses a JSON configuration (see docs/vpn-ipsec.md for the schema). Relative file names
     * are resolved against `baseDir`.
     * @param error Receives a description of the first problem.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseIkeServerConfig(const CJson& json, SIkeServerConfig& out, std::string* error = nullptr,
                                          const std::string& baseDir = std::string());

    /**
     * Snapshot of one CHILD SA.
     */
    struct SIkeChildInfo {
        uint32_t inboundSpi = 0;
        uint32_t outboundSpi = 0;
        std::string proposal;
        std::vector<std::string> localTs;
        std::vector<std::string> remoteTs;
    };

    /**
     * Snapshot of one IKE SA.
     */
    struct SIkeSessionInfo {
        uint64_t spiI = 0;
        uint64_t spiR = 0;
        std::string state;
        std::string identity;               // --> Authenticated identity (EAP user, PSK id, certificate subject).
        std::string remote;                 // --> Peer address and port.
        std::string virtualIp;
        std::string proposal;
        bool nat = false;
        int64_t establishedMs = 0;          // --> Monotonic time of establishment.
        std::vector<SIkeChildInfo> children;
    };

    /**
     * IKEv2 responder bound to the calling thread's event loop.
     */
    class SBOX_API CIkeServer {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CIkeServer(SIkeServerConfig config);

        ~CIkeServer();

        CIkeServer(const CIkeServer&) = delete;

        CIkeServer& operator=(const CIkeServer&) = delete;

        /**
         * Installs the log sink (level, message).
         */
        void logger(std::function<void(EIkeLogLevel, const std::string&)> sink);

        /**
         * Opens the sockets, starts the data path and begins serving.
         * @param dataPath An already created data path to use (null: create one from the
         *        configuration).
         * @return SBOX_OK or a negated errno.
         */
        TTask<int32_t> start(IIpsecDataPathPtr dataPath = nullptr);

        /**
         * Sends DELETE to every peer, removes all SAs and stops.
         */
        TTask<void> stop();

        /** Returns the bound IKE port. */
        uint16_t port() const noexcept;

        /** Returns the bound NAT-T port. */
        uint16_t natPort() const noexcept;

        /** Returns the data path in use (after start). */
        IIpsecDataPathPtr dataPath() const;

        /** Returns a snapshot of the IKE SAs. */
        std::vector<SIkeSessionInfo> sessions() const;

        /**
         * Deletes the IKE SAs of an identity or virtual address (sends DELETE).
         * @return Number of sessions removed.
         */
        TTask<int32_t> disconnect(std::string identityOrAddress);
    };

}
}

#endif
