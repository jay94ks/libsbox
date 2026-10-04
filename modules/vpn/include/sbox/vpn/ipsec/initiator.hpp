#ifndef __INCLUDE_SBOX_VPN_IPSEC_INITIATOR_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_INITIATOR_HPP__

#include <sbox/common.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/datapath.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <memory>
#include <string>
#include <vector>

// --> Minimal IKEv2 initiator (RFC 7296): PSK, certificate and EAP-MSCHAPv2 authentication, a
// configuration request, one CHILD SA installed through a data path, CHILD/IKE rekeying, DPD and
// DELETE. It exists to test the responder end to end and doubles as a host-to-gateway client.

namespace sbox {
namespace vpn {

    /**
     * How the initiator authenticates.
     */
    enum EIkeInitiatorAuth {
        EIKE_IAUTH_PSK = 0,
        EIKE_IAUTH_EAP,         // --> EAP-MSCHAPv2 (server authenticates with a certificate).
        EIKE_IAUTH_CERT,
    };

    /**
     * Initiator configuration.
     */
    struct SIkeInitiatorConfig {
        std::string server;                 // --> Server address (numeric).
        uint16_t serverPort = 500;
        uint16_t serverNatPort = 4500;
        std::string netnsPath;              // --> Namespace of our sockets.
        std::string identity;               // --> IDi ("@fqdn", "user@domain", address or DN).
        std::string remoteId;               // --> IDr to send and expect (optional).
        EIkeInitiatorAuth auth = EIKE_IAUTH_PSK;
        std::string psk;
        std::string user;                   // --> EAP user name.
        std::string password;
        CIkeCertificate certificate;        // --> Our certificate (EIKE_IAUTH_CERT).
        std::vector<CIkeCertificate> caCertificates;    // --> Trust anchors for the server certificate.
        std::vector<SIkeProposal> ikeProposals; // --> Empty: DefaultIkeProposals().
        std::vector<SIkeProposal> espProposals; // --> Empty: DefaultEspProposals().
        uint16_t pfsGroup = 0;              // --> DH group for CHILD rekeys (0: no PFS).
        bool requestAddress = true;         // --> Send CFG_REQUEST for an IPv4 address.
        std::vector<SIkeTrafficSelector> tsi;   // --> Empty: 0.0.0.0/0.
        std::vector<SIkeTrafficSelector> tsr;   // --> Empty: 0.0.0.0/0.
        bool fragmentation = true;
        size_t fragmentSize = 1280;
        bool forceNatT = false;             // --> Fake a NAT so everything uses UDP 4500.
        bool rfc7427 = true;                // --> Announce SIGNATURE_HASH_ALGORITHMS.
        bool mobike = false;
        int64_t timeoutMs = 10000;
        int64_t retransmitMs = 500;
    };

    /**
     * IKEv2 initiator on the calling thread's event loop.
     */
    class SBOX_API CIkeInitiator {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        explicit CIkeInitiator(SIkeInitiatorConfig config);

        ~CIkeInitiator();

        CIkeInitiator(const CIkeInitiator&) = delete;

        CIkeInitiator& operator=(const CIkeInitiator&) = delete;

        /**
         * Runs IKE_SA_INIT and IKE_AUTH and installs the first CHILD SA.
         * @param dataPath Data path for the CHILD SA (null: negotiate only). It must be started
         *        by the caller after this object attached it (see attach()).
         * @return SBOX_OK, -ETIMEDOUT, -EACCES (authentication failed), -EPROTO (refused with a
         *         notify; see lastNotify()), or another error.
         */
        TTask<int32_t> connect(IIpsecDataPathPtr dataPath = nullptr);

        /**
         * Opens the sockets and connects them to a data path without negotiating (so the data
         * path can be started before connect()).
         */
        int32_t attach(IIpsecDataPathPtr dataPath);

        /**
         * Rekeys the CHILD SA (CREATE_CHILD_SA with REKEY_SA, PFS when configured) and deletes
         * the old one.
         */
        TTask<int32_t> rekeyChild();

        /**
         * Rekeys the IKE SA and deletes the old one.
         */
        TTask<int32_t> rekeyIke();

        /**
         * Sends an empty INFORMATIONAL (liveness check).
         */
        TTask<int32_t> dpd();

        /**
         * Deletes the CHILD SA only (INFORMATIONAL DELETE for ESP).
         */
        TTask<int32_t> deleteChild();

        /**
         * Deletes the IKE SA and removes the CHILD SA from the data path.
         */
        TTask<int32_t> close();

        /** Returns true while the IKE SA is up. */
        bool established() const noexcept;

        /** Returns the virtual address the server assigned (invalid when none). */
        net::SIpAddress virtualIp() const;

        /** Returns the attributes of the CP reply. */
        std::vector<SIkeCfgAttribute> configReply() const;

        /** Returns the current CHILD SA (as installed). */
        SIpsecChildSa child() const;

        /** Returns the IKE SA SPIs. */
        std::pair<uint64_t, uint64_t> spis() const;

        /** Returns the negotiated IKE proposal as text. */
        std::string ikeProposal() const;

        /** Returns the negotiated ESP proposal as text. */
        std::string espProposal() const;

        /** Returns the last error notify received (0 when none). */
        uint16_t lastNotify() const noexcept;

        /** Returns true when the exchange ran over the NAT-T port. */
        bool natT() const noexcept;

        /** Returns the number of server-initiated requests answered (DPD, DELETE). */
        uint32_t answeredRequests() const noexcept;

        /** Returns true when the server deleted the IKE SA. */
        bool deletedByPeer() const noexcept;

        /** Returns how many IKE_AUTH response fragments were received in total. */
        uint32_t fragmentsReceived() const noexcept;
    };

}
}

#endif
