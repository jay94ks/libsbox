#ifndef __SRC_VPN_IPSEC_IKESA_HPP__
#define __SRC_VPN_IPSEC_IKESA_HPP__

#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <sbox/core/socket.hpp>
#include <map>
#include <string>
#include <vector>

// --> State and helpers shared by the IKEv2 responder and initiator: key derivation (RFC 7296
// 2.13-2.18), the Encrypted / Encrypted Fragment payloads (RFC 7296 3.14, RFC 7383), message
// id bookkeeping and the AUTH payload computations (RFC 7296 2.15-2.16, RFC 7427).

namespace sbox {
namespace vpn {
namespace ipsec {

    /**
     * Algorithms picked from a negotiated proposal.
     */
    struct Suite {
        uint16_t encr = 0;
        uint16_t keyBits = 0;
        uint16_t integ = EIKE_INTEG_NONE;
        uint16_t prf = EIKE_PRF_NONE;
        uint16_t dh = EIKE_DH_NONE;
        uint16_t esn = EIKE_ESN_NO;

        /** Reads the single transforms of a selected proposal. */
        static Suite from(const SIkeProposal& p);
    };

    /**
     * SK_* keys of an IKE SA.
     */
    struct IkeKeys {
        std::vector<uint8_t> d, ai, ar, ei, er, pi, pr;

        /** Zeroizes everything. */
        void wipe();
    };

    /**
     * KEYMAT split of a CHILD SA (directions relative to the exchange initiator).
     */
    struct ChildKeys {
        std::vector<uint8_t> encIr;     // --> Initiator to responder.
        std::vector<uint8_t> integIr;
        std::vector<uint8_t> encRi;     // --> Responder to initiator.
        std::vector<uint8_t> integRi;

        /** Zeroizes everything. */
        void wipe();
    };

    /** SKEYSEED = prf(Ni | Nr, g^ir). */
    int32_t ComputeSkeyseed(uint16_t prf, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr,
                            const SReadOnlyByteSpan& gir, std::vector<uint8_t>& out);

    /** Rekey SKEYSEED = prf_old(SK_d_old, g^ir_new | Ni | Nr). */
    int32_t ComputeRekeySkeyseed(uint16_t oldPrf, const SReadOnlyByteSpan& oldSkD, const SReadOnlyByteSpan& gir,
                                 const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, std::vector<uint8_t>& out);

    /** {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr). */
    int32_t DeriveIkeKeys(const Suite& suite, const SReadOnlyByteSpan& skeyseed, const SReadOnlyByteSpan& ni,
                          const SReadOnlyByteSpan& nr, uint64_t spiI, uint64_t spiR, IkeKeys& out);

    /** KEYMAT = prf+(SK_d, [g^ir |] Ni | Nr). */
    int32_t DeriveChildKeys(uint16_t prf, const SReadOnlyByteSpan& skD, const SReadOnlyByteSpan& gir,
                            const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, const Suite& child, ChildKeys& out);

    /** Returns the IP address of an endpoint (invalid for non-IP endpoints). */
    net::SIpAddress AddressOf(const SEndpoint& endpoint);

    /** Builds an IP endpoint. */
    SEndpoint EndpointOf(const net::SIpAddress& address, uint16_t port);

    /** NAT detection hash SHA1(SPIi | SPIr | IP | port). */
    std::vector<uint8_t> NatHash(uint64_t spiI, uint64_t spiR, const SEndpoint& endpoint);

    /** Signed octets: RealMessage | Nonce | prf(SK_p, RestOfIDPayload). */
    std::vector<uint8_t> AuthOctets(const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& nonce, uint16_t prf,
                                    const SReadOnlyByteSpan& skP, const SReadOnlyByteSpan& idBody);

    /** Shared-key AUTH: prf(prf(secret, "Key Pad for IKEv2"), octets). */
    int32_t SharedKeyAuth(uint16_t prf, const SReadOnlyByteSpan& secret, const SReadOnlyByteSpan& octets, std::vector<uint8_t>& out);

    /** Parses SIGNATURE_HASH_ALGORITHMS notify data. */
    std::vector<uint16_t> ParseHashAlgorithms(const SReadOnlyByteSpan& data);

    /** Our SIGNATURE_HASH_ALGORITHMS notify data (SHA2-256/384/512). */
    std::vector<uint8_t> OurHashAlgorithms();

    /**
     * Signs AUTH octets with a certificate's key.
     * @param peerHashes Hashes from the peer's SIGNATURE_HASH_ALGORITHMS (empty: no RFC 7427).
     */
    int32_t SignAuth(const CIkeCertificate& cert, const SReadOnlyByteSpan& octets, const std::vector<uint16_t>& peerHashes,
                     uint8_t& method, std::vector<uint8_t>& data);

    /**
     * Verifies an AUTH signature against a certificate.
     * @return SBOX_OK, -ENOTSUP (method/algorithm) or -EKEYREJECTED.
     */
    int32_t VerifyAuth(const CIkeCertificate& cert, uint8_t method, const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& octets);

    /**
     * Checks that an identity is bound to a certificate (DN equals the subject, or the name or
     * address is in the subjectAltName).
     */
    bool IdMatchesCertificate(const SIkeId& id, const CIkeCertificate& cert);

    /**
     * Encodes an unencrypted message (IKE_SA_INIT) with its header length filled in.
     */
    std::vector<uint8_t> EncodePlainMessage(SIkeHeader header, const std::vector<SIkePayload>& payloads);

    /**
     * Cryptographic and transport state of one IKE SA.
     */
    class IkeSa {
    public:
        struct Reassembly {
            bool active = false;
            uint32_t mid = 0;
            bool response = false;
            uint8_t exchange = 0;
            uint16_t total = 0;
            uint8_t firstType = 0;
            std::map<uint16_t, std::vector<uint8_t>> parts;
            int64_t started = 0;
        };

        uint64_t spiI = 0;
        uint64_t spiR = 0;
        bool initiator = false;         // --> We are the original initiator of this IKE SA.
        Suite suite;
        std::vector<uint8_t> ni;
        std::vector<uint8_t> nr;
        IkeKeys keys;
        CIpsecCipher in;
        CIpsecCipher out;

        SEndpoint local;
        SEndpoint remote;
        bool natT = false;              // --> Use the NAT-T port (marker) for IKE.
        bool natLocal = false;          // --> We are behind a NAT.
        bool natRemote = false;         // --> The peer is behind a NAT.
        bool fragmentation = false;     // --> Both sides announced RFC 7383 support.
        size_t fragmentSize = 1280;

        // -- Exchanges the peer starts.
        uint32_t expectMid = 0;
        bool hasLast = false;
        uint32_t lastMid = 0;
        std::vector<std::vector<uint8_t>> lastResponse;

        // -- Exchanges we start.
        uint32_t nextMid = 0;
        bool pending = false;
        uint32_t pendingMid = 0;
        uint8_t pendingExchange = 0;
        std::vector<std::vector<uint8_t>> pendingRequest;
        int32_t retries = 0;
        int64_t retransmitAt = 0;

        Reassembly reasm;

        IkeSa() = default;

        ~IkeSa();

        /**
         * Derives SK_* from SKEYSEED and keys both ciphers.
         */
        int32_t installKeys(const SReadOnlyByteSpan& skeyseed);

        /**
         * Builds the protected message (one datagram, or SKF fragments when allowed and needed).
         */
        int32_t encrypt(uint8_t exchange, bool response, uint32_t mid, const std::vector<SIkePayload>& payloads,
                        std::vector<std::vector<uint8_t>>& datagrams);

        /**
         * Verifies and decrypts a protected message.
         * @return SBOX_OK with the inner payloads, -EAGAIN when a fragment was stored and more are
         *         needed, -EBADMSG/-EKEYREJECTED for bad messages.
         */
        int32_t decrypt(const SIkeHeader& header, const SReadOnlyByteSpan& message, std::vector<SIkePayload>& payloads);

        /** Returns the header flags of a message we send. */
        uint8_t flags(bool response) const noexcept;
    };

}
}
}

#endif
