#ifndef __INCLUDE_SBOX_VPN_IPSEC_EAP_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_EAP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <functional>
#include <string>
#include <vector>

// --> EAP (RFC 3748) packets and the EAP-MSCHAPv2 method (draft-kamath-pppext-eap-mschapv2)
// for both roles. The server is what the IKEv2 responder runs for Windows/macOS/iOS/Android
// username-password clients; the peer exists for the test initiator.

namespace sbox {
namespace vpn {

    /**
     * EAP codes.
     */
    enum EEapCode : uint8_t {
        EEAP_REQUEST = 1,
        EEAP_RESPONSE = 2,
        EEAP_SUCCESS = 3,
        EEAP_FAILURE = 4,
    };

    /**
     * EAP method types.
     */
    enum EEapType : uint8_t {
        EEAP_T_NONE = 0,
        EEAP_T_IDENTITY = 1,
        EEAP_T_NOTIFICATION = 2,
        EEAP_T_NAK = 3,
        EEAP_T_MD5 = 4,
        EEAP_T_MSCHAPV2 = 26,
    };

    /**
     * Result of feeding one EAP message to a method state machine.
     */
    enum EEapStatus {
        EEAPS_CONTINUE = 0,     // --> Send the produced message and wait for the next one.
        EEAPS_SUCCESS,          // --> Authentication succeeded (the produced message, if any, is EAP-Success).
        EEAPS_FAILURE,          // --> Authentication failed (the produced message, if any, is EAP-Failure).
    };

    /**
     * One EAP packet.
     */
    struct SBOX_API SEapPacket {
        uint8_t code = EEAP_REQUEST;
        uint8_t identifier = 0;
        uint8_t type = EEAP_T_NONE;     // --> Only for requests and responses.
        std::vector<uint8_t> data;      // --> Type-data.

        /**
         * Parses a packet (the length field must match the input).
         * @return SBOX_OK or -EBADMSG.
         */
        static int32_t parse(const SReadOnlyByteSpan& bytes, SEapPacket& out);

        /**
         * Encodes the packet.
         */
        std::vector<uint8_t> encode() const;
    };

    /**
     * Looks up the NT password hash (MD4 of the UTF-16LE password, 16 bytes) of a user.
     * Returns false for an unknown user.
     */
    using FEapCredentialLookup = std::function<bool(const std::string& user, std::vector<uint8_t>& ntHash)>;

    /**
     * Authenticator side of EAP-MSCHAPv2 (optionally preceded by EAP-Identity).
     */
    class SBOX_API CEapMsChapV2Server {
    private:
        enum EState {
            STATE_IDLE,
            STATE_IDENTITY,
            STATE_CHALLENGE,
            STATE_SUCCESS_SENT,
            STATE_FAILURE_SENT,
            STATE_DONE,
        };

        FEapCredentialLookup _lookup;
        std::string _serverName;
        EState _state;
        uint8_t _id;
        uint8_t _challenge[16];
        std::string _identity;
        std::string _user;
        std::vector<uint8_t> _msk;
        std::string _error;

    public:
        /**
         * @param lookup Credential lookup by user name (domain already stripped).
         * @param serverName Name sent in the challenge.
         */
        explicit CEapMsChapV2Server(FEapCredentialLookup lookup, std::string serverName = "sbox");

        ~CEapMsChapV2Server();

        /**
         * Produces the first request: EAP-Identity when `askIdentity`, else the challenge.
         */
        std::vector<uint8_t> start(bool askIdentity);

        /**
         * Consumes a response and produces the next request (or EAP-Success/Failure).
         */
        EEapStatus process(const SReadOnlyByteSpan& response, std::vector<uint8_t>& next);

        /** Returns the EAP identity (empty when not asked). */
        inline const std::string& identity() const noexcept { return _identity; }

        /** Returns the authenticated MS-CHAPv2 user name (domain stripped). */
        inline const std::string& user() const noexcept { return _user; }

        /** Returns the 64-byte MSK after success. */
        inline const std::vector<uint8_t>& msk() const noexcept { return _msk; }

        /** Returns a short reason for a failure. */
        inline const std::string& error() const noexcept { return _error; }

    private:
        /** Builds the MS-CHAPv2 challenge request. */
        std::vector<uint8_t> challengeRequest();

        /** Builds an MS-CHAPv2 request with an opcode and a message. */
        std::vector<uint8_t> opRequest(uint8_t opcode, const std::string& message);

        /** Builds EAP-Success or EAP-Failure. */
        std::vector<uint8_t> finalPacket(bool success);
    };

    /**
     * Peer side of EAP-MSCHAPv2 (answers EAP-Identity too).
     */
    class SBOX_API CEapMsChapV2Peer {
    private:
        std::string _identity;
        std::string _user;
        std::vector<uint8_t> _passwordHash;
        uint8_t _peerChallenge[16];
        uint8_t _authChallenge[16];
        uint8_t _ntResponse[24];
        bool _verified;
        std::vector<uint8_t> _msk;

    public:
        /**
         * @param identity EAP identity (usually the user name).
         * @param user MS-CHAPv2 user name.
         * @param password Clear-text password.
         */
        CEapMsChapV2Peer(std::string identity, std::string user, std::string_view password);

        ~CEapMsChapV2Peer();

        /**
         * Consumes a request (or EAP-Success/Failure) and produces the response, if any.
         */
        EEapStatus process(const SReadOnlyByteSpan& request, std::vector<uint8_t>& response);

        /** Returns the MSK after success. */
        inline const std::vector<uint8_t>& msk() const noexcept { return _msk; }
    };

}
}

#endif
