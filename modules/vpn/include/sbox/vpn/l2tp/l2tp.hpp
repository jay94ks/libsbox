#ifndef __INCLUDE_SBOX_VPN_L2TP_L2TP_HPP__
#define __INCLUDE_SBOX_VPN_L2TP_L2TP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// --> L2TPv2 (RFC 2661) in user space: the header, AVPs (including hidden AVPs, section 4.3),
// and the control connection of one tunnel as an LNS (server) or LAC (client): SCCRQ/SCCRP/
// SCCCN, HELLO, StopCCN, incoming calls (ICRQ/ICRP/ICCN), CDN, reliable delivery with Ns/Nr,
// a receive window, retransmission with backoff and ZLB acknowledgements, optional tunnel
// authentication (Challenge/Challenge Response), and data messages carrying PPP frames. A
// tunnel is a synchronous state machine: the owner feeds packets and ticks and provides the
// send function (UDP 1701, possibly inside ESP).

namespace sbox {
namespace vpn {

    /**
     * Control message types (RFC 2661 3.2).
     */
    enum EL2tpMessage : uint16_t {
        EL2TP_ZLB = 0,                  // --> Not a real type: an empty acknowledgement.
        EL2TP_SCCRQ = 1,
        EL2TP_SCCRP = 2,
        EL2TP_SCCCN = 3,
        EL2TP_STOPCCN = 4,
        EL2TP_HELLO = 6,
        EL2TP_OCRQ = 7,
        EL2TP_OCRP = 8,
        EL2TP_OCCN = 9,
        EL2TP_ICRQ = 10,
        EL2TP_ICRP = 11,
        EL2TP_ICCN = 12,
        EL2TP_CDN = 14,
        EL2TP_WEN = 15,
        EL2TP_SLI = 16,
    };

    /**
     * AVP types (RFC 2661 4.4).
     */
    enum EL2tpAvp : uint16_t {
        EL2TP_AVP_MESSAGE_TYPE = 0,
        EL2TP_AVP_RESULT_CODE = 1,
        EL2TP_AVP_PROTOCOL_VERSION = 2,
        EL2TP_AVP_FRAMING_CAPABILITIES = 3,
        EL2TP_AVP_BEARER_CAPABILITIES = 4,
        EL2TP_AVP_TIE_BREAKER = 5,
        EL2TP_AVP_FIRMWARE_REVISION = 6,
        EL2TP_AVP_HOST_NAME = 7,
        EL2TP_AVP_VENDOR_NAME = 8,
        EL2TP_AVP_ASSIGNED_TUNNEL_ID = 9,
        EL2TP_AVP_RECEIVE_WINDOW_SIZE = 10,
        EL2TP_AVP_CHALLENGE = 11,
        EL2TP_AVP_Q931_CAUSE = 12,
        EL2TP_AVP_CHALLENGE_RESPONSE = 13,
        EL2TP_AVP_ASSIGNED_SESSION_ID = 14,
        EL2TP_AVP_CALL_SERIAL_NUMBER = 15,
        EL2TP_AVP_MINIMUM_BPS = 16,
        EL2TP_AVP_MAXIMUM_BPS = 17,
        EL2TP_AVP_BEARER_TYPE = 18,
        EL2TP_AVP_FRAMING_TYPE = 19,
        EL2TP_AVP_CALLED_NUMBER = 21,
        EL2TP_AVP_CALLING_NUMBER = 22,
        EL2TP_AVP_SUB_ADDRESS = 23,
        EL2TP_AVP_TX_CONNECT_SPEED = 24,
        EL2TP_AVP_PHYSICAL_CHANNEL_ID = 25,
        EL2TP_AVP_INITIAL_RECEIVED_LCP_CONFREQ = 26,
        EL2TP_AVP_LAST_SENT_LCP_CONFREQ = 27,
        EL2TP_AVP_LAST_RECEIVED_LCP_CONFREQ = 28,
        EL2TP_AVP_PROXY_AUTHEN_TYPE = 29,
        EL2TP_AVP_PROXY_AUTHEN_NAME = 30,
        EL2TP_AVP_PROXY_AUTHEN_CHALLENGE = 31,
        EL2TP_AVP_PROXY_AUTHEN_ID = 32,
        EL2TP_AVP_PROXY_AUTHEN_RESPONSE = 33,
        EL2TP_AVP_CALL_ERRORS = 34,
        EL2TP_AVP_ACCM = 35,
        EL2TP_AVP_RANDOM_VECTOR = 36,
        EL2TP_AVP_PRIVATE_GROUP_ID = 37,
        EL2TP_AVP_RX_CONNECT_SPEED = 38,
        EL2TP_AVP_SEQUENCING_REQUIRED = 39,
    };

    /**
     * Result codes of StopCCN and CDN (RFC 2661 4.4.2).
     */
    enum EL2tpResult : uint16_t {
        EL2TP_RES_STOP_GENERAL = 1,         // --> StopCCN: general request to clear the control connection.
        EL2TP_RES_STOP_ERROR = 2,           // --> StopCCN: general error, see error code.
        EL2TP_RES_STOP_EXISTS = 3,          // --> StopCCN: control channel already exists.
        EL2TP_RES_STOP_NOT_AUTHORIZED = 4,  // --> StopCCN: requester is not authorized.
        EL2TP_RES_STOP_BAD_VERSION = 5,
        EL2TP_RES_STOP_SHUTDOWN = 6,        // --> StopCCN: requester is being shut down.
        EL2TP_RES_STOP_FSM_ERROR = 7,
        EL2TP_RES_CDN_CARRIER_LOST = 1,     // --> CDN: call disconnected due to loss of carrier.
        EL2TP_RES_CDN_ERROR = 2,            // --> CDN: call disconnected for the reason in the error code.
        EL2TP_RES_CDN_ADMIN = 3,            // --> CDN: administrative reasons.
        EL2TP_RES_CDN_NO_RESOURCES = 4,     // --> CDN: temporary lack of facilities.
    };

    /** Flag bits of the first header word. */
    constexpr uint16_t L2TP_F_TYPE = 0x8000;
    constexpr uint16_t L2TP_F_LENGTH = 0x4000;
    constexpr uint16_t L2TP_F_SEQUENCE = 0x0800;
    constexpr uint16_t L2TP_F_OFFSET = 0x0200;
    constexpr uint16_t L2TP_F_PRIORITY = 0x0100;

    /** The UDP port of L2TP. */
    constexpr uint16_t L2TP_PORT = 1701;

    /**
     * Decoded L2TP header.
     */
    struct SL2tpHeader {
        bool control = false;
        bool hasLength = false;
        bool hasSequence = false;
        bool priority = false;
        uint8_t version = 2;
        uint16_t length = 0;
        uint16_t tunnelId = 0;
        uint16_t sessionId = 0;
        uint16_t ns = 0;
        uint16_t nr = 0;
        size_t payloadOffset = 0;       // --> Where the AVPs / PPP frame start.
        size_t packetSize = 0;          // --> Length field, or the datagram size.
    };

    /**
     * Parses an L2TP header (version 2 only; control messages must carry L and S, no O).
     * @return SBOX_OK, -EBADMSG, or -EPROTONOSUPPORT for another version (L2TPv3, L2F).
     */
    SBOX_API int32_t ParseL2tpHeader(const SReadOnlyByteSpan& packet, SL2tpHeader& out) noexcept;

    /**
     * One AVP.
     */
    struct SL2tpAvp {
        bool mandatory = true;
        bool hidden = false;                // --> On send: hide with the tunnel secret.
        uint16_t vendor = 0;
        uint16_t type = 0;
        std::vector<uint8_t> value;         // --> Revealed value.

        /** Returns a 16-bit value (0 when the size differs). */
        uint16_t u16() const noexcept;

        /** Returns a 32-bit value (0 when the size differs). */
        uint32_t u32() const noexcept;

        /** Returns the value as text. */
        std::string text() const;

        /** Builds a 16-bit AVP. */
        static SL2tpAvp of16(uint16_t type, uint16_t value, bool mandatory = true);

        /** Builds a 32-bit AVP. */
        static SL2tpAvp of32(uint16_t type, uint32_t value, bool mandatory = true);

        /** Builds a byte or text AVP. */
        static SL2tpAvp ofBytes(uint16_t type, const SReadOnlyByteSpan& value, bool mandatory = true);
    };

    /**
     * Parses the AVPs of a control message, revealing hidden AVPs with `secret` (the Random
     * Vector AVP that precedes them supplies the vector).
     * @return SBOX_OK, -EBADMSG (malformed), -EACCES (hidden AVP without a secret / bad length).
     */
    SBOX_API int32_t ParseL2tpAvps(const SReadOnlyByteSpan& data, std::string_view secret, std::vector<SL2tpAvp>& out);

    /**
     * Encodes AVPs; hidden ones are hidden with `secret` and a Random Vector AVP is inserted
     * before the first hidden one.
     */
    SBOX_API void EncodeL2tpAvps(const std::vector<SL2tpAvp>& avps, std::string_view secret, std::vector<uint8_t>& out);

    /**
     * Returns the first IETF AVP of `type`, or nullptr.
     */
    SBOX_API const SL2tpAvp* FindL2tpAvp(const std::vector<SL2tpAvp>& avps, uint16_t type) noexcept;

    /**
     * Builds a control message (T, L, S set).
     */
    SBOX_API std::vector<uint8_t> BuildL2tpControl(uint16_t tunnelId, uint16_t sessionId, uint16_t ns, uint16_t nr,
                                                   const std::vector<SL2tpAvp>& avps, std::string_view secret = std::string_view());

    /**
     * Builds a data message around a PPP frame (with Ns/Nr when `sequence`).
     */
    SBOX_API std::vector<uint8_t> BuildL2tpData(uint16_t tunnelId, uint16_t sessionId, const SReadOnlyByteSpan& ppp, bool sequence = false,
                                                uint16_t ns = 0, uint16_t nr = 0);

    /**
     * Returns the name of a control message type ("SCCRQ"...).
     */
    SBOX_API std::string L2tpMessageName(uint16_t type);

    /**
     * Tunnel settings.
     */
    struct SL2tpTunnelConfig {
        std::string hostName = "sbox-l2tp";
        std::string vendorName = "libsbox";
        std::string secret;                 // --> Tunnel authentication / hidden AVPs (empty: off).
        uint16_t receiveWindow = 8;
        uint32_t helloSeconds = 60;         // --> HELLO after this much control silence (0: off).
        uint32_t retransmitMs = 1000;       // --> First retransmission (doubles up to retransmitCapMs).
        uint32_t retransmitCapMs = 8000;
        uint32_t retransmitTries = 5;
        uint32_t maxSessions = 16;
        uint32_t closeLingerMs = 3000;      // --> State kept after StopCCN to acknowledge retransmissions.
    };

    /**
     * Tunnel states.
     */
    enum EL2tpTunnelState {
        EL2TS_IDLE = 0,
        EL2TS_WAIT_REPLY,           // --> LAC: SCCRQ sent.
        EL2TS_WAIT_CONNECT,         // --> LNS: SCCRP sent.
        EL2TS_ESTABLISHED,
        EL2TS_CLOSING,              // --> StopCCN sent or received.
        EL2TS_CLOSED,
    };

    /**
     * One L2TP tunnel (control connection plus its sessions).
     */
    class SBOX_API CL2tpTunnel {
    private:
        struct SState;
        std::shared_ptr<SState> _state;

    public:
        /**
         * @param lns True for the server (LNS) side, false for a LAC (client).
         * @param localId Our tunnel ID (non-zero).
         */
        CL2tpTunnel(SL2tpTunnelConfig config, bool lns, uint16_t localId);

        ~CL2tpTunnel();

        CL2tpTunnel(const CL2tpTunnel&) = delete;

        CL2tpTunnel& operator=(const CL2tpTunnel&) = delete;

        /** Installs the send function (one UDP payload per call). */
        void sender(std::function<void(const SReadOnlyByteSpan&)> send);

        /** Installs the log sink. */
        void logger(std::function<void(const std::string&)> log);

        /** Called when the control connection is established. */
        void onEstablished(std::function<void()> handler);

        /** Called when a session is established (local session ID). */
        void onSessionUp(std::function<void(uint16_t)> handler);

        /** Called for each PPP frame of a session. */
        void onSessionData(std::function<void(uint16_t, const SReadOnlyByteSpan&)> handler);

        /** Called when a session ends. */
        void onSessionDown(std::function<void(uint16_t, const std::string&)> handler);

        /** Called once when the tunnel is gone (after StopCCN or a timeout). */
        void onClosed(std::function<void(const std::string&)> handler);

        /**
         * Handles one received packet addressed to this tunnel (or an SCCRQ for a new one).
         */
        void input(const SReadOnlyByteSpan& packet);

        /** Runs timers. */
        void tick(int64_t nowMs);

        /** LAC: sends SCCRQ. */
        void start();

        /**
         * LAC: places an incoming call (ICRQ).
         * @return The local session ID, or 0 when not possible.
         */
        uint16_t openSession();

        /**
         * Sends a PPP frame on a session.
         * @return SBOX_OK, -ENOENT or -ENOTCONN.
         */
        int32_t sendData(uint16_t sessionId, const SReadOnlyByteSpan& ppp);

        /** Clears a session with CDN. */
        void closeSession(uint16_t sessionId, uint16_t result = EL2TP_RES_CDN_ADMIN, const std::string& message = std::string());

        /** Clears the tunnel with StopCCN. */
        void close(uint16_t result = EL2TP_RES_STOP_GENERAL, const std::string& message = std::string());

        /** Returns our tunnel ID. */
        uint16_t localId() const noexcept;

        /** Returns the peer's tunnel ID (0 before SCCRQ/SCCRP). */
        uint16_t peerId() const noexcept;

        /** Returns the state. */
        EL2tpTunnelState state() const noexcept;

        /** Returns the peer's host name. */
        std::string peerHostName() const;

        /** Returns the number of established sessions. */
        size_t sessionCount() const noexcept;

        /** Returns the peer session ID of a local session (0 when unknown). */
        uint16_t peerSessionId(uint16_t sessionId) const noexcept;
    };

}
}

#endif
