#include <sbox/vpn/ipsec/eap.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include "crypto.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace ipsec;

    namespace {

        constexpr uint8_t OP_CHALLENGE = 1;
        constexpr uint8_t OP_RESPONSE = 2;
        constexpr uint8_t OP_SUCCESS = 3;
        constexpr uint8_t OP_FAILURE = 4;

        /* Builds MS-CHAPv2 type-data: opcode, id, MS-Length, body. */
        std::vector<uint8_t> msData(uint8_t opcode, uint8_t id, const SReadOnlyByteSpan& body) {
            std::vector<uint8_t> out;
            out.push_back(opcode);
            out.push_back(id);
            // --> MS-Length counts from the OpCode to the end (EAP length minus 5).
            PutBe16(out, uint32_t(4 + body.size));
            Append(out, body);
            return out;
        }

    }

    /* Parses an EAP packet. */
    int32_t SEapPacket::parse(const SReadOnlyByteSpan& bytes, SEapPacket& out) {
        if (bytes.size < 4) {
            return -EBADMSG;
        }

        size_t length = GetBe16(bytes.data + 2);
        if (length != bytes.size || length < 4) {
            return -EBADMSG;
        }

        out.code = bytes[0];
        out.identifier = bytes[1];
        out.type = EEAP_T_NONE;
        out.data.clear();

        if (out.code == EEAP_REQUEST || out.code == EEAP_RESPONSE) {
            if (length < 5) {
                return -EBADMSG;
            }

            out.type = bytes[4];
            out.data.assign(bytes.data + 5, bytes.data + length);
        }
        else if (out.code == EEAP_SUCCESS || out.code == EEAP_FAILURE) {
            if (length != 4) {
                return -EBADMSG;
            }
        }
        else {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

    /* Encodes an EAP packet. */
    std::vector<uint8_t> SEapPacket::encode() const {
        std::vector<uint8_t> out;
        out.push_back(code);
        out.push_back(identifier);
        bool typed = code == EEAP_REQUEST || code == EEAP_RESPONSE;
        PutBe16(out, uint32_t(4 + (typed ? 1 + data.size() : 0)));
        if (typed) {
            out.push_back(type);
            Append(out, BytesOf(data));
        }

        return out;
    }

    // ---------------------------------------------------------------------------------------

    CEapMsChapV2Server::CEapMsChapV2Server(FEapCredentialLookup lookup, std::string serverName)
        : _lookup(std::move(lookup)), _serverName(std::move(serverName)), _state(STATE_IDLE), _id(0) {
        std::memset(_challenge, 0, sizeof(_challenge));
    }

    CEapMsChapV2Server::~CEapMsChapV2Server() {
        IkeWipe(_msk);
    }

    /* First request. */
    std::vector<uint8_t> CEapMsChapV2Server::start(bool askIdentity) {
        IkeRandom(SByteSpan(&_id, 1));

        if (askIdentity) {
            _state = STATE_IDENTITY;
            SEapPacket p;
            p.code = EEAP_REQUEST;
            p.identifier = _id;
            p.type = EEAP_T_IDENTITY;
            return p.encode();
        }

        return challengeRequest();
    }

    /* Challenge request. */
    std::vector<uint8_t> CEapMsChapV2Server::challengeRequest() {
        IkeRandom(SByteSpan(_challenge, sizeof(_challenge)));
        _state = STATE_CHALLENGE;

        std::vector<uint8_t> body;
        body.push_back(16);
        Append(body, SReadOnlyByteSpan(_challenge, 16));
        Append(body, BytesOf(_serverName));

        SEapPacket p;
        p.code = EEAP_REQUEST;
        p.identifier = _id;
        p.type = EEAP_T_MSCHAPV2;
        p.data = msData(OP_CHALLENGE, _id, BytesOf(body));
        return p.encode();
    }

    /* Success/Failure request. */
    std::vector<uint8_t> CEapMsChapV2Server::opRequest(uint8_t opcode, const std::string& message) {
        SEapPacket p;
        p.code = EEAP_REQUEST;
        p.identifier = _id;
        p.type = EEAP_T_MSCHAPV2;
        p.data = msData(opcode, _id, BytesOf(message));
        return p.encode();
    }

    /* EAP-Success / EAP-Failure. */
    std::vector<uint8_t> CEapMsChapV2Server::finalPacket(bool success) {
        SEapPacket p;
        p.code = success ? EEAP_SUCCESS : EEAP_FAILURE;
        p.identifier = _id;
        return p.encode();
    }

    /* Consumes a response. */
    EEapStatus CEapMsChapV2Server::process(const SReadOnlyByteSpan& response, std::vector<uint8_t>& next) {
        next.clear();

        SEapPacket p;
        if (SEapPacket::parse(response, p) != SBOX_OK || p.code != EEAP_RESPONSE || p.identifier != _id) {
            _error = "malformed or unexpected EAP response";
            _state = STATE_DONE;
            next = finalPacket(false);
            return EEAPS_FAILURE;
        }

        if (p.type == EEAP_T_NAK) {
            _error = "peer refused EAP-MSCHAPv2";
            _state = STATE_DONE;
            next = finalPacket(false);
            return EEAPS_FAILURE;
        }

        switch (_state) {
        case STATE_IDENTITY:
            if (p.type != EEAP_T_IDENTITY) {
                break;
            }

            _identity.assign(p.data.begin(), p.data.end());
            ++_id;
            next = challengeRequest();
            return EEAPS_CONTINUE;

        case STATE_CHALLENGE: {
            if (p.type != EEAP_T_MSCHAPV2 || p.data.size() < 5 + 49 || p.data[0] != OP_RESPONSE || p.data[4] != 49) {
                break;
            }

            const uint8_t* resp = p.data.data() + 5;
            const uint8_t* peerChallenge = resp;
            const uint8_t* ntResponse = resp + 24;
            std::string name(p.data.begin() + 5 + 49, p.data.end());
            _user = MsChapUserName(name);

            std::vector<uint8_t> hash;
            uint8_t expected[24];
            bool known = _lookup && _lookup(_user, hash) && hash.size() == 16;
            if (!known) {
                // --> Compute against a random hash anyway so unknown users take the same time.
                hash.assign(16, 0);
                IkeRandom(BytesOf(hash));
            }

            bool ok = MsChapNtResponse(SReadOnlyByteSpan(_challenge, 16), SReadOnlyByteSpan(peerChallenge, 16), _user,
                                       BytesOf(hash), SByteSpan(expected, 24)) == SBOX_OK
                && IkeSecureEquals(SReadOnlyByteSpan(expected, 24), SReadOnlyByteSpan(ntResponse, 24)) && known;

            ++_id;
            if (!ok) {
                _error = known ? "wrong password for '" + _user + "'" : "unknown user '" + _user + "'";
                _state = STATE_FAILURE_SENT;
                std::string chal = ToHex(SReadOnlyByteSpan(_challenge, 16), true);
                next = opRequest(OP_FAILURE, "E=691 R=0 C=" + chal + " V=3 M=Authentication failed");
                IkeWipe(hash);
                return EEAPS_CONTINUE;
            }

            std::string auth = MsChapAuthenticatorResponse(BytesOf(hash), SReadOnlyByteSpan(ntResponse, 24),
                                                           SReadOnlyByteSpan(peerChallenge, 16),
                                                           SReadOnlyByteSpan(_challenge, 16), _user);
            int32_t r = MsChapV2Msk(BytesOf(hash), SReadOnlyByteSpan(ntResponse, 24), _msk);
            IkeWipe(hash);
            if (auth.empty() || r != SBOX_OK) {
                _error = "key derivation failed";
                _state = STATE_DONE;
                next = finalPacket(false);
                return EEAPS_FAILURE;
            }

            _state = STATE_SUCCESS_SENT;
            next = opRequest(OP_SUCCESS, auth + " M=Welcome");
            return EEAPS_CONTINUE;
        }

        case STATE_SUCCESS_SENT:
            if (p.type != EEAP_T_MSCHAPV2 || p.data.empty() || p.data[0] != OP_SUCCESS) {
                break;
            }

            _state = STATE_DONE;
            next = finalPacket(true);
            return EEAPS_SUCCESS;

        case STATE_FAILURE_SENT:
            _state = STATE_DONE;
            next = finalPacket(false);
            return EEAPS_FAILURE;

        default:
            break;
        }

        if (_error.empty()) {
            _error = "unexpected EAP message";
        }

        _state = STATE_DONE;
        IkeWipe(_msk);
        next = finalPacket(false);
        return EEAPS_FAILURE;
    }

    // ---------------------------------------------------------------------------------------

    CEapMsChapV2Peer::CEapMsChapV2Peer(std::string identity, std::string user, std::string_view password)
        : _identity(std::move(identity)), _user(std::move(user)), _verified(false) {
        _passwordHash.assign(16, 0);
        MsChapNtPasswordHash(password, BytesOf(_passwordHash));
        std::memset(_peerChallenge, 0, sizeof(_peerChallenge));
        std::memset(_authChallenge, 0, sizeof(_authChallenge));
        std::memset(_ntResponse, 0, sizeof(_ntResponse));
    }

    CEapMsChapV2Peer::~CEapMsChapV2Peer() {
        IkeWipe(_passwordHash);
        IkeWipe(_msk);
    }

    /* Consumes a request. */
    EEapStatus CEapMsChapV2Peer::process(const SReadOnlyByteSpan& request, std::vector<uint8_t>& response) {
        response.clear();

        SEapPacket p;
        if (SEapPacket::parse(request, p) != SBOX_OK) {
            return EEAPS_FAILURE;
        }

        if (p.code == EEAP_SUCCESS) {
            return _verified ? EEAPS_SUCCESS : EEAPS_FAILURE;
        }

        if (p.code == EEAP_FAILURE || p.code != EEAP_REQUEST) {
            return EEAPS_FAILURE;
        }

        SEapPacket out;
        out.code = EEAP_RESPONSE;
        out.identifier = p.identifier;

        if (p.type == EEAP_T_IDENTITY) {
            out.type = EEAP_T_IDENTITY;
            out.data.assign(_identity.begin(), _identity.end());
            response = out.encode();
            return EEAPS_CONTINUE;
        }

        if (p.type != EEAP_T_MSCHAPV2) {
            out.type = EEAP_T_NAK;
            out.data.push_back(EEAP_T_MSCHAPV2);
            response = out.encode();
            return EEAPS_CONTINUE;
        }

        if (p.data.size() < 4) {
            return EEAPS_FAILURE;
        }

        uint8_t opcode = p.data[0];
        uint8_t msId = p.data[1];
        out.type = EEAP_T_MSCHAPV2;

        if (opcode == OP_CHALLENGE) {
            if (p.data.size() < 5 + 16 || p.data[4] != 16) {
                return EEAPS_FAILURE;
            }

            std::memcpy(_authChallenge, p.data.data() + 5, 16);
            IkeRandom(SByteSpan(_peerChallenge, 16));
            std::string user = MsChapUserName(_user);
            if (MsChapNtResponse(SReadOnlyByteSpan(_authChallenge, 16), SReadOnlyByteSpan(_peerChallenge, 16), user,
                                 BytesOf(_passwordHash), SByteSpan(_ntResponse, 24)) != SBOX_OK) {
                return EEAPS_FAILURE;
            }

            std::vector<uint8_t> body;
            body.push_back(49);
            Append(body, SReadOnlyByteSpan(_peerChallenge, 16));
            body.insert(body.end(), 8, 0);
            Append(body, SReadOnlyByteSpan(_ntResponse, 24));
            body.push_back(0);
            Append(body, BytesOf(_user));
            out.data = msData(OP_RESPONSE, msId, BytesOf(body));
            response = out.encode();
            return EEAPS_CONTINUE;
        }

        if (opcode == OP_SUCCESS) {
            std::string message(p.data.begin() + 4, p.data.end());
            std::string expected = MsChapAuthenticatorResponse(BytesOf(_passwordHash), SReadOnlyByteSpan(_ntResponse, 24),
                                                               SReadOnlyByteSpan(_peerChallenge, 16),
                                                               SReadOnlyByteSpan(_authChallenge, 16), MsChapUserName(_user));
            if (expected.empty() || message.compare(0, expected.size(), expected) != 0) {
                return EEAPS_FAILURE;
            }

            if (MsChapV2Msk(BytesOf(_passwordHash), SReadOnlyByteSpan(_ntResponse, 24), _msk) != SBOX_OK) {
                return EEAPS_FAILURE;
            }

            _verified = true;
            out.data.push_back(OP_SUCCESS);
            response = out.encode();
            return EEAPS_CONTINUE;
        }

        if (opcode == OP_FAILURE) {
            out.data.push_back(OP_FAILURE);
            response = out.encode();
            return EEAPS_FAILURE;
        }

        return EEAPS_FAILURE;
    }

}
}
