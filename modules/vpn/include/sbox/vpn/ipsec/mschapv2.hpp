#ifndef __INCLUDE_SBOX_VPN_IPSEC_MSCHAPV2_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_MSCHAPV2_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <string>
#include <vector>

// --> MS-CHAPv2 (RFC 2759) and its key derivation (RFC 3079, [MS-CHAP] 3.1.5.1). Used by
// EAP-MSCHAPv2 inside IKEv2 and, later, by PPP for L2TP/IPsec. MD4, SHA-1 and DES come from
// libcertpp.

namespace sbox {
namespace vpn {

    /**
     * NtPasswordHash: MD4 of the UTF-16LE password (the UTF-8 input is converted).
     * @param out Receives 16 bytes.
     * @return SBOX_OK, -EINVAL (bad UTF-8 or output size) or -EIO.
     */
    SBOX_API int32_t MsChapNtPasswordHash(std::string_view password, const SByteSpan& out);

    /**
     * HashNtPasswordHash: MD4 of the 16-byte password hash.
     */
    SBOX_API int32_t MsChapHashNtPasswordHash(const SReadOnlyByteSpan& passwordHash, const SByteSpan& out);

    /**
     * ChallengeHash: first 8 bytes of SHA1(PeerChallenge | AuthenticatorChallenge | UserName).
     * The user name must already be stripped of a domain (see MsChapUserName).
     */
    SBOX_API int32_t MsChapChallengeHash(const SReadOnlyByteSpan& peerChallenge, const SReadOnlyByteSpan& authChallenge,
                                         std::string_view userName, const SByteSpan& out);

    /**
     * ChallengeResponse: three DES encryptions of the 8-byte challenge under the password hash.
     * @param out Receives 24 bytes.
     */
    SBOX_API int32_t MsChapChallengeResponse(const SReadOnlyByteSpan& challenge, const SReadOnlyByteSpan& passwordHash,
                                             const SByteSpan& out);

    /**
     * GenerateNTResponse (RFC 2759 8.1).
     * @param out Receives 24 bytes.
     */
    SBOX_API int32_t MsChapNtResponse(const SReadOnlyByteSpan& authChallenge, const SReadOnlyByteSpan& peerChallenge,
                                      std::string_view userName, const SReadOnlyByteSpan& passwordHash, const SByteSpan& out);

    /**
     * GenerateAuthenticatorResponse (RFC 2759 8.7): "S=" followed by 40 upper-case hex digits.
     * @return The string, or an empty string on failure.
     */
    SBOX_API std::string MsChapAuthenticatorResponse(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse,
                                                     const SReadOnlyByteSpan& peerChallenge,
                                                     const SReadOnlyByteSpan& authChallenge, std::string_view userName);

    /**
     * GetMasterKey (RFC 3079 3.4).
     * @param out Receives 16 bytes.
     */
    SBOX_API int32_t MsChapMasterKey(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse,
                                     const SByteSpan& out);

    /**
     * GetAsymmetricStartKey (RFC 3079 3.4).
     * @param out Receives the session key (8 or 16 bytes).
     */
    SBOX_API int32_t MsChapAsymmetricStartKey(const SReadOnlyByteSpan& masterKey, bool isSend, bool isServer,
                                              const SByteSpan& out);

    /**
     * Master Session Key of EAP-MSCHAPv2 ([MS-CHAP] 3.1.5.1): the peer's send key followed by
     * the peer's receive key (equivalently the server's receive then send key), padded with
     * zeros to the 64 bytes RFC 3748 requires of an MSK.
     * @return SBOX_OK, -EINVAL or -EIO.
     */
    SBOX_API int32_t MsChapV2Msk(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse,
                                 std::vector<uint8_t>& out);

    /**
     * Strips a "DOMAIN\" prefix from a user name (RFC 2759 4: only the user name is hashed).
     */
    SBOX_API std::string MsChapUserName(std::string_view name);

}
}

#endif
