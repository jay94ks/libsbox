#ifndef __INCLUDE_SBOX_VPN_IPSEC_PROPOSAL_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_PROPOSAL_HPP__

#include <sbox/common.hpp>
#include <sbox/vpn/ipsec/ikemessage.hpp>
#include <functional>
#include <string>
#include <vector>

// --> Algorithm policy: strongSwan-style proposal strings ("aes256-sha256-modp2048",
// "aes128gcm16-prfsha256-ecp256", "aes256gcm16-noesn"), the built-in defaults that cover
// Windows, Apple and Android clients, and responder-side proposal selection.

namespace sbox {
namespace vpn {

    /**
     * How Diffie-Hellman transforms are treated while selecting.
     */
    enum EIkeDhMode {
        EIKE_DHM_REQUIRED = 0,      // --> IKE SAs, and CHILD SAs created with a KE payload.
        EIKE_DHM_IGNORED,           // --> CHILD SAs of IKE_AUTH: DH transforms are not negotiated.
        EIKE_DHM_NONE,              // --> CHILD SAs created without KE: only "no PFS" is acceptable.
    };

    /**
     * Filter for ESP transforms the data path can run.
     */
    using FIkeTransformFilter = std::function<bool(uint16_t encr, uint16_t keyBits, uint16_t integ)>;

    /**
     * Parses a proposal string; tokens are separated by '-'. Several tokens of one type form
     * alternatives within the proposal.
     * Tokens: aes128/aes192/aes256 (CBC), aes128gcm16/aes256gcm16 (also gcm12), chacha20poly1305,
     * 3des; sha1/sha256/sha384/sha512 (integrity, and the PRF when no prf token is given for IKE);
     * prfsha1/prfsha256/prfsha384/prfsha512; modp1024/modp2048/ecp256/ecp384/curve25519 (alias
     * x25519); esn/noesn (ESP).
     * @param protocol EIKE_PROTO_IKE or EIKE_PROTO_ESP.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseIkeProposal(std::string_view text, uint8_t protocol, SIkeProposal& out);

    /**
     * Formats a proposal back into the string syntax.
     */
    SBOX_API std::string FormatIkeProposal(const SIkeProposal& proposal);

    /**
     * Returns the default IKE proposals (AEAD first, CBC second; MODP-1024 last for Windows).
     */
    SBOX_API std::vector<SIkeProposal> DefaultIkeProposals();

    /**
     * Returns the default ESP proposals.
     */
    SBOX_API std::vector<SIkeProposal> DefaultEspProposals();

    /**
     * Selects one transform per type from the peer's offer, walking our configured proposals in
     * order of preference.
     * @param offered The peer's SA payload proposals.
     * @param configured Our acceptable proposals.
     * @param preferredDh Group of the peer's KE payload (preferred when acceptable), or 0.
     * @param chosen Receives the selection (number, protocol and SPI of the matching offer).
     * @return true when something matched.
     */
    SBOX_API bool SelectIkeProposal(const std::vector<SIkeProposal>& offered, const std::vector<SIkeProposal>& configured,
                                    uint16_t preferredDh, EIkeDhMode dhMode, const FIkeTransformFilter& filter,
                                    SIkeProposal& chosen);

}
}

#endif
