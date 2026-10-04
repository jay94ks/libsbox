#include <sbox/vpn/ipsec/proposal.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <cerrno>

namespace sbox {
namespace vpn {

    namespace {

        struct Token {
            const char* name;
            uint8_t type;
            uint16_t id;
            uint16_t keyLength;
        };

        const Token TOKENS[] = {
            { "aes128", EIKE_TT_ENCR, EIKE_ENCR_AES_CBC, 128 },
            { "aes192", EIKE_TT_ENCR, EIKE_ENCR_AES_CBC, 192 },
            { "aes256", EIKE_TT_ENCR, EIKE_ENCR_AES_CBC, 256 },
            { "aes", EIKE_TT_ENCR, EIKE_ENCR_AES_CBC, 128 },
            { "aes128gcm16", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_16, 128 },
            { "aes192gcm16", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_16, 192 },
            { "aes256gcm16", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_16, 256 },
            { "aes128gcm", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_16, 128 },
            { "aes256gcm", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_16, 256 },
            { "aes128gcm12", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_12, 128 },
            { "aes256gcm12", EIKE_TT_ENCR, EIKE_ENCR_AES_GCM_12, 256 },
            { "chacha20poly1305", EIKE_TT_ENCR, EIKE_ENCR_CHACHA20_POLY1305, 0 },
            { "3des", EIKE_TT_ENCR, EIKE_ENCR_3DES, 0 },
            { "sha1", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA1_96, 0 },
            { "sha", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA1_96, 0 },
            { "sha256", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_256_128, 0 },
            { "sha2_256", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_256_128, 0 },
            { "sha384", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_384_192, 0 },
            { "sha2_384", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_384_192, 0 },
            { "sha512", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_512_256, 0 },
            { "sha2_512", EIKE_TT_INTEG, EIKE_INTEG_HMAC_SHA2_512_256, 0 },
            { "prfsha1", EIKE_TT_PRF, EIKE_PRF_HMAC_SHA1, 0 },
            { "prfsha256", EIKE_TT_PRF, EIKE_PRF_HMAC_SHA2_256, 0 },
            { "prfsha384", EIKE_TT_PRF, EIKE_PRF_HMAC_SHA2_384, 0 },
            { "prfsha512", EIKE_TT_PRF, EIKE_PRF_HMAC_SHA2_512, 0 },
            { "modp1024", EIKE_TT_DH, EIKE_DH_MODP1024, 0 },
            { "modp2048", EIKE_TT_DH, EIKE_DH_MODP2048, 0 },
            { "ecp256", EIKE_TT_DH, EIKE_DH_ECP256, 0 },
            { "ecp384", EIKE_TT_DH, EIKE_DH_ECP384, 0 },
            { "curve25519", EIKE_TT_DH, EIKE_DH_CURVE25519, 0 },
            { "x25519", EIKE_TT_DH, EIKE_DH_CURVE25519, 0 },
            { "esn", EIKE_TT_ESN, EIKE_ESN_YES, 0 },
            { "noesn", EIKE_TT_ESN, EIKE_ESN_NO, 0 },
        };

        /* PRF matching an integrity algorithm (strongSwan's implicit PRF). */
        uint16_t prfOf(uint16_t integ) {
            switch (integ) {
            case EIKE_INTEG_HMAC_SHA1_96: return EIKE_PRF_HMAC_SHA1;
            case EIKE_INTEG_HMAC_SHA2_256_128: return EIKE_PRF_HMAC_SHA2_256;
            case EIKE_INTEG_HMAC_SHA2_384_192: return EIKE_PRF_HMAC_SHA2_384;
            case EIKE_INTEG_HMAC_SHA2_512_256: return EIKE_PRF_HMAC_SHA2_512;
            default: return EIKE_PRF_NONE;
            }
        }

        /* Adds a transform once. */
        void addOnce(SIkeProposal& p, const SIkeTransform& t) {
            for (const SIkeTransform& x : p.transforms) {
                if (x == t) {
                    return;
                }
            }

            p.transforms.push_back(t);
        }

        /* Same algorithm (fixed-key transforms treat 0 and the default length as equal). */
        bool sameEncr(const SIkeTransform& a, const SIkeTransform& b) {
            if (a.id != b.id) {
                return false;
            }

            if (a.keyLength == b.keyLength) {
                return true;
            }

            const SIkeEncrInfo* info = IkeEncrInfo(a.id);
            if (!info || info->keyLengthAttr) {
                return false;
            }

            uint16_t ka = a.keyLength ? a.keyLength : info->defaultBits;
            uint16_t kb = b.keyLength ? b.keyLength : info->defaultBits;
            return ka == kb;
        }

        /* Returns true when the list contains id. */
        bool has(const std::vector<SIkeTransform>& list, uint16_t id) {
            for (const SIkeTransform& t : list) {
                if (t.id == id) {
                    return true;
                }
            }

            return false;
        }

        /* Tries to complete a selection for one (configured, offered) pair. */
        bool tryPair(const SIkeProposal& ours, const SIkeProposal& theirs, uint16_t preferredDh, bool onlyPreferred,
                     EIkeDhMode dhMode, const FIkeTransformFilter& filter, SIkeProposal& chosen) {
            if (ours.protocol != theirs.protocol) {
                return false;
            }

            bool ike = theirs.protocol == EIKE_PROTO_IKE;

            // --> A transform type we do not know makes the whole offer unusable.
            for (const SIkeTransform& t : theirs.transforms) {
                if (t.type < EIKE_TT_ENCR || t.type > EIKE_TT_ESN) {
                    return false;
                }
            }

            std::vector<SIkeTransform> theirEncr = theirs.ofType(EIKE_TT_ENCR);
            std::vector<SIkeTransform> theirInteg = theirs.ofType(EIKE_TT_INTEG);
            std::vector<SIkeTransform> theirPrf = theirs.ofType(EIKE_TT_PRF);
            std::vector<SIkeTransform> theirDh = theirs.ofType(EIKE_TT_DH);
            std::vector<SIkeTransform> theirEsn = theirs.ofType(EIKE_TT_ESN);

            for (const SIkeTransform& oe : ours.ofType(EIKE_TT_ENCR)) {
                const SIkeTransform* match = nullptr;
                for (const SIkeTransform& te : theirEncr) {
                    if (sameEncr(oe, te) && IkeEncrKeyBitsValid(te.id, te.keyLength)) {
                        match = &te;
                        break;
                    }
                }

                if (!match) {
                    continue;
                }

                const SIkeEncrInfo* info = IkeEncrInfo(match->id);
                if (!info) {
                    continue;
                }

                SIkeProposal result;
                result.number = theirs.number;
                result.protocol = theirs.protocol;
                result.spi = theirs.spi;
                result.transforms.push_back(*match);

                // --> Integrity.
                uint16_t integ = EIKE_INTEG_NONE;
                if (info->aead) {
                    bool onlyNone = true;
                    for (const SIkeTransform& t : theirInteg) {
                        onlyNone = onlyNone && t.id == EIKE_INTEG_NONE;
                    }

                    if (!onlyNone && !has(theirInteg, EIKE_INTEG_NONE)) {
                        continue;
                    }
                }
                else {
                    bool found = false;
                    for (const SIkeTransform& oi : ours.ofType(EIKE_TT_INTEG)) {
                        if (oi.id != EIKE_INTEG_NONE && has(theirInteg, oi.id)) {
                            integ = oi.id;
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        continue;
                    }

                    SIkeTransform t;
                    t.type = EIKE_TT_INTEG;
                    t.id = integ;
                    result.transforms.push_back(t);
                }

                if (filter && !filter(match->id, match->keyLength, integ)) {
                    continue;
                }

                // --> PRF (IKE only).
                if (ike) {
                    bool found = false;
                    for (const SIkeTransform& op : ours.ofType(EIKE_TT_PRF)) {
                        if (has(theirPrf, op.id)) {
                            SIkeTransform t;
                            t.type = EIKE_TT_PRF;
                            t.id = op.id;
                            result.transforms.push_back(t);
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        continue;
                    }
                }

                // --> Diffie-Hellman.
                if (ike || dhMode == EIKE_DHM_REQUIRED) {
                    uint16_t group = 0;
                    std::vector<SIkeTransform> ourDh = ours.ofType(EIKE_TT_DH);
                    if (preferredDh && has(ourDh, preferredDh) && has(theirDh, preferredDh) && IkeDhSupported(preferredDh)) {
                        group = preferredDh;
                    }
                    else {
                        for (const SIkeTransform& od : ourDh) {
                            if (od.id != EIKE_DH_NONE && has(theirDh, od.id) && IkeDhSupported(od.id)) {
                                group = od.id;
                                break;
                            }
                        }
                    }

                    if (!group || (onlyPreferred && group != preferredDh)) {
                        continue;
                    }

                    SIkeTransform t;
                    t.type = EIKE_TT_DH;
                    t.id = group;
                    result.transforms.push_back(t);
                }
                else if (dhMode == EIKE_DHM_NONE) {
                    if (!theirDh.empty() && !has(theirDh, EIKE_DH_NONE)) {
                        continue;
                    }
                }

                // --> Extended sequence numbers (ESP).
                if (!ike) {
                    std::vector<SIkeTransform> ourEsn = ours.ofType(EIKE_TT_ESN);
                    if (ourEsn.empty()) {
                        SIkeTransform no;
                        no.type = EIKE_TT_ESN;
                        no.id = EIKE_ESN_NO;
                        ourEsn.push_back(no);
                    }

                    if (!theirEsn.empty()) {
                        bool found = false;
                        for (const SIkeTransform& os : ourEsn) {
                            if (has(theirEsn, os.id)) {
                                SIkeTransform t;
                                t.type = EIKE_TT_ESN;
                                t.id = os.id;
                                result.transforms.push_back(t);
                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            continue;
                        }
                    }
                }

                chosen = std::move(result);
                return true;
            }

            return false;
        }

    }

    /* Parses a proposal string. */
    int32_t ParseIkeProposal(std::string_view text, uint8_t protocol, SIkeProposal& out) {
        out = SIkeProposal();
        out.protocol = protocol;

        bool anyPrf = false;
        std::vector<uint16_t> integs;

        while (!text.empty()) {
            size_t dash = text.find('-');
            std::string_view token = text.substr(0, dash);
            text = dash == std::string_view::npos ? std::string_view() : text.substr(dash + 1);
            if (token.empty()) {
                return -EINVAL;
            }

            const Token* found = nullptr;
            for (const Token& t : TOKENS) {
                if (token == t.name) {
                    found = &t;
                    break;
                }
            }

            if (!found) {
                return -EINVAL;
            }

            if ((found->type == EIKE_TT_PRF && protocol != EIKE_PROTO_IKE) || (found->type == EIKE_TT_ESN && protocol == EIKE_PROTO_IKE)) {
                return -EINVAL;
            }

            SIkeTransform t;
            t.type = found->type;
            t.id = found->id;
            t.keyLength = found->keyLength;
            if (t.type == EIKE_TT_ENCR) {
                const SIkeEncrInfo* info = IkeEncrInfo(t.id);
                if (info && !info->keyLengthAttr) {
                    t.keyLength = 0;
                }
            }

            addOnce(out, t);
            anyPrf = anyPrf || t.type == EIKE_TT_PRF;
            if (t.type == EIKE_TT_INTEG) {
                integs.push_back(t.id);
            }
        }

        if (out.ofType(EIKE_TT_ENCR).empty()) {
            return -EINVAL;
        }

        if (protocol == EIKE_PROTO_IKE) {
            if (!anyPrf) {
                for (uint16_t integ : integs) {
                    SIkeTransform t;
                    t.type = EIKE_TT_PRF;
                    t.id = prfOf(integ);
                    addOnce(out, t);
                }
            }

            if (out.ofType(EIKE_TT_PRF).empty() || out.ofType(EIKE_TT_DH).empty()) {
                return -EINVAL;
            }
        }

        return SBOX_OK;
    }

    /* Formats a proposal. */
    std::string FormatIkeProposal(const SIkeProposal& proposal) {
        std::string out;
        for (const SIkeTransform& t : proposal.transforms) {
            const char* name = nullptr;
            for (const Token& tok : TOKENS) {
                uint16_t len = t.keyLength;
                const SIkeEncrInfo* info = t.type == EIKE_TT_ENCR ? IkeEncrInfo(t.id) : nullptr;
                uint16_t tokLen = tok.keyLength;
                if (info && !info->keyLengthAttr) {
                    len = 0;
                    tokLen = 0;
                }

                if (tok.type == t.type && tok.id == t.id && (t.type != EIKE_TT_ENCR || tokLen == len)) {
                    name = tok.name;
                    break;
                }
            }

            if (t.type == EIKE_TT_INTEG && t.id == EIKE_INTEG_NONE) {
                continue;
            }

            if (!out.empty()) {
                out += '-';
            }

            out += name ? std::string(name) : IkeTransformName(t.type, t.id);
        }

        return out;
    }

    /* Default IKE proposals. */
    std::vector<SIkeProposal> DefaultIkeProposals() {
        std::vector<SIkeProposal> out(2);
        ParseIkeProposal("aes256gcm16-aes128gcm16-chacha20poly1305-prfsha512-prfsha384-prfsha256-prfsha1-"
                         "curve25519-ecp384-ecp256-modp2048-modp1024", EIKE_PROTO_IKE, out[0]);
        ParseIkeProposal("aes256-aes192-aes128-3des-sha512-sha384-sha256-sha1-prfsha512-prfsha384-prfsha256-prfsha1-"
                         "curve25519-ecp384-ecp256-modp2048-modp1024", EIKE_PROTO_IKE, out[1]);
        return out;
    }

    /* Default ESP proposals. */
    std::vector<SIkeProposal> DefaultEspProposals() {
        std::vector<SIkeProposal> out(2);
        ParseIkeProposal("aes256gcm16-aes128gcm16-chacha20poly1305-aes256gcm12-aes128gcm12-"
                         "curve25519-ecp384-ecp256-modp2048-modp1024-noesn", EIKE_PROTO_ESP, out[0]);
        ParseIkeProposal("aes256-aes192-aes128-3des-sha512-sha384-sha256-sha1-"
                         "curve25519-ecp384-ecp256-modp2048-modp1024-noesn", EIKE_PROTO_ESP, out[1]);
        return out;
    }

    /* Selects a proposal. */
    bool SelectIkeProposal(const std::vector<SIkeProposal>& offered, const std::vector<SIkeProposal>& configured,
                           uint16_t preferredDh, EIkeDhMode dhMode, const FIkeTransformFilter& filter, SIkeProposal& chosen) {
        // --> First look for a match that uses the group the peer already sent a KE payload
        // for, which avoids an INVALID_KE_PAYLOAD round trip.
        bool usesDh = dhMode == EIKE_DHM_REQUIRED || (!offered.empty() && offered[0].protocol == EIKE_PROTO_IKE);
        for (int32_t pass = (preferredDh && usesDh) ? 0 : 1; pass < 2; ++pass) {
            for (const SIkeProposal& ours : configured) {
                for (const SIkeProposal& theirs : offered) {
                    if (tryPair(ours, theirs, preferredDh, pass == 0, dhMode, filter, chosen)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

}
}
