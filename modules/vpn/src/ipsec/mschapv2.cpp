#include <sbox/vpn/ipsec/mschapv2.hpp>
#include "crypto.hpp"
#include <certpp/crypto/sym.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/utils/secure.hpp>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace certpp::crypto;
    using namespace ipsec;

    namespace {

        // --> RFC 2759 8.7 magic constants.
        const uint8_t MAGIC1[39] = {
            0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74,
            0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69,
            0x6E, 0x67, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
        };

        const uint8_t MAGIC2[41] = {
            0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x20, 0x69, 0x74,
            0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20,
            0x6F, 0x6E, 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E,
        };

        // --> RFC 3079 3.4 key derivation constants.
        const char* MASTER_MAGIC = "This is the MPPE Master Key";
        const char* KEY_MAGIC2 = "On the client side, this is the send key; on the server side, it is the receive key.";
        const char* KEY_MAGIC3 = "On the client side, this is the receive key; on the server side, it is the send key.";

        /* Expands 7 key bytes into an 8-byte DES key (parity bits left clear, DES ignores them). */
        void desKey(const uint8_t* in, uint8_t* out) {
            out[0] = uint8_t(in[0] & 0xfe);
            out[1] = uint8_t(((in[0] << 7) | (in[1] >> 1)) & 0xfe);
            out[2] = uint8_t(((in[1] << 6) | (in[2] >> 2)) & 0xfe);
            out[3] = uint8_t(((in[2] << 5) | (in[3] >> 3)) & 0xfe);
            out[4] = uint8_t(((in[3] << 4) | (in[4] >> 4)) & 0xfe);
            out[5] = uint8_t(((in[4] << 3) | (in[5] >> 5)) & 0xfe);
            out[6] = uint8_t(((in[5] << 2) | (in[6] >> 6)) & 0xfe);
            out[7] = uint8_t((in[6] << 1) & 0xfe);
        }

        /* One DES block encryption (ECB = CBC with a zero IV over a single block). */
        bool desEncrypt(const uint8_t* key7, const uint8_t* clear, uint8_t* out) {
            uint8_t key[8];
            desKey(key7, key);

            ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
            ISymmetricKeyPtr k = des ? des->createKey(certpp::SReadOnlyByteSpan(key, 8)) : nullptr;
            ISymmetricContextPtr ctx = k ? des->createContext(k) : nullptr;
            if (!ctx) {
                return false;
            }

            const uint8_t zero[8] = { 0 };
            ctx->padding(ESYMPAD_NONE);
            ctx->key(k, certpp::CBuffer(zero, 8));

            ISymmetricTransformerPtr t;
            if (ctx->createEncrypter(t) != certpp::ERET_OK || !t) {
                return false;
            }

            uint8_t buffer[24];
            certpp::SByteSpan step(buffer, sizeof(buffer));
            if (t->transform(certpp::SReadOnlyByteSpan(clear, 8), step) != certpp::ERET_OK) {
                return false;
            }

            size_t written = step.size;
            certpp::SByteSpan last(buffer + written, sizeof(buffer) - written);
            if (t->transformFinal(last) != certpp::ERET_OK) {
                return false;
            }

            written += last.size;

            // --> Unpadded CBC yields exactly one block; a PKCS#7 build would add a second one,
            // and the first block is the ECB value either way.
            if (written < 8) {
                return false;
            }

            std::memcpy(out, buffer, 8);
            certpp::CSecure::zero(certpp::SByteSpan(key, 8));
            return true;
        }

        /* Converts UTF-8 to UTF-16LE. */
        bool utf16le(std::string_view text, std::vector<uint8_t>& out) {
            out.clear();
            size_t i = 0;
            while (i < text.size()) {
                uint32_t c = uint8_t(text[i]);
                size_t extra = 0;
                if (c < 0x80) {
                    extra = 0;
                }
                else if ((c & 0xe0) == 0xc0) {
                    c &= 0x1f;
                    extra = 1;
                }
                else if ((c & 0xf0) == 0xe0) {
                    c &= 0x0f;
                    extra = 2;
                }
                else if ((c & 0xf8) == 0xf0) {
                    c &= 0x07;
                    extra = 3;
                }
                else {
                    return false;
                }

                if (extra && i + extra >= text.size()) {
                    return false;
                }

                for (size_t k = 1; k <= extra; ++k) {
                    uint8_t b = uint8_t(text[i + k]);
                    if ((b & 0xc0) != 0x80) {
                        return false;
                    }

                    c = (c << 6) | (b & 0x3f);
                }

                i += extra + 1;

                if (c >= 0x10000) {
                    c -= 0x10000;
                    uint32_t hi = 0xd800 + (c >> 10);
                    uint32_t lo = 0xdc00 + (c & 0x3ff);
                    out.push_back(uint8_t(hi));
                    out.push_back(uint8_t(hi >> 8));
                    out.push_back(uint8_t(lo));
                    out.push_back(uint8_t(lo >> 8));
                }
                else {
                    out.push_back(uint8_t(c));
                    out.push_back(uint8_t(c >> 8));
                }
            }

            return true;
        }

    }

    /* MD4 of the UTF-16LE password. */
    int32_t MsChapNtPasswordHash(std::string_view password, const SByteSpan& out) {
        if (out.size != 16) {
            return -EINVAL;
        }

        std::vector<uint8_t> unicode;
        if (!utf16le(password, unicode)) {
            return -EINVAL;
        }

        std::vector<uint8_t> h = Hash(EHASH_MD4, BytesOf(unicode));
        if (!unicode.empty()) {
            certpp::CSecure::zero(certpp::SByteSpan(unicode.data(), unicode.size()));
        }

        if (h.size() != 16) {
            return -EIO;
        }

        std::memcpy(out.data, h.data(), 16);
        return SBOX_OK;
    }

    /* MD4 of the password hash. */
    int32_t MsChapHashNtPasswordHash(const SReadOnlyByteSpan& passwordHash, const SByteSpan& out) {
        if (passwordHash.size != 16 || out.size != 16) {
            return -EINVAL;
        }

        std::vector<uint8_t> h = Hash(EHASH_MD4, passwordHash);
        if (h.size() != 16) {
            return -EIO;
        }

        std::memcpy(out.data, h.data(), 16);
        return SBOX_OK;
    }

    /* ChallengeHash. */
    int32_t MsChapChallengeHash(const SReadOnlyByteSpan& peerChallenge, const SReadOnlyByteSpan& authChallenge,
                                std::string_view userName, const SByteSpan& out) {
        if (peerChallenge.size != 16 || authChallenge.size != 16 || out.size != 8) {
            return -EINVAL;
        }

        std::vector<uint8_t> h = HashParts(EHASH_SHA1, { peerChallenge, authChallenge, BytesOf(userName) });
        if (h.size() != 20) {
            return -EIO;
        }

        std::memcpy(out.data, h.data(), 8);
        return SBOX_OK;
    }

    /* ChallengeResponse. */
    int32_t MsChapChallengeResponse(const SReadOnlyByteSpan& challenge, const SReadOnlyByteSpan& passwordHash,
                                    const SByteSpan& out) {
        if (challenge.size != 8 || passwordHash.size != 16 || out.size != 24) {
            return -EINVAL;
        }

        uint8_t z[21];
        std::memset(z, 0, sizeof(z));
        std::memcpy(z, passwordHash.data, 16);

        bool ok = desEncrypt(z, challenge.data, out.data) && desEncrypt(z + 7, challenge.data, out.data + 8)
            && desEncrypt(z + 14, challenge.data, out.data + 16);
        certpp::CSecure::zero(certpp::SByteSpan(z, sizeof(z)));
        return ok ? SBOX_OK : -EIO;
    }

    /* GenerateNTResponse. */
    int32_t MsChapNtResponse(const SReadOnlyByteSpan& authChallenge, const SReadOnlyByteSpan& peerChallenge,
                             std::string_view userName, const SReadOnlyByteSpan& passwordHash, const SByteSpan& out) {
        uint8_t challenge[8];
        int32_t r = MsChapChallengeHash(peerChallenge, authChallenge, userName, SByteSpan(challenge, 8));
        if (r != SBOX_OK) {
            return r;
        }

        return MsChapChallengeResponse(SReadOnlyByteSpan(challenge, 8), passwordHash, out);
    }

    /* GenerateAuthenticatorResponse. */
    std::string MsChapAuthenticatorResponse(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse,
                                            const SReadOnlyByteSpan& peerChallenge, const SReadOnlyByteSpan& authChallenge,
                                            std::string_view userName) {
        if (ntResponse.size != 24) {
            return std::string();
        }

        uint8_t hashHash[16];
        if (MsChapHashNtPasswordHash(passwordHash, SByteSpan(hashHash, 16)) != SBOX_OK) {
            return std::string();
        }

        std::vector<uint8_t> digest = HashParts(EHASH_SHA1, {
            SReadOnlyByteSpan(hashHash, 16), ntResponse, SReadOnlyByteSpan(MAGIC1, sizeof(MAGIC1)) });

        uint8_t challenge[8];
        if (digest.size() != 20 || MsChapChallengeHash(peerChallenge, authChallenge, userName, SByteSpan(challenge, 8)) != SBOX_OK) {
            return std::string();
        }

        digest = HashParts(EHASH_SHA1, { BytesOf(digest), SReadOnlyByteSpan(challenge, 8),
                                          SReadOnlyByteSpan(MAGIC2, sizeof(MAGIC2)) });
        if (digest.size() != 20) {
            return std::string();
        }

        return "S=" + ToHex(BytesOf(digest), true);
    }

    /* GetMasterKey. */
    int32_t MsChapMasterKey(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse, const SByteSpan& out) {
        if (ntResponse.size != 24 || out.size != 16) {
            return -EINVAL;
        }

        uint8_t hashHash[16];
        int32_t r = MsChapHashNtPasswordHash(passwordHash, SByteSpan(hashHash, 16));
        if (r != SBOX_OK) {
            return r;
        }

        std::vector<uint8_t> digest = HashParts(EHASH_SHA1, {
            SReadOnlyByteSpan(hashHash, 16), ntResponse, BytesOf(MASTER_MAGIC) });
        certpp::CSecure::zero(certpp::SByteSpan(hashHash, 16));
        if (digest.size() != 20) {
            return -EIO;
        }

        std::memcpy(out.data, digest.data(), 16);
        return SBOX_OK;
    }

    /* GetAsymmetricStartKey. */
    int32_t MsChapAsymmetricStartKey(const SReadOnlyByteSpan& masterKey, bool isSend, bool isServer, const SByteSpan& out) {
        if (masterKey.size != 16 || out.size == 0 || out.size > 16) {
            return -EINVAL;
        }

        uint8_t pad1[40];
        uint8_t pad2[40];
        std::memset(pad1, 0x00, sizeof(pad1));
        std::memset(pad2, 0xf2, sizeof(pad2));

        // --> The magic depends on direction and role exactly as RFC 3079 3.4 tabulates.
        const char* magic = isSend ? (isServer ? KEY_MAGIC3 : KEY_MAGIC2) : (isServer ? KEY_MAGIC2 : KEY_MAGIC3);

        std::vector<uint8_t> digest = HashParts(EHASH_SHA1, {
            masterKey, SReadOnlyByteSpan(pad1, 40), BytesOf(magic), SReadOnlyByteSpan(pad2, 40) });
        if (digest.size() != 20) {
            return -EIO;
        }

        std::memcpy(out.data, digest.data(), out.size);
        return SBOX_OK;
    }

    /* EAP-MSCHAPv2 MSK. */
    int32_t MsChapV2Msk(const SReadOnlyByteSpan& passwordHash, const SReadOnlyByteSpan& ntResponse, std::vector<uint8_t>& out) {
        uint8_t master[16];
        int32_t r = MsChapMasterKey(passwordHash, ntResponse, SByteSpan(master, 16));
        if (r != SBOX_OK) {
            return r;
        }

        std::vector<uint8_t> msk(64, 0);
        r = MsChapAsymmetricStartKey(SReadOnlyByteSpan(master, 16), true, false, SByteSpan(msk.data(), 16));
        if (r == SBOX_OK) {
            r = MsChapAsymmetricStartKey(SReadOnlyByteSpan(master, 16), false, false, SByteSpan(msk.data() + 16, 16));
        }

        certpp::CSecure::zero(certpp::SByteSpan(master, 16));
        if (r != SBOX_OK) {
            return r;
        }

        out = std::move(msk);
        return SBOX_OK;
    }

    /* Strips a domain prefix. */
    std::string MsChapUserName(std::string_view name) {
        size_t slash = name.rfind('\\');
        if (slash != std::string_view::npos) {
            name.remove_prefix(slash + 1);
        }

        return std::string(name);
    }

}
}
