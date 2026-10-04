#include <sbox/vpn/l2tp/ikev1peer.hpp>
#include <cerrno>

namespace sbox {
namespace vpn {

    namespace {

        /* Splits on '-' and lower-cases. */
        std::vector<std::string> tokens(std::string_view text) {
            std::vector<std::string> out;
            size_t start = 0;
            while (start <= text.size()) {
                size_t dash = text.find('-', start);
                std::string_view part = text.substr(start, dash == std::string_view::npos ? std::string_view::npos : dash - start);
                std::string lower;
                for (char c : part) {
                    lower.push_back(char(c >= 'A' && c <= 'Z' ? c + 32 : c));
                }

                if (!lower.empty()) {
                    out.push_back(lower);
                }

                if (dash == std::string_view::npos) {
                    break;
                }

                start = dash + 1;
            }

            return out;
        }

        /* Hash algorithm token. */
        bool hashOf(const std::string& t, uint16_t& out) {
            if (t == "md5") {
                out = EIKE1_HASH_MD5;
            }
            else if (t == "sha1" || t == "sha") {
                out = EIKE1_HASH_SHA1;
            }
            else if (t == "sha256" || t == "sha2_256") {
                out = EIKE1_HASH_SHA256;
            }
            else if (t == "sha384" || t == "sha2_384") {
                out = EIKE1_HASH_SHA384;
            }
            else if (t == "sha512" || t == "sha2_512") {
                out = EIKE1_HASH_SHA512;
            }
            else {
                return false;
            }

            return true;
        }

        /* Group token. */
        bool groupOf(const std::string& t, uint16_t& out) {
            if (t == "modp1024") {
                out = 2;
            }
            else if (t == "modp2048") {
                out = 14;
            }
            else if (t == "ecp256") {
                out = 19;
            }
            else if (t == "ecp384") {
                out = 20;
            }
            else {
                return false;
            }

            return true;
        }

    }

    /* Phase 1 proposal parser. */
    int32_t ParseIkev1Proposal(std::string_view text, std::vector<SIkev1Suite>& out) {
        struct Cipher { uint16_t encr; uint16_t bits; };
        std::vector<Cipher> ciphers;
        std::vector<uint16_t> hashes;
        std::vector<uint16_t> groups;
        for (const std::string& t : tokens(text)) {
            uint16_t v = 0;
            if (t == "aes128" || t == "aes") {
                ciphers.push_back({ EIKE1_ENCR_AES, 128 });
            }
            else if (t == "aes192") {
                ciphers.push_back({ EIKE1_ENCR_AES, 192 });
            }
            else if (t == "aes256") {
                ciphers.push_back({ EIKE1_ENCR_AES, 256 });
            }
            else if (t == "3des") {
                ciphers.push_back({ EIKE1_ENCR_3DES, 192 });
            }
            else if (hashOf(t, v)) {
                hashes.push_back(v);
            }
            else if (groupOf(t, v)) {
                groups.push_back(v);
            }
            else {
                return -EINVAL;
            }
        }

        if (ciphers.empty() || hashes.empty() || groups.empty()) {
            return -EINVAL;
        }

        for (uint16_t g : groups) {
            for (const Cipher& c : ciphers) {
                for (uint16_t h : hashes) {
                    SIkev1Suite s;
                    s.encr = c.encr;
                    s.keyBits = c.bits;
                    s.hash = h;
                    s.group = g;
                    out.push_back(s);
                }
            }
        }

        return SBOX_OK;
    }

    /* ESP proposal parser. */
    int32_t ParseIkev1EspProposal(std::string_view text, std::vector<SIkev1EspSuite>& out) {
        struct Cipher { uint8_t id; uint16_t bits; bool aead; };
        std::vector<Cipher> ciphers;
        std::vector<uint16_t> auths;
        for (const std::string& t : tokens(text)) {
            if (t == "aes128" || t == "aes") {
                ciphers.push_back({ EIKE1_ESP_AES, 128, false });
            }
            else if (t == "aes192") {
                ciphers.push_back({ EIKE1_ESP_AES, 192, false });
            }
            else if (t == "aes256") {
                ciphers.push_back({ EIKE1_ESP_AES, 256, false });
            }
            else if (t == "3des") {
                ciphers.push_back({ EIKE1_ESP_3DES, 0, false });
            }
            else if (t == "aes128gcm16") {
                ciphers.push_back({ EIKE1_ESP_AES_GCM_16, 128, true });
            }
            else if (t == "aes256gcm16") {
                ciphers.push_back({ EIKE1_ESP_AES_GCM_16, 256, true });
            }
            else if (t == "sha1" || t == "sha") {
                auths.push_back(EIKE1_AA_HMAC_SHA1);
            }
            else if (t == "sha256") {
                auths.push_back(EIKE1_AA_HMAC_SHA256);
            }
            else if (t == "sha384") {
                auths.push_back(EIKE1_AA_HMAC_SHA384);
            }
            else if (t == "sha512") {
                auths.push_back(EIKE1_AA_HMAC_SHA512);
            }
            else {
                return -EINVAL;
            }
        }

        if (ciphers.empty()) {
            return -EINVAL;
        }

        for (const Cipher& c : ciphers) {
            if (c.aead) {
                out.push_back({ c.id, c.bits, EIKE1_AA_NONE });
                continue;
            }

            if (auths.empty()) {
                return -EINVAL;
            }

            for (uint16_t a : auths) {
                out.push_back({ c.id, c.bits, a });
            }
        }

        return SBOX_OK;
    }

    /* ESP suite name. */
    std::string Ikev1EspSuiteName(const SIkev1EspSuite& suite) {
        std::string text;
        switch (suite.espId) {
        case EIKE1_ESP_3DES: text = "3des"; break;
        case EIKE1_ESP_AES: text = "aes" + std::to_string(suite.keyBits ? suite.keyBits : 128); break;
        case EIKE1_ESP_AES_GCM_16: return "aes" + std::to_string(suite.keyBits ? suite.keyBits : 128) + "gcm16";
        default: text = "esp" + std::to_string(suite.espId); break;
        }

        switch (suite.authAlg) {
        case EIKE1_AA_HMAC_SHA1: text += "-sha1"; break;
        case EIKE1_AA_HMAC_SHA256: text += "-sha256"; break;
        case EIKE1_AA_HMAC_SHA384: text += "-sha384"; break;
        case EIKE1_AA_HMAC_SHA512: text += "-sha512"; break;
        default: break;
        }

        return text;
    }

}
}
