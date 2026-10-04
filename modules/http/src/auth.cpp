#include <sbox/http/auth.hpp>
#include <sbox/http/headers.hpp>
#include "lex.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace http {

    namespace {

        const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        int32_t b64Value(char c) noexcept {
            if (c >= 'A' && c <= 'Z') {
                return c - 'A';
            }

            if (c >= 'a' && c <= 'z') {
                return c - 'a' + 26;
            }

            if (c >= '0' && c <= '9') {
                return c - '0' + 52;
            }

            if (c == '+') {
                return 62;
            }

            if (c == '/') {
                return 63;
            }

            return -1;
        }

        inline bool isToken68Char(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/';
        }

        /*
         * Decides whether the text at the cursor is a token68 (true) or an auth-param list.
         */
        bool looksLikeToken68(lex::Cursor cur) noexcept {
            std::string_view t = cur.token();
            cur.skipWs();

            if (t.empty() || cur.peek() != '=') {
                return true;
            }

            ++cur.pos;
            cur.skipWs();

            // --> "name=value" is a parameter; "abc==" or "abc=" at the end is token68 padding.
            return cur.atEnd() || cur.peek() == ',' || cur.peek() == '=';
        }

    }

    /* Encodes base64. */
    std::string Base64Encode(const SReadOnlyByteSpan& bytes) {
        std::string out;
        out.reserve((bytes.size + 2) / 3 * 4);

        size_t i = 0;
        for (; i + 3 <= bytes.size; i += 3) {
            uint32_t v = (uint32_t(bytes[i]) << 16) | (uint32_t(bytes[i + 1]) << 8) | bytes[i + 2];
            out.push_back(B64[(v >> 18) & 63]);
            out.push_back(B64[(v >> 12) & 63]);
            out.push_back(B64[(v >> 6) & 63]);
            out.push_back(B64[v & 63]);
        }

        size_t rest = bytes.size - i;
        if (rest == 1) {
            uint32_t v = uint32_t(bytes[i]) << 16;
            out.push_back(B64[(v >> 18) & 63]);
            out.push_back(B64[(v >> 12) & 63]);
            out += "==";
        } else if (rest == 2) {
            uint32_t v = (uint32_t(bytes[i]) << 16) | (uint32_t(bytes[i + 1]) << 8);
            out.push_back(B64[(v >> 18) & 63]);
            out.push_back(B64[(v >> 12) & 63]);
            out.push_back(B64[(v >> 6) & 63]);
            out.push_back('=');
        }

        return out;
    }

    /* Decodes base64. */
    int32_t Base64Decode(std::string_view text, std::vector<uint8_t>& out) {
        out.clear();

        size_t end = text.size();
        while (end > 0 && text[end - 1] == '=' && text.size() - end < 2) {
            --end;
        }

        // --> With padding the total length must be a multiple of four.
        if (end != text.size() && text.size() % 4 != 0) {
            return -EINVAL;
        }

        if (end % 4 == 1) {
            return -EINVAL;
        }

        out.reserve(end / 4 * 3 + 2);
        uint32_t acc = 0;
        int32_t bits = 0;

        for (size_t i = 0; i < end; ++i) {
            int32_t v = b64Value(text[i]);
            if (v < 0) {
                return -EINVAL;
            }

            acc = (acc << 6) | uint32_t(v);
            bits += 6;

            if (bits >= 8) {
                bits -= 8;
                out.push_back(uint8_t((acc >> bits) & 0xff));
            }
        }

        // --> Leftover bits must be zero (canonical encoding).
        if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) {
            return -EINVAL;
        }

        return SBOX_OK;
    }

    /* Builds a Basic Authorization value. */
    std::string EncodeBasicAuth(std::string_view user, std::string_view password) {
        std::string joined;
        joined.reserve(user.size() + password.size() + 1);
        joined += user;
        joined.push_back(':');
        joined += password;
        return "Basic " + Base64Encode(BytesOf(joined));
    }

    /* Decodes a Basic Authorization value. */
    int32_t DecodeBasicAuth(std::string_view value, std::string& user, std::string& password) {
        value = lex::Trim(value);
        size_t sp = value.find(' ');
        if (sp == std::string_view::npos || !EqualsNoCase(value.substr(0, sp), "Basic")) {
            return -ENOENT;
        }

        std::vector<uint8_t> raw;
        if (Base64Decode(lex::Trim(value.substr(sp + 1)), raw) != SBOX_OK) {
            return -EINVAL;
        }

        std::string_view text(reinterpret_cast<const char*>(raw.data()), raw.size());
        size_t colon = text.find(':');
        if (colon == std::string_view::npos) {
            return -EINVAL;
        }

        user = std::string(text.substr(0, colon));
        password = std::string(text.substr(colon + 1));
        return SBOX_OK;
    }

    /* Compares the scheme. */
    bool SAuthChallenge::isScheme(std::string_view name) const noexcept {
        return EqualsNoCase(scheme, name);
    }

    /* Looks up a parameter. */
    std::string SAuthChallenge::param(std::string_view name) const {
        for (const auto& [k, v] : params) {
            if (EqualsNoCase(k, name)) {
                return v;
            }
        }

        return {};
    }

    /* Checks for a parameter. */
    bool SAuthChallenge::hasParam(std::string_view name) const noexcept {
        for (const auto& kv : params) {
            if (EqualsNoCase(kv.first, name)) {
                return true;
            }
        }

        return false;
    }

    /* Parses WWW-Authenticate challenges. */
    int32_t ParseAuthChallenges(std::string_view value, std::vector<SAuthChallenge>& out) {
        lex::Cursor cur{ value };

        while (true) {
            cur.skipWs();
            while (cur.peek() == ',') {
                ++cur.pos;
                cur.skipWs();
            }

            if (cur.atEnd()) {
                return SBOX_OK;
            }

            SAuthChallenge ch;
            std::string_view scheme = cur.token();
            if (scheme.empty()) {
                return -EINVAL;
            }

            ch.scheme = std::string(scheme);

            size_t before = cur.pos;
            cur.skipWs();
            bool hadSpace = cur.pos != before;

            if (cur.atEnd() || cur.peek() == ',') {
                out.push_back(std::move(ch));
                continue;
            }

            if (!hadSpace) {
                return -EINVAL;
            }

            if (looksLikeToken68(cur)) {
                size_t start = cur.pos;
                while (!cur.atEnd() && isToken68Char(cur.peek())) {
                    ++cur.pos;
                }

                if (cur.pos == start) {
                    return -EINVAL;
                }

                while (cur.peek() == '=') {
                    ++cur.pos;
                }

                ch.token68 = std::string(value.substr(start, cur.pos - start));
                cur.skipWs();

                if (!cur.atEnd() && cur.peek() != ',') {
                    return -EINVAL;
                }

                out.push_back(std::move(ch));
                continue;
            }

            // --> auth-param list: name BWS "=" BWS (token / quoted-string), comma separated.
            // After a comma, "token =" continues this challenge; anything else starts the next.
            while (true) {
                std::string_view name = cur.token();
                cur.skipWs();

                if (name.empty() || cur.peek() != '=') {
                    return -EINVAL;
                }

                ++cur.pos;
                cur.skipWs();

                std::string val;
                if (cur.peek() == '"') {
                    if (!cur.quoted(val)) {
                        return -EINVAL;
                    }
                } else {
                    std::string_view tok = cur.token();
                    if (tok.empty()) {
                        return -EINVAL;
                    }

                    val = std::string(tok);
                }

                ch.params.emplace_back(lex::Lower(name), std::move(val));
                cur.skipWs();

                if (cur.atEnd()) {
                    break;
                }

                if (cur.peek() != ',') {
                    return -EINVAL;
                }

                while (cur.peek() == ',') {
                    ++cur.pos;
                    cur.skipWs();
                }

                if (cur.atEnd()) {
                    break;
                }

                lex::Cursor probe = cur;
                std::string_view next = probe.token();
                probe.skipWs();

                if (next.empty() || probe.peek() != '=') {
                    break;
                }
            }

            out.push_back(std::move(ch));
        }
    }

}
}
