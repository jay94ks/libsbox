#include "lex.hpp"
#include <cstring>

namespace sbox {
namespace http {
namespace lex {

    /* Returns true for a tchar. */
    bool IsTchar(char c) noexcept {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            return true;
        }

        return c != '\0' && std::strchr("!#$%&'*+-.^_`|~", c) != nullptr;
    }

    /* Lower-cases ASCII. */
    std::string Lower(std::string_view text) {
        std::string out(text);
        for (char& c : out) {
            if (c >= 'A' && c <= 'Z') {
                c = char(c - 'A' + 'a');
            }
        }

        return out;
    }

    /* Trims whitespace. */
    std::string_view Trim(std::string_view text) noexcept {
        while (!text.empty() && IsWs(text.front())) {
            text.remove_prefix(1);
        }

        while (!text.empty() && IsWs(text.back())) {
            text.remove_suffix(1);
        }

        return text;
    }

    /* Skips whitespace. */
    void Cursor::skipWs() noexcept {
        while (pos < text.size() && IsWs(text[pos])) {
            ++pos;
        }
    }

    /* Reads a token. */
    std::string_view Cursor::token() noexcept {
        size_t start = pos;
        while (pos < text.size() && IsTchar(text[pos])) {
            ++pos;
        }

        return text.substr(start, pos - start);
    }

    /* Reads a quoted string. */
    bool Cursor::quoted(std::string& out) {
        if (peek() != '"') {
            return false;
        }

        ++pos;
        out.clear();

        while (pos < text.size()) {
            char c = text[pos++];
            if (c == '"') {
                return true;
            }

            if (c == '\\') {
                if (pos >= text.size()) {
                    return false;
                }

                c = text[pos++];
            }

            out.push_back(c);
        }

        return false;
    }

    /* Reads a token or quoted string. */
    bool Cursor::value(std::string& out) {
        if (peek() == '"') {
            return quoted(out);
        }

        std::string_view t = token();
        out = std::string(t);
        return true;
    }

    /* Parses ";name=value" parameters. */
    bool Cursor::params(std::vector<std::pair<std::string, std::string>>& out) {
        while (true) {
            skipWs();
            if (atEnd() || peek() == ',') {
                return true;
            }

            if (peek() != ';') {
                return false;
            }

            ++pos;
            skipWs();

            // --> Tolerate an empty parameter (a stray ";").
            if (atEnd() || peek() == ',' || peek() == ';') {
                continue;
            }

            std::string_view name = token();
            if (name.empty()) {
                return false;
            }

            skipWs();
            std::string val;
            if (peek() == '=') {
                ++pos;
                skipWs();
                if (!value(val)) {
                    return false;
                }
            }

            out.emplace_back(Lower(name), std::move(val));
        }
    }

    /* Quotes a value unless it is a token. */
    std::string QuoteIfNeeded(std::string_view value) {
        bool token = !value.empty();
        for (char c : value) {
            if (!IsTchar(c)) {
                token = false;
                break;
            }
        }

        if (token) {
            return std::string(value);
        }

        std::string out = "\"";
        for (char c : value) {
            if (c == '"' || c == '\\') {
                out.push_back('\\');
            }

            out.push_back(c);
        }

        out.push_back('"');
        return out;
    }

}
}
}
