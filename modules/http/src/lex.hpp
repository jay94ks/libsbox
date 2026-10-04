#ifndef __SRC_HTTP_LEX_HPP__
#define __SRC_HTTP_LEX_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace http {
namespace lex {

    /**
     * Returns true for an RFC 9110 tchar.
     */
    bool IsTchar(char c) noexcept;

    /**
     * Returns true for SP or HTAB.
     */
    inline bool IsWs(char c) noexcept { return c == ' ' || c == '\t'; }

    /**
     * Lower-cases ASCII.
     */
    std::string Lower(std::string_view text);

    /**
     * Trims SP/HTAB from both ends.
     */
    std::string_view Trim(std::string_view text) noexcept;

    /**
     * Cursor over a header value.
     */
    struct Cursor {
        std::string_view text;
        size_t pos = 0;

        inline bool atEnd() const noexcept { return pos >= text.size(); }

        inline char peek() const noexcept { return pos < text.size() ? text[pos] : '\0'; }

        /** Skips SP/HTAB. */
        void skipWs() noexcept;

        /** Reads a token (possibly empty). */
        std::string_view token() noexcept;

        /**
         * Reads a quoted-string starting at '"', unescaping quoted-pairs.
         * @return false when unterminated.
         */
        bool quoted(std::string& out);

        /**
         * Reads a token or a quoted-string as a parameter value.
         * @return false when neither is present / malformed.
         */
        bool value(std::string& out);

        /**
         * Parses `*( OWS ";" OWS name "=" value )` until a ',' or the end.
         * @return false when malformed.
         */
        bool params(std::vector<std::pair<std::string, std::string>>& out);
    };

    /**
     * Quotes a parameter value when it is not a token.
     */
    std::string QuoteIfNeeded(std::string_view value);

}
}
}

#endif
