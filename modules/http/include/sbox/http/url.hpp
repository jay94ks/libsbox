#ifndef __INCLUDE_SBOX_HTTP_URL_HPP__
#define __INCLUDE_SBOX_HTTP_URL_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace http {

    /**
     * Characters PercentEncode leaves alone (everything else becomes %XX).
     */
    enum EPercentSet : uint8_t {
        EPCT_COMPONENT = 0,     // --> Keeps only unreserved (ALPHA DIGIT - . _ ~): one opaque component.
        EPCT_PATH,              // --> Also keeps sub-delims, ':', '@' and '/': a whole path.
        EPCT_QUERY,             // --> Keeps what a query may hold except '&', '=', '+', '#'.
        EPCT_FORM,              // --> application/x-www-form-urlencoded: like COMPONENT, space as '+'.
    };

    /**
     * Percent-encodes `text` (UTF-8 bytes are encoded byte by byte, hex digits upper case).
     */
    SBOX_API std::string PercentEncode(std::string_view text, EPercentSet set = EPCT_COMPONENT);

    /**
     * Decodes %XX escapes (and '+' as space when `plusAsSpace`).
     * @return SBOX_OK, or -EINVAL for a malformed escape (`out` is then unspecified).
     */
    SBOX_API int32_t PercentDecode(std::string_view text, std::string& out, bool plusAsSpace = false);

    /**
     * Name/value pairs of a query string or a form, in order (duplicates kept).
     */
    using SQueryParams = std::vector<std::pair<std::string, std::string>>;

    /**
     * Builds a query string ("a=1&b=x%20y") from pairs; names and values are encoded as
     * components (a space becomes %20, which every server accepts, unlike '+' in some).
     */
    SBOX_API std::string BuildQuery(const SQueryParams& params);

    /**
     * Splits a query string into decoded pairs ('+' decodes to a space; a pair without '='
     * yields an empty value).
     * @return SBOX_OK or -EINVAL for a malformed escape.
     */
    SBOX_API int32_t ParseQuery(std::string_view query, SQueryParams& out);

    /**
     * URI reference (RFC 3986): parsed components kept in their encoded form.
     *
     * The `has*` flags tell an empty component from an absent one ("http://a/?" has an empty
     * query, "http://a/" has none), which matters for reference resolution and recomposition.
     * The scheme is lower-cased, and so is the host of http, https and scheme-less references
     * (other schemes, such as http+unix, keep the host as written); an IPv6 literal is stored without
     * its brackets ("::1"), and hostPort() / toString() put them back.
     */
    struct SBOX_API SUrl {
        std::string scheme;     // --> Lower case, empty for a relative reference.
        std::string userinfo;   // --> "user:password" as written (still percent-encoded).
        std::string host;       // --> Reg-name (encoded) or IP literal without brackets.
        int32_t port = -1;      // --> Explicit port, or -1 when none was given.
        std::string path;       // --> Encoded path ("" or "/a/b").
        std::string query;      // --> Without the '?'.
        std::string fragment;   // --> Without the '#'.
        bool hasAuthority = false;
        bool hasUserinfo = false;
        bool hasQuery = false;
        bool hasFragment = false;

        /**
         * Parses an absolute URI or a relative reference.
         * Control characters, spaces, non-ASCII bytes, malformed %XX escapes, bad ports and
         * malformed IP literals are rejected.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SUrl& out);

        /**
         * Resolves `reference` against `base` (RFC 3986 section 5.2, strict mode).
         * @param base Must be absolute (have a scheme).
         * @return SBOX_OK, or -EINVAL when the base is not absolute or the reference does not parse.
         */
        static int32_t resolve(const SUrl& base, std::string_view reference, SUrl& out);

        /**
         * Resolves an already parsed reference against `base` (RFC 3986 section 5.2.2).
         */
        static SUrl resolve(const SUrl& base, const SUrl& reference);

        /**
         * Recomposes the reference (RFC 3986 section 5.3).
         */
        std::string toString() const;

        /** Returns true when the reference has a scheme. */
        inline bool isAbsolute() const noexcept { return !scheme.empty(); }

        /** Returns true when the host is an IPv6 literal (stored without brackets). */
        bool isIpv6Host() const noexcept;

        /**
         * Returns the explicit port, or the scheme's default (80 for http, 443 for https,
         * 0 when unknown).
         */
        uint16_t effectivePort() const noexcept;

        /**
         * Returns "host[:port]" as used in a Host header: IPv6 in brackets, and the port only
         * when it was explicit and differs from the scheme default.
         */
        std::string hostPort() const;

        /**
         * Returns the origin-form request target: the path ("/" when empty) and "?query".
         */
        std::string requestTarget() const;

        /**
         * Returns the decoded user name and password from the userinfo.
         * @return SBOX_OK, -ENOENT without userinfo, or -EINVAL for a malformed escape.
         */
        int32_t credentials(std::string& user, std::string& password) const;
    };

    /**
     * Removes "." and ".." segments from a path (RFC 3986 section 5.2.4).
     */
    SBOX_API std::string RemoveDotSegments(std::string_view path);

    /**
     * Returns the default port of "http" (80) or "https" (443), 0 for other schemes.
     */
    SBOX_API uint16_t DefaultPort(std::string_view scheme) noexcept;

}
}

#endif
