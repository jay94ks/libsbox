#ifndef __INCLUDE_SBOX_HTTP_AUTH_HPP__
#define __INCLUDE_SBOX_HTTP_AUTH_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace http {

    /**
     * Encodes bytes as standard base64 (RFC 4648 section 4) with padding.
     */
    SBOX_API std::string Base64Encode(const SReadOnlyByteSpan& bytes);

    /**
     * Decodes standard base64. Padding is optional; whitespace and other characters are
     * rejected.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t Base64Decode(std::string_view text, std::vector<uint8_t>& out);

    /**
     * Returns an Authorization value for HTTP Basic: "Basic base64(user:password)".
     */
    SBOX_API std::string EncodeBasicAuth(std::string_view user, std::string_view password);

    /**
     * Decodes a "Basic ..." Authorization value (scheme compared case-insensitively).
     * @return SBOX_OK, -ENOENT when the scheme is not Basic, or -EINVAL when malformed.
     */
    SBOX_API int32_t DecodeBasicAuth(std::string_view value, std::string& user, std::string& password);

    /**
     * One challenge of a WWW-Authenticate / Proxy-Authenticate header (RFC 9110 section 11),
     * e.g. Docker Hub's
     * `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="..."`.
     */
    struct SBOX_API SAuthChallenge {
        std::string scheme;     // --> As sent ("Bearer", "Basic"); compare with isScheme().
        std::string token68;    // --> The token68 form, when the challenge used it.
        std::vector<std::pair<std::string, std::string>> params;   // --> Names lower case, values unquoted.

        /**
         * Returns true when the scheme equals `name` ignoring case.
         */
        bool isScheme(std::string_view name) const noexcept;

        /**
         * Returns a parameter value (name compared case-insensitively), or an empty string.
         */
        std::string param(std::string_view name) const;

        /**
         * Returns true when the parameter is present.
         */
        bool hasParam(std::string_view name) const noexcept;
    };

    /**
     * Parses a WWW-Authenticate value, which may hold several comma separated challenges,
     * each with auth-params or a token68. Appends to `out`.
     * @return SBOX_OK or -EINVAL when malformed.
     */
    SBOX_API int32_t ParseAuthChallenges(std::string_view value, std::vector<SAuthChallenge>& out);

}
}

#endif
