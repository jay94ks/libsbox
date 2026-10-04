#ifndef __INCLUDE_SBOX_IMAGE_REFERENCE_HPP__
#define __INCLUDE_SBOX_IMAGE_REFERENCE_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace image {

    /**
     * Docker Hub's canonical domain in normalized references.
     */
    constexpr const char* DOCKER_HUB_DOMAIN = "docker.io";

    /**
     * Host that serves Docker Hub's registry API.
     */
    constexpr const char* DOCKER_HUB_REGISTRY = "registry-1.docker.io";

    /**
     * An image reference in the grammar of Docker's distribution/reference package:
     *
     *     reference := name [ ":" tag ] [ "@" digest ]
     *     name      := [ domain "/" ] path
     *     domain    := host [ ":" port ]     (host: DNS name, IPv4 or "[IPv6]")
     *     path      := component ( "/" component )*,  component := [a-z0-9]+ ( ( [._] | "__" | "-"+ ) [a-z0-9]+ )*
     *     tag       := [A-Za-z0-9_] [A-Za-z0-9_.-]{0,127}
     *
     * After normalization (ParseNormalizedReference) the domain is always set:
     * "alpine" is "docker.io/library/alpine".
     */
    struct SBOX_API SReference {
        std::string domain;     // --> "docker.io", "localhost:5000", "[::1]:5000"; empty only before normalization.
        std::string path;       // --> "library/alpine".
        std::string tag;        // --> Empty when absent.
        std::string digest;     // --> "sha256:..." or empty.

        /**
         * Parses a reference strictly: nothing is added or rewritten. A first component that
         * contains '.' or ':' or is "localhost" (or has upper-case letters) is the domain.
         * @return SBOX_OK; -EINVAL for a malformed reference, an upper-case repository name,
         *         a name longer than 255 characters or a malformed digest.
         */
        static int32_t parse(std::string_view text, SReference& out);

        /**
         * Returns "domain/path" (or just "path" when there is no domain).
         */
        std::string name() const;

        /**
         * Returns the full form: name[:tag][@digest].
         */
        std::string toString() const;

        /**
         * Returns the short form Docker prints: "docker.io/library/" and "docker.io/" are
         * dropped ("alpine:latest", "user/app:1").
         */
        std::string familiarName() const;

        /**
         * Returns familiarName() with the tag and digest.
         */
        std::string familiarString() const;

        /** Returns true when a tag is set. */
        inline bool hasTag() const noexcept { return !tag.empty(); }

        /** Returns true when a digest is set. */
        inline bool hasDigest() const noexcept { return !digest.empty(); }

        /** Returns true when the references are identical. */
        inline bool operator==(const SReference& other) const noexcept {
            return domain == other.domain && path == other.path && tag == other.tag && digest == other.digest;
        }
    };

    /**
     * Parses and normalizes a user-supplied reference like Docker's ParseNormalizedNamed:
     * a missing domain becomes docker.io, "index.docker.io" becomes docker.io, and single
     * component Docker Hub paths get the "library/" prefix. A 64 character hex string is
     * rejected (it would be ambiguous with an image ID).
     * The tag is left empty when none was given (see WithDefaultTag).
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseNormalizedReference(std::string_view text, SReference& out);

    /**
     * Parses like ParseNormalizedReference and then applies Docker's ParseDockerRef rules: a
     * reference with neither tag nor digest gets ":latest", and one with both keeps only the
     * digest.
     */
    SBOX_API int32_t ParseDockerReference(std::string_view text, SReference& out);

    /**
     * Returns `ref` with ":latest" when it has neither tag nor digest.
     */
    SBOX_API SReference WithDefaultTag(SReference ref);

    /**
     * Returns true when `text` is a valid tag.
     */
    SBOX_API bool IsValidTag(std::string_view text) noexcept;

    /**
     * Returns true when `text` is a 64 character lower-case hex string (an image ID without
     * the "sha256:" prefix).
     */
    SBOX_API bool IsFullHexId(std::string_view text) noexcept;

    /**
     * Returns the host[:port] that serves the registry API of a reference domain
     * ("docker.io" -> "registry-1.docker.io"; other domains unchanged).
     */
    SBOX_API std::string RegistryHost(std::string_view domain);

    /**
     * Returns true when a registry domain is reached over plain HTTP / without TLS
     * verification by default, as Docker does for localhost and 127.0.0.0/8 / ::1.
     */
    SBOX_API bool IsLoopbackRegistry(std::string_view domain) noexcept;

}
}

#endif
