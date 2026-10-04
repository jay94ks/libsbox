#include <sbox/image/reference.hpp>
#include <sbox/image/digest.hpp>
#include <cerrno>

namespace sbox {
namespace image {

    namespace {

        constexpr size_t NAME_TOTAL_LENGTH_MAX = 255;

        /* Returns true for [a-z0-9]. */
        bool isLowerAlnum(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        }

        /* Returns true for [A-Za-z0-9]. */
        bool isAlnum(char c) noexcept {
            return isLowerAlnum(c) || (c >= 'A' && c <= 'Z');
        }

        /* Returns true for [0-9]. */
        bool isDigit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        /* Returns true for a hex digit. */
        bool isHex(char c) noexcept {
            return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        /*
         * Matches one path component: [a-z0-9]+ ( ( [._] | "__" | "-"+ ) [a-z0-9]+ )*.
         */
        bool isPathComponent(std::string_view s) noexcept {
            size_t i = 0;
            size_t n = s.size();
            if (n == 0 || !isLowerAlnum(s[0])) {
                return false;
            }

            while (i < n) {
                while (i < n && isLowerAlnum(s[i])) {
                    ++i;
                }

                if (i == n) {
                    return true;
                }

                // --> Separator: '.', '_', "__" or a run of '-'.
                if (s[i] == '.') {
                    ++i;
                } else if (s[i] == '_') {
                    ++i;
                    if (i < n && s[i] == '_') {
                        ++i;
                    }
                } else if (s[i] == '-') {
                    while (i < n && s[i] == '-') {
                        ++i;
                    }
                } else {
                    return false;
                }

                if (i == n || !isLowerAlnum(s[i])) {
                    return false;
                }
            }

            return true;
        }

        /*
         * Matches a path: component ( "/" component )*.
         */
        bool isPath(std::string_view s) noexcept {
            if (s.empty()) {
                return false;
            }

            size_t start = 0;
            while (true) {
                size_t slash = s.find('/', start);
                std::string_view comp = s.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
                if (!isPathComponent(comp)) {
                    return false;
                }

                if (slash == std::string_view::npos) {
                    return true;
                }

                start = slash + 1;
            }
        }

        /*
         * Matches a domain-name component: [a-zA-Z0-9] | [a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9].
         */
        bool isDomainComponent(std::string_view s) noexcept {
            if (s.empty() || !isAlnum(s.front()) || !isAlnum(s.back())) {
                return false;
            }

            for (char c : s) {
                if (!isAlnum(c) && c != '-') {
                    return false;
                }
            }

            return true;
        }

        /*
         * Matches a registry domain: host [":" port], host being a DNS name / IPv4 address or a
         * bracketed IPv6 address.
         */
        bool isDomain(std::string_view s) noexcept {
            if (s.empty()) {
                return false;
            }

            std::string_view host = s;
            std::string_view port;
            if (s.front() == '[') {
                size_t close = s.find(']');
                if (close == std::string_view::npos || close < 2) {
                    return false;
                }

                for (char c : s.substr(1, close - 1)) {
                    if (!isHex(c) && c != ':') {
                        return false;
                    }
                }

                host = std::string_view();
                std::string_view rest = s.substr(close + 1);
                if (!rest.empty()) {
                    if (rest.front() != ':') {
                        return false;
                    }

                    port = rest.substr(1);
                    if (port.empty()) {
                        return false;
                    }
                }
            } else {
                size_t colon = s.find(':');
                if (colon != std::string_view::npos) {
                    host = s.substr(0, colon);
                    port = s.substr(colon + 1);
                    if (port.empty()) {
                        return false;
                    }
                }

                size_t start = 0;
                while (true) {
                    size_t dot = host.find('.', start);
                    std::string_view comp = host.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
                    if (!isDomainComponent(comp)) {
                        return false;
                    }

                    if (dot == std::string_view::npos) {
                        break;
                    }

                    start = dot + 1;
                }
            }

            for (char c : port) {
                if (!isDigit(c)) {
                    return false;
                }
            }

            return true;
        }

        /*
         * Matches the digest grammar of a reference (algorithm ":" hex{32,}) and the
         * digest's own validation.
         */
        bool isReferenceDigest(std::string_view s) noexcept {
            size_t colon = s.find(':');
            if (colon == std::string_view::npos || colon == 0) {
                return false;
            }

            std::string_view hex = s.substr(colon + 1);
            if (hex.size() < 32) {
                return false;
            }

            return ValidateDigest(s) == SBOX_OK;
        }

        /* Returns a lower-cased copy. */
        std::string lower(std::string_view s) {
            std::string out(s);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

    }

    /* Parses a reference strictly. */
    int32_t SReference::parse(std::string_view text, SReference& out) {
        out = SReference();
        if (text.empty()) {
            return -EINVAL;
        }

        std::string_view rest = text;
        size_t at = rest.find('@');
        if (at != std::string_view::npos) {
            std::string_view dg = rest.substr(at + 1);
            if (!isReferenceDigest(dg)) {
                return -EINVAL;
            }

            out.digest = std::string(dg);
            rest = rest.substr(0, at);
        }

        // --> The tag separator is a ':' after the last '/' (an earlier one is a port).
        size_t lastSlash = rest.rfind('/');
        size_t colon = rest.find(':', lastSlash == std::string_view::npos ? 0 : lastSlash + 1);
        if (colon != std::string_view::npos) {
            std::string_view tag = rest.substr(colon + 1);
            if (!IsValidTag(tag)) {
                return -EINVAL;
            }

            out.tag = std::string(tag);
            rest = rest.substr(0, colon);
        }

        if (rest.empty() || rest.size() > NAME_TOTAL_LENGTH_MAX) {
            return -EINVAL;
        }

        // --> Like the regular expression of distribution/reference, the optional domain is
        // tried first: "foo/bar" parses with domain "foo".
        size_t slash = rest.find('/');
        if (slash != std::string_view::npos) {
            std::string_view first = rest.substr(0, slash);
            std::string_view path = rest.substr(slash + 1);
            if (isDomain(first) && isPath(path)) {
                out.domain = std::string(first);
                out.path = std::string(path);
                return SBOX_OK;
            }
        }

        if (isPath(rest)) {
            out.path = std::string(rest);
            return SBOX_OK;
        }

        out = SReference();
        return -EINVAL;
    }

    /* Returns domain/path. */
    std::string SReference::name() const {
        return domain.empty() ? path : domain + "/" + path;
    }

    /* Returns the full form. */
    std::string SReference::toString() const {
        std::string s = name();
        if (!tag.empty()) {
            s += ":" + tag;
        }

        if (!digest.empty()) {
            s += "@" + digest;
        }

        return s;
    }

    /* Returns the familiar name. */
    std::string SReference::familiarName() const {
        if (domain != DOCKER_HUB_DOMAIN) {
            return name();
        }

        std::string_view p = path;
        if (p.substr(0, 8) == "library/" && p.find('/', 8) == std::string_view::npos) {
            return std::string(p.substr(8));
        }

        return path;
    }

    /* Returns the familiar form with tag and digest. */
    std::string SReference::familiarString() const {
        std::string s = familiarName();
        if (!tag.empty()) {
            s += ":" + tag;
        }

        if (!digest.empty()) {
            s += "@" + digest;
        }

        return s;
    }

    /* Parses and normalizes a reference. */
    int32_t ParseNormalizedReference(std::string_view text, SReference& out) {
        out = SReference();
        if (IsFullHexId(text)) {
            return -EINVAL;
        }

        // --> splitDockerDomain: the first component is a domain only when it looks like one
        // ('.' or ':' inside, "localhost", or upper-case letters).
        std::string domain;
        std::string remainder;
        size_t slash = text.find('/');
        if (slash == std::string_view::npos) {
            domain = DOCKER_HUB_DOMAIN;
            remainder = std::string(text);
        } else {
            std::string_view first = text.substr(0, slash);
            bool looksLikeDomain = first.find_first_of(".:") != std::string_view::npos || first == "localhost" || lower(first) != first;
            if (!looksLikeDomain) {
                domain = DOCKER_HUB_DOMAIN;
                remainder = std::string(text);
            } else {
                domain = std::string(first);
                remainder = std::string(text.substr(slash + 1));
            }
        }

        if (domain == "index.docker.io") {
            domain = DOCKER_HUB_DOMAIN;
        }

        if (domain == DOCKER_HUB_DOMAIN && remainder.find('/') == std::string::npos) {
            remainder = "library/" + remainder;
        }

        std::string_view remote = remainder;
        size_t sep = remote.find(':');
        if (sep != std::string_view::npos) {
            remote = remote.substr(0, sep);
        }

        if (lower(remote) != remote) {
            return -EINVAL;
        }

        SReference parsed;
        int32_t r = SReference::parse(domain + "/" + remainder, parsed);
        if (r != SBOX_OK) {
            return r;
        }

        // --> The strict parse must agree on the split (e.g. "localhost:x/..." with a bad
        // domain falls back to a domain-less path, which is not a normalized name).
        if (parsed.domain != domain) {
            return -EINVAL;
        }

        out = std::move(parsed);
        return SBOX_OK;
    }

    /* Parses with Docker's ParseDockerRef rules. */
    int32_t ParseDockerReference(std::string_view text, SReference& out) {
        int32_t r = ParseNormalizedReference(text, out);
        if (r != SBOX_OK) {
            return r;
        }

        if (out.hasDigest()) {
            out.tag.clear();
        }

        out = WithDefaultTag(std::move(out));
        return SBOX_OK;
    }

    /* Adds ":latest" when neither tag nor digest is set. */
    SReference WithDefaultTag(SReference ref) {
        if (ref.tag.empty() && ref.digest.empty()) {
            ref.tag = "latest";
        }

        return ref;
    }

    /* Returns true for a valid tag. */
    bool IsValidTag(std::string_view text) noexcept {
        if (text.empty() || text.size() > 128) {
            return false;
        }

        for (size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            bool word = isAlnum(c) || c == '_';
            if (!word && (i == 0 || (c != '.' && c != '-'))) {
                return false;
            }
        }

        return true;
    }

    /* Returns true for a 64 character lower-case hex string. */
    bool IsFullHexId(std::string_view text) noexcept {
        if (text.size() != 64) {
            return false;
        }

        for (char c : text) {
            if (!(isDigit(c) || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }

        return true;
    }

    /* Returns the registry API host of a domain. */
    std::string RegistryHost(std::string_view domain) {
        if (domain == DOCKER_HUB_DOMAIN || domain == "index.docker.io") {
            return DOCKER_HUB_REGISTRY;
        }

        return std::string(domain);
    }

    /* Returns true for loopback registries. */
    bool IsLoopbackRegistry(std::string_view domain) noexcept {
        std::string_view host = domain;
        if (!host.empty() && host.front() == '[') {
            size_t close = host.find(']');
            host = close == std::string_view::npos ? host : host.substr(1, close - 1);
            return host == "::1";
        }

        size_t colon = host.find(':');
        if (colon != std::string_view::npos) {
            host = host.substr(0, colon);
        }

        if (host == "localhost") {
            return true;
        }

        return host.substr(0, 4) == "127.";
    }

}
}
