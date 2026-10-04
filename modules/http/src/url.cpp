#include <sbox/http/url.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace http {

    namespace {

        inline bool isAlpha(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        inline bool isDigit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        inline int32_t hexValue(char c) noexcept {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }

            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }

            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }

            return -1;
        }

        inline bool isUnreserved(char c) noexcept {
            return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~';
        }

        inline bool isSubDelim(char c) noexcept {
            return std::strchr("!$&'()*+,;=", c) != nullptr && c != '\0';
        }

        inline char lowerAscii(char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
        }

        /*
         * Returns true when `c` may appear unencoded under `set`.
         */
        bool keepsChar(char c, EPercentSet set) noexcept {
            if (isUnreserved(c)) {
                return true;
            }

            switch (set) {
            case EPCT_PATH:
                return isSubDelim(c) || c == ':' || c == '@' || c == '/';

            case EPCT_QUERY:
                return (isSubDelim(c) && c != '&' && c != '=' && c != '+') || c == ':' || c == '@' || c == '/' || c == '?';

            default:
                return false;
            }
        }

        /*
         * Checks the bytes every URI component shares: printable ASCII, valid %XX escapes.
         */
        bool validUriBytes(std::string_view text) noexcept {
            for (size_t i = 0; i < text.size(); ++i) {
                unsigned char c = (unsigned char) text[i];
                if (c <= 0x20 || c >= 0x7f) {
                    return false;
                }

                if (c == '%') {
                    if (i + 2 >= text.size() || hexValue(text[i + 1]) < 0 || hexValue(text[i + 2]) < 0) {
                        return false;
                    }
                }
            }

            return true;
        }

        /*
         * Validates a registered name: unreserved, sub-delims and %XX.
         */
        bool validRegName(std::string_view host) noexcept {
            for (char c : host) {
                if (!isUnreserved(c) && !isSubDelim(c) && c != '%') {
                    return false;
                }
            }

            return true;
        }

        /*
         * Validates an IPv6 literal (the text inside the brackets), allowing a "%25zone" suffix.
         */
        bool validIpv6(std::string_view text) noexcept {
            std::string addr(text.substr(0, text.find('%')));
            if (addr.size() >= INET6_ADDRSTRLEN) {
                return false;
            }

            in6_addr out{};
            if (::inet_pton(AF_INET6, addr.c_str(), &out) != 1) {
                return false;
            }

            size_t zone = text.find('%');
            if (zone != std::string_view::npos) {
                // --> RFC 6874: the zone separator is written as "%25" inside a URI.
                return text.substr(zone, 3) == "%25" && text.size() > zone + 3;
            }

            return true;
        }

        /*
         * Splits an authority into userinfo, host and port.
         */
        int32_t parseAuthority(std::string_view auth, bool lowerHost, SUrl& out) {
            size_t at = auth.rfind('@');
            if (at != std::string_view::npos) {
                out.userinfo = std::string(auth.substr(0, at));
                out.hasUserinfo = true;
                auth = auth.substr(at + 1);

                if (out.userinfo.find_first_of("[]/?#@") != std::string::npos) {
                    return -EINVAL;
                }
            }

            std::string_view portText;
            bool hasPortColon = false;

            if (!auth.empty() && auth[0] == '[') {
                size_t close = auth.find(']');
                if (close == std::string_view::npos) {
                    return -EINVAL;
                }

                std::string_view literal = auth.substr(1, close - 1);
                if (!validIpv6(literal)) {
                    return -EINVAL;
                }

                out.host.clear();
                for (char c : literal) {
                    out.host.push_back(lowerAscii(c));
                }

                std::string_view rest = auth.substr(close + 1);
                if (!rest.empty()) {
                    if (rest[0] != ':') {
                        return -EINVAL;
                    }

                    hasPortColon = true;
                    portText = rest.substr(1);
                }
            } else {
                size_t colon = auth.find(':');
                std::string_view host = auth.substr(0, colon);

                if (!validRegName(host)) {
                    return -EINVAL;
                }

                out.host.clear();
                for (char c : host) {
                    out.host.push_back(lowerHost ? lowerAscii(c) : c);
                }

                if (colon != std::string_view::npos) {
                    hasPortColon = true;
                    portText = auth.substr(colon + 1);
                }
            }

            out.port = -1;
            if (hasPortColon && !portText.empty()) {
                if (portText.size() > 5) {
                    return -EINVAL;
                }

                int32_t port = 0;
                for (char c : portText) {
                    if (!isDigit(c)) {
                        return -EINVAL;
                    }

                    port = port * 10 + (c - '0');
                }

                if (port > 65535) {
                    return -EINVAL;
                }

                out.port = port;
            }

            return SBOX_OK;
        }

        /*
         * Appends "[host]" or "host" to `out`.
         */
        void appendHost(std::string& out, const SUrl& url) {
            if (url.isIpv6Host()) {
                out.push_back('[');
                out += url.host;
                out.push_back(']');
            } else {
                out += url.host;
            }
        }

        /*
         * Merges a relative path with the base path (RFC 3986 section 5.2.3).
         */
        std::string mergePaths(const SUrl& base, const std::string& path) {
            if (base.hasAuthority && base.path.empty()) {
                return "/" + path;
            }

            size_t slash = base.path.rfind('/');
            if (slash == std::string::npos) {
                return path;
            }

            return base.path.substr(0, slash + 1) + path;
        }

        /*
         * Drops the last segment (and its leading '/') from the output buffer.
         */
        void dropLastSegment(std::string& out) {
            size_t slash = out.rfind('/');
            out.erase(slash == std::string::npos ? 0 : slash);
        }

    }

    /* Percent-encodes text. */
    std::string PercentEncode(std::string_view text, EPercentSet set) {
        static const char HEX[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(text.size() + text.size() / 2);

        for (char c : text) {
            if (keepsChar(c, set)) {
                out.push_back(c);
            } else if (set == EPCT_FORM && c == ' ') {
                out.push_back('+');
            } else {
                unsigned char b = (unsigned char) c;
                out.push_back('%');
                out.push_back(HEX[b >> 4]);
                out.push_back(HEX[b & 15]);
            }
        }

        return out;
    }

    /* Decodes percent escapes. */
    int32_t PercentDecode(std::string_view text, std::string& out, bool plusAsSpace) {
        out.clear();
        out.reserve(text.size());

        for (size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            if (c == '%') {
                if (i + 2 >= text.size()) {
                    return -EINVAL;
                }

                int32_t hi = hexValue(text[i + 1]);
                int32_t lo = hexValue(text[i + 2]);
                if (hi < 0 || lo < 0) {
                    return -EINVAL;
                }

                out.push_back(char((hi << 4) | lo));
                i += 2;
            } else if (c == '+' && plusAsSpace) {
                out.push_back(' ');
            } else {
                out.push_back(c);
            }
        }

        return SBOX_OK;
    }

    /* Builds a query string. */
    std::string BuildQuery(const SQueryParams& params) {
        std::string out;

        for (const auto& [name, value] : params) {
            if (!out.empty()) {
                out.push_back('&');
            }

            out += PercentEncode(name);
            out.push_back('=');
            out += PercentEncode(value);
        }

        return out;
    }

    /* Parses a query string into pairs. */
    int32_t ParseQuery(std::string_view query, SQueryParams& out) {
        size_t pos = 0;

        while (pos <= query.size()) {
            size_t amp = query.find('&', pos);
            std::string_view pair = query.substr(pos, amp == std::string_view::npos ? std::string_view::npos : amp - pos);

            if (!pair.empty()) {
                size_t eq = pair.find('=');
                std::string name, value;

                if (PercentDecode(pair.substr(0, eq), name, true) != SBOX_OK) {
                    return -EINVAL;
                }

                if (eq != std::string_view::npos && PercentDecode(pair.substr(eq + 1), value, true) != SBOX_OK) {
                    return -EINVAL;
                }

                out.emplace_back(std::move(name), std::move(value));
            }

            if (amp == std::string_view::npos) {
                break;
            }

            pos = amp + 1;
        }

        return SBOX_OK;
    }

    /* Returns the default port of a scheme. */
    uint16_t DefaultPort(std::string_view scheme) noexcept {
        if (scheme == "http") {
            return 80;
        }

        if (scheme == "https") {
            return 443;
        }

        return 0;
    }

    /* Removes dot segments from a path. */
    std::string RemoveDotSegments(std::string_view path) {
        std::string in(path);
        std::string out;
        size_t pos = 0;     // --> Start of the unconsumed input (avoids erasing from the front).

        while (pos < in.size()) {
            std::string_view rest(in.data() + pos, in.size() - pos);

            if (rest.substr(0, 3) == "../") {
                pos += 3;
            } else if (rest.substr(0, 2) == "./") {
                pos += 2;
            } else if (rest.substr(0, 3) == "/./") {
                pos += 2;
            } else if (rest == "/.") {
                // --> Replace "/." with "/": keep the slash, drop the dot.
                in.replace(pos, 2, "/");
            } else if (rest.substr(0, 4) == "/../") {
                pos += 3;
                dropLastSegment(out);
            } else if (rest == "/..") {
                in.replace(pos, 3, "/");
                dropLastSegment(out);
            } else if (rest == "." || rest == "..") {
                pos = in.size();
            } else {
                size_t next = in.find('/', pos + (rest[0] == '/' ? 1 : 0));
                if (next == std::string::npos) {
                    next = in.size();
                }

                out.append(in, pos, next - pos);
                pos = next;
            }
        }

        return out;
    }

    /* Parses a URI reference. */
    int32_t SUrl::parse(std::string_view text, SUrl& out) {
        out = SUrl{};

        if (!validUriBytes(text)) {
            return -EINVAL;
        }

        // --> A scheme is "ALPHA *(ALPHA / DIGIT / + - .)" before the first ':' that comes
        // ahead of any '/', '?' or '#'; otherwise the colon belongs to a relative path.
        size_t delim = text.find_first_of(":/?#");
        if (delim != std::string_view::npos && text[delim] == ':' && delim > 0 && isAlpha(text[0])) {
            bool ok = true;
            for (size_t i = 1; i < delim; ++i) {
                char c = text[i];
                if (!isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.') {
                    ok = false;
                    break;
                }
            }

            if (ok) {
                for (size_t i = 0; i < delim; ++i) {
                    out.scheme.push_back(lowerAscii(text[i]));
                }

                text = text.substr(delim + 1);
            }
        }

        size_t hash = text.find('#');
        if (hash != std::string_view::npos) {
            out.fragment = std::string(text.substr(hash + 1));
            out.hasFragment = true;
            text = text.substr(0, hash);
        }

        size_t question = text.find('?');
        if (question != std::string_view::npos) {
            out.query = std::string(text.substr(question + 1));
            out.hasQuery = true;
            text = text.substr(0, question);
        }

        if (text.substr(0, 2) == "//") {
            text = text.substr(2);
            size_t slash = text.find('/');
            std::string_view auth = text.substr(0, slash);

            // --> Host names are case-insensitive, but a scheme like http+unix carries a
            // case-sensitive socket path in the host, so only well-known schemes are folded.
            bool lowerHost = out.scheme.empty() || out.scheme == "http" || out.scheme == "https";
            int32_t r = parseAuthority(auth, lowerHost, out);
            if (r != SBOX_OK) {
                return r;
            }

            out.hasAuthority = true;
            text = slash == std::string_view::npos ? std::string_view() : text.substr(slash);
        }

        if (text.find_first_of("[]") != std::string_view::npos) {
            return -EINVAL;
        }

        out.path = std::string(text);
        return SBOX_OK;
    }

    /* Resolves a parsed reference against a base. */
    SUrl SUrl::resolve(const SUrl& base, const SUrl& ref) {
        SUrl target;

        if (!ref.scheme.empty()) {
            target = ref;
            target.path = RemoveDotSegments(ref.path);
        } else {
            if (ref.hasAuthority) {
                target = ref;
                target.path = RemoveDotSegments(ref.path);
            } else {
                if (ref.path.empty()) {
                    target.path = base.path;
                    target.query = ref.hasQuery ? ref.query : base.query;
                    target.hasQuery = ref.hasQuery || base.hasQuery;
                } else {
                    if (ref.path[0] == '/') {
                        target.path = RemoveDotSegments(ref.path);
                    } else {
                        target.path = RemoveDotSegments(mergePaths(base, ref.path));
                    }

                    target.query = ref.query;
                    target.hasQuery = ref.hasQuery;
                }

                target.userinfo = base.userinfo;
                target.hasUserinfo = base.hasUserinfo;
                target.host = base.host;
                target.port = base.port;
                target.hasAuthority = base.hasAuthority;
            }

            target.scheme = base.scheme;
        }

        target.fragment = ref.fragment;
        target.hasFragment = ref.hasFragment;
        return target;
    }

    /* Parses and resolves a reference. */
    int32_t SUrl::resolve(const SUrl& base, std::string_view reference, SUrl& out) {
        if (!base.isAbsolute()) {
            return -EINVAL;
        }

        SUrl ref;
        int32_t r = parse(reference, ref);
        if (r != SBOX_OK) {
            return r;
        }

        out = resolve(base, ref);
        return SBOX_OK;
    }

    /* Recomposes the reference. */
    std::string SUrl::toString() const {
        std::string out;

        if (!scheme.empty()) {
            out += scheme;
            out.push_back(':');
        }

        if (hasAuthority) {
            out += "//";
            if (hasUserinfo) {
                out += userinfo;
                out.push_back('@');
            }

            appendHost(out, *this);
            if (port >= 0) {
                out.push_back(':');
                out += std::to_string(port);
            }
        }

        out += path;

        if (hasQuery) {
            out.push_back('?');
            out += query;
        }

        if (hasFragment) {
            out.push_back('#');
            out += fragment;
        }

        return out;
    }

    /* Returns true for an IPv6 literal host. */
    bool SUrl::isIpv6Host() const noexcept {
        return host.find(':') != std::string::npos;
    }

    /* Returns the explicit or default port. */
    uint16_t SUrl::effectivePort() const noexcept {
        return port >= 0 ? uint16_t(port) : DefaultPort(scheme);
    }

    /* Returns the Host header form. */
    std::string SUrl::hostPort() const {
        std::string out;
        appendHost(out, *this);

        if (port >= 0 && uint16_t(port) != DefaultPort(scheme)) {
            out.push_back(':');
            out += std::to_string(port);
        }

        return out;
    }

    /* Returns the origin-form request target. */
    std::string SUrl::requestTarget() const {
        std::string out = path.empty() ? std::string("/") : path;

        if (hasQuery) {
            out.push_back('?');
            out += query;
        }

        return out;
    }

    /* Decodes the userinfo into user and password. */
    int32_t SUrl::credentials(std::string& user, std::string& password) const {
        if (!hasUserinfo) {
            return -ENOENT;
        }

        size_t colon = userinfo.find(':');
        if (PercentDecode(std::string_view(userinfo).substr(0, colon), user) != SBOX_OK) {
            return -EINVAL;
        }

        password.clear();
        if (colon != std::string::npos && PercentDecode(std::string_view(userinfo).substr(colon + 1), password) != SBOX_OK) {
            return -EINVAL;
        }

        return SBOX_OK;
    }

}
}
