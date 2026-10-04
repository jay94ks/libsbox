#include <sbox/http/headers.hpp>
#include "lex.hpp"
#include <cerrno>
#include <cstdio>
#include <ctime>

namespace sbox {
namespace http {

    namespace {

        /*
         * Parses an unsigned decimal number that must fill `text` (no sign, no blanks).
         */
        bool parseDecimal(std::string_view text, uint64_t& out) noexcept {
            if (text.empty() || text.size() > 19) {
                return false;
            }

            uint64_t v = 0;
            for (char c : text) {
                if (c < '0' || c > '9') {
                    return false;
                }

                v = v * 10 + uint64_t(c - '0');
            }

            out = v;
            return true;
        }

        /*
         * Looks a parameter up by name, ignoring case.
         */
        std::string findParam(const std::vector<std::pair<std::string, std::string>>& params, std::string_view name) {
            for (const auto& [k, v] : params) {
                if (EqualsNoCase(k, name)) {
                    return v;
                }
            }

            return {};
        }

    }

    /* Compares ASCII strings ignoring case. */
    bool EqualsNoCase(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) {
            return false;
        }

        for (size_t i = 0; i < a.size(); ++i) {
            char x = a[i], y = b[i];
            if (x >= 'A' && x <= 'Z') {
                x = char(x - 'A' + 'a');
            }

            if (y >= 'A' && y <= 'Z') {
                y = char(y - 'A' + 'a');
            }

            if (x != y) {
                return false;
            }
        }

        return true;
    }

    /* Checks for a token. */
    bool IsToken(std::string_view name) noexcept {
        if (name.empty()) {
            return false;
        }

        for (char c : name) {
            if (!lex::IsTchar(c)) {
                return false;
            }
        }

        return true;
    }

    /* Appends a field. */
    void CHeaders::add(std::string_view name, std::string_view value) {
        _fields.push_back(SField{ std::string(name), std::string(lex::Trim(value)) });
    }

    /* Replaces all fields of a name with one. */
    void CHeaders::set(std::string_view name, std::string_view value) {
        size_t first = _fields.size();

        for (size_t i = 0; i < _fields.size();) {
            if (EqualsNoCase(_fields[i].name, name)) {
                if (first == _fields.size()) {
                    first = i;
                    ++i;
                } else {
                    _fields.erase(_fields.begin() + ptrdiff_t(i));
                }
            } else {
                ++i;
            }
        }

        if (first < _fields.size()) {
            _fields[first].value = std::string(lex::Trim(value));
        } else {
            add(name, value);
        }
    }

    /* Removes all fields of a name. */
    size_t CHeaders::remove(std::string_view name) noexcept {
        size_t before = _fields.size();
        std::erase_if(_fields, [&](const SField& f) { return EqualsNoCase(f.name, name); });
        return before - _fields.size();
    }

    /* Checks presence. */
    bool CHeaders::has(std::string_view name) const noexcept {
        return find(name) != nullptr;
    }

    /* Finds the first value. */
    const std::string* CHeaders::find(std::string_view name) const noexcept {
        for (const SField& f : _fields) {
            if (EqualsNoCase(f.name, name)) {
                return &f.value;
            }
        }

        return nullptr;
    }

    /* Returns the first value or a fallback. */
    std::string CHeaders::get(std::string_view name, std::string_view fallback) const {
        const std::string* v = find(name);
        return v ? *v : std::string(fallback);
    }

    /* Returns all values. */
    std::vector<std::string> CHeaders::getAll(std::string_view name) const {
        std::vector<std::string> out;
        for (const SField& f : _fields) {
            if (EqualsNoCase(f.name, name)) {
                out.push_back(f.value);
            }
        }

        return out;
    }

    /* Joins all values with ", ". */
    std::string CHeaders::combined(std::string_view name) const {
        std::string out;
        for (const SField& f : _fields) {
            if (EqualsNoCase(f.name, name)) {
                if (!out.empty()) {
                    out += ", ";
                }

                out += f.value;
            }
        }

        return out;
    }

    /* Checks a comma list for a token. */
    bool CHeaders::hasToken(std::string_view name, std::string_view token) const {
        for (const SField& f : _fields) {
            if (!EqualsNoCase(f.name, name)) {
                continue;
            }

            for (const std::string& item : SplitHeaderList(f.value)) {
                if (EqualsNoCase(item, token)) {
                    return true;
                }
            }
        }

        return false;
    }

    /* Serializes the fields. */
    void CHeaders::serializeTo(std::string& out) const {
        for (const SField& f : _fields) {
            out += f.name;
            out += ": ";
            out += f.value;
            out += "\r\n";
        }
    }

    /* Splits a comma separated list. */
    std::vector<std::string> SplitHeaderList(std::string_view value) {
        std::vector<std::string> out;
        size_t start = 0;
        bool inQuote = false;

        auto flush = [&](size_t end) {
            std::string_view item = lex::Trim(value.substr(start, end - start));
            if (!item.empty()) {
                out.emplace_back(item);
            }
        };

        for (size_t i = 0; i < value.size(); ++i) {
            char c = value[i];

            if (inQuote) {
                if (c == '\\') {
                    ++i;
                } else if (c == '"') {
                    inQuote = false;
                }
            } else if (c == '"') {
                inQuote = true;
            } else if (c == ',') {
                flush(i);
                start = i + 1;
            }
        }

        flush(value.size());
        return out;
    }

    /* Parses a media type. */
    int32_t SMediaType::parse(std::string_view text, SMediaType& out) {
        out = SMediaType{};
        lex::Cursor cur{ text };
        cur.skipWs();

        std::string_view type = cur.token();
        if (type.empty() || cur.peek() != '/') {
            return -EINVAL;
        }

        ++cur.pos;
        std::string_view sub = cur.token();
        if (sub.empty()) {
            return -EINVAL;
        }

        out.type = lex::Lower(type);
        out.subtype = lex::Lower(sub);

        if (!cur.params(out.params) || !cur.atEnd()) {
            return -EINVAL;
        }

        return SBOX_OK;
    }

    /* Returns "type/subtype". */
    std::string SMediaType::essence() const {
        return type + "/" + subtype;
    }

    /* Looks up a parameter. */
    std::string SMediaType::param(std::string_view name) const {
        return findParam(params, name);
    }

    /* Formats the media type. */
    std::string SMediaType::toString() const {
        std::string out = essence();
        for (const auto& [k, v] : params) {
            out += "; ";
            out += k;
            out.push_back('=');
            out += lex::QuoteIfNeeded(v);
        }

        return out;
    }

    /* Looks up a link parameter. */
    std::string SLink::param(std::string_view name) const {
        return findParam(params, name);
    }

    /* Checks the rel parameter. */
    bool SLink::hasRel(std::string_view rel) const {
        std::string rels = param("rel");
        size_t pos = 0;

        while (pos < rels.size()) {
            size_t sp = rels.find_first_of(" \t", pos);
            std::string_view item = std::string_view(rels).substr(pos, sp == std::string::npos ? std::string::npos : sp - pos);

            if (!item.empty() && EqualsNoCase(item, rel)) {
                return true;
            }

            if (sp == std::string::npos) {
                break;
            }

            pos = sp + 1;
        }

        return false;
    }

    /* Parses a Link header. */
    int32_t ParseLinkHeader(std::string_view value, std::vector<SLink>& out) {
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

            if (cur.peek() != '<') {
                return -EINVAL;
            }

            size_t close = value.find('>', cur.pos);
            if (close == std::string_view::npos) {
                return -EINVAL;
            }

            SLink link;
            link.target = std::string(value.substr(cur.pos + 1, close - cur.pos - 1));
            cur.pos = close + 1;

            if (!cur.params(link.params)) {
                return -EINVAL;
            }

            out.push_back(std::move(link));
        }
    }

    /* Parses a Content-Range value. */
    int32_t SContentRange::parse(std::string_view text, SContentRange& out) {
        out = SContentRange{};
        text = lex::Trim(text);

        if (text.size() < 6 || !EqualsNoCase(text.substr(0, 6), "bytes ")) {
            return -EINVAL;
        }

        text = lex::Trim(text.substr(6));
        size_t slash = text.find('/');
        if (slash == std::string_view::npos) {
            return -EINVAL;
        }

        std::string_view range = text.substr(0, slash);
        std::string_view total = text.substr(slash + 1);

        if (total == "*") {
            out.completeLength = -1;
        } else {
            uint64_t n = 0;
            if (!parseDecimal(total, n) || n > uint64_t(INT64_MAX)) {
                return -EINVAL;
            }

            out.completeLength = int64_t(n);
        }

        if (range == "*") {
            if (out.completeLength < 0) {
                return -EINVAL;
            }

            out.unsatisfied = true;
            return SBOX_OK;
        }

        size_t dash = range.find('-');
        if (dash == std::string_view::npos) {
            return -EINVAL;
        }

        if (!parseDecimal(range.substr(0, dash), out.first) || !parseDecimal(range.substr(dash + 1), out.last)) {
            return -EINVAL;
        }

        if (out.last < out.first) {
            return -EINVAL;
        }

        if (out.completeLength >= 0 && out.last >= uint64_t(out.completeLength)) {
            return -EINVAL;
        }

        return SBOX_OK;
    }

    /* Formats a Content-Range value. */
    std::string SContentRange::toString() const {
        std::string total = completeLength < 0 ? std::string("*") : std::to_string(completeLength);

        if (unsatisfied) {
            return "bytes */" + total;
        }

        return "bytes " + std::to_string(first) + "-" + std::to_string(last) + "/" + total;
    }

    /* Formats a Range value. */
    std::string FormatRange(uint64_t first, int64_t last) {
        std::string out = "bytes=" + std::to_string(first) + "-";
        if (last >= 0) {
            out += std::to_string(last);
        }

        return out;
    }

    /* Parses a single byte range against a size. */
    int32_t ParseRange(std::string_view value, uint64_t size, uint64_t& first, uint64_t& last) {
        value = lex::Trim(value);
        if (value.size() < 6 || !EqualsNoCase(value.substr(0, 6), "bytes=")) {
            return -EINVAL;
        }

        value = lex::Trim(value.substr(6));
        if (value.find(',') != std::string_view::npos) {
            return -EINVAL;
        }

        size_t dash = value.find('-');
        if (dash == std::string_view::npos) {
            return -EINVAL;
        }

        std::string_view a = lex::Trim(value.substr(0, dash));
        std::string_view b = lex::Trim(value.substr(dash + 1));

        if (a.empty()) {
            uint64_t suffix = 0;
            if (!parseDecimal(b, suffix)) {
                return -EINVAL;
            }

            if (suffix == 0 || size == 0) {
                return -ERANGE;
            }

            first = suffix >= size ? 0 : size - suffix;
            last = size - 1;
            return SBOX_OK;
        }

        if (!parseDecimal(a, first)) {
            return -EINVAL;
        }

        if (b.empty()) {
            last = size == 0 ? 0 : size - 1;
        } else {
            if (!parseDecimal(b, last) || last < first) {
                return -EINVAL;
            }

            if (size > 0 && last >= size) {
                last = size - 1;
            }
        }

        if (first >= size) {
            return -ERANGE;
        }

        return SBOX_OK;
    }

    /* Formats an IMF-fixdate. */
    std::string FormatHttpDate(int64_t unixSeconds) {
        static const char* DAYS[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        static const char* MONTHS[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        time_t t = unixSeconds >= 0 ? time_t(unixSeconds) : ::time(nullptr);
        struct tm tm{};
        ::gmtime_r(&t, &tm);

        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d GMT",
            DAYS[tm.tm_wday % 7], tm.tm_mday, MONTHS[tm.tm_mon % 12], tm.tm_year + 1900,
            tm.tm_hour, tm.tm_min, tm.tm_sec);

        return buf;
    }

}
}
