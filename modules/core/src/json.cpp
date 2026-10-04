#include <sbox/core/json.hpp>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace sbox {

    /* Constructs null. */
    CJson::CJson() noexcept : _type(EJSON_NULL), _bool(false), _int(0), _double(0) {}

    /* Constructs a boolean. */
    CJson::CJson(bool value) noexcept : _type(EJSON_BOOL), _bool(value), _int(0), _double(0) {}

    /* Constructs an integer. */
    CJson::CJson(int32_t value) noexcept : _type(EJSON_INT), _bool(false), _int(value), _double(0) {}

    /* Constructs an integer. */
    CJson::CJson(int64_t value) noexcept : _type(EJSON_INT), _bool(false), _int(value), _double(0) {}

    /* Constructs an integer. */
    CJson::CJson(uint32_t value) noexcept : _type(EJSON_INT), _bool(false), _int(value), _double(0) {}

    /* Constructs an integer or, beyond INT64_MAX, a double. */
    CJson::CJson(uint64_t value) noexcept : _type(EJSON_INT), _bool(false), _int(0), _double(0) {
        if (value > uint64_t(INT64_MAX)) {
            _type = EJSON_DOUBLE;
            _double = float64_t(value);
        }
        else {
            _int = int64_t(value);
        }
    }

    /* Constructs a number. */
    CJson::CJson(float64_t value) noexcept : _type(EJSON_DOUBLE), _bool(false), _int(0), _double(value) {}

    /* Constructs a string. */
    CJson::CJson(const char* value) : CJson(std::string(value ? value : "")) {}

    /* Constructs a string. */
    CJson::CJson(std::string value) noexcept
        : _type(EJSON_STRING), _bool(false), _int(0), _double(0), _string(std::move(value)) {}

    /* Constructs a string. */
    CJson::CJson(std::string_view value) : CJson(std::string(value)) {}

    /* Returns an empty array. */
    CJson CJson::array() {
        CJson v;
        v._type = EJSON_ARRAY;
        return v;
    }

    /* Returns an empty object. */
    CJson CJson::object() {
        CJson v;
        v._type = EJSON_OBJECT;
        return v;
    }

    /* Returns an array of strings. */
    CJson CJson::fromStrings(const std::vector<std::string>& values) {
        CJson v = array();
        v._items.reserve(values.size());

        for (const std::string& s : values) {
            v._items.emplace_back(s);
        }

        return v;
    }

    /* Returns the boolean. */
    bool CJson::asBool(bool fallback) const noexcept {
        return _type == EJSON_BOOL ? _bool : fallback;
    }

    /* Returns the number as an integer. */
    int64_t CJson::asInt(int64_t fallback) const noexcept {
        if (_type == EJSON_INT) {
            return _int;
        }

        if (_type == EJSON_DOUBLE && std::isfinite(_double)
            && _double >= -9.2e18 && _double <= 9.2e18) {
            return int64_t(_double);
        }

        return fallback;
    }

    /* Returns the number as a double. */
    float64_t CJson::asDouble(float64_t fallback) const noexcept {
        if (_type == EJSON_INT) {
            return float64_t(_int);
        }

        return _type == EJSON_DOUBLE ? _double : fallback;
    }

    /* Returns the string. */
    const std::string& CJson::asString() const noexcept {
        static const std::string empty;
        return _type == EJSON_STRING ? _string : empty;
    }

    /* Returns a string array. */
    std::vector<std::string> CJson::asStrings() const {
        std::vector<std::string> out;
        if (_type != EJSON_ARRAY) {
            return out;
        }

        for (const CJson& item : _items) {
            if (item.isString()) {
                out.push_back(item._string);
            }
        }

        return out;
    }

    /* Appends to an array. */
    CJson& CJson::push(CJson value) {
        if (_type == EJSON_NULL) {
            _type = EJSON_ARRAY;
        }

        _items.push_back(std::move(value));
        return _items.back();
    }

    /* Finds a member. */
    const CJson* CJson::find(std::string_view key) const noexcept {
        if (_type != EJSON_OBJECT) {
            return nullptr;
        }

        for (size_t i = 0; i < _keys.size(); ++i) {
            if (_keys[i] == key) {
                return &_items[i];
            }
        }

        return nullptr;
    }

    /* Finds a member. */
    CJson* CJson::find(std::string_view key) noexcept {
        return const_cast<CJson*>(static_cast<const CJson*>(this)->find(key));
    }

    /* Returns a member or null. */
    const CJson& CJson::get(std::string_view key) const noexcept {
        static const CJson null;
        const CJson* found = find(key);
        return found ? *found : null;
    }

    /* Returns a member, inserting null. */
    CJson& CJson::operator[](std::string_view key) {
        if (CJson* found = find(key)) {
            return *found;
        }

        return set(key, CJson());
    }

    /* Sets a member. */
    CJson& CJson::set(std::string_view key, CJson value) {
        if (_type == EJSON_NULL) {
            _type = EJSON_OBJECT;
        }

        if (CJson* found = find(key)) {
            *found = std::move(value);
            return *found;
        }

        _keys.emplace_back(key);
        _items.push_back(std::move(value));
        return _items.back();
    }

    /* Removes a member. */
    bool CJson::remove(std::string_view key) noexcept {
        for (size_t i = 0; i < _keys.size(); ++i) {
            if (_keys[i] == key) {
                _keys.erase(_keys.begin() + ptrdiff_t(i));
                _items.erase(_items.begin() + ptrdiff_t(i));
                return true;
            }
        }

        return false;
    }

    namespace {

        /**
         * Recursive-descent JSON parser over a string view.
         */
        struct JsonParser {
            std::string_view text;
            size_t pos = 0;

            inline void skipSpace() noexcept {
                while (pos < text.size()) {
                    char c = text[pos];
                    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                        break;
                    }

                    ++pos;
                }
            }

            inline bool consume(std::string_view literal) noexcept {
                if (text.substr(pos, literal.size()) == literal) {
                    pos += literal.size();
                    return true;
                }

                return false;
            }

            static int32_t hexValue(char c) noexcept {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            }

            bool readHex4(uint32_t& out) noexcept {
                if (pos + 4 > text.size()) {
                    return false;
                }

                out = 0;
                for (int i = 0; i < 4; ++i) {
                    int32_t v = hexValue(text[pos + size_t(i)]);
                    if (v < 0) {
                        return false;
                    }

                    out = (out << 4) | uint32_t(v);
                }

                pos += 4;
                return true;
            }

            static void appendUtf8(std::string& out, uint32_t cp) {
                if (cp < 0x80) {
                    out.push_back(char(cp));
                }
                else if (cp < 0x800) {
                    out.push_back(char(0xC0 | (cp >> 6)));
                    out.push_back(char(0x80 | (cp & 0x3F)));
                }
                else if (cp < 0x10000) {
                    out.push_back(char(0xE0 | (cp >> 12)));
                    out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(char(0x80 | (cp & 0x3F)));
                }
                else {
                    out.push_back(char(0xF0 | (cp >> 18)));
                    out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
                    out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(char(0x80 | (cp & 0x3F)));
                }
            }

            bool parseString(std::string& out) {
                if (pos >= text.size() || text[pos] != '"') {
                    return false;
                }

                ++pos;
                while (pos < text.size()) {
                    // --> Copy the run of plain characters in one go.
                    size_t start = pos;
                    while (pos < text.size() && text[pos] != '"' && text[pos] != '\\') {
                        if (uint8_t(text[pos]) < 0x20) {
                            return false;
                        }

                        ++pos;
                    }

                    out.append(text.data() + start, pos - start);
                    if (pos >= text.size()) {
                        return false;
                    }

                    if (text[pos] == '"') {
                        ++pos;
                        return true;
                    }

                    ++pos;
                    if (pos >= text.size()) {
                        return false;
                    }

                    char esc = text[pos++];
                    switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!readHex4(cp)) {
                            return false;
                        }

                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            uint32_t low = 0;
                            if (!consume("\\u") || !readHex4(low) || low < 0xDC00 || low > 0xDFFF) {
                                return false;
                            }

                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        }
                        else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return false;
                        }

                        appendUtf8(out, cp);
                        break;
                    }
                    default:
                        return false;
                    }
                }

                return false;
            }

            bool parseNumber(CJson& out) {
                size_t start = pos;
                bool integral = true;

                if (pos < text.size() && text[pos] == '-') {
                    ++pos;
                }

                if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') {
                    return false;
                }

                if (text[pos] == '0') {
                    ++pos;
                }
                else {
                    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                        ++pos;
                    }
                }

                if (pos < text.size() && text[pos] == '.') {
                    integral = false;
                    ++pos;

                    size_t digits = pos;
                    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                        ++pos;
                    }

                    if (pos == digits) {
                        return false;
                    }
                }

                if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
                    integral = false;
                    ++pos;

                    if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) {
                        ++pos;
                    }

                    size_t digits = pos;
                    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                        ++pos;
                    }

                    if (pos == digits) {
                        return false;
                    }
                }

                std::string number(text.substr(start, pos - start));
                if (integral) {
                    errno = 0;
                    char* end = nullptr;
                    long long v = std::strtoll(number.c_str(), &end, 10);

                    if (errno == 0) {
                        out = CJson(int64_t(v));
                        return true;
                    }

                    // --> Out of int64 range: unsigned values up to UINT64_MAX are kept.
                    errno = 0;
                    unsigned long long u = number[0] == '-' ? 0 : std::strtoull(number.c_str(), &end, 10);
                    if (errno == 0 && number[0] != '-') {
                        out = CJson(uint64_t(u));
                        return true;
                    }
                }

                out = CJson(std::strtod(number.c_str(), nullptr));
                return true;
            }

            bool parseValue(CJson& out, int32_t depth) {
                if (depth > 512) {
                    return false;
                }

                skipSpace();
                if (pos >= text.size()) {
                    return false;
                }

                char c = text[pos];
                if (c == '{') {
                    ++pos;
                    out = CJson::object();
                    skipSpace();

                    if (pos < text.size() && text[pos] == '}') {
                        ++pos;
                        return true;
                    }

                    while (true) {
                        skipSpace();

                        std::string key;
                        if (!parseString(key)) {
                            return false;
                        }

                        skipSpace();
                        if (pos >= text.size() || text[pos] != ':') {
                            return false;
                        }

                        ++pos;
                        CJson value;
                        if (!parseValue(value, depth + 1)) {
                            return false;
                        }

                        out.set(key, std::move(value));
                        skipSpace();

                        if (pos < text.size() && text[pos] == ',') {
                            ++pos;
                            continue;
                        }

                        if (pos < text.size() && text[pos] == '}') {
                            ++pos;
                            return true;
                        }

                        return false;
                    }
                }

                if (c == '[') {
                    ++pos;
                    out = CJson::array();
                    skipSpace();

                    if (pos < text.size() && text[pos] == ']') {
                        ++pos;
                        return true;
                    }

                    while (true) {
                        CJson value;
                        if (!parseValue(value, depth + 1)) {
                            return false;
                        }

                        out.push(std::move(value));
                        skipSpace();

                        if (pos < text.size() && text[pos] == ',') {
                            ++pos;
                            continue;
                        }

                        if (pos < text.size() && text[pos] == ']') {
                            ++pos;
                            return true;
                        }

                        return false;
                    }
                }

                if (c == '"') {
                    std::string s;
                    if (!parseString(s)) {
                        return false;
                    }

                    out = CJson(std::move(s));
                    return true;
                }

                if (consume("true")) {
                    out = CJson(true);
                    return true;
                }

                if (consume("false")) {
                    out = CJson(false);
                    return true;
                }

                if (consume("null")) {
                    out = CJson();
                    return true;
                }

                return parseNumber(out);
            }
        };

        /**
         * Appends a JSON string literal for `s` to `out`.
         */
        void escapeString(std::string& out, const std::string& s) {
            static const char HEX[] = "0123456789abcdef";
            out.push_back('"');

            size_t start = 0;
            for (size_t i = 0; i < s.size(); ++i) {
                uint8_t c = uint8_t(s[i]);
                if (c >= 0x20 && c != '"' && c != '\\') {
                    continue;
                }

                out.append(s, start, i - start);
                start = i + 1;

                switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                default: {
                    char esc[7] = { '\\', 'u', '0', '0', HEX[c >> 4], HEX[c & 15], 0 };
                    out.append(esc);
                    break;
                }
                }
            }

            out.append(s, start, s.size() - start);
            out.push_back('"');
        }

    }

    /* Parses a document. */
    int32_t CJson::parse(std::string_view text, CJson& out, size_t* errorOffset) {
        JsonParser parser{ text, 0 };
        CJson value;

        if (!parser.parseValue(value, 0)) {
            if (errorOffset) {
                *errorOffset = parser.pos;
            }

            return -EINVAL;
        }

        parser.skipSpace();
        if (parser.pos != text.size()) {
            if (errorOffset) {
                *errorOffset = parser.pos;
            }

            return -EINVAL;
        }

        out = std::move(value);
        return SBOX_OK;
    }

    /* Serializes the value. */
    std::string CJson::dump(bool pretty) const {
        std::string out;
        dumpTo(out, pretty, 0);
        return out;
    }

    /* Appends the serialized value. */
    void CJson::dumpTo(std::string& out, bool pretty, int32_t depth) const {
        auto newline = [&](int32_t level) {
            if (pretty) {
                out.push_back('\n');
                out.append(size_t(level) * 2, ' ');
            }
        };

        switch (_type) {
        case EJSON_NULL:
            out.append("null");
            break;

        case EJSON_BOOL:
            out.append(_bool ? "true" : "false");
            break;

        case EJSON_INT:
            out.append(std::to_string(_int));
            break;

        case EJSON_DOUBLE: {
            if (!std::isfinite(_double)) {
                out.append("null");
                break;
            }

            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.17g", _double);
            out.append(buf);
            break;
        }

        case EJSON_STRING:
            escapeString(out, _string);
            break;

        case EJSON_ARRAY:
            out.push_back('[');
            for (size_t i = 0; i < _items.size(); ++i) {
                if (i) {
                    out.push_back(',');
                }

                newline(depth + 1);
                _items[i].dumpTo(out, pretty, depth + 1);
            }

            if (!_items.empty()) {
                newline(depth);
            }

            out.push_back(']');
            break;

        case EJSON_OBJECT:
            out.push_back('{');
            for (size_t i = 0; i < _items.size(); ++i) {
                if (i) {
                    out.push_back(',');
                }

                newline(depth + 1);
                escapeString(out, _keys[i]);
                out.append(pretty ? ": " : ":");
                _items[i].dumpTo(out, pretty, depth + 1);
            }

            if (!_items.empty()) {
                newline(depth);
            }

            out.push_back('}');
            break;
        }
    }

} // namespace sbox
