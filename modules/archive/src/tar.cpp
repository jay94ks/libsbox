#include <sbox/archive/tar.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>

namespace sbox {
namespace archive {

    namespace {

        constexpr size_t BLOCK = 512;

        /* Header field offsets and sizes. */
        constexpr size_t F_NAME = 0, L_NAME = 100;
        constexpr size_t F_MODE = 100, L_MODE = 8;
        constexpr size_t F_UID = 108, L_UID = 8;
        constexpr size_t F_GID = 116, L_GID = 8;
        constexpr size_t F_SIZE = 124, L_SIZE = 12;
        constexpr size_t F_MTIME = 136, L_MTIME = 12;
        constexpr size_t F_CHKSUM = 148, L_CHKSUM = 8;
        constexpr size_t F_TYPE = 156;
        constexpr size_t F_LINK = 157, L_LINK = 100;
        constexpr size_t F_MAGIC = 257;
        constexpr size_t F_VERSION = 263;
        constexpr size_t F_UNAME = 265, L_UNAME = 32;
        constexpr size_t F_GNAME = 297, L_GNAME = 32;
        constexpr size_t F_DEVMAJOR = 329, L_DEVMAJOR = 8;
        constexpr size_t F_DEVMINOR = 337, L_DEVMINOR = 8;
        constexpr size_t F_PREFIX = 345, L_PREFIX = 155;
        constexpr size_t F_GNU_ATIME = 345, F_GNU_CTIME = 357, L_GNU_TIME = 12;

        /* Bytes of padding after `size` bytes of entry data. */
        inline uint64_t padOf(uint64_t size) noexcept {
            return (BLOCK - size % BLOCK) % BLOCK;
        }

        /* Reads a NUL-terminated (or full-width) string field. */
        std::string fieldString(const uint8_t* f, size_t n) {
            size_t len = 0;
            while (len < n && f[len]) {
                len++;
            }

            return std::string(reinterpret_cast<const char*>(f), len);
        }

        /* Parses an octal or GNU base-256 numeric field. */
        bool fieldNumber(const uint8_t* f, size_t n, int64_t& out) {
            if (f[0] & 0x80u) {
                // --> Base-256, two's complement; the top bit of the first byte is only a marker.
                uint8_t inv = (f[0] & 0x40u) ? 0xFF : 0x00;
                uint64_t x = 0;
                for (size_t i = 0; i < n; ++i) {
                    uint8_t c = uint8_t(f[i] ^ inv);
                    if (i == 0) {
                        c &= 0x7Fu;
                    }

                    if (x >> 56) {
                        return false;
                    }

                    x = (x << 8) | c;
                }

                if (x >> 63) {
                    return false;
                }

                out = inv ? ~int64_t(x) : int64_t(x);
                return true;
            }

            size_t i = 0;
            size_t end = 0;
            while (end < n && f[end]) {
                end++;
            }

            while (i < end && f[i] == ' ') {
                i++;
            }

            while (end > i && f[end - 1] == ' ') {
                end--;
            }

            uint64_t v = 0;
            for (; i < end; ++i) {
                if (f[i] < '0' || f[i] > '7') {
                    return false;
                }

                if (v >> 60) {
                    return false;
                }

                v = (v << 3) | uint64_t(f[i] - '0');
            }

            if (v >> 63) {
                return false;
            }

            out = int64_t(v);
            return true;
        }

        /* Parses a decimal integer (optionally negative). */
        bool parseDecimal(const std::string& s, int64_t& out) {
            if (s.empty()) {
                return false;
            }

            size_t i = 0;
            bool neg = false;
            if (s[0] == '-') {
                neg = true;
                i = 1;
            }

            if (i == s.size()) {
                return false;
            }

            uint64_t v = 0;
            for (; i < s.size(); ++i) {
                if (s[i] < '0' || s[i] > '9') {
                    return false;
                }

                if (v > (uint64_t(std::numeric_limits<int64_t>::max()) - 9) / 10) {
                    return false;
                }

                v = v * 10 + uint64_t(s[i] - '0');
            }

            out = neg ? -int64_t(v) : int64_t(v);
            return true;
        }

        /* Parses a PAX time "sec[.frac]". */
        bool parseTime(const std::string& s, STarTime& t) {
            size_t dot = s.find('.');
            std::string whole = s.substr(0, dot);
            int64_t sec = 0;
            bool neg = !whole.empty() && whole[0] == '-';
            if (whole.empty() || whole == "-") {
                sec = 0;
            } else if (!parseDecimal(whole, sec)) {
                return false;
            }

            uint32_t nsec = 0;
            if (dot != std::string::npos) {
                std::string frac = s.substr(dot + 1);
                uint32_t scale = 100000000;
                for (char c : frac) {
                    if (c < '0' || c > '9') {
                        return false;
                    }

                    nsec += uint32_t(c - '0') * scale;
                    scale /= 10;
                }
            }

            if (neg && nsec) {
                // --> "-1.25" is 1.25 s before the epoch: sec -2, nsec 0.75e9.
                sec -= 1;
                nsec = 1000000000u - nsec;
            }

            t.sec = sec;
            t.nsec = nsec;
            return true;
        }

        /* Value of a hex digit, or -1. */
        int32_t hexValue(char c) noexcept {
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

        /* Decodes %XX escapes (LIBARCHIVE.xattr names). */
        std::string urlDecode(const std::string& s) {
            std::string out;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '%' && i + 2 < s.size()) {
                    int32_t hi = hexValue(s[i + 1]);
                    int32_t lo = hexValue(s[i + 2]);
                    if (hi >= 0 && lo >= 0) {
                        out.push_back(char((hi << 4) | lo));
                        i += 2;
                        continue;
                    }
                }

                out.push_back(s[i]);
            }

            return out;
        }

        /* Decodes base64 (padding optional); false on invalid characters. */
        bool base64Decode(const std::string& s, std::string& out) {
            out.clear();
            uint32_t acc = 0;
            int32_t bitsHeld = 0;
            for (char c : s) {
                int32_t v;
                if (c >= 'A' && c <= 'Z') {
                    v = c - 'A';
                } else if (c >= 'a' && c <= 'z') {
                    v = c - 'a' + 26;
                } else if (c >= '0' && c <= '9') {
                    v = c - '0' + 52;
                } else if (c == '+') {
                    v = 62;
                } else if (c == '/') {
                    v = 63;
                } else if (c == '=') {
                    break;
                } else {
                    return false;
                }

                acc = (acc << 6) | uint32_t(v);
                bitsHeld += 6;
                if (bitsHeld >= 8) {
                    bitsHeld -= 8;
                    out.push_back(char((acc >> bitsHeld) & 0xFFu));
                }
            }

            return true;
        }

        /* Parses PAX records "len key=value\n". */
        int32_t parsePax(const std::string& data, std::vector<std::pair<std::string, std::string>>& out) {
            size_t pos = 0;
            while (pos < data.size()) {
                if (data[pos] == '\0') {
                    // --> Some writers pad the record block with NULs.
                    break;
                }

                size_t sp = data.find(' ', pos);
                if (sp == std::string::npos || sp == pos || sp - pos > 20) {
                    return -EBADMSG;
                }

                int64_t len = 0;
                if (!parseDecimal(data.substr(pos, sp - pos), len) || len < 5 || uint64_t(len) > data.size() - pos) {
                    return -EBADMSG;
                }

                size_t end = pos + size_t(len);
                if (data[end - 1] != '\n') {
                    return -EBADMSG;
                }

                size_t eq = data.find('=', sp + 1);
                if (eq == std::string::npos || eq >= end - 1 || eq == sp + 1) {
                    return -EBADMSG;
                }

                std::string key = data.substr(sp + 1, eq - sp - 1);
                std::string value = data.substr(eq + 1, end - 1 - eq - 1);
                bool replaced = false;
                for (auto& kv : out) {
                    if (kv.first == key) {
                        kv.second = value;
                        replaced = true;
                        break;
                    }
                }

                if (!replaced) {
                    out.emplace_back(std::move(key), std::move(value));
                }

                pos = end;
            }

            return SBOX_OK;
        }

        /* Maps a type flag to an entry type. */
        ETarEntryType typeOf(char flag) noexcept {
            switch (flag) {
            case '1':
                return ETAR_HARDLINK;
            case '2':
                return ETAR_SYMLINK;
            case '3':
                return ETAR_CHAR;
            case '4':
                return ETAR_BLOCK;
            case '5':
            case 'D':
                return ETAR_DIR;
            case '6':
                return ETAR_FIFO;
            default:
                // --> '0', '\0', '7' and unknown types are regular files (POSIX, GNU tar).
                return ETAR_FILE;
            }
        }

        enum TState { T_HEADER = 0, T_META, T_DATA, T_ENTRY_END, T_PAD, T_END };

    }

    struct CTarParser::SImpl {
        STarLimits limits;
        TState state = T_HEADER;
        uint8_t hdr[BLOCK];
        size_t hpos = 0;

        char metaType = 0;
        std::string meta;
        uint64_t metaLeft = 0;
        uint64_t dataLeft = 0;
        uint64_t padLeft = 0;

        STarEntry entry;
        std::string longName;
        std::string longLink;
        bool haveLongName = false;
        bool haveLongLink = false;
        std::vector<std::pair<std::string, std::string>> localPax;
        std::vector<std::pair<std::string, std::string>> globalPax;

        explicit SImpl(const STarLimits& l) : limits(l) {}

        /* Applies merged PAX records to the entry; returns the data size override (or -1). */
        int32_t applyPax(uint64_t& size) {
            std::vector<std::pair<std::string, std::string>> merged = globalPax;
            for (const auto& kv : localPax) {
                bool replaced = false;
                for (auto& m : merged) {
                    if (m.first == kv.first) {
                        m.second = kv.second;
                        replaced = true;
                        break;
                    }
                }

                if (!replaced) {
                    merged.push_back(kv);
                }
            }

            for (const auto& kv : merged) {
                const std::string& k = kv.first;
                const std::string& v = kv.second;
                if (v.empty()) {
                    // --> An empty value removes the keyword (falls back to the header field).
                    continue;
                }

                int64_t num = 0;
                if (k == "path") {
                    entry.path = v;
                } else if (k == "linkpath") {
                    entry.linkPath = v;
                } else if (k == "size") {
                    if (!parseDecimal(v, num) || num < 0) {
                        return -EBADMSG;
                    }

                    size = uint64_t(num);
                } else if (k == "uid" || k == "gid") {
                    if (!parseDecimal(v, num)) {
                        return -EBADMSG;
                    }

                    (k == "uid" ? entry.uid : entry.gid) = num;
                } else if (k == "uname") {
                    entry.uname = v;
                } else if (k == "gname") {
                    entry.gname = v;
                } else if (k == "mtime") {
                    if (!parseTime(v, entry.mtime)) {
                        return -EBADMSG;
                    }
                } else if (k == "atime") {
                    if (!parseTime(v, entry.atime)) {
                        return -EBADMSG;
                    }

                    entry.hasAtime = true;
                } else if (k == "ctime") {
                    if (!parseTime(v, entry.ctime)) {
                        return -EBADMSG;
                    }

                    entry.hasCtime = true;
                } else if (k.compare(0, 13, "SCHILY.xattr.") == 0 && k.size() > 13) {
                    entry.xattrs.emplace_back(k.substr(13), v);
                } else if (k.compare(0, 17, "LIBARCHIVE.xattr.") == 0 && k.size() > 17) {
                    std::string name = urlDecode(k.substr(17));
                    std::string value;
                    if (!base64Decode(v, value)) {
                        return -EBADMSG;
                    }

                    bool dup = false;
                    for (const auto& x : entry.xattrs) {
                        dup = dup || x.first == name;
                    }

                    if (!dup) {
                        entry.xattrs.emplace_back(name, value);
                    }
                } else if (k == "SCHILY.devmajor" || k == "SCHILY.devminor") {
                    if (!parseDecimal(v, num) || num < 0 || num > 0xFFFFFFFFll) {
                        return -EBADMSG;
                    }

                    (k == "SCHILY.devmajor" ? entry.devMajor : entry.devMinor) = uint32_t(num);
                } else if (k.compare(0, 11, "GNU.sparse.") == 0) {
                    return -ENOTSUP;
                } else {
                    entry.paxRecords.push_back(kv);
                }
            }

            return SBOX_OK;
        }

        /* Interprets a complete header block. */
        int32_t onHeader(const uint8_t* h, ETarEvent& event) {
            bool zero = true;
            for (size_t i = 0; i < BLOCK; ++i) {
                if (h[i]) {
                    zero = false;
                    break;
                }
            }

            if (zero) {
                state = T_END;
                event = ETEV_END;
                return SBOX_OK;
            }

            int64_t stored = 0;
            if (!fieldNumber(h + F_CHKSUM, L_CHKSUM, stored)) {
                return -EBADMSG;
            }

            int64_t usum = 0;
            int64_t ssum = 0;
            for (size_t i = 0; i < BLOCK; ++i) {
                uint8_t c = (i >= F_CHKSUM && i < F_CHKSUM + L_CHKSUM) ? uint8_t(' ') : h[i];
                usum += c;
                ssum += int8_t(c);
            }

            if (stored != usum && stored != ssum) {
                return -EBADMSG;
            }

            const char flag = char(h[F_TYPE]);
            int64_t size = 0;
            if (!fieldNumber(h + F_SIZE, L_SIZE, size) || size < 0) {
                return -EBADMSG;
            }

            switch (flag) {
            case 'x':
            case 'X':
            case 'g':
            case 'L':
            case 'K':
            case 'V':
                if (uint64_t(size) > limits.maxMetaSize) {
                    return -EFBIG;
                }

                metaType = flag;
                meta.clear();
                metaLeft = uint64_t(size);
                padLeft = padOf(uint64_t(size));
                state = T_META;
                event = ETEV_NEED_INPUT;
                return SBOX_OK;

            case 'S':
            case 'M':
            case 'N':
                return -ENOTSUP;

            default:
                break;
            }

            const bool ustar = std::memcmp(h + F_MAGIC, "ustar\0", 6) == 0;
            const bool gnu = std::memcmp(h + F_MAGIC, "ustar ", 6) == 0;

            entry = STarEntry();
            entry.type = typeOf(flag);
            if (haveLongName) {
                entry.path = longName;
            } else {
                entry.path = fieldString(h + F_NAME, L_NAME);
                if (ustar && h[F_PREFIX]) {
                    entry.path = fieldString(h + F_PREFIX, L_PREFIX) + "/" + entry.path;
                }
            }

            entry.linkPath = haveLongLink ? longLink : fieldString(h + F_LINK, L_LINK);

            int64_t v = 0;
            if (!fieldNumber(h + F_MODE, L_MODE, v)) {
                return -EBADMSG;
            }

            entry.mode = uint32_t(v) & 07777u;
            if (!fieldNumber(h + F_UID, L_UID, entry.uid) || !fieldNumber(h + F_GID, L_GID, entry.gid)
                || !fieldNumber(h + F_MTIME, L_MTIME, entry.mtime.sec)) {
                return -EBADMSG;
            }

            if (ustar || gnu) {
                entry.uname = fieldString(h + F_UNAME, L_UNAME);
                entry.gname = fieldString(h + F_GNAME, L_GNAME);
                if (entry.type == ETAR_CHAR || entry.type == ETAR_BLOCK) {
                    int64_t ma = 0;
                    int64_t mi = 0;
                    if (!fieldNumber(h + F_DEVMAJOR, L_DEVMAJOR, ma) || !fieldNumber(h + F_DEVMINOR, L_DEVMINOR, mi)
                        || ma < 0 || mi < 0 || ma > 0xFFFFFFFFll || mi > 0xFFFFFFFFll) {
                        return -EBADMSG;
                    }

                    entry.devMajor = uint32_t(ma);
                    entry.devMinor = uint32_t(mi);
                }
            }

            if (gnu) {
                int64_t t = 0;
                if (h[F_GNU_ATIME] && fieldNumber(h + F_GNU_ATIME, L_GNU_TIME, t) && t) {
                    entry.atime.sec = t;
                    entry.hasAtime = true;
                }

                if (h[F_GNU_CTIME] && fieldNumber(h + F_GNU_CTIME, L_GNU_TIME, t) && t) {
                    entry.ctime.sec = t;
                    entry.hasCtime = true;
                }
            }

            // --> Old (pre-POSIX) archives mark directories by a trailing slash on a regular entry.
            if (flag == '\0' && !entry.path.empty() && entry.path.back() == '/') {
                entry.type = ETAR_DIR;
            }

            uint64_t dataSize = uint64_t(size);
            int32_t rc = applyPax(dataSize);
            haveLongName = false;
            haveLongLink = false;
            longName.clear();
            longLink.clear();
            localPax.clear();
            if (rc < 0) {
                return rc;
            }

            // --> Like Go's archive/tar: only regular files (and GNU dumpdirs, skipped) carry data.
            uint64_t skip = 0;
            if (entry.type == ETAR_FILE) {
                entry.size = dataSize;
            } else {
                entry.size = 0;
                if (flag == 'D') {
                    skip = dataSize;
                }

                dataSize = 0;
            }

            dataLeft = dataSize;
            padLeft = padOf(dataSize) + skip + padOf(skip);
            state = dataLeft ? T_DATA : T_ENTRY_END;
            event = ETEV_ENTRY;
            return SBOX_OK;
        }

        /* Interprets a complete metadata entry. */
        int32_t onMeta() {
            switch (metaType) {
            case 'x':
            case 'X':
                localPax.clear();
                return parsePax(meta, localPax);

            case 'g': {
                std::vector<std::pair<std::string, std::string>> recs;
                int32_t rc = parsePax(meta, recs);
                if (rc < 0) {
                    return rc;
                }

                for (const auto& kv : recs) {
                    bool replaced = false;
                    for (auto& g : globalPax) {
                        if (g.first == kv.first) {
                            g.second = kv.second;
                            replaced = true;
                            break;
                        }
                    }

                    if (!replaced) {
                        globalPax.push_back(kv);
                    }
                }

                return SBOX_OK;
            }

            case 'L':
                longName = fieldString(reinterpret_cast<const uint8_t*>(meta.data()), meta.size());
                haveLongName = true;
                return SBOX_OK;

            case 'K':
                longLink = fieldString(reinterpret_cast<const uint8_t*>(meta.data()), meta.size());
                haveLongLink = true;
                return SBOX_OK;

            default:
                return SBOX_OK;
            }
        }
    };

    /* Creates a parser. */
    CTarParser::CTarParser(const STarLimits& limits) : _impl(std::make_unique<SImpl>(limits)) {}

    /* Destroys the parser. */
    CTarParser::~CTarParser() = default;

    /* Latest entry. */
    const STarEntry& CTarParser::entry() const noexcept {
        return _impl->entry;
    }

    /* True after the end marker. */
    bool CTarParser::ended() const noexcept {
        return _impl->state == T_END;
    }

    /* True between entries. */
    bool CTarParser::idle() const noexcept {
        return _impl->state == T_END || (_impl->state == T_HEADER && _impl->hpos == 0 && !_impl->haveLongName
                                         && !_impl->haveLongLink && _impl->localPax.empty());
    }

    /* Starts over. */
    void CTarParser::reset() {
        STarLimits limits = _impl->limits;
        _impl = std::make_unique<SImpl>(limits);
    }

    /* Advances to the next event. */
    int32_t CTarParser::next(const SReadOnlyByteSpan& in, size_t& consumed, ETarEvent& event, SReadOnlyByteSpan& data) {
        SImpl& s = *_impl;
        consumed = 0;
        event = ETEV_NEED_INPUT;
        data = SReadOnlyByteSpan();
        size_t pos = 0;

        for (;;) {
            const size_t avail = in.size - pos;
            switch (s.state) {
            case T_END:
                consumed = in.size;
                event = ETEV_END;
                return SBOX_OK;

            case T_HEADER: {
                const uint8_t* h;
                if (s.hpos == 0 && avail >= BLOCK) {
                    h = in.data + pos;
                    pos += BLOCK;
                } else {
                    size_t n = BLOCK - s.hpos;
                    if (n > avail) {
                        n = avail;
                    }

                    if (n) {
                        std::memcpy(s.hdr + s.hpos, in.data + pos, n);
                    }

                    s.hpos += n;
                    pos += n;
                    if (s.hpos < BLOCK) {
                        consumed = pos;
                        return SBOX_OK;
                    }

                    s.hpos = 0;
                    h = s.hdr;
                }

                ETarEvent ev = ETEV_NEED_INPUT;
                int32_t rc = s.onHeader(h, ev);
                consumed = pos;
                if (rc < 0) {
                    return rc;
                }

                if (ev != ETEV_NEED_INPUT) {
                    event = ev;
                    if (ev == ETEV_END) {
                        consumed = in.size;
                    }

                    return SBOX_OK;
                }

                break;
            }

            case T_META: {
                size_t n = s.metaLeft < avail ? size_t(s.metaLeft) : avail;
                s.meta.append(reinterpret_cast<const char*>(in.data + pos), n);
                s.metaLeft -= n;
                pos += n;
                if (s.metaLeft) {
                    consumed = pos;
                    return SBOX_OK;
                }

                int32_t rc = s.onMeta();
                if (rc < 0) {
                    consumed = pos;
                    return rc;
                }

                s.state = T_PAD;
                break;
            }

            case T_DATA: {
                size_t n = s.dataLeft < avail ? size_t(s.dataLeft) : avail;
                if (n == 0) {
                    consumed = pos;
                    return SBOX_OK;
                }

                data = SReadOnlyByteSpan(in.data + pos, n);
                pos += n;
                s.dataLeft -= n;
                if (s.dataLeft == 0) {
                    s.state = T_ENTRY_END;
                }

                consumed = pos;
                event = ETEV_DATA;
                return SBOX_OK;
            }

            case T_ENTRY_END:
                s.state = T_PAD;
                consumed = pos;
                event = ETEV_ENTRY_END;
                return SBOX_OK;

            case T_PAD: {
                size_t n = s.padLeft < avail ? size_t(s.padLeft) : avail;
                s.padLeft -= n;
                pos += n;
                if (s.padLeft) {
                    consumed = pos;
                    return SBOX_OK;
                }

                s.state = T_HEADER;
                break;
            }
            }
        }
    }

    /* Creates a push-style reader. */
    CTarSink::CTarSink(ITarHandler& handler, const STarLimits& limits) : _parser(limits), _handler(handler) {}

    /* Parses and dispatches. */
    int32_t CTarSink::write(const SReadOnlyByteSpan& data) {
        if (_error) {
            return _error;
        }

        SReadOnlyByteSpan in = data;
        while (!_done) {
            size_t consumed = 0;
            ETarEvent ev = ETEV_NEED_INPUT;
            SReadOnlyByteSpan chunk;
            int32_t rc = _parser.next(in, consumed, ev, chunk);
            in = in.slice(consumed);
            if (rc < 0) {
                _error = rc;
                return rc;
            }

            switch (ev) {
            case ETEV_NEED_INPUT:
                return SBOX_OK;
            case ETEV_ENTRY:
                _inEntry = true;
                rc = _handler.onEntry(_parser.entry());
                break;
            case ETEV_DATA:
                rc = _handler.onData(chunk);
                break;
            case ETEV_ENTRY_END:
                _inEntry = false;
                rc = _handler.onEntryEnd();
                break;
            case ETEV_END:
                _done = true;
                rc = _handler.onEnd();
                break;
            }

            if (rc < 0) {
                _error = rc;
                return rc;
            }
        }

        return SBOX_OK;
    }

    /* Verifies the archive did not stop mid-entry. */
    int32_t CTarSink::finish() {
        if (_error) {
            return _error;
        }

        if (_done) {
            return SBOX_OK;
        }

        if (_inEntry || !_parser.idle()) {
            _error = -ENODATA;
            return _error;
        }

        _done = true;
        int32_t rc = _handler.onEnd();
        if (rc < 0) {
            _error = rc;
        }

        return rc;
    }

    /* Creates a pull-style reader. */
    CTarReader::CTarReader(IByteSource& source, const STarLimits& limits)
        : _parser(limits), _source(source), _buf(65536) {}

    /* Runs the parser until it yields an event. */
    int32_t CTarReader::pump(ETarEvent& event, SReadOnlyByteSpan& data, size_t maxData) {
        for (;;) {
            if (_pos == _len && !_eof) {
                SIoResult r = _source.read(SByteSpan(_buf.data(), _buf.size()));
                if (!r.ok()) {
                    return r.error;
                }

                _pos = 0;
                _len = r.bytes;
                _eof = r.bytes == 0;
            }

            size_t avail = _len - _pos;
            size_t lim = avail < maxData ? avail : maxData;
            size_t consumed = 0;
            int32_t rc = _parser.next(SReadOnlyByteSpan(_buf.data() + _pos, lim), consumed, event, data);
            _pos += consumed;
            if (rc < 0) {
                return rc;
            }

            if (event != ETEV_NEED_INPUT) {
                return SBOX_OK;
            }

            if (_eof && _pos == _len) {
                return SBOX_OK;
            }
        }
    }

    /* Moves to the next entry. */
    int32_t CTarReader::next(STarEntry& entry) {
        if (_ended) {
            return 0;
        }

        for (;;) {
            ETarEvent ev = ETEV_NEED_INPUT;
            SReadOnlyByteSpan data;
            int32_t rc = pump(ev, data, size_t(-1));
            if (rc < 0) {
                return rc;
            }

            switch (ev) {
            case ETEV_ENTRY:
                _inEntry = true;
                entry = _parser.entry();
                return 1;
            case ETEV_DATA:
                break;
            case ETEV_ENTRY_END:
                _inEntry = false;
                break;
            case ETEV_END:
                _ended = true;
                return 0;
            case ETEV_NEED_INPUT:
                if (!_inEntry && _parser.idle()) {
                    _ended = true;
                    return 0;
                }

                return -ENODATA;
            }
        }
    }

    /* Reads data of the current entry. */
    SIoResult CTarReader::read(const SByteSpan& buffer) {
        if (!_inEntry || buffer.size == 0) {
            return SIoResult{ SBOX_OK, 0 };
        }

        ETarEvent ev = ETEV_NEED_INPUT;
        SReadOnlyByteSpan data;
        int32_t rc = pump(ev, data, buffer.size);
        if (rc < 0) {
            return SIoResult{ rc, 0 };
        }

        if (ev == ETEV_DATA) {
            std::memcpy(buffer.data, data.data, data.size);
            return SIoResult{ SBOX_OK, data.size };
        }

        if (ev == ETEV_ENTRY_END) {
            _inEntry = false;
            return SIoResult{ SBOX_OK, 0 };
        }

        return SIoResult{ -ENODATA, 0 };
    }

    namespace {

        /* Writes `value` as octal into a field of `n` bytes (n-1 digits and a NUL). */
        bool putOctal(uint8_t* f, size_t n, int64_t value) {
            if (value < 0) {
                return false;
            }

            uint64_t v = uint64_t(value);
            size_t digits = n - 1;
            if (digits < 22 && (v >> (3 * digits)) != 0) {
                return false;
            }

            for (size_t i = digits; i-- > 0;) {
                f[i] = uint8_t('0' + (v & 7u));
                v >>= 3;
            }

            f[digits] = 0;
            return true;
        }

        /* Writes `value` in GNU base-256 into a field of `n` bytes. */
        void putBase256(uint8_t* f, size_t n, int64_t value) {
            uint64_t v = uint64_t(value);
            for (size_t i = n; i-- > 0;) {
                f[i] = uint8_t(v);
                v = uint64_t(int64_t(v) >> 8);
            }

            f[0] = value < 0 ? 0xFF : 0x80;
        }

        /* Encodes one PAX record. */
        void paxRecord(std::string& out, const std::string& key, const std::string& value) {
            size_t base = key.size() + value.size() + 3;
            size_t len = base + std::to_string(base).size();
            if (std::to_string(len).size() != std::to_string(base).size()) {
                len = base + std::to_string(len).size();
            }

            out += std::to_string(len);
            out += ' ';
            out += key;
            out += '=';
            out += value;
            out += '\n';
        }

        /* Formats a PAX time value. */
        std::string paxTime(const STarTime& t) {
            int64_t sec = t.sec;
            uint32_t nsec = t.nsec;
            std::string s;
            if (sec < 0 && nsec) {
                sec += 1;
                nsec = 1000000000u - nsec;
                s = "-" + std::to_string(-sec);
            } else {
                s = std::to_string(sec);
            }

            if (nsec) {
                char frac[16];
                std::snprintf(frac, sizeof(frac), ".%09u", nsec);
                std::string f = frac;
                while (f.back() == '0') {
                    f.pop_back();
                }

                s += f;
            }

            return s;
        }

        /* Fills magic, version and checksum. */
        void sealHeader(uint8_t* h, ETarFormat format) {
            if (format == ETFMT_GNU) {
                std::memcpy(h + F_MAGIC, "ustar  ", 8);
            } else {
                std::memcpy(h + F_MAGIC, "ustar", 6);
                std::memcpy(h + F_VERSION, "00", 2);
            }

            std::memset(h + F_CHKSUM, ' ', L_CHKSUM);
            uint32_t sum = 0;
            for (size_t i = 0; i < BLOCK; ++i) {
                sum += h[i];
            }

            putOctal(h + F_CHKSUM, 7, int64_t(sum));
            h[F_CHKSUM + 7] = ' ';
        }

        /* Copies a string into a field (truncating). */
        void putString(uint8_t* f, size_t n, const std::string& s) {
            std::memcpy(f, s.data(), s.size() < n ? s.size() : n);
        }

    }

    /* Type flag character. */
    char TarTypeFlag(ETarEntryType type) noexcept {
        switch (type) {
        case ETAR_HARDLINK:
            return '1';
        case ETAR_SYMLINK:
            return '2';
        case ETAR_CHAR:
            return '3';
        case ETAR_BLOCK:
            return '4';
        case ETAR_DIR:
            return '5';
        case ETAR_FIFO:
            return '6';
        default:
            return '0';
        }
    }

    /* Writes to the sink. */
    int32_t CTarWriter::put(const uint8_t* data, size_t size) {
        if (_error) {
            return _error;
        }

        int32_t rc = _sink.write(SReadOnlyByteSpan(data, size));
        if (rc < 0) {
            _error = rc;
            return rc;
        }

        _written += size;
        return SBOX_OK;
    }

    /* Writes a pseudo entry with a payload. */
    int32_t CTarWriter::writeMeta(char type, const std::string& name, const std::string& payload) {
        uint8_t h[BLOCK];
        std::memset(h, 0, BLOCK);
        putString(h + F_NAME, L_NAME, name);
        putOctal(h + F_MODE, L_MODE, 0644);
        putOctal(h + F_UID, L_UID, 0);
        putOctal(h + F_GID, L_GID, 0);
        putOctal(h + F_SIZE, L_SIZE, int64_t(payload.size()));
        putOctal(h + F_MTIME, L_MTIME, 0);
        h[F_TYPE] = uint8_t(type);
        sealHeader(h, _format);
        int32_t rc = put(h, BLOCK);
        if (rc == SBOX_OK) {
            rc = put(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
        }

        uint8_t zeros[BLOCK] = { 0 };
        if (rc == SBOX_OK) {
            rc = put(zeros, size_t(padOf(payload.size())));
        }

        return rc;
    }

    /* Writes an entry header (plus PAX/GNU extension entries when needed). */
    int32_t CTarWriter::writeHeader(const STarEntry& e) {
        if (_error) {
            return _error;
        }

        if (_remaining || _finished || e.type >= ETAR_INVALID || e.path.empty()) {
            return -EINVAL;
        }

        const bool pax = _format == ETFMT_PAX;
        const bool gnu = _format == ETFMT_GNU;
        std::string records;
        uint8_t h[BLOCK];
        std::memset(h, 0, BLOCK);

        std::string name = e.path;
        if (e.type == ETAR_DIR && name.back() != '/') {
            name += '/';
        }

        if (name.size() <= L_NAME) {
            putString(h + F_NAME, L_NAME, name);
        } else {
            bool split = false;
            if (!gnu) {
                size_t limit = name.size() - 1 < L_PREFIX ? name.size() - 1 : L_PREFIX;
                size_t slash = name.rfind('/', limit);
                // --> A trailing '/' of a directory cannot be the split point.
                while (slash != std::string::npos && slash + 1 >= name.size()) {
                    slash = slash ? name.rfind('/', slash - 1) : std::string::npos;
                }

                if (slash != std::string::npos && slash > 0 && name.size() - slash - 1 <= L_NAME) {
                    putString(h + F_PREFIX, L_PREFIX, name.substr(0, slash));
                    putString(h + F_NAME, L_NAME, name.substr(slash + 1));
                    split = true;
                }
            }

            if (!split) {
                if (pax) {
                    paxRecord(records, "path", e.path);
                    putString(h + F_NAME, L_NAME, name);
                } else if (gnu) {
                    int32_t rc = writeMeta('L', "././@LongLink", name + std::string(1, '\0'));
                    if (rc < 0) {
                        return rc;
                    }

                    putString(h + F_NAME, L_NAME, name);
                } else {
                    return -ENAMETOOLONG;
                }
            }
        }

        if (e.linkPath.size() > L_LINK) {
            if (pax) {
                paxRecord(records, "linkpath", e.linkPath);
            } else if (gnu) {
                int32_t rc = writeMeta('K', "././@LongLink", e.linkPath + std::string(1, '\0'));
                if (rc < 0) {
                    return rc;
                }
            } else {
                return -ENAMETOOLONG;
            }
        }

        putString(h + F_LINK, L_LINK, e.linkPath);

        // --> Numbers: octal when it fits, else a PAX record (PAX) or base-256 (GNU).
        auto number = [&](size_t off, size_t len, int64_t value, const char* key) -> int32_t {
            if (putOctal(h + off, len, value)) {
                return SBOX_OK;
            }

            if (pax && key) {
                paxRecord(records, key, std::to_string(value));
                putOctal(h + off, len, 0);
                return SBOX_OK;
            }

            if (gnu || pax) {
                putBase256(h + off, len, value);
                return SBOX_OK;
            }

            return -EOVERFLOW;
        };

        const uint64_t size = e.type == ETAR_FILE ? e.size : 0;
        if (size > uint64_t(std::numeric_limits<int64_t>::max())) {
            return -EOVERFLOW;
        }

        int32_t rc = number(F_MODE, L_MODE, int64_t(e.mode & 07777u), nullptr);
        if (rc == SBOX_OK) {
            rc = number(F_UID, L_UID, e.uid, "uid");
        }

        if (rc == SBOX_OK) {
            rc = number(F_GID, L_GID, e.gid, "gid");
        }

        if (rc == SBOX_OK) {
            rc = number(F_SIZE, L_SIZE, int64_t(size), "size");
        }

        if (rc == SBOX_OK) {
            if (pax && e.mtime.nsec) {
                paxRecord(records, "mtime", paxTime(e.mtime));
                if (!putOctal(h + F_MTIME, L_MTIME, e.mtime.sec)) {
                    putOctal(h + F_MTIME, L_MTIME, 0);
                }
            } else {
                rc = number(F_MTIME, L_MTIME, e.mtime.sec, "mtime");
            }
        }

        if (rc == SBOX_OK && (e.type == ETAR_CHAR || e.type == ETAR_BLOCK)) {
            rc = number(F_DEVMAJOR, L_DEVMAJOR, e.devMajor, nullptr);
            if (rc == SBOX_OK) {
                rc = number(F_DEVMINOR, L_DEVMINOR, e.devMinor, nullptr);
            }
        }

        if (rc < 0) {
            return rc;
        }

        for (const auto* field : { &e.uname, &e.gname }) {
            if (field->size() > L_UNAME) {
                if (pax) {
                    paxRecord(records, field == &e.uname ? "uname" : "gname", *field);
                } else if (!gnu) {
                    return -ENAMETOOLONG;
                }
            }
        }

        putString(h + F_UNAME, L_UNAME, e.uname);
        putString(h + F_GNAME, L_GNAME, e.gname);

        if (pax && e.hasAtime) {
            paxRecord(records, "atime", paxTime(e.atime));
        }

        if (pax && e.hasCtime) {
            paxRecord(records, "ctime", paxTime(e.ctime));
        }

        if (!e.xattrs.empty() || !e.paxRecords.empty()) {
            if (_format == ETFMT_USTAR) {
                return -ENOTSUP;
            }

            for (const auto& x : e.xattrs) {
                paxRecord(records, "SCHILY.xattr." + x.first, x.second);
            }

            for (const auto& r : e.paxRecords) {
                paxRecord(records, r.first, r.second);
            }
        }

        if (!records.empty()) {
            std::string base = e.path;
            while (base.size() > 1 && base.back() == '/') {
                base.pop_back();
            }

            size_t slash = base.rfind('/');
            std::string dir = slash == std::string::npos ? std::string() : base.substr(0, slash + 1);
            std::string file = slash == std::string::npos ? base : base.substr(slash + 1);
            std::string metaName = dir + "PaxHeaders.0/" + file;
            if (metaName.size() > L_NAME) {
                metaName.resize(L_NAME);
            }

            rc = writeMeta('x', metaName, records);
            if (rc < 0) {
                return rc;
            }
        }

        h[F_TYPE] = uint8_t(TarTypeFlag(e.type));
        sealHeader(h, _format);
        rc = put(h, BLOCK);
        if (rc < 0) {
            return rc;
        }

        _remaining = size;
        if (size == 0) {
            return SBOX_OK;
        }

        _padding = padOf(size);
        return SBOX_OK;
    }

    /* Writes entry data. */
    int32_t CTarWriter::writeData(const SReadOnlyByteSpan& data) {
        if (_error) {
            return _error;
        }

        if (data.size > _remaining) {
            return -EINVAL;
        }

        int32_t rc = put(data.data, data.size);
        if (rc < 0) {
            return rc;
        }

        _remaining -= data.size;
        if (_remaining == 0 && _padding) {
            uint8_t zeros[BLOCK] = { 0 };
            rc = put(zeros, size_t(_padding));
            _padding = 0;
        }

        return rc;
    }

    /* Header plus data. */
    int32_t CTarWriter::writeEntry(const STarEntry& entry, const SReadOnlyByteSpan& data) {
        int32_t rc = writeHeader(entry);
        if (rc == SBOX_OK && _remaining) {
            rc = writeData(data);
        }

        if (rc == SBOX_OK && _remaining) {
            return -EINVAL;
        }

        return rc;
    }

    /* Writes the end marker. */
    int32_t CTarWriter::finish() {
        if (_error) {
            return _error;
        }

        if (_remaining) {
            return -EINVAL;
        }

        if (_finished) {
            return SBOX_OK;
        }

        uint8_t zeros[2 * BLOCK] = { 0 };
        int32_t rc = put(zeros, sizeof(zeros));
        if (rc < 0) {
            return rc;
        }

        _finished = true;
        return _sink.finish();
    }

}
}
