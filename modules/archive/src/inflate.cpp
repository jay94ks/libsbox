#include <sbox/archive/deflate.hpp>
#include <sbox/archive/checksum.hpp>
#include "bits.hpp"
#include "huffman.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace archive {

    namespace {

        constexpr uint32_t LIT_BITS = 10;
        constexpr uint32_t LIT_MASK = (1u << LIT_BITS) - 1;
        constexpr uint32_t DIST_BITS = 8;
        constexpr uint32_t DIST_MASK = (1u << DIST_BITS) - 1;
        constexpr uint32_t CL_BITS = 7;

        constexpr size_t HISTORY = 32768;
        constexpr size_t WIN_TOTAL = size_t(1) << 18;
        constexpr size_t WIN_SLACK = 64;                // --> Room for 8-byte over-copies past the end.
        constexpr size_t MAX_MATCH = 258;
        constexpr size_t SLIDE_AT = WIN_TOTAL - MAX_MATCH;
        constexpr size_t MAX_GZIP_FIELD = size_t(1) << 20;

        /* The fixed Huffman tables of block type 1, built once. */
        struct FixedTables {
            std::vector<uint32_t> lit;
            std::vector<uint32_t> dist;

            FixedTables() {
                uint8_t lens[288];
                std::memset(lens, 8, 144);
                std::memset(lens + 144, 9, 112);
                std::memset(lens + 256, 7, 24);
                std::memset(lens + 280, 8, 8);
                huff::buildTable(lens, 288, LIT_BITS, huff::A_LITLEN, lit);

                uint8_t dl[32];
                std::memset(dl, 5, 32);
                huff::buildTable(dl, 32, DIST_BITS, huff::A_DIST, dist);
            }
        };

        /* Returns the shared fixed tables. */
        const FixedTables& fixedTables() {
            static const FixedTables tables;
            return tables;
        }

        /* Outcome of one decoding step. */
        enum Step {
            ST_PROGRESS = 0,    // --> State advanced (or the window filled up); call again.
            ST_NEED_INPUT,      // --> Nothing more can be done without input.
        };

        enum State {
            S_HEADER = 0,
            S_BLOCK,
            S_STORED_LEN,
            S_STORED,
            S_DYN_COUNTS,
            S_DYN_CLENS,
            S_DYN_LENS,
            S_HUFF,
            S_TRAILER,
            S_NEXT_MEMBER,
            S_DONE,
        };

        enum GzipState {
            G_FIXED = 0,
            G_XLEN,
            G_EXTRA,
            G_NAME,
            G_COMMENT,
            G_HCRC,
            G_DONE,
        };

    }

    struct CInflater::SImpl {
        EDeflateFormat format;
        EDeflateFormat active;          // --> Resolved container (EDFMT_AUTO picks one per stream).
        bool multiMember;

        int32_t error = SBOX_OK;
        State state = S_HEADER;

        uint64_t bb = 0;                // --> Bit buffer; bits above `bc` are zero between calls.
        uint32_t bc = 0;

        std::vector<uint8_t> win;
        size_t wpos = 0;                // --> Next byte to produce.
        size_t flushPos = 0;            // --> Next byte to hand to the caller.
        size_t ckPos = 0;               // --> Next byte to feed into the checksum.
        size_t histStart = 0;           // --> Start of the current member's history.

        bool lastBlock = false;
        uint32_t storedLeft = 0;

        uint32_t hlit = 0;
        uint32_t hdist = 0;
        uint32_t hclen = 0;
        uint32_t lensIdx = 0;
        uint8_t clens[19];
        uint8_t lens[320];
        std::vector<uint32_t> clTable;
        std::vector<uint32_t> litTable;
        std::vector<uint32_t> distTable;
        const uint32_t* lit = nullptr;
        const uint32_t* dist = nullptr;

        GzipState gstate = G_FIXED;
        uint8_t hbuf[10];
        uint32_t hpos = 0;
        uint32_t xlen = 0;
        CCrc32 hcrc;

        uint8_t tbuf[8];
        uint32_t tpos = 0;

        CCrc32 crc;
        CAdler32 adler;
        uint32_t memberSize = 0;        // --> Output size mod 2^32 (gzip ISIZE).

        SGzipHeader gz;
        uint64_t members = 0;
        uint64_t totalOut = 0;

        /* Configures a fresh decoder. */
        SImpl(EDeflateFormat fmt, bool multi) : format(fmt), active(fmt), multiMember(multi) {
            win.resize(WIN_TOTAL + WIN_SLACK);
            reset();
        }

        /* Returns to the initial state. */
        void reset() noexcept {
            error = SBOX_OK;
            active = format;
            state = format == EDFMT_RAW ? S_BLOCK : S_HEADER;
            bb = 0;
            bc = 0;
            wpos = flushPos = ckPos = histStart = 0;
            lastBlock = false;
            storedLeft = 0;
            gstate = G_FIXED;
            hpos = 0;
            tpos = 0;
            crc.reset();
            adler.reset();
            hcrc.reset();
            memberSize = 0;
            gz = SGzipHeader();
            members = 0;
            totalOut = 0;
        }

        /* Pulls whole bytes into the bit buffer until it holds `n` bits; false when input ran out. */
        inline bool need(uint32_t n, const uint8_t*& in, const uint8_t* end) noexcept {
            while (bc < n) {
                if (in == end) {
                    return false;
                }

                bb |= uint64_t(*in++) << bc;
                bc += 8;
            }

            return true;
        }

        /* Removes `n` bits (n < 64). */
        inline void drop(uint32_t n) noexcept {
            bb >>= n;
            bc -= n;
        }

        /* Returns the low `n` bits without removing them. */
        inline uint32_t peek(uint32_t n) const noexcept {
            return uint32_t(bb & ((uint64_t(1) << n) - 1));
        }

        /* Takes one byte at a byte boundary (bit buffer first, then input). */
        inline bool takeByte(uint8_t& b, const uint8_t*& in, const uint8_t* end) noexcept {
            if (bc >= 8) {
                b = uint8_t(bb);
                drop(8);
                return true;
            }

            if (in == end) {
                return false;
            }

            b = *in++;
            return true;
        }

        /* Folds newly produced bytes into the member checksum. */
        void updateChecksum() noexcept {
            if (ckPos >= wpos) {
                return;
            }

            SReadOnlyByteSpan span(win.data() + ckPos, wpos - ckPos);
            if (active == EDFMT_GZIP) {
                crc.update(span);
            } else if (active == EDFMT_ZLIB) {
                adler.update(span);
            }

            memberSize += uint32_t(span.size);
            totalOut += span.size;
            ckPos = wpos;
        }

        /* Keeps the last 32 KiB of history and moves it to the front of the window. */
        void slide() noexcept {
            size_t keep = wpos < HISTORY ? wpos : HISTORY;
            size_t shift = wpos - keep;
            if (shift == 0) {
                return;
            }

            std::memmove(win.data(), win.data() + shift, keep);
            wpos = flushPos = ckPos = keep;
            histStart = histStart > shift ? histStart - shift : 0;
        }

        /* Starts a new gzip member (or zlib stream) after the previous one finished. */
        void startMember() noexcept {
            histStart = wpos;
            crc.reset();
            adler.reset();
            hcrc.reset();
            memberSize = 0;
            gstate = G_FIXED;
            hpos = 0;
            tpos = 0;
            lastBlock = false;
            state = S_HEADER;
        }

        /* Parses the zlib or gzip header. */
        int32_t stepHeader(const uint8_t*& in, const uint8_t* end) {
            if (active == EDFMT_AUTO) {
                // --> gzip starts with 1f 8b; a zlib CMF byte is never 0x1f (CM must be 8).
                uint8_t first;
                if (bc >= 8) {
                    first = uint8_t(bb);
                } else if (in < end) {
                    first = *in;
                } else {
                    return ST_NEED_INPUT;
                }

                active = first == 0x1F ? EDFMT_GZIP : EDFMT_ZLIB;
            }

            if (active == EDFMT_ZLIB) {
                if (!need(16, in, end)) {
                    return ST_NEED_INPUT;
                }

                uint32_t cmf = peek(8);
                uint32_t flg = (bb >> 8) & 0xFFu;
                if ((cmf & 0x0Fu) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0) {
                    return -EBADMSG;
                }

                if (flg & 0x20u) {
                    // --> Preset dictionaries are not used by any container format we read.
                    return -ENOTSUP;
                }

                drop(16);
                state = S_BLOCK;
                return ST_PROGRESS;
            }

            uint8_t b;
            while (gstate != G_DONE) {
                if (!takeByte(b, in, end)) {
                    return ST_NEED_INPUT;
                }

                if (gstate != G_HCRC) {
                    hcrc.update(SReadOnlyByteSpan(&b, 1));
                }

                switch (gstate) {
                case G_FIXED:
                    hbuf[hpos++] = b;
                    if (hpos == 1 && b != 0x1F) {
                        return -EBADMSG;
                    }

                    if (hpos == 2 && b != 0x8B) {
                        return -EBADMSG;
                    }

                    if (hpos == 3 && b != 8) {
                        return -EBADMSG;
                    }

                    if (hpos == 4 && (b & 0xE0u)) {
                        return -EBADMSG;
                    }

                    if (hpos == 10) {
                        gz = SGzipHeader();
                        gz.flags = hbuf[3];
                        gz.mtime = bits::load32(hbuf + 4);
                        gz.extraFlags = hbuf[8];
                        gz.os = hbuf[9];
                        hpos = 0;
                        gstate = G_XLEN;
                        if (!(gz.flags & 0x04u)) {
                            gstate = G_NAME;
                            if (!(gz.flags & 0x08u)) {
                                gstate = (gz.flags & 0x10u) ? G_COMMENT : ((gz.flags & 0x02u) ? G_HCRC : G_DONE);
                            }
                        }
                    }

                    break;

                case G_XLEN:
                    hbuf[hpos++] = b;
                    if (hpos == 2) {
                        xlen = bits::load16(hbuf);
                        hpos = 0;
                        gstate = G_EXTRA;
                        if (xlen == 0) {
                            gstate = (gz.flags & 0x08u) ? G_NAME : ((gz.flags & 0x10u) ? G_COMMENT : ((gz.flags & 0x02u) ? G_HCRC : G_DONE));
                        }
                    }

                    break;

                case G_EXTRA:
                    gz.extra.push_back(b);
                    if (gz.extra.size() == xlen) {
                        gstate = (gz.flags & 0x08u) ? G_NAME : ((gz.flags & 0x10u) ? G_COMMENT : ((gz.flags & 0x02u) ? G_HCRC : G_DONE));
                    }

                    break;

                case G_NAME:
                    if (b == 0) {
                        gstate = (gz.flags & 0x10u) ? G_COMMENT : ((gz.flags & 0x02u) ? G_HCRC : G_DONE);
                    } else if (gz.name.size() >= MAX_GZIP_FIELD) {
                        return -EBADMSG;
                    } else {
                        gz.name.push_back(char(b));
                    }

                    break;

                case G_COMMENT:
                    if (b == 0) {
                        gstate = (gz.flags & 0x02u) ? G_HCRC : G_DONE;
                    } else if (gz.comment.size() >= MAX_GZIP_FIELD) {
                        return -EBADMSG;
                    } else {
                        gz.comment.push_back(char(b));
                    }

                    break;

                case G_HCRC:
                    hbuf[hpos++] = b;
                    if (hpos == 2) {
                        if (bits::load16(hbuf) != uint16_t(hcrc.value())) {
                            return -EBADMSG;
                        }

                        gstate = G_DONE;
                    }

                    break;

                default:
                    break;
                }
            }

            state = S_BLOCK;
            return ST_PROGRESS;
        }

        /* Reads the 3-bit block header. */
        int32_t stepBlock(const uint8_t*& in, const uint8_t* end) {
            if (!need(3, in, end)) {
                return ST_NEED_INPUT;
            }

            lastBlock = peek(1) != 0;
            uint32_t type = (bb >> 1) & 3u;
            drop(3);
            switch (type) {
            case 0:
                drop(bc & 7u);
                state = S_STORED_LEN;
                break;

            case 1: {
                const FixedTables& ft = fixedTables();
                lit = ft.lit.data();
                dist = ft.dist.data();
                state = S_HUFF;
                break;
            }

            case 2:
                state = S_DYN_COUNTS;
                break;

            default:
                return -EBADMSG;
            }

            return ST_PROGRESS;
        }

        /* Reads LEN/NLEN of a stored block. */
        int32_t stepStoredLen(const uint8_t*& in, const uint8_t* end) {
            if (!need(32, in, end)) {
                return ST_NEED_INPUT;
            }

            uint32_t len = peek(16);
            uint32_t nlen = (bb >> 16) & 0xFFFFu;
            if ((len ^ 0xFFFFu) != nlen) {
                return -EBADMSG;
            }

            drop(32);
            storedLeft = len;
            state = len ? S_STORED : endOfBlock();
            return ST_PROGRESS;
        }

        /* Copies stored bytes into the window. */
        int32_t stepStored(const uint8_t*& in, const uint8_t* end) {
            while (storedLeft) {
                size_t room = WIN_TOTAL - wpos;
                if (room == 0) {
                    return ST_PROGRESS;
                }

                if (bc >= 8) {
                    win[wpos++] = uint8_t(bb);
                    drop(8);
                    storedLeft--;
                    continue;
                }

                size_t avail = size_t(end - in);
                if (avail == 0) {
                    return ST_NEED_INPUT;
                }

                size_t n = storedLeft;
                if (n > room) {
                    n = room;
                }

                if (n > avail) {
                    n = avail;
                }

                std::memcpy(win.data() + wpos, in, n);
                wpos += n;
                in += n;
                storedLeft -= uint32_t(n);
            }

            state = endOfBlock();
            return ST_PROGRESS;
        }

        /* Reads HLIT/HDIST/HCLEN. */
        int32_t stepDynCounts(const uint8_t*& in, const uint8_t* end) {
            if (!need(14, in, end)) {
                return ST_NEED_INPUT;
            }

            hlit = peek(5) + 257;
            hdist = ((bb >> 5) & 31u) + 1;
            hclen = ((bb >> 10) & 15u) + 4;
            drop(14);
            if (hlit > 286 || hdist > 30) {
                return -EBADMSG;
            }

            std::memset(clens, 0, sizeof(clens));
            lensIdx = 0;
            state = S_DYN_CLENS;
            return ST_PROGRESS;
        }

        /* Reads the code-length code lengths. */
        int32_t stepDynClens(const uint8_t*& in, const uint8_t* end) {
            while (lensIdx < hclen) {
                if (!need(3, in, end)) {
                    return ST_NEED_INPUT;
                }

                clens[huff::CODELEN_ORDER[lensIdx++]] = uint8_t(peek(3));
                drop(3);
            }

            if (!huff::buildTable(clens, 19, CL_BITS, huff::A_CODELEN, clTable)) {
                return -EBADMSG;
            }

            lensIdx = 0;
            state = S_DYN_LENS;
            return ST_PROGRESS;
        }

        /* Reads the literal/length and distance code lengths and builds the tables. */
        int32_t stepDynLens(const uint8_t*& in, const uint8_t* end) {
            const uint32_t total = hlit + hdist;
            while (lensIdx < total) {
                while (bc < 14 && in < end) {
                    bb |= uint64_t(*in++) << bc;
                    bc += 8;
                }

                uint32_t e = clTable[peek(CL_BITS)];
                uint32_t n = huff::nbits(e);
                if (huff::kind(e) == huff::K_BAD || n > bc) {
                    return n > bc || bc < CL_BITS ? int32_t(ST_NEED_INPUT) : -EBADMSG;
                }

                uint32_t sym = huff::value(e);
                if (sym < 16) {
                    drop(n);
                    lens[lensIdx++] = uint8_t(sym);
                    continue;
                }

                uint32_t extraBits = sym == 16 ? 2 : (sym == 17 ? 3 : 7);
                if (n + extraBits > bc) {
                    return ST_NEED_INPUT;
                }

                drop(n);
                uint32_t rep = peek(extraBits);
                drop(extraBits);
                uint8_t val = 0;
                if (sym == 16) {
                    if (lensIdx == 0) {
                        return -EBADMSG;
                    }

                    val = lens[lensIdx - 1];
                    rep += 3;
                } else if (sym == 17) {
                    rep += 3;
                } else {
                    rep += 11;
                }

                if (lensIdx + rep > total) {
                    return -EBADMSG;
                }

                std::memset(lens + lensIdx, val, rep);
                lensIdx += rep;
            }

            if (lens[256] == 0) {
                return -EBADMSG;
            }

            if (!huff::buildTable(lens, hlit, LIT_BITS, huff::A_LITLEN, litTable)
                || !huff::buildTable(lens + hlit, hdist, DIST_BITS, huff::A_DIST, distTable)) {
                return -EBADMSG;
            }

            lit = litTable.data();
            dist = distTable.data();
            state = S_HUFF;
            return ST_PROGRESS;
        }

        /* State after a block ended. */
        State endOfBlock() const noexcept {
            if (!lastBlock) {
                return S_BLOCK;
            }

            return active == EDFMT_RAW ? S_DONE : S_TRAILER;
        }

        /* The hot loop: decodes Huffman symbols into the window. */
        int32_t stepHuff(const uint8_t*& inRef, const uint8_t* inEnd) {
            const uint8_t* in = inRef;
            uint64_t b = bb;
            uint32_t c = bc;
            uint8_t* const base = win.data();
            uint8_t* out = base + wpos;
            uint8_t* const outLimit = base + SLIDE_AT;
            const uint8_t* const hist = base + histStart;
            const uint32_t* const lt = lit;
            const uint32_t* const dt = dist;
            int32_t status = ST_PROGRESS;

            for (;;) {
                if (inEnd - in >= 8) {
                    // --> Branch-free refill: bits beyond the counted ones are the next input
                    // bytes, which the following refill ORs in again unchanged.
                    b |= bits::load64(in) << c;
                    in += (63 - c) >> 3;
                    c |= 56;
                } else {
                    while (c <= 56 && in < inEnd) {
                        b |= uint64_t(*in++) << c;
                        c += 8;
                    }
                }

                if (out >= outLimit) {
                    status = ST_PROGRESS;
                    break;
                }

                const uint64_t sb = b;
                const uint32_t sc = c;
                uint32_t e = lt[b & LIT_MASK];
                uint32_t n;
                if (huff::kind(e) == huff::K_SUB) {
                    e = lt[huff::value(e) + ((b >> LIT_BITS) & ((1u << huff::extra(e)) - 1))];
                    n = LIT_BITS + huff::nbits(e);
                } else {
                    n = huff::nbits(e);
                }

                const uint32_t k = huff::kind(e);
                if (k == huff::K_LIT) {
                    if (n > c) {
                        goto needInput;
                    }

                    b >>= n;
                    c -= n;
                    *out++ = uint8_t(huff::value(e));

                    // --> A second literal without refilling when enough bits remain.
                    if (c >= 15 && out < outLimit) {
                        uint32_t e2 = lt[b & LIT_MASK];
                        if (huff::kind(e2) == huff::K_LIT) {
                            uint32_t n2 = huff::nbits(e2);
                            b >>= n2;
                            c -= n2;
                            *out++ = uint8_t(huff::value(e2));
                        }
                    }

                    continue;
                }

                if (k == huff::K_LEN) {
                    uint32_t ex = huff::extra(e);
                    if (n + ex > c) {
                        goto needInput;
                    }

                    b >>= n;
                    c -= n;
                    uint32_t len = huff::value(e) + uint32_t(b & ((uint64_t(1) << ex) - 1));
                    b >>= ex;
                    c -= ex;

                    uint32_t d = dt[b & DIST_MASK];
                    uint32_t dn;
                    if (huff::kind(d) == huff::K_SUB) {
                        d = dt[huff::value(d) + ((b >> DIST_BITS) & ((1u << huff::extra(d)) - 1))];
                        dn = DIST_BITS + huff::nbits(d);
                    } else {
                        dn = huff::nbits(d);
                    }

                    if (huff::kind(d) != huff::K_LEN) {
                        if (c < 15) {
                            goto needInput;
                        }

                        status = -EBADMSG;
                        break;
                    }

                    uint32_t dex = huff::extra(d);
                    if (dn + dex > c) {
                        goto needInput;
                    }

                    b >>= dn;
                    c -= dn;
                    uint32_t distance = huff::value(d) + uint32_t(b & ((uint64_t(1) << dex) - 1));
                    b >>= dex;
                    c -= dex;

                    if (distance > size_t(out - hist)) {
                        status = -EBADMSG;
                        break;
                    }

                    const uint8_t* src = out - distance;
                    if (distance >= 8) {
                        uint8_t* stop = out + len;
                        do {
                            std::memcpy(out, src, 8);
                            out += 8;
                            src += 8;
                        } while (out < stop);

                        out = stop;
                    } else if (distance == 1) {
                        std::memset(out, *src, len);
                        out += len;
                    } else {
                        for (uint32_t i = 0; i < len; ++i) {
                            out[i] = src[i];
                        }

                        out += len;
                    }

                    continue;
                }

                if (k == huff::K_EOB) {
                    if (n > c) {
                        goto needInput;
                    }

                    b >>= n;
                    c -= n;
                    state = endOfBlock();
                    status = ST_PROGRESS;
                    break;
                }

                // --> An invalid code, unless the zero padding of a short buffer made it look so.
                if (c < 15) {
                    goto needInput;
                }

                status = -EBADMSG;
                break;

            needInput:
                b = sb;
                c = sc;
                status = ST_NEED_INPUT;
                break;
            }

            b &= (uint64_t(1) << c) - 1;
            bb = b;
            bc = c;
            inRef = in;
            wpos = size_t(out - base);
            return status;
        }

        /* Reads and checks the zlib or gzip trailer. */
        int32_t stepTrailer(const uint8_t*& in, const uint8_t* end) {
            drop(bc & 7u);
            const uint32_t size = active == EDFMT_GZIP ? 8 : 4;
            while (tpos < size) {
                if (!takeByte(tbuf[tpos], in, end)) {
                    return ST_NEED_INPUT;
                }

                tpos++;
            }

            updateChecksum();
            if (active == EDFMT_ZLIB) {
                uint32_t want = (uint32_t(tbuf[0]) << 24) | (uint32_t(tbuf[1]) << 16) | (uint32_t(tbuf[2]) << 8) | tbuf[3];
                if (want != adler.value()) {
                    return -EBADMSG;
                }

                state = S_DONE;
                return ST_PROGRESS;
            }

            if (bits::load32(tbuf) != crc.value() || bits::load32(tbuf + 4) != memberSize) {
                return -EBADMSG;
            }

            members++;
            state = multiMember ? S_NEXT_MEMBER : S_DONE;
            return ST_PROGRESS;
        }

        /* Runs the state machine until it needs input or the window must be drained. */
        int32_t step(const uint8_t*& in, const uint8_t* end, bool finish) {
            switch (state) {
            case S_HEADER:
                return stepHeader(in, end);
            case S_BLOCK:
                return stepBlock(in, end);
            case S_STORED_LEN:
                return stepStoredLen(in, end);
            case S_STORED:
                return stepStored(in, end);
            case S_DYN_COUNTS:
                return stepDynCounts(in, end);
            case S_DYN_CLENS:
                return stepDynClens(in, end);
            case S_DYN_LENS:
                return stepDynLens(in, end);
            case S_HUFF:
                return stepHuff(in, end);
            case S_TRAILER:
                return stepTrailer(in, end);
            case S_NEXT_MEMBER:
                if (bc == 0 && in == end) {
                    if (finish) {
                        state = S_DONE;
                        return ST_PROGRESS;
                    }

                    return ST_NEED_INPUT;
                }

                updateChecksum();
                startMember();
                return ST_PROGRESS;
            case S_DONE:
            default:
                return ST_PROGRESS;
            }
        }
    };

    /* Creates a decoder. */
    CInflater::CInflater(EDeflateFormat format, bool multiMember)
        : _impl(std::make_unique<SImpl>(format, multiMember)) {}

    /* Destroys the decoder. */
    CInflater::~CInflater() = default;

    /* Starts over. */
    void CInflater::reset() {
        _impl->reset();
    }

    /* Header of the latest gzip member. */
    const SGzipHeader& CInflater::gzipHeader() const noexcept {
        return _impl->gz;
    }

    /* Number of finished gzip members. */
    uint64_t CInflater::members() const noexcept {
        return _impl->members;
    }

    /* Total decompressed bytes. */
    uint64_t CInflater::totalOut() const noexcept {
        return _impl->totalOut;
    }

    /* Decodes as much as input and output allow. */
    int32_t CInflater::process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                               size_t& produced, bool finish) {
        SImpl& s = *_impl;
        consumed = 0;
        produced = 0;
        if (s.error) {
            return s.error;
        }

        const uint8_t* ip = in.data;
        const uint8_t* const ie = in.data + in.size;
        uint8_t* op = out.data;
        size_t oleft = out.size;
        int32_t rc = SBOX_OK;

        for (;;) {
            if (s.flushPos < s.wpos) {
                s.updateChecksum();
                size_t n = s.wpos - s.flushPos;
                if (n > oleft) {
                    n = oleft;
                }

                if (n) {
                    std::memcpy(op, s.win.data() + s.flushPos, n);
                    op += n;
                    oleft -= n;
                    s.flushPos += n;
                }

                if (s.flushPos < s.wpos) {
                    break;
                }
            }

            if (s.state == S_DONE) {
                // --> Hand back whole bytes the bit buffer read past the end of a raw/zlib stream.
                if (s.active != EDFMT_GZIP) {
                    s.drop(s.bc & 7u);
                    size_t back = s.bc / 8;
                    size_t taken = size_t(ip - in.data);
                    if (back > taken) {
                        back = taken;
                    }

                    ip -= back;
                    s.bb = 0;
                    s.bc = 0;
                }

                rc = CODEC_END;
                break;
            }

            if (s.wpos >= SLIDE_AT) {
                s.slide();
            }

            int32_t st = s.step(ip, ie, finish);
            if (st < 0) {
                s.error = st;
                rc = st;
                break;
            }

            if (st == ST_NEED_INPUT) {
                if (s.flushPos < s.wpos) {
                    continue;
                }

                if (finish && ip == ie) {
                    s.error = -ENODATA;
                    rc = -ENODATA;
                }

                break;
            }
        }

        consumed = size_t(ip - in.data);
        produced = out.size - oleft;
        return rc;
    }

}
}
