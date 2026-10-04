#include <sbox/archive/deflate.hpp>
#include <sbox/archive/checksum.hpp>
#include "bits.hpp"
#include "huffman.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>

namespace sbox {
namespace archive {

    namespace {

        constexpr size_t WSIZE = 32768;
        constexpr uint32_t WMASK = WSIZE - 1;
        constexpr uint32_t MAX_DIST = WSIZE;
        constexpr size_t BUF = size_t(1) << 18;
        constexpr size_t BUF_SLACK = 512;           // --> Over-reads of the 8-byte match comparison.
        constexpr size_t KEEP = WSIZE + 512;        // --> History kept in front of strstart on a slide.
        constexpr uint32_t MIN_MATCH = 3;
        constexpr uint32_t MAX_MATCH = 258;
        constexpr size_t MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1;
        constexpr uint32_t HASH_BITS = 15;
        constexpr uint32_t HASH_SIZE = 1u << HASH_BITS;
        constexpr uint32_t TOO_FAR = 4096;
        constexpr size_t SYM_LIMIT = 16383;
        constexpr size_t STORED_MAX = 65535;

        /* Matcher parameters per level (zlib's table). */
        struct LevelConfig {
            uint16_t good;      // --> Shorten the chain search once a match this long exists.
            uint16_t lazy;      // --> Lazy: do not look further after a match this long. Greedy: max insert length.
            uint16_t nice;      // --> Stop searching on a match this long.
            uint16_t chain;     // --> Maximum hash-chain steps.
            bool lazyMode;
        };

        constexpr LevelConfig LEVELS[10] = {
            { 0, 0, 0, 0, false },
            { 4, 4, 8, 4, false },
            { 4, 5, 16, 8, false },
            { 4, 6, 32, 32, false },
            { 4, 4, 16, 16, true },
            { 8, 16, 32, 32, true },
            { 8, 16, 128, 128, true },
            { 8, 32, 128, 256, true },
            { 32, 128, 258, 1024, true },
            { 32, 258, 258, 4096, true },
        };

        /* Length/distance symbol lookup tables. */
        struct CodeTables {
            uint8_t lengthCode[256];    // --> (length - 3) -> length symbol - 257.
            uint8_t distCode[512];      // --> zlib's split table: dist-1 < 256 direct, else 256 + ((dist-1) >> 7).
            uint8_t fixedLitLen[288];
            uint16_t fixedLitCode[288];
            uint16_t fixedDistCode[30];

            CodeTables() {
                for (uint32_t code = 0; code < 28; ++code) {
                    for (uint32_t i = 0; i < (1u << huff::LEN_EXTRA[code]); ++i) {
                        lengthCode[huff::LEN_BASE[code] - 3 + i] = uint8_t(code);
                    }
                }

                lengthCode[255] = 28;

                for (uint32_t code = 0; code < 30; ++code) {
                    uint32_t base = huff::DIST_BASE[code] - 1;
                    for (uint32_t i = 0; i < (1u << huff::DIST_EXTRA[code]); ++i) {
                        uint32_t d = base + i;
                        if (d < 256) {
                            distCode[d] = uint8_t(code);
                        } else {
                            distCode[256 + (d >> 7)] = uint8_t(code);
                        }
                    }
                }

                std::memset(fixedLitLen, 8, 144);
                std::memset(fixedLitLen + 144, 9, 112);
                std::memset(fixedLitLen + 256, 7, 24);
                std::memset(fixedLitLen + 280, 8, 8);
                makeCodes(fixedLitLen, 288, fixedLitCode);

                uint8_t dl[30];
                std::memset(dl, 5, 30);
                makeCodes(dl, 30, fixedDistCode);
            }

            /* Assigns canonical, bit-reversed codes for the given lengths. */
            static void makeCodes(const uint8_t* lens, uint32_t n, uint16_t* codes) {
                uint32_t count[16] = { 0 };
                for (uint32_t i = 0; i < n; ++i) {
                    count[lens[i]]++;
                }

                count[0] = 0;
                uint32_t next[16] = { 0 };
                uint32_t code = 0;
                for (uint32_t len = 1; len <= 15; ++len) {
                    code = (code + count[len - 1]) << 1;
                    next[len] = code;
                }

                for (uint32_t i = 0; i < n; ++i) {
                    codes[i] = lens[i] ? uint16_t(bits::reverse(next[lens[i]]++, lens[i])) : 0;
                }
            }
        };

        /* Returns the shared lookup tables. */
        const CodeTables& codeTables() {
            static const CodeTables tables;
            return tables;
        }

        /* Distance symbol of a distance (1..32768). */
        inline uint32_t distSymbol(const CodeTables& t, uint32_t dist) noexcept {
            uint32_t d = dist - 1;
            return d < 256 ? t.distCode[d] : t.distCode[256 + (d >> 7)];
        }

        /*
         * Computes Huffman code lengths limited to `maxBits` for `freq[0..n)`.
         * Unused symbols get length 0; at least two symbols get a code when any is used.
         */
        void buildLengths(const uint32_t* freq, uint32_t n, uint32_t maxBits, uint8_t* lens) {
            std::memset(lens, 0, n);
            struct Leaf {
                uint32_t freq;
                uint16_t sym;
            };

            Leaf leaves[320];
            uint32_t count = 0;
            for (uint32_t i = 0; i < n; ++i) {
                if (freq[i]) {
                    leaves[count++] = Leaf{ freq[i], uint16_t(i) };
                }
            }

            if (count == 0) {
                return;
            }

            if (count == 1) {
                // --> A lone code still needs one bit, and decoders want a complete code: add a twin.
                lens[leaves[0].sym] = 1;
                lens[leaves[0].sym == 0 ? 1 : 0] = 1;
                return;
            }

            std::sort(leaves, leaves + count, [](const Leaf& a, const Leaf& b) {
                return a.freq != b.freq ? a.freq < b.freq : a.sym < b.sym;
            });

            // --> Two-queue Huffman construction: leaves in ascending order, internal nodes are
            // created in non-decreasing weight order, so both queues stay sorted.
            uint64_t weight[640];
            int32_t parent[640];
            for (uint32_t i = 0; i < count; ++i) {
                weight[i] = leaves[i].freq;
            }

            uint32_t leafPos = 0;
            uint32_t nodePos = count;
            uint32_t nodeEnd = count;
            auto takeMin = [&]() -> uint32_t {
                if (leafPos < count && (nodePos >= nodeEnd || weight[leafPos] <= weight[nodePos])) {
                    return leafPos++;
                }

                return nodePos++;
            };

            for (uint32_t k = 0; k + 1 < count; ++k) {
                uint32_t a = takeMin();
                uint32_t b = takeMin();
                weight[nodeEnd] = weight[a] + weight[b];
                parent[a] = int32_t(nodeEnd);
                parent[b] = int32_t(nodeEnd);
                nodeEnd++;
            }

            uint32_t root = nodeEnd - 1;
            uint32_t depth[640];
            depth[root] = 0;
            for (uint32_t i = root; i-- > 0;) {
                depth[i] = depth[parent[i]] + 1;
            }

            // --> zlib's length limiting: every node (leaf or internal) below maxBits counts as
            // overflow; the subtrees hanging off depth maxBits each have k leaves and 2k - 2 such
            // nodes, so overflow is even and each fix step below removes exactly one unit of Kraft
            // excess, leaving a complete code.
            uint32_t blCount[64] = { 0 };
            int32_t overflow = 0;
            for (uint32_t i = 0; i < root; ++i) {
                if (depth[i] > maxBits) {
                    overflow++;
                }
            }

            for (uint32_t i = 0; i < count; ++i) {
                blCount[depth[i] > maxBits ? maxBits : depth[i]]++;
            }

            while (overflow > 0) {
                uint32_t b = maxBits - 1;
                while (blCount[b] == 0) {
                    b--;
                }

                blCount[b]--;
                blCount[b + 1] += 2;
                blCount[maxBits]--;
                overflow -= 2;
            }

            // --> Longest codes to the least frequent symbols.
            uint32_t idx = 0;
            for (uint32_t b = maxBits; b >= 1; --b) {
                for (uint32_t k = 0; k < blCount[b]; ++k) {
                    lens[leaves[idx++].sym] = uint8_t(b);
                }
            }
        }

    }

    struct CDeflater::SImpl {
        EDeflateFormat format;
        int32_t level;
        LevelConfig cfg;
        const CodeTables& tabs;

        std::vector<uint8_t> buf;
        size_t strstart = 0;
        size_t lookahead = 0;
        uint32_t bufBase = 0;           // --> Global position (mod 2^32) of buf[0].
        uint32_t blockStartG = 0;       // --> Global position where the current block's input starts.
        std::vector<uint32_t> head;
        std::vector<uint32_t> prev;

        ptrdiff_t matchStart = 0;
        ptrdiff_t prevMatch = 0;
        uint32_t matchLength = MIN_MATCH - 1;
        uint32_t prevLength = MIN_MATCH - 1;
        bool matchAvailable = false;

        std::vector<uint32_t> syms;     // --> (distance << 9) | (literal or length - 3); distance 0 = literal.
        uint32_t litFreq[286];
        uint32_t distFreq[30];

        uint64_t bitBuf = 0;
        uint32_t bitCount = 0;
        std::vector<uint8_t> pending;
        size_t pendingPos = 0;

        bool headerDone = false;
        bool finished = false;          // --> Final block and trailer are in `pending`.
        CCrc32 crc;
        CAdler32 adler;
        uint32_t inSize = 0;

        std::string gzName;
        uint32_t gzMtime = 0;

        const uint8_t* ip = nullptr;
        const uint8_t* ie = nullptr;

        /* Configures the encoder. */
        SImpl(EDeflateFormat fmt, int32_t lvl) : format(fmt == EDFMT_AUTO ? EDFMT_GZIP : fmt), tabs(codeTables()) {
            if (lvl < 0 || lvl > 9) {
                lvl = 6;
            }

            level = lvl;
            cfg = LEVELS[lvl];
            buf.resize(BUF + BUF_SLACK);
            if (level > 0) {
                head.resize(HASH_SIZE);
                prev.resize(WSIZE);
                syms.reserve(SYM_LIMIT + 1);
            }

            reset();
        }

        /* Starts a new stream. */
        void reset() noexcept {
            strstart = 0;
            lookahead = 0;
            bufBase = 0;
            blockStartG = 0;
            std::fill(head.begin(), head.end(), 0u);
            std::fill(prev.begin(), prev.end(), 0u);
            matchStart = prevMatch = 0;
            matchLength = prevLength = MIN_MATCH - 1;
            matchAvailable = false;
            syms.clear();
            std::memset(litFreq, 0, sizeof(litFreq));
            std::memset(distFreq, 0, sizeof(distFreq));
            bitBuf = 0;
            bitCount = 0;
            pending.clear();
            pendingPos = 0;
            headerDone = false;
            finished = false;
            crc.reset();
            adler.reset();
            inSize = 0;
        }

        /* Appends up to 32 bits LSB-first. */
        inline void putBits(uint32_t value, uint32_t n) {
            bitBuf |= uint64_t(value) << bitCount;
            bitCount += n;
            if (bitCount >= 32) {
                uint8_t b[4];
                bits::store32(b, uint32_t(bitBuf));
                pending.insert(pending.end(), b, b + 4);
                bitBuf >>= 32;
                bitCount -= 32;
            }
        }

        /* Pads to a byte boundary and moves the bit buffer into `pending`. */
        void alignBits() {
            while (bitCount > 0) {
                pending.push_back(uint8_t(bitBuf));
                bitBuf >>= 8;
                bitCount = bitCount >= 8 ? bitCount - 8 : 0;
            }

            bitBuf = 0;
        }

        /* Appends raw bytes (the bit buffer must be aligned and empty). */
        void putBytes(const uint8_t* p, size_t n) {
            pending.insert(pending.end(), p, p + n);
        }

        /* Writes the zlib or gzip header. */
        void writeHeader() {
            if (format == EDFMT_ZLIB) {
                // --> CINFO 7 (32 KiB window), CM 8; FLEVEL reflects the level; FCHECK makes it % 31 == 0.
                uint32_t flevel = level < 2 ? 0 : (level < 6 ? 1 : (level == 6 ? 2 : 3));
                uint32_t hdr = (0x78u << 8) | (flevel << 6);
                hdr += 31 - (hdr % 31);
                uint8_t b[2] = { uint8_t(hdr >> 8), uint8_t(hdr) };
                putBytes(b, 2);
            } else if (format == EDFMT_GZIP) {
                uint8_t b[10] = { 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3 };
                if (!gzName.empty()) {
                    b[3] = 0x08;
                }

                bits::store32(b + 4, gzMtime);
                b[8] = level == 9 ? 2 : (level == 1 ? 4 : 0);
                putBytes(b, 10);
                if (!gzName.empty()) {
                    putBytes(reinterpret_cast<const uint8_t*>(gzName.data()), gzName.size());
                    pending.push_back(0);
                }
            }

            headerDone = true;
        }

        /* Writes the zlib or gzip trailer. */
        void writeTrailer() {
            alignBits();
            if (format == EDFMT_ZLIB) {
                uint32_t a = adler.value();
                uint8_t b[4] = { uint8_t(a >> 24), uint8_t(a >> 16), uint8_t(a >> 8), uint8_t(a) };
                putBytes(b, 4);
            } else if (format == EDFMT_GZIP) {
                uint8_t b[8];
                bits::store32(b, crc.value());
                bits::store32(b + 4, inSize);
                putBytes(b, 8);
            }
        }

        /* Copies input into the window, sliding it when the end is near. */
        void fill() {
            if (BUF - (strstart + lookahead) < 4096 && strstart > KEEP) {
                size_t shift = strstart - KEEP;
                std::memmove(buf.data(), buf.data() + shift, KEEP + lookahead);
                bufBase += uint32_t(shift);
                strstart -= shift;
                matchStart -= ptrdiff_t(shift);
                prevMatch -= ptrdiff_t(shift);
            }

            size_t room = BUF - (strstart + lookahead);
            size_t n = size_t(ie - ip);
            if (n > room) {
                n = room;
            }

            if (n == 0) {
                return;
            }

            uint8_t* dst = buf.data() + strstart + lookahead;
            std::memcpy(dst, ip, n);
            SReadOnlyByteSpan span(dst, n);
            if (format == EDFMT_GZIP) {
                crc.update(span);
            } else if (format == EDFMT_ZLIB) {
                adler.update(span);
            }

            inSize += uint32_t(n);
            ip += n;
            lookahead += n;
        }

        /* Hash of the 3 bytes at `p`. */
        static inline uint32_t hash3(const uint8_t* p) noexcept {
            uint32_t v = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16);
            return (v * 0x9E3779B1u) >> (32 - HASH_BITS);
        }

        /* Inserts position `idx` into the hash chains; returns the previous chain head. */
        inline uint32_t insert(size_t idx) noexcept {
            uint32_t g = bufBase + uint32_t(idx);
            uint32_t h = hash3(buf.data() + idx);
            uint32_t cand = head[h];
            prev[g & WMASK] = cand;
            head[h] = g;
            return cand;
        }

        /* Length of the common prefix of `a` and `b`, at most `limit`. */
        static inline uint32_t commonLength(const uint8_t* a, const uint8_t* b, uint32_t limit) noexcept {
            uint32_t len = 0;
            while (len < limit) {
                uint64_t x = bits::load64(a + len) ^ bits::load64(b + len);
                if (x) {
                    len += uint32_t(__builtin_ctzll(x)) >> 3;
                    return len < limit ? len : limit;
                }

                len += 8;
            }

            return limit;
        }

        /* Follows the hash chain from `candG`; returns the best length found (> best to count). */
        uint32_t longestMatch(uint32_t candG, uint32_t best) {
            uint32_t chain = cfg.chain;
            if (best >= cfg.good) {
                chain >>= 2;
            }

            uint32_t limit = lookahead < MAX_MATCH ? uint32_t(lookahead) : MAX_MATCH;
            uint32_t nice = cfg.nice < limit ? cfg.nice : limit;
            const uint8_t* cur = buf.data() + strstart;
            const uint32_t curG = bufBase + uint32_t(strstart);
            uint32_t lastDist = 0;
            if (best >= limit) {
                return best;
            }

            while (chain-- > 0) {
                uint32_t dist = curG - candG;
                // --> Distances must grow along the chain; anything else is a stale entry.
                if (dist == 0 || dist > MAX_DIST || dist > strstart || dist <= lastDist) {
                    break;
                }

                lastDist = dist;
                const uint8_t* m = cur - dist;
                if (m[best] == cur[best] && m[0] == cur[0] && m[1] == cur[1]) {
                    uint32_t len = commonLength(m, cur, limit);
                    if (len > best) {
                        best = len;
                        matchStart = ptrdiff_t(strstart) - ptrdiff_t(dist);
                        if (len >= nice) {
                            break;
                        }
                    }
                }

                candG = prev[candG & WMASK];
            }

            return best;
        }

        /* Records a literal; true when the symbol buffer is full. */
        inline bool tallyLit(uint8_t c) {
            syms.push_back(c);
            litFreq[c]++;
            return syms.size() >= SYM_LIMIT;
        }

        /* Records a match; true when the symbol buffer is full. */
        inline bool tallyMatch(uint32_t dist, uint32_t len) {
            syms.push_back((dist << 9) | (len - MIN_MATCH));
            litFreq[257 + tabs.lengthCode[len - MIN_MATCH]]++;
            distFreq[distSymbol(tabs, dist)]++;
            return syms.size() >= SYM_LIMIT;
        }

        /* Writes the symbols with the given codes. */
        void writeSymbols(const uint8_t* litLen, const uint16_t* litCode, const uint8_t* distLen, const uint16_t* distCode) {
            for (uint32_t s : syms) {
                uint32_t dist = s >> 9;
                if (dist == 0) {
                    putBits(litCode[s & 0xFFu], litLen[s & 0xFFu]);
                    continue;
                }

                uint32_t lc = tabs.lengthCode[s & 0xFFu];
                uint32_t sym = 257 + lc;
                putBits(litCode[sym], litLen[sym]);
                if (huff::LEN_EXTRA[lc]) {
                    putBits((s & 0xFFu) + MIN_MATCH - huff::LEN_BASE[lc], huff::LEN_EXTRA[lc]);
                }

                uint32_t dc = distSymbol(tabs, dist);
                putBits(distCode[dc], distLen[dc]);
                if (huff::DIST_EXTRA[dc]) {
                    putBits(dist - huff::DIST_BASE[dc], huff::DIST_EXTRA[dc]);
                }
            }

            putBits(litCode[256], litLen[256]);
        }

        /* Writes `len` stored bytes as one or more stored blocks. */
        void writeStored(const uint8_t* data, size_t len, bool last) {
            do {
                size_t n = len < STORED_MAX ? len : STORED_MAX;
                len -= n;
                putBits((last && len == 0) ? 1u : 0u, 3);
                alignBits();
                uint8_t h[4];
                bits::store16(h, uint16_t(n));
                bits::store16(h + 2, uint16_t(~n));
                putBytes(h, 4);
                putBytes(data, n);
                data += n;
            } while (len > 0);
        }

        /* Emits the collected symbols as the cheapest of stored, fixed and dynamic. */
        void flushBlock(bool last) {
            const uint32_t curG = bufBase + uint32_t(strstart);
            const uint32_t rawLen = curG - blockStartG;
            // --> Stored is only possible while the block's raw bytes are still in the buffer.
            const bool storedOk = uint32_t(curG - bufBase) >= rawLen;

            litFreq[256] = 1;
            uint8_t litLen[286];
            uint8_t distLen[30];
            buildLengths(litFreq, 286, 15, litLen);
            buildLengths(distFreq, 30, 15, distLen);

            uint32_t hlit = 286;
            while (hlit > 257 && litLen[hlit - 1] == 0) {
                hlit--;
            }

            uint32_t hdist = 30;
            while (hdist > 1 && distLen[hdist - 1] == 0) {
                hdist--;
            }

            // --> Run-length code the concatenated code lengths (symbols 16/17/18).
            uint8_t all[316];
            std::memcpy(all, litLen, hlit);
            std::memcpy(all + hlit, distLen, hdist);
            const uint32_t total = hlit + hdist;
            uint16_t rle[316];
            uint32_t rleCount = 0;
            uint32_t clFreq[19] = { 0 };
            for (uint32_t i = 0; i < total;) {
                uint8_t v = all[i];
                uint32_t run = 1;
                while (i + run < total && all[i + run] == v) {
                    run++;
                }

                i += run;
                if (v == 0) {
                    while (run >= 11) {
                        uint32_t r = run > 138 ? 138 : run;
                        rle[rleCount++] = uint16_t(18 | ((r - 11) << 5));
                        clFreq[18]++;
                        run -= r;
                    }

                    if (run >= 3) {
                        rle[rleCount++] = uint16_t(17 | ((run - 3) << 5));
                        clFreq[17]++;
                        run = 0;
                    }
                } else {
                    rle[rleCount++] = v;
                    clFreq[v]++;
                    run--;
                    while (run >= 3) {
                        uint32_t r = run > 6 ? 6 : run;
                        rle[rleCount++] = uint16_t(16 | ((r - 3) << 5));
                        clFreq[16]++;
                        run -= r;
                    }
                }

                while (run > 0) {
                    rle[rleCount++] = v;
                    clFreq[v]++;
                    run--;
                }
            }

            uint8_t clLen[19];
            buildLengths(clFreq, 19, 7, clLen);
            uint32_t hclen = 19;
            while (hclen > 4 && clLen[huff::CODELEN_ORDER[hclen - 1]] == 0) {
                hclen--;
            }

            uint64_t extraBits = 0;
            for (uint32_t i = 0; i < 29; ++i) {
                extraBits += uint64_t(litFreq[257 + i]) * huff::LEN_EXTRA[i];
            }

            for (uint32_t i = 0; i < 30; ++i) {
                extraBits += uint64_t(distFreq[i]) * huff::DIST_EXTRA[i];
            }

            uint64_t dynBits = 3 + 14 + 3 * uint64_t(hclen) + extraBits;
            uint64_t fixBits = 3 + extraBits;
            for (uint32_t i = 0; i < 286; ++i) {
                dynBits += uint64_t(litFreq[i]) * litLen[i];
                fixBits += uint64_t(litFreq[i]) * tabs.fixedLitLen[i];
            }

            for (uint32_t i = 0; i < 30; ++i) {
                dynBits += uint64_t(distFreq[i]) * distLen[i];
                fixBits += uint64_t(distFreq[i]) * 5;
            }

            for (uint32_t i = 0; i < 19; ++i) {
                dynBits += uint64_t(clFreq[i]) * clLen[i];
            }

            dynBits += uint64_t(clFreq[16]) * 2 + uint64_t(clFreq[17]) * 3 + uint64_t(clFreq[18]) * 7;

            uint64_t storedBits = ~uint64_t(0);
            if (storedOk) {
                uint64_t chunks = rawLen / STORED_MAX + 1;
                storedBits = uint64_t(rawLen) * 8 + chunks * (3 + 7 + 32);
            }

            if (storedBits <= fixBits && storedBits <= dynBits) {
                writeStored(buf.data() + (curG - bufBase - rawLen), rawLen, last);
            } else if (fixBits <= dynBits) {
                putBits(last ? 3u : 2u, 3);
                uint8_t fdl[30];
                std::memset(fdl, 5, 30);
                writeSymbols(tabs.fixedLitLen, tabs.fixedLitCode, fdl, tabs.fixedDistCode);
            } else {
                uint16_t litCode[286];
                uint16_t distCodeArr[30];
                uint16_t clCode[19];
                CodeTables::makeCodes(litLen, 286, litCode);
                CodeTables::makeCodes(distLen, 30, distCodeArr);
                CodeTables::makeCodes(clLen, 19, clCode);

                putBits(last ? 5u : 4u, 3);
                putBits(hlit - 257, 5);
                putBits(hdist - 1, 5);
                putBits(hclen - 4, 4);
                for (uint32_t i = 0; i < hclen; ++i) {
                    putBits(clLen[huff::CODELEN_ORDER[i]], 3);
                }

                for (uint32_t i = 0; i < rleCount; ++i) {
                    uint32_t sym = rle[i] & 31u;
                    putBits(clCode[sym], clLen[sym]);
                    if (sym == 16) {
                        putBits(rle[i] >> 5, 2);
                    } else if (sym == 17) {
                        putBits(rle[i] >> 5, 3);
                    } else if (sym == 18) {
                        putBits(rle[i] >> 5, 7);
                    }
                }

                writeSymbols(litLen, litCode, distLen, distCodeArr);
            }

            syms.clear();
            std::memset(litFreq, 0, sizeof(litFreq));
            std::memset(distFreq, 0, sizeof(distFreq));
            blockStartG = curG;
        }

        /*
         * Greedy matcher (levels 1-3). Returns true when a block was emitted (so `pending`
         * should be drained before continuing), false when more input is needed or done.
         */
        bool runGreedy(bool finish) {
            for (;;) {
                if (lookahead < MIN_LOOKAHEAD) {
                    fill();
                    if (lookahead < MIN_LOOKAHEAD && !finish) {
                        return false;
                    }

                    if (lookahead == 0) {
                        return false;
                    }
                }

                uint32_t len = 0;
                if (lookahead >= MIN_MATCH) {
                    uint32_t cand = insert(strstart);
                    len = longestMatch(cand, MIN_MATCH - 1);
                    if (len < MIN_MATCH) {
                        len = 0;
                    }
                }

                bool full;
                if (len) {
                    full = tallyMatch(uint32_t(ptrdiff_t(strstart) - matchStart), len);
                    lookahead -= len;
                    if (len <= cfg.lazy && lookahead >= MIN_MATCH) {
                        for (uint32_t i = 1; i < len; ++i) {
                            insert(strstart + i);
                        }
                    }

                    strstart += len;
                } else {
                    full = tallyLit(buf[strstart]);
                    lookahead--;
                    strstart++;
                }

                if (full) {
                    flushBlock(false);
                    return true;
                }
            }
        }

        /* Lazy matcher (levels 4-9); same contract as runGreedy. */
        bool runLazy(bool finish) {
            for (;;) {
                if (lookahead < MIN_LOOKAHEAD) {
                    fill();
                    if (lookahead < MIN_LOOKAHEAD && !finish) {
                        return false;
                    }

                    if (lookahead == 0) {
                        break;
                    }
                }

                uint32_t cand = 0;
                bool haveCand = false;
                if (lookahead >= MIN_MATCH) {
                    cand = insert(strstart);
                    haveCand = true;
                }

                prevLength = matchLength;
                prevMatch = matchStart;
                matchLength = MIN_MATCH - 1;
                if (haveCand && prevLength < cfg.lazy) {
                    matchLength = longestMatch(cand, prevLength);
                    if (matchLength <= prevLength) {
                        matchLength = MIN_MATCH - 1;
                        matchStart = prevMatch;
                    } else if (matchLength == MIN_MATCH && ptrdiff_t(strstart) - matchStart > ptrdiff_t(TOO_FAR)) {
                        matchLength = MIN_MATCH - 1;
                    }
                }

                if (prevLength >= MIN_MATCH && matchLength <= prevLength) {
                    size_t maxInsert = strstart + lookahead - MIN_MATCH;
                    bool full = tallyMatch(uint32_t(ptrdiff_t(strstart) - 1 - prevMatch), prevLength);
                    lookahead -= prevLength - 1;
                    uint32_t n = prevLength - 2;
                    do {
                        if (++strstart <= maxInsert) {
                            insert(strstart);
                        }
                    } while (--n != 0);

                    matchAvailable = false;
                    matchLength = MIN_MATCH - 1;
                    strstart++;
                    if (full) {
                        flushBlock(false);
                        return true;
                    }
                } else if (matchAvailable) {
                    bool full = tallyLit(buf[strstart - 1]);
                    strstart++;
                    lookahead--;
                    if (full) {
                        // --> The block ends before the byte that is now pending.
                        strstart--;
                        flushBlock(false);
                        strstart++;
                        return true;
                    }
                } else {
                    matchAvailable = true;
                    strstart++;
                    lookahead--;
                }
            }

            if (matchAvailable) {
                tallyLit(buf[strstart - 1]);
                matchAvailable = false;
            }

            return false;
        }

        /* Level 0: buffers input and writes stored blocks. Returns true when a block was emitted. */
        bool runStored(bool finish) {
            for (;;) {
                size_t room = STORED_MAX - lookahead;
                size_t n = size_t(ie - ip);
                if (n > room) {
                    n = room;
                }

                if (n) {
                    SReadOnlyByteSpan span(ip, n);
                    if (format == EDFMT_GZIP) {
                        crc.update(span);
                    } else if (format == EDFMT_ZLIB) {
                        adler.update(span);
                    }

                    std::memcpy(buf.data() + lookahead, ip, n);
                    inSize += uint32_t(n);
                    ip += n;
                    lookahead += n;
                }

                if (lookahead == STORED_MAX && (ip < ie || !finish)) {
                    writeStored(buf.data(), lookahead, false);
                    lookahead = 0;
                    return true;
                }

                return false;
            }
        }
    };

    /* Creates an encoder. */
    CDeflater::CDeflater(EDeflateFormat format, int32_t level)
        : _impl(std::make_unique<SImpl>(format, level)) {}

    /* Destroys the encoder. */
    CDeflater::~CDeflater() = default;

    /* Starts a new stream. */
    void CDeflater::reset() {
        _impl->reset();
    }

    /* Sets the gzip FNAME and MTIME fields. */
    void CDeflater::gzipHeader(std::string_view name, uint32_t mtime) noexcept {
        if (!_impl->headerDone) {
            _impl->gzName.assign(name.data(), name.size());
            _impl->gzMtime = mtime;
        }
    }

    /* Compresses as much as input and output allow. */
    int32_t CDeflater::process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
                               size_t& produced, bool finish) {
        SImpl& s = *_impl;
        s.ip = in.data;
        s.ie = in.data + in.size;
        uint8_t* op = out.data;
        size_t oleft = out.size;
        int32_t rc = SBOX_OK;

        if (!s.headerDone) {
            s.writeHeader();
        }

        for (;;) {
            size_t avail = s.pending.size() - s.pendingPos;
            if (avail) {
                size_t n = avail < oleft ? avail : oleft;
                std::memcpy(op, s.pending.data() + s.pendingPos, n);
                op += n;
                oleft -= n;
                s.pendingPos += n;
                if (s.pendingPos < s.pending.size()) {
                    break;
                }
            }

            s.pending.clear();
            s.pendingPos = 0;
            if (s.finished) {
                rc = CODEC_END;
                break;
            }

            bool emitted;
            if (s.level == 0) {
                emitted = s.runStored(finish);
            } else if (s.cfg.lazyMode) {
                emitted = s.runLazy(finish);
            } else {
                emitted = s.runGreedy(finish);
            }

            if (emitted) {
                continue;
            }

            bool lastInput = finish && s.ip == s.ie;
            if (!lastInput) {
                // --> Either more input is needed, or the window is full and was not processed yet.
                if (s.ip == s.ie) {
                    break;
                }

                continue;
            }

            if (s.level == 0) {
                s.writeStored(s.buf.data(), s.lookahead, true);
                s.lookahead = 0;
            } else {
                s.flushBlock(true);
            }

            s.writeTrailer();
            s.alignBits();
            s.finished = true;
        }

        consumed = size_t(s.ip - in.data);
        produced = out.size - oleft;
        s.ip = s.ie = nullptr;
        return rc;
    }

}
}
