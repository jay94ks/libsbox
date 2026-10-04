#include <sbox/archive/zstd.hpp>
#include <sbox/archive/checksum.hpp>
#include "bits.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace archive {

    namespace {

        constexpr uint32_t ZSTD_MAGIC = 0xFD2FB528u;
        constexpr uint32_t SKIPPABLE_MASK = 0xFFFFFFF0u;
        constexpr uint32_t SKIPPABLE_MAGIC = 0x184D2A50u;
        constexpr size_t BLOCK_MAX = size_t(128) << 10;
        constexpr size_t MARGIN = 64;               // --> Separates wild-copy overruns from needed history.
        constexpr size_t SLACK = 64;                // --> Writable bytes past every buffer end.
        constexpr uint64_t HARD_WINDOW_LIMIT = uint64_t(2) << 30;

        constexpr uint32_t HUF_MAX_BITS = 11;
        constexpr uint32_t LL_MAX = 35;
        constexpr uint32_t ML_MAX = 52;
        constexpr uint32_t OF_MAX = 31;
        constexpr uint32_t LL_MAX_LOG = 9;
        constexpr uint32_t ML_MAX_LOG = 9;
        constexpr uint32_t OF_MAX_LOG = 8;

        constexpr uint32_t LL_BASE[36] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                           16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512,
                                           1024, 2048, 4096, 8192, 16384, 32768, 65536 };
        constexpr uint8_t LL_BITS[36] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
                                          13, 14, 15, 16 };
        constexpr uint32_t ML_BASE[53] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                                           19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
                                           35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
                                           1027, 2051, 4099, 8195, 16387, 32771, 65539 };
        constexpr uint8_t ML_BITS[53] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
                                          12, 13, 14, 15, 16 };

        constexpr int16_t LL_DEFAULT[36] = { 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
                                             2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
                                             -1, -1, -1, -1 };
        constexpr int16_t ML_DEFAULT[53] = { 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
                                             -1, -1, -1, -1, -1 };
        constexpr int16_t OF_DEFAULT[29] = { 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };

        /* Status of the backward bit reader after a reload. */
        enum Reload { R_UNFINISHED = 0, R_END_OF_BUFFER, R_COMPLETED, R_OVERFLOW };

        /*
         * Reads a zstd backward bitstream: bits are taken from the end of the buffer towards its
         * start, most significant first, after the padding marker in the last byte.
         */
        struct BackBits {
            const uint8_t* start = nullptr;
            const uint8_t* ptr = nullptr;
            uint64_t container = 0;
            uint32_t consumed = 0;

            /* Positions the reader on `src[0..size)`; false for an empty stream or a missing marker. */
            bool init(const uint8_t* src, size_t size) noexcept {
                if (size == 0 || src[size - 1] == 0) {
                    return false;
                }

                start = src;
                uint32_t hb = bits::highBit(src[size - 1]);
                if (size >= 8) {
                    ptr = src + size - 8;
                    container = bits::load64(ptr);
                    consumed = 8 - hb;
                } else {
                    ptr = src;
                    container = 0;
                    for (size_t i = 0; i < size; ++i) {
                        container |= uint64_t(src[i]) << (8 * i);
                    }

                    consumed = 8 - hb + uint32_t(8 - size) * 8;
                }

                return true;
            }

            /* Peeks `n` (1..57) bits; zeros past the start of the stream. */
            inline uint64_t look(uint32_t n) const noexcept {
                if (consumed >= 64) {
                    return 0;
                }

                return (container << consumed) >> (64 - n);
            }

            /* Reads `n` (0..57) bits. */
            inline uint64_t read(uint32_t n) noexcept {
                if (n == 0) {
                    return 0;
                }

                uint64_t v = look(n);
                consumed += n;
                return v;
            }

            /* Refills the container from earlier bytes. */
            inline Reload reload() noexcept {
                if (consumed > 64) {
                    return R_OVERFLOW;
                }

                if (ptr >= start + 8) {
                    ptr -= consumed >> 3;
                    consumed &= 7;
                    container = bits::load64(ptr);
                    return R_UNFINISHED;
                }

                if (ptr == start) {
                    return consumed < 64 ? R_END_OF_BUFFER : R_COMPLETED;
                }

                uint32_t nbBytes = consumed >> 3;
                Reload result = R_UNFINISHED;
                if (ptr - nbBytes < start) {
                    nbBytes = uint32_t(ptr - start);
                    result = R_END_OF_BUFFER;
                }

                ptr -= nbBytes;
                consumed -= nbBytes * 8;
                container = bits::load64(ptr);
                return result;
            }

            /* True when every bit was consumed exactly. */
            inline bool finished() const noexcept {
                return ptr == start && consumed == 64;
            }
        };

        /* Little-endian forward bit reader for FSE table descriptions. */
        struct FwdBits {
            const uint8_t* src;
            size_t size;
            size_t pos = 0;     // --> In bits.

            /* Peeks 32 bits at the current position (zeros past the end). */
            uint32_t peek32() const noexcept {
                size_t byte = pos >> 3;
                uint64_t v = 0;
                if (byte + 8 <= size) {
                    v = bits::load64(src + byte);
                } else {
                    for (size_t i = 0; i < 8 && byte + i < size; ++i) {
                        v |= uint64_t(src[byte + i]) << (8 * i);
                    }
                }

                return uint32_t(v >> (pos & 7));
            }
        };

        /*
         * Reads an FSE normalized-count description (RFC 8878 4.1.1).
         * Returns the number of bytes used, or a negated errno.
         */
        int32_t readNCount(const uint8_t* src, size_t size, int16_t* norm, uint32_t& maxSymbol, uint32_t& tableLog, uint32_t maxLog) {
            if (size < 1) {
                return -EBADMSG;
            }

            FwdBits fb{ src, size };
            uint32_t v = fb.peek32();
            tableLog = (v & 0xFu) + 5;
            if (tableLog > maxLog) {
                return -EBADMSG;
            }

            fb.pos += 4;
            int32_t remaining = (1 << tableLog) + 1;
            int32_t threshold = 1 << tableLog;
            uint32_t nbBits = tableLog + 1;
            uint32_t symbol = 0;
            bool previous0 = false;
            const uint32_t limit = maxSymbol;

            while (remaining > 1 && symbol <= limit) {
                if (previous0) {
                    uint32_t n0 = symbol;
                    for (;;) {
                        v = fb.peek32();
                        if ((v & 0xFFFFu) == 0xFFFFu) {
                            n0 += 24;
                            fb.pos += 16;
                            if (fb.pos > size * 8) {
                                return -EBADMSG;
                            }

                            continue;
                        }

                        break;
                    }

                    while ((v & 3u) == 3u) {
                        n0 += 3;
                        v >>= 2;
                        fb.pos += 2;
                    }

                    n0 += v & 3u;
                    fb.pos += 2;
                    if (n0 > limit + 1) {
                        return -EBADMSG;
                    }

                    while (symbol < n0) {
                        norm[symbol++] = 0;
                    }

                    if (symbol > limit) {
                        break;
                    }
                }

                v = fb.peek32();
                int32_t max = (2 * threshold - 1) - remaining;
                int32_t count;
                if (int32_t(v & uint32_t(threshold - 1)) < max) {
                    count = int32_t(v & uint32_t(threshold - 1));
                    fb.pos += nbBits - 1;
                } else {
                    count = int32_t(v & uint32_t(2 * threshold - 1));
                    if (count >= threshold) {
                        count -= max;
                    }

                    fb.pos += nbBits;
                }

                count--;
                remaining -= count < 0 ? -count : count;
                norm[symbol++] = int16_t(count);
                previous0 = count == 0;
                while (remaining < threshold) {
                    nbBits--;
                    threshold >>= 1;
                }

                if (fb.pos > size * 8) {
                    return -EBADMSG;
                }
            }

            if (remaining != 1 || symbol > limit + 1) {
                return -EBADMSG;
            }

            maxSymbol = symbol - 1;
            size_t used = (fb.pos + 7) >> 3;
            if (used > size) {
                return -EBADMSG;
            }

            return int32_t(used);
        }

        /* One state of an FSE decoding table. */
        struct FseCell {
            uint16_t next;      // --> Baseline of the next state.
            uint8_t nbBits;
            uint8_t symbol;
        };

        /* Builds the FSE decoding table (RFC 8878 4.1.1) for normalized counts. */
        bool buildFse(const int16_t* norm, uint32_t maxSymbol, uint32_t tableLog, FseCell* table) {
            const uint32_t size = 1u << tableLog;
            uint32_t high = size - 1;
            uint16_t symbolNext[256];
            for (uint32_t s = 0; s <= maxSymbol; ++s) {
                if (norm[s] == -1) {
                    table[high--].symbol = uint8_t(s);
                    symbolNext[s] = 1;
                } else {
                    symbolNext[s] = uint16_t(norm[s] < 0 ? 0 : norm[s]);
                }
            }

            const uint32_t step = (size >> 1) + (size >> 3) + 3;
            const uint32_t mask = size - 1;
            uint32_t position = 0;
            for (uint32_t s = 0; s <= maxSymbol; ++s) {
                for (int32_t i = 0; i < norm[s]; ++i) {
                    table[position].symbol = uint8_t(s);
                    do {
                        position = (position + step) & mask;
                    } while (position > high);
                }
            }

            if (position != 0) {
                return false;
            }

            for (uint32_t u = 0; u < size; ++u) {
                uint32_t s = table[u].symbol;
                uint32_t nextState = symbolNext[s]++;
                if (nextState == 0) {
                    return false;
                }

                uint32_t nb = tableLog - bits::highBit(nextState);
                table[u].nbBits = uint8_t(nb);
                table[u].next = uint16_t((nextState << nb) - size);
            }

            return true;
        }

        /* One state of a sequence decoding table, with the symbol's baseline and extra bits. */
        struct SeqCell {
            uint32_t base;
            uint16_t next;
            uint8_t nbBits;
            uint8_t extra;
        };

        /* Which sequence field a table decodes. */
        enum SeqKind { SK_LL = 0, SK_OF, SK_ML };

        /* A sequence decoding table. */
        struct SeqTable {
            SeqCell cells[1u << 9];
            uint32_t log = 0;
            bool valid = false;
        };

        /* Fills a sequence table from an FSE table. */
        void fillSeqTable(SeqTable& t, const FseCell* fse, uint32_t log, SeqKind kind) {
            const uint32_t size = 1u << log;
            for (uint32_t u = 0; u < size; ++u) {
                uint32_t s = fse[u].symbol;
                SeqCell& c = t.cells[u];
                c.next = fse[u].next;
                c.nbBits = fse[u].nbBits;
                if (kind == SK_LL) {
                    c.base = LL_BASE[s];
                    c.extra = LL_BITS[s];
                } else if (kind == SK_ML) {
                    c.base = ML_BASE[s];
                    c.extra = ML_BITS[s];
                } else {
                    c.base = uint32_t(1) << s;
                    c.extra = uint8_t(s);
                }
            }

            t.log = log;
            t.valid = true;
        }

        enum ZState {
            Z_MAGIC = 0,
            Z_SKIP_SIZE,
            Z_SKIP,
            Z_FHD,
            Z_FHDR_REST,
            Z_BLOCK_HDR,
            Z_BLOCK_BODY,
            Z_CHECKSUM,
        };

        enum ZStep { ZS_PROGRESS = 0, ZS_NEED_INPUT };

    }

    struct CZstdDecoder::SImpl {
        uint64_t maxWindow;
        int32_t error = SBOX_OK;
        ZState state = Z_MAGIC;

        std::vector<uint8_t> stage;     // --> Bytes of a unit that arrived split across calls.
        uint64_t skipLeft = 0;

        uint8_t fhd = 0;
        uint64_t windowSize = 0;
        uint64_t fcs = 0;
        bool hasFcs = false;
        bool hasChecksum = false;
        size_t blockMax = 0;
        uint64_t frameOut = 0;
        CXxHash64 xxh;

        std::unique_ptr<uint8_t[]> win;
        size_t winCap = 0;
        size_t bufSize = 0;             // --> Window + one block + margin for the current frame.
        size_t pos = 0;
        size_t flushPos = 0;
        size_t extEnd = 0;              // --> End of the previous segment (0 when there is none).

        bool lastBlock = false;
        uint32_t blockType = 0;
        uint32_t blockSize = 0;

        std::vector<uint8_t> lits;
        size_t litSize = 0;

        uint16_t huf[1u << HUF_MAX_BITS];
        uint32_t hufLog = 0;
        bool hufValid = false;

        SeqTable llTable;
        SeqTable ofTable;
        SeqTable mlTable;
        SeqTable llDefault;
        SeqTable ofDefault;
        SeqTable mlDefault;
        uint32_t rep[3] = { 1, 4, 8 };

        uint64_t frames = 0;

        /* Prepares the predefined tables. */
        explicit SImpl(uint64_t maxWin) : maxWindow(maxWin > HARD_WINDOW_LIMIT ? HARD_WINDOW_LIMIT : maxWin) {
            lits.resize(BLOCK_MAX + SLACK);
            FseCell fse[1u << 9];
            buildFse(LL_DEFAULT, 35, 6, fse);
            fillSeqTable(llDefault, fse, 6, SK_LL);
            buildFse(OF_DEFAULT, 28, 5, fse);
            fillSeqTable(ofDefault, fse, 5, SK_OF);
            buildFse(ML_DEFAULT, 52, 6, fse);
            fillSeqTable(mlDefault, fse, 6, SK_ML);
        }

        /* Back to "expecting a frame". */
        void reset() noexcept {
            error = SBOX_OK;
            state = Z_MAGIC;
            stage.clear();
            pos = flushPos = extEnd = 0;
            frames = 0;
        }

        /*
         * Collects `need` contiguous bytes: points `data` straight into the input when they are
         * all there, otherwise accumulates them in `stage`. False when more input is needed.
         */
        bool gather(size_t need, const uint8_t*& in, const uint8_t* end, const uint8_t*& data) {
            if (stage.empty() && size_t(end - in) >= need) {
                data = in;
                in += need;
                return true;
            }

            size_t have = stage.size();
            size_t take = need - have;
            if (take > size_t(end - in)) {
                take = size_t(end - in);
            }

            stage.insert(stage.end(), in, in + take);
            in += take;
            if (stage.size() < need) {
                return false;
            }

            data = stage.data();
            return true;
        }

        /* Parses the frame header after the descriptor byte. */
        int32_t parseFrameHeader(const uint8_t* p) {
            const bool single = (fhd >> 5) & 1u;
            const uint32_t didFlag = fhd & 3u;
            const uint32_t fcsFlag = fhd >> 6;
            hasChecksum = (fhd >> 2) & 1u;

            if (!single) {
                uint32_t wd = *p++;
                uint32_t windowLog = 10 + (wd >> 3);
                uint64_t base = uint64_t(1) << windowLog;
                windowSize = base + (base / 8) * (wd & 7u);
            }

            static const uint32_t DID_SIZE[4] = { 0, 1, 2, 4 };
            uint32_t did = 0;
            for (uint32_t i = 0; i < DID_SIZE[didFlag]; ++i) {
                did |= uint32_t(p[i]) << (8 * i);
            }

            p += DID_SIZE[didFlag];
            if (did != 0) {
                return -ENOTSUP;
            }

            uint32_t fcsSize = fcsFlag == 0 ? (single ? 1 : 0) : (1u << fcsFlag);
            hasFcs = fcsSize != 0;
            fcs = 0;
            if (fcsSize == 1) {
                fcs = p[0];
            } else if (fcsSize == 2) {
                fcs = uint64_t(bits::load16(p)) + 256;
            } else if (fcsSize == 4) {
                fcs = bits::load32(p);
            } else if (fcsSize == 8) {
                fcs = bits::load64(p);
            }

            if (single) {
                windowSize = fcs;
            }

            if (windowSize > maxWindow) {
                return -EFBIG;
            }

            blockMax = windowSize < BLOCK_MAX ? size_t(windowSize) : BLOCK_MAX;
            // --> A wrap happens only once more than window + MARGIN bytes precede the write position,
            // so history still needed from the old segment always lies MARGIN bytes past any overrun.
            bufSize = size_t(windowSize) + blockMax + 2 * MARGIN;
            if (winCap < bufSize + SLACK) {
                win.reset();
                win.reset(new (std::nothrow) uint8_t[bufSize + SLACK]);
                if (!win) {
                    winCap = 0;
                    return -ENOMEM;
                }

                winCap = bufSize + SLACK;
            }

            pos = flushPos = extEnd = 0;
            frameOut = 0;
            xxh.reset(0);
            rep[0] = 1;
            rep[1] = 4;
            rep[2] = 8;
            hufValid = false;
            llTable.valid = ofTable.valid = mlTable.valid = false;
            return SBOX_OK;
        }

        /* Size of the frame header after the descriptor byte. */
        size_t frameHeaderRest() const noexcept {
            const bool single = (fhd >> 5) & 1u;
            static const uint32_t DID_SIZE[4] = { 0, 1, 2, 4 };
            uint32_t fcsFlag = fhd >> 6;
            uint32_t fcsSize = fcsFlag == 0 ? (single ? 1 : 0) : (1u << fcsFlag);
            return (single ? 0 : 1) + DID_SIZE[fhd & 3u] + fcsSize;
        }

        /* Builds the Huffman decoding table from weights (RFC 8878 4.2.1). */
        int32_t buildHuffman(uint8_t* weights, uint32_t count) {
            if (count == 0 || count > 255) {
                return -EBADMSG;
            }

            uint32_t total = 0;
            uint32_t rankCount[HUF_MAX_BITS + 2] = { 0 };
            for (uint32_t i = 0; i < count; ++i) {
                if (weights[i] > HUF_MAX_BITS) {
                    return -EBADMSG;
                }

                rankCount[weights[i]]++;
                if (weights[i]) {
                    total += 1u << (weights[i] - 1);
                }
            }

            if (total == 0) {
                return -EBADMSG;
            }

            uint32_t maxBits = bits::highBit(total) + 1;
            if (maxBits > HUF_MAX_BITS) {
                return -EBADMSG;
            }

            uint32_t rest = (1u << maxBits) - total;
            if (rest == 0 || (rest & (rest - 1)) != 0) {
                return -EBADMSG;
            }

            uint32_t lastWeight = bits::highBit(rest) + 1;
            weights[count] = uint8_t(lastWeight);
            rankCount[lastWeight]++;
            const uint32_t nsym = count + 1;

            uint32_t rankStart[HUF_MAX_BITS + 2] = { 0 };
            uint32_t next = 0;
            for (uint32_t w = 1; w <= maxBits; ++w) {
                rankStart[w] = next;
                next += rankCount[w] << (w - 1);
            }

            if (next != (1u << maxBits)) {
                return -EBADMSG;
            }

            for (uint32_t s = 0; s < nsym; ++s) {
                uint32_t w = weights[s];
                if (!w) {
                    continue;
                }

                uint32_t length = (1u << w) >> 1;
                uint16_t cell = uint16_t((s << 8) | (maxBits + 1 - w));
                for (uint32_t i = 0; i < length; ++i) {
                    huf[rankStart[w] + i] = cell;
                }

                rankStart[w] += length;
            }

            hufLog = maxBits;
            hufValid = true;
            return SBOX_OK;
        }

        /* Reads a Huffman tree description; returns the bytes used or an error. */
        int32_t readHuffmanTree(const uint8_t* src, size_t size) {
            if (size < 1) {
                return -EBADMSG;
            }

            uint8_t weights[256 + 1];
            uint32_t count = 0;
            uint32_t hb = src[0];
            size_t used;
            if (hb < 128) {
                if (hb == 0 || size < 1 + size_t(hb)) {
                    return -EBADMSG;
                }

                const uint8_t* p = src + 1;
                int16_t norm[256];
                uint32_t maxSym = 255;
                uint32_t log = 0;
                int32_t n = readNCount(p, hb, norm, maxSym, log, 6);
                if (n < 0) {
                    return n;
                }

                FseCell fse[1u << 6];
                if (!buildFse(norm, maxSym, log, fse)) {
                    return -EBADMSG;
                }

                BackBits br;
                if (!br.init(p + n, hb - size_t(n))) {
                    return -EBADMSG;
                }

                uint32_t s1 = uint32_t(br.read(log));
                br.reload();
                uint32_t s2 = uint32_t(br.read(log));
                br.reload();
                for (;;) {
                    if (count > 253) {
                        return -EBADMSG;
                    }

                    weights[count++] = fse[s1].symbol;
                    s1 = fse[s1].next + uint32_t(br.read(fse[s1].nbBits));
                    if (br.reload() == R_OVERFLOW) {
                        weights[count++] = fse[s2].symbol;
                        break;
                    }

                    if (count > 253) {
                        return -EBADMSG;
                    }

                    weights[count++] = fse[s2].symbol;
                    s2 = fse[s2].next + uint32_t(br.read(fse[s2].nbBits));
                    if (br.reload() == R_OVERFLOW) {
                        weights[count++] = fse[s1].symbol;
                        break;
                    }
                }

                used = 1 + size_t(hb);
            } else {
                count = hb - 127;
                size_t bytes = (count + 1) / 2;
                if (size < 1 + bytes) {
                    return -EBADMSG;
                }

                for (uint32_t i = 0; i < count; ++i) {
                    uint8_t b = src[1 + i / 2];
                    weights[i] = (i & 1u) ? (b & 0x0Fu) : (b >> 4);
                }

                used = 1 + bytes;
            }

            int32_t rc = buildHuffman(weights, count);
            return rc < 0 ? rc : int32_t(used);
        }

        /* Decodes one Huffman literal stream into dst[0..n). */
        int32_t decodeStream(const uint8_t* src, size_t size, uint8_t* dst, size_t n) {
            BackBits br;
            if (!br.init(src, size)) {
                return -EBADMSG;
            }

            const uint16_t* t = huf;
            const uint32_t log = hufLog;
            size_t i = 0;
            while (i + 4 <= n && br.reload() == R_UNFINISHED) {
                for (int32_t k = 0; k < 4; ++k) {
                    uint16_t c = t[(br.container << br.consumed) >> (64 - log)];
                    dst[i++] = uint8_t(c >> 8);
                    br.consumed += c & 0xFFu;
                }
            }

            while (i < n) {
                if (br.reload() == R_OVERFLOW) {
                    return -EBADMSG;
                }

                uint16_t c = t[br.look(log)];
                dst[i++] = uint8_t(c >> 8);
                br.consumed += c & 0xFFu;
            }

            br.reload();
            return br.finished() ? SBOX_OK : -EBADMSG;
        }

        /* Decodes the literals section into `lits`; returns the bytes used or an error. */
        int32_t decodeLiterals(const uint8_t* src, size_t size) {
            if (size < 1) {
                return -EBADMSG;
            }

            const uint32_t type = src[0] & 3u;
            const uint32_t sf = (src[0] >> 2) & 3u;
            if (type <= 1) {
                size_t hs;
                size_t regen;
                if (sf == 0 || sf == 2) {
                    hs = 1;
                    regen = src[0] >> 3;
                } else if (sf == 1) {
                    if (size < 2) {
                        return -EBADMSG;
                    }

                    hs = 2;
                    regen = (src[0] >> 4) + (size_t(src[1]) << 4);
                } else {
                    if (size < 3) {
                        return -EBADMSG;
                    }

                    hs = 3;
                    regen = (src[0] >> 4) + (size_t(src[1]) << 4) + (size_t(src[2]) << 12);
                }

                if (regen > blockMax) {
                    return -EBADMSG;
                }

                if (type == 0) {
                    if (size < hs + regen) {
                        return -EBADMSG;
                    }

                    std::memcpy(lits.data(), src + hs, regen);
                    litSize = regen;
                    return int32_t(hs + regen);
                }

                if (size < hs + 1) {
                    return -EBADMSG;
                }

                std::memset(lits.data(), src[hs], regen);
                litSize = regen;
                return int32_t(hs + 1);
            }

            size_t hs;
            size_t regen;
            size_t csize;
            bool four = sf != 0;
            if (sf <= 1) {
                if (size < 3) {
                    return -EBADMSG;
                }

                uint32_t v = bits::load24(src);
                hs = 3;
                regen = (v >> 4) & 0x3FFu;
                csize = (v >> 14) & 0x3FFu;
            } else if (sf == 2) {
                if (size < 4) {
                    return -EBADMSG;
                }

                uint32_t v = bits::load32(src);
                hs = 4;
                regen = (v >> 4) & 0x3FFFu;
                csize = (v >> 18) & 0x3FFFu;
            } else {
                if (size < 5) {
                    return -EBADMSG;
                }

                uint64_t v = uint64_t(bits::load32(src)) | (uint64_t(src[4]) << 32);
                hs = 5;
                regen = size_t((v >> 4) & 0x3FFFFu);
                csize = size_t((v >> 22) & 0x3FFFFu);
            }

            if (regen > blockMax || size < hs + csize) {
                return -EBADMSG;
            }

            const uint8_t* p = src + hs;
            size_t left = csize;
            if (type == 2) {
                int32_t n = readHuffmanTree(p, left);
                if (n < 0) {
                    return n;
                }

                p += n;
                left -= size_t(n);
            } else if (!hufValid) {
                return -EBADMSG;
            }

            uint8_t* dst = lits.data();
            if (!four) {
                int32_t rc = decodeStream(p, left, dst, regen);
                if (rc < 0) {
                    return rc;
                }
            } else {
                if (left < 6) {
                    return -EBADMSG;
                }

                size_t s1 = bits::load16(p);
                size_t s2 = bits::load16(p + 2);
                size_t s3 = bits::load16(p + 4);
                if (s1 + s2 + s3 + 6 > left) {
                    return -EBADMSG;
                }

                size_t s4 = left - 6 - s1 - s2 - s3;
                size_t seg = (regen + 3) / 4;
                if (seg * 3 > regen) {
                    return -EBADMSG;
                }

                const uint8_t* q = p + 6;
                int32_t rc = decodeStream(q, s1, dst, seg);
                if (rc == SBOX_OK) {
                    rc = decodeStream(q + s1, s2, dst + seg, seg);
                }

                if (rc == SBOX_OK) {
                    rc = decodeStream(q + s1 + s2, s3, dst + 2 * seg, seg);
                }

                if (rc == SBOX_OK) {
                    rc = decodeStream(q + s1 + s2 + s3, s4, dst + 3 * seg, regen - 3 * seg);
                }

                if (rc < 0) {
                    return rc;
                }
            }

            litSize = regen;
            return int32_t(hs + csize);
        }

        /* Reads one sequence table description; returns the bytes used or an error. */
        int32_t readSeqTable(uint32_t mode, SeqKind kind, const uint8_t* src, size_t size) {
            SeqTable& t = kind == SK_LL ? llTable : (kind == SK_OF ? ofTable : mlTable);
            const SeqTable& def = kind == SK_LL ? llDefault : (kind == SK_OF ? ofDefault : mlDefault);
            const uint32_t maxSym = kind == SK_LL ? LL_MAX : (kind == SK_OF ? OF_MAX : ML_MAX);
            const uint32_t maxLog = kind == SK_LL ? LL_MAX_LOG : (kind == SK_OF ? OF_MAX_LOG : ML_MAX_LOG);

            switch (mode) {
            case 0:
                t = def;
                return 0;

            case 1: {
                if (size < 1 || src[0] > maxSym) {
                    return -EBADMSG;
                }

                FseCell cell{ 0, 0, src[0] };
                fillSeqTable(t, &cell, 0, kind);
                return 1;
            }

            case 2: {
                int16_t norm[64];
                uint32_t ms = maxSym;
                uint32_t log = 0;
                int32_t n = readNCount(src, size, norm, ms, log, maxLog);
                if (n < 0) {
                    return n;
                }

                FseCell fse[1u << 9];
                if (!buildFse(norm, ms, log, fse)) {
                    return -EBADMSG;
                }

                fillSeqTable(t, fse, log, kind);
                return n;
            }

            default:
                return t.valid ? 0 : -EBADMSG;
            }
        }

        /* Copies a match of `len` bytes from `offset` back, handling the previous segment. */
        inline int32_t copyMatch(uint8_t* base, uint8_t*& op, size_t offset, size_t len) {
            size_t inSeg = size_t(op - base);
            if (offset > inSeg) {
                // --> Part of the match lies in the previous segment (before the wrap).
                size_t need = offset - inSeg;
                if (need > extEnd) {
                    return -EBADMSG;
                }

                const uint8_t* src = base + extEnd - need;
                size_t n = need < len ? need : len;
                std::memmove(op, src, n);
                op += n;
                len -= n;
                if (len == 0) {
                    return SBOX_OK;
                }
            }

            const uint8_t* src = op - offset;
            if (offset >= 16) {
                uint8_t* stop = op + len;
                do {
                    std::memcpy(op, src, 16);
                    op += 16;
                    src += 16;
                } while (op < stop);

                op = stop;
            } else if (offset == 1) {
                std::memset(op, *src, len);
                op += len;
            } else {
                for (size_t i = 0; i < len; ++i) {
                    op[i] = src[i];
                }

                op += len;
            }

            return SBOX_OK;
        }

        /* Decodes and executes the sequences section. */
        int32_t decodeSequences(const uint8_t* src, size_t size, uint8_t* base, uint8_t* op, uint8_t*& opEnd) {
            if (size < 1) {
                return -EBADMSG;
            }

            uint32_t nbSeq = src[0];
            size_t hs = 1;
            if (nbSeq >= 128) {
                if (nbSeq == 255) {
                    if (size < 3) {
                        return -EBADMSG;
                    }

                    nbSeq = uint32_t(bits::load16(src + 1)) + 0x7F00u;
                    hs = 3;
                } else {
                    if (size < 2) {
                        return -EBADMSG;
                    }

                    nbSeq = ((nbSeq - 128) << 8) + src[1];
                    hs = 2;
                }
            }

            const uint8_t* lit = lits.data();
            const uint8_t* const litEnd = lits.data() + litSize;
            uint8_t* const blockStart = op;
            uint8_t* const blockLimit = op + blockMax;
            const uint64_t outBefore = frameOut;

            if (nbSeq == 0) {
                if (size != hs) {
                    return -EBADMSG;
                }
            } else {
                if (size < hs + 1) {
                    return -EBADMSG;
                }

                uint32_t modes = src[hs];
                if (modes & 3u) {
                    return -EBADMSG;
                }

                const uint8_t* p = src + hs + 1;
                const uint8_t* const end = src + size;
                int32_t n = readSeqTable(modes >> 6, SK_LL, p, size_t(end - p));
                if (n < 0) {
                    return n;
                }

                p += n;
                n = readSeqTable((modes >> 4) & 3u, SK_OF, p, size_t(end - p));
                if (n < 0) {
                    return n;
                }

                p += n;
                n = readSeqTable((modes >> 2) & 3u, SK_ML, p, size_t(end - p));
                if (n < 0) {
                    return n;
                }

                p += n;
                BackBits br;
                if (!br.init(p, size_t(end - p))) {
                    return -EBADMSG;
                }

                const SeqCell* llt = llTable.cells;
                const SeqCell* oft = ofTable.cells;
                const SeqCell* mlt = mlTable.cells;
                uint32_t sLL = uint32_t(br.read(llTable.log));
                uint32_t sOF = uint32_t(br.read(ofTable.log));
                uint32_t sML = uint32_t(br.read(mlTable.log));
                br.reload();

                for (uint32_t i = 0; i < nbSeq; ++i) {
                    const SeqCell ll = llt[sLL];
                    const SeqCell of = oft[sOF];
                    const SeqCell ml = mlt[sML];

                    uint32_t ofValue = of.base + uint32_t(br.read(of.extra));
                    br.reload();
                    size_t matchLength = ml.base + size_t(br.read(ml.extra));
                    size_t litLength = ll.base + size_t(br.read(ll.extra));
                    br.reload();

                    size_t offset;
                    if (ofValue > 3) {
                        offset = ofValue - 3;
                        rep[2] = rep[1];
                        rep[1] = rep[0];
                        rep[0] = uint32_t(offset);
                    } else {
                        uint32_t idx = ofValue - 1 + (litLength == 0 ? 1u : 0u);
                        if (idx == 0) {
                            offset = rep[0];
                        } else {
                            offset = idx == 3 ? size_t(rep[0]) - 1 : rep[idx];
                            if (offset == 0) {
                                return -EBADMSG;
                            }

                            if (idx != 1) {
                                rep[2] = rep[1];
                            }

                            rep[1] = rep[0];
                            rep[0] = uint32_t(offset);
                        }
                    }

                    if (litLength > size_t(litEnd - lit) || litLength + matchLength > size_t(blockLimit - op)) {
                        return -EBADMSG;
                    }

                    if (litLength <= 16) {
                        std::memcpy(op, lit, 16);
                    } else {
                        std::memcpy(op, lit, litLength);
                    }

                    op += litLength;
                    lit += litLength;

                    uint64_t produced = outBefore + uint64_t(op - blockStart);
                    if (offset > produced || offset > windowSize) {
                        return -EBADMSG;
                    }

                    if (int32_t rc = copyMatch(base, op, offset, matchLength); rc < 0) {
                        return rc;
                    }

                    if (i + 1 < nbSeq) {
                        sLL = ll.next + uint32_t(br.read(ll.nbBits));
                        sML = ml.next + uint32_t(br.read(ml.nbBits));
                        sOF = of.next + uint32_t(br.read(of.nbBits));
                        if (br.reload() == R_OVERFLOW) {
                            return -EBADMSG;
                        }
                    }
                }

                if (br.reload() == R_OVERFLOW || !br.finished()) {
                    return -EBADMSG;
                }
            }

            size_t rest = size_t(litEnd - lit);
            if (rest > size_t(blockLimit - op)) {
                return -EBADMSG;
            }

            std::memcpy(op, lit, rest);
            op += rest;
            opEnd = op;
            return SBOX_OK;
        }

        /* Decodes one block body into the window. */
        int32_t decodeBlock(const uint8_t* src) {
            // --> Start a new segment at the buffer start once the window behind us is complete.
            if (pos + blockMax + MARGIN > bufSize) {
                extEnd = pos;
                pos = flushPos = 0;
            }

            uint8_t* base = win.get();
            uint8_t* op = base + pos;
            if (blockType == 0) {
                std::memcpy(op, src, blockSize);
                op += blockSize;
            } else if (blockType == 1) {
                std::memset(op, src[0], blockSize);
                op += blockSize;
            } else {
                int32_t n = decodeLiterals(src, blockSize);
                if (n < 0) {
                    return n;
                }

                uint8_t* opEnd = op;
                int32_t rc = decodeSequences(src + n, blockSize - size_t(n), base, op, opEnd);
                if (rc < 0) {
                    return rc;
                }

                op = opEnd;
            }

            size_t produced = size_t(op - (base + pos));
            if (hasChecksum) {
                xxh.update(SReadOnlyByteSpan(base + pos, produced));
            }

            frameOut += produced;
            pos += produced;
            if (hasFcs && frameOut > fcs) {
                return -EBADMSG;
            }

            return SBOX_OK;
        }

        /* Checks the end-of-frame conditions. */
        int32_t endFrame() {
            if (hasFcs && frameOut != fcs) {
                return -EBADMSG;
            }

            frames++;
            state = Z_MAGIC;
            return ZS_PROGRESS;
        }

        /* Advances the state machine by one unit. */
        int32_t step(const uint8_t*& in, const uint8_t* end) {
            const uint8_t* data = nullptr;
            switch (state) {
            case Z_MAGIC: {
                if (!gather(4, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                uint32_t magic = bits::load32(data);
                stage.clear();
                if (magic == ZSTD_MAGIC) {
                    state = Z_FHD;
                } else if ((magic & SKIPPABLE_MASK) == SKIPPABLE_MAGIC) {
                    state = Z_SKIP_SIZE;
                } else {
                    return -EBADMSG;
                }

                return ZS_PROGRESS;
            }

            case Z_SKIP_SIZE:
                if (!gather(4, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                skipLeft = bits::load32(data);
                stage.clear();
                state = Z_SKIP;
                return ZS_PROGRESS;

            case Z_SKIP: {
                size_t n = size_t(end - in);
                if (n > skipLeft) {
                    n = size_t(skipLeft);
                }

                in += n;
                skipLeft -= n;
                if (skipLeft) {
                    return ZS_NEED_INPUT;
                }

                state = Z_MAGIC;
                return ZS_PROGRESS;
            }

            case Z_FHD:
                if (!gather(1, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                fhd = data[0];
                stage.clear();
                if (fhd & 0x08u) {
                    return -EBADMSG;
                }

                state = Z_FHDR_REST;
                return ZS_PROGRESS;

            case Z_FHDR_REST: {
                size_t rest = frameHeaderRest();
                if (rest && !gather(rest, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                int32_t rc = parseFrameHeader(data);
                stage.clear();
                if (rc < 0) {
                    return rc;
                }

                state = Z_BLOCK_HDR;
                return ZS_PROGRESS;
            }

            case Z_BLOCK_HDR: {
                if (!gather(3, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                uint32_t h = bits::load24(data);
                stage.clear();
                lastBlock = h & 1u;
                blockType = (h >> 1) & 3u;
                blockSize = h >> 3;
                if (blockType == 3 || blockSize > blockMax) {
                    return -EBADMSG;
                }

                state = Z_BLOCK_BODY;
                return ZS_PROGRESS;
            }

            case Z_BLOCK_BODY: {
                size_t need = blockType == 1 ? 1 : blockSize;
                if (need && !gather(need, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                if (blockType == 2 && blockSize == 0) {
                    return -EBADMSG;
                }

                int32_t rc = decodeBlock(data);
                stage.clear();
                if (rc < 0) {
                    return rc;
                }

                if (!lastBlock) {
                    state = Z_BLOCK_HDR;
                    return ZS_PROGRESS;
                }

                if (hasChecksum) {
                    state = Z_CHECKSUM;
                    return ZS_PROGRESS;
                }

                return endFrame();
            }

            case Z_CHECKSUM: {
                if (!gather(4, in, end, data)) {
                    return ZS_NEED_INPUT;
                }

                uint32_t want = bits::load32(data);
                stage.clear();
                if (want != uint32_t(xxh.digest())) {
                    return -EBADMSG;
                }

                return endFrame();
            }
            }

            return -EINVAL;
        }
    };

    /* Creates a decoder. */
    CZstdDecoder::CZstdDecoder(uint64_t maxWindow)
        : _impl(std::make_unique<SImpl>(maxWindow)) {}

    /* Destroys the decoder. */
    CZstdDecoder::~CZstdDecoder() = default;

    /* Starts over. */
    void CZstdDecoder::reset() {
        _impl->reset();
    }

    /* Number of finished frames. */
    uint64_t CZstdDecoder::frames() const noexcept {
        return _impl->frames;
    }

    /* Decodes as much as input and output allow. */
    int32_t CZstdDecoder::process(const SReadOnlyByteSpan& in, size_t& consumed, const SByteSpan& out,
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
            if (s.flushPos < s.pos) {
                size_t n = s.pos - s.flushPos;
                if (n > oleft) {
                    n = oleft;
                }

                if (n) {
                    std::memcpy(op, s.win.get() + s.flushPos, n);
                    op += n;
                    oleft -= n;
                    s.flushPos += n;
                }

                if (s.flushPos < s.pos) {
                    break;
                }
            }

            int32_t st = s.step(ip, ie);
            if (st < 0) {
                s.error = st;
                rc = st;
                break;
            }

            if (st == ZS_NEED_INPUT) {
                if (s.flushPos < s.pos) {
                    continue;
                }

                if (finish && ip == ie) {
                    if (s.state == Z_MAGIC && s.stage.empty()) {
                        rc = CODEC_END;
                    } else {
                        s.error = -ENODATA;
                        rc = -ENODATA;
                    }
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
