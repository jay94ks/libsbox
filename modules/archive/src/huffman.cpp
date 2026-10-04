#include "huffman.hpp"
#include "bits.hpp"
#include <cstring>

namespace sbox {
namespace archive {
namespace huff {

    namespace {

        /* Decoded meaning of symbol `sym` of an alphabet, with `n` codeword bits. */
        uint32_t symbolEntry(Alphabet alphabet, uint32_t sym, uint32_t n) noexcept {
            switch (alphabet) {
            case A_LITLEN:
                if (sym < 256) {
                    return entry(K_LIT, n, 0, sym);
                }

                if (sym == 256) {
                    return entry(K_EOB, n, 0, 0);
                }

                if (sym < 286) {
                    return entry(K_LEN, n, LEN_EXTRA[sym - 257], LEN_BASE[sym - 257]);
                }

                return entry(K_BAD, n, 0, 0);

            case A_DIST:
                if (sym < 30) {
                    return entry(K_LEN, n, DIST_EXTRA[sym], DIST_BASE[sym]);
                }

                return entry(K_BAD, n, 0, 0);

            case A_CODELEN:
            default:
                return entry(K_LIT, n, 0, sym);
            }
        }

    }

    /* Builds a root table plus sub-tables for a canonical Huffman code. */
    bool buildTable(const uint8_t* lens, uint32_t n, uint32_t rootBits, Alphabet alphabet, std::vector<uint32_t>& table) {
        uint32_t count[16] = { 0 };
        for (uint32_t i = 0; i < n; ++i) {
            if (lens[i] > 15) {
                return false;
            }

            count[lens[i]]++;
        }

        count[0] = 0;
        const uint32_t rootSize = 1u << rootBits;
        const uint32_t rootMask = rootSize - 1;
        table.assign(rootSize, entry(K_BAD, 0, 0, 0));

        uint32_t maxLen = 0;
        for (uint32_t len = 15; len >= 1; --len) {
            if (count[len]) {
                maxLen = len;
                break;
            }
        }

        if (maxLen == 0) {
            // --> No codes at all: legal for distances (literal-only data), the caller decides.
            return alphabet != A_CODELEN;
        }

        int32_t left = 1;
        for (uint32_t len = 1; len <= 15; ++len) {
            left <<= 1;
            left -= int32_t(count[len]);
            if (left < 0) {
                return false;
            }
        }

        if (left > 0 && (alphabet == A_CODELEN || maxLen != 1)) {
            return false;
        }

        uint32_t next[16] = { 0 };
        uint32_t code = 0;
        for (uint32_t len = 1; len <= 15; ++len) {
            code = (code + count[len - 1]) << 1;
            next[len] = code;
        }

        uint16_t codes[320];
        for (uint32_t i = 0; i < n; ++i) {
            if (lens[i]) {
                codes[i] = uint16_t(bits::reverse(next[lens[i]]++, lens[i]));
            }
        }

        if (maxLen > rootBits) {
            uint8_t prefixMax[1u << 11];
            std::memset(prefixMax, 0, rootSize);
            for (uint32_t i = 0; i < n; ++i) {
                if (lens[i] > rootBits) {
                    uint32_t p = codes[i] & rootMask;
                    if (lens[i] > prefixMax[p]) {
                        prefixMax[p] = lens[i];
                    }
                }
            }

            uint32_t offset = rootSize;
            for (uint32_t p = 0; p < rootSize; ++p) {
                if (prefixMax[p]) {
                    uint32_t subBits = prefixMax[p] - rootBits;
                    table[p] = entry(K_SUB, rootBits, subBits, offset);
                    offset += 1u << subBits;
                }
            }

            table.resize(offset, entry(K_BAD, 0, 0, 0));
        }

        for (uint32_t i = 0; i < n; ++i) {
            uint32_t len = lens[i];
            if (!len) {
                continue;
            }

            if (len <= rootBits) {
                uint32_t e = symbolEntry(alphabet, i, len);
                for (uint32_t k = codes[i]; k < rootSize; k += 1u << len) {
                    table[k] = e;
                }
            } else {
                uint32_t sub = table[codes[i] & rootMask];
                uint32_t subSize = 1u << extra(sub);
                uint32_t base = value(sub);
                uint32_t e = symbolEntry(alphabet, i, len - rootBits);
                for (uint32_t k = uint32_t(codes[i]) >> rootBits; k < subSize; k += 1u << (len - rootBits)) {
                    table[base + k] = e;
                }
            }
        }

        return true;
    }

}
}
}
