#ifndef __SRC_ARCHIVE_HUFFMAN_HPP__
#define __SRC_ARCHIVE_HUFFMAN_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace archive {
namespace huff {

    /*
     * DEFLATE decoding table entries (uint32):
     *   bits  0..4   number of bits of the codeword (or root bits for a sub-table pointer)
     *   bits  5..8   extra bits (length/distance) or sub-table index bits
     *   bits  9..11  kind
     *   bits 16..31  value: literal byte, length/distance base, or sub-table offset
     */
    constexpr uint32_t K_LIT = 0;   // --> Literal byte (or a code-length symbol).
    constexpr uint32_t K_LEN = 1;   // --> Length (litlen table) or distance (dist table) base.
    constexpr uint32_t K_EOB = 2;   // --> End of block.
    constexpr uint32_t K_SUB = 3;   // --> Pointer to a sub-table.
    constexpr uint32_t K_BAD = 4;   // --> Unused code or invalid symbol.

    /* Packs a table entry. */
    constexpr uint32_t entry(uint32_t kind, uint32_t nbits, uint32_t extra, uint32_t value) noexcept {
        return nbits | (extra << 5) | (kind << 9) | (value << 16);
    }

    /* Field accessors. */
    constexpr uint32_t nbits(uint32_t e) noexcept { return e & 31u; }
    constexpr uint32_t extra(uint32_t e) noexcept { return (e >> 5) & 15u; }
    constexpr uint32_t kind(uint32_t e) noexcept { return (e >> 9) & 7u; }
    constexpr uint32_t value(uint32_t e) noexcept { return e >> 16; }

    /* Length symbol 257 + i: base length and extra bits. */
    inline constexpr uint16_t LEN_BASE[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                               35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    inline constexpr uint8_t LEN_EXTRA[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                               3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };

    /* Distance symbol i: base distance and extra bits. */
    inline constexpr uint16_t DIST_BASE[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                                                257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                                                8193, 12289, 16385, 24577 };
    inline constexpr uint8_t DIST_EXTRA[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                                                7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

    /* Transmission order of the code-length code lengths. */
    inline constexpr uint8_t CODELEN_ORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

    /* Which alphabet a table decodes. */
    enum Alphabet { A_LITLEN, A_DIST, A_CODELEN };

    /*
     * Builds a decoding table for canonical code lengths `lens[0..n)`.
     * Returns false for an over-subscribed code or a disallowed incomplete one (zlib rules:
     * incomplete only when exactly one code of length 1 is used, never for code lengths).
     */
    bool buildTable(const uint8_t* lens, uint32_t n, uint32_t rootBits, Alphabet alphabet, std::vector<uint32_t>& table);

}
}
}

#endif
