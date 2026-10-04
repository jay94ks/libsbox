#ifndef __SRC_ARCHIVE_BITS_HPP__
#define __SRC_ARCHIVE_BITS_HPP__

#include <sbox/common.hpp>
#include <cstring>

namespace sbox {
namespace archive {
namespace bits {

    /* Loads a little-endian 16-bit value from unaligned memory. */
    inline uint16_t load16(const uint8_t* p) noexcept {
        return uint16_t(p[0] | (uint16_t(p[1]) << 8));
    }

    /* Loads a little-endian 24-bit value from unaligned memory. */
    inline uint32_t load24(const uint8_t* p) noexcept {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16);
    }

    /* Loads a little-endian 32-bit value from unaligned memory. */
    inline uint32_t load32(const uint8_t* p) noexcept {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint32_t v;
        std::memcpy(&v, p, 4);
        return v;
#else
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
#endif
    }

    /* Loads a little-endian 64-bit value from unaligned memory. */
    inline uint64_t load64(const uint8_t* p) noexcept {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint64_t v;
        std::memcpy(&v, p, 8);
        return v;
#else
        return uint64_t(load32(p)) | (uint64_t(load32(p + 4)) << 32);
#endif
    }

    /* Stores a little-endian 16-bit value. */
    inline void store16(uint8_t* p, uint16_t v) noexcept {
        p[0] = uint8_t(v);
        p[1] = uint8_t(v >> 8);
    }

    /* Stores a little-endian 32-bit value. */
    inline void store32(uint8_t* p, uint32_t v) noexcept {
        p[0] = uint8_t(v);
        p[1] = uint8_t(v >> 8);
        p[2] = uint8_t(v >> 16);
        p[3] = uint8_t(v >> 24);
    }

    /* Stores a little-endian 64-bit value. */
    inline void store64(uint8_t* p, uint64_t v) noexcept {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        std::memcpy(p, &v, 8);
#else
        store32(p, uint32_t(v));
        store32(p + 4, uint32_t(v >> 32));
#endif
    }

    /* Index of the highest set bit (value must be non-zero). */
    inline uint32_t highBit(uint32_t v) noexcept {
        return 31u - uint32_t(__builtin_clz(v));
    }

    /* Reverses the low `n` bits of `code`. */
    inline uint32_t reverse(uint32_t code, uint32_t n) noexcept {
        uint32_t r = 0;
        for (uint32_t i = 0; i < n; ++i) {
            r = (r << 1) | (code & 1u);
            code >>= 1;
        }

        return r;
    }

}
}
}

#endif
