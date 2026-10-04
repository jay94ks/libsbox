#include <sbox/archive/checksum.hpp>
#include "bits.hpp"
#include <array>

namespace sbox {
namespace archive {

    namespace {

        using CrcTables = std::array<std::array<uint32_t, 256>, 8>;

        /* Builds the slice-by-8 tables at compile time. */
        constexpr CrcTables makeCrcTables() noexcept {
            CrcTables t{};
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t c = i;
                for (int32_t k = 0; k < 8; ++k) {
                    c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                }

                t[0][i] = c;
            }

            for (uint32_t i = 0; i < 256; ++i) {
                for (size_t k = 1; k < 8; ++k) {
                    t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xFFu];
                }
            }

            return t;
        }

        constexpr CrcTables CRC_TABLES = makeCrcTables();

        /* Runs the raw (pre/post-inverted) CRC state over a buffer, eight bytes at a time. */
        uint32_t crcUpdate(uint32_t crc, const uint8_t* p, size_t n) noexcept {
            const auto& t = CRC_TABLES;
            while (n >= 8) {
                uint32_t one = bits::load32(p) ^ crc;
                uint32_t two = bits::load32(p + 4);
                crc = t[7][one & 0xFFu] ^ t[6][(one >> 8) & 0xFFu] ^ t[5][(one >> 16) & 0xFFu] ^ t[4][one >> 24]
                    ^ t[3][two & 0xFFu] ^ t[2][(two >> 8) & 0xFFu] ^ t[1][(two >> 16) & 0xFFu] ^ t[0][two >> 24];
                p += 8;
                n -= 8;
            }

            while (n--) {
                crc = t[0][(crc ^ *p++) & 0xFFu] ^ (crc >> 8);
            }

            return crc;
        }

        constexpr uint64_t XXH_P1 = 11400714785074694791ull;
        constexpr uint64_t XXH_P2 = 14029467366897019727ull;
        constexpr uint64_t XXH_P3 = 1609587929392839161ull;
        constexpr uint64_t XXH_P4 = 9650029242287828579ull;
        constexpr uint64_t XXH_P5 = 2870177450012600261ull;

        /* Rotates left. */
        inline uint64_t rotl(uint64_t v, uint32_t r) noexcept {
            return (v << r) | (v >> (64 - r));
        }

        /* One XXH64 accumulator round. */
        inline uint64_t xxhRound(uint64_t acc, uint64_t input) noexcept {
            acc += input * XXH_P2;
            acc = rotl(acc, 31);
            return acc * XXH_P1;
        }

        /* Merges an accumulator into the converged hash. */
        inline uint64_t xxhMerge(uint64_t acc, uint64_t v) noexcept {
            acc ^= xxhRound(0, v);
            return acc * XXH_P1 + XXH_P4;
        }

    }

    /* Feeds bytes into the CRC. */
    void CCrc32::update(const SReadOnlyByteSpan& data) noexcept {
        if (data.size) {
            _state = crcUpdate(_state, data.data, data.size);
        }
    }

    /* Continues a finished CRC value. */
    uint32_t CCrc32::extend(uint32_t crc, const uint8_t* data, size_t size) noexcept {
        return crcUpdate(crc ^ 0xFFFFFFFFu, data, size) ^ 0xFFFFFFFFu;
    }

    /* One-shot CRC. */
    uint32_t CCrc32::compute(const SReadOnlyByteSpan& data) noexcept {
        return extend(0, data.data, data.size);
    }

    /* Feeds bytes into the Adler-32. */
    void CAdler32::update(const SReadOnlyByteSpan& data) noexcept {
        constexpr uint32_t MOD = 65521;
        // --> 5552 is the largest n for which 255n(n+1)/2 + (n+1)(MOD-1) fits in 32 bits.
        constexpr size_t NMAX = 5552;

        const uint8_t* p = data.data;
        size_t n = data.size;
        uint32_t a = _a;
        uint32_t b = _b;
        while (n > 0) {
            size_t chunk = n < NMAX ? n : NMAX;
            n -= chunk;
            while (chunk >= 8) {
                a += p[0]; b += a;
                a += p[1]; b += a;
                a += p[2]; b += a;
                a += p[3]; b += a;
                a += p[4]; b += a;
                a += p[5]; b += a;
                a += p[6]; b += a;
                a += p[7]; b += a;
                p += 8;
                chunk -= 8;
            }

            while (chunk--) {
                a += *p++;
                b += a;
            }

            a %= MOD;
            b %= MOD;
        }

        _a = a;
        _b = b;
    }

    /* One-shot Adler-32. */
    uint32_t CAdler32::compute(const SReadOnlyByteSpan& data) noexcept {
        CAdler32 a;
        a.update(data);
        return a.value();
    }

    /* Starts an XXH64 state. */
    CXxHash64::CXxHash64(uint64_t seed) noexcept {
        reset(seed);
    }

    /* Resets the XXH64 state. */
    void CXxHash64::reset(uint64_t seed) noexcept {
        _seed = seed;
        _v[0] = seed + XXH_P1 + XXH_P2;
        _v[1] = seed + XXH_P2;
        _v[2] = seed;
        _v[3] = seed - XXH_P1;
        _total = 0;
        _buffered = 0;
    }

    /* Feeds bytes into XXH64. */
    void CXxHash64::update(const SReadOnlyByteSpan& data) noexcept {
        const uint8_t* p = data.data;
        size_t n = data.size;
        _total += n;

        if (_buffered + n < 32) {
            if (n) {
                std::memcpy(_buffer + _buffered, p, n);
            }

            _buffered += uint32_t(n);
            return;
        }

        if (_buffered) {
            size_t fill = 32 - _buffered;
            std::memcpy(_buffer + _buffered, p, fill);
            for (size_t i = 0; i < 4; ++i) {
                _v[i] = xxhRound(_v[i], bits::load64(_buffer + i * 8));
            }

            p += fill;
            n -= fill;
            _buffered = 0;
        }

        uint64_t v0 = _v[0], v1 = _v[1], v2 = _v[2], v3 = _v[3];
        while (n >= 32) {
            v0 = xxhRound(v0, bits::load64(p));
            v1 = xxhRound(v1, bits::load64(p + 8));
            v2 = xxhRound(v2, bits::load64(p + 16));
            v3 = xxhRound(v3, bits::load64(p + 24));
            p += 32;
            n -= 32;
        }

        _v[0] = v0; _v[1] = v1; _v[2] = v2; _v[3] = v3;
        if (n) {
            std::memcpy(_buffer, p, n);
        }

        _buffered = uint32_t(n);
    }

    /* Finalises a copy of the state. */
    uint64_t CXxHash64::digest() const noexcept {
        uint64_t h;
        if (_total >= 32) {
            h = rotl(_v[0], 1) + rotl(_v[1], 7) + rotl(_v[2], 12) + rotl(_v[3], 18);
            h = xxhMerge(h, _v[0]);
            h = xxhMerge(h, _v[1]);
            h = xxhMerge(h, _v[2]);
            h = xxhMerge(h, _v[3]);
        } else {
            h = _seed + XXH_P5;
        }

        h += _total;

        const uint8_t* p = _buffer;
        uint32_t n = _buffered;
        while (n >= 8) {
            h ^= xxhRound(0, bits::load64(p));
            h = rotl(h, 27) * XXH_P1 + XXH_P4;
            p += 8;
            n -= 8;
        }

        if (n >= 4) {
            h ^= uint64_t(bits::load32(p)) * XXH_P1;
            h = rotl(h, 23) * XXH_P2 + XXH_P3;
            p += 4;
            n -= 4;
        }

        while (n--) {
            h ^= uint64_t(*p++) * XXH_P5;
            h = rotl(h, 11) * XXH_P1;
        }

        h ^= h >> 33;
        h *= XXH_P2;
        h ^= h >> 29;
        h *= XXH_P3;
        h ^= h >> 32;
        return h;
    }

    /* One-shot XXH64. */
    uint64_t CXxHash64::compute(const SReadOnlyByteSpan& data, uint64_t seed) noexcept {
        CXxHash64 h(seed);
        h.update(data);
        return h.digest();
    }

}
}
