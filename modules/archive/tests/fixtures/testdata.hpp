#ifndef __TESTS_ARCHIVE_FIXTURES_TESTDATA_HPP__
#define __TESTS_ARCHIVE_FIXTURES_TESTDATA_HPP__

// Deterministic test data shared with fixtures/gen_fixtures.py (same algorithms, same output).

#include <sbox/common.hpp>
#include <sbox/archive/codec.hpp>
#include <cstring>
#include <string>
#include <vector>

namespace testdata {

    using namespace sbox;

    /* xorshift32 generator. */
    struct Rng {
        uint32_t x;

        explicit Rng(uint32_t seed) : x(seed ? seed : 1u) {}

        uint32_t next() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            return x;
        }
    };

    /* `n` pseudo-random bytes. */
    inline std::vector<uint8_t> Random(size_t n, uint32_t seed) {
        Rng r(seed);
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = uint8_t(r.next() >> 24);
        }

        return v;
    }

    /* `n` bytes of word salad. */
    inline std::vector<uint8_t> Text(size_t n, uint32_t seed) {
        static const char* const WORDS[] = { "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
                                             "lorem", "ipsum", "dolor", "sit", "amet", "sbox", "layer", "tar", "\n" };
        Rng r(seed);
        std::vector<uint8_t> v;
        v.reserve(n + 16);
        while (v.size() < n) {
            const char* w = WORDS[r.next() % 17];
            v.insert(v.end(), w, w + std::strlen(w));
            v.push_back(' ');
        }

        v.resize(n);
        return v;
    }

    /* `n` bytes repeating Text(period, seed). */
    inline std::vector<uint8_t> Repeat(size_t n, size_t period, uint32_t seed) {
        std::vector<uint8_t> unit = Text(period, seed);
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = unit[i % period];
        }

        return v;
    }

    /* Runs a codec over a whole buffer with the given chunk sizes (0 = everything at once). */
    inline int32_t Run(archive::ICodec& codec, const std::vector<uint8_t>& in, std::vector<uint8_t>& out,
                       size_t inChunk = 0, size_t outChunk = 0) {
        out.clear();
        size_t pos = 0;
        std::vector<uint8_t> buf(outChunk ? outChunk : 65536);
        size_t stall = 0;
        for (;;) {
            size_t n = in.size() - pos;
            if (inChunk && n > inChunk) {
                n = inChunk;
            }

            bool finish = pos + n == in.size();
            size_t c = 0;
            size_t p = 0;
            int32_t rc = codec.process(SReadOnlyByteSpan(in.data() + pos, n), c, SByteSpan(buf.data(), buf.size()), p, finish);
            pos += c;
            out.insert(out.end(), buf.begin(), buf.begin() + p);
            if (rc < 0 || rc == archive::CODEC_END) {
                return rc;
            }

            if (c == 0 && p == 0) {
                if (++stall > 4) {
                    return -EDEADLK;
                }
            } else {
                stall = 0;
            }
        }
    }

    /* Converts a vector to a string (for comparisons with readable failure output). */
    inline std::string Str(const std::vector<uint8_t>& v) {
        return std::string(v.begin(), v.end());
    }

}

#endif
