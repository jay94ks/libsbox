#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/archive/checksum.hpp>
#include "fixtures/testdata.hpp"

using namespace sbox;
using namespace sbox::archive;

TEST_CASE("CRC-32 known values") {
    CHECK(CCrc32::compute(BytesOf("")) == 0u);
    CHECK(CCrc32::compute(BytesOf("123456789")) == 0xCBF43926u);
    CHECK(CCrc32::compute(BytesOf("The quick brown fox jumps over the lazy dog")) == 0x414FA339u);
}

TEST_CASE("CRC-32 streaming equals one-shot") {
    std::vector<uint8_t> data = testdata::Random(100003, 7);
    uint32_t whole = CCrc32::compute(BytesOf(data));
    for (size_t chunk : { size_t(1), size_t(3), size_t(7), size_t(8), size_t(1000), size_t(65536) }) {
        CCrc32 c;
        for (size_t i = 0; i < data.size(); i += chunk) {
            size_t n = std::min(chunk, data.size() - i);
            c.update(SReadOnlyByteSpan(data.data() + i, n));
        }

        CHECK(c.value() == whole);
    }

    uint32_t a = CCrc32::compute(SReadOnlyByteSpan(data.data(), 500));
    CHECK(CCrc32::extend(a, data.data() + 500, data.size() - 500) == whole);
}

TEST_CASE("Adler-32 known values") {
    CHECK(CAdler32::compute(BytesOf("")) == 1u);
    CHECK(CAdler32::compute(BytesOf("Wikipedia")) == 0x11E60398u);

    // --> Long input exercises the modulo deferral.
    std::vector<uint8_t> ff(1 << 20, 0xFF);
    CAdler32 a;
    for (size_t i = 0; i < ff.size(); i += 4097) {
        a.update(SReadOnlyByteSpan(ff.data() + i, std::min<size_t>(4097, ff.size() - i)));
    }

    CHECK(a.value() == CAdler32::compute(BytesOf(ff)));
}

TEST_CASE("XXH64 known values and streaming") {
    CHECK(CXxHash64::compute(BytesOf("")) == 0xEF46DB3751D8E999ull);
    CHECK(CXxHash64::compute(BytesOf("a")) == 0xD24EC4F1A98C6E5Bull);
    CHECK(CXxHash64::compute(BytesOf("abc")) == 0x44BC2CF5AD770999ull);

    std::vector<uint8_t> data = testdata::Text(10007, 3);
    uint64_t whole = CXxHash64::compute(BytesOf(data));
    for (size_t chunk : { size_t(1), size_t(5), size_t(31), size_t(32), size_t(33), size_t(4096) }) {
        CXxHash64 h;
        for (size_t i = 0; i < data.size(); i += chunk) {
            h.update(SReadOnlyByteSpan(data.data() + i, std::min(chunk, data.size() - i)));
        }

        CHECK(h.digest() == whole);
    }
}
