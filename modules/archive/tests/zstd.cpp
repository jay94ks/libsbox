#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/archive/zstd.hpp>
#include <sbox/archive/checksum.hpp>
#include "fixtures/testdata.hpp"
#include "fixtures/zstd_vectors.hpp"
#include <chrono>
#include <string>

using namespace sbox;
using namespace sbox::archive;

namespace {

    /* Rebuilds the plaintext a fixture describes. */
    std::vector<uint8_t> expected(const fixtures::SVector& v) {
        std::vector<uint8_t> out;
        for (int i = 0; i < v.parts; ++i) {
            const fixtures::SPart& p = v.part[i];
            std::vector<uint8_t> part;
            if (p.kind == 0) {
                part = testdata::Random(p.n, p.seed);
            } else if (p.kind == 1) {
                part = testdata::Text(p.n, p.seed);
            } else if (p.kind == 2) {
                part = testdata::Repeat(p.n, p.period, p.seed);
            } else {
                part.assign(p.n, 0);
            }

            out.insert(out.end(), part.begin(), part.end());
        }

        return out;
    }

    /* Finds a fixture by name. */
    const fixtures::SVector& vec(const char* name) {
        for (const fixtures::SVector& v : fixtures::fixtures_zstd_vectors_hpp_list) {
            if (std::string(v.name) == name) {
                return v;
            }
        }

        FAIL("missing fixture " << name);
        return fixtures::fixtures_zstd_vectors_hpp_list[0];
    }

    std::vector<uint8_t> bytesOf(const fixtures::SVector& v) {
        return std::vector<uint8_t>(v.data, v.data + v.size);
    }

    /* Builds a frame header: magic + FHD + optional fields. */
    std::vector<uint8_t> frameHeader(uint8_t fhd, std::initializer_list<uint8_t> rest) {
        std::vector<uint8_t> f = { 0x28, 0xB5, 0x2F, 0xFD, fhd };
        f.insert(f.end(), rest.begin(), rest.end());
        return f;
    }

    /* Appends a 3-byte block header. */
    void blockHeader(std::vector<uint8_t>& f, bool last, uint32_t type, uint32_t size) {
        uint32_t h = (last ? 1u : 0u) | (type << 1) | (size << 3);
        f.push_back(uint8_t(h));
        f.push_back(uint8_t(h >> 8));
        f.push_back(uint8_t(h >> 16));
    }

    int32_t decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out, size_t inChunk = 0, size_t outChunk = 0,
                   uint64_t maxWindow = uint64_t(128) << 20) {
        CZstdDecoder dec(maxWindow);
        return testdata::Run(dec, in, out, inChunk, outChunk);
    }

}

TEST_CASE("zstd decodes python-zstandard vectors in any chunking") {
    for (const fixtures::SVector& v : fixtures::fixtures_zstd_vectors_hpp_list) {
        CAPTURE(v.name);
        std::vector<uint8_t> in = bytesOf(v);
        std::vector<uint8_t> want = expected(v);
        for (auto chunks : { std::pair<size_t, size_t>{ 0, 0 }, { 1, 0 }, { 0, 1 }, { 5, 7 }, { 4096, 100 } }) {
            if (want.size() > 300000 && (chunks.first == 1 || chunks.second < 100)) {
                continue;
            }

            std::vector<uint8_t> out;
            CHECK(decode(in, out, chunks.first, chunks.second) == CODEC_END);
            CHECK(out.size() == want.size());
            CHECK(out == want);
        }
    }
}

TEST_CASE("hand-built raw, RLE and checksummed frames") {
    std::vector<uint8_t> out;

    SUBCASE("raw block, single segment") {
        std::vector<uint8_t> f = frameHeader(0x20, { 5 });
        blockHeader(f, true, 0, 5);
        f.insert(f.end(), { 'h', 'e', 'l', 'l', 'o' });
        CHECK(decode(f, out) == CODEC_END);
        CHECK(testdata::Str(out) == "hello");
    }

    SUBCASE("RLE block") {
        std::vector<uint8_t> f = frameHeader(0x20, { 10 });
        blockHeader(f, true, 1, 10);
        f.push_back('a');
        CHECK(decode(f, out) == CODEC_END);
        CHECK(testdata::Str(out) == "aaaaaaaaaa");
    }

    SUBCASE("several blocks with a content checksum and a window descriptor") {
        // --> FHD: checksum flag, FCS 2 bytes (value - 256), window descriptor 0 (1 KiB).
        std::string want = "abcdefgh" + std::string(300, 'z') + "tail";
        uint16_t fcs = uint16_t(want.size() - 256);
        std::vector<uint8_t> f = frameHeader(0x44, { 0x00, uint8_t(fcs), uint8_t(fcs >> 8) });
        blockHeader(f, false, 0, 8);
        f.insert(f.end(), want.begin(), want.begin() + 8);
        blockHeader(f, false, 1, 300);
        f.push_back('z');
        blockHeader(f, true, 0, 4);
        f.insert(f.end(), { 't', 'a', 'i', 'l' });
        uint32_t sum = uint32_t(CXxHash64::compute(BytesOf(want)));
        f.insert(f.end(), { uint8_t(sum), uint8_t(sum >> 8), uint8_t(sum >> 16), uint8_t(sum >> 24) });
        CHECK(decode(f, out, 3, 2) == CODEC_END);
        CHECK(testdata::Str(out) == want);

        f[f.size() - 2] ^= 1;
        CHECK(decode(f, out) == -EBADMSG);
    }

    SUBCASE("content size mismatch") {
        std::vector<uint8_t> f = frameHeader(0x20, { 6 });
        blockHeader(f, true, 0, 5);
        f.insert(f.end(), { 'h', 'e', 'l', 'l', 'o' });
        CHECK(decode(f, out) == -EBADMSG);
    }

    SUBCASE("block larger than the window") {
        std::vector<uint8_t> f = frameHeader(0x20, { 4 });
        blockHeader(f, true, 0, 5);
        f.insert(f.end(), { 'h', 'e', 'l', 'l', 'o' });
        CHECK(decode(f, out) == -EBADMSG);
    }

    SUBCASE("reserved bit, reserved block type, dictionary") {
        std::vector<uint8_t> f = frameHeader(0x28, { 1 });
        CHECK(decode(f, out) == -EBADMSG);
        f = frameHeader(0x20, { 1 });
        blockHeader(f, true, 3, 1);
        f.push_back(0);
        CHECK(decode(f, out) == -EBADMSG);
        f = frameHeader(0x21, { 7, 1 });
        CHECK(decode(f, out) == -ENOTSUP);
    }

    SUBCASE("skippable frame alone and empty input") {
        std::vector<uint8_t> f = { 0x5E, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3 };
        CHECK(decode(f, out) == CODEC_END);
        CHECK(out.empty());
        CHECK(decode({}, out) == CODEC_END);
        CHECK(decode({ 1, 2, 3, 4 }, out) == -EBADMSG);
    }
}

TEST_CASE("zstd window limit") {
    const fixtures::SVector& v = vec("zstd_long_window");
    std::vector<uint8_t> out;
    CHECK(decode(bytesOf(v), out, 0, 0, uint64_t(8) << 20) == -EFBIG);
    REQUIRE(decode(bytesOf(v), out) == CODEC_END);
    CHECK(out == expected(v));
}

TEST_CASE("zstd rejects corrupt and truncated input") {
    const fixtures::SVector& v = vec("zstd_text_l19");
    std::vector<uint8_t> in = bytesOf(v);
    std::vector<uint8_t> out;

    for (size_t n = 0; n < in.size(); n += (n < 64 ? 1 : 101)) {
        std::vector<uint8_t> cut(in.begin(), in.begin() + n);
        int32_t rc = decode(cut, out);
        CAPTURE(n);
        CHECK((rc == -ENODATA || rc == -EBADMSG || (n == 0 && rc == CODEC_END)));
    }

    testdata::Rng r(4321);
    int32_t ok = 0;
    for (int32_t iter = 0; iter < 1500; ++iter) {
        std::vector<uint8_t> bad = in;
        int32_t flips = 1 + int32_t(r.next() % 4);
        for (int32_t k = 0; k < flips; ++k) {
            bad[4 + r.next() % (bad.size() - 4)] ^= uint8_t(1u << (r.next() % 8));
        }

        int32_t rc = decode(bad, out);
        if (rc == CODEC_END) {
            ok++;
        } else {
            CHECK(rc < 0);
        }
    }

    // --> The XXH64 content checksum catches corruption that still decodes.
    CHECK(ok == 0);

    // --> Without a checksum, corruption must still never crash.
    std::vector<uint8_t> nosum = bytesOf(vec("zstd_nosize"));
    for (int32_t iter = 0; iter < 1500; ++iter) {
        std::vector<uint8_t> bad = nosum;
        bad[4 + r.next() % (bad.size() - 4)] ^= uint8_t(1u << (r.next() % 8));
        int32_t rc = decode(bad, out);
        CHECK((rc == CODEC_END || rc < 0));
    }
}

TEST_CASE("zstd throughput (informational)") {
    struct Item {
        const char* name;
        int repeat;
    };

    for (Item item : { Item{ "zstd_text_multiblock", 20 }, Item{ "zstd_text_l3", 50 }, Item{ "zstd_repeat_wrap", 2 },
                       Item{ "zstd_long_window", 1 } }) {
        const fixtures::SVector& v = vec(item.name);
        std::vector<uint8_t> in = bytesOf(v);
        std::vector<uint8_t> out;
        size_t total = 0;
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < item.repeat; ++i) {
            REQUIRE(decode(in, out, 0, 1 << 20) == CODEC_END);
            total += out.size();
        }

        double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        MESSAGE(std::string(item.name) << ": " << double(total) / 1e6 / sec << " MB/s");
    }
}
