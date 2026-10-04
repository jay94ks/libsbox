#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/archive/deflate.hpp>
#include <sbox/archive/checksum.hpp>
#include "fixtures/testdata.hpp"
#include "fixtures/deflate_vectors.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

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

    EDeflateFormat formatOf(int f) {
        return f == 0 ? EDFMT_RAW : (f == 1 ? EDFMT_ZLIB : EDFMT_GZIP);
    }

    /* Compresses then decompresses, checking the result. */
    void roundTrip(const std::vector<uint8_t>& data, EDeflateFormat fmt, int32_t level, size_t inChunk = 0, size_t outChunk = 0) {
        CDeflater enc(fmt, level);
        std::vector<uint8_t> packed;
        REQUIRE(testdata::Run(enc, data, packed, inChunk, outChunk) == CODEC_END);

        CInflater dec(fmt);
        std::vector<uint8_t> unpacked;
        REQUIRE(testdata::Run(dec, packed, unpacked, inChunk, outChunk) == CODEC_END);
        REQUIRE(unpacked.size() == data.size());
        CHECK(unpacked == data);
    }

    /* Returns true when a shell command exists. */
    bool haveTool(const char* name) {
        std::string cmd = std::string("command -v ") + name + " >/dev/null 2>&1";
        return std::system(cmd.c_str()) == 0;
    }

    /* Writes a buffer to a file. */
    void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
        FILE* f = std::fopen(path.c_str(), "wb");
        REQUIRE(f != nullptr);
        if (!data.empty()) {
            REQUIRE(std::fwrite(data.data(), 1, data.size(), f) == data.size());
        }

        std::fclose(f);
    }

    /* Reads a whole file. */
    std::vector<uint8_t> readFile(const std::string& path) {
        std::vector<uint8_t> out;
        FILE* f = std::fopen(path.c_str(), "rb");
        REQUIRE(f != nullptr);
        uint8_t buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
            out.insert(out.end(), buf, buf + n);
        }

        std::fclose(f);
        return out;
    }

}

TEST_CASE("inflate decodes python zlib/gzip vectors in any chunking") {
    for (const fixtures::SVector& v : fixtures::fixtures_deflate_vectors_hpp_list) {
        CAPTURE(v.name);
        std::vector<uint8_t> in(v.data, v.data + v.size);
        std::vector<uint8_t> want = expected(v);
        for (auto chunks : { std::pair<size_t, size_t>{ 0, 0 }, { 1, 0 }, { 0, 1 }, { 7, 13 }, { 4096, 100 } }) {
            if (want.size() > 100000 && (chunks.first == 1 || chunks.second == 1)) {
                continue;
            }

            CInflater dec(formatOf(v.format));
            std::vector<uint8_t> out;
            CHECK(testdata::Run(dec, in, out, chunks.first, chunks.second) == CODEC_END);
            CHECK(out == want);
        }

        if (v.format >= 1) {
            CInflater autoDec(EDFMT_AUTO);
            std::vector<uint8_t> out;
            CHECK(testdata::Run(autoDec, in, out) == CODEC_END);
            CHECK(out == want);
        }
    }
}

TEST_CASE("gzip header fields and members are reported") {
    for (const fixtures::SVector& v : fixtures::fixtures_deflate_vectors_hpp_list) {
        std::string name = v.name;
        std::vector<uint8_t> in(v.data, v.data + v.size);
        std::vector<uint8_t> out;
        if (name == "gzip_fields") {
            CInflater dec(EDFMT_GZIP);
            REQUIRE(testdata::Run(dec, in, out) == CODEC_END);
            CHECK(dec.gzipHeader().name == "hello.txt");
            CHECK(dec.gzipHeader().comment == "a comment");
            CHECK(dec.gzipHeader().mtime == 1700000000u);
            CHECK(dec.gzipHeader().extra.size() == 6);
        } else if (name == "gzip_multi") {
            CInflater dec(EDFMT_GZIP);
            REQUIRE(testdata::Run(dec, in, out) == CODEC_END);
            CHECK(dec.members() == 2);
            CHECK(out == expected(v));

            // --> Single-member mode stops after the first member.
            CInflater single(EDFMT_GZIP, false);
            CHECK(testdata::Run(single, in, out) == CODEC_END);
            CHECK(out.size() == 1000);
        }
    }
}

TEST_CASE("deflate round trips at every level and format") {
    std::vector<std::vector<uint8_t>> inputs;
    inputs.push_back({});
    inputs.push_back({ 'x' });
    inputs.push_back(testdata::Random(70000, 1));
    inputs.push_back(testdata::Text(150000, 2));
    inputs.push_back(std::vector<uint8_t>(300000, 0));
    inputs.push_back(testdata::Repeat(600000, 777, 3));
    {
        // --> Mixed: compressible text with random holes.
        std::vector<uint8_t> mix = testdata::Text(100000, 4);
        std::vector<uint8_t> rnd = testdata::Random(30000, 5);
        mix.insert(mix.begin() + 50000, rnd.begin(), rnd.end());
        inputs.push_back(mix);
    }

    for (int32_t level = 0; level <= 9; ++level) {
        for (const auto& data : inputs) {
            CAPTURE(level);
            CAPTURE(data.size());
            roundTrip(data, EDFMT_GZIP, level);
        }
    }

    roundTrip(inputs[3], EDFMT_RAW, 6);
    roundTrip(inputs[3], EDFMT_ZLIB, 9);
    roundTrip(inputs[3], EDFMT_RAW, 1, 1, 0);
    roundTrip(inputs[6], EDFMT_ZLIB, 6, 0, 1);
    roundTrip(inputs[6], EDFMT_GZIP, 9, 333, 77);
}

TEST_CASE("deflate compresses compressible data and levels order sensibly") {
    std::vector<uint8_t> text = testdata::Text(500000, 9);
    size_t sizes[10];
    for (int32_t level = 0; level <= 9; ++level) {
        CDeflater enc(EDFMT_RAW, level);
        std::vector<uint8_t> packed;
        REQUIRE(testdata::Run(enc, text, packed) == CODEC_END);
        sizes[level] = packed.size();
    }

    MESSAGE("text 500000 -> l0 " << sizes[0] << ", l1 " << sizes[1] << ", l6 " << sizes[6] << ", l9 " << sizes[9]);
    CHECK(sizes[0] > text.size());
    CHECK(sizes[1] < text.size() / 3);
    CHECK(sizes[6] <= sizes[1]);
    CHECK(sizes[9] <= sizes[6] + sizes[6] / 100);

    std::vector<uint8_t> zeros(1 << 20, 0);
    CDeflater enc(EDFMT_RAW, 6);
    std::vector<uint8_t> packed;
    REQUIRE(testdata::Run(enc, zeros, packed) == CODEC_END);
    CHECK(packed.size() < 2000);

    std::vector<uint8_t> rnd = testdata::Random(200000, 10);
    CDeflater enc2(EDFMT_RAW, 9);
    REQUIRE(testdata::Run(enc2, rnd, packed) == CODEC_END);
    // --> Incompressible data falls back to stored blocks: at most a few bytes per 64 KiB.
    CHECK(packed.size() < rnd.size() + rnd.size() / 1000);
}

TEST_CASE("Huffman length limiting survives skewed (Fibonacci) frequencies") {
    // --> Symbol counts growing like Fibonacci numbers produce an unlimited code deeper than 15.
    std::vector<uint8_t> data;
    uint64_t a = 1;
    uint64_t b = 1;
    for (int sym = 0; sym < 26; ++sym) {
        for (uint64_t i = 0; i < a; ++i) {
            data.push_back(uint8_t('a' + sym));
        }

        uint64_t c = a + b;
        a = b;
        b = c;
    }

    // --> Shuffle so LZ77 finds few matches and Huffman coding dominates.
    testdata::Rng r(99);
    for (size_t i = data.size(); i > 1; --i) {
        std::swap(data[i - 1], data[r.next() % i]);
    }

    for (int32_t level : { 1, 6, 9 }) {
        roundTrip(data, EDFMT_RAW, level);
    }
}

TEST_CASE("inflate rejects corrupt and truncated input") {
    std::vector<uint8_t> text = testdata::Text(20000, 21);
    CDeflater enc(EDFMT_GZIP, 6);
    std::vector<uint8_t> gz;
    REQUIRE(testdata::Run(enc, text, gz) == CODEC_END);

    auto decode = [](EDeflateFormat fmt, const std::vector<uint8_t>& in) {
        CInflater dec(fmt);
        std::vector<uint8_t> out;
        return testdata::Run(dec, in, out);
    };

    SUBCASE("bad CRC and ISIZE") {
        std::vector<uint8_t> bad = gz;
        bad[bad.size() - 8] ^= 1;
        CHECK(decode(EDFMT_GZIP, bad) == -EBADMSG);
        bad = gz;
        bad[bad.size() - 1] ^= 1;
        CHECK(decode(EDFMT_GZIP, bad) == -EBADMSG);
    }

    SUBCASE("bad adler32") {
        CDeflater z(EDFMT_ZLIB, 6);
        std::vector<uint8_t> zl;
        REQUIRE(testdata::Run(z, text, zl) == CODEC_END);
        zl.back() ^= 0x80;
        CHECK(decode(EDFMT_ZLIB, zl) == -EBADMSG);
    }

    SUBCASE("bad magic and header") {
        std::vector<uint8_t> bad = gz;
        bad[1] = 0x8C;
        CHECK(decode(EDFMT_GZIP, bad) == -EBADMSG);
        CHECK(decode(EDFMT_ZLIB, { 0x78, 0x9D, 0x00 }) == -EBADMSG);
    }

    SUBCASE("invalid block type") {
        CHECK(decode(EDFMT_RAW, { 0x07, 0x00 }) == -EBADMSG);
    }

    SUBCASE("stored block with bad NLEN") {
        CHECK(decode(EDFMT_RAW, { 0x01, 0x05, 0x00, 0xFA, 0xF0, 'a', 'b', 'c', 'd', 'e' }) == -EBADMSG);
        CHECK(decode(EDFMT_RAW, { 0x01, 0x05, 0x00, 0xFA, 0xFF, 'a', 'b', 'c', 'd', 'e' }) == CODEC_END);
    }

    SUBCASE("over-subscribed dynamic code") {
        // --> Dynamic block, HLIT 257, HDIST 1, HCLEN 4: code lengths 16,17,18,0 all = 1 (over-subscribed).
        CHECK(decode(EDFMT_RAW, { 0x05, 0x00, 0x92, 0x04, 0x00 }) == -EBADMSG);
    }

    SUBCASE("distance too far back") {
        // --> Fixed block: length-3 match (code 257 = 0000001) at distance 1 with no history.
        CHECK(decode(EDFMT_RAW, { 0x03, 0x02, 0x00 }) == -EBADMSG);
    }

    SUBCASE("trailing garbage after the last member") {
        std::vector<uint8_t> bad = gz;
        bad.push_back(0);
        bad.push_back(0);
        bad.push_back(0);
        CHECK(decode(EDFMT_GZIP, bad) == -EBADMSG);
    }

    SUBCASE("every truncation fails") {
        for (size_t n = 0; n < gz.size(); n += (n < 64 ? 1 : 97)) {
            std::vector<uint8_t> cut(gz.begin(), gz.begin() + n);
            int32_t rc = decode(EDFMT_GZIP, cut);
            CAPTURE(n);
            CHECK((rc == -ENODATA || rc == -EBADMSG));
        }
    }

    SUBCASE("random corruption never crashes and never passes silently") {
        testdata::Rng r(1234);
        int32_t ok = 0;
        for (int32_t iter = 0; iter < 1500; ++iter) {
            std::vector<uint8_t> bad = gz;
            int32_t flips = 1 + int32_t(r.next() % 4);
            for (int32_t k = 0; k < flips; ++k) {
                bad[10 + r.next() % (bad.size() - 10)] ^= uint8_t(1u << (r.next() % 8));
            }

            CInflater dec(EDFMT_GZIP);
            std::vector<uint8_t> out;
            int32_t rc = testdata::Run(dec, bad, out);
            if (rc == CODEC_END) {
                ok++;
            } else {
                CHECK(rc < 0);
            }
        }

        // --> CRC-32 catches essentially every corruption that still parses.
        CHECK(ok == 0);
    }
}

TEST_CASE("interoperates with the system gzip binary") {
    if (!haveTool("gzip")) {
        MESSAGE("gzip binary not found, skipping");
        return;
    }

    char dir[] = "/tmp/sbox-archive-gzip-XXXXXX";
    REQUIRE(::mkdtemp(dir) != nullptr);
    std::string base = dir;
    std::vector<uint8_t> data = testdata::Text(300000, 31);
    data.insert(data.end(), 5000, 'z');

    for (int32_t level : { 1, 6, 9 }) {
        CDeflater enc(EDFMT_GZIP, level);
        std::vector<uint8_t> gz;
        REQUIRE(testdata::Run(enc, data, gz) == CODEC_END);
        writeFile(base + "/ours.gz", gz);
        REQUIRE(std::system(("gzip -dc " + base + "/ours.gz > " + base + "/ours.out").c_str()) == 0);
        CHECK(readFile(base + "/ours.out") == data);
    }

    writeFile(base + "/plain", data);
    REQUIRE(std::system(("gzip -9 -c " + base + "/plain > " + base + "/theirs.gz && gzip -1 -c " + base
                         + "/plain >> " + base + "/theirs.gz").c_str()) == 0);
    std::vector<uint8_t> theirs = readFile(base + "/theirs.gz");
    CInflater dec(EDFMT_GZIP);
    std::vector<uint8_t> out;
    REQUIRE(testdata::Run(dec, theirs, out, 1000, 0) == CODEC_END);
    std::vector<uint8_t> twice = data;
    twice.insert(twice.end(), data.begin(), data.end());
    CHECK(out == twice);
    CHECK(dec.members() == 2);

    CHECK(std::system(("rm -rf " + base).c_str()) == 0);
}

TEST_CASE("throughput (informational)") {
#ifdef NDEBUG
    std::vector<uint8_t> data = testdata::Text(16 << 20, 77);
#else
    // --> Unoptimised builds are an order of magnitude slower; keep the run short.
    std::vector<uint8_t> data = testdata::Text(4 << 20, 77);
#endif
    for (int32_t level : { 1, 6, 9 }) {
        auto t0 = std::chrono::steady_clock::now();
        CDeflater enc(EDFMT_GZIP, level);
        std::vector<uint8_t> gz;
        REQUIRE(testdata::Run(enc, data, gz) == CODEC_END);
        auto t1 = std::chrono::steady_clock::now();
        CInflater dec(EDFMT_GZIP);
        std::vector<uint8_t> out;
        REQUIRE(testdata::Run(dec, gz, out) == CODEC_END);
        auto t2 = std::chrono::steady_clock::now();
        CHECK(out.size() == data.size());
        double mb = double(data.size()) / 1e6;
        double ct = std::chrono::duration<double>(t1 - t0).count();
        double dt = std::chrono::duration<double>(t2 - t1).count();
        MESSAGE("level " << level << ": ratio " << double(gz.size()) / double(data.size()) << ", deflate "
                << mb / ct << " MB/s, inflate " << mb / dt << " MB/s");
    }

    std::vector<uint8_t> big(32 << 20);
    for (size_t i = 0; i < big.size(); i += 4) {
        big[i] = uint8_t(i >> 12);
    }

    auto t0 = std::chrono::steady_clock::now();
    uint32_t crc = CCrc32::compute(BytesOf(big));
    auto t1 = std::chrono::steady_clock::now();
    MESSAGE("crc32 " << double(big.size()) / 1e6 / std::chrono::duration<double>(t1 - t0).count() << " MB/s (" << crc << ")");
}
