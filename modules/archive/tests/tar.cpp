#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/archive/tar.hpp>
#include "fixtures/testdata.hpp"
#include "fixtures/tar_vectors.hpp"
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <unistd.h>

using namespace sbox;
using namespace sbox::archive;

namespace {

    /* An entry with its data, as collected by the handler below. */
    struct Item {
        STarEntry entry;
        std::string data;
    };

    /* Handler that records everything. */
    class Collector : public ITarHandler {
    public:
        std::vector<Item> items;
        bool ended = false;
        int32_t endCount = 0;

        int32_t onEntry(const STarEntry& entry) override {
            items.push_back(Item{ entry, std::string() });
            return SBOX_OK;
        }

        int32_t onData(const SReadOnlyByteSpan& data) override {
            items.back().data.append(reinterpret_cast<const char*>(data.data), data.size);
            return SBOX_OK;
        }

        int32_t onEntryEnd() override {
            endCount++;
            return SBOX_OK;
        }

        int32_t onEnd() override {
            ended = true;
            return SBOX_OK;
        }

        const Item* find(const std::string& path) const {
            for (const Item& i : items) {
                if (i.entry.path == path) {
                    return &i;
                }
            }

            return nullptr;
        }
    };

    /* Parses a whole buffer through CTarSink in chunks. */
    int32_t parse(const std::vector<uint8_t>& tar, Collector& c, size_t chunk = 0) {
        CTarSink sink(c);
        size_t step = chunk ? chunk : tar.size();
        for (size_t i = 0; i < tar.size(); i += step) {
            int32_t rc = sink.write(SReadOnlyByteSpan(tar.data() + i, std::min(step, tar.size() - i)));
            if (rc < 0) {
                return rc;
            }
        }

        return sink.finish();
    }

    std::vector<uint8_t> fixture(const char* name) {
        for (const fixtures::SVector& v : fixtures::fixtures_tar_vectors_hpp_list) {
            if (std::string(v.name) == name) {
                return std::vector<uint8_t>(v.data, v.data + v.size);
            }
        }

        FAIL("missing fixture");
        return {};
    }

    std::string xattr(const STarEntry& e, const std::string& name) {
        for (const auto& x : e.xattrs) {
            if (x.first == name) {
                return x.second;
            }
        }

        return "<none>";
    }

    const std::string LONG_DIR = std::string(60, 'd') + "/" + std::string(60, 'e') + "/";
    const std::string LONG_NAME = LONG_DIR + std::string(80, 'f');
    const std::string LONG_LINK = "/target/" + std::string(120, 't');

}

TEST_CASE("python tarfile archives parse in all formats and chunkings") {
    for (const char* fmt : { "tar_gnu", "tar_pax", "tar_ustar" }) {
        CAPTURE(fmt);
        std::vector<uint8_t> tar = fixture(fmt);
        for (size_t chunk : { size_t(0), size_t(1), size_t(100), size_t(511), size_t(513) }) {
            Collector c;
            REQUIRE(parse(tar, c, chunk) == SBOX_OK);
            CHECK(c.ended);
            CHECK(size_t(c.endCount) == c.items.size());

            const Item* dir = c.find("dir/");
            REQUIRE(dir != nullptr);
            CHECK(dir->entry.type == ETAR_DIR);
            CHECK(dir->entry.mode == 0755u);
            CHECK(dir->entry.uname == "u1");

            const Item* file = c.find("dir/file.txt");
            REQUIRE(file != nullptr);
            CHECK(file->entry.type == ETAR_FILE);
            CHECK(file->data == "hello world\n");
            CHECK(file->entry.uid == 1000);
            CHECK(file->entry.gname == "staff");
            CHECK(file->entry.mtime.sec == 1600000001);

            const Item* sym = c.find("dir/sym");
            REQUIRE(sym != nullptr);
            CHECK(sym->entry.type == ETAR_SYMLINK);
            CHECK(sym->entry.linkPath == "file.txt");

            const Item* hard = c.find("dir/hard");
            REQUIRE(hard != nullptr);
            CHECK(hard->entry.type == ETAR_HARDLINK);
            CHECK(hard->entry.linkPath == "dir/file.txt");
            CHECK(hard->entry.size == 0);

            const Item* chr = c.find("dir/chr");
            REQUIRE(chr != nullptr);
            CHECK(chr->entry.type == ETAR_CHAR);
            CHECK(chr->entry.devMajor == 1);
            CHECK(chr->entry.devMinor == 3);
            CHECK(c.find("dir/blk")->entry.devMajor == 7);
            CHECK(c.find("dir/fifo")->entry.type == ETAR_FIFO);

            if (std::string(fmt) == "tar_ustar") {
                const Item* split = c.find(LONG_DIR + std::string(40, 'f'));
                REQUIRE(split != nullptr);
                CHECK(split->data == "prefix split\n");
            } else {
                const Item* longName = c.find(LONG_NAME);
                REQUIRE(longName != nullptr);
                CHECK(longName->data == "long name\n");
                const Item* longLink = c.find("dir/longlink");
                REQUIRE(longLink != nullptr);
                CHECK(longLink->entry.linkPath == LONG_LINK);
            }

            if (std::string(fmt) == "tar_gnu") {
                const Item* big = c.find("dir/bigid");
                REQUIRE(big != nullptr);
                CHECK(big->entry.uid == (int64_t(1) << 30));
                CHECK(big->entry.gid == (int64_t(1) << 21) + 5);
            }

            if (std::string(fmt) == "tar_pax") {
                const Item* x = c.find("dir/xattr");
                REQUIRE(x != nullptr);
                CHECK(x->data == "abc");
                CHECK(x->entry.mtime.sec == 1600000010);
                CHECK(x->entry.mtime.nsec == 250000000u);
                CHECK(x->entry.uid == (int64_t(1) << 30));
                CHECK(x->entry.uname == std::string(40, 'u'));
                CHECK(xattr(x->entry, "user.foo") == "bar");
                CHECK(xattr(x->entry, "security.capability") == std::string("\x01\x00\x00\x02", 4));
                CHECK(xattr(x->entry, "user.lib x") == "libval");
                bool sawComment = false;
                for (const auto& r : x->entry.paxRecords) {
                    sawComment = sawComment || (r.first == "comment" && r.second == "global");
                }

                CHECK(sawComment);
            }
        }
    }
}

TEST_CASE("pull reader walks entries and skips unread data") {
    std::vector<uint8_t> tar = fixture("tar_pax");
    CMemorySource src(BytesOf(tar));
    CTarReader reader(src);
    STarEntry e;
    std::vector<std::string> names;
    int32_t rc;
    while ((rc = reader.next(e)) == 1) {
        names.push_back(e.path);
        if (e.path == "dir/file.txt") {
            uint8_t buf[5];
            std::string got;
            for (;;) {
                SIoResult r = reader.read(SByteSpan(buf, sizeof(buf)));
                REQUIRE(r.ok());
                if (r.bytes == 0) {
                    break;
                }

                got.append(reinterpret_cast<char*>(buf), r.bytes);
            }

            CHECK(got == "hello world\n");
        }
    }

    CHECK(rc == 0);
    CHECK(names.size() == 10);
    CHECK(names.front() == "dir/");
}

TEST_CASE("writer round trips in every format") {
    for (ETarFormat fmt : { ETFMT_PAX, ETFMT_GNU, ETFMT_USTAR }) {
        CAPTURE(int(fmt));
        std::vector<uint8_t> tar;
        CVectorSink sink(tar);
        CTarWriter w(sink, fmt);

        STarEntry d;
        d.type = ETAR_DIR;
        d.path = "a";
        d.mode = 01777;
        d.mtime.sec = 12345;
        REQUIRE(w.writeEntry(d) == SBOX_OK);

        STarEntry f;
        f.path = "a/file";
        f.mode = 04755;
        f.uid = 7;
        f.gid = 8;
        f.uname = "user";
        f.gname = "group";
        std::string payload = testdata::Str(testdata::Text(1500, 3));
        f.size = payload.size();
        f.mtime.sec = 1700000000;
        REQUIRE(w.writeHeader(f) == SBOX_OK);
        REQUIRE(w.writeData(BytesOf(std::string_view(payload).substr(0, 700))) == SBOX_OK);
        CHECK(w.writeEntry(d) == -EINVAL);
        REQUIRE(w.writeData(BytesOf(std::string_view(payload).substr(700))) == SBOX_OK);

        STarEntry l;
        l.type = ETAR_SYMLINK;
        l.path = "a/link";
        l.linkPath = "../x/y";
        REQUIRE(w.writeEntry(l) == SBOX_OK);

        STarEntry c;
        c.type = ETAR_CHAR;
        c.path = "a/null";
        c.devMajor = 1;
        c.devMinor = 3;
        REQUIRE(w.writeEntry(c) == SBOX_OK);

        STarEntry split;
        split.path = LONG_DIR + std::string(40, 'f');
        split.size = 1;
        REQUIRE(w.writeEntry(split, BytesOf("z")) == SBOX_OK);

        STarEntry longEntry;
        longEntry.path = LONG_NAME;
        longEntry.type = ETAR_SYMLINK;
        longEntry.linkPath = LONG_LINK;
        STarEntry bigId;
        bigId.path = "a/big";
        bigId.uid = int64_t(1) << 33;
        bigId.mtime.sec = -100;
        STarEntry xa;
        xa.path = "a/xattr";
        xa.xattrs.push_back({ "user.k", std::string("v\0w", 3) });
        xa.mtime = STarTime{ 5, 123456789 };

        if (fmt == ETFMT_USTAR) {
            CHECK(w.writeEntry(longEntry) == -ENAMETOOLONG);
            CHECK(w.writeEntry(bigId) == -EOVERFLOW);
            CHECK(w.writeEntry(xa) == -ENOTSUP);
        } else {
            REQUIRE(w.writeEntry(longEntry) == SBOX_OK);
            REQUIRE(w.writeEntry(bigId) == SBOX_OK);
            REQUIRE(w.writeEntry(xa) == SBOX_OK);
        }

        REQUIRE(w.finish() == SBOX_OK);
        CHECK(tar.size() % 512 == 0);

        Collector col;
        REQUIRE(parse(tar, col, 333) == SBOX_OK);
        CHECK(col.ended);
        REQUIRE(col.find("a/") != nullptr);
        CHECK(col.find("a/")->entry.mode == 01777u);
        const Item* rf = col.find("a/file");
        REQUIRE(rf != nullptr);
        CHECK(rf->data == payload);
        CHECK(rf->entry.mode == 04755u);
        CHECK(rf->entry.uname == "user");
        CHECK(col.find("a/link")->entry.linkPath == "../x/y");
        CHECK(col.find("a/null")->entry.devMinor == 3);
        CHECK(col.find(split.path) != nullptr);
        if (fmt != ETFMT_USTAR) {
            REQUIRE(col.find(LONG_NAME) != nullptr);
            CHECK(col.find(LONG_NAME)->entry.linkPath == LONG_LINK);
            CHECK(col.find("a/big")->entry.uid == (int64_t(1) << 33));
            CHECK(col.find("a/big")->entry.mtime.sec == -100);
            CHECK(xattr(col.find("a/xattr")->entry, "user.k") == std::string("v\0w", 3));
            if (fmt == ETFMT_PAX) {
                CHECK(col.find("a/xattr")->entry.mtime.nsec == 123456789u);
            }
        }
    }
}

TEST_CASE("large sizes use PAX records or base-256") {
    for (ETarFormat fmt : { ETFMT_PAX, ETFMT_GNU }) {
        std::vector<uint8_t> tar;
        CVectorSink sink(tar);
        CTarWriter w(sink, fmt);
        STarEntry f;
        f.path = "huge";
        f.size = uint64_t(10) << 30;
        REQUIRE(w.writeHeader(f) == SBOX_OK);

        // --> Only parse the header(s): feed what was written and check the announced size.
        CTarParser p;
        size_t consumed = 0;
        ETarEvent ev = ETEV_NEED_INPUT;
        SReadOnlyByteSpan data;
        SReadOnlyByteSpan in = BytesOf(tar);
        do {
            REQUIRE(p.next(in, consumed, ev, data) == SBOX_OK);
            in = in.slice(consumed);
        } while (ev == ETEV_NEED_INPUT && in.size);

        REQUIRE(ev == ETEV_ENTRY);
        CHECK(p.entry().size == (uint64_t(10) << 30));
    }
}

TEST_CASE("malformed archives are rejected") {
    std::vector<uint8_t> tar = fixture("tar_ustar");

    SUBCASE("bad checksum") {
        std::vector<uint8_t> bad = tar;
        bad[0] ^= 1;
        Collector c;
        CHECK(parse(bad, c) == -EBADMSG);
    }

    SUBCASE("bad octal") {
        std::vector<uint8_t> bad = tar;
        bad[124] = '9';
        // --> Re-seal the checksum so only the number is wrong.
        std::memset(bad.data() + 148, ' ', 8);
        uint32_t sum = 0;
        for (size_t i = 0; i < 512; ++i) {
            sum += bad[i];
        }

        std::snprintf(reinterpret_cast<char*>(bad.data() + 148), 8, "%06o", sum);
        Collector c;
        CHECK(parse(bad, c) == -EBADMSG);
    }

    SUBCASE("truncated archive") {
        std::vector<uint8_t> cut(tar.begin(), tar.begin() + 1024 + 100);
        Collector c;
        CHECK(parse(cut, c) == -ENODATA);
    }

    SUBCASE("missing end marker is tolerated at an entry boundary") {
        Collector c0;
        REQUIRE(parse(tar, c0) == SBOX_OK);
        std::vector<uint8_t> noEnd;
        CVectorSink sink(noEnd);
        CTarWriter w(sink);
        STarEntry f;
        f.path = "x";
        f.size = 3;
        REQUIRE(w.writeEntry(f, BytesOf("abc")) == SBOX_OK);
        Collector c;
        CHECK(parse(noEnd, c) == SBOX_OK);
        CHECK(c.items.size() == 1);
        CHECK(c.ended);
    }

    SUBCASE("sparse entries are not supported") {
        std::vector<uint8_t> bad;
        CVectorSink sink(bad);
        CTarWriter w(sink);
        STarEntry f;
        f.path = "sparse";
        f.paxRecords.push_back({ "GNU.sparse.major", "1" });
        REQUIRE(w.writeEntry(f) == SBOX_OK);
        REQUIRE(w.finish() == SBOX_OK);
        Collector c;
        CHECK(parse(bad, c) == -ENOTSUP);
    }

    SUBCASE("oversized PAX header") {
        std::vector<uint8_t> bad;
        CVectorSink sink(bad);
        CTarWriter w(sink);
        STarEntry f;
        f.path = "p";
        f.paxRecords.push_back({ "comment", std::string(2 << 20, 'c') });
        REQUIRE(w.writeEntry(f) == SBOX_OK);
        Collector c;
        CHECK(parse(bad, c) == -EFBIG);
    }

    SUBCASE("garbage PAX record") {
        std::vector<uint8_t> bad;
        CVectorSink sink(bad);
        CTarWriter w(sink);
        STarEntry f;
        f.path = "p";
        f.paxRecords.push_back({ "size", "-5" });
        REQUIRE(w.writeEntry(f) == SBOX_OK);
        Collector c;
        CHECK(parse(bad, c) == -EBADMSG);
    }
}

TEST_CASE("random corruption never crashes the parser") {
    std::vector<uint8_t> tar = fixture("tar_pax");
    testdata::Rng r(777);
    int32_t failures = 0;
    for (int32_t iter = 0; iter < 3000; ++iter) {
        std::vector<uint8_t> bad = tar;
        int32_t flips = 1 + int32_t(r.next() % 8);
        for (int32_t k = 0; k < flips; ++k) {
            // --> Mostly the metadata area (headers and PAX records live in the first blocks).
            size_t pos = (r.next() & 1) ? r.next() % 4096 : r.next() % bad.size();
            bad[pos] = uint8_t(r.next());
        }

        Collector c;
        int32_t rc = parse(bad, c, 1 + r.next() % 2000);
        failures += rc < 0;
        CHECK((rc == SBOX_OK || rc == -EBADMSG || rc == -ENODATA || rc == -ENOTSUP || rc == -EFBIG));
    }

    CHECK(failures > 0);
}

TEST_CASE("system tar reads our archives") {
    if (std::system("command -v tar >/dev/null 2>&1") != 0) {
        MESSAGE("tar binary not found, skipping");
        return;
    }

    char dir[] = "/tmp/sbox-archive-tar-XXXXXX";
    REQUIRE(::mkdtemp(dir) != nullptr);
    std::string base = dir;
    for (ETarFormat fmt : { ETFMT_PAX, ETFMT_GNU }) {
        std::vector<uint8_t> tar;
        CVectorSink sink(tar);
        CTarWriter w(sink, fmt);
        STarEntry d;
        d.type = ETAR_DIR;
        d.path = LONG_DIR;
        d.mode = 0755;
        REQUIRE(w.writeEntry(d) == SBOX_OK);
        STarEntry f;
        f.path = LONG_NAME;
        f.mode = 0644;
        f.size = 6;
        REQUIRE(w.writeEntry(f, BytesOf("hello\n")) == SBOX_OK);
        REQUIRE(w.finish() == SBOX_OK);

        std::string path = base + "/t.tar";
        FILE* fp = std::fopen(path.c_str(), "wb");
        REQUIRE(fp != nullptr);
        REQUIRE(std::fwrite(tar.data(), 1, tar.size(), fp) == tar.size());
        std::fclose(fp);
        std::string out = base + "/x" + std::to_string(int(fmt));
        REQUIRE(std::system(("mkdir -p " + out + " && tar -xf " + path + " -C " + out).c_str()) == 0);
        FILE* rf = std::fopen((out + "/" + LONG_NAME).c_str(), "rb");
        REQUIRE(rf != nullptr);
        char buf[16] = { 0 };
        CHECK(std::fread(buf, 1, sizeof(buf), rf) == 6);
        std::fclose(rf);
        CHECK(std::string(buf) == "hello\n");
    }

    CHECK(std::system(("rm -rf " + base).c_str()) == 0);
}
