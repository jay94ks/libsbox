#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/file.hpp>
#include <unistd.h>

using namespace sbox;

TEST_CASE("makeDirs, writeAtomic, readAll and removeTree") {
    char base[] = "/tmp/sbox-core-file-XXXXXX";
    REQUIRE(::mkdtemp(base) != nullptr);

    std::string deep = CFile::join(base, "a/b/c");
    CHECK(CFile::makeDirs(deep) == SBOX_OK);
    CHECK(CFile::makeDirs(deep) == SBOX_OK);

    std::string file = CFile::join(deep, "f.txt");
    CHECK(CFile::writeAtomic(file, "line1\nline2\n") == SBOX_OK);

    std::string text;
    CHECK(CFile::readAll(file, text) == SBOX_OK);
    CHECK(text == "line1\nline2\n");
    CHECK(CFile::splitLines(text).size() == 2);
    CHECK(CFile::readAll(file, text, 3) == -EFBIG);

    CHECK(::symlink("/etc", CFile::join(base, "a/link").c_str()) == 0);
    CHECK(CFile::removeTree(base) == SBOX_OK);
    CHECK_FALSE(CFile::exists(base));
    CHECK(CFile::exists("/etc/hostname") == CFile::exists("/etc/hostname"));
    CHECK(CFile::removeTree(base) == SBOX_OK);
}

TEST_CASE("join normalises separators") {
    CHECK(CFile::join("/a/", "/b") == "/a/b");
    CHECK(CFile::join("/a", "b") == "/a/b");
    CHECK(CFile::join("", "b") == "/b");
}
