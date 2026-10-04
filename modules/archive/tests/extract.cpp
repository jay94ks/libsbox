#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/archive/extract.hpp>
#include <sbox/archive/tree.hpp>
#include <sbox/archive/deflate.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include "fixtures/testdata.hpp"
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

using namespace sbox;
using namespace sbox::archive;

namespace {

    /* A unique temporary directory removed on scope exit. */
    struct TempDir {
        std::string path;

        explicit TempDir(const char* tag = "x") {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "/tmp/sbox-archive-%s-XXXXXX", tag);
            REQUIRE(::mkdtemp(buf) != nullptr);
            path = buf;
        }

        ~TempDir() {
            CFile::removeTree(path);
        }

        std::string operator/(const std::string& rel) const {
            return path + "/" + rel;
        }
    };

    /* Builds an archive in memory. */
    struct TarBuilder {
        std::vector<uint8_t> bytes;
        CVectorSink sink{ bytes };
        CTarWriter writer{ sink };

        TarBuilder& dir(const std::string& path, uint32_t mode = 0755) {
            STarEntry e;
            e.type = ETAR_DIR;
            e.path = path;
            e.mode = mode;
            e.mtime.sec = 1500000000;
            REQUIRE(writer.writeEntry(e) == SBOX_OK);
            return *this;
        }

        TarBuilder& file(const std::string& path, const std::string& data, uint32_t mode = 0644, int64_t uid = 0, int64_t gid = 0) {
            STarEntry e;
            e.path = path;
            e.mode = mode;
            e.size = data.size();
            e.uid = uid;
            e.gid = gid;
            e.mtime.sec = 1500000001;
            REQUIRE(writer.writeEntry(e, BytesOf(data)) == SBOX_OK);
            return *this;
        }

        TarBuilder& entry(const STarEntry& e, const std::string& data = std::string()) {
            REQUIRE(writer.writeEntry(e, BytesOf(data)) == SBOX_OK);
            return *this;
        }

        TarBuilder& symlink(const std::string& path, const std::string& target) {
            STarEntry e;
            e.type = ETAR_SYMLINK;
            e.path = path;
            e.linkPath = target;
            e.mode = 0777;
            return entry(e);
        }

        TarBuilder& hardlink(const std::string& path, const std::string& target) {
            STarEntry e;
            e.type = ETAR_HARDLINK;
            e.path = path;
            e.linkPath = target;
            return entry(e);
        }

        std::vector<uint8_t> done() {
            REQUIRE(writer.finish() == SBOX_OK);
            return bytes;
        }
    };

    int32_t extract(const std::vector<uint8_t>& tar, const std::string& root, const SExtractOptions& opt = SExtractOptions(),
                    SExtractStats* stats = nullptr) {
        CMemorySource src(BytesOf(tar));
        return ExtractArchive(src, root, opt, ECOMP_AUTO, SPipelineHooks(), stats);
    }

    std::string readText(const std::string& path) {
        std::string s;
        CFile::readAll(path, s);
        return s;
    }

    bool isLink(const std::string& path) {
        struct stat st{};
        return ::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
    }

    struct stat lst(const std::string& path) {
        struct stat st{};
        REQUIRE(::lstat(path.c_str(), &st) == 0);
        return st;
    }

    std::string getX(const std::string& path, const char* name) {
        char buf[256];
        ssize_t n = ::lgetxattr(path.c_str(), name, buf, sizeof(buf));
        return n < 0 ? std::string("<none>") : std::string(buf, size_t(n));
    }

    /* True when `prefix`.* xattrs can be set on files in /tmp. */
    bool xattrSupported(const char* name) {
        TempDir t("xa");
        std::string f = t / "f";
        CFile::writeAtomic(f, "");
        return ::lsetxattr(f.c_str(), name, "1", 1, 0) == 0;
    }

    /* Both resolvers: openat2 and the O_NOFOLLOW walk. */
    const bool RESOLVERS[] = { false, true };

}

TEST_CASE("CleanArchivePath") {
    std::string out;
    CHECK(CleanArchivePath("./a//b/./c/", out) == SBOX_OK);
    CHECK(out == "a/b/c");
    CHECK(CleanArchivePath("/etc/passwd", out) == SBOX_OK);
    CHECK(out == "etc/passwd");
    CHECK(CleanArchivePath("a/../b", out) == SBOX_OK);
    CHECK(out == "b");
    CHECK(CleanArchivePath("./", out) == SBOX_OK);
    CHECK(out.empty());
    CHECK(CleanArchivePath("../../etc/passwd", out) == -EXDEV);
    CHECK(CleanArchivePath("a/../../b", out) == -EXDEV);
    CHECK(CleanArchivePath(std::string_view("a\0b", 3), out) == -EINVAL);
}

TEST_CASE("extracts every entry type with metadata") {
    for (bool walk : RESOLVERS) {
        CAPTURE(walk);
        TempDir root("basic");
        TarBuilder b;
        b.dir("./").dir("d", 0750).file("d/f", "hello", 04755).symlink("d/s", "f").hardlink("d/h", "d/f");
        b.file("implicit/parent/x", "deep");
        STarEntry fifo;
        fifo.type = ETAR_FIFO;
        fifo.path = "d/fifo";
        fifo.mode = 0640;
        b.entry(fifo);
        STarEntry chr;
        chr.type = ETAR_CHAR;
        chr.path = "d/null";
        chr.mode = 0666;
        chr.devMajor = 1;
        chr.devMinor = 3;
        b.entry(chr);
        b.dir("ro", 0555).file("ro/inside", "x", 0444);
        STarEntry t;
        t.path = "timed";
        t.mtime = STarTime{ 1234567890, 500000000 };
        t.size = 1;
        b.entry(t, "t");

        SExtractOptions opt;
        opt.noOpenat2 = walk;
        SExtractStats stats;
        REQUIRE(extract(b.done(), root.path, opt, &stats) == SBOX_OK);

        CHECK(readText(root / "d/f") == "hello");
        CHECK((lst(root / "d/f").st_mode & 07777) == 04755);
        CHECK((lst(root / "d").st_mode & 07777) == 0750);
        CHECK(lst(root / "d").st_mtime == 1500000000);
        CHECK(isLink(root / "d/s"));
        CHECK(lst(root / "d/h").st_ino == lst(root / "d/f").st_ino);
        CHECK(S_ISFIFO(lst(root / "d/fifo").st_mode));
        CHECK((lst(root / "d/fifo").st_mode & 0777) == 0640);
        CHECK(readText(root / "implicit/parent/x") == "deep");
        CHECK((lst(root / "implicit").st_mode & 0777) == 0755);
        CHECK((lst(root / "ro").st_mode & 0777) == 0555);
        CHECK(readText(root / "ro/inside") == "x");
        CHECK(lst(root / "timed").st_mtim.tv_sec == 1234567890);
        CHECK(lst(root / "timed").st_mtim.tv_nsec == 500000000);
        CHECK(lst(root / "d/f").st_mtime == 1500000001);

        if (::geteuid() == 0) {
            REQUIRE(S_ISCHR(lst(root / "d/null").st_mode));
            CHECK(lst(root / "d/null").st_rdev == makedev(1, 3));
            CHECK(stats.devices == 2);
        }

        CHECK(stats.files == 4);
        CHECK(stats.hardlinks == 1);
        CHECK(stats.symlinks == 1);
    }
}

TEST_CASE("paths escaping the root are rejected or skipped") {
    for (bool walk : RESOLVERS) {
        CAPTURE(walk);
        TempDir root("escape");
        TempDir outside("outside");
        std::string rel = "../../../../../../.." + outside.path + "/pwned";
        TarBuilder b;
        b.file(rel, "bad");
        std::vector<uint8_t> tar = b.done();

        SExtractOptions opt;
        opt.noOpenat2 = walk;
        CHECK(extract(tar, root.path, opt) == -EXDEV);
        CHECK_FALSE(CFile::exists(outside / "pwned"));

        opt.skipUnsafe = true;
        int32_t notices = 0;
        opt.notice = [&](const SExtractNotice& n) {
            notices += n.kind == EXN_UNSAFE_SKIPPED;
        };

        SExtractStats stats;
        CHECK(extract(tar, root.path, opt, &stats) == SBOX_OK);
        CHECK(notices == 1);
        CHECK(stats.skipped == 1);
        CHECK_FALSE(CFile::exists(outside / "pwned"));

        // --> Absolute paths are taken relative to the root.
        TarBuilder abs;
        abs.file(outside.path + "/abs", "inside");
        REQUIRE(extract(abs.done(), root.path, opt) == SBOX_OK);
        CHECK_FALSE(CFile::exists(outside / "abs"));
        CHECK(readText(root.path + outside.path + "/abs") == "inside");
    }
}

TEST_CASE("symlinks cannot redirect writes outside the root") {
    for (bool walk : RESOLVERS) {
        CAPTURE(walk);
        TempDir root("symesc");
        TempDir outside("victim");
        REQUIRE(CFile::writeAtomic(outside / "target", "original") == SBOX_OK);

        TarBuilder b;
        // --> Absolute and relative links pointing out, then writes through them. Inside the
        // root they resolve to <root><outside>, which exists there too.
        b.dir(outside.path);
        b.symlink("abs", outside.path);
        b.symlink("rel", "../../../../../../../../../.." + outside.path);
        b.file("abs/target", "pwned-abs");
        b.file("rel/target", "pwned-rel");
        // --> Symlink-then-file: the file must replace the link, not write through it.
        b.symlink("trick", outside.path + "/target");
        b.file("trick", "replaced");
        // --> Symlink-then-dir: the directory must replace the link.
        b.symlink("dirtrick", outside.path);
        b.dir("dirtrick");
        b.file("dirtrick/target", "inside");
        // --> Hardlink through a symlinked directory resolves inside the root.
        b.dir("etc").file("etc/passwd", "fake");
        b.symlink("sysetc", "/etc");
        b.hardlink("linked", "sysetc/passwd");

        SExtractOptions opt;
        opt.noOpenat2 = walk;
        REQUIRE(extract(b.done(), root.path, opt) == SBOX_OK);

        CHECK(readText(outside / "target") == "original");
        CHECK(readText(root.path + outside.path + "/target") == "pwned-rel");
        CHECK_FALSE(isLink(root / "trick"));
        CHECK(readText(root / "trick") == "replaced");
        CHECK_FALSE(isLink(root / "dirtrick"));
        CHECK(readText(root / "dirtrick/target") == "inside");
        CHECK(lst(root / "linked").st_ino == lst(root / "etc/passwd").st_ino);
        CHECK(readText(root / "linked") == "fake");
    }
}

TEST_CASE("hardlinks may not point outside the root") {
    for (bool walk : RESOLVERS) {
        CAPTURE(walk);
        TempDir root("hlesc");
        TarBuilder b;
        b.hardlink("h", "../../../../etc/passwd");
        SExtractOptions opt;
        opt.noOpenat2 = walk;
        CHECK(extract(b.done(), root.path, opt) == -EXDEV);
        CHECK_FALSE(CFile::exists(root / "h"));

        // --> A link to a path that does not exist inside the root fails instead of reaching /etc.
        TarBuilder c;
        c.symlink("s", "/etc").hardlink("h2", "s/passwd");
        CHECK(extract(c.done(), root.path, opt) == -ENOENT);
        CHECK_FALSE(CFile::exists(root / "h2"));
    }
}

TEST_CASE("apply-mode whiteouts flatten layers") {
    TempDir root("apply");
    TarBuilder base;
    base.dir("a").file("a/x", "1").file("a/y", "2").dir("b").file("b/old", "3").dir("b/sub").file("b/sub/deep", "4");
    base.dir("c").file("c/1", "5").file("keep", "6");
    SExtractOptions opt;
    opt.whiteouts = EWHT_APPLY;
    REQUIRE(extract(base.done(), root.path, opt) == SBOX_OK);

    TarBuilder layer;
    layer.file("a/.wh.x", "");
    layer.file("b/.wh..wh..opq", "");
    layer.file("b/new", "7");
    layer.file(".wh.c", "");
    layer.file(".wh.missing", "");
    layer.file("a/.wh..wh.plnk", "");
    SExtractStats stats;
    REQUIRE(extract(layer.done(), root.path, opt, &stats) == SBOX_OK);

    CHECK_FALSE(CFile::exists(root / "a/x"));
    CHECK(readText(root / "a/y") == "2");
    CHECK_FALSE(CFile::exists(root / "b/old"));
    CHECK_FALSE(CFile::exists(root / "b/sub"));
    CHECK(readText(root / "b/new") == "7");
    CHECK_FALSE(CFile::exists(root / "c"));
    CHECK(readText(root / "keep") == "6");
    CHECK_FALSE(CFile::exists(root / "a/.wh.x"));
    CHECK(stats.whiteouts == 5);
}

TEST_CASE("overlay-mode whiteouts produce overlayfs markers") {
    if (::geteuid() != 0 || !xattrSupported("trusted.sbox")) {
        MESSAGE("needs root and trusted xattrs, skipping");
        return;
    }

    TempDir root("ovl");
    TarBuilder layer;
    layer.dir("d").file("d/.wh.gone", "").file("d/.wh..wh..opq", "").file("d/kept", "k");
    layer.file("fresh/.wh..wh..opq", "");
    SExtractOptions opt;
    opt.whiteouts = EWHT_OVERLAY;
    REQUIRE(extract(layer.done(), root.path, opt) == SBOX_OK);

    struct stat st = lst(root / "d/gone");
    CHECK(S_ISCHR(st.st_mode));
    CHECK(st.st_rdev == makedev(0, 0));
    CHECK(getX(root / "d", "trusted.overlay.opaque") == "y");
    CHECK(getX(root / "fresh", "trusted.overlay.opaque") == "y");
    CHECK(readText(root / "d/kept") == "k");
    CHECK_FALSE(CFile::exists(root / "d/.wh.gone"));
}

TEST_CASE("userxattr whiteouts produce xwhiteout files") {
    if (!xattrSupported("user.sbox")) {
        MESSAGE("user xattrs unsupported, skipping");
        return;
    }

    TempDir root("uxa");
    TarBuilder layer;
    layer.dir("d").file("d/.wh.gone", "").dir("o").file("o/.wh..wh..opq", "");
    SExtractOptions opt;
    opt.whiteouts = EWHT_OVERLAY_USERXATTR;
    REQUIRE(extract(layer.done(), root.path, opt) == SBOX_OK);

    struct stat st = lst(root / "d/gone");
    CHECK(S_ISREG(st.st_mode));
    CHECK(st.st_size == 0);
    CHECK(getX(root / "d/gone", "user.overlay.whiteout") != "<none>");
    CHECK(getX(root / "d", "user.overlay.opaque") == "x");
    CHECK(getX(root / "o", "user.overlay.opaque") == "y");
}

TEST_CASE("ownership: id shift and ignore") {
    if (::geteuid() != 0) {
        MESSAGE("needs root to chown, skipping");
        return;
    }

    TempDir root("ids");
    TarBuilder b;
    b.dir("d").file("d/f", "x", 0644, 1000, 2000).symlink("d/l", "f");
    STarEntry nodeE;
    nodeE.type = ETAR_FIFO;
    nodeE.path = "d/p";
    nodeE.uid = 5;
    nodeE.gid = 6;
    b.entry(nodeE);
    std::vector<uint8_t> tar = b.done();

    SExtractOptions opt;
    opt.uidShift = 100000;
    opt.gidShift = 200000;
    REQUIRE(extract(tar, root.path, opt) == SBOX_OK);
    CHECK(lst(root / "d/f").st_uid == 101000u);
    CHECK(lst(root / "d/f").st_gid == 202000u);
    CHECK(lst(root / "d").st_uid == 100000u);
    CHECK(lst(root / "d/l").st_uid == 100000u);
    CHECK(lst(root / "d/p").st_gid == 200006u);

    TempDir root2("ids2");
    opt.ownership = EOWN_IGNORE;
    REQUIRE(extract(tar, root2.path, opt) == SBOX_OK);
    CHECK(lst(root2 / "d/f").st_uid == 0u);

    TempDir root3("ids3");
    opt.ownership = EOWN_PRESERVE;
    opt.uidShift = -5000;
    CHECK(extract(tar, root3.path, opt) == -EOVERFLOW);
}

TEST_CASE("xattrs including security.capability are restored") {
    if (!xattrSupported("user.sbox")) {
        MESSAGE("user xattrs unsupported, skipping");
        return;
    }

    TempDir root("xattr");
    TarBuilder b;
    STarEntry f;
    f.path = "bin";
    f.mode = 0755;
    f.size = 2;
    f.xattrs.push_back({ "user.note", "hi" });
    // --> VFS_CAP_REVISION_2, permitted = CAP_NET_BIND_SERVICE (bit 10).
    std::string cap("\x00\x00\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    if (::geteuid() == 0) {
        f.xattrs.push_back({ "security.capability", cap });
    }

    b.entry(f, "#!");
    STarEntry d;
    d.type = ETAR_DIR;
    d.path = "dir";
    d.mode = 0755;
    d.xattrs.push_back({ "user.dir", "v" });
    b.entry(d);

    int32_t failures = 0;
    SExtractOptions opt;
    opt.notice = [&](const SExtractNotice& n) {
        failures += n.kind == EXN_XATTR_FAILED;
    };

    REQUIRE(extract(b.done(), root.path, opt) == SBOX_OK);
    CHECK(getX(root / "bin", "user.note") == "hi");
    CHECK(getX(root / "dir", "user.dir") == "v");
    if (::geteuid() == 0 && failures == 0) {
        CHECK(getX(root / "bin", "security.capability") == cap);
    }
}

TEST_CASE("devices can be disabled and are reported") {
    TempDir root("nodev");
    TarBuilder b;
    STarEntry chr;
    chr.type = ETAR_CHAR;
    chr.path = "null";
    chr.devMajor = 1;
    chr.devMinor = 3;
    b.entry(chr);
    SExtractOptions opt;
    opt.devices = false;
    int32_t skipped = 0;
    opt.notice = [&](const SExtractNotice& n) {
        skipped += n.kind == EXN_DEVICE_SKIPPED;
    };

    REQUIRE(extract(b.done(), root.path, opt) == SBOX_OK);
    CHECK(skipped == 1);
    CHECK_FALSE(CFile::exists(root / "null"));
}

namespace {

    /* Recursively describes a tree for comparisons. */
    void describe(const std::string& base, const std::string& rel, std::map<std::string, std::string>& out) {
        std::string path = rel.empty() ? base : base + "/" + rel;
        struct stat st = lst(path);
        char line[512];
        std::snprintf(line, sizeof(line), "mode=%o uid=%u gid=%u", unsigned(st.st_mode), unsigned(st.st_uid), unsigned(st.st_gid));
        std::string d = line;
        if (S_ISREG(st.st_mode)) {
            d += " data=" + readText(path) + " nlink=" + std::to_string(st.st_nlink) + " mtime=" + std::to_string(st.st_mtime);
        } else if (S_ISLNK(st.st_mode)) {
            char t[512];
            ssize_t n = ::readlink(path.c_str(), t, sizeof(t));
            d += " link=" + std::string(t, size_t(n > 0 ? n : 0));
        } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
            d += " rdev=" + std::to_string(st.st_rdev);
        }

        if (!S_ISLNK(st.st_mode)) {
            d += " user.a=" + getX(path, "user.a");
        }

        if (!rel.empty()) {
            out[rel] = d;
        }

        if (S_ISDIR(st.st_mode)) {
            std::vector<std::string> names;
            DIR* dir = ::opendir(path.c_str());
            REQUIRE(dir != nullptr);
            while (struct dirent* e = ::readdir(dir)) {
                if (std::strcmp(e->d_name, ".") && std::strcmp(e->d_name, "..")) {
                    names.push_back(e->d_name);
                }
            }

            ::closedir(dir);
            for (const std::string& n : names) {
                describe(base, rel.empty() ? n : rel + "/" + n, out);
            }
        }
    }

    /* Populates a sample tree. */
    void populate(const std::string& base) {
        REQUIRE(CFile::makeDirs(base + "/a/b/c") == SBOX_OK);
        REQUIRE(CFile::writeAtomic(base + "/a/file", "content", 0640) == SBOX_OK);
        REQUIRE(CFile::writeAtomic(base + "/a/b/big", testdata::Str(testdata::Text(300000, 5)), 0600) == SBOX_OK);
        REQUIRE(CFile::writeAtomic(base + "/a/b/c/empty", "", 0644) == SBOX_OK);
        REQUIRE(::link((base + "/a/file").c_str(), (base + "/a/b/hard").c_str()) == 0);
        REQUIRE(::symlink("../file", (base + "/a/b/sym").c_str()) == 0);
        REQUIRE(::symlink("/absolute/dangling", (base + "/dangling").c_str()) == 0);
        REQUIRE(::mkfifo((base + "/a/fifo").c_str(), 0620) == 0);
        REQUIRE(::chmod((base + "/a/b").c_str(), 02775) == 0);
        if (::geteuid() == 0) {
            REQUIRE(::mknod((base + "/a/null").c_str(), S_IFCHR | 0666, makedev(1, 3)) == 0);
            REQUIRE(::lchown((base + "/a/file").c_str(), 1234, 5678) == 0);
        }

        ::lsetxattr((base + "/a/file").c_str(), "user.a", "xv", 2, 0);
        struct timespec ts[2] = { { 1000, 0 }, { 2000, 0 } };
        REQUIRE(::utimensat(AT_FDCWD, (base + "/a/file").c_str(), ts, AT_SYMLINK_NOFOLLOW) == 0);
    }

}

TEST_CASE("tree -> tar -> extract round trip (push and pull, gzip, digest hooks)") {
    TempDir src("tree-src");
    populate(src.path);
    std::map<std::string, std::string> want;
    describe(src.path, "", want);

    SUBCASE("push writer") {
        std::vector<uint8_t> tar;
        CVectorSink sink(tar);
        CTarWriter w(sink);
        REQUIRE(WriteTree(src.path, w) == SBOX_OK);
        REQUIRE(w.finish() == SBOX_OK);

        TempDir dst("tree-dst");
        REQUIRE(extract(tar, dst.path) == SBOX_OK);
        std::map<std::string, std::string> got;
        describe(dst.path, "", got);
        CHECK(got == want);
    }

    SUBCASE("pull source through gzip with digest hooks") {
        CTreeTarSource tree(src.path);
        uint64_t tarBytes = 0;
        CTapSource tapTar(tree, [&](const SReadOnlyByteSpan& s) { tarBytes += s.size; });
        CCodecSource gz(CreateEncoder(ECOMP_GZIP, 6), tapTar);
        std::vector<uint8_t> packed;
        CVectorSink out(packed);
        REQUIRE(Pump(gz, out) == SBOX_OK);
        CHECK(DetectCompression(BytesOf(packed)) == ECOMP_GZIP);

        TempDir dst("tree-dst2");
        uint64_t seenCompressed = 0;
        uint64_t seenTar = 0;
        SPipelineHooks hooks;
        hooks.compressed = [&](const SReadOnlyByteSpan& s) { seenCompressed += s.size; };
        hooks.uncompressed = [&](const SReadOnlyByteSpan& s) { seenTar += s.size; };
        CMemorySource src2(BytesOf(packed));
        REQUIRE(ExtractArchive(src2, dst.path, SExtractOptions(), ECOMP_AUTO, hooks) == SBOX_OK);
        CHECK(seenCompressed == packed.size());
        CHECK(seenTar == tarBytes);
        std::map<std::string, std::string> got;
        describe(dst.path, "", got);
        CHECK(got == want);
    }

    SUBCASE("prefix, filter and id shift") {
        STreeOptions opt;
        opt.prefix = "layer";
        opt.filter = [](const std::string& rel, const struct stat&) { return rel != "a/b"; };
        std::vector<uint8_t> tar;
        CVectorSink sink(tar);
        CTarWriter w(sink);
        REQUIRE(WriteTree(src.path, w, opt) == SBOX_OK);
        REQUIRE(w.finish() == SBOX_OK);
        CMemorySource ms(BytesOf(tar));
        CTarReader r(ms);
        STarEntry e;
        std::set<std::string> paths;
        while (r.next(e) == 1) {
            paths.insert(e.path);
        }

        CHECK(paths.count("layer/a/") == 1);
        CHECK(paths.count("layer/a/file") == 1);
        CHECK(paths.count("layer/a/b/") == 0);
        CHECK(paths.count("layer/a/b/big") == 0);

        if (::geteuid() == 0) {
            STreeOptions shifted;
            shifted.uidShift = 2000;
            std::vector<uint8_t> t2;
            CVectorSink s2(t2);
            CTarWriter w2(s2);
            CHECK(WriteTree(src.path, w2, shifted) == -EOVERFLOW);
        }
    }
}

TEST_CASE("overlay upper dir converts to .wh. entries and back") {
    if (::geteuid() != 0 || !xattrSupported("trusted.sbox")) {
        MESSAGE("needs root and trusted xattrs, skipping");
        return;
    }

    TempDir upper("upper");
    REQUIRE(CFile::makeDirs(upper / "op") == SBOX_OK);
    REQUIRE(CFile::writeAtomic(upper / "op/new", "n") == SBOX_OK);
    REQUIRE(::lsetxattr((upper / "op").c_str(), "trusted.overlay.opaque", "y", 1, 0) == 0);
    REQUIRE(::mknod((upper / "gone").c_str(), S_IFCHR, makedev(0, 0)) == 0);
    REQUIRE(CFile::writeAtomic(upper / "xw", "") == SBOX_OK);
    REQUIRE(::lsetxattr((upper / "xw").c_str(), "user.overlay.whiteout", "y", 1, 0) == 0);
    REQUIRE(::lsetxattr((upper / "op").c_str(), "trusted.overlay.origin", "zz", 2, 0) == 0);

    STreeOptions opt;
    opt.overlayWhiteouts = true;
    std::vector<uint8_t> tar;
    CVectorSink sink(tar);
    CTarWriter w(sink);
    REQUIRE(WriteTree(upper.path, w, opt) == SBOX_OK);
    REQUIRE(w.finish() == SBOX_OK);

    CMemorySource ms(BytesOf(tar));
    CTarReader r(ms);
    STarEntry e;
    std::vector<std::string> paths;
    while (r.next(e) == 1) {
        paths.push_back(e.path);
        for (const auto& x : e.xattrs) {
            CHECK(x.first.find("overlay.") == std::string::npos);
        }
    }

    std::vector<std::string> want = { ".wh.gone", "op/", "op/.wh..wh..opq", "op/new", ".wh.xw" };
    CHECK(paths == want);

    TempDir again("again");
    SExtractOptions xo;
    xo.whiteouts = EWHT_OVERLAY;
    REQUIRE(extract(tar, again.path, xo) == SBOX_OK);
    CHECK(S_ISCHR(lst(again / "gone").st_mode));
    CHECK(S_ISCHR(lst(again / "xw").st_mode));
    CHECK(getX(again / "op", "trusted.overlay.opaque") == "y");
}

TEST_CASE("corrupt and truncated compressed archives fail") {
    TempDir src("cor-src");
    populate(src.path);
    CTreeTarSource tree(src.path);
    CCodecSource gz(CreateEncoder(ECOMP_GZIP, 1), tree);
    std::vector<uint8_t> packed;
    CVectorSink out(packed);
    REQUIRE(Pump(gz, out) == SBOX_OK);

    TempDir dst("cor-dst");
    std::vector<uint8_t> cut(packed.begin(), packed.begin() + packed.size() / 2);
    CHECK(extract(cut, dst.path) == -ENODATA);

    std::vector<uint8_t> bad = packed;
    bad[bad.size() - 6] ^= 0x40;
    TempDir dst2("cor-dst2");
    CHECK(extract(bad, dst2.path) == -EBADMSG);
}

TEST_CASE("async pipeline: tree -> gzip -> pipe -> extract") {
    TempDir src("async-src");
    populate(src.path);
    std::map<std::string, std::string> want;
    describe(src.path, "", want);
    TempDir dst("async-dst");

    CStream readEnd;
    CStream writeEnd;
    REQUIRE(CPipe::create(readEnd, writeEnd) == SBOX_OK);

    CEventLoop loop;
    int32_t producerRc = -1;
    auto producer = [&]() -> TTask<void> {
        CTreeTarSource tree(src.path);
        CCodecSource gz(CreateEncoder(ECOMP_GZIP, 6), tree);
        producerRc = co_await PumpSourceToStream(gz, writeEnd);
        writeEnd.close();
    };

    uint64_t compressed = 0;
    auto consumer = [&]() -> TTask<int32_t> {
        SPipelineHooks hooks;
        hooks.compressed = [&](const SReadOnlyByteSpan& s) { compressed += s.size; };
        SExtractStats stats;
        int32_t rc = co_await ExtractArchiveAsync(readEnd, dst.path, SExtractOptions(), ECOMP_AUTO, hooks, &stats);
        co_return rc;
    };

    loop.spawn(producer());
    int32_t rc = loop.run(consumer());
    CHECK(rc == SBOX_OK);
    CHECK(producerRc == SBOX_OK);
    CHECK(compressed > 0);
    std::map<std::string, std::string> got;
    describe(dst.path, "", got);
    CHECK(got == want);
}

TEST_CASE("encode/decode IStream adapters over a pipe") {
    CStream readEnd;
    CStream writeEnd;
    REQUIRE(CPipe::create(readEnd, writeEnd) == SBOX_OK);
    std::vector<uint8_t> data = testdata::Text(500000, 8);

    CEventLoop loop;
    auto producer = [&]() -> TTask<void> {
        CEncodeStream enc(writeEnd, std::make_unique<CDeflater>(EDFMT_GZIP, 6));
        for (size_t i = 0; i < data.size(); i += 70000) {
            SIoResult r = co_await enc.send(SReadOnlyByteSpan(data.data() + i, std::min<size_t>(70000, data.size() - i)));
            CHECK(r.ok());
        }

        CHECK(co_await enc.finish() == SBOX_OK);
        writeEnd.close();
    };

    auto consumer = [&]() -> TTask<std::vector<uint8_t>> {
        CDecodeStream dec(readEnd, CreateDecoder(ECOMP_AUTO));
        std::vector<uint8_t> out;
        SIoResult r = co_await dec.recvAll(out);
        CHECK(r.ok());
        co_return out;
    };

    loop.spawn(producer());
    std::vector<uint8_t> got = loop.run(consumer());
    CHECK(got == data);
}

TEST_CASE("file descriptor pipeline: WriteTreeArchive -> file -> ExtractArchive") {
    TempDir src("fd-src");
    populate(src.path);
    std::map<std::string, std::string> want;
    describe(src.path, "", want);
    TempDir work("fd-work");
    std::string blob = work / "layer.tar.gz";

    int fd = ::open(blob.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0);
    uint64_t tarBytes = 0;
    uint64_t gzBytes = 0;
    SPipelineHooks hooks;
    hooks.uncompressed = [&](const SReadOnlyByteSpan& s) { tarBytes += s.size; };
    hooks.compressed = [&](const SReadOnlyByteSpan& s) { gzBytes += s.size; };
    {
        CFdSink sink(fd);
        CHECK(WriteTreeArchive(src.path, sink, ECOMP_GZIP, 9, STreeOptions(), hooks) == SBOX_OK);
    }

    ::close(fd);
    CHECK(uint64_t(lst(blob).st_size) == gzBytes);
    CHECK(tarBytes % 512 == 0);

    TempDir dst("fd-dst");
    fd = ::open(blob.c_str(), O_RDONLY | O_CLOEXEC);
    REQUIRE(fd >= 0);
    CFdSource source(fd);
    SExtractStats stats;
    CHECK(ExtractArchive(source, dst.path, SExtractOptions(), ECOMP_GZIP, SPipelineHooks(), &stats) == SBOX_OK);
    ::close(fd);
    CHECK(stats.bytes > 300000);
    std::map<std::string, std::string> got;
    describe(dst.path, "", got);
    CHECK(got == want);

    std::vector<uint8_t> unused;
    CVectorSink none(unused);
    CHECK(WriteTreeArchive(src.path, none, ECOMP_ZSTD) == -ENOTSUP);
}
