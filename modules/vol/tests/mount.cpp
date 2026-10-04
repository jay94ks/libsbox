#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "testutil.hpp"

#include <sbox/vol/mount.hpp>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

namespace {

    /* Returns the OCI options of a mount object joined with commas. */
    std::string optionsOf(const CJson& mount) {
        std::string out;
        for (const std::string& o : mount.get("options").asStrings()) {
            out += (out.empty() ? "" : ",") + o;
        }

        return out;
    }

}

TEST_CASE("CleanAbsolutePath") {
    std::string out;
    CHECK(CleanAbsolutePath("/a/b", out) == SBOX_OK);
    CHECK(out == "/a/b");
    CHECK(CleanAbsolutePath("//a/./b/../c/", out) == SBOX_OK);
    CHECK(out == "/a/c");
    CHECK(CleanAbsolutePath("/", out) == SBOX_OK);
    CHECK(out == "/");
    CHECK(CleanAbsolutePath("/a/..", out) == SBOX_OK);
    CHECK(out == "/");
    CHECK(CleanAbsolutePath("/..", out) == -EINVAL);
    CHECK(CleanAbsolutePath("rel/path", out) == -EINVAL);
    CHECK(CleanAbsolutePath("", out) == -EINVAL);
}

TEST_CASE("-v translation table") {
    struct Case {
        const char* spec;
        int32_t rc;
        EMountType type;
        const char* source;
        const char* target;
        bool readOnly;
        const char* oci;            // --> Expected OCI options for a resolved source "/SRC" ("" to skip).
    };

    const Case cases[] = {
        { "/data", SBOX_OK, EMT_VOLUME, "", "/data", false, "rbind,rw,rprivate" },
        { "myvol:/data", SBOX_OK, EMT_VOLUME, "myvol", "/data", false, "rbind,rw,rprivate" },
        { "myvol:/data:ro", SBOX_OK, EMT_VOLUME, "myvol", "/data", true, "rbind,ro,rprivate" },
        { "myvol:/data:ro,nocopy", SBOX_OK, EMT_VOLUME, "myvol", "/data", true, "rbind,ro,rprivate" },
        { "/host/dir:/ctr", SBOX_OK, EMT_BIND, "/host/dir", "/ctr", false, "rbind,rw,rprivate" },
        { "/host/dir:/ctr:rw,rshared", SBOX_OK, EMT_BIND, "/host/dir", "/ctr", false, "rbind,rw,rshared" },
        { "/host/dir:/ctr:ro,slave,z", SBOX_OK, EMT_BIND, "/host/dir", "/ctr", true, "rbind,ro,slave" },
        { "/host//dir/../x:/ctr/./y/", SBOX_OK, EMT_BIND, "/host/x", "/ctr/y", false, "" },
        { "/host:/ctr:Z,cached", SBOX_OK, EMT_BIND, "/host", "/ctr", false, "" },
        { "", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "relative", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "/data:rw", -EINVAL, EMT_INVALID, "", "", false, "" },
        { ":/data", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "myvol:/", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "myvol:data", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "a:b:c:d", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "myvol:/data:ro,rw", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "myvol:/data:bogus", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "myvol:/data:rshared", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "/host:/data:nocopy", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "./rel:/data", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "x:/data", -EINVAL, EMT_INVALID, "", "", false, "" },
        { "/host:/data:z,Z", -EINVAL, EMT_INVALID, "", "", false, "" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.spec);
        SMountRequest r;
        std::string error;
        int32_t rc = ParseVolumeFlag(c.spec, r, &error);
        CAPTURE(error);
        CHECK(rc == c.rc);
        if (rc != SBOX_OK) {
            CHECK(!error.empty());
            continue;
        }

        CHECK(r.type == c.type);
        CHECK(r.source == c.source);
        CHECK(r.target == c.target);
        CHECK(r.readOnly == c.readOnly);
        CHECK(r.createHostPath == (c.type == EMT_BIND));
        if (c.oci[0] != '\0') {
            CJson m;
            REQUIRE(BuildOciMount(r, "/SRC", m) == SBOX_OK);
            CHECK(m.get("destination").asString() == c.target);
            CHECK(m.get("type").asString() == "bind");
            CHECK(m.get("source").asString() == "/SRC");
            CHECK(optionsOf(m) == c.oci);
        }
    }

    SMountRequest r;
    REQUIRE(ParseVolumeFlag("v1:/x:nocopy,ro", r) == SBOX_OK);
    CHECK(r.noCopy);
    REQUIRE(ParseVolumeFlag("/h:/x:z", r) == SBOX_OK);
    CHECK(r.selinuxLabel == "z");
}

TEST_CASE("--mount translation table") {
    struct Case {
        const char* spec;
        int32_t rc;
        EMountType type;
        const char* source;
        const char* target;
        const char* oci;
    };

    const Case cases[] = {
        { "type=volume,source=data,target=/var/lib/data", SBOX_OK, EMT_VOLUME, "data", "/var/lib/data", "rbind,rw,rprivate" },
        { "src=data,dst=/d,readonly", SBOX_OK, EMT_VOLUME, "data", "/d", "rbind,ro,rprivate" },
        { "target=/anon", SBOX_OK, EMT_VOLUME, "", "/anon", "rbind,rw,rprivate" },
        { "type=volume,src=data,destination=/d,ro=true,volume-nocopy", SBOX_OK, EMT_VOLUME, "data", "/d", "rbind,ro,rprivate" },
        { "type=bind,source=/srv/web,target=/usr/share/nginx/html,readonly=1", SBOX_OK, EMT_BIND, "/srv/web", "/usr/share/nginx/html", "rbind,ro,rprivate" },
        { "type=bind,src=/srv,dst=/srv,bind-propagation=rslave", SBOX_OK, EMT_BIND, "/srv", "/srv", "rbind,rw,rslave" },
        { "type=bind,src=/srv,dst=/srv,bind-nonrecursive", SBOX_OK, EMT_BIND, "/srv", "/srv", "bind,rw,rprivate" },
        { "type=bind,src=/srv,dst=/srv,bind-nonrecursive=false,ro=0", SBOX_OK, EMT_BIND, "/srv", "/srv", "rbind,rw,rprivate" },
        { "TYPE=tmpfs,Target=/run,tmpfs-size=64m,tmpfs-mode=1770", SBOX_OK, EMT_TMPFS, "", "/run", "nosuid,nodev,noexec,size=64m,mode=1770" },
        { "type=tmpfs,dst=/cache,readonly,tmpfs-size=1000", SBOX_OK, EMT_TMPFS, "", "/cache", "nosuid,nodev,noexec,ro,size=1000" },
        { "type=tmpfs,dst=/t", SBOX_OK, EMT_TMPFS, "", "/t", "nosuid,nodev,noexec" },
        { "type=volume,dst=/x,\"volume-opt=o=addr=10.0.0.1,rw\",volume-opt=type=nfs", SBOX_OK, EMT_VOLUME, "", "/x", "" },
        { "type=bind,dst=/x", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=bind,src=relative,dst=/x", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,src=data", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,src=data,dst=/", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,src=data,dst=rel", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=tmpfs,src=x,dst=/t", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=bind,src=/a,dst=/b,volume-nocopy", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,src=data,dst=/b,bind-propagation=shared", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,src=data,dst=/b,tmpfs-size=1m", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=bind,src=/a,dst=/b,bind-propagation=sideways", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=npipe,src=/a,dst=/b", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,dst=/b,unknown=1", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,dst=/b,whatever", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,dst=/b,readonly=maybe", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=tmpfs,dst=/b,tmpfs-mode=999", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=tmpfs,dst=/b,tmpfs-size=big", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,dst=/b,volume-subpath=../x", -EINVAL, EMT_INVALID, "", "", "" },
        { "type=volume,dst=/b,\"volume-opt=unterminated", -EINVAL, EMT_INVALID, "", "", "" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.spec);
        SMountRequest r;
        std::string error;
        int32_t rc = ParseMountFlag(c.spec, r, &error);
        CAPTURE(error);
        CHECK(rc == c.rc);
        if (rc != SBOX_OK) {
            CHECK(!error.empty());
            continue;
        }

        CHECK(r.type == c.type);
        CHECK(r.source == c.source);
        CHECK(r.target == c.target);
        CHECK(!r.createHostPath);
        if (c.oci[0] != '\0') {
            CJson m;
            REQUIRE(BuildOciMount(r, r.type == EMT_TMPFS ? std::string() : std::string("/SRC"), m) == SBOX_OK);
            CHECK(optionsOf(m) == c.oci);
            CHECK(m.get("type").asString() == (r.type == EMT_TMPFS ? "tmpfs" : "bind"));
        }
    }

    SMountRequest r;
    REQUIRE(ParseMountFlag("type=volume,dst=/x,\"volume-opt=o=addr=10.0.0.1,rw\",volume-opt=type=nfs,"
                           "volume-opt=device=:/export,volume-label=a=b,volume-driver=local,volume-subpath=sub/./dir",
                           r) == SBOX_OK);
    CHECK(r.volumeOptions["o"] == "addr=10.0.0.1,rw");
    CHECK(r.volumeOptions["type"] == "nfs");
    CHECK(r.volumeOptions["device"] == ":/export");
    CHECK(r.volumeLabels["a"] == "b");
    CHECK(r.volumeDriver == "local");
    CHECK(r.volumeSubpath == "sub/dir");

    REQUIRE(ParseMountFlag("type=tmpfs,dst=/t,tmpfs-size=10G", r) == SBOX_OK);
    CHECK(r.tmpfsSize == (uint64_t(10) << 30));
    CJson m;
    REQUIRE(BuildOciMount(r, "", m) == SBOX_OK);
    CHECK(m.dump() == "{\"destination\":\"/t\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"nodev\",\"noexec\",\"size=10g\"]}");
}

TEST_CASE("--tmpfs translation") {
    SMountRequest r;
    REQUIRE(ParseTmpfsFlag("/run", r) == SBOX_OK);
    CJson m;
    REQUIRE(BuildOciMount(r, "", m) == SBOX_OK);
    CHECK(optionsOf(m) == "nosuid,nodev,noexec");

    REQUIRE(ParseTmpfsFlag("/run:rw,exec,size=64m,mode=755", r) == SBOX_OK);
    REQUIRE(BuildOciMount(r, "", m) == SBOX_OK);
    CHECK(optionsOf(m) == "nosuid,nodev,exec,size=64m,mode=755");

    REQUIRE(ParseTmpfsFlag("/ro:ro,suid,dev", r) == SBOX_OK);
    REQUIRE(BuildOciMount(r, "", m) == SBOX_OK);
    CHECK(optionsOf(m) == "noexec,suid,dev,ro");

    CHECK(ParseTmpfsFlag("relative", r) == -EINVAL);
    CHECK(ParseTmpfsFlag("/x:a,,b", r) == -EINVAL);
}

TEST_CASE("ValidateHostPath") {
    TempDir dir("hostpath");
    std::string cleaned;
    CHECK(ValidateHostPath(dir.path + "/./", false, cleaned) == SBOX_OK);
    CHECK(cleaned == dir.path);
    CHECK(ValidateHostPath(dir / "missing", false, cleaned) == -ENOENT);
    CHECK(ValidateHostPath(dir / "made/deep", true, cleaned) == SBOX_OK);
    CHECK(CFile::exists(dir / "made/deep"));
    CHECK(ValidateHostPath("relative", true, cleaned) == -EINVAL);

    // --> Inside the store only a volume's _data may be bound.
    std::string store = dir / "store";
    REQUIRE(CFile::makeDirs(store + "/vol/_data/sub", 0755) == SBOX_OK);
    CHECK(ValidateHostPath(store, false, cleaned, store) == -EACCES);
    CHECK(ValidateHostPath(store + "/vol", false, cleaned, store) == -EACCES);
    CHECK(ValidateHostPath(store + "/vol/volume.json", false, cleaned, store) == -EACCES);
    CHECK(ValidateHostPath(store + "/vol/_data", false, cleaned, store) == SBOX_OK);
    CHECK(ValidateHostPath(store + "/vol/_data/sub", false, cleaned, store) == SBOX_OK);
    CHECK(ValidateHostPath(store + "-other", true, cleaned, store) == SBOX_OK);
}

TEST_CASE("PrepareContainerMounts creates, acquires and copies up") {
    TempDir dir("prepare");
    CEventLoop loop;
    SVolumeStoreOptions so;
    so.root = dir / "volumes";
    CVolumeStore store(so);

    // --> Image rootfs with content at the volume targets, plus a symlinked target.
    std::string rootfs = dir / "rootfs";
    REQUIRE(CFile::makeDirs(rootfs + "/var/lib/app", 0755) == SBOX_OK);
    REQUIRE(writeFile(rootfs + "/var/lib/app/seed.db", "seed"));
    REQUIRE(CFile::makeDirs(rootfs + "/etc/conf", 0700) == SBOX_OK);
    REQUIRE(writeFile(rootfs + "/etc/conf/app.ini", "x=1"));
    REQUIRE(::symlink("/etc/conf", (rootfs + "/config").c_str()) == 0);
    REQUIRE(CFile::makeDirs(dir / "host", 0755) == SBOX_OK);

    std::vector<SMountRequest> reqs(5);
    REQUIRE(ParseVolumeFlag("appdata:/var/lib/app", reqs[0]) == SBOX_OK);
    REQUIRE(ParseVolumeFlag("/config", reqs[1]) == SBOX_OK);
    REQUIRE(ParseMountFlag("type=volume,src=empty,dst=/var/lib/app/nocopy,volume-nocopy,volume-label=team=x", reqs[2]) == SBOX_OK);
    REQUIRE(ParseVolumeFlag(dir / "host" + ":/mnt/host:ro", reqs[3]) == SBOX_OK);
    REQUIRE(ParseMountFlag("type=tmpfs,dst=/run,tmpfs-size=1m", reqs[4]) == SBOX_OK);

    std::vector<CJson> mounts;
    std::string error;
    REQUIRE(loop.run(PrepareContainerMounts(store, reqs, "ctr1", rootfs, mounts, &error)) == SBOX_OK);
    REQUIRE(mounts.size() == 5);

    SVolume app;
    REQUIRE(store.inspect("appdata", app) == SBOX_OK);
    CHECK(app.users == std::vector<std::string>{ "ctr1" });
    CHECK(mounts[0].get("source").asString() == app.mountpoint);
    CHECK(readFile(app.mountpoint + "/seed.db") == "seed");

    // --> The anonymous volume got the content behind the symlink (resolved inside rootfs).
    std::string anonSource = mounts[1].get("source").asString();
    CHECK(readFile(anonSource + "/app.ini") == "x=1");
    struct stat st{};
    REQUIRE(::stat(anonSource.c_str(), &st) == 0);
    CHECK((st.st_mode & 07777) == 0700);

    SVolume empty;
    REQUIRE(store.inspect("empty", empty) == SBOX_OK);
    CHECK(empty.labels["team"] == "x");
    CHECK(IsDirectoryEmpty(empty.mountpoint));

    CHECK(mounts[3].get("source").asString() == dir / "host");
    CHECK(optionsOf(mounts[3]) == "rbind,ro,rprivate");
    CHECK(mounts[4].get("type").asString() == "tmpfs");

    // --> A second container shares the named volume; content is not copied twice.
    REQUIRE(writeFile(rootfs + "/var/lib/app/second", "2"));
    std::vector<SMountRequest> again(1);
    REQUIRE(ParseVolumeFlag("appdata:/var/lib/app", again[0]) == SBOX_OK);
    REQUIRE(loop.run(PrepareContainerMounts(store, again, "ctr2", rootfs, mounts, &error)) == SBOX_OK);
    CHECK(!CFile::exists(app.mountpoint + "/second"));
    REQUIRE(store.inspect("appdata", app) == SBOX_OK);
    CHECK(app.users.size() == 2);

    // --> Failure (missing --mount bind source) rolls back everything acquired by this call.
    std::vector<SMountRequest> bad(3);
    REQUIRE(ParseVolumeFlag("fresh:/a", bad[0]) == SBOX_OK);
    REQUIRE(ParseVolumeFlag("/b", bad[1]) == SBOX_OK);
    REQUIRE(ParseMountFlag("type=bind,src=" + dir / "nope" + ",dst=/c", bad[2]) == SBOX_OK);
    std::vector<std::string> before;
    {
        std::vector<SVolume> all;
        store.list(all);
        for (const SVolume& v : all) {
            before.push_back(v.name);
        }
    }

    CHECK(loop.run(PrepareContainerMounts(store, bad, "ctr3", rootfs, mounts, &error)) == -ENOENT);
    CHECK(error.find("does not exist") != std::string::npos);
    CHECK(mounts.empty());
    SVolume fresh;
    REQUIRE(store.inspect("fresh", fresh) == SBOX_OK);
    CHECK(fresh.users.empty());
    std::vector<SVolume> after;
    store.list(after);
    CHECK(after.size() == before.size() + 1);

    // --> Duplicate targets.
    std::vector<SMountRequest> dup(2);
    REQUIRE(ParseVolumeFlag("v1:/same", dup[0]) == SBOX_OK);
    REQUIRE(ParseVolumeFlag("v2:/same", dup[1]) == SBOX_OK);
    CHECK(loop.run(PrepareContainerMounts(store, dup, "ctr4", "", mounts, &error)) == -EINVAL);
    CHECK(error.find("duplicate") != std::string::npos);
    SVolume v1;
    REQUIRE(store.inspect("v1", v1) == SBOX_OK);
    CHECK(v1.users.empty());

    // --> Binding the store's metadata is refused.
    std::vector<SMountRequest> meta(1);
    REQUIRE(ParseMountFlag("type=bind,src=" + so.root + ",dst=/store", meta[0]) == SBOX_OK);
    CHECK(loop.run(PrepareContainerMounts(store, meta, "ctr5", "", mounts, &error)) == -EACCES);

    // --> volume-subpath resolves inside the volume and refuses to escape through symlinks.
    REQUIRE(CFile::makeDirs(app.mountpoint + "/sub/dir", 0755) == SBOX_OK);
    REQUIRE(::symlink("/etc", (app.mountpoint + "/sub/escape").c_str()) == 0);
    std::vector<SMountRequest> sub(1);
    REQUIRE(ParseMountFlag("src=appdata,dst=/s,volume-subpath=sub/dir", sub[0]) == SBOX_OK);
    REQUIRE(loop.run(PrepareContainerMounts(store, sub, "ctr6", "", mounts, &error)) == SBOX_OK);
    CHECK(mounts[0].get("source").asString() == app.mountpoint + "/sub/dir");
    REQUIRE(ParseMountFlag("src=appdata,dst=/s,volume-subpath=sub/escape", sub[0]) == SBOX_OK);
    CHECK(loop.run(PrepareContainerMounts(store, sub, "ctr7", "", mounts, &error)) == -ENOENT);

    // --> releaseUser removes anonymous volumes (docker run --rm).
    std::vector<std::string> released;
    REQUIRE(loop.run(store.releaseUser("ctr1", true, &released)) == SBOX_OK);
    CHECK(released.size() == 3);
    CHECK(!CFile::exists(anonSource));
}
