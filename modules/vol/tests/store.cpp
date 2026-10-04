#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "testutil.hpp"

#include <sbox/vol/store.hpp>
#include <set>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

namespace {

    SVolumeStoreOptions storeAt(const std::string& root) {
        SVolumeStoreOptions o;
        o.root = root;
        return o;
    }

    SVolumeCreate named(const std::string& name, TStringMap labels = {}, TStringMap options = {}) {
        SVolumeCreate c;
        c.name = name;
        c.labels = std::move(labels);
        c.options = std::move(options);
        return c;
    }

}

TEST_CASE("volume names follow Docker's local driver rule") {
    CHECK(IsValidVolumeName("data"));
    CHECK(IsValidVolumeName("my_vol-1.2"));
    CHECK(IsValidVolumeName("0a"));
    CHECK(!IsValidVolumeName("a"));
    CHECK(!IsValidVolumeName(""));
    CHECK(!IsValidVolumeName(".hidden"));
    CHECK(!IsValidVolumeName("_x"));
    CHECK(!IsValidVolumeName("a/b"));
    CHECK(!IsValidVolumeName(".."));
    CHECK(!IsValidVolumeName("sp ace"));
    CHECK(!IsValidVolumeName(std::string(256, 'a')));

    std::string anon = NewAnonymousVolumeName();
    CHECK(anon.size() == 64);
    CHECK(anon.find_first_not_of("0123456789abcdef") == std::string::npos);
    CHECK(anon != NewAnonymousVolumeName());
    CHECK(IsValidVolumeName(anon));
}

TEST_CASE("store lifecycle: create, inspect, list, acquire, release, remove") {
    TempDir dir("store");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "volumes"));
    CHECK(store.root() == dir / "volumes");

    std::vector<SVolume> all;
    CHECK(store.list(all) == SBOX_OK);
    CHECK(all.empty());

    SVolume v;
    REQUIRE(loop.run(store.create(named("data", { { "env", "prod" } }), v)) == SBOX_OK);
    CHECK(v.name == "data");
    CHECK(v.driver == "local");
    CHECK(v.scope == "local");
    CHECK(v.mountpoint == dir / "volumes/data/_data");
    CHECK(v.createdAt.size() == 20);
    CHECK(v.createdAt.back() == 'Z');
    CHECK(CFile::exists(v.mountpoint));
    CHECK(CFile::exists(dir / "volumes/data/volume.json"));
    CHECK(!CFile::exists(dir / "volumes/data/opts.json"));
    CHECK(!v.isAnonymous());

    // --> On-disk metadata is Docker's inspect document.
    CJson meta;
    std::string text = readFile(dir / "volumes/data/volume.json");
    REQUIRE(CJson::parse(text, meta) == SBOX_OK);
    CHECK(meta.get("Name").asString() == "data");
    CHECK(meta.get("Driver").asString() == "local");
    CHECK(meta.get("Labels").get("env").asString() == "prod");
    CHECK(meta.get("Scope").asString() == "local");
    CHECK(meta.get("Mountpoint").asString() == v.mountpoint);

    CJson inspect = v.toJson();
    CHECK(inspect.size() == 7);
    CHECK(inspect.keyAt(0) == "CreatedAt");
    CHECK(inspect.keyAt(6) == "Scope");

    // --> Creating an existing name returns it unchanged.
    SVolume again;
    REQUIRE(loop.run(store.create(named("data", { { "other", "x" } }), again)) == SBOX_OK);
    CHECK(again.createdAt == v.createdAt);
    CHECK(again.labels.count("other") == 0);

    SVolumeCreate other = named("data");
    other.driver = "nfsplugin";
    CHECK(loop.run(store.create(other, again)) == -ENOTSUP);

    REQUIRE(loop.run(store.create(named("logs"), v)) == SBOX_OK);
    REQUIRE(store.list(all) == SBOX_OK);
    REQUIRE(all.size() == 2);
    CHECK(all[0].name == "data");
    CHECK(all[1].name == "logs");

    // --> Users are reference counted and persisted.
    std::string mp;
    REQUIRE(loop.run(store.acquire("data", "c1", mp)) == SBOX_OK);
    CHECK(mp == dir / "volumes/data/_data");
    REQUIRE(loop.run(store.acquire("data", "c2", mp)) == SBOX_OK);
    REQUIRE(loop.run(store.acquire("data", "c2", mp)) == SBOX_OK);
    REQUIRE(store.inspect("data", v) == SBOX_OK);
    CHECK(v.users == std::vector<std::string>{ "c1", "c2" });
    CHECK(!v.mounted);

    {
        CVolumeStore second(storeAt(dir / "volumes"));
        REQUIRE(second.inspect("data", v) == SBOX_OK);
        CHECK(v.users.size() == 2);
        CHECK(loop.run(second.remove("data")) == -EBUSY);
        CHECK(second.lastError().find("in use") != std::string::npos);
    }

    REQUIRE(loop.run(store.release("data", "c1")) == SBOX_OK);
    REQUIRE(loop.run(store.release("data", "unknown")) == SBOX_OK);
    REQUIRE(store.inspect("data", v) == SBOX_OK);
    CHECK(v.users == std::vector<std::string>{ "c2" });
    CHECK(loop.run(store.remove("data")) == -EBUSY);
    REQUIRE(loop.run(store.release("data", "c2")) == SBOX_OK);

    REQUIRE(writeFile(dir / "volumes/data/_data/file", "content"));
    SVolumeUsage u;
    REQUIRE(store.usage("data", u) == SBOX_OK);
    CHECK(u.bytes > 0);
    CHECK(u.refCount == 0);

    REQUIRE(loop.run(store.remove("data")) == SBOX_OK);
    CHECK(!CFile::exists(dir / "volumes/data"));
    CHECK(store.inspect("data", v) == -ENOENT);
    CHECK(loop.run(store.remove("data")) == -ENOENT);
    CHECK(store.lastError().find("no such volume") != std::string::npos);
    CHECK(loop.run(store.acquire("data", "c1", mp)) == -ENOENT);
    CHECK(loop.run(store.acquire("logs", "", mp)) == -EINVAL);

    // --> Force removes a volume in use.
    REQUIRE(loop.run(store.acquire("logs", "c9", mp)) == SBOX_OK);
    CHECK(loop.run(store.remove("logs", true)) == SBOX_OK);
    REQUIRE(store.list(all) == SBOX_OK);
    CHECK(all.empty());

    // --> Leftovers of an interrupted remove or create are ignored and cleaned.
    REQUIRE(CFile::makeDirs(dir / "volumes/half/_data", 0755) == SBOX_OK);
    REQUIRE(store.list(all) == SBOX_OK);
    CHECK(all.empty());
    REQUIRE(loop.run(store.create(named("half"), v)) == SBOX_OK);
    CHECK(store.inspect("half", v) == SBOX_OK);
}

TEST_CASE("invalid names and options are rejected") {
    TempDir dir("invalid");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));
    SVolume v;
    CHECK(loop.run(store.create(named("x"), v)) == -EINVAL);
    CHECK(loop.run(store.create(named("../etc"), v)) == -EINVAL);
    CHECK(loop.run(store.create(named("ok", {}, { { "type", "tmpfs" } }), v)) == -EINVAL);
    CHECK(store.lastError().find("device") != std::string::npos);
    CHECK(loop.run(store.create(named("ok", {}, { { "flavor", "x" } }), v)) == -EINVAL);
    CHECK(store.inspect("x", v) == -EINVAL);
}

TEST_CASE("anonymous volumes, releaseUser and prune") {
    TempDir dir("anon");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));

    SVolume a, b, named1, named2;
    REQUIRE(loop.run(store.create(SVolumeCreate(), a)) == SBOX_OK);
    REQUIRE(loop.run(store.create(SVolumeCreate(), b)) == SBOX_OK);
    CHECK(a.isAnonymous());
    CHECK(a.name.size() == 64);
    CHECK(a.labels.count(ANONYMOUS_LABEL) == 1);
    REQUIRE(loop.run(store.create(named("keep", { { "team", "a" } }), named1)) == SBOX_OK);
    REQUIRE(loop.run(store.create(named("drop", { { "team", "b" } }), named2)) == SBOX_OK);

    std::string mp;
    REQUIRE(loop.run(store.acquire(a.name, "ctr", mp)) == SBOX_OK);
    REQUIRE(loop.run(store.acquire("keep", "ctr", mp)) == SBOX_OK);
    REQUIRE(writeFile(mp + "/f", std::string(10000, 'x')));

    // --> Prune without all: only unused anonymous volumes.
    SPruneReport report;
    REQUIRE(loop.run(store.prune(SPruneOptions(), report)) == SBOX_OK);
    CHECK(report.removed == std::vector<std::string>{ b.name });

    // --> docker run --rm: release everything, remove anonymous ones.
    std::vector<std::string> released;
    REQUIRE(loop.run(store.releaseUser("ctr", true, &released)) == SBOX_OK);
    CHECK(released.size() == 2);
    SVolume v;
    CHECK(store.inspect(a.name, v) == -ENOENT);
    REQUIRE(store.inspect("keep", v) == SBOX_OK);
    CHECK(v.users.empty());

    // --> Label filters with all.
    SPruneOptions opts;
    opts.all = true;
    opts.labelFilters = { "team=b" };
    REQUIRE(loop.run(store.prune(opts, report)) == SBOX_OK);
    CHECK(report.removed == std::vector<std::string>{ "drop" });

    opts.labelFilters = { "!team" };
    REQUIRE(loop.run(store.prune(opts, report)) == SBOX_OK);
    CHECK(report.removed.empty());

    opts.labelFilters = { "team!=b" };
    REQUIRE(loop.run(store.prune(opts, report)) == SBOX_OK);
    CHECK(report.removed == std::vector<std::string>{ "keep" });
    CHECK(report.reclaimedBytes >= 10000);
}

TEST_CASE("runtime state from an earlier boot is discarded") {
    TempDir dir("boot");
    CEventLoop loop;
    CVolumeStore store(storeAt(dir / "v"));
    SVolume v;
    REQUIRE(loop.run(store.create(named("vol"), v)) == SBOX_OK);
    std::string mp;
    REQUIRE(loop.run(store.acquire("vol", "old-container", mp)) == SBOX_OK);

    CJson state;
    REQUIRE(CJson::parse(readFile(dir / "v/vol/state.json"), state) == SBOX_OK);
    CHECK(state.get("Users").size() == 1);
    state.set("BootId", CJson("00000000-0000-0000-0000-000000000000"));
    REQUIRE(writeFile(dir / "v/vol/state.json", state.dump()));

    REQUIRE(store.inspect("vol", v) == SBOX_OK);
    CHECK(v.users.empty());
    CHECK(loop.run(store.remove("vol")) == SBOX_OK);
}

TEST_CASE("two processes create volumes concurrently") {
    TempDir dir("conc");
    std::string root = dir / "v";
    constexpr int PER_PROCESS = 20;

    auto worker = [&](int index) -> int {
        CEventLoop loop;
        CVolumeStore store(storeAt(root));
        for (int i = 0; i < PER_PROCESS; ++i) {
            SVolume v;
            // --> Half the names are shared between both processes, half are private.
            std::string name = (i % 2 == 0) ? "shared-" + std::to_string(i) : "p" + std::to_string(index) + "-" + std::to_string(i);
            if (loop.run(store.create(named(name), v)) != SBOX_OK) {
                return 10 + i;
            }

            std::string mp;
            if (loop.run(store.acquire(name, "worker-" + std::to_string(index), mp)) != SBOX_OK) {
                return 40 + i;
            }

            SVolume anon;
            if (loop.run(store.create(SVolumeCreate(), anon)) != SBOX_OK) {
                return 70 + i;
            }
        }

        return 0;
    };

    std::vector<pid_t> pids;
    for (int p = 0; p < 2; ++p) {
        std::fflush(nullptr);
        pid_t pid = ::fork();
        REQUIRE(pid >= 0);
        if (pid == 0) {
            ::_exit(worker(p));
        }

        pids.push_back(pid);
    }

    CEventLoop loop;
    for (pid_t pid : pids) {
        int status = loop.run(waitChild(pid));
        CHECK(status == 0);
    }

    CVolumeStore store(storeAt(root));
    std::vector<SVolume> all;
    REQUIRE(store.list(all) == SBOX_OK);
    // --> 10 shared + 2 x 10 private + 2 x 20 anonymous.
    CHECK(all.size() == 10 + 20 + 40);
    std::set<std::string> names;
    for (const SVolume& v : all) {
        names.insert(v.name);
        if (v.name.compare(0, 7, "shared-") == 0) {
            CHECK(v.users.size() == 2);
        }
    }

    CHECK(names.size() == all.size());

    // --> Concurrent release + prune leaves a consistent store.
    std::vector<std::string> released;
    REQUIRE(loop.run(store.releaseUser("worker-0", false, &released)) == SBOX_OK);
    CHECK(released.size() == 20);
    REQUIRE(loop.run(store.releaseUser("worker-1", false, nullptr)) == SBOX_OK);
    SPruneOptions opts;
    opts.all = true;
    SPruneReport report;
    REQUIRE(loop.run(store.prune(opts, report)) == SBOX_OK);
    CHECK(report.removed.size() == 70);
    REQUIRE(store.list(all) == SBOX_OK);
    CHECK(all.empty());
}

TEST_CASE("tmpfs volume is mounted on first acquire and unmounted on last release") {
    if (!isRoot()) {
        MESSAGE("skipped: needs root for mount(2)");
        return;
    }

    TempDir dir("tmpvol");
    std::string root = dir / "v";
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        CVolumeStore store(storeAt(root));
        SVolume v;
        CHILD_CHECK(loop.run(store.create(named("scratch", {}, { { "type", "tmpfs" }, { "device", "tmpfs" }, { "o", "size=2m" } }), v)) == SBOX_OK);
        CHILD_CHECK(CFile::exists(root + "/scratch/opts.json"));
        CHILD_CHECK(!IsMountPoint(v.mountpoint));

        std::string mp;
        CHILD_CHECK(loop.run(store.acquire("scratch", "c1", mp)) == SBOX_OK);
        CHILD_CHECK(IsMountPoint(mp));
        CHILD_CHECK(writeFile(mp + "/x", "in memory"));
        CHILD_CHECK(loop.run(store.acquire("scratch", "c2", mp)) == SBOX_OK);
        CHILD_CHECK(store.inspect("scratch", v) == SBOX_OK && v.mounted && v.users.size() == 2);
        CHILD_CHECK(loop.run(store.release("scratch", "c1")) == SBOX_OK);
        CHILD_CHECK(IsMountPoint(mp));
        CHILD_CHECK(readFile(mp + "/x") == "in memory");
        CHILD_CHECK(loop.run(store.release("scratch", "c2")) == SBOX_OK);
        CHILD_CHECK(!IsMountPoint(mp));
        CHILD_CHECK(!CFile::exists(mp + "/x"));
        CHILD_CHECK(store.inspect("scratch", v) == SBOX_OK && !v.mounted);

        // --> Force-removing a mounted volume unmounts it first; the bind source survives.
        CHILD_CHECK(::mkdir((root + "-host").c_str(), 0755) == 0);
        CHILD_CHECK(writeFile(root + "-host/keep", "host data"));
        CHILD_CHECK(loop.run(store.create(named("hostdir", {}, { { "type", "none" }, { "device", root + "-host" }, { "o", "bind" } }), v)) == SBOX_OK);
        CHILD_CHECK(loop.run(store.acquire("hostdir", "c3", mp)) == SBOX_OK);
        CHILD_CHECK(readFile(mp + "/keep") == "host data");
        CHILD_CHECK(loop.run(store.remove("hostdir")) == -EBUSY);
        CHILD_CHECK(loop.run(store.remove("hostdir", true)) == SBOX_OK);
        CHILD_CHECK(readFile(root + "-host/keep") == "host data");
        CHILD_CHECK(!CFile::exists(root + "/hostdir"));

        // --> A failing mount leaves no user behind.
        CHILD_CHECK(loop.run(store.create(named("broken", {}, { { "type", "nosuchfs" }, { "device", "/dev/null" } }), v)) == SBOX_OK);
        CHILD_CHECK(loop.run(store.acquire("broken", "c4", mp)) < 0);
        CHILD_CHECK(store.lastError().find("cannot mount") != std::string::npos);
        CHILD_CHECK(store.inspect("broken", v) == SBOX_OK && v.users.empty());
        CFile::removeTree(root + "-host");
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}

TEST_CASE("data directories get the configured owner") {
    if (!isRoot()) {
        MESSAGE("skipped: needs root for chown");
        return;
    }

    TempDir dir("owner");
    CEventLoop loop;
    SVolumeStoreOptions o = storeAt(dir / "v");
    o.dataUid = 65534;
    o.dataGid = 65534;
    CVolumeStore store(o);
    SVolume v;
    REQUIRE(loop.run(store.create(named("remapped"), v)) == SBOX_OK);
    struct stat st{};
    REQUIRE(::stat(v.mountpoint.c_str(), &st) == 0);
    CHECK(st.st_uid == 65534);
    CHECK(st.st_gid == 65534);
    CHECK((st.st_mode & 07777) == 0755);
}
