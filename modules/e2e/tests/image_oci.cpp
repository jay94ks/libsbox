// image -> oci: an image built in the test is loaded (docker save archive) or pulled (in-test
// registry served by the http module) with `sbox-image`, turned into a bundle with the overlay
// and the copy snapshotters, and run with CRuntime and with the `sbox` CLI.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"
#include <sbox/core/socket.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/http/server.hpp>
#include <sbox/oci/runtime.hpp>
#include <map>

using namespace sbox;
using namespace e2e;

namespace {

    const std::string TAG = "e2e/busy:1";

    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root (or no private mount namespace); skipping");
            return false;
        }

        if (!haveTools()) {
            MESSAGE("CLI tools were not built; skipping");
            return false;
        }

        return true;
    }

    /**
     * Read-only registry (API v2) serving one repository from memory.
     */
    struct Registry {
        http::CHttpServer server;
        CListener listener;
        bool done = false;
        std::map<std::string, std::string> blobs;          // --> digest -> bytes.
        std::map<std::string, std::string> manifests;      // --> tag or digest -> manifest.
        std::string repository;
        int32_t blobGets = 0;

        std::string domain() const {
            return "127.0.0.1:" + std::to_string(listener.localEndpoint().port());
        }

        int32_t start(const ImageFixture& img, const std::string& repo, const std::string& tag) {
            repository = repo;
            blobs[img.configDigest] = img.config;
            for (size_t i = 0; i < img.gzLayers.size(); ++i) {
                blobs[img.gzDigests[i]] = img.gzLayers[i];
            }

            manifests[tag] = img.manifest;
            manifests[img.manifestDigest] = img.manifest;

            SEndpoint ep;
            SEndpoint::fromIp("127.0.0.1", 0, ep);
            int32_t r = listener.listen(ep);
            if (r != SBOX_OK) {
                return r;
            }

            Registry* self = this;
            server.route("GET", "/v2/", [](http::SServerRequest&, http::SServerResponse& res) -> TTask<void> {
                res.setJson(CJson::object());
                co_return;
            });

            server.routePrefix("GET", "/v2/", [self](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
                // --> routeRest: "<repo>/manifests/<ref>" or "<repo>/blobs/<digest>".
                std::string rest = req.routeRest;
                std::string prefix = self->repository + "/";
                if (rest.compare(0, prefix.size(), prefix) != 0) {
                    res.setText("{\"errors\":[{\"code\":\"NAME_UNKNOWN\"}]}", 404, "application/json");
                    co_return;
                }

                rest = rest.substr(prefix.size());
                if (rest.compare(0, 10, "manifests/") == 0) {
                    auto it = self->manifests.find(rest.substr(10));
                    if (it == self->manifests.end()) {
                        res.setText("{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\"}]}", 404, "application/json");
                        co_return;
                    }

                    res.setText(it->second, 200, "application/vnd.docker.distribution.manifest.v2+json");
                    res.headers.set("Docker-Content-Digest", image::DigestOf(BytesOf(it->second)));
                    co_return;
                }

                if (rest.compare(0, 6, "blobs/") == 0) {
                    auto it = self->blobs.find(rest.substr(6));
                    if (it == self->blobs.end()) {
                        res.setText("{\"errors\":[{\"code\":\"BLOB_UNKNOWN\"}]}", 404, "application/json");
                        co_return;
                    }

                    ++self->blobGets;
                    res.setText(it->second, 200, "application/octet-stream");
                    res.headers.set("Docker-Content-Digest", it->first);
                    co_return;
                }

                res.setText("", 404);
            });

            CEventLoop::current()->spawn([](Registry* s) -> TTask<void> {
                co_await s->server.serve(s->listener);
                s->done = true;
            }(this));
            return SBOX_OK;
        }

        TTask<void> stop() {
            server.stop(true);
            while (!done) {
                co_await CEventLoop::current()->sleepFor(1);
            }
        }
    };

    /**
     * `sbox-image --root <store> -q ARGS...` (variadic: braced string lists inside co_await
     * expressions crash GCC 13).
     */
    template<typename... A>
    TTask<ToolResult> imageTool(const TempDir& tmp, const std::string& store, A&&... args) {
        return runTool(tmp.path, tool("sbox-image"), Args("--root", store, "-q", std::forward<A>(args)...));
    }

    /**
     * `sbox --root <state> ARGS...`.
     */
    template<typename... A>
    TTask<ToolResult> sboxTool(const TempDir& tmp, const std::string& state, A&&... args) {
        return runTool(tmp.path, tool("sbox"), Args("--root", state, std::forward<A>(args)...));
    }

    /**
     * Returns true when `path` is a mount point in this process's mount namespace.
     */
    bool isMounted(const std::string& path) {
        std::string info;
        CFile::readAll("/proc/self/mountinfo", info);
        return info.find(" " + path + " ") != std::string::npos;
    }

    /**
     * The whole flow for one snapshotter: bundle, CRuntime, CLI run, CLI lifecycle, cleanup.
     */
    TTask<void> runSnapshotter(const TempDir& tmp, std::string store, std::string mode) {
        std::string state = tmp / ("state-" + mode);
        std::string bundle = tmp / ("bundle-" + mode);

        ToolResult b = co_await imageTool(tmp, store, "--snapshotter", mode, "--json", "bundle", TAG, bundle);
        REQUIRE_MESSAGE(b.code == 0, b.err);
        CJson info = parseJson(b.out);
        std::string rootId = info.get("Id").asString();
        CHECK(info.get("Snapshotter").asString() == mode);
        CHECK(CFile::exists(bundle + "/config.json"));
        CHECK(isMounted(bundle + "/rootfs") == (mode == "overlay"));

        // --> Layer two's whiteout removed /etc/removed; its files are on top.
        CHECK_FALSE(CFile::exists(bundle + "/rootfs/etc/removed"));
        CHECK(CFile::exists(bundle + "/rootfs/etc/motd"));
        CHECK(CFile::exists(bundle + "/rootfs/bin/e2ehelper"));

        // --> The library runs the image's Cmd with the Docker-style config the image module wrote.
        ContainerRun cr = co_await runContainer(state, bundle, "e2e-rt-" + mode + "-" + randomSuffix());
        REQUIRE_MESSAGE(cr.error == SBOX_OK, cr.message);
        CHECK(cr.code == 0);
        CHECK(cr.out == "hello from layer-two\n");

        // --> The CLI's foreground run, the way a user types it.
        std::string id = "e2e-run-" + mode + "-" + randomSuffix();
        ToolResult run = co_await sboxTool(tmp, state, "run", "--bundle", bundle, id);
        CHECK_MESSAGE(run.code == 0, run.err);
        CHECK(run.out == "hello from layer-two\n");
        ToolResult gone = co_await sboxTool(tmp, state, "state", id);
        CHECK(gone.code != 0);
        CHECK(gone.err.find("container does not exist") != std::string::npos);

        // --> Exit codes come through `sbox run`; arguments after -- replace the image Cmd.
        std::string bundle7 = tmp / ("bundle7-" + mode);
        ToolResult b7 = co_await imageTool(tmp, store, "--snapshotter", mode, "--json", "bundle", "--env", "CODE=7", TAG, bundle7,
                                       "--", "/bin/sh", "-c", "echo $E2E$CODE; exit $CODE");
        REQUIRE_MESSAGE(b7.code == 0, b7.err);
        std::string rootId7 = parseJson(b7.out).get("Id").asString();
        ToolResult run7 = co_await sboxTool(tmp, state, "run", "--bundle", bundle7, "e2e-run7-" + mode + "-" + randomSuffix());
        CHECK(run7.code == 7);
        CHECK(run7.out == "17\n");

        if (mode == "overlay") {
            // --> Changes a container makes in its overlay root become a new image with commit:
            // a new file, and a deleted image file (an overlay whiteout turned into .wh.motd).
            std::string bundleC = tmp / "bundle-commit";
            ToolResult bc = co_await imageTool(tmp, store, "--snapshotter", "overlay", "--json", "bundle", TAG, bundleC,
                                               "--", "/bin/sh", "-c", "echo committed > /etc/committed; rm /etc/motd");
            REQUIRE_MESSAGE(bc.code == 0, bc.err);
            std::string rootIdC = parseJson(bc.out).get("Id").asString();
            ToolResult runC = co_await sboxTool(tmp, state, "run", "--bundle", bundleC, "e2e-commit-" + randomSuffix());
            CHECK_MESSAGE(runC.code == 0, runC.err);
            ToolResult commit = co_await imageTool(tmp, store, "commit", "--message", "e2e", rootIdC, "e2e/committed:1");
            REQUIRE_MESSAGE(commit.code == 0, commit.err);
            CHECK((co_await imageTool(tmp, store, "rm", rootIdC)).code == 0);

            std::string bundleN = tmp / "bundle-committed";
            ToolResult bn = co_await imageTool(tmp, store, "--snapshotter", "copy", "--json", "bundle", "e2e/committed:1", bundleN,
                                               "--", "/bin/sh", "-c", "cat /etc/committed; test -e /etc/motd || echo motd-gone");
            REQUIRE_MESSAGE(bn.code == 0, bn.err);
            ToolResult runN = co_await sboxTool(tmp, state, "run", "--bundle", bundleN, "e2e-committed-" + randomSuffix());
            CHECK_MESSAGE(runN.code == 0, runN.err);
            CHECK(runN.out == "committed\nmotd-gone\n");
            CHECK((co_await imageTool(tmp, store, "rm", parseJson(bn.out).get("Id").asString())).code == 0);
        }

        // --> Detached lifecycle: create / state / start / state / kill / state / delete.
        std::string bundleSleep = tmp / ("bundle-sleep-" + mode);
        ToolResult bs = co_await imageTool(tmp, store, "--snapshotter", mode, "--json", "bundle", TAG, bundleSleep, "--", "/bin/sleep", "300");
        REQUIRE_MESSAGE(bs.code == 0, bs.err);
        std::string rootIdSleep = parseJson(bs.out).get("Id").asString();
        std::string sid = "e2e-life-" + mode + "-" + randomSuffix();
        ToolResult created = co_await sboxTool(tmp, state, "create", "--bundle", bundleSleep, "--pid-file", tmp / (sid + ".pid"), sid);
        REQUIRE_MESSAGE(created.code == 0, created.err);
        CJson st = parseJson((co_await sboxTool(tmp, state, "state", sid)).out);
        CHECK(st.get("status").asString() == "created");
        std::string pidText;
        CFile::readAll(tmp / (sid + ".pid"), pidText);
        CHECK(std::to_string(st.get("pid").asInt()) == pidText);

        CHECK((co_await sboxTool(tmp, state, "start", sid)).code == 0);
        st = parseJson((co_await sboxTool(tmp, state, "state", sid)).out);
        CHECK(st.get("status").asString() == "running");
        ToolResult ex = co_await sboxTool(tmp, state, "exec", sid, "/bin/sh", "-c", "cat /etc/motd; echo $E2E");
        CHECK_MESSAGE(ex.code == 0, ex.err);
        CHECK(ex.out == "layer-two\n1\n");
        ToolResult list = co_await sboxTool(tmp, state, "list", "-q");
        CHECK(list.out.find(sid) != std::string::npos);
        ToolResult ps = co_await sboxTool(tmp, state, "ps", "--format", "json", sid);
        CHECK(parseJson(ps.out).size() == 1);

        CHECK((co_await sboxTool(tmp, state, "kill", sid, "KILL")).code == 0);
        std::string status;
        for (int i = 0; i < 200 && status != "stopped"; ++i) {
            status = parseJson((co_await sboxTool(tmp, state, "state", sid)).out).get("status").asString();
            if (status != "stopped") {
                co_await CEventLoop::current()->sleepFor(25);
            }
        }

        CHECK(status == "stopped");
        ToolResult del = co_await sboxTool(tmp, state, "delete", sid);
        CHECK_MESSAGE(del.code == 0, del.err);
        CHECK((co_await sboxTool(tmp, state, "state", sid)).code != 0);

        // --> The container roots go away with `sbox-image rm` (unmounting the overlay first).
        std::vector<std::string> roots;
        roots.push_back(rootId);
        roots.push_back(rootId7);
        roots.push_back(rootIdSleep);
        for (const std::string& rid : roots) {
            ToolResult rm = co_await imageTool(tmp, store, "rm", rid);
            CHECK_MESSAGE(rm.code == 0, rm.err);
        }

        CHECK_FALSE(isMounted(bundle + "/rootfs"));
        ToolResult left = co_await imageTool(tmp, store, "--json", "ps");
        CHECK(parseJson(left.out).size() == 0);
    }

}

TEST_CASE("a docker-save archive loads with sbox-image and its bundles run under CRuntime and the sbox CLI") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    ImageFixture img;
    REQUIRE(buildImage(tmp.path, img));
    std::string archivePath = tmp / "busy.tar";
    REQUIRE(writeDockerSave(img, TAG, archivePath));

    CEventLoop loop;
    loop.run([](const TempDir& t, const ImageFixture& fx, std::string archive) -> TTask<void> {
        std::string store = t / "images";
        ToolResult load = co_await imageTool(t, store, "load", "-i", archive);
        REQUIRE_MESSAGE(load.code == 0, load.err);
        CHECK(load.out.find("e2e/busy:1") != std::string::npos);

        ToolResult inspect = co_await imageTool(t, store, "inspect", TAG);
        REQUIRE(inspect.code == 0);
        CJson doc = parseJson(inspect.out);
        const CJson& first = doc.isObject() ? doc : doc.at(0);
        CHECK(first.get("Id").asString() == fx.configDigest);

        bool overlay = true;
        {
            // --> overlay needs kernel support where the store lives; the copy path always works.
            ToolResult probe = co_await imageTool(t, store, "--snapshotter", "overlay", "--json", "mount", TAG);
            overlay = probe.code == 0;
            if (overlay) {
                co_await imageTool(t, store, "rm", parseJson(probe.out).get("Id").asString());
            } else {
                MESSAGE("overlay unavailable: " << probe.err);
            }
        }

        if (overlay) {
            co_await runSnapshotter(t, store, "overlay");
        }

        co_await runSnapshotter(t, store, "copy");

        // --> `sbox-image save` output loads into a fresh store with the same image ID.
        std::string saved = t / "saved.tar";
        ToolResult save = co_await imageTool(t, store, "save", "-o", saved, TAG);
        REQUIRE_MESSAGE(save.code == 0, save.err);
        std::string store2 = t / "images2";
        REQUIRE((co_await imageTool(t, store2, "load", "-i", saved)).code == 0);
        ToolResult inspect2 = co_await imageTool(t, store2, "inspect", TAG);
        CJson doc2 = parseJson(inspect2.out);
        const CJson& first2 = doc2.isObject() ? doc2 : doc2.at(0);
        CHECK(first2.get("Id").asString() == fx.configDigest);
    }(tmp, img, archivePath));
}

TEST_CASE("an image pulled from an in-test registry is the same image and runs with sbox run") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    ImageFixture img;
    REQUIRE(buildImage(tmp.path, img, { "/bin/sh", "-c", "cat /data/seed.txt; test ! -e /etc/removed" }));

    CEventLoop loop;
    loop.run([](const TempDir& t, const ImageFixture& fx) -> TTask<void> {
        Registry reg;
        REQUIRE(reg.start(fx, "e2e/pulled", "v1") == SBOX_OK);
        std::string ref = reg.domain() + "/e2e/pulled:v1";
        std::string store = t / "images";

        ToolResult pull = co_await imageTool(t, store, "--plain-http", reg.domain(), "pull", ref);
        REQUIRE_MESSAGE(pull.code == 0, pull.err);
        CHECK(reg.blobGets == 3);

        ToolResult inspect = co_await imageTool(t, store, "inspect", ref);
        CJson doc = parseJson(inspect.out);
        const CJson& first = doc.isObject() ? doc : doc.at(0);
        CHECK(first.get("Id").asString() == fx.configDigest);
        CHECK(inspect.out.find(fx.manifestDigest) != std::string::npos);

        // --> A second pull downloads nothing.
        ToolResult again = co_await imageTool(t, store, "--plain-http", reg.domain(), "pull", ref);
        CHECK(again.code == 0);
        CHECK(reg.blobGets == 3);

        std::string bundle = t / "bundle";
        ToolResult b = co_await imageTool(t, store, "--snapshotter", "copy", "--json", "bundle", ref, bundle);
        REQUIRE_MESSAGE(b.code == 0, b.err);
        ToolResult run = co_await sboxTool(t, t / "state", "run", "--bundle", bundle, "e2e-pull-" + randomSuffix());
        CHECK_MESSAGE(run.code == 0, run.err);
        CHECK(run.out == "seeded by the image\n");
        CHECK((co_await imageTool(t, store, "rm", parseJson(b.out).get("Id").asString())).code == 0);

        // --> --user resolves through the image's /etc/passwd; --read-only makes the root read-only.
        std::string bundleU = t / "bundle-user";
        ToolResult bu = co_await imageTool(t, store, "--snapshotter", "copy", "--json", "bundle", "--user", "nobody", "--read-only",
                                           ref, bundleU, "--", "/bin/sh", "-c", "id -u; id -g; touch /x 2>/dev/null || echo ro");
        REQUIRE_MESSAGE(bu.code == 0, bu.err);
        ToolResult runU = co_await sboxTool(t, t / "state", "run", "--bundle", bundleU, "e2e-user-" + randomSuffix());
        CHECK_MESSAGE(runU.code == 0, runU.err);
        CHECK(runU.out == "65534\n65534\nro\n");
        CHECK((co_await imageTool(t, store, "rm", parseJson(bu.out).get("Id").asString())).code == 0);

        co_await reg.stop();
    }(tmp, img));
}

TEST_CASE("rootless: an unprivileged user loads, bundles and runs the image") {
    if (!canRun()) {
        return;
    }

    TempDir tmp;
    ImageFixture img;
    REQUIRE(buildImage(tmp.path, img));
    std::string archivePath = tmp / "busy.tar";
    REQUIRE(writeDockerSave(img, TAG, archivePath));

    // --> Everything the user touches belongs to uid 65534 (no shared store, no cgroup delegation).
    std::string home = tmp / "home";
    CFile::makeDirs(home + "/run", 0700);
    REQUIRE(::chown(home.c_str(), 65534, 65534) == 0);
    REQUIRE(::chown((home + "/run").c_str(), 65534, 65534) == 0);
    ::chmod((home + "/run").c_str(), 0700);

    CEventLoop loop;
    loop.run([](const TempDir& t, std::string userHome, std::string archive) -> TTask<void> {
        RunOptions as;
        as.uid = 65534;
        as.gid = 65534;
        as.env = Args("HOME=" + userHome, "XDG_RUNTIME_DIR=" + userHome + "/run", "XDG_DATA_HOME=" + userHome + "/data");

        // --> Default store ($XDG_DATA_HOME/sbox/image) and default state root ($XDG_RUNTIME_DIR/sbox).
        ToolResult load = co_await runTool(t.path, tool("sbox-image"), Args("-q", "load", "-i", archive), as);
        REQUIRE_MESSAGE(load.code == 0, load.err);
        CHECK(CFile::exists(userHome + "/data/sbox/image/index.json"));

        std::string bundle = userHome + "/bundle";
        ToolResult b = co_await runTool(t.path, tool("sbox-image"),
            Args("-q", "--json", "bundle", TAG, bundle, "--", "/bin/sh", "-c", "id -u; cat /etc/motd; cat /proc/self/uid_map"), as);
        REQUIRE_MESSAGE(b.code == 0, b.err);
        CHECK(parseJson(b.out).get("Snapshotter").asString() == "copy");

        ToolResult run = co_await runTool(t.path, tool("sbox"), Args("run", "--bundle", bundle, "e2e-rootless-" + randomSuffix()), as);
        CHECK_MESSAGE(run.code == 0, run.err);
        std::vector<std::string> lines;
        for (std::string_view l : CFile::splitLines(run.out)) {
            lines.emplace_back(l);
        }

        REQUIRE_MESSAGE(lines.size() == 3, run.out);
        CHECK(lines[0] == "0");
        CHECK(lines[1] == "layer-two");
        CHECK(lines[2].find("65534") != std::string::npos);
        CHECK(CFile::exists(userHome + "/run/sbox"));

        ToolResult rm = co_await runTool(t.path, tool("sbox-image"), Args("rm", parseJson(b.out).get("Id").asString()), as);
        CHECK_MESSAGE(rm.code == 0, rm.err);
    }(tmp, home, archivePath));
}
