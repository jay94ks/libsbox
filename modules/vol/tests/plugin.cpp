#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "pluginclient.hpp"
#include "testutil.hpp"

#include <sbox/core/socket.hpp>
#include <sbox/http/server.hpp>
#include <sbox/vol/plugin.hpp>

using namespace sbox;
using namespace sbox::vol;
using namespace testutil;

namespace {

    /**
     * Plugin served on a UNIX socket inside the current loop.
     */
    struct PluginServer {
        CVolumeStore store;
        CVolumePlugin plugin;
        http::CHttpServer server;
        CListener listener;
        std::string socket;

        PluginServer(const std::string& root, const std::string& sock)
            : store(makeOptions(root)), plugin(store), socket(sock) {
            plugin.attach(server);
            SEndpoint ep;
            SEndpoint::fromUnix(socket, ep);
            listener.listen(ep);
        }

        static SVolumeStoreOptions makeOptions(const std::string& root) {
            SVolumeStoreOptions o;
            o.root = root;
            return o;
        }
    };

    /* Creates one volume through its own client (parameters live in the coroutine frame). */
    TTask<void> createOne(std::string sock, std::string name, PluginReply* out, int* finished) {
        http::CHttpClient own;
        *out = co_await pluginCall(own, sock, "/VolumeDriver.Create", nameBody(name));
        ++*finished;
    }

    /* Runs `body` against a served plugin and stops the server afterwards. */
    TTask<void> withServer(PluginServer& ps, std::function<TTask<void>(http::CHttpClient&)> body) {
        CEventLoop* loop = CEventLoop::current();
        bool done = false;
        auto serve = [&]() -> TTask<void> {
            co_await ps.server.serve(ps.listener);
            done = true;
        };

        loop->spawn(serve());
        {
            http::CHttpClient client;
            co_await body(client);
        }

        ps.server.stop();
        while (!done) {
            co_await loop->sleepFor(1);
        }
    }

}

TEST_CASE("handler basics without HTTP") {
    TempDir dir("handler");
    CEventLoop loop;
    SVolumeStoreOptions o;
    o.root = dir / "v";
    CVolumeStore store(o);
    CVolumePlugin plugin(store);

    CHECK(std::string(CVolumePlugin::contentType()) == "application/vnd.docker.plugins.v1.2+json");
    CHECK(CVolumePlugin::isKnownPath("/VolumeDriver.Mount"));
    CHECK(!CVolumePlugin::isKnownPath("/NetworkDriver.Join"));

    CJson r = loop.run(plugin.handle("/Plugin.Activate", CJson()));
    CHECK(r.dump() == "{\"Implements\":[\"VolumeDriver\"]}");
    r = loop.run(plugin.handle("/VolumeDriver.Capabilities", CJson::object()));
    CHECK(r.dump() == "{\"Capabilities\":{\"Scope\":\"local\"}}");
    r = loop.run(plugin.handle("/VolumeDriver.Get", nameBody("absent")));
    CHECK(CVolumePlugin::isError(r));
    CHECK(r.get("Err").asString() == "no such volume: absent");
    r = loop.run(plugin.handle("/VolumeDriver.Create", CJson::object()));
    CHECK(r.get("Err").asString() == "missing volume name");
    r = loop.run(plugin.handle("/VolumeDriver.Bogus", CJson::object()));
    CHECK(CVolumePlugin::isError(r));
    r = loop.run(plugin.handle("/VolumeDriver.List", CJson()));
    CHECK(!CVolumePlugin::isError(r));
    CHECK(r.get("Volumes").isArray());
}

TEST_CASE("Docker volume plugin protocol end to end over a UNIX socket") {
    TempDir dir("plugin");
    CEventLoop loop;
    PluginServer ps(dir / "volumes", dir / "sboxvol.sock");
    REQUIRE(ps.listener.isValid());

    loop.run(withServer(ps, [&](http::CHttpClient& client) -> TTask<void> {
        std::string sock = ps.socket;

        PluginReply r = co_await pluginCall(client, sock, "/Plugin.Activate", CJson::object());
        CHECK(r.rc == SBOX_OK);
        CHECK(r.status == 200);
        CHECK(r.contentType == "application/vnd.docker.plugins.v1.2+json");
        CHECK(r.body.get("Implements").asStrings() == std::vector<std::string>{ "VolumeDriver" });

        r = co_await pluginCall(client, sock, "/VolumeDriver.Capabilities", CJson::object());
        CHECK(r.body.get("Capabilities").get("Scope").asString() == "local");

        // --> Create with local driver options.
        CJson opts = CJson::object();
        opts.set("type", CJson("tmpfs"));
        opts.set("device", CJson("tmpfs"));
        opts.set("o", CJson("size=1m"));
        r = co_await pluginCall(client, sock, "/VolumeDriver.Create", nameBody("withopts", "Opts", opts));
        CHECK(r.status == 200);
        CHECK(r.body.get("Err").asString() == "");

        r = co_await pluginCall(client, sock, "/VolumeDriver.Create", nameBody("plain", "Opts", CJson()));
        CHECK(r.body.get("Err").asString() == "");

        // --> Invalid options: Err with HTTP 200.
        CJson badOpts = CJson::object();
        badOpts.set("flavor", CJson("x"));
        r = co_await pluginCall(client, sock, "/VolumeDriver.Create", nameBody("bad", "Opts", badOpts));
        CHECK(r.status == 200);
        CHECK(r.body.get("Err").asString().find("invalid option") != std::string::npos);

        r = co_await pluginCall(client, sock, "/VolumeDriver.Get", nameBody("withopts"));
        CHECK(r.body.get("Err").asString() == "");
        const CJson& vol = r.body.get("Volume");
        CHECK(vol.get("Name").asString() == "withopts");
        CHECK(vol.get("Mountpoint").asString() == dir / "volumes/withopts/_data");
        CHECK(vol.get("CreatedAt").asString().size() == 20);
        CHECK(vol.get("Status").get("Options").get("type").asString() == "tmpfs");

        r = co_await pluginCall(client, sock, "/VolumeDriver.List", CJson::object());
        CHECK(r.body.get("Volumes").size() == 2);
        CHECK(r.body.get("Volumes").at(0).get("Name").asString() == "plain");

        r = co_await pluginCall(client, sock, "/VolumeDriver.Path", nameBody("plain"));
        CHECK(r.body.get("Mountpoint").asString() == dir / "volumes/plain/_data");

        // --> Mount / Unmount with IDs (reference counted).
        r = co_await pluginCall(client, sock, "/VolumeDriver.Mount", nameBody("plain", "ID", CJson("mount-1")));
        CHECK(r.body.get("Err").asString() == "");
        CHECK(r.body.get("Mountpoint").asString() == dir / "volumes/plain/_data");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Mount", nameBody("plain", "ID", CJson("mount-2")));
        CHECK(r.body.get("Err").asString() == "");

        r = co_await pluginCall(client, sock, "/VolumeDriver.Remove", nameBody("plain"));
        CHECK(r.status == 200);
        CHECK(r.body.get("Err").asString().find("in use") != std::string::npos);

        r = co_await pluginCall(client, sock, "/VolumeDriver.Get", nameBody("plain"));
        CHECK(r.body.get("Volume").get("Status").get("RefCount").asInt() == 2);

        r = co_await pluginCall(client, sock, "/VolumeDriver.Unmount", nameBody("plain", "ID", CJson("mount-1")));
        CHECK(r.body.get("Err").asString() == "");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Unmount", nameBody("plain", "ID", CJson("mount-2")));
        CHECK(r.body.get("Err").asString() == "");

        r = co_await pluginCall(client, sock, "/VolumeDriver.Remove", nameBody("plain"));
        CHECK(r.body.get("Err").asString() == "");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Remove", nameBody("plain"));
        CHECK(r.body.get("Err").asString() == "no such volume: plain");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Mount", nameBody("plain", "ID", CJson("m")));
        CHECK(r.body.get("Err").asString() == "no such volume: plain");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Path", nameBody("plain"));
        CHECK(r.body.get("Err").asString() == "no such volume: plain");

        // --> Unknown endpoints answer 404 with Err.
        r = co_await pluginCall(client, sock, "/VolumeDriver.Frobnicate", CJson::object());
        CHECK(r.status == 404);
        CHECK(r.body.get("Err").asString().find("unsupported") != std::string::npos);

        // --> Concurrent creates through one server.
        std::vector<PluginReply> replies(8);
        int finished = 0;
        for (int i = 0; i < 8; ++i) {
            CEventLoop::current()->spawn(createOne(sock, "par-" + std::to_string(i), &replies[size_t(i)], &finished));
        }

        while (finished < 8) {
            co_await CEventLoop::current()->sleepFor(1);
        }

        for (const PluginReply& p : replies) {
            CHECK(p.rc == SBOX_OK);
            CHECK(p.body.get("Err").asString() == "");
        }

        r = co_await pluginCall(client, sock, "/VolumeDriver.List", CJson::object());
        CHECK(r.body.get("Volumes").size() == 9);
    }));
}

TEST_CASE("plugin Mount of a tmpfs volume mounts it, Unmount releases it") {
    if (!isRoot()) {
        MESSAGE("skipped: needs root for mount(2)");
        return;
    }

    TempDir dir("pluginmnt");
    std::string root = dir / "volumes";
    std::string sock = dir / "p.sock";
    int code = runInPrivateMountNs([&]() -> int {
        CEventLoop loop;
        PluginServer ps(root, sock);
        int failures = 0;
        loop.run(withServer(ps, [&](http::CHttpClient& client) -> TTask<void> {
            CJson opts = CJson::object();
            opts.set("type", CJson("tmpfs"));
            opts.set("device", CJson("tmpfs"));
            opts.set("o", CJson("size=1m,mode=0777"));
            PluginReply r = co_await pluginCall(client, sock, "/VolumeDriver.Create", nameBody("mem", "Opts", opts));
            failures += r.body.get("Err").asString() != "";
            r = co_await pluginCall(client, sock, "/VolumeDriver.Mount", nameBody("mem", "ID", CJson("abc")));
            std::string mp = r.body.get("Mountpoint").asString();
            failures += mp.empty() || !IsMountPoint(mp);
            failures += !writeFile(mp + "/f", "x");
            r = co_await pluginCall(client, sock, "/VolumeDriver.Unmount", nameBody("mem", "ID", CJson("abc")));
            failures += r.body.get("Err").asString() != "";
            failures += IsMountPoint(mp);
            failures += CFile::exists(mp + "/f");
        }));

        CHILD_CHECK(failures == 0);
        return 0;
    });

    if (code == 77) {
        MESSAGE("skipped: cannot create a mount namespace");
        return;
    }

    CHECK(code == 0);
}
