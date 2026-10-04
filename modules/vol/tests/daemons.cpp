#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "pluginclient.hpp"
#include "testutil.hpp"

#ifndef SBOX_TEST_BIN_DIR
#define SBOX_TEST_BIN_DIR ""
#endif

using namespace sbox;
using namespace testutil;

namespace {

    std::string binary(const char* name) {
        return std::string(SBOX_TEST_BIN_DIR) + "/" + name;
    }

    /* Starts a program in the background. */
    pid_t startDaemon(std::vector<std::string> argv) {
        std::vector<char*> args;
        for (std::string& a : argv) {
            args.push_back(a.data());
        }

        args.push_back(nullptr);
        std::fflush(nullptr);
        pid_t pid = ::fork();
        if (pid == 0) {
            ::execv(args[0], args.data());
            ::_exit(127);
        }

        return pid;
    }

    /* Waits until `path` exists (the daemon is listening). */
    TTask<bool> waitForSocket(std::string path, int64_t timeoutMs = 20000) {
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        while (CEventLoop::nowMs() < deadline) {
            struct stat st{};
            if (::stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
                co_return true;
            }

            co_await CEventLoop::current()->sleepFor(10);
        }

        co_return false;
    }

    /* Runs the sboxvol CLI against a store. */
    TTask<int> sboxvol(std::string root, std::vector<std::string> args, std::string* out = nullptr) {
        std::vector<std::string> argv = { binary("sboxvol"), "--root", root };
        argv.insert(argv.end(), args.begin(), args.end());
        co_return co_await runProgram(argv, out);
    }

}

TEST_CASE("sboxvol CLI commands") {
    if (::access(binary("sboxvol").c_str(), X_OK) != 0) {
        MESSAGE("skipped: sboxvol binary not built");
        return;
    }

    TempDir dir("cli");
    std::string root = dir / "store";
    CEventLoop loop;
    std::string out;

    CHECK(loop.run(runProgram({ binary("sboxvol"), "--help" }, &out)) == 0);
    CHECK(out.find("Usage: sboxvol") != std::string::npos);

    CHECK(loop.run(sboxvol(root, { "create", "--label", "env=test", "--opt", "size=", "named" }, &out)) != 0);
    CHECK(loop.run(sboxvol(root, { "create", "--label", "env=test", "named" }, &out)) == 0);
    CHECK(out == "named\n");
    CHECK(loop.run(sboxvol(root, { "create" }, &out)) == 0);
    std::string anon = out.substr(0, out.size() - 1);
    CHECK(anon.size() == 64);

    CHECK(loop.run(sboxvol(root, { "ls" }, &out)) == 0);
    CHECK(out.find("DRIVER    VOLUME NAME") == 0);
    CHECK(out.find("local     named") != std::string::npos);
    CHECK(loop.run(sboxvol(root, { "ls", "-q", "--filter", "label=env=test" }, &out)) == 0);
    CHECK(out == "named\n");

    CHECK(loop.run(sboxvol(root, { "inspect", "named" }, &out)) == 0);
    CJson inspected;
    REQUIRE(CJson::parse(out, inspected) == SBOX_OK);
    REQUIRE(inspected.size() == 1);
    CHECK(inspected.at(0).get("Name").asString() == "named");
    CHECK(inspected.at(0).get("Labels").get("env").asString() == "test");
    CHECK(inspected.at(0).get("Mountpoint").asString() == root + "/named/_data");
    CHECK(loop.run(sboxvol(root, { "inspect", "missing" }, &out)) == 1);

    REQUIRE(writeFile(root + "/named/_data/payload", "backed up"));
    CHECK(loop.run(sboxvol(root, { "backup", "named", dir / "named.tgz" })) == 0);
    CHECK(loop.run(sboxvol(root, { "restore", "copy", dir / "named.tgz" })) == 0);
    CHECK(readFile(root + "/copy/_data/payload") == "backed up");
    CHECK(loop.run(sboxvol(root, { "restore", "copy", dir / "named.tgz" })) == 1);
    CHECK(loop.run(sboxvol(root, { "restore", "--overwrite", "copy", dir / "named.tgz" })) == 0);

    // --> Backup to stdout and restore from stdin.
    std::string archive;
    CHECK(loop.run(sboxvol(root, { "backup", "named", "-" }, &archive)) == 0);
    CHECK(archive.size() > 20);
    CHECK(loop.run(runProgram({ binary("sboxvol"), "--root", root, "restore", "piped", "-" }, nullptr, archive)) == 0);
    CHECK(readFile(root + "/piped/_data/payload") == "backed up");

    CHECK(loop.run(sboxvol(root, { "prune" }, &out)) == 0);
    CHECK(out.find("Deleted Volumes:\n" + anon) == 0);
    CHECK(loop.run(sboxvol(root, { "rm", "named", "copy" }, &out)) == 0);
    CHECK(out == "named\ncopy\n");
    CHECK(loop.run(sboxvol(root, { "rm", "named" }, &out)) == 1);
    CHECK(loop.run(sboxvol(root, { "prune", "-a" }, &out)) == 0);
    CHECK(out.find("piped") != std::string::npos);
    CHECK(loop.run(sboxvol(root, { "ls", "-q" }, &out)) == 0);
    CHECK(out.empty());
    CHECK(loop.run(sboxvol(root, { "frobnicate" })) == 1);
}

TEST_CASE("sboxvol serve speaks the volume plugin protocol and stops on SIGTERM") {
    if (::access(binary("sboxvol").c_str(), X_OK) != 0) {
        MESSAGE("skipped: sboxvol binary not built");
        return;
    }

    TempDir dir("volsrv");
    std::string root = dir / "store";
    std::string sock = dir / "plugins/sboxvol.sock";
    CEventLoop loop;
    pid_t pid = startDaemon({ binary("sboxvol"), "--root", root, "serve", "--socket", sock });
    REQUIRE(pid > 0);
    bool up = loop.run(waitForSocket(sock));
    REQUIRE(up);

    auto flow = [&]() -> TTask<void> {
        http::CHttpClient client;
        PluginReply r = co_await pluginCall(client, sock, "/Plugin.Activate", CJson::object());
        CHECK(r.rc == SBOX_OK);
        CHECK(r.status == 200);
        CHECK(r.contentType == "application/vnd.docker.plugins.v1.2+json");
        CHECK(r.body.dump() == "{\"Implements\":[\"VolumeDriver\"]}");

        r = co_await pluginCall(client, sock, "/VolumeDriver.Create", nameBody("dockervol", "Opts", CJson::object()));
        CHECK(r.body.get("Err").asString() == "");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Mount", nameBody("dockervol", "ID", CJson("c0ffee")));
        CHECK(r.body.get("Mountpoint").asString() == root + "/dockervol/_data");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Remove", nameBody("dockervol"));
        CHECK(r.status == 200);
        CHECK(!r.body.get("Err").asString().empty());
        r = co_await pluginCall(client, sock, "/VolumeDriver.Unmount", nameBody("dockervol", "ID", CJson("c0ffee")));
        CHECK(r.body.get("Err").asString() == "");
        r = co_await pluginCall(client, sock, "/VolumeDriver.List", CJson::object());
        CHECK(r.body.get("Volumes").size() == 1);
        r = co_await pluginCall(client, sock, "/VolumeDriver.Capabilities", CJson::object());
        CHECK(r.body.dump() == "{\"Capabilities\":{\"Scope\":\"local\"}}");
        r = co_await pluginCall(client, sock, "/VolumeDriver.Remove", nameBody("dockervol"));
        CHECK(r.body.get("Err").asString() == "");
    };

    loop.run(flow());
    CHECK(::kill(pid, SIGTERM) == 0);
    int status = loop.run(waitChild(pid, 20000));
    CHECK(status == 0);
    CHECK(!CFile::exists(sock));
}

TEST_CASE("sboxnet serves the network and IPAM plugin and stops on SIGINT") {
    if (::access(binary("sboxnet").c_str(), X_OK) != 0) {
        MESSAGE("skipped: sboxnet binary not built");
        return;
    }

    TempDir dir("netsrv");
    std::string sock = dir / "sboxnet.sock";
    CEventLoop loop;
    std::string help;
    CHECK(loop.run(runProgram({ binary("sboxnet"), "--help" }, &help)) == 0);
    CHECK(help.find("--state-dir") != std::string::npos);
    CHECK(loop.run(runProgram({ binary("sboxnet"), "--bogus" })) == 1);

    pid_t pid = startDaemon({ binary("sboxnet"), "--socket", sock, "--state-dir", dir / "state", "--no-firewall" });
    REQUIRE(pid > 0);
    bool up = loop.run(waitForSocket(sock));
    REQUIRE(up);

    auto flow = [&]() -> TTask<void> {
        http::CHttpClient client;
        PluginReply r = co_await pluginCall(client, sock, "/Plugin.Activate", CJson::object());
        CHECK(r.rc == SBOX_OK);
        CHECK(r.status == 200);
        CHECK(r.contentType == "application/vnd.docker.plugins.v1.2+json");
        std::vector<std::string> impl = r.body.get("Implements").asStrings();
        CHECK(impl == std::vector<std::string>{ "NetworkDriver", "IpamDriver" });

        r = co_await pluginCall(client, sock, "/NetworkDriver.GetCapabilities", CJson::object());
        CHECK(r.status == 200);
        CHECK(r.body.get("Scope").asString() == "local");

        r = co_await pluginCall(client, sock, "/IpamDriver.GetDefaultAddressSpaces", CJson::object());
        CHECK(r.status == 200);
        CHECK(r.body.get("LocalDefaultAddressSpace").asString() == "local");
        CHECK(r.body.get("GlobalDefaultAddressSpace").asString() == "global");

        r = co_await pluginCall(client, sock, "/NetworkDriver.Nonsense", CJson::object());
        CHECK(!r.body.get("Err").asString().empty());
    };

    loop.run(flow());
    CHECK(::kill(pid, SIGINT) == 0);
    int status = loop.run(waitChild(pid, 20000));
    CHECK(status == 0);
    CHECK(!CFile::exists(sock));
}
