#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "clitest.hpp"
#include <sbox/box/cgroup.hpp>
#include <sbox/oci/spec.hpp>

using namespace sbox;
using namespace sbox::oci;
using namespace ocitest;

namespace {

    /**
     * A bundle and a state root for CLI runs.
     */
    struct CliEnv {
        TempDir tmp;
        std::string bundle;
        std::string root;
        std::string id;
        std::vector<std::string> globals;

        CliEnv() {
            bundle = tmp / "bundle";
            root = tmp / "state";
            CFile::makeDirs(bundle, 0755);
            REQUIRE(makeRootfs(bundle + "/rootfs"));
            id = "cli-" + randomSuffix();
            globals = { "--root", root };
        }

        ToolResult sbox(std::vector<std::string> args, const std::string& input = std::string()) {
            std::vector<std::string> all = globals;
            all.insert(all.end(), args.begin(), args.end());
            return runTool(tmp.path, tool("sbox"), all, input);
        }
    };

    bool canRun() {
        if (!isRoot()) {
            MESSAGE("not root; skipping container test");
            return false;
        }

        return true;
    }

}

TEST_CASE("version, help and unknown commands") {
    TempDir tmp;
    ToolResult r = runTool(tmp.path, tool("sbox"), { "--version" });
    CHECK(r.code == 0);
    CHECK(r.out.rfind("sbox version ", 0) == 0);
    CHECK(r.out.find("spec: 1.2.1") != std::string::npos);

    r = runTool(tmp.path, tool("sboxrun"), { "-v" });
    CHECK(r.out.rfind("sboxrun version ", 0) == 0);

    r = runTool(tmp.path, tool("sbox"), { "--help" });
    CHECK(r.code == 0);
    CHECK(r.out.find("create") != std::string::npos);

    r = runTool(tmp.path, tool("sbox"), { "bogus" });
    CHECK(r.code == 1);
    CHECK(r.err.find("No help topic for 'bogus'") != std::string::npos);

    r = runTool(tmp.path, tool("sbox"), { "--bogus-flag", "list" });
    CHECK(r.code == 1);

    r = runTool(tmp.path, tool("sbox"), { "checkpoint", "x" });
    CHECK(r.code == 1);
    CHECK(r.err.find("not supported") != std::string::npos);

    r = runTool(tmp.path, tool("sbox"), { "--root", tmp / "empty", "state", "nope" });
    CHECK(r.code == 1);
    CHECK(r.err.find("level=error msg=\"container does not exist\"") != std::string::npos);
}

TEST_CASE("spec writes runc's default configuration") {
    TempDir tmp;
    ToolResult r = runTool(tmp.path, tool("sbox"), { "spec", "--bundle", tmp.path });
    REQUIRE(r.code == 0);

    SSpec spec;
    std::string err;
    REQUIRE(LoadSpec(tmp / "config.json", spec, err) == SBOX_OK);
    CHECK(jsonEqual(SpecToJson(spec), SpecToJson(DefaultSpec(false, 0, 0, "sbox"))));

    r = runTool(tmp.path, tool("sbox"), { "spec", "-b", tmp.path });
    CHECK(r.code == 1);
    CHECK(r.err.find("exists") != std::string::npos);

    CFile::removeTree(tmp / "config.json");
    r = runTool(tmp.path, tool("sbox"), { "spec", "--rootless", "--bundle", tmp.path });
    REQUIRE(r.code == 0);
    REQUIRE(LoadSpec(tmp / "config.json", spec, err) == SBOX_OK);
    CHECK(jsonEqual(SpecToJson(spec), SpecToJson(DefaultSpec(true, ::geteuid(), ::getegid(), "sbox"))));
}

TEST_CASE("features describes this runtime") {
    TempDir tmp;
    ToolResult r = runTool(tmp.path, tool("sbox"), { "features" });
    REQUIRE(r.code == 0);
    CJson f = parseJson(r.out);
    CHECK(f.get("ociVersionMax").asString() == "1.2.1");
    CHECK(f.get("hooks").size() == 6);
    CHECK(f.get("linux").get("seccomp").get("enabled").asBool());
    CHECK(!f.get("linux").get("apparmor").get("enabled").asBool(true));
    CHECK(f.get("linux").get("capabilities").size() >= 38);
}

TEST_CASE("the CLI lifecycle: create, state, start, ps, list, kill, delete") {
    if (!canRun()) {
        return;
    }

    CliEnv env;
    REQUIRE(writeSpec(env.bundle, testSpec({ "sleep", "1000" })));

    ToolResult r = env.sbox({ "create", "--bundle", env.bundle, "--pid-file", env.tmp / "pid", env.id });
    REQUIRE_MESSAGE(r.code == 0, r.err);

    r = env.sbox({ "state", env.id });
    REQUIRE(r.code == 0);
    CJson st = parseJson(r.out);
    CHECK(st.get("status").asString() == "created");
    CHECK(st.get("ociVersion").asString() == "1.2.1");
    int64_t pid = st.get("pid").asInt();
    CHECK(pid > 0);
    std::string pidFile;
    CFile::readAll(env.tmp / "pid", pidFile);
    CHECK(pidFile == std::to_string(pid));

    r = env.sbox({ "list" });
    // --> Go tabwriter layout: columns padded to the widest cell + 3, at least 12.
    std::string header = "ID" + std::string(env.id.size() + 1, ' ') + "PID         STATUS      BUNDLE";
    CHECK_MESSAGE(r.out.rfind(header, 0) == 0, r.out);
    CHECK(r.out.find(env.id) != std::string::npos);
    CHECK(r.out.find("created") != std::string::npos);

    r = env.sbox({ "start", env.id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    CHECK(parseJson(env.sbox({ "state", env.id }).out).get("status").asString() == "running");

    r = env.sbox({ "ps", "--format", "json", env.id });
    REQUIRE(r.code == 0);
    CJson pids = parseJson(r.out);
    REQUIRE(pids.isArray());
    CHECK(pids.size() >= 1);

    r = env.sbox({ "ps", env.id });
    REQUIRE_MESSAGE(r.code == 0, r.err);
    CHECK(r.out.find("PID") != std::string::npos);
    CHECK(r.out.find("sleep 1000") != std::string::npos);

    r = env.sbox({ "list", "--format", "json" });
    CJson list = parseJson(r.out);
    REQUIRE(list.size() == 1);
    CHECK(list.at(0).get("status").asString() == "running");
    CHECK(list.at(0).get("owner").asString() == "root");

    r = env.sbox({ "list", "-q" });
    CHECK(r.out == env.id + "\n");

    r = env.sbox({ "delete", env.id });
    CHECK(r.code == 1);
    CHECK(r.err.find("that is not stopped: running") != std::string::npos);

    r = env.sbox({ "kill", env.id, "NOPE" });
    CHECK(r.code == 1);

    r = env.sbox({ "kill", env.id, "SIGKILL" });
    REQUIRE(r.code == 0);
    CHECK(waitToolStatus(env.tmp.path, tool("sbox"), env.globals, env.id, "stopped") == "stopped");

    r = env.sbox({ "kill", env.id });
    CHECK(r.code == 1);
    CHECK(r.err.find("container not running") != std::string::npos);

    r = env.sbox({ "delete", env.id });
    CHECK(r.code == 0);
    r = env.sbox({ "state", env.id });
    CHECK(r.code == 1);
}

TEST_CASE("run in the foreground returns the exit status and removes the container") {
    if (!canRun()) {
        return;
    }

    CliEnv env;
    REQUIRE(writeSpec(env.bundle, testSpec({ "sh", "-c", "echo from-container; exit 6" })));

    ToolResult r = env.sbox({ "run", "--bundle", env.bundle, env.id });
    CHECK(r.code == 6);
    CHECK(r.out.find("from-container") != std::string::npos);
    CHECK(env.sbox({ "state", env.id }).code == 1);

    // --> --keep leaves the stopped container.
    r = env.sbox({ "run", "--keep", "-b", env.bundle, env.id });
    CHECK(r.code == 6);
    CHECK(parseJson(env.sbox({ "state", env.id }).out).get("status").asString() == "stopped");
    CHECK(env.sbox({ "delete", env.id }).code == 0);
}

TEST_CASE("run with a terminal proxies the pty") {
    if (!canRun()) {
        return;
    }

    CliEnv env;
    SSpec spec = testSpec({ "sh", "-c", "test -t 0 && test -t 1 && echo tty-ok; read line; echo got:$line" });
    spec.process->terminal = true;
    REQUIRE(writeSpec(env.bundle, spec));

    ToolResult r = env.sbox({ "run", "-b", env.bundle, env.id }, "hello\n");
    CHECK(r.code == 0);
    CHECK_MESSAGE(r.out.find("tty-ok") != std::string::npos, r.out);
    CHECK_MESSAGE(r.out.find("got:hello") != std::string::npos, r.out);

    // --> Detached with a terminal needs a console socket.
    r = env.sbox({ "run", "-d", "-b", env.bundle, env.id });
    CHECK(r.code == 1);
    CHECK(r.err.find("console socket") != std::string::npos);
}

TEST_CASE("exec from the command line: output, status, env, cwd, user") {
    if (!canRun()) {
        return;
    }

    CliEnv env;
    REQUIRE(writeSpec(env.bundle, testSpec({ "sleep", "1000" })));
    REQUIRE(env.sbox({ "run", "-d", "-b", env.bundle, env.id }).code == 0);
    CHECK(parseJson(env.sbox({ "state", env.id }).out).get("status").asString() == "running");

    ToolResult r = env.sbox({ "exec", "--env", "GREETING=hi", "--cwd", "/tmp", env.id, "sh", "-c", "echo $GREETING; pwd; exit 4" });
    CHECK(r.code == 4);
    CHECK(r.out == "hi\n/tmp\n");

    r = env.sbox({ "exec", "-u", "65534:65534", env.id, "id", "-u" });
    CHECK(r.code == 0);
    CHECK(r.out == "65534\n");

    r = env.sbox({ "exec", env.id });
    CHECK(r.code == 1);
    CHECK(r.err.find("args cannot be empty") != std::string::npos);

    r = env.sbox({ "exec", "-d", "--pid-file", env.tmp / "exec.pid", env.id, "sleep", "500" });
    CHECK(r.code == 0);
    std::string text;
    CFile::readAll(env.tmp / "exec.pid", text);
    CHECK(std::atoi(text.c_str()) > 0);

    r = env.sbox({ "pause", env.id });
    CHECK(r.code == 0);
    CHECK(parseJson(env.sbox({ "state", env.id }).out).get("status").asString() == "paused");
    r = env.sbox({ "exec", env.id, "true" });
    CHECK(r.code == 1);
    CHECK(r.err.find("paused") != std::string::npos);
    CHECK(env.sbox({ "resume", env.id }).code == 0);

    r = env.sbox({ "events", "--stats", env.id });
    CHECK(r.code == 0);
    CJson ev = parseJson(r.out);
    CHECK(ev.get("type").asString() == "stats");
    CHECK(ev.get("id").asString() == env.id);
    CHECK(ev.get("data").get("pids").get("current").asInt() >= 2);

    r = env.sbox({ "update", "--memory", "48m", "--pids-limit", "20", env.id });
    CHECK_MESSAGE(r.code == 0, r.err);
    r = env.sbox({ "update", "--memory", "lots", env.id });
    CHECK(r.code == 1);

    CHECK(env.sbox({ "delete", "--force", env.id }).code == 0);
    CHECK(env.sbox({ "state", env.id }).code == 1);
}
