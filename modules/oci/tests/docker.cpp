#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "clitest.hpp"
#include <algorithm>
#include <sys/mount.h>

// End-to-end check with a real Docker engine: a private dockerd (own data-root, exec-root and
// socket, no iptables, no bridge) is started with `sboxrun` registered as a runtime, an image
// is imported from the test rootfs and containers are run with --runtime=sboxrun.
//
// Opt-in: it starts daemons and takes a while, so it runs only with SBOX_TEST_DOCKER=1 (and
// root, and dockerd/docker installed).

using namespace sbox;
using namespace ocitest;

namespace {

    /**
     * Unmounts everything below `prefix` (deepest first).
     */
    void unmountBelow(const std::string& prefix) {
        std::string text;
        CFile::readAll("/proc/self/mountinfo", text);
        std::vector<std::string> points;
        for (std::string_view line : CFile::splitLines(text)) {
            // --> Field 5 is the mount point.
            size_t pos = 0;
            for (int i = 0; i < 4 && pos != std::string_view::npos; ++i) {
                pos = line.find(' ', pos + 1);
            }

            if (pos == std::string_view::npos) {
                continue;
            }

            size_t end = line.find(' ', pos + 1);
            std::string point(line.substr(pos + 1, end - pos - 1));
            if (point.rfind(prefix, 0) == 0) {
                points.push_back(point);
            }
        }

        std::sort(points.begin(), points.end(), [](const std::string& a, const std::string& b) { return a.size() > b.size(); });
        for (const std::string& p : points) {
            ::umount2(p.c_str(), MNT_DETACH);
        }
    }

}

TEST_CASE("docker run --runtime=sboxrun (real dockerd, opt-in)") {
    const char* optIn = std::getenv("SBOX_TEST_DOCKER");
    if (!optIn || std::string(optIn) != "1") {
        MESSAGE("set SBOX_TEST_DOCKER=1 to run the Docker end-to-end test");
        return;
    }

    if (!isRoot() || ::access("/usr/bin/dockerd", X_OK) != 0 || ::access("/usr/bin/docker", X_OK) != 0) {
        MESSAGE("needs root and dockerd/docker; skipping");
        return;
    }

    TempDir tmp;
    REQUIRE(makeRootfs(tmp / "rootfs"));
    CJson cfg = CJson::object();
    CJson runtimes = CJson::object();
    CJson sboxrun = CJson::object();
    sboxrun.set("path", tool("sboxrun"));
    runtimes.set("sboxrun", sboxrun);
    cfg.set("runtimes", runtimes);
    cfg.set("iptables", false);
    cfg.set("ip6tables", false);
    cfg.set("bridge", "none");
    cfg.set("data-root", tmp / "data");
    cfg.set("exec-root", tmp / "exec");
    cfg.set("pidfile", tmp / "docker.pid");
    cfg.set("hosts", CJson::fromStrings({ "unix://" + (tmp / "docker.sock") }));
    REQUIRE(CFile::writeAtomic(tmp / "daemon.json", cfg.dump(true), 0644) == SBOX_OK);

    pid_t daemon = ::fork();
    if (daemon == 0) {
        int log = ::open((tmp / "dockerd.log").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ::dup2(log, 1);
        ::dup2(log, 2);
        std::string config = tmp / "daemon.json";
        ::execl("/usr/bin/dockerd", "dockerd", "--config-file", config.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }

    std::string d = "docker -H unix://" + (tmp / "docker.sock") + " ";
    int status = 1;
    for (int i = 0; i < 300 && status != 0; ++i) {
        ::usleep(100000);
        capture(d + "version >/dev/null 2>&1", &status);
    }

    if (status == 0) {
        capture("tar -C " + (tmp / "rootfs") + " -cf " + (tmp / "rootfs.tar") + " .");
        std::string out = capture(d + "import " + (tmp / "rootfs.tar") + " sboxtest:latest 2>&1", &status);
        REQUIRE_MESSAGE(status == 0, out);

        std::string run = d + "run --rm --runtime=sboxrun --network=none sboxtest:latest ";
        out = capture(run + "sh -c 'echo hello-docker; exit 7' 2>&1", &status);
        CHECK(status == 7);
        CHECK(out.find("hello-docker") != std::string::npos);

        out = capture(run + "no-such-binary 2>&1", &status);
        CHECK(status == 127);
        CHECK(out.find("executable file not found") != std::string::npos);

        out = capture(d + "run --rm -t --runtime=sboxrun --network=none sboxtest:latest sh -c 'test -t 1 && echo is-a-tty' 2>&1", &status);
        CHECK(status == 0);
        CHECK(out.find("is-a-tty") != std::string::npos);

        std::string cid = capture(d + "run -d --runtime=sboxrun --network=none -m 64m sboxtest:latest sleep 1000", &status);
        REQUIRE(status == 0);
        while (!cid.empty() && cid.back() == '\n') {
            cid.pop_back();
        }

        out = capture(d + "exec " + cid + " sh -c 'echo exec-ok; exit 3' 2>&1", &status);
        CHECK(status == 3);
        CHECK(out.find("exec-ok") != std::string::npos);

        capture(d + "pause " + cid, &status);
        CHECK(status == 0);
        out = capture(d + "inspect -f '{{.State.Status}}' " + cid);
        CHECK(out == "paused\n");
        capture(d + "unpause " + cid, &status);
        CHECK(status == 0);

        capture(d + "update --pids-limit 50 " + cid + " 2>&1", &status);
        CHECK(status == 0);
        out = capture(d + "top " + cid + " 2>&1", &status);
        CHECK(out.find("sleep 1000") != std::string::npos);

        capture(d + "stop -t 1 " + cid + " 2>&1", &status);
        CHECK(status == 0);
        out = capture(d + "inspect -f '{{.State.ExitCode}}' " + cid);
        CHECK(out == "137\n");
        capture(d + "rm " + cid + " 2>&1", &status);
        CHECK(status == 0);
    } else {
        std::string log;
        CFile::readAll(tmp / "dockerd.log", log);
        MESSAGE("dockerd did not come up: " << log);
    }

    ::kill(daemon, SIGTERM);
    for (int i = 0; i < 300; ++i) {
        if (::waitpid(daemon, nullptr, WNOHANG) == daemon) {
            break;
        }

        ::usleep(100000);
    }

    unmountBelow(tmp.path);
}
