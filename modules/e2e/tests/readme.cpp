// The CSandbox example of README.md, compiled exactly as written (CMake cuts the first ```cpp
// block out of README.md into its own program) and run: it feeds "1 2\n" to `main.py` in
// /srv/job and returns the program's exit code. /srv/job is provided in this test's private
// mount namespace (a tmpfs over /srv), so the host's /srv is never touched.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "e2e.hpp"

using namespace sbox;
using namespace e2e;

TEST_CASE("the README example compiles and runs as written") {
    if (!isRoot()) {
        MESSAGE("not root (or no private mount namespace): cannot provide /srv/job; skipping");
        return;
    }

    struct stat st;
    if (::stat("/srv", &st) != 0 || !S_ISDIR(st.st_mode)) {
        MESSAGE("the host has no /srv to mount over; skipping");
        return;
    }

    TempDir tmp;
    std::string job = tmp / "job";
    CFile::makeDirs(job, 0777);
    ::chmod(job.c_str(), 0777);     // --> The sandbox's root maps to host uid 65534.

    // --> The program sums the numbers on stdin, writes the sum to /work and exits with it.
#if SBOX_E2E_README_PYTHON
    CFile::writeAtomic(job + "/main.py",
        "import sys\n"
        "total = sum(int(x) for x in sys.stdin.read().split())\n"
        "open('/work/result.txt', 'w').write(str(total))\n"
        "sys.exit(total)\n", 0644);
#else
    CFile::writeAtomic(job + "/main.py",
        "read a b\n"
        "echo $((a + b)) > /work/result.txt\n"
        "exit $((a + b))\n", 0644);
#endif

    REQUIRE(::mount("tmpfs", "/srv", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=64k") == 0);
    REQUIRE(::mkdir("/srv/job", 0755) == 0);
    REQUIRE(::mount(job.c_str(), "/srv/job", nullptr, MS_BIND, nullptr) == 0);

    CEventLoop loop;
    ToolResult r = loop.run(runTool(tmp.path, SBOX_E2E_README_EXAMPLE, std::vector<std::string>()));

    ::umount2("/srv/job", MNT_DETACH);
    ::umount2("/srv", MNT_DETACH);

    // --> The example returns SBoxResult::exitCode, which is 0 for a setup failure (for example
    // a program the policy's mounts cannot reach) and 2 when python cannot open main.py.
    CHECK_MESSAGE(r.code == 3, "the README example did not run main.py in /work (exit ", r.code,
                  "); see docs/e2e.md. stdout: ", r.out, " stderr: ", r.err);
    std::string result;
    CHECK(CFile::readAll(job + "/result.txt", result) == SBOX_OK);
    CHECK(trim(result) == "3");
}
