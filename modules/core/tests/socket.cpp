#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <cerrno>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;

namespace {

    /* A private temporary directory, removed on destruction. */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/tmp/sbox-core-sock-XXXXXX";
            REQUIRE(::mkdtemp(tmpl) != nullptr);
            path = tmpl;
        }

        ~TempDir() {
            CFile::removeTree(path);
        }
    };

    /* Returns the names in a directory. */
    std::vector<std::string> entries(const std::string& dir) {
        std::vector<std::string> out;
        DIR* d = ::opendir(dir.c_str());
        while (d) {
            dirent* e = ::readdir(d);
            if (!e) {
                break;
            }

            std::string name = e->d_name;
            if (name != "." && name != "..") {
                out.push_back(name);
            }
        }

        if (d) {
            ::closedir(d);
        }

        return out;
    }

    /* Blocking connect to a UNIX path: 0 or -errno. */
    int32_t connectPath(const std::string& path) {
        int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return -errno;
        }

        sockaddr_un sa{};
        sa.sun_family = AF_UNIX;
        std::snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path.c_str());
        int32_t r = ::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 ? 0 : -errno;
        ::close(fd);
        return r;
    }

}

TEST_CASE("a UNIX listener's path appears only once it accepts connections") {
    TempDir dir;
    std::string path = dir.path + "/daemon.sock";
    const int rounds = 1000;

    // --> The child does what a plugin client does: wait for the socket file, then connect.
    // Each round the parent listens, learns the outcome, closes and removes the file.
    int toParent[2], toChild[2];
    REQUIRE(::pipe(toParent) == 0);
    REQUIRE(::pipe(toChild) == 0);
    pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        ::close(toParent[0]);
        ::close(toChild[1]);
        for (int i = 0; i < rounds; ++i) {
            struct stat st{};
            while (::stat(path.c_str(), &st) != 0) {
            }

            char result = connectPath(path) == 0 ? 'y' : 'n';
            char ack = 0;
            if (::write(toParent[1], &result, 1) != 1 || ::read(toChild[0], &ack, 1) != 1) {
                ::_exit(2);
            }
        }

        ::_exit(0);
    }

    ::close(toParent[1]);
    ::close(toChild[0]);
    int refused = 0;
    for (int i = 0; i < rounds; ++i) {
        SEndpoint ep;
        REQUIRE(SEndpoint::fromUnix(path, ep) == SBOX_OK);
        CListener listener;
        REQUIRE(listener.listen(ep) == SBOX_OK);

        char result = 0;
        REQUIRE(::read(toParent[0], &result, 1) == 1);
        refused += result == 'n';
        listener.close();
        ::unlink(path.c_str());
        REQUIRE(::write(toChild[1], "k", 1) == 1);
    }

    int status = 0;
    ::waitpid(pid, &status, 0);
    ::close(toParent[0]);
    ::close(toChild[1]);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(refused == 0);
    CHECK(entries(dir.path).empty());
}

TEST_CASE("a UNIX listener replaces a stale socket but not another file, and reports its path") {
    TempDir dir;
    std::string path = dir.path + "/svc.sock";
    SEndpoint ep;
    REQUIRE(SEndpoint::fromUnix(path, ep) == SBOX_OK);

    {
        CListener first;
        REQUIRE(first.listen(ep) == SBOX_OK);
    }

    // --> The stale socket file of a previous run is replaced; no temporary name is left.
    CListener listener;
    REQUIRE(listener.listen(ep) == SBOX_OK);
    CHECK(entries(dir.path) == std::vector<std::string>{ "svc.sock" });
    SEndpoint bound = listener.localEndpoint();
    REQUIRE(bound.family() == AF_UNIX);
    CHECK(std::string(reinterpret_cast<const sockaddr_un*>(&bound.storage)->sun_path) == path);
    CHECK(connectPath(path) == 0);

    CEventLoop loop;
    loop.run([](CListener& l, SEndpoint target) -> TTask<void> {
        CSocket client;
        REQUIRE(co_await client.connect(target, 2000) == SBOX_OK);
        CSocket accepted;
        CHECK(co_await l.accept(accepted, 2000) == SBOX_OK);
    }(listener, bound));

    // --> A regular file is never replaced.
    std::string file = dir.path + "/data";
    REQUIRE(CFile::writeAtomic(file, "keep") == SBOX_OK);
    SEndpoint fileEp;
    REQUIRE(SEndpoint::fromUnix(file, fileEp) == SBOX_OK);
    CListener other;
    CHECK(other.listen(fileEp) == -EADDRINUSE);
    std::string text;
    CHECK(CFile::readAll(file, text) == SBOX_OK);
    CHECK(text == "keep");

    // --> Moving the listener keeps the reported path.
    CListener moved(std::move(listener));
    SEndpoint again = moved.localEndpoint();
    CHECK(std::string(reinterpret_cast<const sockaddr_un*>(&again.storage)->sun_path) == path);
}
