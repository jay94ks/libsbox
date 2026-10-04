#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/socket.hpp>
#include <cerrno>
#include <csignal>
#include <stdexcept>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace sbox;

namespace {

    TTask<int32_t> addLater(int32_t a, int32_t b) {
        co_await CEventLoop::current()->sleepFor(5);
        co_return a + b;
    }

    TTask<int32_t> throwing() {
        co_await CEventLoop::current()->yield();
        throw std::runtime_error("boom");
    }

}

TEST_CASE("run returns the task result after timers fire") {
    CEventLoop loop;
    int64_t start = CEventLoop::nowMs();

    CHECK(loop.run(addLater(2, 3)) == 5);
    CHECK(CEventLoop::nowMs() - start >= 5);
    CHECK(CEventLoop::current() == nullptr);
}

TEST_CASE("run rethrows the task exception") {
    CEventLoop loop;
    CHECK_THROWS_AS(loop.run(throwing()), std::runtime_error);
}

TEST_CASE("pipe transfers data and reports EOF") {
    CEventLoop loop;

    auto body = []() -> TTask<std::string> {
        CStream r, w;
        REQUIRE(CPipe::create(r, w) == SBOX_OK);

        CEventLoop::current()->spawn([](CStream writer) -> TTask<void> {
            std::string big(200000, 'x');
            SIoResult s = co_await writer.send(BytesOf(big));
            CHECK(s.ok());
            writer.close();
        }(std::move(w)));

        std::vector<uint8_t> all;
        SIoResult got = co_await r.recvAll(all);
        CHECK(got.ok());
        co_return std::string(all.begin(), all.end());
    };

    CHECK(loop.run(body()).size() == 200000);
}

TEST_CASE("recv times out and close cancels a waiter") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CStream r, w;
        REQUIRE(CPipe::create(r, w) == SBOX_OK);

        uint8_t buf[4];
        SIoResult t = co_await r.recv(SByteSpan(buf, 4), 10);
        CHECK(t.error == -ETIMEDOUT);

        CEventLoop::current()->spawn([](CStream* reader) -> TTask<void> {
            co_await CEventLoop::current()->sleepFor(5);
            reader->close();
        }(&r));

        SIoResult c = co_await r.recv(SByteSpan(buf, 4));
        CHECK(c.error == -ECANCELED);
    };

    loop.run(body());
}

TEST_CASE("tcp listener and socket exchange bytes on port 0") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        SEndpoint any;
        REQUIRE(SEndpoint::parse("127.0.0.1:0", any) == SBOX_OK);

        CListener listener;
        REQUIRE(listener.listen(any) == SBOX_OK);
        SEndpoint bound = listener.localEndpoint();
        CHECK(bound.port() != 0);

        CEventLoop::current()->spawn([](CListener* l) -> TTask<void> {
            CSocket peer;
            REQUIRE(co_await l->accept(peer) == SBOX_OK);

            uint8_t buf[5];
            SIoResult r = co_await peer.recvExact(SByteSpan(buf, 5));
            CHECK(r.ok());
            co_await peer.send(SReadOnlyByteSpan(buf, 5));
        }(&listener));

        CSocket client;
        REQUIRE(co_await client.connect(bound, 1000) == SBOX_OK);
        co_await client.send(BytesOf("hello"));

        uint8_t echo[5];
        SIoResult r = co_await client.recvExact(SByteSpan(echo, 5));
        CHECK(r.ok());
        CHECK(TextOf(SReadOnlyByteSpan(echo, 5)) == "hello");
    };

    loop.run(body());
}

TEST_CASE("unix socket passes descriptors") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        CSocket a, b;
        REQUIRE(CSocket::pair(a, b) == SBOX_OK);

        CStream r, w;
        REQUIRE(CPipe::create(r, w) == SBOX_OK);
        REQUIRE(a.sendFds(BytesOf("x"), { w.nativeHandle() }) == SBOX_OK);

        uint8_t byte = 0;
        std::vector<CFd> fds;
        SIoResult got = co_await b.recvFds(SByteSpan(&byte, 1), fds, 1000);
        CHECK(got.ok());
        REQUIRE(fds.size() == 1);

        CStream passed(std::move(fds[0]));
        co_await passed.send(BytesOf("ok"));

        uint8_t buf[2];
        SIoResult r2 = co_await r.recvExact(SByteSpan(buf, 2), 1000);
        CHECK(r2.ok());
    };

    loop.run(body());
}

TEST_CASE("pidfd readiness signals process exit") {
    CEventLoop loop;

    auto body = []() -> TTask<void> {
        pid_t pid = ::fork();
        if (pid == 0) {
            ::usleep(20000);
            ::_exit(7);
        }

        CFd pidfd(int(::syscall(SYS_pidfd_open, pid, 0)));
        REQUIRE(pidfd.isValid());

        int32_t ev = co_await CEventLoop::current()->waitFd(pidfd.get(), EFDE_READ, 5000);
        CHECK(ev > 0);

        siginfo_t info{};
        CHECK(::waitid(P_PIDFD, idtype_t(pidfd.get()), &info, WEXITED) == 0);
        CHECK(info.si_status == 7);
    };

    loop.run(body());
}

TEST_CASE("endpoint parsing and formatting") {
    SEndpoint ep;
    CHECK(SEndpoint::parse("[::1]:8080", ep) == SBOX_OK);
    CHECK(ep.toString() == "[::1]:8080");
    CHECK(SEndpoint::parse("unix:/run/x.sock", ep) == SBOX_OK);
    CHECK(ep.toString() == "unix:/run/x.sock");
    CHECK(SEndpoint::parse("@abstract", ep) == SBOX_OK);
    CHECK(ep.toString() == "@abstract");
    CHECK(SEndpoint::parse("1.2.3.4:99999", ep) == -EINVAL);
    CHECK(SEndpoint::parse("nohost", ep) == -EINVAL);
}
