// CStream::send to a pipe whose reader is gone: -EPIPE, no SIGPIPE (regression: the README
// sandbox example died of SIGPIPE when the sandboxed program exited before reading stdin).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/stream.hpp>
#include <cerrno>
#include <csignal>
#include <pthread.h>

using namespace sbox;

namespace {

    bool sigpipePending() {
        sigset_t pending;
        sigemptyset(&pending);
        ::sigpending(&pending);
        return sigismember(&pending, SIGPIPE) == 1;
    }

}

TEST_CASE("writing to a pipe without a reader is -EPIPE and leaves SIGPIPE alone") {
    // --> Default disposition: a stray SIGPIPE would kill this test.
    ::signal(SIGPIPE, SIG_DFL);

    CEventLoop loop;
    loop.run([]() -> TTask<void> {
        CStream readEnd, writeEnd;
        REQUIRE(CPipe::create(readEnd, writeEnd) == SBOX_OK);
        readEnd.close();

        std::string data = "data for nobody";
        SIoResult r = co_await writeEnd.send(BytesOf(data));
        CHECK(r.error == -EPIPE);
        CHECK(r.bytes == 0);
        CHECK_FALSE(sigpipePending());

        // --> The signal mask is restored: SIGPIPE is not left blocked.
        sigset_t mask;
        ::pthread_sigmask(SIG_SETMASK, nullptr, &mask);
        CHECK(sigismember(&mask, SIGPIPE) == 0);
    }());

    // --> A SIGPIPE that was already pending (blocked by the caller) stays pending.
    sigset_t pipeSet, saved;
    sigemptyset(&pipeSet);
    sigaddset(&pipeSet, SIGPIPE);
    ::pthread_sigmask(SIG_BLOCK, &pipeSet, &saved);
    ::raise(SIGPIPE);
    REQUIRE(sigpipePending());

    loop.run([]() -> TTask<void> {
        CStream readEnd, writeEnd;
        REQUIRE(CPipe::create(readEnd, writeEnd) == SBOX_OK);
        readEnd.close();
        std::string data = "x";
        SIoResult r = co_await writeEnd.send(BytesOf(data));
        CHECK(r.error == -EPIPE);
    }());

    CHECK(sigpipePending());
    struct timespec zero{ 0, 0 };
    CHECK(::sigtimedwait(&pipeSet, nullptr, &zero) == SIGPIPE);
    ::pthread_sigmask(SIG_SETMASK, &saved, nullptr);
}
