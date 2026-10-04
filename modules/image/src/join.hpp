#ifndef __SRC_IMAGE_JOIN_HPP__
#define __SRC_IMAGE_JOIN_HPP__

#include <sbox/core/eventloop.hpp>
#include <sbox/core/task.hpp>
#include <coroutine>
#include <functional>

namespace sbox {
namespace image {

    /**
     * State shared by the workers of RunConcurrently and the coroutine waiting for them.
     */
    struct JoinState {
        size_t remaining = 0;
        std::coroutine_handle<> waiter;
        int32_t firstError = SBOX_OK;
    };

    /**
     * Awaiter that resumes once every worker finished.
     */
    struct JoinAwaiter {
        std::shared_ptr<JoinState> state;

        inline bool await_ready() const noexcept { return state->remaining == 0; }

        inline void await_suspend(std::coroutine_handle<> h) noexcept { state->waiter = h; }

        inline void await_resume() const noexcept {}
    };

    /**
     * Runs one worker and signals the waiter when it was the last one.
     */
    inline TTask<void> RunJoined(TTask<int32_t> task, std::shared_ptr<JoinState> state) {
        int32_t r = co_await task;
        if (r != SBOX_OK && state->firstError == SBOX_OK) {
            state->firstError = r;
        }

        if (--state->remaining == 0 && state->waiter) {
            CEventLoop::current()->post(state->waiter);
        }
    }

    /**
     * Runs `count` jobs with at most `parallel` of them in flight on the current loop.
     * `job(i)` creates the coroutine of job i. Returns the first error (all jobs still run
     * to completion, unless `stopOnError` is set, in which case jobs not yet started are skipped).
     */
    inline TTask<int32_t> RunConcurrently(size_t count, size_t parallel, std::function<TTask<int32_t>(size_t)> job,
                                          bool stopOnError = true) {
        if (count == 0) {
            co_return SBOX_OK;
        }

        if (parallel == 0) {
            parallel = 1;
        }

        struct Queue {
            size_t next = 0;
        };

        auto queue = std::make_shared<Queue>();
        auto state = std::make_shared<JoinState>();
        size_t workers = parallel < count ? parallel : count;
        state->remaining = workers;
        for (size_t w = 0; w < workers; ++w) {
            auto worker = [](std::shared_ptr<Queue> q, std::shared_ptr<JoinState> st, size_t total, bool stop,
                             std::function<TTask<int32_t>(size_t)> fn) -> TTask<int32_t> {
                int32_t result = SBOX_OK;
                while (q->next < total) {
                    if (stop && st->firstError != SBOX_OK) {
                        break;
                    }

                    size_t i = q->next++;
                    int32_t r = co_await fn(i);
                    if (r != SBOX_OK) {
                        if (st->firstError == SBOX_OK) {
                            st->firstError = r;
                        }

                        result = r;
                    }
                }

                co_return result;
            }(queue, state, count, stopOnError, job);
            CEventLoop::current()->spawn(RunJoined(std::move(worker), state));
        }

        co_await JoinAwaiter{ state };
        co_return state->firstError;
    }

}
}

#endif
