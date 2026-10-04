#ifndef __INCLUDE_SBOX_CORE_EVENTLOOP_HPP__
#define __INCLUDE_SBOX_CORE_EVENTLOOP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <coroutine>
#include <functional>

namespace sbox {

    /**
     * Readiness bits used by CEventLoop::waitFd (the epoll values, spelled out so callers need
     * not include <sys/epoll.h>).
     */
    enum EFdEvents : uint32_t {
        EFDE_READ   = 0x001u,   // --> EPOLLIN: readable (or a pidfd whose process exited).
        EFDE_WRITE  = 0x004u,   // --> EPOLLOUT: writable.
        EFDE_ERROR  = 0x008u,   // --> EPOLLERR: reported in the result, never needs asking for.
        EFDE_HANGUP = 0x010u,   // --> EPOLLHUP: reported in the result, never needs asking for.
    };

    /**
     * Single-threaded event loop over epoll that drives TTask coroutines.
     *
     * One loop belongs to the thread that runs it; CEventLoop::current() returns it while
     * run() is active. Everything that waits -- descriptors (sockets, pipes, pidfds, netlink),
     * timers, other tasks -- does so on this loop, so a program built on libsbox needs no extra
     * threads. That is what makes CSandbox::fork safe: the fork rule ("no other thread exists at
     * fork time") holds as long as nobody calls runBlocking().
     *
     * Not thread-safe, except post() which may be called from any thread.
     */
    class SBOX_API CEventLoop {
    private:
        struct SImpl;
        SImpl* _impl;

    public:
        /**
         * Waiter state shared by the fd/timer awaiters. Exposed only so the awaiters can live in
         * this header; treat it as private.
         */
        struct SWait {
            std::coroutine_handle<> handle;
            int32_t result;         // --> revents (> 0) on readiness, -ETIMEDOUT or -ECANCELED.
            int32_t fd;
            uint32_t events;
            int64_t deadline;       // --> Monotonic ms, or -1 for none.
            uint64_t timerSeq;      // --> Key of the armed timer, 0 when none.
            SWait* nextReader;      // --> Intrusive links of the per-fd waiter lists.
        };

    public:
        CEventLoop();

        CEventLoop(const CEventLoop&) = delete;

        CEventLoop& operator=(const CEventLoop&) = delete;

        /**
         * Destroys the loop. Frames of spawned tasks that are still suspended are destroyed.
         */
        ~CEventLoop();

        /**
         * Returns the loop running on the calling thread, or nullptr.
         */
        static CEventLoop* current() noexcept;

        /**
         * Returns the monotonic clock in milliseconds, as used for deadlines.
         */
        static int64_t nowMs() noexcept;

        /**
         * Runs the loop until `task` completes and returns its result (rethrowing its exception).
         * Spawned tasks that are still pending stay suspended and continue on the next run().
         */
        template<typename T>
        T run(TTask<T> task) {
            struct SDone { bool done = false; };
            SDone state;

            // --> Starts `inner` and resumes when it finished, without taking its result: the
            // value (or exception) stays in the promise for the take() below.
            struct SStart {
                typename TTask<T>::handle_type inner;

                inline bool await_ready() const noexcept { return inner.done(); }

                inline std::coroutine_handle<> await_suspend(std::coroutine_handle<> h) noexcept {
                    inner.promise().continuation = h;
                    return inner;
                }

                inline void await_resume() const noexcept {}
            };

            auto wrapper = [](typename TTask<T>::handle_type inner, SDone& st) -> TTask<void> {
                co_await SStart{ inner };
                st.done = true;
            }(task.handle(), state);

            // --> runUntil only returns once the wrapper finished, so `task` is complete after it.
            post(wrapper.handle());
            runUntil(state.done);
            return task.handle().promise().take();
        }

        /**
         * Starts a task that runs on its own; the loop keeps it alive until it finishes.
         * An exception escaping the task terminates the process.
         */
        void spawn(TTask<void> task);

        /**
         * Queues a coroutine to be resumed on this loop. Safe to call from any thread.
         */
        void post(std::coroutine_handle<> h);

        /**
         * Runs `fn` on a new short-lived thread and resumes the caller on this loop when it
         * returns. For calls that can only block (getaddrinfo, a large fsync). Starts a thread:
         * do not use it in a process that is going to fork.
         */
        TTask<void> runBlocking(std::function<void()> fn);

        /**
         * Wakes every coroutine waiting on `fd` with -ECANCELED and stops watching it.
         * Call this before closing a descriptor others may be waiting on.
         */
        void cancelFd(int fd) noexcept;

    public:
        /**
         * Awaiter returned by waitFd().
         */
        struct SFdAwaiter {
            CEventLoop* loop;
            SWait wait;

            inline bool await_ready() const noexcept { return false; }

            bool await_suspend(std::coroutine_handle<> h) noexcept;

            inline int32_t await_resume() const noexcept { return wait.result; }
        };

        /**
         * Waits until `fd` is ready for `events` (EFDE_READ and/or EFDE_WRITE).
         * Several coroutines may wait on the same descriptor at once.
         * @param fd Any descriptor epoll accepts (socket, pipe, eventfd, pidfd, netlink, tun).
         * @param events Bitwise OR of EFDE_READ / EFDE_WRITE.
         * @param timeoutMs Maximum wait, or a negative value to wait without limit.
         * @return The ready EFDE_* bits (> 0), -ETIMEDOUT, or another negated errno when the
         *         descriptor cannot be watched (e.g. -EPERM for a regular file).
         */
        inline SFdAwaiter waitFd(int fd, uint32_t events, int64_t timeoutMs = -1) noexcept {
            SFdAwaiter aw{ this, SWait{} };
            aw.wait.fd = fd;
            aw.wait.events = events;
            aw.wait.deadline = timeoutMs < 0 ? -1 : nowMs() + timeoutMs;
            return aw;
        }

        /**
         * Awaiter returned by sleepFor().
         */
        struct SSleepAwaiter {
            CEventLoop* loop;
            SWait wait;

            inline bool await_ready() const noexcept { return false; }

            void await_suspend(std::coroutine_handle<> h) noexcept;

            inline void await_resume() const noexcept {}
        };

        /**
         * Suspends the caller for `delayMs` milliseconds (0 yields to other ready work).
         */
        inline SSleepAwaiter sleepFor(int64_t delayMs) noexcept {
            SSleepAwaiter aw{ this, SWait{} };
            aw.wait.fd = -1;
            aw.wait.deadline = nowMs() + (delayMs < 0 ? 0 : delayMs);
            return aw;
        }

        /**
         * Suspends the caller until the loop's next turn, letting other ready work run.
         */
        inline SSleepAwaiter yield() noexcept { return sleepFor(0); }

    private:
        /**
         * Runs loop iterations until `done` turns true.
         */
        void runUntil(const bool& done);

        /**
         * Starts watching a waiter's descriptor; false when epoll refused it (result is set).
         */
        bool addFdWait(SWait* wait) noexcept;

        /**
         * Arms the waiter's deadline timer.
         */
        void addTimer(SWait* wait) noexcept;

        /**
         * Wraps a spawned task so the loop can drop it once it finished.
         */
        static TTask<void> runSpawned(CEventLoop* loop, TTask<void> task, uint64_t id);
    };

} // namespace sbox

#endif
