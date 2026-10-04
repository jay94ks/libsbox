#ifndef __INCLUDE_SBOX_CORE_TASK_HPP__
#define __INCLUDE_SBOX_CORE_TASK_HPP__

#include <sbox/common.hpp>
#include <coroutine>
#include <exception>
#include <optional>
#include <utility>

namespace sbox {

    template<typename T = void>
    class TTask;

    namespace detail {

        /**
         * Final awaiter of a TTask frame: hands control back to whoever awaited the task
         * (symmetric transfer), or to nobody when the task was never awaited.
         */
        struct SFinalAwaiter {
            inline bool await_ready() const noexcept { return false; }

            template<typename P>
            std::coroutine_handle<> await_suspend(std::coroutine_handle<P> h) const noexcept {
                std::coroutine_handle<> next = h.promise().continuation;
                return next ? next : std::noop_coroutine();
            }

            inline void await_resume() const noexcept {}
        };

        /**
         * State shared by every TTask promise: the awaiting coroutine and a captured exception.
         */
        struct SPromiseBase {
            std::coroutine_handle<> continuation;
            std::exception_ptr exception;

            inline std::suspend_always initial_suspend() const noexcept { return {}; }

            inline SFinalAwaiter final_suspend() const noexcept { return {}; }

            inline void unhandled_exception() noexcept { exception = std::current_exception(); }

            /**
             * Rethrows the exception the coroutine body exited with, if any.
             */
            inline void rethrow() const {
                if (exception) {
                    std::rethrow_exception(exception);
                }
            }
        };

        /**
         * Promise of a TTask that produces a value.
         */
        template<typename T>
        struct SPromise : SPromiseBase {
            std::optional<T> value;

            TTask<T> get_return_object() noexcept;

            template<typename U>
            void return_value(U&& result) {
                value.emplace(std::forward<U>(result));
            }

            /**
             * Moves the produced value out (rethrowing a captured exception first).
             */
            T take() {
                rethrow();
                return std::move(*value);
            }
        };

        /**
         * Promise of a TTask that produces nothing.
         */
        template<>
        struct SPromise<void> : SPromiseBase {
            TTask<void> get_return_object() noexcept;

            inline void return_void() const noexcept {}

            /**
             * Rethrows a captured exception, if any.
             */
            inline void take() const {
                rethrow();
            }
        };

    }

    /**
     * Lazily started coroutine producing a `T`.
     *
     * The body does not run until the task is awaited (or handed to CEventLoop::run/spawn), and
     * awaiting resumes the body inline on the awaiting thread; completion transfers straight
     * back to the awaiter. A task owns its frame: destroying an unfinished task destroys the
     * frame, so keep the task alive for as long as it may still run.
     */
    template<typename T>
    class [[nodiscard]] TTask {
    public:
        using promise_type = detail::SPromise<T>;
        using handle_type = std::coroutine_handle<promise_type>;

    private:
        handle_type _handle;

    public:
        TTask() noexcept : _handle(nullptr) {}

        explicit TTask(handle_type h) noexcept : _handle(h) {}

        TTask(TTask&& other) noexcept : _handle(std::exchange(other._handle, nullptr)) {}

        TTask(const TTask&) = delete;

        TTask& operator=(const TTask&) = delete;

        /**
         * Takes over another task's frame, destroying the frame this task owned.
         */
        TTask& operator=(TTask&& other) noexcept {
            if (this != &other) {
                if (_handle) {
                    _handle.destroy();
                }

                _handle = std::exchange(other._handle, nullptr);
            }

            return *this;
        }

        ~TTask() {
            if (_handle) {
                _handle.destroy();
            }
        }

        /** Returns true when the task owns a coroutine frame. */
        inline bool isValid() const noexcept { return bool(_handle); }

        /** Returns true when the task has no frame or the frame has finished. */
        inline bool isDone() const noexcept { return !_handle || _handle.done(); }

        /** Returns the coroutine handle without giving up ownership. */
        inline handle_type handle() const noexcept { return _handle; }

        /** Gives up ownership of the frame; the caller destroys it. */
        inline handle_type release() noexcept { return std::exchange(_handle, nullptr); }

        /**
         * Awaiter that starts the task and resumes the awaiter when it completes.
         */
        struct SAwaiter {
            handle_type handle;

            inline bool await_ready() const noexcept { return !handle || handle.done(); }

            inline std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
                handle.promise().continuation = awaiting;
                return handle;
            }

            T await_resume() {
                return handle.promise().take();
            }
        };

        /**
         * Awaits the task from another coroutine.
         */
        SAwaiter operator co_await() const& noexcept { return SAwaiter{ _handle }; }

        /**
         * Awaits a temporary task. The temporary lives until the end of the full expression,
         * which spans the whole suspension, so this is safe.
         */
        SAwaiter operator co_await() const&& noexcept { return SAwaiter{ _handle }; }
    };

    namespace detail {

        template<typename T>
        inline TTask<T> SPromise<T>::get_return_object() noexcept {
            return TTask<T>(std::coroutine_handle<SPromise<T>>::from_promise(*this));
        }

        inline TTask<void> SPromise<void>::get_return_object() noexcept {
            return TTask<void>(std::coroutine_handle<SPromise<void>>::from_promise(*this));
        }

    }

    /**
     * Eagerly started coroutine that owns itself: its frame is destroyed when the body returns.
     * Used for fire-and-forget work such as CEventLoop::spawn. An escaping exception terminates.
     */
    class CDetachedTask {
    public:
        struct promise_type {
            inline CDetachedTask get_return_object() const noexcept { return {}; }

            inline std::suspend_never initial_suspend() const noexcept { return {}; }

            inline std::suspend_never final_suspend() const noexcept { return {}; }

            inline void return_void() const noexcept {}

            inline void unhandled_exception() const noexcept { std::terminate(); }
        };
    };

} // namespace sbox

#endif
