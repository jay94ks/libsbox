#ifndef __SRC_VPN_IPSEC_QUEUE_HPP__
#define __SRC_VPN_IPSEC_QUEUE_HPP__

#include <sbox/core/eventloop.hpp>
#include <coroutine>
#include <deque>

namespace sbox {
namespace vpn {
namespace ipsec {

    /**
     * Single-consumer queue a coroutine can wait on (same thread, same loop).
     */
    template<typename T>
    class AsyncQueue {
    private:
        std::deque<T> _items;
        std::coroutine_handle<> _waiter;
        CEventLoop* _loop = nullptr;
        bool _closed = false;

    public:
        /** Appends an item and wakes the consumer. */
        void push(T item) {
            if (_closed) {
                return;
            }

            _items.push_back(std::move(item));
            wake();
        }

        /** Stops the queue; the consumer's wait returns false once it is empty. */
        void close() {
            _closed = true;
            wake();
        }

        /** Returns true once closed. */
        inline bool closed() const noexcept { return _closed; }

        /** Awaiter returned by wait(). */
        struct Awaiter {
            AsyncQueue* queue;

            inline bool await_ready() const noexcept { return !queue->_items.empty() || queue->_closed; }

            inline void await_suspend(std::coroutine_handle<> h) noexcept {
                queue->_waiter = h;
                queue->_loop = CEventLoop::current();
            }

            inline bool await_resume() const noexcept { return !queue->_items.empty(); }
        };

        /** Waits until an item is available (true) or the queue closed (false). */
        inline Awaiter wait() noexcept { return Awaiter{ this }; }

        /** Takes the oldest item (call after wait() returned true). */
        T pop() {
            T item = std::move(_items.front());
            _items.pop_front();
            return item;
        }

    private:
        /** Resumes the waiting consumer on its loop. */
        void wake() {
            if (_waiter && _loop) {
                std::coroutine_handle<> h = _waiter;
                _waiter = nullptr;
                _loop->post(h);
            }
        }
    };

}
}
}

#endif
