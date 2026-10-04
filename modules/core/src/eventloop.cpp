#include <sbox/core/eventloop.hpp>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace sbox {

    namespace {

        thread_local CEventLoop* tlsCurrent = nullptr;

        /**
         * Waiters registered on one descriptor and the epoll interest currently armed for it.
         */
        struct SFdEntry {
            CEventLoop::SWait* waiters = nullptr;
            uint32_t armed = 0;
        };

    }

    /**
     * Private state of a CEventLoop.
     */
    struct CEventLoop::SImpl {
        int epollFd = -1;
        int wakeFd = -1;

        std::deque<std::coroutine_handle<>> ready;
        std::map<std::pair<int64_t, uint64_t>, SWait*> timers;
        std::unordered_map<int, SFdEntry> fds;
        uint64_t timerSeq = 0;

        std::mutex remoteLock;
        std::deque<std::coroutine_handle<>> remote;

        std::map<uint64_t, TTask<void>> spawned;
        std::vector<uint64_t> finished;
        uint64_t spawnSeq = 0;
    };

    /* Creates the epoll instance and the cross-thread wakeup eventfd. */
    CEventLoop::CEventLoop() : _impl(new SImpl()) {
        _impl->epollFd = ::epoll_create1(EPOLL_CLOEXEC);
        _impl->wakeFd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = _impl->wakeFd;
        ::epoll_ctl(_impl->epollFd, EPOLL_CTL_ADD, _impl->wakeFd, &ev);
    }

    /* Destroys pending spawned tasks and the kernel objects. */
    CEventLoop::~CEventLoop() {
        CEventLoop* prev = tlsCurrent;
        tlsCurrent = this;
        _impl->spawned.clear();
        tlsCurrent = prev;

        ::close(_impl->wakeFd);
        ::close(_impl->epollFd);
        delete _impl;
    }

    /* Returns the loop of the calling thread. */
    CEventLoop* CEventLoop::current() noexcept {
        return tlsCurrent;
    }

    /* Returns CLOCK_MONOTONIC in milliseconds. */
    int64_t CEventLoop::nowMs() noexcept {
        timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
    }

    /* Wraps a spawned task. */
    TTask<void> CEventLoop::runSpawned(CEventLoop* loop, TTask<void> task, uint64_t id) {
        co_await task;
        loop->_impl->finished.push_back(id);
    }

    /* Starts a self-running task. */
    void CEventLoop::spawn(TTask<void> task) {
        uint64_t id = ++_impl->spawnSeq;
        TTask<void> wrapper = runSpawned(this, std::move(task), id);
        std::coroutine_handle<> h = wrapper.handle();

        _impl->spawned.emplace(id, std::move(wrapper));
        _impl->ready.push_back(h);
    }

    /* Queues a coroutine for resumption, from any thread. */
    void CEventLoop::post(std::coroutine_handle<> h) {
        if (tlsCurrent == this) {
            _impl->ready.push_back(h);
            return;
        }

        {
            std::lock_guard<std::mutex> guard(_impl->remoteLock);
            _impl->remote.push_back(h);
        }

        uint64_t one = 1;
        ssize_t n = ::write(_impl->wakeFd, &one, sizeof(one));
        (void) n;
    }

    /* Offloads a blocking call to a temporary thread. */
    TTask<void> CEventLoop::runBlocking(std::function<void()> fn) {
        struct SAwaiter {
            CEventLoop* loop;
            std::function<void()>* fn;

            inline bool await_ready() const noexcept { return false; }

            void await_suspend(std::coroutine_handle<> h) {
                CEventLoop* target = loop;
                std::function<void()>* work = fn;

                std::thread([target, work, h]() {
                    (*work)();
                    target->post(h);
                }).detach();
            }

            inline void await_resume() const noexcept {}
        };

        co_await SAwaiter{ this, &fn };
    }

    /* Arms the waiter's deadline. */
    void CEventLoop::addTimer(SWait* wait) noexcept {
        wait->timerSeq = ++_impl->timerSeq;
        _impl->timers.emplace(std::make_pair(wait->deadline, wait->timerSeq), wait);
    }

    /* Registers a waiter on its descriptor and updates the epoll interest. */
    bool CEventLoop::addFdWait(SWait* wait) noexcept {
        SFdEntry& entry = _impl->fds[wait->fd];
        uint32_t want = entry.armed | (wait->events & (EPOLLIN | EPOLLOUT));

        if (want != entry.armed || entry.armed == 0) {
            epoll_event ev{};
            ev.events = want;
            ev.data.fd = wait->fd;

            int op = entry.armed == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
            if (::epoll_ctl(_impl->epollFd, op, wait->fd, &ev) < 0) {
                // --> A descriptor closed and reopened under the same number while we still had
                // it registered shows up as EEXIST on ADD; MOD fixes that up.
                // --> The reverse (closed and reopened after epoll dropped it) is ENOENT on MOD.
                if (errno == EEXIST && op == EPOLL_CTL_ADD
                    && ::epoll_ctl(_impl->epollFd, EPOLL_CTL_MOD, wait->fd, &ev) == 0) {
                }
                else if (errno == ENOENT && op == EPOLL_CTL_MOD
                    && ::epoll_ctl(_impl->epollFd, EPOLL_CTL_ADD, wait->fd, &ev) == 0) {
                }
                else {
                    wait->result = -errno;
                    if (entry.waiters == nullptr) {
                        _impl->fds.erase(wait->fd);
                    }

                    return false;
                }
            }

            entry.armed = want;
        }

        wait->nextReader = entry.waiters;
        entry.waiters = wait;
        return true;
    }

    /* Suspends on a descriptor. */
    bool CEventLoop::SFdAwaiter::await_suspend(std::coroutine_handle<> h) noexcept {
        wait.handle = h;
        wait.result = 0;
        wait.timerSeq = 0;

        if (!loop->addFdWait(&wait)) {
            return false;
        }

        if (wait.deadline >= 0) {
            loop->addTimer(&wait);
        }

        return true;
    }

    /* Suspends until the deadline. */
    void CEventLoop::SSleepAwaiter::await_suspend(std::coroutine_handle<> h) noexcept {
        wait.handle = h;
        wait.result = 0;
        loop->addTimer(&wait);
    }

    /* Cancels every waiter of a descriptor. */
    void CEventLoop::cancelFd(int fd) noexcept {
        auto it = _impl->fds.find(fd);
        if (it == _impl->fds.end()) {
            return;
        }

        for (SWait* w = it->second.waiters; w; w = w->nextReader) {
            if (w->timerSeq) {
                _impl->timers.erase(std::make_pair(w->deadline, w->timerSeq));
                w->timerSeq = 0;
            }

            w->result = -ECANCELED;
            _impl->ready.push_back(w->handle);
        }

        ::epoll_ctl(_impl->epollFd, EPOLL_CTL_DEL, fd, nullptr);
        _impl->fds.erase(it);
    }

    namespace {

        /**
         * Unlinks `wait` from its descriptor's waiter list.
         */
        void unlinkWaiter(SFdEntry& entry, CEventLoop::SWait* wait) noexcept {
            CEventLoop::SWait** link = &entry.waiters;
            while (*link) {
                if (*link == wait) {
                    *link = wait->nextReader;
                    return;
                }

                link = &(*link)->nextReader;
            }
        }

    }

    /* Runs the loop until `done` turns true. */
    void CEventLoop::runUntil(const bool& done) {
        CEventLoop* prev = tlsCurrent;
        tlsCurrent = this;

        epoll_event events[64];
        std::vector<int> touched;

        while (!done) {
            // --> Resume everything that is ready. Resumed coroutines may queue more; those run
            // in the same pass so a chain of immediately-ready steps does not pay an epoll_wait.
            while (!_impl->ready.empty() && !done) {
                std::coroutine_handle<> h = _impl->ready.front();
                _impl->ready.pop_front();
                h.resume();
            }

            for (uint64_t id : _impl->finished) {
                _impl->spawned.erase(id);
            }

            _impl->finished.clear();

            if (done) {
                break;
            }

            int timeout = -1;
            if (!_impl->ready.empty()) {
                timeout = 0;
            }
            else if (!_impl->timers.empty()) {
                int64_t delta = _impl->timers.begin()->first.first - nowMs();
                timeout = delta < 0 ? 0 : (delta > 0x7fffffff ? 0x7fffffff : int(delta));
            }

            int n = ::epoll_wait(_impl->epollFd, events, 64, timeout);
            if (n < 0 && errno != EINTR) {
                break;
            }

            touched.clear();
            for (int i = 0; i < n; ++i) {
                int fd = events[i].data.fd;
                uint32_t revents = events[i].events;

                if (fd == _impl->wakeFd) {
                    uint64_t count = 0;
                    ssize_t r = ::read(_impl->wakeFd, &count, sizeof(count));
                    (void) r;

                    std::lock_guard<std::mutex> guard(_impl->remoteLock);
                    while (!_impl->remote.empty()) {
                        _impl->ready.push_back(_impl->remote.front());
                        _impl->remote.pop_front();
                    }

                    continue;
                }

                auto it = _impl->fds.find(fd);
                if (it == _impl->fds.end()) {
                    continue;
                }

                // --> Wake every waiter whose interest matches; errors and hangups wake everyone,
                // since the next read or write is what reports them.
                SWait** link = &it->second.waiters;
                while (*link) {
                    SWait* w = *link;
                    uint32_t hit = revents & (w->events | EPOLLERR | EPOLLHUP);

                    if (hit) {
                        *link = w->nextReader;
                        w->result = int32_t(hit);

                        if (w->timerSeq) {
                            _impl->timers.erase(std::make_pair(w->deadline, w->timerSeq));
                            w->timerSeq = 0;
                        }

                        _impl->ready.push_back(w->handle);
                    }
                    else {
                        link = &w->nextReader;
                    }
                }

                touched.push_back(fd);
            }

            // --> Expired timers: sleeps resume normally, fd waits resume with -ETIMEDOUT.
            int64_t now = nowMs();
            while (!_impl->timers.empty() && _impl->timers.begin()->first.first <= now) {
                SWait* w = _impl->timers.begin()->second;
                _impl->timers.erase(_impl->timers.begin());
                w->timerSeq = 0;

                if (w->fd >= 0) {
                    auto it = _impl->fds.find(w->fd);
                    if (it != _impl->fds.end()) {
                        unlinkWaiter(it->second, w);
                        touched.push_back(w->fd);
                    }

                    w->result = -ETIMEDOUT;
                }

                _impl->ready.push_back(w->handle);
            }

            // --> Narrow (or drop) the epoll interest of descriptors whose waiters left, so a
            // level-triggered fd nobody waits on does not spin the loop.
            for (int fd : touched) {
                auto it = _impl->fds.find(fd);
                if (it == _impl->fds.end()) {
                    continue;
                }

                uint32_t want = 0;
                for (SWait* w = it->second.waiters; w; w = w->nextReader) {
                    want |= w->events & (EPOLLIN | EPOLLOUT);
                }

                if (want == 0) {
                    ::epoll_ctl(_impl->epollFd, EPOLL_CTL_DEL, fd, nullptr);
                    _impl->fds.erase(it);
                }
                else if (want != it->second.armed) {
                    epoll_event ev{};
                    ev.events = want;
                    ev.data.fd = fd;
                    ::epoll_ctl(_impl->epollFd, EPOLL_CTL_MOD, fd, &ev);
                    it->second.armed = want;
                }
            }
        }

        tlsCurrent = prev;
    }

} // namespace sbox
