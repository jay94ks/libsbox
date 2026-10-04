#ifndef __INCLUDE_SBOX_NET_NETNS_HPP__
#define __INCLUDE_SBOX_NET_NETNS_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <functional>

namespace sbox {
namespace net {

    /**
     * Switches the calling thread into another network namespace and back.
     *
     * Only for short synchronous work: opening a socket (netlink, packet, listening TCP), opening
     * /dev/net/tun, writing /proc/sys/net. A socket keeps the namespace it was created in, so
     * the usual pattern is "enter, socket(), leave" and then use the socket asynchronously.
     *
     * Never keep a scope alive across a co_await: other coroutines of the same loop would run in
     * the wrong namespace. The destructor restores the original namespace and aborts the process
     * when that fails, because continuing in the wrong namespace would silently configure the
     * wrong network.
     */
    class SBOX_API CNetnsScope {
    private:
        CFd _saved;
        int32_t _error;

    public:
        /**
         * Enters the namespace at `path` (a /proc/<pid>/ns/net file or a bind-mounted one).
         * An empty path is a no-op scope.
         */
        explicit CNetnsScope(const std::string& path) noexcept;

        /**
         * Enters the namespace referred to by `nsFd` (-1 is a no-op scope).
         */
        explicit CNetnsScope(int nsFd) noexcept;

        CNetnsScope(const CNetnsScope&) = delete;

        CNetnsScope& operator=(const CNetnsScope&) = delete;

        /**
         * Returns to the original namespace (aborts when that is impossible).
         */
        ~CNetnsScope();

        /** Returns SBOX_OK when the switch succeeded (or was a no-op), else a negated errno. */
        inline int32_t error() const noexcept { return _error; }

    private:
        /** Saves the current namespace and enters `nsFd`. */
        void enter(int nsFd) noexcept;
    };

    /**
     * Network namespace helpers.
     *
     * A persistent namespace is an nsfs bind mount on a regular file, exactly what
     * `ip netns add` (/var/run/netns/<name>) and Docker (/var/run/docker/netns/<id>) create, so
     * the files are interchangeable with those tools.
     */
    class SBOX_API CNetns {
    public:
        /** iproute2's directory of named namespaces. */
        static constexpr const char* IPROUTE2_DIR = "/var/run/netns";

        /** Docker's directory of sandbox namespaces. */
        static constexpr const char* DOCKER_DIR = "/var/run/docker/netns";

        /**
         * Creates a new network namespace and pins it by bind-mounting it onto `path` (a new
         * file is created; an existing path is -EEXIST). The calling thread stays in its own
         * namespace.
         */
        static int32_t create(const std::string& path) noexcept;

        /**
         * Creates a named namespace in `dir` the way `ip netns add` does: the directory is made
         * a shared mount first so the pin propagates to other mount namespaces.
         * @param outPath Receives `dir/name`.
         */
        static int32_t createNamed(std::string_view name, std::string& outPath, const std::string& dir = IPROUTE2_DIR) noexcept;

        /**
         * Unpins a namespace created by create() (lazy unmount, then unlink). Missing is not an
         * error. Processes still inside keep the namespace alive.
         */
        static int32_t remove(const std::string& path) noexcept;

        /**
         * Opens a namespace file (O_RDONLY | O_CLOEXEC).
         */
        static int32_t open(const std::string& path, CFd& out) noexcept;

        /**
         * Opens the calling thread's namespace.
         */
        static int32_t openCurrent(CFd& out) noexcept;

        /**
         * Creates an unpinned namespace and returns a descriptor that keeps it alive.
         */
        static int32_t createAnonymous(CFd& out) noexcept;

        /**
         * Returns the namespace inode of `path` (to compare namespaces).
         */
        static int32_t inode(const std::string& path, uint64_t& out) noexcept;

        /**
         * Returns true when `path` is a network namespace file.
         */
        static bool isNetns(const std::string& path) noexcept;

        /**
         * Runs `fn` in a short-lived child process that joined the namespace at `path`.
         *
         * The child is forked (no exec) and calls setns() before `fn`; the parent waits for it on
         * its pidfd without blocking the loop. Use this for work that must live entirely inside
         * the namespace (blocking calls, a nested event loop). `fn` must not touch the parent's
         * event loop. Do not use this in a process that has other threads.
         * @return The value `fn` returned, or a negated errno when the child could not run or
         *         died (-ECHILD).
         */
        static TTask<int32_t> run(const std::string& path, std::function<int32_t()> fn);
    };

}
}

#endif
