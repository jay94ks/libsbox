#ifndef __INCLUDE_SBOX_BOX_SANDBOX_HPP__
#define __INCLUDE_SBOX_BOX_SANDBOX_HPP__

#include <sbox/common.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/task.hpp>
#include <sbox/box/policy.hpp>
#include <functional>

namespace sbox {

    /**
     * A program running under an SBoxPolicy.
     *
     * The process is watched on the caller's CEventLoop through its pidfd (no SIGCHLD, no
     * blocking wait): a supervisor task enforces the wall-clock limit and, when the program
     * ends, kills whatever is left in its cgroup, collects the statistics and removes the
     * cgroup. Destroying a running sandbox kills it.
     *
     * Read stdout/stderr concurrently with wait() (e.g. from a spawned task) when the program
     * may write more than a pipe buffer.
     */
    class SBOX_API CSandbox {
    public:
        struct SState;

    private:
        std::shared_ptr<SState> _state;

    public:
        CSandbox() noexcept = default;

        CSandbox(CSandbox&&) noexcept = default;

        CSandbox& operator=(CSandbox&& other) noexcept;

        CSandbox(const CSandbox&) = delete;

        CSandbox& operator=(const CSandbox&) = delete;

        /**
         * Kills the program if it is still running.
         */
        ~CSandbox();

        /**
         * Starts `args` (args[0] is searched in the policy's PATH) inside the sandbox.
         * Setup failures do not throw: the sandbox is then not valid() and wait() reports
         * EBEXIT_SETUP_FAILURE with the error and the failed step.
         */
        static TTask<CSandbox> spawn(SBoxPolicy policy, std::vector<std::string> args);

        /**
         * Runs `fn` of the current program inside the sandbox (no exec); its return value is the
         * exit code. The fork rule applies: the calling process must have no other thread
         * (checked: -EBUSY otherwise), since locks held by other threads would stay locked in
         * the child. The function runs under the same isolation, seccomp filter included.
         */
        static TTask<CSandbox> fork(SBoxPolicy policy, std::function<int32_t()> fn);

        /** Returns true when the program was started. */
        bool isValid() const noexcept;

        /** Returns the setup error (SBOX_OK when started). */
        int32_t error() const noexcept;

        /** Returns the failed setup step, if any. */
        const std::string& failedStep() const noexcept;

        /** Returns the pid of the sandbox init in the caller's pid namespace. */
        pid_t pid() const noexcept;

        /** Returns the stdin pipe (an invalid stream unless the policy chose EBSTD_PIPE). */
        CStream& stdinPipe() noexcept;

        /** Returns the stdout pipe. */
        CStream& stdoutPipe() noexcept;

        /** Returns the stderr pipe. */
        CStream& stderrPipe() noexcept;

        /**
         * Waits until the program ended and everything was cleaned up.
         */
        TTask<SBoxResult> wait();

        /**
         * Kills every process of the sandbox now (the result reason is EBEXIT_SIGNAL).
         */
        int32_t kill() noexcept;

    private:
        /**
         * Shared implementation of spawn() and fork().
         */
        static TTask<void> start(std::shared_ptr<SState> state, SBoxPolicy policy, std::vector<std::string> args, std::function<int32_t()> fn);

        /**
         * Supervises a started program until it ended.
         */
        static TTask<void> supervise(std::shared_ptr<SState> state);
    };

} // namespace sbox

#endif
