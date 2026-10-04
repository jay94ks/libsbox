#ifndef __INCLUDE_SBOX_OCI_RUNTIME_HPP__
#define __INCLUDE_SBOX_OCI_RUNTIME_HPP__

#include <sbox/common.hpp>
#include <sbox/box/cgroup.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <sbox/oci/spec.hpp>
#include <sbox/oci/state.hpp>
#include <functional>

namespace sbox {
namespace oci {

    /**
     * Severity of a runtime log message.
     */
    enum ELogLevel : uint32_t {
        ELOG_DEBUG = 0,
        ELOG_INFO,
        ELOG_WARNING,
        ELOG_ERROR,
    };

    /**
     * Receives warnings and debug notes of the runtime (the CLI turns them into runc's log lines).
     */
    using FLogSink = std::function<void(ELogLevel level, const std::string& message)>;

    /**
     * Runtime-wide settings (runc's global flags).
     */
    struct SRuntimeOptions {
        std::string root;                       // --> State directory; empty = DefaultRoot(rootless).
        bool rootless = false;                  // --> Cgroup failures are warnings; default root under XDG_RUNTIME_DIR.
        bool systemdCgroup = false;             // --> cgroupsPath is "slice:prefix:name" (mapped to cgroupfs).
        FLogSink log;
        int64_t hookTimeoutMs = -1;             // --> Default for hooks without a timeout (negative: none).
    };

    /**
     * Options of create (and run).
     */
    struct SCreateOptions {
        std::string bundle = ".";               // --> Directory holding config.json.
        std::string pidFile;                    // --> Receives the init pid (written atomically).
        std::string consoleSocket;              // --> AF_UNIX socket that receives the pty master.
        uint32_t preserveFds = 0;               // --> Pass fds 3 .. 3+N-1 on to the container.
        bool noPivot = false;                   // --> MS_MOVE + chroot instead of pivot_root.
        bool noNewKeyring = false;              // --> Accepted; no session keyring is created anyway.
        std::vector<SFdMapping> stdio;          // --> Standard streams; empty = inherit 0, 1, 2.
    };

    /**
     * Options of exec.
     */
    struct SExecOptions {
        SProcessSpec process;
        std::string consoleSocket;
        std::string pidFile;
        bool detach = false;                    // --> Leave the process to the caller's subreaper.
        uint32_t preserveFds = 0;
        std::vector<SFdMapping> stdio;          // --> Empty = inherit 0, 1, 2.
        bool ignorePaused = false;
    };

    /**
     * A container process the caller keeps supervising (foreground run/exec).
     */
    class SBOX_API CContainerProcess {
    private:
        CProcess _process;
        CFd _pidfd;                 // --> Adopted process (reparented to us as a subreaper).
        pid_t _pid = 0;
        bool _adopted = false;
        CFd _pty;

    public:
        CContainerProcess() noexcept = default;

        CContainerProcess(CContainerProcess&&) noexcept = default;

        CContainerProcess& operator=(CContainerProcess&&) noexcept = default;

        /** Returns the process id (host pid namespace). */
        inline pid_t pid() const noexcept { return _pid; }

        /** Takes the pty master (terminal without a console socket). */
        inline CFd takePty() noexcept { return std::move(_pty); }

        /**
         * Sends a signal.
         */
        int32_t kill(int sig) const noexcept;

        /**
         * Waits for the process to exit and reaps it.
         * @return SBOX_OK, -ETIMEDOUT, or another negated errno.
         */
        TTask<int32_t> wait(SExitStatus& out, int64_t timeoutMs = -1);

    private:
        friend class CRuntime;
    };

    /**
     * runc-compatible OCI container runtime.
     *
     * Every container has a directory <root>/<id> holding state.json (written atomically,
     * updates serialized with flock on the directory) and, between create and start, the
     * exec.fifo start gate. The container init is launched by the box engine with a FIFO start
     * gate and left running when the runtime process exits: later invocations find it through
     * the recorded pid and its start time (from /proc/<pid>/stat), so a reused pid is never
     * mistaken for the container, and talk to it through pidfds.
     *
     * Methods set lastError() to a runc-style message when they fail ("container does not
     * exist", "cannot delete container x that is not stopped: running" ...).
     */
    class SBOX_API CRuntime {
    private:
        SRuntimeOptions _options;
        std::string _error;

    public:
        /**
         * Creates a runtime over a state root.
         */
        explicit CRuntime(SRuntimeOptions options);

        /**
         * Returns the default state root: /run/sbox, or $XDG_RUNTIME_DIR/sbox (/tmp/sbox-<uid>
         * without it) when rootless.
         */
        static std::string DefaultRoot(bool rootless);

        /** Returns the state root in use. */
        inline const std::string& root() const noexcept { return _options.root; }

        /** Returns the message of the last failure. */
        inline const std::string& lastError() const noexcept { return _error; }

        /**
         * Creates a container from a bundle: the init is set up completely and waits at the start
         * gate; prestart, createRuntime and createContainer hooks have run.
         * @param keep When not null, receives the init for supervision (foreground run);
         *        otherwise the init is left running on its own.
         * @return SBOX_OK; -EEXIST for a used id; -EINVAL for a bad id or configuration; or the
         *         errno of the failed setup step.
         */
        TTask<int32_t> create(const std::string& id, const SCreateOptions& options, CContainerProcess* keep = nullptr);

        /**
         * Starts a created container: startContainer hooks, release of the start gate,
         * poststart hooks.
         */
        TTask<int32_t> start(const std::string& id);

        /**
         * Returns the OCI state of a container.
         * @return SBOX_OK or -ENOENT.
         */
        TTask<int32_t> state(const std::string& id, SState& out);

        /**
         * Sends a signal to the init (or with `all` to every process of the container).
         * @return SBOX_OK, -ENOENT, or -ESRCH when the container is not running.
         */
        TTask<int32_t> kill(const std::string& id, int sig, bool all = false);

        /**
         * Deletes a container: a created one is killed; a running one only with `force`.
         * Remaining processes are killed, the cgroup is removed, poststop hooks run and the state
         * directory is removed.
         */
        TTask<int32_t> remove(const std::string& id, bool force = false);

        /**
         * Runs an additional process in a running (or created) container: all its namespaces
         * are joined through /proc/<init>/ns/<type>, its cgroup and seccomp profile apply.
         * @param keep When not null, receives the process for supervision; otherwise it is left
         *        running (with `detach` it is reparented to the caller's subreaper).
         */
        TTask<int32_t> exec(const std::string& id, const SExecOptions& options, CContainerProcess* keep = nullptr);

        /**
         * Lists the pids of the container (from its cgroup; without one, the processes in the
         * init's pid namespace).
         */
        TTask<int32_t> processes(const std::string& id, std::vector<pid_t>& out);

        /**
         * Freezes a running container.
         */
        TTask<int32_t> pause(const std::string& id);

        /**
         * Thaws a paused container.
         */
        TTask<int32_t> resume(const std::string& id);

        /**
         * Updates the resource limits of a container; fields not set in `resources` keep their
         * value. The stored configuration is updated too.
         */
        TTask<int32_t> update(const std::string& id, const SResourcesSpec& resources);

        /**
         * Reads the cgroup statistics of a container.
         */
        TTask<int32_t> stats(const std::string& id, SCgroupStats& out);

        /**
         * Returns the configuration a container was created from.
         */
        TTask<int32_t> config(const std::string& id, SSpec& out);

        /**
         * Lists every container under the root.
         */
        TTask<int32_t> list(std::vector<SState>& out);

    private:
        /**
         * Logs through the sink.
         */
        void log(ELogLevel level, const std::string& message) const;

        /**
         * Records an error message and returns `rc`.
         */
        int32_t fail(int32_t rc, std::string message);

        /**
         * Returns the directory of a container.
         */
        std::string containerDir(const std::string& id) const;
    };

    /**
     * Parses a signal given as a number or a name with or without the SIG prefix ("9", "KILL",
     * "SIGKILL", "sigterm").
     * @return The signal number, or -EINVAL.
     */
    SBOX_API int32_t ParseSignal(std::string_view text) noexcept;

}
}

#endif
