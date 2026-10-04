#ifndef __INCLUDE_SBOX_OCI_HOOKS_HPP__
#define __INCLUDE_SBOX_OCI_HOOKS_HPP__

#include <sbox/common.hpp>
#include <sbox/core/task.hpp>
#include <sbox/oci/spec.hpp>

namespace sbox {
namespace oci {

    /**
     * Where a hook runs.
     */
    struct SHookContext {
        std::string stateJson;                  // --> Written to the hook's standard input.
        pid_t containerPid = 0;                 // --> When > 0: run in this process's namespaces.
        std::vector<std::string> namespaces;    // --> Namespace types to join ("mount", "user" ...); pid is never joined.
        int64_t defaultTimeoutMs = -1;          // --> Used when the hook has no timeout (negative: none).
    };

    /**
     * Runs one hook as a child process: `path` is executed with `args` (args[0] is argv[0]) and
     * exactly `env`, the state JSON on standard input, standard output and error captured, with
     * the runtime's own capabilities. With a container pid the hook joins that container's
     * namespaces first (createContainer and startContainer hooks); the executable is opened in
     * the runtime's mount namespace before, as the OCI specification requires.
     * @param error Receives "<path>: exit status 1, stdout: ..., stderr: ..." on failure.
     * @return SBOX_OK, -ETIMEDOUT, -ECHILD (non-zero exit), or another negated errno.
     */
    SBOX_API TTask<int32_t> RunHook(const SHook& hook, const SHookContext& context, std::string& error);

    /**
     * Runs hooks in order and stops at the first failure (see RunHook).
     */
    SBOX_API TTask<int32_t> RunHooks(const std::vector<SHook>& hooks, const SHookContext& context, std::string& error);

}
}

#endif
