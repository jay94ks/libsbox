#ifndef __SRC_OCI_PROCUTIL_HPP__
#define __SRC_OCI_PROCUTIL_HPP__

#include <sbox/box/launch.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/stream.hpp>
#include <memory>

namespace sbox {
namespace oci {

    /**
     * Output of a child collected by a spawned task.
     */
    struct OutputCollector {
        CStream stream;
        std::string data;
        size_t limit = 64 * 1024;
        bool done = false;
    };

    /**
     * Reads a stream to EOF (or until closed) into the collector; excess output is dropped.
     */
    TTask<void> CollectOutput(std::shared_ptr<OutputCollector> c);

    /**
     * Waits until every collector is done, or closes the remaining ones after `timeoutMs`
     * (a grandchild may keep a pipe open forever).
     */
    TTask<void> FinishCollectors(const std::vector<std::shared_ptr<OutputCollector>>& list, int64_t timeoutMs);

    /**
     * Returns the capability sets of the calling process (from /proc/self/status), so that a
     * child the runtime starts on its own behalf (hooks, ps) keeps the runtime's privileges.
     */
    SCapabilities CurrentCapabilities();

    /**
     * Opens a pidfd for `pid` and checks that it still names the process started at
     * `startTime` (checked after opening, so the pidfd cannot refer to a reused pid).
     * @return SBOX_OK, -ESRCH when the process is gone, or another negated errno.
     */
    int32_t OpenVerifiedPidfd(pid_t pid, uint64_t startTime, CFd& out);

    /**
     * Waits until a pidfd (of any process, not only a child) reports exit.
     * @return SBOX_OK or -ETIMEDOUT.
     */
    TTask<int32_t> WaitPidfdExit(int pidfd, int64_t timeoutMs);

}
}

#endif
