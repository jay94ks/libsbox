#include "procutil.hpp"
#include <sbox/core/file.hpp>
#include <sbox/oci/state.hpp>
#include <cerrno>
#include <cstdlib>
#include <sys/syscall.h>
#include <unistd.h>

namespace sbox {
namespace oci {

    /* Reads a stream into a collector. */
    TTask<void> CollectOutput(std::shared_ptr<OutputCollector> c) {
        uint8_t buf[4096];
        while (true) {
            SIoResult r = co_await c->stream.recv(SByteSpan(buf, sizeof(buf)));
            if (!r.ok() || r.bytes == 0) {
                break;
            }

            size_t room = c->data.size() < c->limit ? c->limit - c->data.size() : 0;
            c->data.append(reinterpret_cast<const char*>(buf), r.bytes < room ? r.bytes : room);
        }

        c->done = true;
    }

    /* Waits for collectors with a bound. */
    TTask<void> FinishCollectors(const std::vector<std::shared_ptr<OutputCollector>>& list, int64_t timeoutMs) {
        CEventLoop* loop = CEventLoop::current();
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;

        while (true) {
            bool all = true;
            for (const auto& c : list) {
                all = all && c->done;
            }

            if (all) {
                co_return;
            }

            if (CEventLoop::nowMs() >= deadline) {
                break;
            }

            co_await loop->sleepFor(2);
        }

        for (const auto& c : list) {
            if (!c->done) {
                c->stream.close();
            }
        }

        // --> Let the readers observe the cancellation before the caller drops its references.
        for (int i = 0; i < 100; ++i) {
            bool all = true;
            for (const auto& c : list) {
                all = all && c->done;
            }

            if (all) {
                break;
            }

            co_await loop->yield();
        }
    }

    /* Returns the capability sets of the calling process. */
    SCapabilities CurrentCapabilities() {
        SCapabilities caps;
        std::string text;
        if (CFile::readAll("/proc/self/status", text) != SBOX_OK) {
            return caps;
        }

        for (std::string_view line : CFile::splitLines(text)) {
            auto value = [&](std::string_view key, uint64_t& out) {
                if (line.substr(0, key.size()) == key) {
                    std::string hex(line.substr(key.size()));
                    out = std::strtoull(hex.c_str(), nullptr, 16);
                }
            };

            value("CapInh:", caps.inheritable);
            value("CapPrm:", caps.permitted);
            value("CapEff:", caps.effective);
            value("CapBnd:", caps.bounding);
            value("CapAmb:", caps.ambient);
        }

        return caps;
    }

    /* Opens a pidfd and verifies the process start time. */
    int32_t OpenVerifiedPidfd(pid_t pid, uint64_t startTime, CFd& out) {
        if (pid <= 0) {
            return -ESRCH;
        }

        CFd fd(int(::syscall(SYS_pidfd_open, pid, 0)));
        if (!fd.isValid()) {
            return -errno;
        }

        // --> Checked after opening: if the pid had been reused, the start time differs.
        if (!ProcessAlive(pid, startTime)) {
            return -ESRCH;
        }

        out = std::move(fd);
        return SBOX_OK;
    }

    /* Waits for a pidfd to report exit. */
    TTask<int32_t> WaitPidfdExit(int pidfd, int64_t timeoutMs) {
        int32_t w = co_await CEventLoop::current()->waitFd(pidfd, EFDE_READ, timeoutMs);
        co_return w > 0 ? SBOX_OK : (w == 0 ? -ETIMEDOUT : w);
    }

}
}
