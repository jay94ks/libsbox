#include <sbox/oci/hooks.hpp>
#include <sbox/box/launch.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/span.hpp>
#include <sbox/core/stream.hpp>
#include "procutil.hpp"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace sbox {
namespace oci {

    namespace {

        /**
         * Formats the failure of a hook like runc ("exit status 1, stdout: ..., stderr: ...").
         */
        std::string describe(const SHook& hook, const std::string& what, const std::string& out, const std::string& err) {
            std::string msg = "error running hook " + hook.path + ": " + what;
            msg += ", stdout: " + out;
            msg += ", stderr: " + err;
            return msg;
        }

    }

    /* Runs one hook. */
    TTask<int32_t> RunHook(const SHook& hook, const SHookContext& context, std::string& error) {
        CEventLoop* loop = CEventLoop::current();
        error.clear();

        SLaunchSpec spec;
        spec.args = hook.args.empty() ? std::vector<std::string>{ hook.path } : hook.args;
        spec.env = hook.env;
        spec.capabilities = CurrentCapabilities();
        spec.noNewPrivileges = false;
        spec.newSession = false;
        spec.parentDeathSignal = SIGKILL;

        CFd exe;
        if (context.containerPid > 0) {
            // --> Resolved in the runtime's mount namespace, executed in the container's.
            exe.reset(::open(hook.path.c_str(), O_PATH | O_CLOEXEC));
            if (!exe.isValid()) {
                int32_t rc = -errno;
                error = describe(hook, std::string("open: ") + std::strerror(errno), "", "");
                co_return rc;
            }

            std::string base = "/proc/" + std::to_string(context.containerPid) + "/ns/";
            for (const std::string& type : context.namespaces) {
                const char* proc = NamespaceProcName(type);
                uint32_t bit = NamespaceFromName(type);
                if (!proc || bit == ENS_NONE || bit == ENS_PID) {
                    continue;
                }

                spec.namespaces.push_back(SNamespaceSpec{ ENamespace(bit), base + proc });
            }

            std::vector<std::string> argv = spec.args;
            std::vector<std::string> envp = spec.env;
            spec.function = [argv, envp]() -> int32_t {
                std::vector<char*> a, e;
                for (const std::string& s : argv) {
                    a.push_back(const_cast<char*>(s.c_str()));
                }

                for (const std::string& s : envp) {
                    e.push_back(const_cast<char*>(s.c_str()));
                }

                a.push_back(nullptr);
                e.push_back(nullptr);
                ::syscall(SYS_execveat, 3, "", a.data(), e.data(), AT_EMPTY_PATH);
                return 127;
            };
            spec.fds.push_back({ exe.get(), 3 });
        } else {
            spec.executable = hook.path;
        }

        auto outC = std::make_shared<OutputCollector>();
        auto errC = std::make_shared<OutputCollector>();
        CStream inWrite;
        CFd inChild, outChild, errChild;

        if (int32_t rc = CPipe::createForChild(inWrite, inChild, false); rc != SBOX_OK) {
            co_return rc;
        }

        if (int32_t rc = CPipe::createForChild(outC->stream, outChild, true); rc != SBOX_OK) {
            co_return rc;
        }

        if (int32_t rc = CPipe::createForChild(errC->stream, errChild, true); rc != SBOX_OK) {
            co_return rc;
        }

        spec.fds.push_back({ inChild.get(), 0 });
        spec.fds.push_back({ outChild.get(), 1 });
        spec.fds.push_back({ errChild.get(), 2 });

        CProcess proc;
        int32_t rc = co_await CProcess::spawn(spec, proc);
        inChild.reset();
        outChild.reset();
        errChild.reset();
        exe.reset();

        if (rc != SBOX_OK) {
            error = describe(hook, proc.failedStep() + ": " + std::strerror(-rc), "", "");
            co_return rc;
        }

        loop->spawn(CollectOutput(outC));
        loop->spawn(CollectOutput(errC));

        // --> The state fits a pipe buffer in practice; a hook that does not read its input
        // must not block the runtime, so the write is bounded by the hook's timeout too.
        int64_t timeoutMs = hook.timeout ? int64_t(*hook.timeout) * 1000 : context.defaultTimeoutMs;
        co_await inWrite.send(BytesOf(context.stateJson), timeoutMs < 0 ? 30000 : timeoutMs);
        inWrite.close();

        std::vector<std::shared_ptr<OutputCollector>> collectors;
        collectors.push_back(outC);
        collectors.push_back(errC);

        SExitStatus st;
        rc = co_await proc.wait(st, timeoutMs);
        if (rc == -ETIMEDOUT) {
            proc.kill(SIGKILL);
            co_await proc.wait(st, 5000);
            co_await FinishCollectors(collectors, 200);
            error = describe(hook, "timeout after " + std::to_string(timeoutMs / 1000) + "s", outC->data, errC->data);
            co_return -ETIMEDOUT;
        }

        co_await FinishCollectors(collectors, 1000);

        if (rc != SBOX_OK) {
            error = describe(hook, std::string("wait: ") + std::strerror(-rc), outC->data, errC->data);
            co_return rc;
        }

        if (st.signaled) {
            error = describe(hook, "signal: " + std::string(strsignal(st.signal)), outC->data, errC->data);
            co_return -ECHILD;
        }

        if (st.exitCode != 0) {
            error = describe(hook, "exit status " + std::to_string(st.exitCode), outC->data, errC->data);
            co_return -ECHILD;
        }

        co_return SBOX_OK;
    }

    /* Runs hooks in order. */
    TTask<int32_t> RunHooks(const std::vector<SHook>& hooks, const SHookContext& context, std::string& error) {
        for (const SHook& hook : hooks) {
            int32_t rc = co_await RunHook(hook, context, error);
            if (rc != SBOX_OK) {
                co_return rc;
            }
        }

        co_return SBOX_OK;
    }

}
}
