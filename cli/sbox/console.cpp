// Foreground supervision (signal forwarding, pty proxy) and `ps` table output.
#include "cli.hpp"
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/stream.hpp>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <termios.h>
#include <unistd.h>

namespace sboxcli {

    namespace {

        /**
         * State shared by the supervision tasks.
         */
        struct Session {
            oci::CContainerProcess* process = nullptr;
            CStream signals;
            CStream pty;                // --> Master side of the container's terminal.
            CStream input;              // --> Our standard input (duplicate).
            bool signalsDone = true;
            bool outputDone = true;
            bool inputDone = true;
        };

        /**
         * Writes all bytes to a blocking descriptor.
         */
        bool writeAll(int fd, const uint8_t* data, size_t size) {
            while (size > 0) {
                ssize_t n = ::write(fd, data, size);
                if (n < 0 && errno == EINTR) {
                    continue;
                }

                if (n < 0 && errno == EAGAIN) {
                    // --> Our stdout may be non-blocking (shared file description): wait a little.
                    struct timespec ts{ 0, 1000000 };
                    ::nanosleep(&ts, nullptr);
                    continue;
                }

                if (n <= 0) {
                    return false;
                }

                data += n;
                size -= size_t(n);
            }

            return true;
        }

        /**
         * Copies the terminal window size of our stdin to the container's pty.
         */
        void copyWindowSize(int pty) {
            struct winsize ws;
            if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
                ::ioctl(pty, TIOCSWINSZ, &ws);
            }
        }

        /**
         * Forwards received signals to the container process.
         */
        TTask<void> forwardSignals(std::shared_ptr<Session> s) {
            struct signalfd_siginfo info;
            while (true) {
                SIoResult r = co_await s->signals.recv(SByteSpan(reinterpret_cast<uint8_t*>(&info), sizeof(info)));
                if (!r.ok() || r.bytes < sizeof(info)) {
                    break;
                }

                int sig = int(info.ssi_signo);
                if (sig == SIGWINCH) {
                    if (s->pty.isValid()) {
                        copyWindowSize(s->pty.nativeHandle());
                    }

                    continue;
                }

                s->process->kill(sig);
            }

            s->signalsDone = true;
        }

        /**
         * Copies the container's terminal output to our stdout.
         */
        TTask<void> copyOutput(std::shared_ptr<Session> s) {
            uint8_t buf[8192];
            while (true) {
                SIoResult r = co_await s->pty.recv(SByteSpan(buf, sizeof(buf)));
                if (!r.ok() || r.bytes == 0) {
                    break;
                }

                if (!writeAll(STDOUT_FILENO, buf, r.bytes)) {
                    break;
                }
            }

            s->outputDone = true;
        }

        /**
         * Copies our stdin to the container's terminal.
         */
        TTask<void> copyInput(std::shared_ptr<Session> s) {
            uint8_t buf[8192];
            while (true) {
                SIoResult r = co_await s->input.recv(SByteSpan(buf, sizeof(buf)));
                if (!r.ok() || r.bytes == 0) {
                    break;
                }

                SIoResult w = co_await s->pty.send(SReadOnlyByteSpan(buf, r.bytes));
                if (!w.ok()) {
                    break;
                }
            }

            s->inputDone = true;
        }

        /**
         * Returns the capability sets of this process (children it starts keep its privileges).
         */
        SCapabilities currentCapabilities() {
            SCapabilities caps;
            std::string text;
            if (CFile::readAll("/proc/self/status", text) != SBOX_OK) {
                return caps;
            }

            for (std::string_view line : CFile::splitLines(text)) {
                auto value = [&](std::string_view key, uint64_t& out) {
                    if (line.substr(0, key.size()) == key) {
                        out = std::strtoull(std::string(line.substr(key.size())).c_str(), nullptr, 16);
                    }
                };

                value("CapPrm:", caps.permitted);
                value("CapEff:", caps.effective);
                value("CapBnd:", caps.bounding);
            }

            return caps;
        }

    }

    /* Supervises a foreground container process. */
    TTask<int> Supervise(oci::CContainerProcess& process, bool terminal) {
        CEventLoop* loop = CEventLoop::current();
        auto s = std::make_shared<Session>();
        s->process = &process;

        sigset_t set, old;
        sigemptyset(&set);
        for (int sig : { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGWINCH }) {
            sigaddset(&set, sig);
        }

        ::sigprocmask(SIG_BLOCK, &set, &old);
        int sfd = ::signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
        if (sfd >= 0) {
            s->signals = CStream(CFd(sfd));
            s->signalsDone = false;
            loop->spawn(forwardSignals(s));
        }

        struct termios saved;
        bool raw = false;
        int stdinFlags = -1;

        if (terminal) {
            CFd master = process.takePty();
            if (master.isValid()) {
                if (::isatty(STDIN_FILENO) && ::tcgetattr(STDIN_FILENO, &saved) == 0) {
                    struct termios t = saved;
                    ::cfmakeraw(&t);
                    raw = ::tcsetattr(STDIN_FILENO, TCSANOW, &t) == 0;
                    copyWindowSize(master.get());
                }

                s->pty = CStream(std::move(master));
                s->outputDone = false;
                loop->spawn(copyOutput(s));

                stdinFlags = ::fcntl(STDIN_FILENO, F_GETFL);
                CFd in(::fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3));
                if (in.isValid()) {
                    s->input = CStream(std::move(in));
                    s->inputDone = false;
                    loop->spawn(copyInput(s));
                }
            }
        }

        SExitStatus st;
        int32_t rc = co_await process.wait(st);

        // --> Drain what the container wrote before it exited (EIO once the slave is gone).
        int64_t deadline = CEventLoop::nowMs() + 1000;
        while (!s->outputDone && CEventLoop::nowMs() < deadline) {
            co_await loop->sleepFor(2);
        }

        s->pty.close();
        s->input.close();
        s->signals.close();

        for (int i = 0; i < 100 && !(s->outputDone && s->inputDone && s->signalsDone); ++i) {
            co_await loop->yield();
        }

        if (stdinFlags >= 0) {
            ::fcntl(STDIN_FILENO, F_SETFL, stdinFlags);
        }

        if (raw) {
            ::tcsetattr(STDIN_FILENO, TCSANOW, &saved);
        }

        ::sigprocmask(SIG_SETMASK, &old, nullptr);

        if (rc != SBOX_OK) {
            co_return Fail("cannot wait for the container process: " + std::string(std::strerror(-rc)));
        }

        co_return st.signaled ? 128 + st.signal : st.exitCode;
    }

    /* Prints runc's ps table. */
    TTask<int> PrintPsTable(const std::vector<pid_t>& pids, const std::vector<std::string>& options) {
        SLaunchSpec spec;
        spec.args = { "ps" };
        spec.args.insert(spec.args.end(), options.begin(), options.end());
        spec.env = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" };
        spec.capabilities = currentCapabilities();
        spec.noNewPrivileges = false;
        spec.newSession = false;

        CStream outRead;
        CFd outChild;
        if (CPipe::createForChild(outRead, outChild, true) != SBOX_OK) {
            co_return Fail("cannot create a pipe");
        }

        spec.fds.push_back({ outChild.get(), 1 });
        spec.fds.push_back({ STDERR_FILENO, 2 });

        CProcess proc;
        int32_t rc = co_await CProcess::spawn(spec, proc);
        outChild.reset();
        if (rc != SBOX_OK) {
            co_return Fail("cannot run ps: " + std::string(std::strerror(-rc)));
        }

        std::vector<uint8_t> out;
        co_await outRead.recvAll(out, size_t(16) << 20);
        SExitStatus st;
        co_await proc.wait(st);

        if (!st.exited || st.exitCode != 0) {
            co_return Fail("ps exited with status " + std::to_string(st.exitCode));
        }

        std::string text(out.begin(), out.end());
        std::vector<std::string_view> lines = CFile::splitLines(text);
        if (lines.empty()) {
            co_return 0;
        }

        // --> The PID column of the header tells which field to match.
        std::istringstream header{ std::string(lines[0]) };
        std::string word;
        int pidIndex = -1;
        for (int i = 0; header >> word; ++i) {
            if (word == "PID") {
                pidIndex = i;
                break;
            }
        }

        if (pidIndex < 0) {
            co_return Fail("couldn't find PID field in ps output");
        }

        std::string result = std::string(lines[0]) + "\n";
        for (size_t i = 1; i < lines.size(); ++i) {
            std::istringstream fields{ std::string(lines[i]) };
            std::string field;
            for (int j = 0; j <= pidIndex && fields >> field; ++j) {
            }

            pid_t p = pid_t(std::strtol(field.c_str(), nullptr, 10));
            if (std::find(pids.begin(), pids.end(), p) != pids.end()) {
                result += std::string(lines[i]) + "\n";
            }
        }

        std::fwrite(result.data(), 1, result.size(), stdout);
        co_return 0;
    }

}
