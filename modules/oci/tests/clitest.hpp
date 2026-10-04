#ifndef __TESTS_OCI_CLITEST_HPP__
#define __TESTS_OCI_CLITEST_HPP__

// Runs the sbox / sboxrun binaries the way a container manager does: fork + exec with standard
// streams redirected to files (a created container inherits them, so pipes would only see EOF
// when the container exits -- exactly as with runc).

#include "ocitest.hpp"
#include <sys/socket.h>
#include <sys/un.h>

namespace ocitest {

    /**
     * Result of one invocation.
     */
    struct ToolResult {
        int code = -1;
        std::string out;
        std::string err;
    };

    /**
     * Returns the path of a built tool.
     */
    inline std::string tool(const std::string& name) {
        return std::string(SBOX_TEST_BIN_DIR) + "/" + name;
    }

    /**
     * Runs a tool with arguments; `input` is its standard input. Waits for it to exit.
     */
    inline ToolResult runTool(const std::string& scratch, const std::string& binary, const std::vector<std::string>& args,
                              const std::string& input = std::string(), int timeoutSec = 60) {
        static int counter = 0;
        std::string base = scratch + "/io-" + std::to_string(::getpid()) + "-" + std::to_string(counter++);
        std::string inPath = base + ".in", outPath = base + ".out", errPath = base + ".err";
        CFile::writeAtomic(inPath, input, 0644);

        pid_t pid = ::fork();
        if (pid == 0) {
            int in = ::open(inPath.c_str(), O_RDONLY);
            int out = ::open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            int err = ::open(errPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            ::dup2(in, 0);
            ::dup2(out, 1);
            ::dup2(err, 2);
            ::alarm(unsigned(timeoutSec));

            std::vector<char*> argv;
            std::string b = binary;
            argv.push_back(const_cast<char*>(b.c_str()));
            for (const std::string& a : args) {
                argv.push_back(const_cast<char*>(a.c_str()));
            }

            argv.push_back(nullptr);
            ::execv(binary.c_str(), argv.data());
            ::_exit(127);
        }

        ToolResult r;
        int st = 0;
        ::waitpid(pid, &st, 0);
        r.code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        CFile::readAll(outPath, r.out);
        CFile::readAll(errPath, r.err);
        return r;
    }

    /**
     * Parses JSON output.
     */
    inline CJson parseJson(const std::string& text) {
        CJson doc;
        CJson::parse(text, doc);
        return doc;
    }

    /**
     * Returns the last JSON log line of a runc-style log file.
     */
    inline CJson lastLogLine(const std::string& path) {
        std::string text;
        CFile::readAll(path, text);
        std::vector<std::string_view> lines = CFile::splitLines(text);
        return lines.empty() ? CJson() : parseJson(std::string(lines.back()));
    }

    /**
     * Polls `state` until the status matches (5 s).
     */
    inline std::string waitToolStatus(const std::string& scratch, const std::string& binary, const std::vector<std::string>& globals,
                                      const std::string& id, const std::string& want) {
        std::string status;
        for (int i = 0; i < 250; ++i) {
            std::vector<std::string> args = globals;
            args.push_back("state");
            args.push_back(id);
            ToolResult r = runTool(scratch, binary, args);
            status = parseJson(r.out).get("status").asString();
            if (status == want) {
                break;
            }

            ::usleep(20000);
        }

        return status;
    }

    /**
     * Receives one descriptor over a listening UNIX socket (accept + SCM_RIGHTS).
     */
    inline int receiveFd(int listenFd) {
        int conn = ::accept4(listenFd, nullptr, nullptr, SOCK_CLOEXEC);
        if (conn < 0) {
            return -1;
        }

        char byte;
        struct iovec iov{ &byte, 1 };
        alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int))];
        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        int fd = -1;
        if (::recvmsg(conn, &msg, MSG_CMSG_CLOEXEC) > 0) {
            struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            if (cm && cm->cmsg_type == SCM_RIGHTS) {
                std::memcpy(&fd, CMSG_DATA(cm), sizeof(int));
            }
        }

        ::close(conn);
        return fd;
    }

    /**
     * Creates a listening UNIX socket.
     */
    inline int listenUnix(const std::string& path) {
        int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(fd, 4) != 0) {
            ::close(fd);
            return -1;
        }

        return fd;
    }

}

#endif
