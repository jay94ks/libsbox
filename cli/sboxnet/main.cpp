// sboxnet: Docker remote network driver + IPAM driver plugin daemon.
// The protocol handlers are sbox::net::CDockerPlugin; this file serves them over HTTP on a UNIX
// socket (default /run/docker/plugins/sboxnet.sock) until SIGTERM/SIGINT.
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/http/server.hpp>
#include <sbox/net/docker.hpp>
#include <sbox/net/network.hpp>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/signalfd.h>
#include <unistd.h>

using namespace sbox;

namespace {

    const char* USAGE =
        "Usage: sboxnet [OPTIONS]\n"
        "\n"
        "Docker remote network driver and IPAM driver plugin backed by libsbox networking.\n"
        "Register with dockerd by its socket in /run/docker/plugins, then:\n"
        "  docker network create -d sboxnet --ipam-driver sboxnet NAME\n"
        "\n"
        "Options:\n"
        "  --socket PATH      plugin socket (default /run/docker/plugins/sboxnet.sock)\n"
        "  --state-dir DIR    network state (default /var/lib/sbox/net, rootless $XDG_RUNTIME_DIR/sbox/net)\n"
        "  --no-firewall      do not program the sbox nftables table\n"
        "  -h, --help         show this help\n";

    /* Prints an error and returns the exit code 1. */
    int failWith(const std::string& message) {
        std::fprintf(stderr, "sboxnet: %s\n", message.c_str());
        return 1;
    }

    /* Stops the server on SIGTERM / SIGINT read from a signalfd. */
    TTask<void> watchSignals(int sfd, http::CHttpServer& server) {
        int32_t rc = co_await CEventLoop::current()->waitFd(sfd, EFDE_READ);
        if (rc > 0) {
            signalfd_siginfo info{};
            if (::read(sfd, &info, sizeof(info)) == ssize_t(sizeof(info))) {
                std::fprintf(stderr, "sboxnet: signal %u, stopping\n", info.ssi_signo);
            }

            server.stop();
        }
    }

    /* Serves until stopped. */
    TTask<int32_t> serveLoop(http::CHttpServer& server, CListener& listener, int sfd) {
        CEventLoop* loop = CEventLoop::current();
        loop->spawn(watchSignals(sfd, server));
        int32_t rc = co_await server.serve(listener);
        loop->cancelFd(sfd);
        co_await loop->yield();
        co_return rc;
    }

    /* Returns the value of "--name value" / "--name=value" at argv[i] (advancing i). */
    bool optionValue(int argc, char** argv, int& i, const char* name, std::string& out) {
        size_t n = std::strlen(name);
        if (std::strcmp(argv[i], name) == 0) {
            if (i + 1 >= argc) {
                return false;
            }

            out = argv[++i];
            return true;
        }

        if (std::strncmp(argv[i], name, n) == 0 && argv[i][n] == '=') {
            out = argv[i] + n + 1;
            return true;
        }

        return false;
    }

}

int main(int argc, char** argv) {
    std::string socket = "/run/docker/plugins/sboxnet.sock";
    net::SNetworkManagerOptions options;
    options.stateDir = net::DefaultNetworkStateDir();

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::fputs(USAGE, stdout);
            return 0;
        }

        if (arg == "--no-firewall") {
            options.firewall = false;
            continue;
        }

        if (arg.compare(0, 8, "--socket") == 0) {
            if (!optionValue(argc, argv, i, "--socket", socket) || socket.empty()) {
                return failWith("missing --socket value");
            }

            continue;
        }

        if (arg.compare(0, 11, "--state-dir") == 0) {
            if (!optionValue(argc, argv, i, "--state-dir", options.stateDir) || options.stateDir.empty()) {
                return failWith("missing --state-dir value");
            }

            continue;
        }

        return failWith("unknown argument " + arg + " (see --help)");
    }

    // --> Signals are read from a signalfd on the event loop; block them before any thread exists.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (::sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
        return failWith(std::string("sigprocmask: ") + std::strerror(errno));
    }

    CFd sfd(::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
    if (!sfd.isValid()) {
        return failWith(std::string("signalfd: ") + std::strerror(errno));
    }

    std::signal(SIGPIPE, SIG_IGN);

    int32_t rc = CFile::makeDirs(options.stateDir, 0700);
    if (rc < 0) {
        return failWith("cannot create state directory " + options.stateDir + ": " + std::strerror(-rc));
    }

    size_t slash = socket.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        CFile::makeDirs(socket.substr(0, slash), 0755);
    }

    SEndpoint ep;
    CListener listener;
    rc = SEndpoint::fromUnix(socket, ep);
    if (rc == SBOX_OK) {
        rc = listener.listen(ep);
    }

    if (rc < 0) {
        return failWith("cannot listen on " + socket + ": " + std::strerror(-rc));
    }

    CEventLoop loop;
    net::CNetworkManager manager(options);
    net::CDockerPlugin plugin(manager);

    http::SServerOptions serverOptions;
    serverOptions.jsonContentType = net::CDockerPlugin::contentType();
    http::CHttpServer server(serverOptions);
    server.fallback([&plugin](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
        CJson body;
        if (co_await req.readJson(body) < 0) {
            CJson err = CJson::object();
            err.set("Err", CJson("invalid JSON request body"));
            res.setJson(err, 400);
            co_return;
        }

        CJson reply = co_await plugin.handle(req.path, std::move(body));
        // --> Docker reads "Err" from the body for any status; the net module recommends 500 for errors.
        res.setJson(reply, net::CDockerPlugin::isError(reply) ? 500 : 200);
    });

    std::fprintf(stderr, "sboxnet: serving network/IPAM plugin on %s (state %s)\n", socket.c_str(), options.stateDir.c_str());
    rc = loop.run(serveLoop(server, listener, sfd.get()));
    listener.close();
    ::unlink(socket.c_str());
    return rc < 0 ? failWith(std::string("server: ") + std::strerror(-rc)) : 0;
}
