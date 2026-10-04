// sboxnet: Docker remote network driver + IPAM driver plugin daemon.
// The protocol handlers are sbox::net::CDockerPlugin; this file serves them over HTTP on a UNIX
// socket (default /run/docker/plugins/sboxnet.sock) until SIGTERM/SIGINT. Besides the net
// module's drivers it registers the vpn module's WireGuard overlay driver ("wg-overlay"), whose
// user-space devices live on this daemon's event loop (restored at startup).
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/http/server.hpp>
#include <sbox/net/docker.hpp>
#include <sbox/net/network.hpp>
#include <sbox/vpn/wg/overlay.hpp>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <sys/signalfd.h>
#include <unistd.h>

using namespace sbox;

namespace {

    const char* USAGE =
        "Usage: sboxnet [OPTIONS]                  serve the plugin\n"
        "       sboxnet [OPTIONS] network COMMAND  manage networks in the state directory\n"
        "\n"
        "Docker remote network driver and IPAM driver plugin backed by libsbox networking.\n"
        "Register with dockerd by its socket in /run/docker/plugins, then:\n"
        "  docker network create -d sboxnet --ipam-driver sboxnet NAME\n"
        "WireGuard overlay across hosts (driver wg-overlay, picked by the option):\n"
        "  docker network create -d sboxnet --subnet 10.210.0.0/16 --ip-range 10.210.1.0/24 \\\n"
        "      --gateway 10.210.1.1 -o sbox.wg.overlay.file=/etc/sbox/ov.json NAME\n"
        "\n"
        "Options:\n"
        "  --socket PATH      plugin socket (default /run/docker/plugins/sboxnet.sock)\n"
        "  --state-dir DIR    network state (default /var/lib/sbox/net, rootless $XDG_RUNTIME_DIR/sbox/net)\n"
        "  --no-firewall      do not program the sbox nftables table\n"
        "  --host-netns PATH  network namespace treated as the host (default: this process's)\n"
        "  --wg-uapi-dir DIR  UAPI sockets of user-space WireGuard devices (default /var/run/wireguard)\n"
        "  -h, --help         show this help\n"
        "\n"
        "Network commands (the same state the plugin, sbox-cni and sbox-image bundle --network use):\n"
        "  network create [-d DRIVER] [--subnet CIDR [--gateway IP] [--ip-range CIDR]]... [--internal]\n"
        "                 [--ipv6] [-o KEY=VALUE]... [--label KEY=VALUE]... NAME\n"
        "  network ls [-q]\n"
        "  network inspect NAME...\n"
        "  network rm NAME...\n";

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

    /* Restores the overlay devices, then serves until stopped. */
    TTask<int32_t> serveLoop(http::CHttpServer& server, CListener& listener, int sfd, net::CNetworkManager& manager,
        vpn::CWgOverlayDriver& overlay)
    {
        CEventLoop* loop = CEventLoop::current();
        // --> User-space WireGuard devices of overlay networks die with the process that ran
        // them; bring them back before answering Docker (a failure is reported, not fatal).
        int32_t restored = co_await overlay.restore(manager);
        if (restored < 0) {
            std::fprintf(stderr, "sboxnet: cannot restore wg-overlay devices: %s\n", std::strerror(-restored));
        } else if (restored > 0) {
            std::fprintf(stderr, "sboxnet: restored %d wg-overlay device(s)\n", int(restored));
        }

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

    /* Splits "key=value" into a map entry; false without '='. */
    bool keyValue(const std::string& text, std::map<std::string, std::string>& out) {
        size_t eq = text.find('=');
        if (eq == std::string::npos || eq == 0) {
            return false;
        }

        out[text.substr(0, eq)] = text.substr(eq + 1);
        return true;
    }

    /* Prints JSON to stdout. */
    void printJson(const CJson& j) {
        std::string text = j.dump(true);
        std::fwrite(text.data(), 1, text.size(), stdout);
        std::fputc('\n', stdout);
    }

    /* sboxnet network create|ls|inspect|rm. */
    TTask<int> networkCommand(net::CNetworkManager& manager, std::vector<std::string> args) {
        if (args.empty()) {
            co_return failWith("network: a command is required (create, ls, inspect, rm)");
        }

        std::string cmd = args[0];
        std::vector<std::string> rest(args.begin() + 1, args.end());
        auto value = [&](size_t& i, const char* name, std::string& out) {
            std::string key = name;
            if (rest[i] == key && i + 1 < rest.size()) {
                out = rest[++i];
                return true;
            }

            if (rest[i].compare(0, key.size() + 1, key + "=") == 0) {
                out = rest[i].substr(key.size() + 1);
                return true;
            }

            return false;
        };

        if (cmd == "create") {
            net::SNetworkCreate req;
            std::string v;
            for (size_t i = 0; i < rest.size(); ++i) {
                if (value(i, "--driver", v) || value(i, "-d", v)) {
                    req.driver = v;
                } else if (value(i, "--subnet", v)) {
                    net::SSubnetConfig sc;
                    if (net::SIpPrefix::parse(v, sc.subnet) != SBOX_OK) {
                        co_return failWith("network create: invalid --subnet " + v);
                    }

                    sc.subnet = sc.subnet.network();
                    req.subnets.push_back(sc);
                } else if (value(i, "--gateway", v)) {
                    if (req.subnets.empty() || net::SIpAddress::parse(v, req.subnets.back().gateway) != SBOX_OK) {
                        co_return failWith("network create: invalid --gateway " + v + " (it follows its --subnet)");
                    }
                } else if (value(i, "--ip-range", v)) {
                    if (req.subnets.empty() || net::SIpPrefix::parse(v, req.subnets.back().ipRange) != SBOX_OK) {
                        co_return failWith("network create: invalid --ip-range " + v + " (it follows its --subnet)");
                    }
                } else if (rest[i] == "--internal") {
                    req.internal = true;
                } else if (rest[i] == "--ipv6") {
                    req.enableIpv6 = true;
                } else if (value(i, "--opt", v) || value(i, "-o", v)) {
                    if (!keyValue(v, req.options)) {
                        co_return failWith("network create: invalid option " + v + " (want KEY=VALUE)");
                    }
                } else if (value(i, "--label", v)) {
                    if (!keyValue(v, req.labels)) {
                        co_return failWith("network create: invalid label " + v + " (want KEY=VALUE)");
                    }
                } else if (!rest[i].empty() && rest[i][0] == '-') {
                    co_return failWith("network create: unknown option " + rest[i]);
                } else if (req.name.empty()) {
                    req.name = rest[i];
                } else {
                    co_return failWith("network create: unexpected argument " + rest[i]);
                }
            }

            if (req.name.empty()) {
                co_return failWith("network create: a name is required");
            }

            // --> Like the plugin: an overlay configuration option names its driver.
            if (req.driver == "bridge" && (req.options.count(vpn::WG_OVERLAY_OPTION) || req.options.count(vpn::WG_OVERLAY_FILE_OPTION))) {
                req.driver = vpn::WG_OVERLAY_DRIVER;
            }

            net::SNetwork out;
            int32_t r = co_await manager.createNetwork(req, out);
            if (r != SBOX_OK) {
                co_return failWith("network create: " + std::string(std::strerror(-r)));
            }

            std::printf("%s\n", out.id.c_str());
            co_return 0;
        }

        if (cmd == "ls" || cmd == "list") {
            bool quiet = !rest.empty() && (rest[0] == "-q" || rest[0] == "--quiet");
            std::vector<net::SNetwork> all;
            int32_t r = co_await manager.listNetworks(all);
            if (r != SBOX_OK) {
                co_return failWith("network ls: " + std::string(std::strerror(-r)));
            }

            if (!quiet) {
                std::printf("%-14s %-20s %-12s %s\n", "NETWORK ID", "NAME", "DRIVER", "SUBNET");
            }

            for (const net::SNetwork& n : all) {
                if (quiet) {
                    std::printf("%s\n", n.name.c_str());
                    continue;
                }

                std::string subnets;
                for (const net::SNetworkSubnet& sn : n.subnets) {
                    subnets += (subnets.empty() ? "" : ",") + sn.subnet.toString();
                }

                std::printf("%-14s %-20s %-12s %s\n", n.id.substr(0, 12).c_str(), n.name.c_str(), n.driver.c_str(), subnets.c_str());
            }

            co_return 0;
        }

        if (cmd == "inspect" || cmd == "rm" || cmd == "remove") {
            if (rest.empty()) {
                co_return failWith("network " + cmd + ": a network name is required");
            }

            int rc = 0;
            CJson arr = CJson::array();
            for (const std::string& name : rest) {
                if (cmd == "inspect") {
                    net::SNetwork n;
                    int32_t r = co_await manager.getNetwork(name, n);
                    if (r != SBOX_OK) {
                        rc = failWith("network inspect: " + name + ": " + std::strerror(-r));
                        continue;
                    }

                    arr.push(n.toJson());
                } else {
                    int32_t r = co_await manager.deleteNetwork(name);
                    if (r != SBOX_OK) {
                        rc = failWith("network rm: " + name + ": " + (r == -EBUSY ? std::string("network has active endpoints") : std::string(std::strerror(-r))));
                        continue;
                    }

                    std::printf("%s\n", name.c_str());
                }
            }

            if (cmd == "inspect") {
                printJson(arr);
            }

            co_return rc;
        }

        co_return failWith("network: unknown command " + cmd);
    }

}

int main(int argc, char** argv) {
    std::string socket = "/run/docker/plugins/sboxnet.sock";
    net::SNetworkManagerOptions options;
    options.stateDir = net::DefaultNetworkStateDir();
    vpn::SWgOverlayDriverOptions overlayOptions;

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

        if (arg.compare(0, 13, "--host-netns") == 0) {
            if (!optionValue(argc, argv, i, "--host-netns", options.hostNetns) || options.hostNetns.empty()) {
                return failWith("missing --host-netns value");
            }

            continue;
        }

        if (arg.compare(0, 13, "--wg-uapi-dir") == 0) {
            if (!optionValue(argc, argv, i, "--wg-uapi-dir", overlayOptions.uapiDir) || overlayOptions.uapiDir.empty()) {
                return failWith("missing --wg-uapi-dir value");
            }

            continue;
        }

        if (arg.compare(0, 11, "--state-dir") == 0) {
            if (!optionValue(argc, argv, i, "--state-dir", options.stateDir) || options.stateDir.empty()) {
                return failWith("missing --state-dir value");
            }

            continue;
        }

        if (arg == "network") {
            // --> One-shot management command over the same state directory.
            std::vector<std::string> rest(argv + i + 1, argv + argc);
            CFile::makeDirs(options.stateDir, 0700);
            std::signal(SIGPIPE, SIG_IGN);
            CEventLoop loop;
            net::CNetworkManager manager(options);
            auto overlay = std::make_shared<vpn::CWgOverlayDriver>(overlayOptions);
            manager.registerDriver(overlay);
            return loop.run(networkCommand(manager, rest));
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
    auto overlay = std::make_shared<vpn::CWgOverlayDriver>(overlayOptions);
    manager.registerDriver(overlay);
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
    rc = loop.run(serveLoop(server, listener, sfd.get(), manager, *overlay));
    listener.close();
    ::unlink(socket.c_str());
    return rc < 0 ? failWith(std::string("server: ") + std::strerror(-rc)) : 0;
}
