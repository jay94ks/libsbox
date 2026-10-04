// sboxvol: Docker-compatible volume tool and Docker volume plugin daemon.
// The store, driver, backup and plugin logic live in sbox::vol; this file parses the command line,
// prints results and runs the plugin's HTTP server on a UNIX socket until SIGTERM/SIGINT.
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/http/server.hpp>
#include <sbox/vol/backup.hpp>
#include <sbox/vol/plugin.hpp>
#include <sbox/vol/store.hpp>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/signalfd.h>
#include <unistd.h>

using namespace sbox;

namespace {

    const char* DEFAULT_SOCKET = "/run/docker/plugins/sboxvol.sock";

    const char* USAGE =
        "Usage: sboxvol [--root DIR] COMMAND [ARGS]\n"
        "\n"
        "Docker-compatible named volumes (local driver) and Docker volume plugin.\n"
        "\n"
        "Commands:\n"
        "  create [-d local] [--opt k=v]... [--label k=v]... [NAME]   create a volume (prints its name)\n"
        "  ls [-q] [--filter label=k[=v]] [--filter dangling=true]    list volumes\n"
        "  inspect [--size] NAME...                                  print volumes as JSON\n"
        "  rm [-f] NAME...                                           remove volumes (-f: even in use)\n"
        "  prune [-a] [--filter label=k[=v]]                         remove unused (anonymous) volumes\n"
        "  backup [--level N] [--freeze] [--no-xattrs] NAME FILE|-   write a tar.gz of a volume\n"
        "  restore [--overwrite] [--no-create] [--opt k=v] [--label k=v] NAME FILE|-\n"
        "                                                            restore a backup into a volume\n"
        "  serve [--socket PATH]                                     run the Docker volume plugin\n"
        "                                                            (default " "/run/docker/plugins/sboxvol.sock)\n"
        "\n"
        "Global options:\n"
        "  --root DIR   volume store (default /var/lib/sbox/volumes, rootless $XDG_DATA_HOME/sbox/volumes)\n"
        "  -h, --help   show this help\n";

    /* Prints an error and returns the exit code 1. */
    int failWith(const std::string& message) {
        std::fprintf(stderr, "sboxvol: %s\n", message.c_str());
        return 1;
    }

    /* Returns the store's reason for a failure. */
    std::string reasonOf(const vol::CVolumeStore& store, int32_t rc, const std::string& what) {
        if (!store.lastError().empty()) {
            return store.lastError();
        }

        if (rc == -ENOENT && !what.empty()) {
            return "no such volume: " + what;
        }

        return (what.empty() ? std::string() : what + ": ") + std::strerror(-rc);
    }

    /* Splits "k=v" into a map entry. */
    bool addPair(vol::TStringMap& map, const std::string& text) {
        size_t eq = text.find('=');
        if (eq == 0 || text.empty()) {
            return false;
        }

        map[text.substr(0, eq)] = eq == std::string::npos ? std::string() : text.substr(eq + 1);
        return true;
    }

    /* Formats bytes like the docker CLI (decimal units). */
    std::string humanSize(uint64_t bytes) {
        static const char* UNITS[] = { "B", "kB", "MB", "GB", "TB", "PB" };
        double v = double(bytes);
        size_t u = 0;
        while (v >= 1000.0 && u + 1 < sizeof(UNITS) / sizeof(UNITS[0])) {
            v /= 1000.0;
            ++u;
        }

        char text[32];
        std::snprintf(text, sizeof(text), u == 0 ? "%.0f%s" : "%.4g%s", v, UNITS[u]);
        return text;
    }

    /**
     * Command line cursor: options first, then positional arguments.
     */
    struct Args {
        std::vector<std::string> items;
        size_t pos = 0;

        bool done() const { return pos >= items.size(); }

        const std::string& peek() const { return items[pos]; }

        std::string next() { return items[pos++]; }

        /* Returns the value of an option ("--opt v" or "--opt=v"); false when missing. */
        bool value(const std::string& opt, std::string& out) {
            const std::string& cur = items[pos];
            if (cur == opt) {
                if (pos + 1 >= items.size()) {
                    return false;
                }

                out = items[pos + 1];
                pos += 2;
                return true;
            }

            out = cur.substr(opt.size() + 1);
            ++pos;
            return true;
        }

        bool is(const std::string& opt) const {
            const std::string& cur = items[pos];
            return cur == opt || (cur.size() > opt.size() && cur.compare(0, opt.size() + 1, opt + "=") == 0);
        }
    };

    /* sboxvol create. */
    TTask<int> cmdCreate(vol::CVolumeStore& store, Args args) {
        vol::SVolumeCreate req;
        while (!args.done()) {
            std::string v;
            if (args.is("--opt") || args.is("-o")) {
                if (!args.value(args.is("--opt") ? "--opt" : "-o", v) || !addPair(req.options, v)) {
                    co_return failWith("invalid --opt");
                }
            } else if (args.is("--label")) {
                if (!args.value("--label", v) || !addPair(req.labels, v)) {
                    co_return failWith("invalid --label");
                }
            } else if (args.is("--driver") || args.is("-d")) {
                if (!args.value(args.is("--driver") ? "--driver" : "-d", req.driver)) {
                    co_return failWith("missing driver");
                }
            } else if (!args.peek().empty() && args.peek()[0] == '-') {
                co_return failWith("unknown option " + args.peek());
            } else if (req.name.empty()) {
                req.name = args.next();
            } else {
                co_return failWith("create takes at most one name");
            }
        }

        vol::SVolume out;
        int32_t rc = co_await store.create(req, out);
        if (rc < 0) {
            co_return failWith(reasonOf(store, rc, std::string()));
        }

        std::printf("%s\n", out.name.c_str());
        co_return 0;
    }

    /* sboxvol ls. */
    int cmdList(vol::CVolumeStore& store, Args args) {
        bool quiet = false;
        bool dangling = false;
        std::vector<std::string> labels;
        while (!args.done()) {
            std::string v;
            if (args.peek() == "-q" || args.peek() == "--quiet") {
                quiet = true;
                args.next();
            } else if (args.is("--filter") || args.is("-f")) {
                if (!args.value(args.is("--filter") ? "--filter" : "-f", v)) {
                    return failWith("missing filter");
                }

                if (v.compare(0, 6, "label=") == 0) {
                    labels.push_back(v.substr(6));
                } else if (v.compare(0, 7, "label!=") == 0) {
                    labels.push_back("!" + v.substr(7));
                } else if (v == "dangling=true" || v == "dangling=1") {
                    dangling = true;
                } else {
                    return failWith("unsupported filter " + v);
                }
            } else {
                return failWith("unknown argument " + args.peek());
            }
        }

        std::vector<vol::SVolume> all;
        int32_t rc = store.list(all);
        if (rc < 0) {
            return failWith(reasonOf(store, rc, store.root()));
        }

        if (!quiet) {
            std::printf("%-10s%s\n", "DRIVER", "VOLUME NAME");
        }

        for (const vol::SVolume& v : all) {
            if (dangling && !v.users.empty()) {
                continue;
            }

            bool keep = true;
            for (const std::string& f : labels) {
                bool neg = !f.empty() && f[0] == '!';
                std::string expr = neg ? f.substr(1) : f;
                size_t eq = expr.find('=');
                auto it = v.labels.find(expr.substr(0, eq));
                bool match = it != v.labels.end() && (eq == std::string::npos || it->second == expr.substr(eq + 1));
                keep = keep && match != neg;
            }

            if (!keep) {
                continue;
            }

            if (quiet) {
                std::printf("%s\n", v.name.c_str());
            } else {
                std::printf("%-10s%s\n", v.driver.c_str(), v.name.c_str());
            }
        }

        return 0;
    }

    /* sboxvol inspect. */
    int cmdInspect(vol::CVolumeStore& store, Args args) {
        bool size = false;
        CJson out = CJson::array();
        int code = 0;
        while (!args.done()) {
            std::string name = args.next();
            if (name == "--size" || name == "-s") {
                size = true;
                continue;
            }

            vol::SVolume v;
            int32_t rc = store.inspect(name, v);
            if (rc < 0) {
                code = failWith(rc == -ENOENT ? "no such volume: " + name : name + ": " + std::strerror(-rc));
                continue;
            }

            CJson j = v.toJson(size);
            if (size) {
                vol::SVolumeUsage u;
                if (store.usage(name, u) == SBOX_OK) {
                    j["UsageData"].set("Size", CJson(int64_t(u.bytes)));
                }
            }

            out.push(std::move(j));
        }

        std::printf("%s\n", out.dump(true).c_str());
        return code;
    }

    /* sboxvol rm. */
    TTask<int> cmdRemove(vol::CVolumeStore& store, Args args) {
        bool force = false;
        std::vector<std::string> names;
        while (!args.done()) {
            std::string a = args.next();
            if (a == "-f" || a == "--force") {
                force = true;
            } else {
                names.push_back(a);
            }
        }

        if (names.empty()) {
            co_return failWith("rm needs at least one volume name");
        }

        int code = 0;
        for (const std::string& n : names) {
            int32_t rc = co_await store.remove(n, force);
            if (rc < 0) {
                code = failWith(reasonOf(store, rc, n));
                continue;
            }

            std::printf("%s\n", n.c_str());
        }

        co_return code;
    }

    /* sboxvol prune. */
    TTask<int> cmdPrune(vol::CVolumeStore& store, Args args) {
        vol::SPruneOptions opts;
        while (!args.done()) {
            std::string v;
            if (args.peek() == "-a" || args.peek() == "--all") {
                opts.all = true;
                args.next();
            } else if (args.peek() == "-f" || args.peek() == "--force") {
                args.next();
            } else if (args.is("--filter")) {
                if (!args.value("--filter", v)) {
                    co_return failWith("missing filter");
                }

                if (v.compare(0, 6, "label=") == 0) {
                    opts.labelFilters.push_back(v.substr(6));
                } else if (v.compare(0, 7, "label!=") == 0) {
                    opts.labelFilters.push_back("!" + v.substr(7));
                } else if (v == "all=true" || v == "all=1") {
                    opts.all = true;
                } else {
                    co_return failWith("unsupported filter " + v);
                }
            } else {
                co_return failWith("unknown argument " + args.peek());
            }
        }

        vol::SPruneReport report;
        int32_t rc = co_await store.prune(opts, report);
        if (!report.removed.empty()) {
            std::printf("Deleted Volumes:\n");
            for (const std::string& n : report.removed) {
                std::printf("%s\n", n.c_str());
            }

            std::printf("\n");
        }

        std::printf("Total reclaimed space: %s\n", humanSize(report.reclaimedBytes).c_str());
        co_return rc < 0 ? failWith(reasonOf(store, rc, std::string())) : 0;
    }

    /* sboxvol backup. */
    TTask<int> cmdBackup(vol::CVolumeStore& store, Args args) {
        vol::SBackupOptions opts;
        std::vector<std::string> pos;
        while (!args.done()) {
            std::string v;
            if (args.is("--level")) {
                if (!args.value("--level", v) || v.empty() || v.size() > 1 || v[0] < '0' || v[0] > '9') {
                    co_return failWith("--level takes 0..9");
                }

                opts.level = v[0] - '0';
            } else if (args.peek() == "--freeze") {
                opts.freeze = true;
                args.next();
            } else if (args.peek() == "--no-xattrs") {
                opts.xattrs = false;
                args.next();
            } else {
                pos.push_back(args.next());
            }
        }

        if (pos.size() != 2) {
            co_return failWith("usage: sboxvol backup [--level N] [--freeze] NAME FILE|-");
        }

        int32_t rc;
        if (pos[1] == "-") {
            archive::CFdSink out(STDOUT_FILENO);
            rc = co_await vol::BackupVolume(store, pos[0], out, opts);
        } else {
            rc = co_await vol::BackupVolumeToFile(store, pos[0], pos[1], opts);
        }

        co_return rc < 0 ? failWith("backup of " + pos[0] + " failed: " + reasonOf(store, rc, std::string())) : 0;
    }

    /* sboxvol restore. */
    TTask<int> cmdRestore(vol::CVolumeStore& store, Args args) {
        vol::SRestoreOptions opts;
        std::vector<std::string> pos;
        while (!args.done()) {
            std::string v;
            if (args.peek() == "--overwrite") {
                opts.overwrite = true;
                args.next();
            } else if (args.peek() == "--no-create") {
                opts.create = false;
                args.next();
            } else if (args.is("--opt")) {
                if (!args.value("--opt", v) || !addPair(opts.createOptions.options, v)) {
                    co_return failWith("invalid --opt");
                }
            } else if (args.is("--label")) {
                if (!args.value("--label", v) || !addPair(opts.createOptions.labels, v)) {
                    co_return failWith("invalid --label");
                }
            } else {
                pos.push_back(args.next());
            }
        }

        if (pos.size() != 2) {
            co_return failWith("usage: sboxvol restore [--overwrite] NAME FILE|-");
        }

        int32_t rc;
        if (pos[1] == "-") {
            archive::CFdSource in(STDIN_FILENO);
            rc = co_await vol::RestoreVolume(store, pos[0], in, opts);
        } else {
            rc = co_await vol::RestoreVolumeFromFile(store, pos[0], pos[1], opts);
        }

        if (rc == -ENOTEMPTY) {
            co_return failWith("volume " + pos[0] + " is not empty (use --overwrite)");
        }

        co_return rc < 0 ? failWith("restore into " + pos[0] + " failed: " + reasonOf(store, rc, std::string())) : 0;
    }

    /* Stops the server on SIGTERM / SIGINT read from a signalfd. */
    TTask<void> watchSignals(int sfd, http::CHttpServer& server) {
        int32_t rc = co_await CEventLoop::current()->waitFd(sfd, EFDE_READ);
        if (rc > 0) {
            signalfd_siginfo info{};
            if (::read(sfd, &info, sizeof(info)) == ssize_t(sizeof(info))) {
                std::fprintf(stderr, "sboxvol: signal %u, stopping\n", info.ssi_signo);
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

    /* sboxvol serve. */
    int cmdServe(vol::CVolumeStore& store, Args args) {
        std::string socket = DEFAULT_SOCKET;
        while (!args.done()) {
            if (args.is("--socket")) {
                if (!args.value("--socket", socket) || socket.empty()) {
                    return failWith("missing socket path");
                }
            } else {
                return failWith("unknown argument " + args.peek());
            }
        }

        // --> Signals are taken from a signalfd on the event loop: block them first (before any
        // thread exists, so every later thread inherits the mask).
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

        size_t slash = socket.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            CFile::makeDirs(socket.substr(0, slash), 0755);
        }

        SEndpoint ep;
        CListener listener;
        int32_t rc = SEndpoint::fromUnix(socket, ep);
        if (rc == SBOX_OK) {
            rc = listener.listen(ep);
        }

        if (rc < 0) {
            return failWith("cannot listen on " + socket + ": " + std::strerror(-rc));
        }

        CEventLoop loop;
        http::CHttpServer server;
        vol::CVolumePlugin plugin(store);
        plugin.attach(server);
        std::fprintf(stderr, "sboxvol: serving volume plugin on %s (store %s)\n", socket.c_str(), store.root().c_str());

        rc = loop.run(serveLoop(server, listener, sfd.get()));
        listener.close();
        ::unlink(socket.c_str());
        return rc < 0 ? failWith(std::string("server: ") + std::strerror(-rc)) : 0;
    }

}

int main(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        args.items.emplace_back(argv[i]);
    }

    vol::SVolumeStoreOptions options;
    while (!args.done() && !args.peek().empty() && args.peek()[0] == '-') {
        if (args.peek() == "-h" || args.peek() == "--help") {
            std::fputs(USAGE, stdout);
            return 0;
        }

        if (args.is("--root")) {
            if (!args.value("--root", options.root) || options.root.empty()) {
                return failWith("missing --root value");
            }

            continue;
        }

        return failWith("unknown option " + args.peek() + " (see --help)");
    }

    if (args.done()) {
        std::fputs(USAGE, stderr);
        return 2;
    }

    std::string command = args.next();
    for (const std::string& a : args.items) {
        if (a == "-h" || a == "--help") {
            std::fputs(USAGE, stdout);
            return 0;
        }
    }

    vol::CVolumeStore store(options);
    if (command == "serve") {
        return cmdServe(store, std::move(args));
    }

    if (command == "ls" || command == "list") {
        return cmdList(store, std::move(args));
    }

    if (command == "inspect") {
        return cmdInspect(store, std::move(args));
    }

    CEventLoop loop;
    if (command == "create") {
        return loop.run(cmdCreate(store, std::move(args)));
    }

    if (command == "rm" || command == "remove") {
        return loop.run(cmdRemove(store, std::move(args)));
    }

    if (command == "prune") {
        return loop.run(cmdPrune(store, std::move(args)));
    }

    if (command == "backup") {
        return loop.run(cmdBackup(store, std::move(args)));
    }

    if (command == "restore") {
        return loop.run(cmdRestore(store, std::move(args)));
    }

    return failWith("unknown command " + command + " (see --help)");
}
