// sbox-l2tp: L2TP/IPsec server for the built-in Windows/macOS/iOS/Android clients.
//   sbox-l2tp run -c config.json        serve in the foreground (Ctrl-C/SIGTERM stops, SIGUSR1 lists sessions)
//   sbox-l2tp check -c config.json      validate a configuration
//   sbox-l2tp profile ...               print client setup (Windows PowerShell, Apple profile, Android)
//   sbox-l2tp nthash <password>         print the NT hash for "ntHash" in the user list
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include <sbox/vpn/l2tp/profiles.hpp>
#include <sbox/vpn/l2tp/server.hpp>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/signalfd.h>
#include <unistd.h>
#include <vector>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    /* Prints usage. */
    void usage() {
        std::fputs(
            "usage: sbox-l2tp <command> [options]\n"
            "\n"
            "commands:\n"
            "  run -c FILE [-v]          run the L2TP/IPsec server in the foreground (SIGUSR1 lists sessions)\n"
            "  check -c FILE             validate a configuration file\n"
            "  profile --server HOST (--psk KEY | -c FILE) [--user NAME] [--password PW] [--name NAME]\n"
            "          [--auth mschapv2|chap|pap] [--routes CIDR,...] [--nat] --format windows|apple|android\n"
            "                            print client setup: PowerShell (Add-VpnConnection -TunnelType L2tp),\n"
            "                            an Apple .mobileconfig, or Android/macOS/iOS steps\n"
            "  nthash PASSWORD           print MD4(UTF-16LE(PASSWORD)) for \"ntHash\"\n",
            stderr);
    }

    /* Simple option reader. */
    struct Args {
        std::vector<std::string> items;
        size_t at = 0;

        bool more() const { return at < items.size(); }

        std::string next() { return at < items.size() ? items[at++] : std::string(); }
    };

    /* Splits "a,b,c". */
    std::vector<std::string> splitList(const std::string& text) {
        std::vector<std::string> out;
        size_t start = 0;
        while (start <= text.size()) {
            size_t comma = text.find(',', start);
            std::string part = text.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (!part.empty()) {
                out.push_back(part);
            }

            if (comma == std::string::npos) {
                break;
            }

            start = comma + 1;
        }

        return out;
    }

    /* Loads and parses a configuration. */
    int32_t loadConfig(const std::string& path, SL2tpServerConfig& out) {
        std::string text;
        int32_t r = CFile::readAll(path, text);
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-l2tp: cannot read %s: %s\n", path.c_str(), std::strerror(-r));
            return r;
        }

        CJson json;
        size_t offset = 0;
        if (CJson::parse(text, json, &offset) != SBOX_OK) {
            std::fprintf(stderr, "sbox-l2tp: %s: JSON syntax error at byte %zu\n", path.c_str(), offset);
            return -EINVAL;
        }

        std::string dir = path.find('/') == std::string::npos ? std::string(".") : path.substr(0, path.rfind('/'));
        std::string error;
        r = ParseL2tpServerConfig(json, out, &error, dir);
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-l2tp: %s: %s\n", path.c_str(), error.c_str());
        }

        return r;
    }

    /* Prints the sessions. */
    void printSessions(const CL2tpServer& server) {
        std::vector<SIkev1SessionInfo> ike = server.ikeSessions();
        std::fprintf(stderr, "%zu ISAKMP SA(s)\n", ike.size());
        for (const SIkev1SessionInfo& s : ike) {
            std::fprintf(stderr, "  %016llx/%016llx %-11s %-24s %-22s %s%s ipsec=%zu\n", static_cast<unsigned long long>(s.cookieI),
                         static_cast<unsigned long long>(s.cookieR), s.state.c_str(), s.identity.c_str(), s.remote.c_str(),
                         s.suite.c_str(), s.nat ? " NAT-T" : "", s.ipsecSas);
        }

        std::vector<SL2tpSessionInfo> sessions = server.sessions();
        std::fprintf(stderr, "%zu PPP session(s)\n", sessions.size());
        int64_t now = CEventLoop::nowMs();
        for (const SL2tpSessionInfo& s : sessions) {
            std::fprintf(stderr, "  %5u/%-5u %-16s %-15s %-22s %-9s up %llds in %llu/%llu out %llu/%llu\n", unsigned(s.tunnelId),
                         unsigned(s.sessionId), s.user.empty() ? "-" : s.user.c_str(), s.address.empty() ? "-" : s.address.c_str(),
                         s.remote.c_str(), s.auth.c_str(), static_cast<long long>(s.upMs ? (now - s.upMs) / 1000 : 0),
                         static_cast<unsigned long long>(s.inPackets), static_cast<unsigned long long>(s.inBytes),
                         static_cast<unsigned long long>(s.outPackets), static_cast<unsigned long long>(s.outBytes));
        }
    }

    /* Waits for SIGINT/SIGTERM; SIGUSR1 prints the sessions. */
    TTask<void> waitForSignal(int fd, const CL2tpServer& server) {
        while (true) {
            int32_t r = co_await CEventLoop::current()->waitFd(fd, EFDE_READ);
            if (r < 0) {
                co_return;
            }

            signalfd_siginfo info;
            if (::read(fd, &info, sizeof(info)) != ssize_t(sizeof(info))) {
                continue;
            }

            if (info.ssi_signo == SIGUSR1) {
                printSessions(server);
                continue;
            }

            co_return;
        }
    }

    /* Serves until a signal arrives. */
    TTask<int32_t> serve(SL2tpServerConfig config, bool verbose, int signalFd) {
        CL2tpServer server(std::move(config));
        server.logger([verbose](EIkeLogLevel level, const std::string& message) {
            if (level == EIKE_LOG_DEBUG && !verbose) {
                return;
            }

            static const char* NAMES[] = { "debug", "info", "warning", "error" };
            char stamp[32];
            std::time_t now = std::time(nullptr);
            std::tm tm;
            ::localtime_r(&now, &tm);
            std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);
            std::fprintf(stderr, "%s [%s] %s\n", stamp, NAMES[level], message.c_str());
        });

        int32_t r = co_await server.start();
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-l2tp: failed to start: %s\n", std::strerror(-r));
            co_return r;
        }

        co_await waitForSignal(signalFd, server);
        std::fputs("sbox-l2tp: stopping (disconnecting clients)\n", stderr);
        co_await server.stop();
        co_return SBOX_OK;
    }

    /* "run" command. */
    int runCommand(Args& args) {
        std::string path;
        bool verbose = false;
        while (args.more()) {
            std::string a = args.next();
            if (a == "-c" || a == "--config") {
                path = args.next();
            }
            else if (a == "-v" || a == "--verbose") {
                verbose = true;
            }
            else {
                usage();
                return 2;
            }
        }

        if (path.empty()) {
            usage();
            return 2;
        }

        SL2tpServerConfig config;
        if (loadConfig(path, config) != SBOX_OK) {
            return 1;
        }

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        ::sigprocmask(SIG_BLOCK, &mask, nullptr);
        CFd sfd(::signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
        if (!sfd.isValid()) {
            std::perror("signalfd");
            return 1;
        }

        CEventLoop loop;
        int32_t r = loop.run(serve(std::move(config), verbose, sfd.get()));
        return r == SBOX_OK ? 0 : 1;
    }

    /* "check" command. */
    int checkCommand(Args& args) {
        std::string path;
        while (args.more()) {
            std::string a = args.next();
            if (a == "-c" || a == "--config") {
                path = args.next();
            }
        }

        if (path.empty()) {
            usage();
            return 2;
        }

        SL2tpServerConfig config;
        if (loadConfig(path, config) != SBOX_OK) {
            return 1;
        }

        std::string auth;
        for (EPppAuth a : config.auth) {
            auth += std::string(auth.empty() ? "" : ",") + PppAuthName(a);
        }

        std::printf("configuration OK: %zu user(s), %zu PSK(s), pool %s, auth %s, data path %s\n", config.users.size(),
                    config.ike.psks.size(), config.pool.toString().c_str(), auth.c_str(),
                    config.dataPath == EL2TK_AUTO ? "auto" : config.dataPath == EL2TK_KERNEL ? "kernel" : config.dataPath == EL2TK_USER ? "user" : "none");
        return 0;
    }

    /* "profile" command. */
    int profileCommand(Args& args) {
        SL2tpClientProfile p;
        std::string format;
        std::string configPath;
        while (args.more()) {
            std::string a = args.next();
            if (a == "--server") {
                p.server = args.next();
            }
            else if (a == "--psk") {
                p.psk = args.next();
            }
            else if (a == "-c" || a == "--config") {
                configPath = args.next();
            }
            else if (a == "--user") {
                p.user = args.next();
            }
            else if (a == "--password") {
                p.password = args.next();
            }
            else if (a == "--name") {
                p.name = args.next();
            }
            else if (a == "--auth") {
                if (!ParsePppAuth(args.next(), p.auth)) {
                    std::fputs("sbox-l2tp: --auth must be mschapv2, chap or pap\n", stderr);
                    return 2;
                }
            }
            else if (a == "--routes") {
                p.routes = splitList(args.next());
            }
            else if (a == "--nat") {
                p.serverBehindNat = true;
            }
            else if (a == "--format") {
                format = args.next();
            }
            else {
                usage();
                return 2;
            }
        }

        if (!configPath.empty() && p.psk.empty()) {
            SL2tpServerConfig config;
            if (loadConfig(configPath, config) != SBOX_OK) {
                return 1;
            }

            for (const SIkePsk& k : config.ike.psks) {
                if (k.id.empty()) {
                    p.psk = k.secret;
                }
            }

            if (!config.auth.empty()) {
                p.auth = config.auth[0];
            }
        }

        if (p.server.empty() || p.psk.empty() || format.empty()) {
            usage();
            return 2;
        }

        if (format == "windows") {
            std::fputs(WindowsL2tpSetup(p).c_str(), stdout);
        }
        else if (format == "apple") {
            std::fputs(AppleL2tpMobileConfig(p).c_str(), stdout);
        }
        else if (format == "android") {
            std::fputs(AndroidL2tpSetup(p).c_str(), stdout);
        }
        else {
            usage();
            return 2;
        }

        return 0;
    }

    /* "nthash" command. */
    int nthashCommand(Args& args) {
        if (!args.more()) {
            usage();
            return 2;
        }

        std::string password = args.next();
        uint8_t hash[16];
        if (MsChapNtPasswordHash(password, SByteSpan(hash, sizeof(hash))) != SBOX_OK) {
            std::fputs("sbox-l2tp: invalid password\n", stderr);
            return 1;
        }

        for (uint8_t b : hash) {
            std::printf("%02x", b);
        }

        std::printf("\n");
        return 0;
    }

}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }

    Args args;
    for (int i = 2; i < argc; ++i) {
        args.items.emplace_back(argv[i]);
    }

    std::string command = argv[1];
    if (command == "run") {
        return runCommand(args);
    }

    if (command == "check") {
        return checkCommand(args);
    }

    if (command == "profile") {
        return profileCommand(args);
    }

    if (command == "nthash") {
        return nthashCommand(args);
    }

    usage();
    return 2;
}
