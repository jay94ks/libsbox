// sbox-ike: IKEv2 VPN responder for the built-in Windows/macOS/iOS/Android clients.
//   sbox-ike run -c config.json       serve in the foreground (Ctrl-C stops and sends DELETE)
//   sbox-ike check -c config.json     validate a configuration
//   sbox-ike mkcert ...               create a CA and a server certificate, plus client setup files
//   sbox-ike profile ...              print client setup material for an existing CA
//   sbox-ike nthash <password>        print the NT hash for "ntHash" in the user list
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/vpn/ipsec/certs.hpp>
#include <sbox/vpn/ipsec/mschapv2.hpp>
#include <sbox/vpn/ipsec/profiles.hpp>
#include <sbox/vpn/ipsec/server.hpp>
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
            "usage: sbox-ike <command> [options]\n"
            "\n"
            "commands:\n"
            "  run -c FILE [-v]          run the IKEv2 responder in the foreground (SIGUSR1 lists SAs)\n"
            "  check -c FILE             validate a configuration file\n"
            "  mkcert --name HOST [--ip ADDR]... [--dns NAME]... [--out DIR] [--ecdsa] [--days N]\n"
            "         [--client NAME --p12-password PW] [--user NAME] [--routes CIDR,...]\n"
            "                            create ca.pem/ca.key, server.pem/server.key (and client.p12)\n"
            "                            and write windows-setup.ps1, <name>.mobileconfig, android.txt\n"
            "  profile --ca FILE --server HOST [--remote-id ID] [--auth eap|psk|cert] [--user NAME]\n"
            "          [--password PW] [--psk KEY] [--local-id ID] [--p12 FILE --p12-password PW]\n"
            "          [--routes CIDR,...] [--name NAME] --format windows|apple|android\n"
            "  nthash PASSWORD           print MD4(UTF-16LE(PASSWORD)) for \"ntHash\"\n",
            stderr);
    }

    /* Simple option reader: --key value and flags. */
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
    int32_t loadConfig(const std::string& path, SIkeServerConfig& out) {
        std::string text;
        int32_t r = CFile::readAll(path, text);
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: cannot read %s: %s\n", path.c_str(), std::strerror(-r));
            return r;
        }

        CJson json;
        size_t offset = 0;
        if (CJson::parse(text, json, &offset) != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: %s: JSON syntax error at byte %zu\n", path.c_str(), offset);
            return -EINVAL;
        }

        std::string dir = path.find('/') == std::string::npos ? std::string(".") : path.substr(0, path.rfind('/'));
        std::string error;
        r = ParseIkeServerConfig(json, out, &error, dir);
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: %s: %s\n", path.c_str(), error.c_str());
        }

        return r;
    }

    /* Prints the IKE SAs. */
    void printSessions(const CIkeServer& server) {
        std::vector<SIkeSessionInfo> sessions = server.sessions();
        std::fprintf(stderr, "%zu IKE SA(s)\n", sessions.size());
        for (const SIkeSessionInfo& s : sessions) {
            std::fprintf(stderr, "  %016llx/%016llx %-11s %-24s %-22s vip=%s %s%s\n", static_cast<unsigned long long>(s.spiI),
                         static_cast<unsigned long long>(s.spiR), s.state.c_str(), s.identity.c_str(), s.remote.c_str(),
                         s.virtualIp.empty() ? "-" : s.virtualIp.c_str(), s.proposal.c_str(), s.nat ? " NAT" : "");
            for (const SIkeChildInfo& c : s.children) {
                std::string local;
                std::string remote;
                for (const std::string& t : c.localTs) {
                    local += t + " ";
                }

                for (const std::string& t : c.remoteTs) {
                    remote += t + " ";
                }

                std::fprintf(stderr, "    child %08x_i %08x_o %s  %s=== %s\n", c.inboundSpi, c.outboundSpi, c.proposal.c_str(),
                             local.c_str(), remote.c_str());
            }
        }
    }

    /* Waits for SIGINT/SIGTERM on a signalfd; SIGUSR1 prints the IKE SAs. */
    TTask<void> waitForSignal(int fd, const CIkeServer& server) {
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
    TTask<int32_t> serve(SIkeServerConfig config, bool verbose, int signalFd) {
        CIkeServer server(std::move(config));
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
            std::fprintf(stderr, "sbox-ike: failed to start: %s\n", std::strerror(-r));
            co_return r;
        }

        co_await waitForSignal(signalFd, server);
        std::fputs("sbox-ike: stopping (sending DELETE to connected clients)\n", stderr);
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

        SIkeServerConfig config;
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

        SIkeServerConfig config;
        if (loadConfig(path, config) != SBOX_OK) {
            return 1;
        }

        std::printf("configuration OK: %zu user(s), %zu PSK(s), %zu client CA(s), pool %s\n", config.users.size(),
                    config.psks.size(), config.caCertificates.size(),
                    config.pool.isValid() ? config.pool.toString().c_str() : "(none)");
        if (config.certificate.isValid()) {
            std::printf("server certificate: %s (issuer %s)\n", config.certificate.subject().c_str(), config.certificate.issuer().c_str());
        }

        return 0;
    }

    /* Writes a file, reporting errors. */
    bool writeFile(const std::string& path, std::string_view data, uint32_t mode) {
        int32_t r = CFile::writeAtomic(path, data, mode);
        if (r != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: cannot write %s: %s\n", path.c_str(), std::strerror(-r));
            return false;
        }

        std::printf("  wrote %s\n", path.c_str());
        return true;
    }

    /* "mkcert" command. */
    int mkcertCommand(Args& args) {
        std::string name;
        std::string out = ".";
        std::vector<std::string> ips;
        std::vector<std::string> dns;
        bool ecdsa = false;
        uint32_t days = 825;
        std::string client;
        std::string p12Password;
        std::string user;
        std::vector<std::string> routes;

        while (args.more()) {
            std::string a = args.next();
            if (a == "--name") {
                name = args.next();
            }
            else if (a == "--ip") {
                ips.push_back(args.next());
            }
            else if (a == "--dns") {
                dns.push_back(args.next());
            }
            else if (a == "--out") {
                out = args.next();
            }
            else if (a == "--ecdsa") {
                ecdsa = true;
            }
            else if (a == "--days") {
                days = uint32_t(std::strtoul(args.next().c_str(), nullptr, 10));
            }
            else if (a == "--client") {
                client = args.next();
            }
            else if (a == "--p12-password") {
                p12Password = args.next();
            }
            else if (a == "--user") {
                user = args.next();
            }
            else if (a == "--routes") {
                routes = splitList(args.next());
            }
            else {
                usage();
                return 2;
            }
        }

        if (name.empty() || days == 0) {
            usage();
            return 2;
        }

        if (CFile::makeDirs(out, 0700) != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: cannot create %s\n", out.c_str());
            return 1;
        }

        // --> A literal address as the name goes into the iPAddress SAN as well.
        net::SIpAddress literal;
        if (net::SIpAddress::parse(name, literal) == SBOX_OK) {
            ips.insert(ips.begin(), name);
        }
        else {
            dns.insert(dns.begin(), name);
        }

        std::printf("generating %s keys (RSA keys take a few seconds)...\n", ecdsa ? "ECDSA P-256" : "RSA 2048");

        SVpnCertOptions caOptions;
        caOptions.commonName = name + " VPN CA";
        caOptions.ecdsa = ecdsa;
        CIkeCertificate ca;
        if (GenerateVpnCa(caOptions, ca) != SBOX_OK) {
            std::fputs("sbox-ike: CA generation failed\n", stderr);
            return 1;
        }

        SVpnCertOptions serverOptions;
        serverOptions.commonName = name;
        serverOptions.dnsNames = dns;
        serverOptions.ipAddresses = ips;
        serverOptions.days = days;
        serverOptions.ecdsa = ecdsa;
        CIkeCertificate server;
        if (IssueVpnCertificate(ca, serverOptions, server) != SBOX_OK) {
            std::fputs("sbox-ike: server certificate generation failed\n", stderr);
            return 1;
        }

        bool ok = writeFile(CFile::join(out, "ca.pem"), ca.toPem(), 0644) && writeFile(CFile::join(out, "ca.key"), ca.keyPem(), 0600)
            && writeFile(CFile::join(out, "server.pem"), server.toPem(), 0644)
            && writeFile(CFile::join(out, "server.key"), server.keyPem(), 0600);
        if (!ok) {
            return 1;
        }

        SVpnClientProfile profile;
        profile.name = name + " VPN";
        profile.server = name;
        profile.remoteId = name;
        profile.ca = ca;
        profile.user = user;
        profile.routes = routes;

        if (!client.empty()) {
            SVpnCertOptions clientOptions;
            clientOptions.commonName = client;
            clientOptions.server = false;
            clientOptions.dnsNames = { client };
            clientOptions.days = days;
            clientOptions.ecdsa = ecdsa;
            CIkeCertificate cert;
            std::vector<uint8_t> p12;
            if (IssueVpnCertificate(ca, clientOptions, cert) != SBOX_OK || ExportIkePkcs12(cert, p12Password, p12, 2048) != SBOX_OK) {
                std::fputs("sbox-ike: client certificate generation failed\n", stderr);
                return 1;
            }

            ok = writeFile(CFile::join(out, client + ".pem"), cert.toPem(), 0644)
                && writeFile(CFile::join(out, client + ".p12"), std::string_view(reinterpret_cast<const char*>(p12.data()), p12.size()), 0600);
            if (!ok) {
                return 1;
            }

            profile.auth = EVPA_CERT;
            profile.localId = "@" + client;
            profile.clientPkcs12 = p12;
            profile.clientPkcs12Password = p12Password;
        }

        ok = writeFile(CFile::join(out, "windows-setup.ps1"), WindowsVpnSetup(profile), 0644)
            && writeFile(CFile::join(out, "vpn.mobileconfig"), AppleMobileConfig(profile), 0600)
            && writeFile(CFile::join(out, "android.txt"), AndroidVpnSetup(profile), 0644);
        if (!ok) {
            return 1;
        }

        std::printf("\nServer configuration snippet:\n");
        std::printf("  \"serverId\": \"%s\", \"certificate\": \"%s\", \"key\": \"%s\",%s\n", name.c_str(),
                    CFile::join(out, "server.pem").c_str(), CFile::join(out, "server.key").c_str(),
                    client.empty() ? "" : (" \"ca\": \"" + CFile::join(out, "ca.pem") + "\",").c_str());
        std::printf("\nWindows (elevated PowerShell): run windows-setup.ps1, or at least:\n");
        std::printf("  Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\\LocalMachine\\Root\n");
        std::printf("  Add-VpnConnection -Name '%s VPN' -ServerAddress '%s' -TunnelType Ikev2 -AuthenticationMethod %s "
                    "-EncryptionLevel Required\n", name.c_str(), name.c_str(), client.empty() ? "Eap" : "MachineCertificate");
        std::printf("macOS/iOS: open vpn.mobileconfig (System Settings > Profiles / Settings > Profile Downloaded).\n");
        std::printf("Android 11+: see android.txt (install ca.pem as a CA certificate first).\n");
        return 0;
    }

    /* "profile" command. */
    int profileCommand(Args& args) {
        SVpnClientProfile p;
        std::string caPath;
        std::string p12Path;
        std::string format;
        while (args.more()) {
            std::string a = args.next();
            if (a == "--ca") {
                caPath = args.next();
            }
            else if (a == "--server") {
                p.server = args.next();
            }
            else if (a == "--remote-id") {
                p.remoteId = args.next();
            }
            else if (a == "--auth") {
                std::string auth = args.next();
                p.auth = auth == "psk" ? EVPA_PSK : auth == "cert" ? EVPA_CERT : EVPA_EAP;
            }
            else if (a == "--user") {
                p.user = args.next();
            }
            else if (a == "--password") {
                p.password = args.next();
            }
            else if (a == "--psk") {
                p.psk = args.next();
            }
            else if (a == "--local-id") {
                p.localId = args.next();
            }
            else if (a == "--p12") {
                p12Path = args.next();
            }
            else if (a == "--p12-password") {
                p.clientPkcs12Password = args.next();
            }
            else if (a == "--routes") {
                p.routes = splitList(args.next());
            }
            else if (a == "--name") {
                p.name = args.next();
            }
            else if (a == "--format") {
                format = args.next();
            }
            else {
                usage();
                return 2;
            }
        }

        if (p.server.empty() || format.empty()) {
            usage();
            return 2;
        }

        if (!caPath.empty() && CIkeCertificate::loadFiles(caPath, std::string(), p.ca) != SBOX_OK) {
            std::fprintf(stderr, "sbox-ike: cannot load CA %s\n", caPath.c_str());
            return 1;
        }

        if (!p12Path.empty()) {
            std::string data;
            if (CFile::readAll(p12Path, data) != SBOX_OK) {
                std::fprintf(stderr, "sbox-ike: cannot read %s\n", p12Path.c_str());
                return 1;
            }

            p.clientPkcs12.assign(data.begin(), data.end());
        }

        std::string text;
        if (format == "windows") {
            text = WindowsVpnSetup(p);
        }
        else if (format == "apple") {
            text = AppleMobileConfig(p);
        }
        else if (format == "android") {
            text = AndroidVpnSetup(p);
        }
        else {
            usage();
            return 2;
        }

        std::fwrite(text.data(), 1, text.size(), stdout);
        return 0;
    }

    /* "nthash" command. */
    int nthashCommand(Args& args) {
        std::string password = args.next();
        if (password.empty()) {
            usage();
            return 2;
        }

        uint8_t hash[16];
        if (MsChapNtPasswordHash(password, SByteSpan(hash, 16)) != SBOX_OK) {
            std::fputs("sbox-ike: password is not valid UTF-8\n", stderr);
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

    if (command == "mkcert") {
        return mkcertCommand(args);
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
