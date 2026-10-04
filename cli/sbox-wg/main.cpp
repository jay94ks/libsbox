// sbox-wg: WireGuard keys, devices (kernel or user space) and client configurations.
//
//   sbox-wg genkey | genpsk | pubkey < private
//   sbox-wg up <config> [--name IF] [--netns PATH] [--mode auto|kernel|userspace] [--uapi-dir DIR]
//   sbox-wg show [IF] [--netns PATH] [--uapi-dir DIR]
//   sbox-wg showconf IF [--netns PATH] [--uapi-dir DIR]
//   sbox-wg client-config --endpoint HOST:PORT --address CIDR (--server-config FILE | --server-key KEY)
//                         [--dns LIST] [--allowed-ips LIST] [--keepalive N] [--mtu N] [--no-psk]
//                         [--append-to FILE]
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/net/rtnl.hpp>
#include <sbox/vpn/wg/config.hpp>
#include <sbox/vpn/wg/device.hpp>
#include <sbox/vpn/wg/kernel.hpp>
#include <sbox/vpn/wg/uapi.hpp>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <map>
#include <string>
#include <sys/signalfd.h>
#include <unistd.h>
#include <vector>

using namespace sbox;
using namespace sbox::vpn;

namespace {

    /* Prints usage and returns the exit code for bad usage. */
    int usage() {
        std::fputs(
            "usage: sbox-wg <command> [options]\n"
            "  genkey                         print a new private key\n"
            "  genpsk                         print a new preshared key\n"
            "  pubkey                         read a private key on stdin, print its public key\n"
            "  up <config>                    create the interface from a wg-quick file; a user-space\n"
            "                                 device runs in the foreground until SIGINT/SIGTERM\n"
            "      [--name IF] [--netns PATH] [--mode auto|kernel|userspace] [--uapi-dir DIR]\n"
            "  show [IF] [--netns PATH]       show devices like `wg show`\n"
            "  showconf IF [--netns PATH]     print the device configuration\n"
            "  client-config --endpoint HOST:PORT --address CIDR[,CIDR]\n"
            "      (--server-config FILE | --server-key KEY) [--dns LIST] [--allowed-ips LIST]\n"
            "      [--keepalive N] [--mtu N] [--no-psk] [--append-to FILE]\n"
            "                                 print a configuration for the official WireGuard apps\n",
            stderr);
        return 2;
    }

    /* Prints an error for a negated errno. */
    int fail(const char* what, int32_t code, const std::string& detail = std::string()) {
        std::fprintf(stderr, "sbox-wg: %s: %s%s%s\n", what, std::strerror(code < 0 ? -code : code), detail.empty() ? "" : ": ",
            detail.c_str());
        return 1;
    }

    /* Parsed command line: positional arguments and --key value options. */
    struct SArgs {
        std::vector<std::string> positional;
        std::map<std::string, std::string> options;

        bool has(const std::string& k) const { return options.find(k) != options.end(); }

        std::string get(const std::string& k, const std::string& fallback = std::string()) const {
            auto it = options.find(k);
            return it == options.end() ? fallback : it->second;
        }
    };

    /* Splits argv; flags without a value are recorded as "1". */
    bool parseArgs(int argc, char** argv, int start, SArgs& out) {
        static const char* FLAGS[] = { "--no-psk" };
        for (int i = start; i < argc; ++i) {
            std::string a = argv[i];
            if (a.rfind("--", 0) != 0) {
                out.positional.push_back(a);
                continue;
            }

            bool flag = false;
            for (const char* f : FLAGS) {
                flag = flag || a == f;
            }

            if (flag) {
                out.options[a] = "1";
                continue;
            }

            if (i + 1 >= argc) {
                return false;
            }

            out.options[a] = argv[++i];
        }

        return true;
    }

    /* Reads stdin fully. */
    std::string readStdin() {
        std::string out;
        char buf[4096];
        ssize_t n;
        while ((n = ::read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
            out.append(buf, size_t(n));
        }

        return out;
    }

    /* Trims whitespace. */
    std::string trim(std::string s) {
        while (!s.empty() && std::strchr(" \t\r\n", s.back())) {
            s.pop_back();
        }

        size_t i = 0;
        while (i < s.size() && std::strchr(" \t\r\n", s[i])) {
            ++i;
        }

        return s.substr(i);
    }

    /* Splits a comma separated list. */
    std::vector<std::string> splitList(const std::string& text) {
        std::vector<std::string> out;
        size_t start = 0;
        while (start <= text.size()) {
            size_t comma = text.find(',', start);
            std::string item = trim(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
            if (!item.empty()) {
                out.push_back(item);
            }

            if (comma == std::string::npos) {
                break;
            }

            start = comma + 1;
        }

        return out;
    }

    /* Formats a byte count like `wg show`. */
    std::string bytes(uint64_t v) {
        char buf[64];
        if (v < 1024) {
            std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(v));
        }
        else if (v < (uint64_t(1) << 20)) {
            std::snprintf(buf, sizeof(buf), "%.2f KiB", double(v) / 1024.0);
        }
        else if (v < (uint64_t(1) << 30)) {
            std::snprintf(buf, sizeof(buf), "%.2f MiB", double(v) / 1048576.0);
        }
        else {
            std::snprintf(buf, sizeof(buf), "%.2f GiB", double(v) / 1073741824.0);
        }

        return buf;
    }

    /* Prints one device like `wg show`. */
    void printStatus(const SWgDeviceStatus& st) {
        std::printf("interface: %s%s\n", st.name.c_str(), st.kernel ? "" : " (user space)");
        if (st.publicKey.valid) {
            std::printf("  public key: %s\n", st.publicKey.toBase64().c_str());
        }

        if (st.privateKey.valid) {
            std::printf("  private key: (hidden)\n");
        }

        if (st.listenPort) {
            std::printf("  listening port: %u\n", unsigned(st.listenPort));
        }

        if (st.fwmark) {
            std::printf("  fwmark: 0x%x\n", st.fwmark);
        }

        time_t now = ::time(nullptr);
        for (const SWgPeerStatus& p : st.peers) {
            std::printf("\npeer: %s\n", p.publicKey.toBase64().c_str());
            if (p.hasPresharedKey) {
                std::printf("  preshared key: (hidden)\n");
            }

            if (p.endpoint.isValid()) {
                std::printf("  endpoint: %s\n", p.endpoint.toString().c_str());
            }

            std::string ips;
            for (const net::SIpPrefix& ip : p.allowedIps) {
                ips += (ips.empty() ? "" : ", ") + ip.toString();
            }

            std::printf("  allowed ips: %s\n", ips.empty() ? "(none)" : ips.c_str());
            if (p.lastHandshakeSec > 0) {
                std::printf("  latest handshake: %lld seconds ago\n", static_cast<long long>(now - p.lastHandshakeSec));
            }

            if (p.rxBytes || p.txBytes) {
                std::printf("  transfer: %s received, %s sent\n", bytes(p.rxBytes).c_str(), bytes(p.txBytes).c_str());
            }

            if (p.persistentKeepalive) {
                std::printf("  persistent keepalive: every %u seconds\n", unsigned(p.persistentKeepalive));
            }
        }
    }

    /* Reads one device through the kernel family or its UAPI socket. */
    TTask<int32_t> readDevice(std::string name, std::string netns, std::string uapiDir, SWgDeviceStatus& out) {
        CWgKernelClient kc;
        if (co_await kc.open(netns) == SBOX_OK && co_await kc.getDevice(name, out) == SBOX_OK) {
            out.name = name;
            co_return SBOX_OK;
        }

        int32_t r = co_await WgUapiGet(WgUapiSocketPath(name, uapiDir), out);
        out.name = name;
        out.kernel = false;
        if (r == SBOX_OK && !out.publicKey.valid && out.privateKey.valid) {
            DeriveWgPublicKey(out.privateKey, out.publicKey);
        }

        co_return r;
    }

    /* Lists the device names: kernel links of kind wireguard plus UAPI sockets. */
    TTask<std::vector<std::string>> listDevices(std::string netns, std::string uapiDir) {
        std::vector<std::string> names;
        net::CRtnl rt;
        if (rt.open(netns) == SBOX_OK) {
            std::vector<net::SLinkInfo> links;
            if (co_await rt.listLinks(links) == SBOX_OK) {
                for (const net::SLinkInfo& l : links) {
                    if (l.kind == "wireguard") {
                        names.push_back(l.name);
                    }
                }
            }
        }

        DIR* d = ::opendir(uapiDir.c_str());
        if (d) {
            while (dirent* e = ::readdir(d)) {
                std::string n = e->d_name;
                if (n.size() > 5 && n.compare(n.size() - 5, 5, ".sock") == 0) {
                    names.push_back(n.substr(0, n.size() - 5));
                }
            }

            ::closedir(d);
        }

        co_return names;
    }

    /* `show`. */
    TTask<int> cmdShow(SArgs args) {
        std::string netns = args.get("--netns");
        std::string uapiDir = args.get("--uapi-dir", WG_UAPI_DIR);
        std::vector<std::string> names;
        if (!args.positional.empty()) {
            names.push_back(args.positional[0]);
        }
        else {
            names = co_await listDevices(netns, uapiDir);
        }

        int rc = 0;
        for (size_t i = 0; i < names.size(); ++i) {
            SWgDeviceStatus st;
            int32_t r = co_await readDevice(names[i], netns, uapiDir, st);
            if (r != SBOX_OK) {
                rc = fail(names[i].c_str(), r);
                continue;
            }

            if (i) {
                std::printf("\n");
            }

            printStatus(st);
        }

        co_return rc;
    }

    /* `showconf`. */
    TTask<int> cmdShowconf(SArgs args) {
        if (args.positional.empty()) {
            co_return usage();
        }

        SWgDeviceStatus st;
        int32_t r = co_await readDevice(args.positional[0], args.get("--netns"), args.get("--uapi-dir", WG_UAPI_DIR), st);
        if (r != SBOX_OK) {
            co_return fail(args.positional[0].c_str(), r);
        }

        SWgConfig c;
        c.privateKey = st.privateKey;
        c.listenPort = st.listenPort;
        c.fwmark = st.fwmark;
        for (const SWgPeerStatus& p : st.peers) {
            SWgPeerConfig pc;
            pc.publicKey = p.publicKey;
            pc.presharedKey = p.presharedKey;
            pc.endpoint = p.endpoint;
            pc.allowedIps = p.allowedIps;
            pc.persistentKeepalive = p.persistentKeepalive;
            c.peers.push_back(pc);
        }

        std::fputs(WriteWgConfig(c, false).c_str(), stdout);
        co_return 0;
    }

    /* Waits for SIGINT/SIGTERM on a signalfd and closes the device. */
    TTask<void> stopOnSignal(int fd, CWgDevice* device) {
        int32_t r = co_await CEventLoop::current()->waitFd(fd, EFDE_READ);
        if (r > 0) {
            signalfd_siginfo info;
            ssize_t n = ::read(fd, &info, sizeof(info));
            (void)n;
            std::fprintf(stderr, "sbox-wg: signal %u, shutting down\n", info.ssi_signo);
        }

        co_await device->close();
    }

    /* `up`. */
    TTask<int> cmdUp(SArgs args) {
        if (args.positional.empty()) {
            co_return usage();
        }

        std::string path = args.positional[0];
        std::string text;
        int32_t r = CFile::readAll(path, text);
        if (r != SBOX_OK) {
            co_return fail(path.c_str(), r);
        }

        SWgConfig cfg;
        std::string err;
        r = ParseWgConfig(text, cfg, &err);
        if (r != SBOX_OK) {
            co_return fail(path.c_str(), r, err);
        }

        r = co_await ResolveWgConfigEndpoints(cfg);
        if (r != SBOX_OK) {
            co_return fail("resolving endpoints", r);
        }

        std::string name = args.get("--name");
        if (name.empty()) {
            size_t slash = path.rfind('/');
            name = path.substr(slash == std::string::npos ? 0 : slash + 1);
            if (name.size() > 5 && name.compare(name.size() - 5, 5, ".conf") == 0) {
                name.resize(name.size() - 5);
            }
        }

        SWgDeviceOptions o;
        o.name = name;
        o.netnsPath = args.get("--netns");
        o.addresses = cfg.addresses;
        o.mtu = cfg.mtu ? cfg.mtu : WG_DEFAULT_MTU;
        o.routeAllowedIps = cfg.table != "off";
        o.uapi = true;
        o.uapiDir = args.get("--uapi-dir", WG_UAPI_DIR);
        std::string mode = args.get("--mode", "auto");
        o.mode = mode == "kernel" ? EWGM_KERNEL : (mode == "userspace" ? EWGM_USERSPACE : EWGM_AUTO);

        // --> Signals become readable events, before anything that may wait.
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigprocmask(SIG_BLOCK, &mask, nullptr);
        CFd sfd(::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));

        CWgDevice dev;
        r = co_await dev.create(o);
        if (r != SBOX_OK) {
            co_return fail(name.c_str(), r);
        }

        r = co_await dev.setConfig(cfg);
        if (r != SBOX_OK) {
            co_await dev.close();
            co_return fail("configuring", r);
        }

        if (!cfg.dns.empty()) {
            std::fprintf(stderr, "sbox-wg: note: DNS is not configured by sbox-wg (%zu entries ignored)\n", cfg.dns.size());
        }

        if (dev.isKernel()) {
            std::fprintf(stderr, "sbox-wg: %s is up (kernel module)\n", name.c_str());
            co_return 0;
        }

        std::fprintf(stderr, "sbox-wg: %s is up (user space, port %u, UAPI %s); Ctrl-C to stop\n", name.c_str(),
            unsigned(dev.listenPort()), WgUapiSocketPath(name, o.uapiDir).c_str());
        CEventLoop::current()->spawn(stopOnSignal(sfd.get(), &dev));
        co_await dev.wait();
        CEventLoop::current()->cancelFd(sfd.get());
        co_return 0;
    }

    /* `client-config`. */
    int cmdClientConfig(const SArgs& args) {
        SWgClientRequest req;
        SWgConfig server;
        bool haveServer = false;

        std::string serverPath = args.get("--server-config");
        if (!serverPath.empty()) {
            std::string text, err;
            int32_t r = CFile::readAll(serverPath, text);
            if (r != SBOX_OK) {
                return fail(serverPath.c_str(), r);
            }

            r = ParseWgConfig(text, server, &err);
            if (r != SBOX_OK) {
                return fail(serverPath.c_str(), r, err);
            }

            if (DeriveWgPublicKey(server.privateKey, req.serverPublicKey) != SBOX_OK) {
                return fail(serverPath.c_str(), -EINVAL, "no PrivateKey");
            }

            haveServer = true;
        }
        else if (SWgKey::fromBase64(args.get("--server-key"), req.serverPublicKey) != SBOX_OK) {
            return usage();
        }

        req.serverEndpoint = args.get("--endpoint");
        if (req.serverEndpoint.find(':') == std::string::npos && haveServer && server.listenPort > 0 && !req.serverEndpoint.empty()) {
            // --> A bare host name gets the server's listen port.
            req.serverEndpoint += ":" + std::to_string(server.listenPort);
        }

        for (const std::string& a : splitList(args.get("--address"))) {
            net::SIpPrefix p;
            if (net::SIpPrefix::parse(a, p) != SBOX_OK) {
                return fail("--address", -EINVAL, a);
            }

            req.clientAddresses.push_back(p);
        }

        for (const std::string& a : splitList(args.get("--allowed-ips"))) {
            net::SIpPrefix p;
            if (net::SIpPrefix::parse(a, p) != SBOX_OK) {
                return fail("--allowed-ips", -EINVAL, a);
            }

            req.allowedIps.push_back(p);
        }

        req.dns = splitList(args.get("--dns"));
        req.presharedKey = !args.has("--no-psk");
        req.persistentKeepalive = uint16_t(std::atoi(args.get("--keepalive", "25").c_str()));
        req.mtu = uint32_t(std::atoi(args.get("--mtu", "0").c_str()));

        SWgClientBundle bundle;
        int32_t r = GenerateWgClientConfig(req, bundle);
        if (r != SBOX_OK) {
            return fail("client-config", r, "--endpoint and --address are required");
        }

        std::fputs(bundle.text.c_str(), stdout);

        std::string append = args.get("--append-to");
        if (!append.empty()) {
            std::string text;
            CFile::readAll(append, text);
            SWgConfig only;
            only.peers.push_back(bundle.serverPeer);
            std::string block = WriteWgConfig(only, false);
            // --> Drop the empty [Interface] section WriteWgConfig starts with.
            block = block.substr(block.find("[Peer]"));
            if (!text.empty() && text.back() != '\n') {
                text += "\n";
            }

            text += "\n" + block;
            r = CFile::writeAtomic(append, text, 0600);
            if (r != SBOX_OK) {
                return fail(append.c_str(), r);
            }
        }
        else {
            std::fprintf(stderr, "# add to the server:\n[Peer]\nPublicKey = %s\n", bundle.serverPeer.publicKey.toBase64().c_str());
            if (bundle.serverPeer.presharedKey.valid) {
                std::fprintf(stderr, "PresharedKey = %s\n", bundle.serverPeer.presharedKey.toBase64().c_str());
            }

            std::string ips;
            for (const net::SIpPrefix& p : bundle.serverPeer.allowedIps) {
                ips += (ips.empty() ? "" : ", ") + p.toString();
            }

            std::fprintf(stderr, "AllowedIPs = %s\n", ips.c_str());
        }

        return 0;
    }

}

int main(int argc, char** argv) {
    if (argc < 2) {
        return usage();
    }

    std::string cmd = argv[1];
    SArgs args;
    if (!parseArgs(argc, argv, 2, args)) {
        return usage();
    }

    if (cmd == "genkey" || cmd == "genpsk") {
        SWgKey k;
        int32_t r = cmd == "genkey" ? GenerateWgPrivateKey(k) : GenerateWgPresharedKey(k);
        if (r != SBOX_OK) {
            return fail(cmd.c_str(), r);
        }

        std::printf("%s\n", k.toBase64().c_str());
        return 0;
    }

    if (cmd == "pubkey") {
        SWgKey priv, pub;
        if (SWgKey::fromBase64(trim(readStdin()), priv) != SBOX_OK) {
            std::fputs("sbox-wg: pubkey: a base64 private key is expected on stdin\n", stderr);
            return 1;
        }

        int32_t r = DeriveWgPublicKey(priv, pub);
        if (r != SBOX_OK) {
            return fail("pubkey", r);
        }

        std::printf("%s\n", pub.toBase64().c_str());
        return 0;
    }

    if (cmd == "client-config") {
        return cmdClientConfig(args);
    }

    CEventLoop loop;
    if (cmd == "show") {
        return loop.run(cmdShow(args));
    }

    if (cmd == "showconf") {
        return loop.run(cmdShowconf(args));
    }

    if (cmd == "up") {
        return loop.run(cmdUp(args));
    }

    return usage();
}
