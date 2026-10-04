#include <sbox/vpn/wg/uapi.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <cerrno>
#include <cstdlib>

namespace sbox {
namespace vpn {

    namespace {

        /* Parses an unsigned decimal. */
        bool number(std::string_view text, uint64_t max, uint64_t& out) {
            if (text.empty() || text.size() > 20) {
                return false;
            }

            uint64_t v = 0;
            for (char c : text) {
                if (c < '0' || c > '9') {
                    return false;
                }

                uint64_t next = v * 10 + uint64_t(c - '0');
                if (next < v) {
                    return false;
                }

                v = next;
            }

            if (v > max) {
                return false;
            }

            out = v;
            return true;
        }

        /* Splits text into key=value lines, calling `fn` until it fails. */
        template<typename F>
        int32_t forEachLine(std::string_view text, F&& fn) {
            while (!text.empty()) {
                size_t nl = text.find('\n');
                std::string_view line = text.substr(0, nl);
                text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
                if (line.empty()) {
                    continue;
                }

                size_t eq = line.find('=');
                if (eq == std::string_view::npos) {
                    return -EINVAL;
                }

                int32_t r = fn(line.substr(0, eq), line.substr(eq + 1));
                if (r != SBOX_OK) {
                    return r;
                }
            }

            return SBOX_OK;
        }

        /* Exchanges one request on a UAPI socket and returns the answer text. */
        TTask<int32_t> exchange(std::string path, std::string request, std::string& answer, int64_t timeoutMs) {
            SEndpoint ep;
            int32_t r = SEndpoint::fromUnix(path, ep);
            if (r != SBOX_OK) {
                co_return r;
            }

            CSocket sock;
            r = co_await sock.connect(ep, timeoutMs);
            if (r != SBOX_OK) {
                co_return r;
            }

            SIoResult w = co_await sock.send(BytesOf(request), timeoutMs);
            if (!w.ok()) {
                co_return w.error;
            }

            answer.clear();
            uint8_t buf[4096];
            for (;;) {
                SIoResult got = co_await sock.recv(SByteSpan(buf, sizeof(buf)), timeoutMs);
                if (!got.ok()) {
                    co_return got.error;
                }

                if (got.bytes == 0) {
                    break;
                }

                answer.append(reinterpret_cast<const char*>(buf), got.bytes);
                // --> The answer ends with the errno line and an empty line.
                size_t at = answer.rfind("errno=");
                if (at != std::string::npos && answer.size() >= 2 && answer.compare(answer.size() - 2, 2, "\n\n") == 0
                    && (at == 0 || answer[at - 1] == '\n'))
                {
                    break;
                }
            }

            co_return SBOX_OK;
        }

    }

    /* Socket path of an interface. */
    std::string WgUapiSocketPath(const std::string& name, const std::string& dir) {
        return CFile::join(dir, name + ".sock");
    }

    /* Formats a get answer. */
    std::string FormatWgUapiGet(const SWgDeviceStatus& status) {
        std::string out;
        if (status.privateKey.valid) {
            out += "private_key=" + status.privateKey.toHex() + "\n";
        }

        out += "listen_port=" + std::to_string(status.listenPort) + "\n";
        if (status.fwmark) {
            out += "fwmark=" + std::to_string(status.fwmark) + "\n";
        }

        for (const SWgPeerStatus& p : status.peers) {
            out += "public_key=" + p.publicKey.toHex() + "\n";
            out += "preshared_key=" + (p.presharedKey.valid ? p.presharedKey.toHex() : std::string(64, '0')) + "\n";
            out += "protocol_version=" + std::to_string(p.protocolVersion) + "\n";
            if (p.endpoint.isValid()) {
                out += "endpoint=" + p.endpoint.toString() + "\n";
            }

            out += "last_handshake_time_sec=" + std::to_string(p.lastHandshakeSec) + "\n";
            out += "last_handshake_time_nsec=" + std::to_string(p.lastHandshakeNsec) + "\n";
            out += "tx_bytes=" + std::to_string(p.txBytes) + "\n";
            out += "rx_bytes=" + std::to_string(p.rxBytes) + "\n";
            out += "persistent_keepalive_interval=" + std::to_string(p.persistentKeepalive) + "\n";
            for (const net::SIpPrefix& ip : p.allowedIps) {
                out += "allowed_ip=" + ip.toString() + "\n";
            }
        }

        return out;
    }

    /* Parses a get answer. */
    int32_t ParseWgUapiGet(std::string_view text, SWgDeviceStatus& out) {
        out = SWgDeviceStatus();
        int32_t answerErrno = -1;
        SWgPeerStatus* peer = nullptr;

        int32_t r = forEachLine(text, [&](std::string_view key, std::string_view value) -> int32_t {
            uint64_t n = 0;
            if (key == "errno") {
                if (!number(value, 4095, n)) {
                    return -EBADMSG;
                }

                answerErrno = int32_t(n);
                return SBOX_OK;
            }

            if (key == "private_key") {
                return SWgKey::fromHex(value, out.privateKey) == SBOX_OK ? SBOX_OK : -EBADMSG;
            }

            if (key == "listen_port") {
                if (!number(value, 65535, n)) {
                    return -EBADMSG;
                }

                out.listenPort = uint16_t(n);
                return SBOX_OK;
            }

            if (key == "fwmark") {
                if (!number(value, 0xffffffffull, n)) {
                    return -EBADMSG;
                }

                out.fwmark = uint32_t(n);
                return SBOX_OK;
            }

            if (key == "public_key") {
                out.peers.emplace_back();
                peer = &out.peers.back();
                return SWgKey::fromHex(value, peer->publicKey) == SBOX_OK ? SBOX_OK : -EBADMSG;
            }

            if (!peer) {
                return SBOX_OK;     // --> Unknown device-level keys are ignored.
            }

            if (key == "preshared_key") {
                SWgKey k;
                if (SWgKey::fromHex(value, k) != SBOX_OK) {
                    return -EBADMSG;
                }

                peer->hasPresharedKey = !k.isZero();
                peer->presharedKey = peer->hasPresharedKey ? k : SWgKey();
            }
            else if (key == "endpoint") {
                if (SEndpoint::parse(value, peer->endpoint) != SBOX_OK) {
                    return -EBADMSG;
                }
            }
            else if (key == "last_handshake_time_sec") {
                if (!number(value, ~uint64_t(0) >> 1, n)) {
                    return -EBADMSG;
                }

                peer->lastHandshakeSec = int64_t(n);
            }
            else if (key == "last_handshake_time_nsec") {
                if (!number(value, 999999999, n)) {
                    return -EBADMSG;
                }

                peer->lastHandshakeNsec = int64_t(n);
            }
            else if (key == "tx_bytes") {
                if (!number(value, ~uint64_t(0), n)) {
                    return -EBADMSG;
                }

                peer->txBytes = n;
            }
            else if (key == "rx_bytes") {
                if (!number(value, ~uint64_t(0), n)) {
                    return -EBADMSG;
                }

                peer->rxBytes = n;
            }
            else if (key == "persistent_keepalive_interval") {
                if (!number(value, 65535, n)) {
                    return -EBADMSG;
                }

                peer->persistentKeepalive = uint16_t(n);
            }
            else if (key == "allowed_ip") {
                net::SIpPrefix p;
                if (net::SIpPrefix::parse(value, p) != SBOX_OK) {
                    return -EBADMSG;
                }

                peer->allowedIps.push_back(p);
            }
            else if (key == "protocol_version") {
                if (!number(value, 0xffffffffull, n)) {
                    return -EBADMSG;
                }

                peer->protocolVersion = uint32_t(n);
            }

            return SBOX_OK;
        });

        if (r != SBOX_OK) {
            return r == -EINVAL ? -EBADMSG : r;
        }

        if (answerErrno < 0) {
            return -EBADMSG;
        }

        return answerErrno == 0 ? SBOX_OK : -answerErrno;
    }

    /* Formats a set request. */
    std::string FormatWgUapiSet(const SWgDeviceConfig& config) {
        std::string out;
        if (config.privateKey.valid) {
            out += "private_key=" + config.privateKey.toHex() + "\n";
        }

        if (config.listenPort >= 0) {
            out += "listen_port=" + std::to_string(config.listenPort) + "\n";
        }

        if (config.fwmark >= 0) {
            out += "fwmark=" + std::to_string(config.fwmark) + "\n";
        }

        if (config.replacePeers) {
            out += "replace_peers=true\n";
        }

        for (const SWgPeerConfig& p : config.peers) {
            out += "public_key=" + p.publicKey.toHex() + "\n";
            if (p.remove) {
                out += "remove=true\n";
                continue;
            }

            if (p.updateOnly) {
                out += "update_only=true\n";
            }

            if (p.presharedKey.valid) {
                out += "preshared_key=" + p.presharedKey.toHex() + "\n";
            }

            if (p.endpoint.isValid()) {
                out += "endpoint=" + p.endpoint.toString() + "\n";
            }

            if (p.persistentKeepalive >= 0) {
                out += "persistent_keepalive_interval=" + std::to_string(p.persistentKeepalive) + "\n";
            }

            if (p.replaceAllowedIps) {
                out += "replace_allowed_ips=true\n";
            }

            for (const net::SIpPrefix& ip : p.allowedIps) {
                out += "allowed_ip=" + ip.toString() + "\n";
            }
        }

        return out;
    }

    /* Parses a set request. */
    int32_t ParseWgUapiSet(std::string_view text, SWgDeviceConfig& out) {
        out = SWgDeviceConfig();
        SWgPeerConfig* peer = nullptr;

        return forEachLine(text, [&](std::string_view key, std::string_view value) -> int32_t {
            uint64_t n = 0;
            if (key == "private_key") {
                return SWgKey::fromHex(value, out.privateKey);
            }

            if (key == "listen_port") {
                if (!number(value, 65535, n)) {
                    return -EINVAL;
                }

                out.listenPort = int32_t(n);
                return SBOX_OK;
            }

            if (key == "fwmark") {
                if (!number(value, 0xffffffffull, n)) {
                    return -EINVAL;
                }

                out.fwmark = int64_t(n);
                return SBOX_OK;
            }

            if (key == "replace_peers") {
                out.replacePeers = value == "true";
                return SBOX_OK;
            }

            if (key == "public_key") {
                out.peers.emplace_back();
                peer = &out.peers.back();
                // --> In the UAPI, allowed IPs are added unless replace_allowed_ips is given.
                peer->replaceAllowedIps = false;
                return SWgKey::fromHex(value, peer->publicKey);
            }

            if (!peer) {
                return -EINVAL;
            }

            if (key == "remove") {
                peer->remove = value == "true";
            }
            else if (key == "update_only") {
                peer->updateOnly = value == "true";
            }
            else if (key == "preshared_key") {
                return SWgKey::fromHex(value, peer->presharedKey);
            }
            else if (key == "endpoint") {
                return SEndpoint::parse(value, peer->endpoint) == SBOX_OK ? SBOX_OK : -EINVAL;
            }
            else if (key == "persistent_keepalive_interval") {
                if (!number(value, 65535, n)) {
                    return -EINVAL;
                }

                peer->persistentKeepalive = int32_t(n);
            }
            else if (key == "replace_allowed_ips") {
                peer->replaceAllowedIps = value == "true";
            }
            else if (key == "allowed_ip") {
                net::SIpPrefix p;
                if (net::SIpPrefix::parse(value, p) != SBOX_OK) {
                    return -EINVAL;
                }

                peer->allowedIps.push_back(p);
            }
            else if (key == "protocol_version") {
                if (value != "1") {
                    return -EPROTONOSUPPORT;
                }
            }
            else {
                return -EINVAL;
            }

            return SBOX_OK;
        });
    }

    /* UAPI get over a socket. */
    TTask<int32_t> WgUapiGet(std::string socketPath, SWgDeviceStatus& out, int64_t timeoutMs) {
        std::string answer;
        int32_t r = co_await exchange(std::move(socketPath), "get=1\n\n", answer, timeoutMs);
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return ParseWgUapiGet(answer, out);
    }

    /* UAPI set over a socket. */
    TTask<int32_t> WgUapiSet(std::string socketPath, SWgDeviceConfig config, int64_t timeoutMs) {
        std::string answer;
        int32_t r = co_await exchange(std::move(socketPath), "set=1\n" + FormatWgUapiSet(config) + "\n", answer, timeoutMs);
        if (r != SBOX_OK) {
            co_return r;
        }

        SWgDeviceStatus ignored;
        co_return ParseWgUapiGet(answer, ignored);
    }

}
}
