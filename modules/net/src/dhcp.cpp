#include <sbox/net/dhcp.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/core/eventloop.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sbox {
namespace net {

    namespace {

        constexpr uint32_t MAGIC_COOKIE = 0x63825363u;
        constexpr size_t BOOTP_FIXED = 236;
        constexpr uint16_t CLIENT_PORT = 68;
        constexpr uint16_t SERVER_PORT = 67;

        enum : uint8_t {
            OPT_PAD = 0,
            OPT_SUBNET_MASK = 1,
            OPT_ROUTER = 3,
            OPT_DNS = 6,
            OPT_HOSTNAME = 12,
            OPT_DOMAIN = 15,
            OPT_MTU = 26,
            OPT_REQUESTED_IP = 50,
            OPT_LEASE_TIME = 51,
            OPT_MESSAGE_TYPE = 53,
            OPT_SERVER_ID = 54,
            OPT_PARAMS = 55,
            OPT_MAX_SIZE = 57,
            OPT_RENEW_TIME = 58,
            OPT_REBIND_TIME = 59,
            OPT_CLIENT_ID = 61,
            OPT_END = 255,
        };

        /* Internet checksum over a buffer, continuing from `sum`. */
        uint32_t checksumAdd(uint32_t sum, const uint8_t* data, size_t length) noexcept {
            for (size_t i = 0; i + 1 < length; i += 2) {
                sum += uint32_t(data[i] << 8 | data[i + 1]);
            }

            if (length & 1) {
                sum += uint32_t(data[length - 1] << 8);
            }

            return sum;
        }

        /* Folds a checksum. */
        uint16_t checksumFinish(uint32_t sum) noexcept {
            while (sum >> 16) {
                sum = (sum & 0xffff) + (sum >> 16);
            }

            return uint16_t(~sum & 0xffff);
        }

        /* Writes a big-endian u16. */
        void put16(uint8_t* p, uint16_t v) noexcept {
            p[0] = uint8_t(v >> 8);
            p[1] = uint8_t(v);
        }

        /* Writes a big-endian u32. */
        void put32(uint8_t* p, uint32_t v) noexcept {
            p[0] = uint8_t(v >> 24);
            p[1] = uint8_t(v >> 16);
            p[2] = uint8_t(v >> 8);
            p[3] = uint8_t(v);
        }

        /* Reads a big-endian u16. */
        uint16_t get16(const uint8_t* p) noexcept {
            return uint16_t(p[0] << 8 | p[1]);
        }

        /* Reads a big-endian u32. */
        uint32_t get32(const uint8_t* p) noexcept {
            return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]);
        }

        /* Returns the IPv4 address at `p`. */
        SIpAddress v4At(const uint8_t* p) noexcept {
            SIpAddress a;
            SIpAddress::fromBytes(p, 4, a);
            return a;
        }

        /* Copies an IPv4 address (zeros when unset). */
        void putAddress(uint8_t* p, const SIpAddress& a) noexcept {
            if (a.isV4()) {
                std::memcpy(p, a.bytes, 4);
            }
            else {
                std::memset(p, 0, 4);
            }
        }

        /* Returns the prefix length of a netmask. */
        uint8_t maskLength(const SIpAddress& mask) noexcept {
            uint32_t m = mask.v4();
            uint8_t n = 0;
            while (n < 32 && (m & (0x80000000u >> n))) {
                ++n;
            }

            return n;
        }

        /* Fills a lease from an ACK. */
        void leaseFromAck(const SDhcpMessage& ack, const SMacAddress& serverMac, SDhcpLease& lease) {
            lease.address = ack.yiaddr;
            SIpAddress mask = ack.address(OPT_SUBNET_MASK);
            lease.prefixLength = mask.isValid() ? maskLength(mask) : 24;
            lease.router = ack.address(OPT_ROUTER);
            lease.dns = ack.addresses(OPT_DNS);
            lease.domain = ack.text(OPT_DOMAIN);
            lease.server = ack.address(OPT_SERVER_ID);
            if (!lease.server.isValid()) {
                lease.server = ack.siaddr;
            }

            if (serverMac.isValid()) {
                lease.serverMac = serverMac;
            }

            lease.leaseTime = ack.u32(OPT_LEASE_TIME, 3600);
            lease.renewTime = ack.u32(OPT_RENEW_TIME, lease.leaseTime / 2);
            lease.rebindTime = ack.u32(OPT_REBIND_TIME, uint32_t(uint64_t(lease.leaseTime) * 7 / 8));
            lease.mtu = 0;

            auto it = ack.options.find(OPT_MTU);
            if (it != ack.options.end() && it->second.size() >= 2) {
                lease.mtu = get16(it->second.data());
            }

            lease.acquiredAt = int64_t(::time(nullptr));
        }

    }

    /* Returns the message type. */
    EDhcpType SDhcpMessage::type() const noexcept {
        auto it = options.find(OPT_MESSAGE_TYPE);
        if (it == options.end() || it->second.empty() || it->second[0] > EDHCP_INFORM) {
            return EDHCP_INVALID;
        }

        return EDhcpType(it->second[0]);
    }

    /* Sets the message type. */
    void SDhcpMessage::type(EDhcpType value) {
        uint8_t v = value;
        setOption(OPT_MESSAGE_TYPE, &v, 1);
    }

    /* Sets an option. */
    void SDhcpMessage::setOption(uint8_t code, const void* data, size_t length) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        options[code] = std::vector<uint8_t>(p, p + length);
    }

    /* Sets an address option. */
    void SDhcpMessage::setAddress(uint8_t code, const SIpAddress& address) {
        if (address.isV4()) {
            setOption(code, address.bytes, 4);
        }
    }

    /* Sets a u32 option. */
    void SDhcpMessage::setU32(uint8_t code, uint32_t value) {
        uint8_t b[4];
        put32(b, value);
        setOption(code, b, 4);
    }

    /* Returns an address option. */
    SIpAddress SDhcpMessage::address(uint8_t code) const noexcept {
        auto it = options.find(code);
        if (it == options.end() || it->second.size() < 4) {
            return SIpAddress();
        }

        return v4At(it->second.data());
    }

    /* Returns an address list option. */
    std::vector<SIpAddress> SDhcpMessage::addresses(uint8_t code) const {
        std::vector<SIpAddress> out;
        auto it = options.find(code);
        if (it == options.end()) {
            return out;
        }

        for (size_t i = 0; i + 4 <= it->second.size(); i += 4) {
            out.push_back(v4At(it->second.data() + i));
        }

        return out;
    }

    /* Returns a u32 option. */
    uint32_t SDhcpMessage::u32(uint8_t code, uint32_t fallback) const noexcept {
        auto it = options.find(code);
        if (it == options.end() || it->second.size() < 4) {
            return fallback;
        }

        return get32(it->second.data());
    }

    /* Returns a string option. */
    std::string SDhcpMessage::text(uint8_t code) const {
        auto it = options.find(code);
        if (it == options.end()) {
            return std::string();
        }

        std::string s(it->second.begin(), it->second.end());
        while (!s.empty() && s.back() == 0) {
            s.pop_back();
        }

        return s;
    }

    /* Encodes the message. */
    std::vector<uint8_t> SDhcpMessage::encode() const {
        std::vector<uint8_t> out(BOOTP_FIXED + 4, 0);
        out[0] = op;
        out[1] = 1;         // --> htype Ethernet.
        out[2] = 6;         // --> hlen.
        put32(&out[4], xid);
        put16(&out[8], secs);
        put16(&out[10], flags);
        putAddress(&out[12], ciaddr);
        putAddress(&out[16], yiaddr);
        putAddress(&out[20], siaddr);
        putAddress(&out[24], giaddr);
        if (chaddr.isValid()) {
            std::memcpy(&out[28], chaddr.bytes, 6);
        }

        put32(&out[BOOTP_FIXED], MAGIC_COOKIE);

        // --> Message type first, as several servers expect.
        auto emit = [&](uint8_t code, const std::vector<uint8_t>& value) {
            size_t at = 0;
            do {
                size_t chunk = value.size() - at > 255 ? 255 : value.size() - at;
                out.push_back(code);
                out.push_back(uint8_t(chunk));
                out.insert(out.end(), value.begin() + ptrdiff_t(at), value.begin() + ptrdiff_t(at + chunk));
                at += chunk;
            } while (at < value.size());
        };

        auto type = options.find(OPT_MESSAGE_TYPE);
        if (type != options.end()) {
            emit(OPT_MESSAGE_TYPE, type->second);
        }

        for (const auto& [code, value] : options) {
            if (code != OPT_MESSAGE_TYPE && code != OPT_PAD && code != OPT_END) {
                emit(code, value);
            }
        }

        out.push_back(OPT_END);
        if (out.size() < 300) {
            out.resize(300, 0);
        }

        return out;
    }

    /* Decodes a message. */
    int32_t SDhcpMessage::decode(const uint8_t* data, size_t length, SDhcpMessage& out) {
        if (length < BOOTP_FIXED + 4 || get32(data + BOOTP_FIXED) != MAGIC_COOKIE) {
            return -EBADMSG;
        }

        SDhcpMessage m;
        m.op = data[0];
        m.xid = get32(data + 4);
        m.secs = get16(data + 8);
        m.flags = get16(data + 10);
        m.ciaddr = v4At(data + 12);
        m.yiaddr = v4At(data + 16);
        m.siaddr = v4At(data + 20);
        m.giaddr = v4At(data + 24);
        if (data[1] == 1 && data[2] == 6) {
            m.chaddr = SMacAddress::fromBytes(data + 28);
        }

        size_t at = BOOTP_FIXED + 4;
        while (at < length) {
            uint8_t code = data[at++];
            if (code == OPT_PAD) {
                continue;
            }

            if (code == OPT_END) {
                break;
            }

            if (at >= length) {
                return -EBADMSG;
            }

            size_t len = data[at++];
            if (at + len > length) {
                return -EBADMSG;
            }

            // --> RFC 3396: repeated options concatenate.
            std::vector<uint8_t>& v = m.options[code];
            v.insert(v.end(), data + at, data + at + len);
            at += len;
        }

        out = std::move(m);
        return SBOX_OK;
    }

    /* Serializes a lease. */
    CJson SDhcpLease::toJson() const {
        CJson j = CJson::object();
        j.set("address", address.toString());
        j.set("prefixLength", int32_t(prefixLength));
        j.set("router", router.isValid() ? CJson(router.toString()) : CJson());
        CJson d = CJson::array();
        for (const SIpAddress& a : dns) {
            d.push(a.toString());
        }

        j.set("dns", std::move(d));
        j.set("domain", domain);
        j.set("server", server.isValid() ? CJson(server.toString()) : CJson());
        j.set("serverMac", serverMac.isValid() ? CJson(serverMac.toString()) : CJson());
        j.set("leaseTime", leaseTime);
        j.set("renewTime", renewTime);
        j.set("rebindTime", rebindTime);
        j.set("mtu", mtu);
        j.set("acquiredAt", acquiredAt);
        return j;
    }

    /* Parses a lease. */
    int32_t SDhcpLease::fromJson(const CJson& json, SDhcpLease& out) {
        SDhcpLease l;
        if (SIpAddress::parse(json.get("address").asString(), l.address) != SBOX_OK) {
            return -EINVAL;
        }

        l.prefixLength = uint8_t(json.get("prefixLength").asInt(24));
        SIpAddress::parse(json.get("router").asString(), l.router);
        const CJson& d = json.get("dns");
        for (size_t i = 0; i < d.size(); ++i) {
            SIpAddress a;
            if (SIpAddress::parse(d.at(i).asString(), a) == SBOX_OK) {
                l.dns.push_back(a);
            }
        }

        l.domain = json.get("domain").asString();
        SIpAddress::parse(json.get("server").asString(), l.server);
        SMacAddress::parse(json.get("serverMac").asString(), l.serverMac);
        l.leaseTime = uint32_t(json.get("leaseTime").asInt());
        l.renewTime = uint32_t(json.get("renewTime").asInt());
        l.rebindTime = uint32_t(json.get("rebindTime").asInt());
        l.mtu = uint32_t(json.get("mtu").asInt());
        l.acquiredAt = json.get("acquiredAt").asInt();
        out = std::move(l);
        return SBOX_OK;
    }

    /* Constructs a closed client. */
    CDhcpClient::CDhcpClient() noexcept : _ifindex(0) {}

    /* Opens the packet socket on an interface. */
    int32_t CDhcpClient::open(const std::string& ifname, const std::string& netnsPath, SMacAddress mac) noexcept {
        close();
        if (ifname.empty() || ifname.size() >= IFNAMSIZ) {
            return -EINVAL;
        }

        CFd fd;
        ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::memcpy(ifr.ifr_name, ifname.data(), ifname.size());

        {
            CNetnsScope scope(netnsPath);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            fd.reset(::socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_IP)));
            if (!fd.isValid()) {
                return -errno;
            }
        }

        // --> Interface ioctls resolve names in the socket's namespace.
        if (::ioctl(fd.get(), SIOCGIFINDEX, &ifr) < 0) {
            return -errno;
        }

        int32_t index = ifr.ifr_ifindex;

        if (!mac.isValid()) {
            if (::ioctl(fd.get(), SIOCGIFHWADDR, &ifr) < 0) {
                return -errno;
            }

            mac = SMacAddress::fromBytes(reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data));
        }

        sockaddr_ll sll;
        std::memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex = index;
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
            return -errno;
        }

        _fd = std::move(fd);
        _ifindex = index;
        _mac = mac;
        return SBOX_OK;
    }

    /* Closes the socket. */
    void CDhcpClient::close() noexcept {
        if (_fd.isValid()) {
            if (CEventLoop* loop = CEventLoop::current()) {
                loop->cancelFd(_fd.get());
            }

            _fd.reset();
        }
    }

    /* Builds a request skeleton. */
    SDhcpMessage CDhcpClient::makeRequest(EDhcpType type, uint32_t xid) const {
        SDhcpMessage m;
        m.op = 1;
        m.xid = xid;
        m.chaddr = _mac;
        m.type(type);

        if (_clientId.empty()) {
            uint8_t id[7];
            id[0] = 1;
            std::memcpy(id + 1, _mac.bytes, 6);
            m.setOption(OPT_CLIENT_ID, id, sizeof(id));
        }
        else {
            m.setOption(OPT_CLIENT_ID, _clientId.data(), _clientId.size());
        }

        if (type != EDHCP_RELEASE) {
            static const uint8_t PARAMS[] = { OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_MTU,
                OPT_LEASE_TIME, OPT_RENEW_TIME, OPT_REBIND_TIME };
            m.setOption(OPT_PARAMS, PARAMS, sizeof(PARAMS));

            uint8_t maxSize[2];
            put16(maxSize, 1500);
            m.setOption(OPT_MAX_SIZE, maxSize, 2);

            if (!_hostname.empty()) {
                m.setOption(OPT_HOSTNAME, _hostname.data(), _hostname.size());
            }
        }

        return m;
    }

    /* Sends a message wrapped in IPv4/UDP. */
    int32_t CDhcpClient::send(const SDhcpMessage& msg, const SIpAddress& from, const SIpAddress& to, const SMacAddress& toMac) noexcept {
        if (!_fd.isValid()) {
            return -EBADF;
        }

        std::vector<uint8_t> payload;
        try {
            payload = msg.encode();
        }
        catch (...) {
            return -ENOMEM;
        }

        size_t udpLen = 8 + payload.size();
        size_t total = 20 + udpLen;
        std::vector<uint8_t> packet(total, 0);
        uint8_t* ip = packet.data();
        uint8_t* udp = ip + 20;

        SIpAddress src = from.isV4() ? from : SIpAddress::fromV4(0);
        SIpAddress dst = to.isV4() ? to : SIpAddress::fromV4(0xffffffffu);

        ip[0] = 0x45;
        ip[1] = 0x10;       // --> Low delay, as dhclient does.
        put16(ip + 2, uint16_t(total));
        put16(ip + 4, 0);
        put16(ip + 6, 0);
        ip[8] = 64;
        ip[9] = 17;
        std::memcpy(ip + 12, src.bytes, 4);
        std::memcpy(ip + 16, dst.bytes, 4);
        put16(ip + 10, checksumFinish(checksumAdd(0, ip, 20)));

        put16(udp, CLIENT_PORT);
        put16(udp + 2, SERVER_PORT);
        put16(udp + 4, uint16_t(udpLen));
        std::memcpy(udp + 8, payload.data(), payload.size());

        // --> UDP checksum over the pseudo header.
        uint8_t pseudo[12];
        std::memcpy(pseudo, src.bytes, 4);
        std::memcpy(pseudo + 4, dst.bytes, 4);
        pseudo[8] = 0;
        pseudo[9] = 17;
        put16(pseudo + 10, uint16_t(udpLen));
        uint16_t sum = checksumFinish(checksumAdd(checksumAdd(0, pseudo, 12), udp, udpLen));
        put16(udp + 6, sum == 0 ? 0xffff : sum);

        sockaddr_ll sll;
        std::memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex = _ifindex;
        sll.sll_halen = 6;
        if (toMac.isValid() && to.isV4()) {
            std::memcpy(sll.sll_addr, toMac.bytes, 6);
        }
        else {
            std::memset(sll.sll_addr, 0xff, 6);
        }

        while (::sendto(_fd.get(), packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
            if (errno != EINTR) {
                return -errno;
            }
        }

        return SBOX_OK;
    }

    /* Waits for a matching reply. */
    TTask<int32_t> CDhcpClient::receive(uint32_t xid, int64_t deadline, SDhcpMessage& out, SMacAddress& from) {
        std::vector<uint8_t> buffer(2048);

        while (true) {
            sockaddr_ll sll;
            socklen_t slen = sizeof(sll);
            ssize_t n = ::recvfrom(_fd.get(), buffer.data(), buffer.size(), MSG_DONTWAIT,
                reinterpret_cast<sockaddr*>(&sll), &slen);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno != EAGAIN) {
                    co_return -errno;
                }

                int64_t left = deadline - CEventLoop::nowMs();
                if (left <= 0) {
                    co_return -ETIMEDOUT;
                }

                int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, left);
                if (w < 0) {
                    co_return w;
                }

                continue;
            }

            // --> Filter: IPv4, UDP, to port 68, our transaction and hardware address.
            const uint8_t* p = buffer.data();
            size_t len = size_t(n);
            if (len < 28 || (p[0] >> 4) != 4 || p[9] != 17) {
                continue;
            }

            size_t ihl = size_t(p[0] & 15) * 4;
            if (ihl < 20 || len < ihl + 8 || get16(p + ihl + 2) != CLIENT_PORT) {
                continue;
            }

            size_t udpLen = get16(p + ihl + 4);
            if (udpLen < 8 || ihl + udpLen > len) {
                continue;
            }

            SDhcpMessage m;
            if (SDhcpMessage::decode(p + ihl + 8, udpLen - 8, m) != SBOX_OK) {
                continue;
            }

            if (m.op != 2 || m.xid != xid || !(m.chaddr == _mac)) {
                continue;
            }

            from = sll.sll_halen == 6 ? SMacAddress::fromBytes(sll.sll_addr) : SMacAddress();
            out = std::move(m);
            co_return SBOX_OK;
        }
    }

    /* Runs one REQUEST exchange with retransmissions. */
    TTask<int32_t> CDhcpClient::requestLease(SDhcpMessage request, SDhcpLease& lease, const SIpAddress& from,
        const SIpAddress& to, const SMacAddress& toMac, int64_t timeoutMs)
    {
        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        int64_t interval = 1000;

        while (CEventLoop::nowMs() < deadline) {
            int32_t r = send(request, from, to, toMac);
            if (r != SBOX_OK) {
                co_return r;
            }

            int64_t until = CEventLoop::nowMs() + interval;
            if (until > deadline) {
                until = deadline;
            }

            while (true) {
                SDhcpMessage reply;
                SMacAddress serverMac;
                r = co_await receive(request.xid, until, reply, serverMac);
                if (r == -ETIMEDOUT) {
                    break;
                }

                if (r != SBOX_OK) {
                    co_return r;
                }

                if (reply.type() == EDHCP_NAK) {
                    co_return -ECONNREFUSED;
                }

                if (reply.type() == EDHCP_ACK && reply.yiaddr.isV4() && !reply.yiaddr.isUnspecified()) {
                    leaseFromAck(reply, serverMac, lease);
                    co_return SBOX_OK;
                }
            }

            interval = interval < 4000 ? interval * 2 : 4000;
        }

        co_return -ETIMEDOUT;
    }

    /* Acquires a lease. */
    TTask<int32_t> CDhcpClient::acquire(SDhcpLease& out, int64_t timeoutMs) {
        if (!_fd.isValid()) {
            co_return -EBADF;
        }

        int64_t deadline = CEventLoop::nowMs() + timeoutMs;
        int32_t lastError = -ETIMEDOUT;

        while (CEventLoop::nowMs() < deadline) {
            uint32_t xid = 0;
            RandomBytes(reinterpret_cast<uint8_t*>(&xid), sizeof(xid));

            SDhcpMessage discover = makeRequest(EDHCP_DISCOVER, xid);
            discover.flags = 0x8000;

            SDhcpMessage offer;
            SMacAddress serverMac;
            bool offered = false;
            int64_t interval = 1000;

            while (!offered && CEventLoop::nowMs() < deadline) {
                int32_t r = send(discover, SIpAddress(), SIpAddress(), SMacAddress());
                if (r != SBOX_OK) {
                    co_return r;
                }

                int64_t until = CEventLoop::nowMs() + interval;
                if (until > deadline) {
                    until = deadline;
                }

                while (true) {
                    r = co_await receive(xid, until, offer, serverMac);
                    if (r == -ETIMEDOUT) {
                        break;
                    }

                    if (r != SBOX_OK) {
                        co_return r;
                    }

                    if (offer.type() == EDHCP_OFFER && offer.yiaddr.isV4()) {
                        offered = true;
                        break;
                    }
                }

                interval = interval < 4000 ? interval * 2 : 4000;
            }

            if (!offered) {
                break;
            }

            // --> SELECTING: broadcast REQUEST naming the chosen server and address.
            SDhcpMessage request = makeRequest(EDHCP_REQUEST, xid);
            request.flags = 0x8000;
            request.setAddress(OPT_REQUESTED_IP, offer.yiaddr);
            SIpAddress server = offer.address(OPT_SERVER_ID);
            request.setAddress(OPT_SERVER_ID, server.isValid() ? server : offer.siaddr);

            int64_t left = deadline - CEventLoop::nowMs();
            if (left <= 0) {
                break;
            }

            SDhcpLease lease;
            int32_t r = co_await requestLease(request, lease, SIpAddress(), SIpAddress(), SMacAddress(), left);
            if (r == SBOX_OK) {
                if (!lease.serverMac.isValid()) {
                    lease.serverMac = serverMac;
                }

                out = std::move(lease);
                co_return SBOX_OK;
            }

            if (r != -ECONNREFUSED) {
                co_return r;
            }

            // --> NAK: start over with a new transaction.
            lastError = r;
        }

        co_return lastError;
    }

    /* Renews a lease with its server. */
    TTask<int32_t> CDhcpClient::renew(SDhcpLease& lease, int64_t timeoutMs) {
        if (!_fd.isValid()) {
            co_return -EBADF;
        }

        uint32_t xid = 0;
        RandomBytes(reinterpret_cast<uint8_t*>(&xid), sizeof(xid));

        // --> RENEWING: ciaddr set, no requested-ip / server-id options, unicast to the server.
        SDhcpMessage request = makeRequest(EDHCP_REQUEST, xid);
        request.ciaddr = lease.address;

        SDhcpLease updated = lease;
        int32_t r = co_await requestLease(request, updated, lease.address, lease.server, lease.serverMac, timeoutMs);
        if (r == SBOX_OK) {
            lease = std::move(updated);
        }

        co_return r;
    }

    /* Rebinds a lease with any server. */
    TTask<int32_t> CDhcpClient::rebind(SDhcpLease& lease, int64_t timeoutMs) {
        if (!_fd.isValid()) {
            co_return -EBADF;
        }

        uint32_t xid = 0;
        RandomBytes(reinterpret_cast<uint8_t*>(&xid), sizeof(xid));

        SDhcpMessage request = makeRequest(EDHCP_REQUEST, xid);
        request.ciaddr = lease.address;

        SDhcpLease updated = lease;
        int32_t r = co_await requestLease(request, updated, lease.address, SIpAddress(), SMacAddress(), timeoutMs);
        if (r == SBOX_OK) {
            lease = std::move(updated);
        }

        co_return r;
    }

    /* Releases a lease. */
    int32_t CDhcpClient::release(const SDhcpLease& lease) noexcept {
        uint32_t xid = 0;
        RandomBytes(reinterpret_cast<uint8_t*>(&xid), sizeof(xid));

        try {
            SDhcpMessage msg = makeRequest(EDHCP_RELEASE, xid);
            msg.ciaddr = lease.address;
            msg.setAddress(OPT_SERVER_ID, lease.server);
            return send(msg, lease.address, lease.server, lease.serverMac);
        }
        catch (...) {
            return -ENOMEM;
        }
    }

}
}
