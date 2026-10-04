#include <sbox/net/netlink.hpp>
#include <sbox/net/netns.hpp>
#include <sbox/core/eventloop.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif

#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif

namespace sbox {
namespace net {

    namespace {

        constexpr size_t RECV_BUFFER = 256 * 1024;

        /* Rounds up to the netlink alignment. */
        constexpr size_t align4(size_t n) noexcept {
            return (n + 3) & ~size_t(3);
        }

        /* Returns the netlink header of a builder buffer. */
        nlmsghdr* headerOf(std::vector<uint8_t>& buffer) noexcept {
            return reinterpret_cast<nlmsghdr*>(buffer.data());
        }

        /* Returns the netlink header of a builder buffer. */
        const nlmsghdr* headerOf(const std::vector<uint8_t>& buffer) noexcept {
            return reinterpret_cast<const nlmsghdr*>(buffer.data());
        }

        /* Extracts the extended ACK message of an NLMSG_ERROR. */
        std::string extackMessage(const nlmsghdr* nlh) {
            if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS)) {
                return std::string();
            }

            const auto* err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(nlh));
            size_t payload = nlh->nlmsg_len - NLMSG_HDRLEN;
            size_t offset = sizeof(nlmsgerr);

            // --> Without NLM_F_CAPPED the original request follows the error header in full.
            if (!(nlh->nlmsg_flags & NLM_F_CAPPED)) {
                offset += align4(err->msg.nlmsg_len) - NLMSG_HDRLEN;
            }

            if (offset >= payload) {
                return std::string();
            }

            CNlAttrs attrs(reinterpret_cast<const uint8_t*>(NLMSG_DATA(nlh)) + offset, payload - offset);
            return attrs.str(NLMSGERR_ATTR_MSG);
        }

    }

    /* Starts a message. */
    CNlMessage::CNlMessage(uint16_t type, uint16_t flags) : _buffer(NLMSG_HDRLEN, 0) {
        nlmsghdr* h = headerOf(_buffer);
        h->nlmsg_len = uint32_t(NLMSG_HDRLEN);
        h->nlmsg_type = type;
        h->nlmsg_flags = flags;
    }

    /* Starts a generic netlink message. */
    CNlMessage CNlMessage::genl(uint16_t familyId, uint8_t command, uint8_t version, uint16_t flags) {
        CNlMessage msg(familyId, flags);
        genlmsghdr g;
        std::memset(&g, 0, sizeof(g));
        g.cmd = command;
        g.version = version;
        msg.putHeader(&g, sizeof(g));
        return msg;
    }

    /* Returns the message type. */
    uint16_t CNlMessage::type() const noexcept {
        return headerOf(_buffer)->nlmsg_type;
    }

    /* Returns the flags. */
    uint16_t CNlMessage::flags() const noexcept {
        return headerOf(_buffer)->nlmsg_flags;
    }

    /* Replaces the flags. */
    void CNlMessage::flags(uint16_t value) noexcept {
        headerOf(_buffer)->nlmsg_flags = value;
    }

    /* Returns the sequence number. */
    uint32_t CNlMessage::seq() const noexcept {
        return headerOf(_buffer)->nlmsg_seq;
    }

    /* Sets the sequence number. */
    void CNlMessage::seq(uint32_t value) noexcept {
        headerOf(_buffer)->nlmsg_seq = value;
    }

    /* Appends the family header. */
    void CNlMessage::putHeader(const void* data, size_t length) {
        size_t at = _buffer.size();
        _buffer.resize(at + align4(length), 0);
        std::memcpy(_buffer.data() + at, data, length);
        headerOf(_buffer)->nlmsg_len = uint32_t(_buffer.size());
    }

    /* Appends an attribute. */
    void CNlMessage::put(uint16_t type, const void* data, size_t length) {
        size_t at = _buffer.size();
        _buffer.resize(at + align4(NLA_HDRLEN + length), 0);

        nlattr attr;
        attr.nla_len = uint16_t(NLA_HDRLEN + length);
        attr.nla_type = type;
        std::memcpy(_buffer.data() + at, &attr, sizeof(attr));

        if (length) {
            std::memcpy(_buffer.data() + at + NLA_HDRLEN, data, length);
        }

        headerOf(_buffer)->nlmsg_len = uint32_t(_buffer.size());
    }

    /* Appends a flag attribute. */
    void CNlMessage::putFlag(uint16_t type) {
        put(type, nullptr, 0);
    }

    /* Appends a u8. */
    void CNlMessage::putU8(uint16_t type, uint8_t value) {
        put(type, &value, sizeof(value));
    }

    /* Appends a u16. */
    void CNlMessage::putU16(uint16_t type, uint16_t value) {
        put(type, &value, sizeof(value));
    }

    /* Appends a u32. */
    void CNlMessage::putU32(uint16_t type, uint32_t value) {
        put(type, &value, sizeof(value));
    }

    /* Appends a u64. */
    void CNlMessage::putU64(uint16_t type, uint64_t value) {
        put(type, &value, sizeof(value));
    }

    /* Appends a big-endian u16. */
    void CNlMessage::putBe16(uint16_t type, uint16_t value) {
        uint16_t be = htons(value);
        put(type, &be, sizeof(be));
    }

    /* Appends a big-endian u32. */
    void CNlMessage::putBe32(uint16_t type, uint32_t value) {
        uint32_t be = htonl(value);
        put(type, &be, sizeof(be));
    }

    /* Appends a big-endian u64. */
    void CNlMessage::putBe64(uint16_t type, uint64_t value) {
        uint8_t be[8];
        for (size_t i = 0; i < 8; ++i) {
            be[i] = uint8_t(value >> (56 - 8 * i));
        }

        put(type, be, sizeof(be));
    }

    /* Appends a string with its terminator. */
    void CNlMessage::putString(uint16_t type, std::string_view value) {
        size_t at = _buffer.size();
        size_t length = value.size() + 1;
        _buffer.resize(at + align4(NLA_HDRLEN + length), 0);

        nlattr attr;
        attr.nla_len = uint16_t(NLA_HDRLEN + length);
        attr.nla_type = type;
        std::memcpy(_buffer.data() + at, &attr, sizeof(attr));
        std::memcpy(_buffer.data() + at + NLA_HDRLEN, value.data(), value.size());
        headerOf(_buffer)->nlmsg_len = uint32_t(_buffer.size());
    }

    /* Appends an address. */
    void CNlMessage::putAddress(uint16_t type, const SIpAddress& value) {
        put(type, value.bytes, value.length());
    }

    /* Opens a nested attribute. */
    size_t CNlMessage::beginNested(uint16_t type) {
        size_t at = _buffer.size();
        put(uint16_t(type | NLA_F_NESTED), nullptr, 0);
        return at;
    }

    /* Closes a nested attribute. */
    void CNlMessage::endNested(size_t token) noexcept {
        nlattr attr;
        std::memcpy(&attr, _buffer.data() + token, sizeof(attr));
        attr.nla_len = uint16_t(_buffer.size() - token);
        std::memcpy(_buffer.data() + token, &attr, sizeof(attr));
    }

    /* Returns a u8. */
    uint8_t SNlAttr::u8() const noexcept {
        return length >= 1 ? data[0] : 0;
    }

    /* Returns a u16. */
    uint16_t SNlAttr::u16() const noexcept {
        uint16_t v = 0;
        if (length >= sizeof(v)) {
            std::memcpy(&v, data, sizeof(v));
        }

        return v;
    }

    /* Returns a u32. */
    uint32_t SNlAttr::u32() const noexcept {
        uint32_t v = 0;
        if (length >= sizeof(v)) {
            std::memcpy(&v, data, sizeof(v));
        }

        return v;
    }

    /* Returns a u64. */
    uint64_t SNlAttr::u64() const noexcept {
        uint64_t v = 0;
        if (length >= sizeof(v)) {
            std::memcpy(&v, data, sizeof(v));
        }

        return v;
    }

    /* Returns a big-endian u16. */
    uint16_t SNlAttr::be16() const noexcept {
        return ntohs(u16());
    }

    /* Returns a big-endian u32. */
    uint32_t SNlAttr::be32() const noexcept {
        return ntohl(u32());
    }

    /* Returns a string. */
    std::string SNlAttr::str() const {
        size_t n = 0;
        while (n < length && data[n] != 0) {
            ++n;
        }

        return std::string(reinterpret_cast<const char*>(data), n);
    }

    /* Returns an address. */
    SIpAddress SNlAttr::address() const noexcept {
        SIpAddress out;
        SIpAddress::fromBytes(data, length, out);
        return out;
    }

    /* Parses an attribute stream. */
    CNlAttrs::CNlAttrs(const uint8_t* data, size_t length) {
        size_t at = 0;

        while (at + NLA_HDRLEN <= length) {
            nlattr attr;
            std::memcpy(&attr, data + at, sizeof(attr));

            if (attr.nla_len < NLA_HDRLEN || at + attr.nla_len > length) {
                break;
            }

            SNlAttr item;
            item.type = uint16_t(attr.nla_type & NLA_TYPE_MASK);
            item.data = data + at + NLA_HDRLEN;
            item.length = attr.nla_len - NLA_HDRLEN;
            _items.push_back(item);

            at += align4(attr.nla_len);
        }
    }

    /* Parses a nested attribute. */
    CNlAttrs CNlAttrs::nested(const SNlAttr& attr) {
        return CNlAttrs(attr.data, attr.length);
    }

    /* Finds an attribute. */
    const SNlAttr* CNlAttrs::find(uint16_t type) const noexcept {
        for (const SNlAttr& a : _items) {
            if (a.type == type) {
                return &a;
            }
        }

        return nullptr;
    }

    /* Returns a u32 attribute. */
    uint32_t CNlAttrs::u32(uint16_t type, uint32_t fallback) const noexcept {
        const SNlAttr* a = find(type);
        return a ? a->u32() : fallback;
    }

    /* Returns a string attribute. */
    std::string CNlAttrs::str(uint16_t type) const {
        const SNlAttr* a = find(type);
        return a ? a->str() : std::string();
    }

    /* Parses the attributes after a family header. */
    CNlAttrs SNlReply::attrs(size_t headerSize) const {
        size_t skip = align4(headerSize);
        if (skip > payload.size()) {
            return CNlAttrs();
        }

        return CNlAttrs(payload.data() + skip, payload.size() - skip);
    }

    /* Constructs a closed socket. */
    CNetlinkSocket::CNetlinkSocket() noexcept : _protocol(-1), _seq(0), _portId(0), _busy(false) {}

    /* Closes the socket. */
    CNetlinkSocket::~CNetlinkSocket() {
        close();
    }

    /* Opens a socket in a namespace given by path. */
    int32_t CNetlinkSocket::open(int protocol, const std::string& netnsPath) noexcept {
        if (netnsPath.empty()) {
            return openIn(protocol, -1);
        }

        CFd ns;
        int32_t r = CNetns::open(netnsPath, ns);
        if (r != SBOX_OK) {
            return r;
        }

        return openIn(protocol, ns.get());
    }

    /* Opens a socket in a namespace given by descriptor. */
    int32_t CNetlinkSocket::openIn(int protocol, int netnsFd) noexcept {
        close();

        CFd fd;
        {
            CNetnsScope scope(netnsFd);
            if (scope.error() != SBOX_OK) {
                return scope.error();
            }

            fd.reset(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol));
            if (!fd.isValid()) {
                return errno == EPROTONOSUPPORT ? -ENOTSUP : -errno;
            }
        }

        int one = 1;
        ::setsockopt(fd.get(), SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
        ::setsockopt(fd.get(), SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one));

        int bufferSize = int(RECV_BUFFER);
        ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));

        sockaddr_nl local;
        std::memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;

        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
            return -errno;
        }

        socklen_t len = sizeof(local);
        if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&local), &len) < 0) {
            return -errno;
        }

        uint32_t seed = 0;
        RandomBytes(reinterpret_cast<uint8_t*>(&seed), sizeof(seed));

        _fd = std::move(fd);
        _protocol = protocol;
        _portId = local.nl_pid;
        _seq = seed & 0x7fffffffu;
        return SBOX_OK;
    }

    /* Closes the socket. */
    void CNetlinkSocket::close() noexcept {
        if (!_fd.isValid()) {
            return;
        }

        if (CEventLoop* loop = CEventLoop::current()) {
            loop->cancelFd(_fd.get());
        }

        _fd.reset();
    }

    /* Joins a multicast group. */
    int32_t CNetlinkSocket::joinGroup(uint32_t group) noexcept {
        int g = int(group);
        if (::setsockopt(_fd.get(), SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &g, sizeof(g)) < 0) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Returns true when the lock is free (and takes it). */
    bool CNetlinkSocket::SLockAwaiter::await_ready() const noexcept {
        if (!socket->_busy) {
            socket->_busy = true;
            return true;
        }

        return false;
    }

    /* Queues the waiter. */
    void CNetlinkSocket::SLockAwaiter::await_suspend(std::coroutine_handle<> h) {
        socket->_waiters.push_back(h);
    }

    /* Releases the lock to the next waiter. */
    void CNetlinkSocket::unlock() noexcept {
        if (_waiters.empty()) {
            _busy = false;
            return;
        }

        // --> Ownership passes straight to the next waiter (_busy stays true), so a request
        // arriving meanwhile cannot overtake the queue.
        std::coroutine_handle<> next = _waiters.front();
        _waiters.pop_front();
        CEventLoop::current()->post(next);
    }

    /* Returns the next sequence number. */
    uint32_t CNetlinkSocket::nextSeq() noexcept {
        _seq = (_seq + 1) & 0x7fffffffu;
        if (_seq == 0) {
            _seq = 1;
        }

        return _seq;
    }

    /* Sends one datagram. */
    TTask<int32_t> CNetlinkSocket::sendBuffer(const std::vector<uint8_t>& buffer, int64_t deadline) {
        sockaddr_nl kernel;
        std::memset(&kernel, 0, sizeof(kernel));
        kernel.nl_family = AF_NETLINK;

        while (true) {
            ssize_t n = ::sendto(_fd.get(), buffer.data(), buffer.size(), 0,
                reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel));
            if (n >= 0) {
                co_return SBOX_OK;
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EAGAIN) {
                co_return -errno;
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_WRITE, left);
            if (w < 0) {
                co_return w;
            }
        }
    }

    /* Receives one datagram. */
    TTask<int32_t> CNetlinkSocket::recvBuffer(std::vector<uint8_t>& buffer, int64_t deadline) {
        while (true) {
            sockaddr_nl from;
            iovec iov{ buffer.data(), buffer.size() };
            msghdr mh;
            std::memset(&mh, 0, sizeof(mh));
            mh.msg_name = &from;
            mh.msg_namelen = sizeof(from);
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;

            ssize_t n = ::recvmsg(_fd.get(), &mh, MSG_DONTWAIT);
            if (n >= 0) {
                if (mh.msg_flags & MSG_TRUNC) {
                    co_return -EMSGSIZE;
                }

                // --> Only the kernel (port 0) may talk to us; anything else is spoofing.
                if (from.nl_pid != 0) {
                    continue;
                }

                co_return int32_t(n);
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EAGAIN) {
                co_return -errno;
            }

            int64_t left = deadline < 0 ? -1 : deadline - CEventLoop::nowMs();
            if (deadline >= 0 && left <= 0) {
                co_return -ETIMEDOUT;
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, left);
            if (w < 0) {
                co_return w;
            }
        }
    }

    /* Runs one send/receive exchange. */
    TTask<int32_t> CNetlinkSocket::exchange(const std::vector<uint8_t>& out, std::vector<uint32_t> ackSeqs,
        uint32_t batchSeq, uint32_t dumpSeq, std::vector<SNlReply>* replies, int64_t timeoutMs)
    {
        _lastError.clear();

        if (!_fd.isValid()) {
            co_return -EBADF;
        }

        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        int32_t r = co_await sendBuffer(out, deadline);
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<uint8_t> buffer(RECV_BUFFER);
        int32_t firstError = SBOX_OK;
        bool dumpDone = dumpSeq == 0;
        bool interrupted = false;

        auto isAckSeq = [&](uint32_t seq) {
            for (uint32_t s : ackSeqs) {
                if (s == seq) {
                    return true;
                }
            }

            return false;
        };

        auto markAcked = [&](uint32_t seq) {
            for (size_t i = 0; i < ackSeqs.size(); ++i) {
                if (ackSeqs[i] == seq) {
                    ackSeqs.erase(ackSeqs.begin() + ptrdiff_t(i));
                    return;
                }
            }
        };

        while (!ackSeqs.empty() || !dumpDone) {
            int32_t n = co_await recvBuffer(buffer, deadline);
            if (n < 0) {
                co_return firstError != SBOX_OK ? firstError : n;
            }

            size_t at = 0;
            size_t total = size_t(n);

            while (at + NLMSG_HDRLEN <= total) {
                const auto* nlh = reinterpret_cast<const nlmsghdr*>(buffer.data() + at);
                if (nlh->nlmsg_len < NLMSG_HDRLEN || at + nlh->nlmsg_len > total) {
                    break;
                }

                at += align4(nlh->nlmsg_len);

                uint32_t seq = nlh->nlmsg_seq;
                bool ours = isAckSeq(seq) || seq == dumpSeq || seq == batchSeq;
                if (!ours || nlh->nlmsg_pid != _portId) {
                    continue;
                }

                if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
                    interrupted = true;
                }

                if (nlh->nlmsg_type == NLMSG_ERROR) {
                    const auto* err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(nlh));
                    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                        co_return -EPROTO;
                    }

                    if (err->error != 0 && firstError == SBOX_OK) {
                        firstError = err->error;
                        _lastError = extackMessage(nlh);

                        // --> Once the batch failed, the kernel may not answer every message:
                        // collect what is already queued but stop waiting long.
                        int64_t shortDeadline = CEventLoop::nowMs() + 200;
                        if (deadline < 0 || shortDeadline < deadline) {
                            deadline = shortDeadline;
                        }
                    }

                    if (seq == batchSeq && batchSeq != 0) {
                        // --> An error on the batch header covers the whole batch.
                        co_return firstError != SBOX_OK ? firstError : SBOX_OK;
                    }

                    if (seq == dumpSeq) {
                        dumpDone = true;
                    }

                    markAcked(seq);
                    continue;
                }

                if (nlh->nlmsg_type == NLMSG_DONE) {
                    if (seq == dumpSeq) {
                        dumpDone = true;

                        if (nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(int32_t))) {
                            int32_t code;
                            std::memcpy(&code, NLMSG_DATA(nlh), sizeof(code));
                            if (code < 0 && firstError == SBOX_OK) {
                                firstError = code;
                            }
                        }
                    }

                    continue;
                }

                if (nlh->nlmsg_type == NLMSG_NOOP || nlh->nlmsg_type == NLMSG_OVERRUN) {
                    continue;
                }

                if (replies) {
                    SNlReply reply;
                    reply.type = nlh->nlmsg_type;
                    reply.flags = nlh->nlmsg_flags;
                    const uint8_t* payload = reinterpret_cast<const uint8_t*>(NLMSG_DATA(nlh));
                    reply.payload.assign(payload, payload + (nlh->nlmsg_len - NLMSG_HDRLEN));
                    replies->push_back(std::move(reply));
                }
            }
        }

        if (firstError == SBOX_OK && interrupted) {
            co_return -EINTR;
        }

        co_return firstError;
    }

    /* Sends a request and waits for the ACK. */
    TTask<int32_t> CNetlinkSocket::request(CNlMessage& message, std::vector<SNlReply>* replies, int64_t timeoutMs) {
        co_await lock();

        uint32_t seq = nextSeq();
        message.seq(seq);
        message.flags(uint16_t(message.flags() | NLM_F_REQUEST | NLM_F_ACK));

        int32_t r = co_await exchange(message.bytes(), std::vector<uint32_t>{ seq }, 0, 0, replies, timeoutMs);
        unlock();
        co_return r;
    }

    /* Sends a dump request and collects the replies. */
    TTask<int32_t> CNetlinkSocket::dump(CNlMessage& message, std::vector<SNlReply>& replies, int64_t timeoutMs) {
        co_await lock();

        int32_t r = -EINTR;
        for (int32_t attempt = 0; attempt < 4 && r == -EINTR; ++attempt) {
            replies.clear();
            uint32_t seq = nextSeq();
            message.seq(seq);
            message.flags(uint16_t((message.flags() | NLM_F_REQUEST | NLM_F_DUMP) & ~NLM_F_ACK));
            r = co_await exchange(message.bytes(), std::vector<uint32_t>(), 0, seq, &replies, timeoutMs);
        }

        unlock();
        co_return r;
    }

    /* Sends a batch of messages. */
    TTask<int32_t> CNetlinkSocket::batch(std::vector<CNlMessage>& messages, int64_t timeoutMs) {
        co_await lock();

        std::vector<uint8_t> out;
        std::vector<uint32_t> acks;
        uint32_t first = 0;

        for (CNlMessage& m : messages) {
            uint32_t seq = nextSeq();
            if (first == 0) {
                first = seq;
            }

            m.seq(seq);
            m.flags(uint16_t(m.flags() | NLM_F_REQUEST));
            if (m.flags() & NLM_F_ACK) {
                acks.push_back(seq);
            }

            out.insert(out.end(), m.bytes().begin(), m.bytes().end());
        }

        int32_t r = co_await exchange(out, acks, first, 0, nullptr, timeoutMs);
        unlock();
        co_return r;
    }

    /* Receives notifications. */
    TTask<int32_t> CNetlinkSocket::receive(std::vector<SNlReply>& out, int64_t timeoutMs) {
        std::vector<uint8_t> buffer(RECV_BUFFER);
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        int32_t n = co_await recvBuffer(buffer, deadline);
        if (n < 0) {
            co_return n;
        }

        size_t at = 0;
        while (at + NLMSG_HDRLEN <= size_t(n)) {
            const auto* nlh = reinterpret_cast<const nlmsghdr*>(buffer.data() + at);
            if (nlh->nlmsg_len < NLMSG_HDRLEN || at + nlh->nlmsg_len > size_t(n)) {
                break;
            }

            SNlReply reply;
            reply.type = nlh->nlmsg_type;
            reply.flags = nlh->nlmsg_flags;
            const uint8_t* payload = reinterpret_cast<const uint8_t*>(NLMSG_DATA(nlh));
            reply.payload.assign(payload, payload + (nlh->nlmsg_len - NLMSG_HDRLEN));
            out.push_back(std::move(reply));
            at += align4(nlh->nlmsg_len);
        }

        co_return SBOX_OK;
    }

    /* Resolves a generic netlink family. */
    TTask<int32_t> ResolveGenlFamily(CNetlinkSocket& socket, std::string name, SGenlFamily& out) {
        CNlMessage msg = CNlMessage::genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1);
        msg.putString(CTRL_ATTR_FAMILY_NAME, name);

        std::vector<SNlReply> replies;
        int32_t r = co_await socket.request(msg, &replies);
        if (r == -EINVAL) {
            // --> Some kernels answer an unknown family name with EINVAL instead of ENOENT; the
            // request itself is fixed and valid, so both mean "not registered".
            co_return -ENOENT;
        }

        if (r != SBOX_OK) {
            co_return r;
        }

        for (const SNlReply& reply : replies) {
            if (reply.type != GENL_ID_CTRL) {
                continue;
            }

            CNlAttrs attrs = reply.attrs(GENL_HDRLEN);
            const SNlAttr* id = attrs.find(CTRL_ATTR_FAMILY_ID);
            if (!id) {
                continue;
            }

            SGenlFamily family;
            family.id = id->u16();
            family.version = attrs.u32(CTRL_ATTR_VERSION);
            family.headerSize = attrs.u32(CTRL_ATTR_HDRSIZE);
            family.maxAttr = attrs.u32(CTRL_ATTR_MAXATTR);

            if (const SNlAttr* groups = attrs.find(CTRL_ATTR_MCAST_GROUPS)) {
                CNlAttrs list = CNlAttrs::nested(*groups);
                for (const SNlAttr& g : list.items()) {
                    CNlAttrs ga = CNlAttrs::nested(g);
                    family.groups.emplace_back(ga.str(CTRL_ATTR_MCAST_GRP_NAME), ga.u32(CTRL_ATTR_MCAST_GRP_ID));
                }
            }

            out = std::move(family);
            co_return SBOX_OK;
        }

        co_return -ENOENT;
    }

}
}
