#include <sbox/core/socket.hpp>
#include <sbox/core/eventloop.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace sbox {

    /* Constructs an empty endpoint. */
    SEndpoint::SEndpoint() noexcept : length(0) {
        std::memset(&storage, 0, sizeof(storage));
    }

    /* Returns the family. */
    int SEndpoint::family() const noexcept {
        return length ? storage.ss_family : AF_UNSPEC;
    }

    /* Returns the port. */
    uint16_t SEndpoint::port() const noexcept {
        if (family() == AF_INET) {
            return ntohs(reinterpret_cast<const sockaddr_in*>(&storage)->sin_port);
        }

        if (family() == AF_INET6) {
            return ntohs(reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_port);
        }

        return 0;
    }

    /* Sets the port. */
    void SEndpoint::port(uint16_t value) noexcept {
        if (family() == AF_INET) {
            reinterpret_cast<sockaddr_in*>(&storage)->sin_port = htons(value);
        }
        else if (family() == AF_INET6) {
            reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port = htons(value);
        }
    }

    /* Builds an IP endpoint. */
    int32_t SEndpoint::fromIp(std::string_view address, uint16_t port, SEndpoint& out) noexcept {
        char text[INET6_ADDRSTRLEN + 1];
        if (address.size() >= sizeof(text)) {
            return -EINVAL;
        }

        std::memcpy(text, address.data(), address.size());
        text[address.size()] = 0;

        out = SEndpoint();
        auto* v4 = reinterpret_cast<sockaddr_in*>(&out.storage);
        if (::inet_pton(AF_INET, text, &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
            v4->sin_port = htons(port);
            out.length = sizeof(sockaddr_in);
            return SBOX_OK;
        }

        auto* v6 = reinterpret_cast<sockaddr_in6*>(&out.storage);
        if (::inet_pton(AF_INET6, text, &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
            v6->sin6_port = htons(port);
            out.length = sizeof(sockaddr_in6);
            return SBOX_OK;
        }

        return -EINVAL;
    }

    /* Builds a UNIX endpoint. */
    int32_t SEndpoint::fromUnix(std::string_view path, SEndpoint& out) noexcept {
        out = SEndpoint();
        auto* un = reinterpret_cast<sockaddr_un*>(&out.storage);

        if (path.empty() || path.size() >= sizeof(un->sun_path)) {
            return -EINVAL;
        }

        un->sun_family = AF_UNIX;
        std::memcpy(un->sun_path, path.data(), path.size());

        if (path[0] == '@') {
            // --> Abstract names start with a NUL byte and are not terminated.
            un->sun_path[0] = 0;
            out.length = socklen_t(offsetof(sockaddr_un, sun_path) + path.size());
        }
        else {
            out.length = socklen_t(offsetof(sockaddr_un, sun_path) + path.size() + 1);
        }

        return SBOX_OK;
    }

    /* Parses a numeric endpoint. */
    int32_t SEndpoint::parse(std::string_view text, SEndpoint& out) noexcept {
        if (text.substr(0, 5) == "unix:") {
            return fromUnix(text.substr(5), out);
        }

        if (!text.empty() && (text[0] == '/' || text[0] == '@')) {
            return fromUnix(text, out);
        }

        std::string_view host;
        std::string_view portText;

        if (!text.empty() && text[0] == '[') {
            size_t close = text.find(']');
            if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') {
                return -EINVAL;
            }

            host = text.substr(1, close - 1);
            portText = text.substr(close + 2);
        }
        else {
            size_t colon = text.rfind(':');
            if (colon == std::string_view::npos) {
                return -EINVAL;
            }

            host = text.substr(0, colon);
            portText = text.substr(colon + 1);
        }

        if (portText.empty() || portText.size() > 5) {
            return -EINVAL;
        }

        uint32_t port = 0;
        for (char c : portText) {
            if (c < '0' || c > '9') {
                return -EINVAL;
            }

            port = port * 10 + uint32_t(c - '0');
        }

        if (port > 65535) {
            return -EINVAL;
        }

        return fromIp(host, uint16_t(port), out);
    }

    /* Formats the endpoint. */
    std::string SEndpoint::toString() const {
        char text[INET6_ADDRSTRLEN + 1] = { 0 };

        switch (family()) {
        case AF_INET:
            ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&storage)->sin_addr, text, sizeof(text));
            return std::string(text) + ":" + std::to_string(port());

        case AF_INET6:
            ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_addr, text, sizeof(text));
            return "[" + std::string(text) + "]:" + std::to_string(port());

        case AF_UNIX: {
            const auto* un = reinterpret_cast<const sockaddr_un*>(&storage);
            size_t max = length - offsetof(sockaddr_un, sun_path);

            if (max == 0) {
                return "unix:";
            }

            if (un->sun_path[0] == 0) {
                return "@" + std::string(un->sun_path + 1, max - 1);
            }

            return "unix:" + std::string(un->sun_path, ::strnlen(un->sun_path, max));
        }

        default:
            return std::string();
        }
    }

    /* Resolves a host name. */
    TTask<int32_t> ResolveEndpoints(std::string host, uint16_t port, std::vector<SEndpoint>& out) {
        SEndpoint numeric;
        if (SEndpoint::fromIp(host, port, numeric) == SBOX_OK) {
            out.push_back(numeric);
            co_return SBOX_OK;
        }

        int32_t result = SBOX_OK;
        std::vector<SEndpoint> found;

        co_await CEventLoop::current()->runBlocking([&]() {
            addrinfo hints{};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;

            addrinfo* list = nullptr;
            int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &list);
            if (rc != 0) {
                result = rc == EAI_SYSTEM ? -errno : -EHOSTUNREACH;
                return;
            }

            for (addrinfo* ai = list; ai; ai = ai->ai_next) {
                SEndpoint ep;
                std::memcpy(&ep.storage, ai->ai_addr, ai->ai_addrlen);
                ep.length = ai->ai_addrlen;
                ep.port(port);
                found.push_back(ep);
            }

            ::freeaddrinfo(list);
        });

        out.insert(out.end(), found.begin(), found.end());
        co_return found.empty() && result == SBOX_OK ? -EHOSTUNREACH : result;
    }

    /* Connects the socket. */
    TTask<int32_t> CSocket::connect(const SEndpoint& endpoint, int64_t timeoutMs) {
        close();

        CFd fd(::socket(endpoint.family(), SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (!fd.isValid()) {
            co_return -errno;
        }

        if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&endpoint.storage), endpoint.length) < 0) {
            if (errno != EINPROGRESS && errno != EAGAIN) {
                co_return -errno;
            }

            int32_t w = co_await CEventLoop::current()->waitFd(fd.get(), EFDE_WRITE, timeoutMs);
            if (w < 0) {
                CEventLoop::current()->cancelFd(fd.get());
                co_return w;
            }

            int err = 0;
            socklen_t len = sizeof(err);
            ::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                co_return -err;
            }
        }

        _fd = std::move(fd);
        _socket = true;
        co_return SBOX_OK;
    }

    /* Half-closes the write side. */
    int32_t CSocket::shutdownWrite() noexcept {
        return ::shutdown(_fd.get(), SHUT_WR) < 0 ? -errno : SBOX_OK;
    }

    /* Returns the local address. */
    SEndpoint CSocket::localEndpoint() const noexcept {
        SEndpoint ep;
        ep.length = sizeof(ep.storage);
        if (::getsockname(_fd.get(), reinterpret_cast<sockaddr*>(&ep.storage), &ep.length) < 0) {
            ep.length = 0;
        }

        return ep;
    }

    /* Returns the peer address. */
    SEndpoint CSocket::remoteEndpoint() const noexcept {
        SEndpoint ep;
        ep.length = sizeof(ep.storage);
        if (::getpeername(_fd.get(), reinterpret_cast<sockaddr*>(&ep.storage), &ep.length) < 0) {
            ep.length = 0;
        }

        return ep;
    }

    /* Sends bytes with descriptors. */
    int32_t CSocket::sendFds(const SReadOnlyByteSpan& bytes, const std::vector<int>& fds) noexcept {
        if (bytes.empty() || fds.size() > 64) {
            return -EINVAL;
        }

        iovec iov{ const_cast<uint8_t*>(bytes.data), bytes.size };
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 64)];
        std::memset(control, 0, sizeof(control));

        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (!fds.empty()) {
            msg.msg_control = control;
            msg.msg_controllen = CMSG_SPACE(sizeof(int) * fds.size());

            cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
            std::memcpy(CMSG_DATA(cm), fds.data(), sizeof(int) * fds.size());
        }

        while (true) {
            ssize_t n = ::sendmsg(_fd.get(), &msg, MSG_NOSIGNAL);
            if (n >= 0) {
                return SBOX_OK;
            }

            if (errno != EINTR) {
                return -errno;
            }
        }
    }

    /* Receives bytes with descriptors. */
    TTask<SIoResult> CSocket::recvFds(const SByteSpan& bytes, std::vector<CFd>& fds, int64_t timeoutMs) {
        while (true) {
            iovec iov{ bytes.data, bytes.size };
            alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 64)];

            msghdr msg{};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);

            ssize_t n = ::recvmsg(_fd.get(), &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
            if (n >= 0) {
                for (cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
                    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
                        size_t count = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        int received[64];
                        std::memcpy(received, CMSG_DATA(cm), count * sizeof(int));

                        for (size_t i = 0; i < count; ++i) {
                            fds.emplace_back(received[i]);
                        }
                    }
                }

                co_return SIoResult{ SBOX_OK, size_t(n) };
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EAGAIN) {
                co_return SIoResult{ -errno, 0 };
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, timeoutMs);
            if (w < 0) {
                co_return SIoResult{ w, 0 };
            }
        }
    }

    /* Creates a socket pair. */
    int32_t CSocket::pair(CSocket& a, CSocket& b) noexcept {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) < 0) {
            return -errno;
        }

        a = CSocket(CFd(fds[0]));
        b = CSocket(CFd(fds[1]));
        return SBOX_OK;
    }

    /* Move-assigns the listener. */
    CListener& CListener::operator=(CListener&& other) noexcept {
        if (this != &other) {
            close();
            _fd = std::move(other._fd);
        }

        return *this;
    }

    /* Closes the listener. */
    CListener::~CListener() {
        close();
    }

    /* Binds and listens. */
    int32_t CListener::listen(const SEndpoint& endpoint, int32_t backlog) noexcept {
        close();

        CFd fd(::socket(endpoint.family(), SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (!fd.isValid()) {
            return -errno;
        }

        if (endpoint.family() == AF_UNIX) {
            const auto* un = reinterpret_cast<const sockaddr_un*>(&endpoint.storage);
            struct stat st{};

            // --> Replace a stale socket file left by a previous run, but never a regular file.
            if (un->sun_path[0] != 0 && ::lstat(un->sun_path, &st) == 0 && S_ISSOCK(st.st_mode)) {
                ::unlink(un->sun_path);
            }
        }
        else {
            int one = 1;
            ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        }

        if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&endpoint.storage), endpoint.length) < 0) {
            return -errno;
        }

        if (::listen(fd.get(), backlog) < 0) {
            return -errno;
        }

        _fd = std::move(fd);
        return SBOX_OK;
    }

    /* Returns the bound address. */
    SEndpoint CListener::localEndpoint() const noexcept {
        SEndpoint ep;
        ep.length = sizeof(ep.storage);
        if (::getsockname(_fd.get(), reinterpret_cast<sockaddr*>(&ep.storage), &ep.length) < 0) {
            ep.length = 0;
        }

        return ep;
    }

    /* Accepts a connection. */
    TTask<int32_t> CListener::accept(CSocket& out, int64_t timeoutMs) {
        while (true) {
            int fd = ::accept4(_fd.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (fd >= 0) {
                out = CSocket(CFd(fd));
                co_return SBOX_OK;
            }

            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }

            if (errno != EAGAIN) {
                co_return -errno;
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, timeoutMs);
            if (w < 0) {
                co_return w;
            }
        }
    }

    /* Stops listening. */
    void CListener::close() noexcept {
        if (!_fd.isValid()) {
            return;
        }

        if (CEventLoop* loop = CEventLoop::current()) {
            loop->cancelFd(_fd.get());
        }

        _fd.reset();
    }

    /* Move-assigns the datagram socket. */
    CDatagramSocket& CDatagramSocket::operator=(CDatagramSocket&& other) noexcept {
        if (this != &other) {
            close();
            _fd = std::move(other._fd);
        }

        return *this;
    }

    /* Closes the datagram socket. */
    CDatagramSocket::~CDatagramSocket() {
        close();
    }

    /* Opens and binds the socket. */
    int32_t CDatagramSocket::open(int family, const SEndpoint& local) noexcept {
        close();

        CFd fd(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (!fd.isValid()) {
            return -errno;
        }

        if (local.isValid()
            && ::bind(fd.get(), reinterpret_cast<const sockaddr*>(&local.storage), local.length) < 0) {
            return -errno;
        }

        _fd = std::move(fd);
        return SBOX_OK;
    }

    /* Returns the bound address. */
    SEndpoint CDatagramSocket::localEndpoint() const noexcept {
        SEndpoint ep;
        ep.length = sizeof(ep.storage);
        if (::getsockname(_fd.get(), reinterpret_cast<sockaddr*>(&ep.storage), &ep.length) < 0) {
            ep.length = 0;
        }

        return ep;
    }

    /* Sends a datagram. */
    int32_t CDatagramSocket::sendTo(const SReadOnlyByteSpan& bytes, const SEndpoint& to) noexcept {
        while (true) {
            ssize_t n = ::sendto(_fd.get(), bytes.data, bytes.size, MSG_NOSIGNAL,
                reinterpret_cast<const sockaddr*>(&to.storage), to.length);

            if (n >= 0) {
                return SBOX_OK;
            }

            if (errno != EINTR) {
                return -errno;
            }
        }
    }

    /* Receives a datagram. */
    TTask<SIoResult> CDatagramSocket::recvFrom(const SByteSpan& buffer, SEndpoint& from, int64_t timeoutMs) {
        while (true) {
            from = SEndpoint();
            from.length = sizeof(from.storage);

            ssize_t n = ::recvfrom(_fd.get(), buffer.data, buffer.size, MSG_DONTWAIT,
                reinterpret_cast<sockaddr*>(&from.storage), &from.length);

            if (n >= 0) {
                co_return SIoResult{ SBOX_OK, size_t(n) };
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EAGAIN) {
                co_return SIoResult{ -errno, 0 };
            }

            int32_t w = co_await CEventLoop::current()->waitFd(_fd.get(), EFDE_READ, timeoutMs);
            if (w < 0) {
                co_return SIoResult{ w, 0 };
            }
        }
    }

    /* Closes the datagram socket. */
    void CDatagramSocket::close() noexcept {
        if (!_fd.isValid()) {
            return;
        }

        if (CEventLoop* loop = CEventLoop::current()) {
            loop->cancelFd(_fd.get());
        }

        _fd.reset();
    }

} // namespace sbox
