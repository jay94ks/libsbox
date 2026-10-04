#ifndef __INCLUDE_SBOX_CORE_SOCKET_HPP__
#define __INCLUDE_SBOX_CORE_SOCKET_HPP__

#include <sbox/common.hpp>
#include <sbox/core/stream.hpp>
#include <sys/socket.h>

namespace sbox {

    /**
     * Socket address of any family libsbox uses (IPv4, IPv6, UNIX path or abstract name).
     */
    struct SBOX_API SEndpoint {
        sockaddr_storage storage;
        socklen_t length;   // --> 0 means "no address".

        /**
         * Constructs an empty endpoint.
         */
        SEndpoint() noexcept;

        /** Returns the address family (AF_INET, AF_INET6, AF_UNIX) or AF_UNSPEC. */
        int family() const noexcept;

        /** Returns true when an address is set. */
        inline bool isValid() const noexcept { return length != 0; }

        /** Returns the port of an IP endpoint (host order), 0 otherwise. */
        uint16_t port() const noexcept;

        /** Sets the port of an IP endpoint. */
        void port(uint16_t value) noexcept;

        /**
         * Parses a numeric endpoint: "1.2.3.4:80", "[::1]:80", "unix:/run/x.sock", a bare
         * absolute path, or "@name" for the abstract UNIX namespace. Host names are not resolved
         * here (see ResolveEndpoints).
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SEndpoint& out) noexcept;

        /**
         * Builds an IP endpoint from a numeric address (no port in the text) and a port.
         */
        static int32_t fromIp(std::string_view address, uint16_t port, SEndpoint& out) noexcept;

        /**
         * Builds a UNIX endpoint ("@name" selects the abstract namespace).
         */
        static int32_t fromUnix(std::string_view path, SEndpoint& out) noexcept;

        /**
         * Formats the endpoint in the form parse() accepts.
         */
        std::string toString() const;
    };

    /**
     * Resolves "host:port" (or a numeric endpoint) to addresses. Names go through getaddrinfo on
     * a short-lived thread (CEventLoop::runBlocking), so this must not run in a process that is
     * about to fork.
     */
    SBOX_API TTask<int32_t> ResolveEndpoints(std::string host, uint16_t port, std::vector<SEndpoint>& out);

    /**
     * Connected stream socket (TCP or UNIX stream).
     */
    class SBOX_API CSocket : public CStream {
    public:
        CSocket() noexcept = default;

        /**
         * Wraps an already connected socket descriptor.
         */
        explicit CSocket(CFd fd) noexcept : CStream(std::move(fd)) {}

        /**
         * Connects to `endpoint`.
         * @return SBOX_OK or a negated errno (-ETIMEDOUT, -ECONNREFUSED, ...).
         */
        TTask<int32_t> connect(const SEndpoint& endpoint, int64_t timeoutMs = -1);

        /**
         * Half-closes the sending direction (the peer sees EOF).
         */
        int32_t shutdownWrite() noexcept;

        /**
         * Returns the local address.
         */
        SEndpoint localEndpoint() const noexcept;

        /**
         * Returns the peer address.
         */
        SEndpoint remoteEndpoint() const noexcept;

        /**
         * Sends bytes together with descriptors (SCM_RIGHTS) over a UNIX socket, without waiting.
         * Used for the OCI console socket. At least one byte must be sent.
         */
        int32_t sendFds(const SReadOnlyByteSpan& bytes, const std::vector<int>& fds) noexcept;

        /**
         * Receives bytes and descriptors (SCM_RIGHTS) over a UNIX socket, waiting for data.
         * @param fds Receives owned descriptors.
         */
        TTask<SIoResult> recvFds(const SByteSpan& bytes, std::vector<CFd>& fds, int64_t timeoutMs = -1);

        /**
         * Creates a connected UNIX stream socket pair.
         */
        static int32_t pair(CSocket& a, CSocket& b) noexcept;
    };

    /**
     * Listening stream socket.
     */
    class SBOX_API CListener {
    private:
        CFd _fd;

    public:
        CListener() noexcept = default;

        CListener(CListener&&) noexcept = default;

        CListener& operator=(CListener&& other) noexcept;

        ~CListener();

        /** Returns true when listening. */
        inline bool isValid() const noexcept { return _fd.isValid(); }

        /** Returns the raw descriptor. */
        inline int nativeHandle() const noexcept { return _fd.get(); }

        /**
         * Binds and listens. A UNIX path that exists as a stale socket is replaced.
         * @return SBOX_OK or a negated errno.
         */
        int32_t listen(const SEndpoint& endpoint, int32_t backlog = 128) noexcept;

        /**
         * Returns the bound address (useful after binding port 0).
         */
        SEndpoint localEndpoint() const noexcept;

        /**
         * Waits for and accepts a connection.
         */
        TTask<int32_t> accept(CSocket& out, int64_t timeoutMs = -1);

        /**
         * Stops listening, waking a pending accept with -ECANCELED.
         */
        void close() noexcept;
    };

    /**
     * Datagram socket (UDP, or UNIX datagram).
     */
    class SBOX_API CDatagramSocket {
    private:
        CFd _fd;

    public:
        CDatagramSocket() noexcept = default;

        CDatagramSocket(CDatagramSocket&&) noexcept = default;

        CDatagramSocket& operator=(CDatagramSocket&& other) noexcept;

        ~CDatagramSocket();

        /** Returns true when open. */
        inline bool isValid() const noexcept { return _fd.isValid(); }

        /** Returns the raw descriptor (for setsockopt such as UDP_ENCAP). */
        inline int nativeHandle() const noexcept { return _fd.get(); }

        /**
         * Opens a socket of `family` and binds it to `local` (when valid).
         */
        int32_t open(int family, const SEndpoint& local) noexcept;

        /**
         * Returns the bound address.
         */
        SEndpoint localEndpoint() const noexcept;

        /**
         * Sends one datagram without waiting (datagram sockets rarely block).
         */
        int32_t sendTo(const SReadOnlyByteSpan& bytes, const SEndpoint& to) noexcept;

        /**
         * Waits for and receives one datagram.
         * @param from Receives the sender address.
         */
        TTask<SIoResult> recvFrom(const SByteSpan& buffer, SEndpoint& from, int64_t timeoutMs = -1);

        /**
         * Closes the socket, waking a pending receive with -ECANCELED.
         */
        void close() noexcept;
    };

} // namespace sbox

#endif
