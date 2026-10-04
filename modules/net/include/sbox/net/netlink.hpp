#ifndef __INCLUDE_SBOX_NET_NETLINK_HPP__
#define __INCLUDE_SBOX_NET_NETLINK_HPP__

#include <sbox/common.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/task.hpp>
#include <sbox/net/address.hpp>
#include <coroutine>
#include <deque>

namespace sbox {
namespace net {

    /**
     * Builder of one netlink message: header, fixed family header and (nested) attributes.
     *
     * The length field of the netlink header is kept up to date after every append, so the
     * message can be sent at any point. Nested attributes carry NLA_F_NESTED.
     */
    class SBOX_API CNlMessage {
    private:
        std::vector<uint8_t> _buffer;

    public:
        /**
         * Starts a message of `type` with `flags` (NLM_F_REQUEST is added on send).
         */
        CNlMessage(uint16_t type, uint16_t flags = 0);

        /**
         * Starts a generic netlink message (family id as type, genlmsghdr appended).
         */
        static CNlMessage genl(uint16_t familyId, uint8_t command, uint8_t version, uint16_t flags = 0);

        /** Returns the message type. */
        uint16_t type() const noexcept;

        /** Returns the netlink flags. */
        uint16_t flags() const noexcept;

        /** Replaces the netlink flags. */
        void flags(uint16_t value) noexcept;

        /** Returns the sequence number. */
        uint32_t seq() const noexcept;

        /** Sets the sequence number. */
        void seq(uint32_t value) noexcept;

        /**
         * Appends the fixed family header (ifinfomsg, rtmsg, nfgenmsg, ...), 4-byte aligned.
         */
        void putHeader(const void* data, size_t length);

        /**
         * Appends an attribute with a raw payload.
         */
        void put(uint16_t type, const void* data, size_t length);

        /** Appends an empty (flag) attribute. */
        void putFlag(uint16_t type);

        /** Appends an 8-bit attribute. */
        void putU8(uint16_t type, uint8_t value);

        /** Appends a 16-bit host order attribute. */
        void putU16(uint16_t type, uint16_t value);

        /** Appends a 32-bit host order attribute. */
        void putU32(uint16_t type, uint32_t value);

        /** Appends a 64-bit host order attribute. */
        void putU64(uint16_t type, uint64_t value);

        /** Appends a 16-bit big-endian attribute. */
        void putBe16(uint16_t type, uint16_t value);

        /** Appends a 32-bit big-endian attribute. */
        void putBe32(uint16_t type, uint32_t value);

        /** Appends a 64-bit big-endian attribute. */
        void putBe64(uint16_t type, uint64_t value);

        /** Appends a NUL-terminated string attribute. */
        void putString(uint16_t type, std::string_view value);

        /** Appends the raw bytes of an IP address (4 or 16 bytes). */
        void putAddress(uint16_t type, const SIpAddress& value);

        /**
         * Opens a nested attribute; returns the token endNested() closes.
         */
        size_t beginNested(uint16_t type);

        /**
         * Closes a nested attribute opened by beginNested().
         */
        void endNested(size_t token) noexcept;

        /** Returns the encoded message. */
        inline const std::vector<uint8_t>& bytes() const noexcept { return _buffer; }

        /** Returns the encoded message length. */
        inline size_t size() const noexcept { return _buffer.size(); }
    };

    /**
     * One attribute inside a received message (views the receive buffer).
     */
    struct SBOX_API SNlAttr {
        uint16_t type;          // --> Attribute type without the NESTED/BYTEORDER flags.
        const uint8_t* data;
        size_t length;

        /** Returns the payload as u8 (0 when too short). */
        uint8_t u8() const noexcept;

        /** Returns the payload as host order u16 (0 when too short). */
        uint16_t u16() const noexcept;

        /** Returns the payload as host order u32 (0 when too short). */
        uint32_t u32() const noexcept;

        /** Returns the payload as host order u64 (0 when too short). */
        uint64_t u64() const noexcept;

        /** Returns the payload as big-endian u16 converted to host order. */
        uint16_t be16() const noexcept;

        /** Returns the payload as big-endian u32 converted to host order. */
        uint32_t be32() const noexcept;

        /** Returns the payload as a string (up to the first NUL). */
        std::string str() const;

        /** Returns the payload as an IP address (4 or 16 bytes), or an invalid one. */
        SIpAddress address() const noexcept;
    };

    /**
     * Parsed list of attributes in the order they appeared.
     */
    class SBOX_API CNlAttrs {
    private:
        std::vector<SNlAttr> _items;

    public:
        CNlAttrs() = default;

        /**
         * Parses attributes from `data`; trailing garbage is ignored.
         */
        CNlAttrs(const uint8_t* data, size_t length);

        /**
         * Parses the attributes of a nested attribute.
         */
        static CNlAttrs nested(const SNlAttr& attr);

        /** Returns the first attribute of `type`, or nullptr. */
        const SNlAttr* find(uint16_t type) const noexcept;

        /** Returns all attributes. */
        inline const std::vector<SNlAttr>& items() const noexcept { return _items; }

        /** Returns the u32 of `type` or `fallback`. */
        uint32_t u32(uint16_t type, uint32_t fallback = 0) const noexcept;

        /** Returns the string of `type` or an empty string. */
        std::string str(uint16_t type) const;
    };

    /**
     * Received netlink message (copied out of the receive buffer).
     */
    struct SBOX_API SNlReply {
        uint16_t type;
        uint16_t flags;
        std::vector<uint8_t> payload;   // --> Everything after the netlink header.

        /**
         * Parses the attributes that follow a fixed family header of `headerSize` bytes.
         */
        CNlAttrs attrs(size_t headerSize) const;
    };

    /**
     * Netlink socket bound to the netns it was opened in, driven by the calling thread's
     * CEventLoop.
     *
     * Requests are serialized: a second coroutine calling request() while one is in flight waits
     * its turn, so one socket can be shared by concurrent tasks. Every request carries its own
     * sequence number; stale replies (from timed out requests) are discarded. Errors come back
     * as negated errno and the kernel's extended ACK message is kept in lastError().
     */
    class SBOX_API CNetlinkSocket {
    private:
        CFd _fd;
        int _protocol;
        uint32_t _seq;
        uint32_t _portId;
        bool _busy;
        std::deque<std::coroutine_handle<>> _waiters;
        std::string _lastError;

    public:
        CNetlinkSocket() noexcept;

        CNetlinkSocket(CNetlinkSocket&&) noexcept = default;

        CNetlinkSocket& operator=(CNetlinkSocket&&) noexcept = default;

        ~CNetlinkSocket();

        /**
         * Opens a socket of `protocol` (NETLINK_ROUTE, NETLINK_NETFILTER, NETLINK_GENERIC).
         * @param netnsPath Network namespace to open the socket in (empty: the current one).
         *        The socket keeps operating on that namespace for its whole life.
         * @return SBOX_OK or a negated errno.
         */
        int32_t open(int protocol, const std::string& netnsPath = std::string()) noexcept;

        /**
         * Opens a socket of `protocol` inside the namespace referred to by `netnsFd`.
         */
        int32_t openIn(int protocol, int netnsFd) noexcept;

        /** Returns true when open. */
        inline bool isValid() const noexcept { return _fd.isValid(); }

        /** Returns the raw descriptor. */
        inline int nativeHandle() const noexcept { return _fd.get(); }

        /** Returns the netlink protocol. */
        inline int protocol() const noexcept { return _protocol; }

        /** Returns the extended ACK text (or a summary) of the last failed request. */
        inline const std::string& lastError() const noexcept { return _lastError; }

        /**
         * Sends a request and waits for its ACK (NLM_F_ACK is added). Replies the kernel sends
         * before the ACK (NLM_F_ECHO, GET requests) are appended to `replies` when given.
         * @return SBOX_OK or a negated errno (the kernel's error, or -ETIMEDOUT).
         */
        TTask<int32_t> request(CNlMessage& message, std::vector<SNlReply>* replies = nullptr, int64_t timeoutMs = 5000);

        /**
         * Sends a dump request (NLM_F_DUMP added) and collects every multipart reply until
         * NLMSG_DONE. A dump interrupted by concurrent changes is retried a few times.
         */
        TTask<int32_t> dump(CNlMessage& message, std::vector<SNlReply>& replies, int64_t timeoutMs = 5000);

        /**
         * Sends several messages in one datagram (nfnetlink batch) and waits until each message
         * that asked for an ACK got one, or the batch failed.
         * @param messages Messages in order; sequence numbers are assigned here. Messages with
         *        NLM_F_ACK in their flags are waited for.
         * @return SBOX_OK or the first error the kernel reported.
         */
        TTask<int32_t> batch(std::vector<CNlMessage>& messages, int64_t timeoutMs = 5000);

        /**
         * Joins a multicast group (for notifications read with receive()).
         */
        int32_t joinGroup(uint32_t group) noexcept;

        /**
         * Waits for and returns the next datagram's messages (multicast notifications).
         */
        TTask<int32_t> receive(std::vector<SNlReply>& out, int64_t timeoutMs = -1);

        /**
         * Closes the socket.
         */
        void close() noexcept;

    private:
        struct SLockAwaiter {
            CNetlinkSocket* socket;

            bool await_ready() const noexcept;

            void await_suspend(std::coroutine_handle<> h);

            inline void await_resume() const noexcept {}
        };

        /** Waits until no other request is in flight. */
        inline SLockAwaiter lock() noexcept { return SLockAwaiter{ this }; }

        /** Hands the socket to the next waiter. */
        void unlock() noexcept;

        /** Returns the next sequence number. */
        uint32_t nextSeq() noexcept;

        /** Sends a buffer as one datagram. */
        TTask<int32_t> sendBuffer(const std::vector<uint8_t>& buffer, int64_t deadline);

        /** Receives one datagram into `buffer`; returns its length or an error. */
        TTask<int32_t> recvBuffer(std::vector<uint8_t>& buffer, int64_t deadline);

        /** Runs one exchange without taking the lock. */
        TTask<int32_t> exchange(const std::vector<uint8_t>& out, std::vector<uint32_t> ackSeqs, uint32_t batchSeq,
            uint32_t dumpSeq, std::vector<SNlReply>* replies, int64_t timeoutMs);
    };

    /**
     * Generic netlink family description (CTRL_CMD_GETFAMILY).
     */
    struct SGenlFamily {
        uint16_t id = 0;
        uint32_t version = 0;
        uint32_t headerSize = 0;
        uint32_t maxAttr = 0;
        std::vector<std::pair<std::string, uint32_t>> groups;     // --> Multicast group names and ids.
    };

    /**
     * Resolves a generic netlink family by name ("nlctrl", "wireguard", ...).
     * @param socket A NETLINK_GENERIC socket.
     * @return SBOX_OK, -ENOENT when the family is not registered, or another error.
     */
    SBOX_API TTask<int32_t> ResolveGenlFamily(CNetlinkSocket& socket, std::string name, SGenlFamily& out);

}
}

#endif
