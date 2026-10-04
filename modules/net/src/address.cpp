#include <sbox/net/address.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <sys/random.h>
#include <sys/socket.h>

namespace sbox {
namespace net {

    namespace {

        /* Copies a string view into a terminated buffer; false when it does not fit. */
        bool copyText(std::string_view text, char* buffer, size_t capacity) noexcept {
            if (text.empty() || text.size() >= capacity) {
                return false;
            }

            std::memcpy(buffer, text.data(), text.size());
            buffer[text.size()] = 0;
            return true;
        }

        /* Parses a decimal number in [0, max]; false on junk or overflow. */
        bool parseDecimal(std::string_view text, uint32_t max, uint32_t& out) noexcept {
            if (text.empty() || text.size() > 10) {
                return false;
            }

            uint64_t value = 0;
            for (char c : text) {
                if (c < '0' || c > '9') {
                    return false;
                }

                value = value * 10 + uint64_t(c - '0');
            }

            if (value > max) {
                return false;
            }

            out = uint32_t(value);
            return true;
        }

        /* Returns the hex value of a digit or -1. */
        int32_t hexValue(char c) noexcept {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }

            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }

            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }

            return -1;
        }

    }

    /* Constructs an empty address. */
    SIpAddress::SIpAddress() noexcept : family(0) {
        std::memset(bytes, 0, sizeof(bytes));
    }

    /* Returns the socket family. */
    int SIpAddress::afamily() const noexcept {
        return family == 4 ? AF_INET : (family == 6 ? AF_INET6 : AF_UNSPEC);
    }

    /* Parses a numeric address. */
    int32_t SIpAddress::parse(std::string_view text, SIpAddress& out) noexcept {
        char buffer[INET6_ADDRSTRLEN + 1];
        if (!copyText(text, buffer, sizeof(buffer))) {
            return -EINVAL;
        }

        SIpAddress result;
        if (::inet_pton(AF_INET, buffer, result.bytes) == 1) {
            result.family = 4;
            out = result;
            return SBOX_OK;
        }

        if (::inet_pton(AF_INET6, buffer, result.bytes) == 1) {
            result.family = 6;
            out = result;
            return SBOX_OK;
        }

        return -EINVAL;
    }

    /* Builds an address from raw bytes. */
    int32_t SIpAddress::fromBytes(const uint8_t* data, size_t length, SIpAddress& out) noexcept {
        if (length != 4 && length != 16) {
            return -EINVAL;
        }

        out = SIpAddress();
        out.family = length == 4 ? 4 : 6;
        std::memcpy(out.bytes, data, length);
        return SBOX_OK;
    }

    /* Builds an IPv4 address from a host order value. */
    SIpAddress SIpAddress::fromV4(uint32_t hostOrder) noexcept {
        SIpAddress out;
        out.family = 4;
        uint32_t be = htonl(hostOrder);
        std::memcpy(out.bytes, &be, 4);
        return out;
    }

    /* Returns the IPv4 value in host order. */
    uint32_t SIpAddress::v4() const noexcept {
        if (family != 4) {
            return 0;
        }

        uint32_t be;
        std::memcpy(&be, bytes, 4);
        return ntohl(be);
    }

    /* Formats the address. */
    std::string SIpAddress::toString() const {
        char buffer[INET6_ADDRSTRLEN + 1];
        if (!isValid() || ::inet_ntop(afamily(), bytes, buffer, sizeof(buffer)) == nullptr) {
            return std::string();
        }

        return std::string(buffer);
    }

    /* Returns true for the unspecified address. */
    bool SIpAddress::isUnspecified() const noexcept {
        for (size_t i = 0; i < length(); ++i) {
            if (bytes[i] != 0) {
                return false;
            }
        }

        return isValid();
    }

    /* Returns true for loopback addresses. */
    bool SIpAddress::isLoopback() const noexcept {
        if (family == 4) {
            return bytes[0] == 127;
        }

        if (family == 6) {
            static const uint8_t LOOP[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            return std::memcmp(bytes, LOOP, 16) == 0;
        }

        return false;
    }

    /* Adds an offset with carry over the whole address. */
    SIpAddress SIpAddress::add(uint64_t offset) const noexcept {
        SIpAddress out = *this;
        size_t len = length();
        uint64_t carry = offset;

        // --> Byte-wise addition from the least significant byte: the offset is folded in
        // eight bits at a time together with the carry.
        for (size_t i = len; i > 0 && carry != 0; --i) {
            uint64_t sum = uint64_t(out.bytes[i - 1]) + (carry & 0xff);
            out.bytes[i - 1] = uint8_t(sum & 0xff);
            carry = (carry >> 8) + (sum >> 8);
        }

        return out;
    }

    /* Returns this - base when it fits 64 bits. */
    uint64_t SIpAddress::distanceFrom(const SIpAddress& base) const noexcept {
        if (family != base.family || !isValid()) {
            return UINT64_MAX;
        }

        size_t len = length();
        uint8_t diff[16];
        int32_t borrow = 0;

        for (size_t i = len; i > 0; --i) {
            int32_t d = int32_t(bytes[i - 1]) - int32_t(base.bytes[i - 1]) - borrow;
            borrow = d < 0 ? 1 : 0;
            diff[i - 1] = uint8_t(d & 0xff);
        }

        if (borrow) {
            return UINT64_MAX;
        }

        uint64_t value = 0;
        for (size_t i = 0; i < len; ++i) {
            if (len - i > 8) {
                if (diff[i] != 0) {
                    return UINT64_MAX;
                }

                continue;
            }

            value = (value << 8) | diff[i];
        }

        return value;
    }

    /* Compares two addresses. */
    int32_t SIpAddress::compare(const SIpAddress& other) const noexcept {
        if (family != other.family) {
            return family < other.family ? -1 : 1;
        }

        int32_t c = std::memcmp(bytes, other.bytes, length());
        return c < 0 ? -1 : (c > 0 ? 1 : 0);
    }

    /* Parses "addr/len". */
    int32_t SIpPrefix::parse(std::string_view text, SIpPrefix& out) noexcept {
        size_t slash = text.find('/');
        SIpPrefix result;

        if (SIpAddress::parse(text.substr(0, slash), result.address) != SBOX_OK) {
            return -EINVAL;
        }

        if (slash == std::string_view::npos) {
            result.length = uint8_t(result.address.bits());
        }
        else {
            uint32_t len = 0;
            if (!parseDecimal(text.substr(slash + 1), result.address.bits(), len)) {
                return -EINVAL;
            }

            result.length = uint8_t(len);
        }

        out = result;
        return SBOX_OK;
    }

    /* Formats "addr/len". */
    std::string SIpPrefix::toString() const {
        if (!isValid()) {
            return std::string();
        }

        return address.toString() + "/" + std::to_string(length);
    }

    /* Builds the netmask. */
    SIpAddress SIpPrefix::mask() const noexcept {
        SIpAddress out;
        out.family = address.family;
        uint32_t remaining = length;

        for (size_t i = 0; i < out.length(); ++i) {
            if (remaining >= 8) {
                out.bytes[i] = 0xff;
                remaining -= 8;
            }
            else {
                out.bytes[i] = uint8_t(0xff << (8 - remaining));
                remaining = 0;
            }
        }

        return out;
    }

    /* Clears the host bits. */
    SIpPrefix SIpPrefix::network() const noexcept {
        SIpPrefix out = *this;
        SIpAddress m = mask();

        for (size_t i = 0; i < out.address.length(); ++i) {
            out.address.bytes[i] &= m.bytes[i];
        }

        return out;
    }

    /* Returns true when the host bits are zero. */
    bool SIpPrefix::isNetwork() const noexcept {
        return network().address == address;
    }

    /* Returns true when the address is inside. */
    bool SIpPrefix::contains(const SIpAddress& addr) const noexcept {
        if (!isValid() || addr.family != address.family) {
            return false;
        }

        return SIpPrefix(addr, length).network().address == network().address;
    }

    /* Returns true when the subnets overlap. */
    bool SIpPrefix::overlaps(const SIpPrefix& other) const noexcept {
        if (!isValid() || !other.isValid() || address.family != other.address.family) {
            return false;
        }

        // --> Two prefixes overlap exactly when the shorter one contains the longer one.
        return length <= other.length ? contains(other.address) : other.contains(address);
    }

    /* Returns the last address. */
    SIpAddress SIpPrefix::last() const noexcept {
        SIpAddress out = network().address;
        SIpAddress m = mask();

        for (size_t i = 0; i < out.length(); ++i) {
            out.bytes[i] |= uint8_t(~m.bytes[i]);
        }

        return out;
    }

    /* Returns the subnet size. */
    uint64_t SIpPrefix::size() const noexcept {
        uint32_t hostBits = address.bits() - length;
        if (hostBits >= 64) {
            return UINT64_MAX;
        }

        return uint64_t(1) << hostBits;
    }

    /* Returns network + offset. */
    SIpAddress SIpPrefix::at(uint64_t offset) const noexcept {
        return network().address.add(offset);
    }

    /* Constructs an empty MAC. */
    SMacAddress::SMacAddress() noexcept : valid(false) {
        std::memset(bytes, 0, sizeof(bytes));
    }

    /* Parses a MAC address. */
    int32_t SMacAddress::parse(std::string_view text, SMacAddress& out) noexcept {
        if (text.size() != 17) {
            return -EINVAL;
        }

        SMacAddress result;
        for (size_t i = 0; i < 6; ++i) {
            int32_t hi = hexValue(text[i * 3]);
            int32_t lo = hexValue(text[i * 3 + 1]);
            if (hi < 0 || lo < 0) {
                return -EINVAL;
            }

            if (i < 5 && text[i * 3 + 2] != ':' && text[i * 3 + 2] != '-') {
                return -EINVAL;
            }

            result.bytes[i] = uint8_t(hi * 16 + lo);
        }

        result.valid = true;
        out = result;
        return SBOX_OK;
    }

    /* Builds a MAC from raw bytes. */
    SMacAddress SMacAddress::fromBytes(const uint8_t* data) noexcept {
        SMacAddress out;
        std::memcpy(out.bytes, data, 6);
        out.valid = true;
        return out;
    }

    /* Returns a random locally administered unicast MAC. */
    SMacAddress SMacAddress::random() noexcept {
        SMacAddress out;
        RandomBytes(out.bytes, 6);
        // --> Clear the multicast bit, set the locally administered bit.
        out.bytes[0] = uint8_t((out.bytes[0] & 0xfe) | 0x02);
        out.valid = true;
        return out;
    }

    /* Returns Docker's IPv4-derived MAC. */
    SMacAddress SMacAddress::fromIpv4(const SIpAddress& addr) noexcept {
        if (!addr.isV4()) {
            return random();
        }

        SMacAddress out;
        out.bytes[0] = 0x02;
        out.bytes[1] = 0x42;
        std::memcpy(out.bytes + 2, addr.bytes, 4);
        out.valid = true;
        return out;
    }

    /* Formats the MAC. */
    std::string SMacAddress::toString() const {
        if (!valid) {
            return std::string();
        }

        static const char HEX[] = "0123456789abcdef";
        std::string out;
        out.reserve(17);

        for (size_t i = 0; i < 6; ++i) {
            if (i) {
                out.push_back(':');
            }

            out.push_back(HEX[bytes[i] >> 4]);
            out.push_back(HEX[bytes[i] & 15]);
        }

        return out;
    }

    /* Compares MACs. */
    bool SMacAddress::operator==(const SMacAddress& other) const noexcept {
        return valid == other.valid && std::memcmp(bytes, other.bytes, 6) == 0;
    }

    /* Fills a buffer with random bytes. */
    void RandomBytes(uint8_t* out, size_t length) noexcept {
        size_t done = 0;

        while (done < length) {
            ssize_t n = ::getrandom(out + done, length - done, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                // --> getrandom cannot fail on supported kernels except for EINTR; fall back to
                // a weak but non-constant fill rather than leaving zeros.
                for (; done < length; ++done) {
                    out[done] = uint8_t((reinterpret_cast<uintptr_t>(out) >> (done % 8)) ^ done);
                }

                return;
            }

            done += size_t(n);
        }
    }

    /* Returns random hex characters. */
    std::string RandomHex(size_t length) {
        static const char HEX[] = "0123456789abcdef";
        std::vector<uint8_t> raw((length + 1) / 2);
        RandomBytes(raw.data(), raw.size());

        std::string out;
        out.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            uint8_t b = raw[i / 2];
            out.push_back(HEX[(i & 1) ? (b & 15) : (b >> 4)]);
        }

        return out;
    }

}
}
