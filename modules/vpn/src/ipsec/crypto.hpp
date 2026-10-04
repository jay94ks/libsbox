#ifndef __SRC_VPN_IPSEC_CRYPTO_HPP__
#define __SRC_VPN_IPSEC_CRYPTO_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/hasher.hpp>
#include <vector>

// --> Private adapters between the ipsec code and libcertpp (hashes, HMAC, span conversion).

namespace sbox {
namespace vpn {
namespace ipsec {

    /** Converts an sbox read-only span to the identically laid out certpp one. */
    inline certpp::SReadOnlyByteSpan Cp(const SReadOnlyByteSpan& s) {
        return certpp::SReadOnlyByteSpan(s.data, s.size);
    }

    /** Converts an sbox mutable span to the identically laid out certpp one. */
    inline certpp::SByteSpan Cp(const SByteSpan& s) {
        return certpp::SByteSpan(s.data, s.size);
    }

    /** Hashes `data` with a certpp hasher (empty on failure). */
    std::vector<uint8_t> Hash(certpp::crypto::EHashers which, const SReadOnlyByteSpan& data);

    /** Hashes the concatenation of several parts. */
    std::vector<uint8_t> HashParts(certpp::crypto::EHashers which, std::initializer_list<SReadOnlyByteSpan> parts);

    /** HMAC of `data` keyed with `key` (empty on failure). */
    std::vector<uint8_t> Hmac(certpp::crypto::EHashers which, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& data);

    /** Returns the certpp hash behind an IKE PRF, or EHASH_UNKNOWN. */
    certpp::crypto::EHashers PrfHash(uint16_t prf);

    /** Returns the certpp hash behind an IKE integrity transform, or EHASH_UNKNOWN. */
    certpp::crypto::EHashers IntegHash(uint16_t integ);

    /** Appends bytes to a vector. */
    inline void Append(std::vector<uint8_t>& out, const SReadOnlyByteSpan& bytes) {
        if (bytes.size) {
            out.insert(out.end(), bytes.data, bytes.data + bytes.size);
        }
    }

    /** Appends a big-endian 16-bit value. */
    inline void PutBe16(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v));
    }

    /** Appends a big-endian 32-bit value. */
    inline void PutBe32(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back(uint8_t(v >> 24));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v));
    }

    /** Appends a big-endian 64-bit value. */
    inline void PutBe64(std::vector<uint8_t>& out, uint64_t v) {
        PutBe32(out, uint32_t(v >> 32));
        PutBe32(out, uint32_t(v));
    }

    /** Reads a big-endian 16-bit value. */
    inline uint16_t GetBe16(const uint8_t* p) {
        return uint16_t((uint16_t(p[0]) << 8) | p[1]);
    }

    /** Reads a big-endian 32-bit value. */
    inline uint32_t GetBe32(const uint8_t* p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
    }

    /** Reads a big-endian 64-bit value. */
    inline uint64_t GetBe64(const uint8_t* p) {
        return (uint64_t(GetBe32(p)) << 32) | GetBe32(p + 4);
    }

    /** Writes a big-endian 16-bit value in place. */
    inline void SetBe16(uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v >> 8);
        p[1] = uint8_t(v);
    }

    /** Writes a big-endian 32-bit value in place. */
    inline void SetBe32(uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v >> 24);
        p[1] = uint8_t(v >> 16);
        p[2] = uint8_t(v >> 8);
        p[3] = uint8_t(v);
    }

    /** Formats bytes as lowercase hex. */
    std::string ToHex(const SReadOnlyByteSpan& bytes, bool upper = false);

    /** Parses hex (whitespace and ':' ignored); false on a bad digit or odd count. */
    bool FromHex(std::string_view text, std::vector<uint8_t>& out);

}
}
}

#endif
