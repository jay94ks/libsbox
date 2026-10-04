#ifndef __INCLUDE_SBOX_ARCHIVE_CHECKSUM_HPP__
#define __INCLUDE_SBOX_ARCHIVE_CHECKSUM_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace archive {

    /**
     * Streaming CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320) as used by gzip and zip.
     * Not a cryptographic hash: it only detects accidental corruption.
     */
    class SBOX_API CCrc32 {
    private:
        uint32_t _state = 0xFFFFFFFFu;

    public:
        /**
         * Feeds bytes into the checksum.
         */
        void update(const SReadOnlyByteSpan& data) noexcept;

        /** Returns the checksum of everything fed so far. */
        inline uint32_t value() const noexcept { return _state ^ 0xFFFFFFFFu; }

        /** Starts over. */
        inline void reset() noexcept { _state = 0xFFFFFFFFu; }

        /**
         * Continues a finished CRC-32 value over more bytes (crc = 0 starts a new one).
         */
        static uint32_t extend(uint32_t crc, const uint8_t* data, size_t size) noexcept;

        /**
         * Computes the CRC-32 of a buffer in one call.
         */
        static uint32_t compute(const SReadOnlyByteSpan& data) noexcept;
    };

    /**
     * Streaming Adler-32 as used by the zlib container (RFC 1950).
     */
    class SBOX_API CAdler32 {
    private:
        uint32_t _a = 1;
        uint32_t _b = 0;

    public:
        /**
         * Feeds bytes into the checksum.
         */
        void update(const SReadOnlyByteSpan& data) noexcept;

        /** Returns the checksum of everything fed so far. */
        inline uint32_t value() const noexcept { return (_b << 16) | _a; }

        /** Starts over. */
        inline void reset() noexcept { _a = 1; _b = 0; }

        /**
         * Computes the Adler-32 of a buffer in one call.
         */
        static uint32_t compute(const SReadOnlyByteSpan& data) noexcept;
    };

    /**
     * Streaming XXH64 (the content checksum of zstd frames). Not a cryptographic hash.
     */
    class SBOX_API CXxHash64 {
    private:
        uint64_t _v[4];
        uint64_t _seed;
        uint64_t _total;
        uint8_t _buffer[32];
        uint32_t _buffered;

    public:
        /**
         * Starts a hash with the given seed (zstd uses 0).
         */
        explicit CXxHash64(uint64_t seed = 0) noexcept;

        /**
         * Starts over with the given seed.
         */
        void reset(uint64_t seed = 0) noexcept;

        /**
         * Feeds bytes into the hash.
         */
        void update(const SReadOnlyByteSpan& data) noexcept;

        /**
         * Returns the hash of everything fed so far (the state is not changed).
         */
        uint64_t digest() const noexcept;

        /**
         * Hashes a buffer in one call.
         */
        static uint64_t compute(const SReadOnlyByteSpan& data, uint64_t seed = 0) noexcept;
    };

}
}

#endif
