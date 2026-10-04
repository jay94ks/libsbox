#ifndef __SRC_TLS_WIRE_HPP__
#define __SRC_TLS_WIRE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <cstring>

namespace sbox {
namespace tls {

    /**
     * Appends big-endian integers and length-prefixed blocks to a byte vector, the way TLS
     * structures are encoded. Nested blocks are opened with begin*() and closed with end(),
     * which back-patches the length prefix.
     */
    class Writer {
    private:
        std::vector<uint8_t>& _out;
        std::vector<std::pair<size_t, uint8_t>> _open;     // --> (prefix offset, prefix width).

    public:
        explicit Writer(std::vector<uint8_t>& out) : _out(out) {}

        /** Appends one byte. */
        inline void u8(uint32_t v) { _out.push_back(uint8_t(v)); }

        /** Appends a 16-bit big-endian value. */
        inline void u16(uint32_t v) { u8(v >> 8); u8(v); }

        /** Appends a 24-bit big-endian value. */
        inline void u24(uint32_t v) { u8(v >> 16); u8(v >> 8); u8(v); }

        /** Appends raw bytes. */
        inline void bytes(const SReadOnlyByteSpan& b) {
            if (b.size) {
                _out.insert(_out.end(), b.data, b.data + b.size);
            }
        }

        /** Appends raw bytes. */
        inline void bytes(const std::vector<uint8_t>& b) { bytes(BytesOf(b)); }

        /** Opens a block with a length prefix of `width` bytes (1, 2 or 3). */
        inline void begin(uint8_t width) {
            _open.emplace_back(_out.size(), width);
            _out.resize(_out.size() + width);
        }

        /** Closes the innermost block, writing its length into the prefix. */
        inline void end() {
            auto [at, width] = _open.back();
            _open.pop_back();

            size_t len = _out.size() - at - width;
            for (uint8_t i = 0; i < width; ++i) {
                _out[at + width - 1 - i] = uint8_t(len >> (8 * i));
            }
        }

        /** Returns the number of bytes written so far. */
        inline size_t size() const { return _out.size(); }
    };

    /**
     * Reads big-endian integers and length-prefixed blocks from a span. Any read past the end
     * sets a sticky failure flag and yields zeroes, so a parser can read a whole structure and
     * check ok() once.
     */
    class Reader {
    private:
        SReadOnlyByteSpan _data;
        size_t _pos = 0;
        bool _failed = false;

    public:
        Reader() = default;

        explicit Reader(const SReadOnlyByteSpan& data) : _data(data) {}

        /** Returns true when no read has failed. */
        inline bool ok() const { return !_failed; }

        /** Returns true when every byte was consumed and no read failed. */
        inline bool done() const { return !_failed && _pos == _data.size; }

        /** Returns the number of unread bytes. */
        inline size_t left() const { return _failed ? 0 : _data.size - _pos; }

        /** Marks the reader failed. */
        inline void fail() { _failed = true; }

        /** Reads one byte. */
        inline uint32_t u8() {
            if (left() < 1) { _failed = true; return 0; }
            return _data[_pos++];
        }

        /** Reads a 16-bit big-endian value. */
        inline uint32_t u16() {
            if (left() < 2) { _failed = true; return 0; }
            uint32_t v = (uint32_t(_data[_pos]) << 8) | _data[_pos + 1];
            _pos += 2;
            return v;
        }

        /** Reads a 24-bit big-endian value. */
        inline uint32_t u24() {
            if (left() < 3) { _failed = true; return 0; }
            uint32_t v = (uint32_t(_data[_pos]) << 16) | (uint32_t(_data[_pos + 1]) << 8) | _data[_pos + 2];
            _pos += 3;
            return v;
        }

        /** Reads `n` raw bytes as a span (empty on failure). */
        inline SReadOnlyByteSpan bytes(size_t n) {
            if (left() < n) { _failed = true; return SReadOnlyByteSpan(); }
            SReadOnlyByteSpan s(_data.data + _pos, n);
            _pos += n;
            return s;
        }

        /** Reads a block with a length prefix of `width` bytes and returns a reader over it. */
        inline Reader block(uint8_t width) {
            size_t n = width == 1 ? u8() : width == 2 ? u16() : u24();
            Reader sub(bytes(n));
            if (_failed) {
                sub._failed = true;
            }
            return sub;
        }

        /** Reads the remaining bytes. */
        inline SReadOnlyByteSpan rest() { return bytes(left()); }
    };

    /** Copies a span into a new vector. */
    inline std::vector<uint8_t> ToVector(const SReadOnlyByteSpan& s) {
        return s.size ? std::vector<uint8_t>(s.data, s.data + s.size) : std::vector<uint8_t>();
    }

}
}

#endif
