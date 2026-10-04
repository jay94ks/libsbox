#ifndef __INCLUDE_SBOX_CORE_SPAN_HPP__
#define __INCLUDE_SBOX_CORE_SPAN_HPP__

#include <sbox/common.hpp>
#include <cstring>

namespace sbox {

    /**
     * Mutable, non-owning view over a contiguous run of elements.
     * The layout (`data`, `size`) matches certpp::TSpan so the two convert field by field.
     */
    template<typename T>
    struct TSpan {
        T* data;
        size_t size;    // --> Number of elements in the span.

        /**
         * Constructs a span over `count` elements starting at `ptr`.
         */
        constexpr TSpan(T* ptr = nullptr, size_t count = 0) noexcept
            : data(ptr), size(count) {}

        /**
         * Returns true when the span has no elements.
         */
        constexpr bool empty() const noexcept {
            return data == nullptr || size == 0;
        }

        /**
         * Returns a pointer to the first element.
         */
        constexpr T* begin() const noexcept {
            return data;
        }

        /**
         * Returns a pointer past the last element.
         */
        constexpr T* end() const noexcept {
            return data + size;
        }

        /**
         * Accesses an element by index without bounds checking.
         */
        constexpr T& operator[](size_t index) const noexcept {
            return data[index];
        }

        /**
         * Returns the sub-span [offset, offset + length), clamped to the span's bounds.
         */
        constexpr TSpan<T> slice(size_t offset, size_t length) const noexcept {
            if (offset >= size) {
                return TSpan<T>(nullptr, 0);
            }

            if (length > size - offset) {
                length = size - offset;
            }

            return TSpan<T>(data + offset, length);
        }

        /**
         * Returns the sub-span starting at `offset` up to the end.
         */
        constexpr TSpan<T> slice(size_t offset) const noexcept {
            return offset >= size ? TSpan<T>(nullptr, 0) : TSpan<T>(data + offset, size - offset);
        }
    };

    /**
     * Read-only, non-owning view over a contiguous run of elements.
     */
    template<typename T>
    struct TReadOnlySpan {
        const T* data;
        size_t size;    // --> Number of elements in the span.

        /**
         * Constructs a read-only span over `count` elements starting at `ptr`.
         */
        constexpr TReadOnlySpan(const T* ptr = nullptr, size_t count = 0) noexcept
            : data(ptr), size(count) {}

        /**
         * Implicitly views a mutable span as read-only.
         */
        constexpr TReadOnlySpan(const TSpan<T>& span) noexcept
            : data(span.data), size(span.size) {}

        /**
         * Returns true when the span has no elements.
         */
        constexpr bool empty() const noexcept {
            return data == nullptr || size == 0;
        }

        /**
         * Returns a pointer to the first element.
         */
        constexpr const T* begin() const noexcept {
            return data;
        }

        /**
         * Returns a pointer past the last element.
         */
        constexpr const T* end() const noexcept {
            return data + size;
        }

        /**
         * Accesses an element by index without bounds checking.
         */
        constexpr const T& operator[](size_t index) const noexcept {
            return data[index];
        }

        /**
         * Returns the sub-span [offset, offset + length), clamped to the span's bounds.
         */
        constexpr TReadOnlySpan<T> slice(size_t offset, size_t length) const noexcept {
            if (offset >= size) {
                return TReadOnlySpan<T>(nullptr, 0);
            }

            if (length > size - offset) {
                length = size - offset;
            }

            return TReadOnlySpan<T>(data + offset, length);
        }

        /**
         * Returns the sub-span starting at `offset` up to the end.
         */
        constexpr TReadOnlySpan<T> slice(size_t offset) const noexcept {
            return offset >= size ? TReadOnlySpan<T>(nullptr, 0) : TReadOnlySpan<T>(data + offset, size - offset);
        }

        /**
         * Returns true when both spans hold the same bytes.
         */
        inline bool equals(const TReadOnlySpan<T>& other) const noexcept {
            if (size != other.size) {
                return false;
            }

            return size == 0 || std::memcmp(data, other.data, size * sizeof(T)) == 0;
        }
    };

    using SByteSpan = TSpan<uint8_t>;
    using SReadOnlyByteSpan = TReadOnlySpan<uint8_t>;

    /**
     * Views the bytes of a string as a read-only byte span (no copy, no terminator).
     */
    inline SReadOnlyByteSpan BytesOf(std::string_view text) noexcept {
        return SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

    /**
     * Views the bytes of a byte vector as a read-only byte span.
     */
    inline SReadOnlyByteSpan BytesOf(const std::vector<uint8_t>& bytes) noexcept {
        return SReadOnlyByteSpan(bytes.data(), bytes.size());
    }

    /**
     * Views the bytes of a byte vector as a mutable byte span.
     */
    inline SByteSpan BytesOf(std::vector<uint8_t>& bytes) noexcept {
        return SByteSpan(bytes.data(), bytes.size());
    }

    /**
     * Views a read-only byte span as a string view.
     */
    inline std::string_view TextOf(const SReadOnlyByteSpan& bytes) noexcept {
        return std::string_view(reinterpret_cast<const char*>(bytes.data), bytes.size);
    }

} // namespace sbox

#endif
