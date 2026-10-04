#ifndef __INCLUDE_SBOX_VERSION_HPP__
#define __INCLUDE_SBOX_VERSION_HPP__

#include <sbox/common.hpp>

namespace sbox {

    /**
     * Semantic version triple.
     */
    struct SVersion {
        uint16_t major;
        uint16_t minor;
        uint16_t patch;

        /**
         * Compares two versions for equality.
         */
        constexpr bool operator==(const SVersion& other) const noexcept {
            return major == other.major && minor == other.minor && patch == other.patch;
        }

        /**
         * Compares two versions for inequality.
         */
        constexpr bool operator!=(const SVersion& other) const noexcept {
            return !(*this == other);
        }
    };

    /**
     * Version of the headers the caller was compiled against. Bump this (and the version in the
     * root CMakeLists.txt) whenever the API or ABI changes.
     */
    constexpr SVersion HEADER_VERSION = { 0, 1, 0 };

    /**
     * Returns the version of the headers the library binary was compiled with.
     * Comparing it with HEADER_VERSION detects a header/binary mismatch.
     */
    SBOX_API SVersion GetLibraryVersion() noexcept;

} // namespace sbox

#endif
