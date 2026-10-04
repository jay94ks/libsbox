#ifndef __INCLUDE_SBOX_COMMON_HPP__
#define __INCLUDE_SBOX_COMMON_HPP__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

/**
 * Marks a type or free function whose definition lives out of line in a library source.
 * libsbox targets Linux only, so this is a visibility attribute rather than a dllexport switch:
 * the libraries are built with -fvisibility=hidden and only SBOX_API symbols are exported.
 */
#if defined(__SHARED_LIBSBOX__) && __SHARED_LIBSBOX__
    #define SBOX_API __attribute__((visibility("default")))
#else
    #define SBOX_API
#endif

namespace sbox {

    using uint8_t = ::uint8_t;
    using uint16_t = ::uint16_t;
    using uint32_t = ::uint32_t;
    using uint64_t = ::uint64_t;

    using int8_t = ::int8_t;
    using int16_t = ::int16_t;
    using int32_t = ::int32_t;
    using int64_t = ::int64_t;

    using float32_t = float;
    using float64_t = double;

    using size_t = ::size_t;
    using ssize_t = ::ssize_t;
    using ptrdiff_t = ::ptrdiff_t;
    using offset_t = ::off_t;
    using nullptr_t = decltype(nullptr);

    /**
     * Result code convention of libsbox.
     *
     * Almost every operation here is a thin layer over Linux system calls, and the errno a call
     * failed with is the most useful thing a caller (or the OCI runtime's error output) can get.
     * So instead of a library-specific code table, fallible functions return an `int32_t` that is
     * `SBOX_OK` (zero) on success and a *negated* errno value on failure (`-ENOENT`, `-EPERM`).
     * Functions that also produce a count return it as a non-negative value of the same type.
     */
    constexpr int32_t SBOX_OK = 0;

    using std::swap;
    using std::move;

} // namespace sbox

#endif
