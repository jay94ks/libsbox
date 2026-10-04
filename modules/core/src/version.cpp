#include <sbox/version.hpp>

namespace sbox {

    /* Returns the version the library was compiled with. */
    SVersion GetLibraryVersion() noexcept {
        return HEADER_VERSION;
    }

} // namespace sbox
