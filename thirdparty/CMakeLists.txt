# --> doctest is used as its single header only; its own CMake project is not needed.
if(SBOX_BUILD_TESTS)
    add_library(doctest INTERFACE)
    target_include_directories(doctest SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/doctest)
endif()

# --> libcertpp provides every cryptographic primitive libsbox needs (hashes, AEADs, X25519, ...).
# It is built static and without its tests, as a plain dependency.
set(CERTPP_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CERTPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(libcertpp EXCLUDE_FROM_ALL)
