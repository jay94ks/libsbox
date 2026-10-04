cmake_minimum_required(VERSION 3.20)

project(sbox
    VERSION 0.1.0
    DESCRIPTION "libsbox - Linux sandbox and OCI container runtime library"
    LANGUAGES C CXX
)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "libsbox only supports Linux")
endif()

# --> C++20 rather than libcertpp's C++17: the public API is coroutine based (co_await).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

option(SBOX_BUILD_SHARED "Build the sbox libraries as shared objects" OFF)
option(SBOX_BUILD_TESTS "Build the doctest test executables" ON)
option(SBOX_BUILD_CLI "Build the command line tools under cli/" ON)
option(SBOX_WERROR "Treat compiler warnings as errors in libsbox's own targets" OFF)
set(SBOX_SANITIZER "" CACHE STRING "Sanitizer for libsbox's own targets: address, undefined, thread or empty")

set(SBOX_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
list(APPEND CMAKE_MODULE_PATH ${SBOX_ROOT}/cmake)
include(SboxModule)

if(SBOX_BUILD_TESTS)
    enable_testing()
endif()

add_subdirectory(thirdparty)

# --> Every modules/<name>/CMakeLists.txt is picked up, so adding a module touches no shared file.
# Order does not matter: a DEPENDS on sbox::<other> is resolved when CMake generates, not here.
# Each module is described in docs/<name>.md.
file(GLOB SBOX_MODULE_LISTS RELATIVE ${SBOX_ROOT}/modules ${SBOX_ROOT}/modules/*/CMakeLists.txt)
list(SORT SBOX_MODULE_LISTS)

foreach(SBOX_MODULE_LIST ${SBOX_MODULE_LISTS})
    get_filename_component(SBOX_MODULE ${SBOX_MODULE_LIST} DIRECTORY)
    add_subdirectory(modules/${SBOX_MODULE})
endforeach()

if(SBOX_BUILD_CLI AND EXISTS ${SBOX_ROOT}/cli/CMakeLists.txt)
    add_subdirectory(cli)
endif()
