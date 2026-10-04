# sbox_add_module(<name>
#     [PUBLIC_HEADERS_IN_ROOT]        # headers live in <repo>/include/sbox/<name>/ (required modules)
#     [DEPENDS <module>...]           # other sbox modules, linked PUBLIC
#     [LINK <target>...]              # other targets (certpp::certpp, ...), linked PUBLIC
#     [PRIVATE_LINK <target>...])     # linked PRIVATE
#
# Builds modules/<name>/src/**/*.cpp into the library target `sbox_<name>` (alias `sbox::<name>`)
# and every modules/<name>/tests/**/*.cpp into its own doctest executable / CTest case named
# `<name>_<relative path with / replaced by _>`. Tests are labelled with the module name, so
# `ctest -L <name>` runs one module and plain `ctest -j` runs everything at once.
#
# Public headers of an optional module live in modules/<name>/include/sbox/<name>/; those of the
# required modules (core, box) live in the repository's include/sbox/ instead.
function(sbox_add_module NAME)
    cmake_parse_arguments(MOD "PUBLIC_HEADERS_IN_ROOT" "" "DEPENDS;LINK;PRIVATE_LINK" ${ARGN})

    set(MOD_DIR ${SBOX_ROOT}/modules/${NAME})
    file(GLOB_RECURSE MOD_SOURCES CONFIGURE_DEPENDS ${MOD_DIR}/src/*.cpp)

    if(SBOX_BUILD_SHARED)
        add_library(sbox_${NAME} SHARED ${MOD_SOURCES})
        set_target_properties(sbox_${NAME} PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            VERSION ${PROJECT_VERSION}
            SOVERSION ${PROJECT_VERSION_MAJOR}
        )
        target_compile_definitions(sbox_${NAME} PUBLIC __SHARED_LIBSBOX__=1)
    else()
        add_library(sbox_${NAME} STATIC ${MOD_SOURCES})
    endif()

    add_library(sbox::${NAME} ALIAS sbox_${NAME})

    target_include_directories(sbox_${NAME}
        PUBLIC $<BUILD_INTERFACE:${SBOX_ROOT}/include>
        PRIVATE ${MOD_DIR}/src
    )

    if(NOT MOD_PUBLIC_HEADERS_IN_ROOT)
        target_include_directories(sbox_${NAME} PUBLIC $<BUILD_INTERFACE:${MOD_DIR}/include>)
    endif()

    foreach(DEP ${MOD_DEPENDS})
        target_link_libraries(sbox_${NAME} PUBLIC sbox::${DEP})
    endforeach()

    if(MOD_LINK)
        target_link_libraries(sbox_${NAME} PUBLIC ${MOD_LINK})
    endif()

    if(MOD_PRIVATE_LINK)
        target_link_libraries(sbox_${NAME} PRIVATE ${MOD_PRIVATE_LINK})
    endif()

    sbox_apply_warnings(sbox_${NAME})

    if(SBOX_BUILD_TESTS)
        file(GLOB_RECURSE MOD_TESTS CONFIGURE_DEPENDS ${MOD_DIR}/tests/*.cpp)

        foreach(TEST_SOURCE ${MOD_TESTS})
            file(RELATIVE_PATH TEST_REL ${MOD_DIR}/tests ${TEST_SOURCE})
            string(REGEX REPLACE "\\.cpp$" "" TEST_REL ${TEST_REL})
            string(REPLACE "/" "_" TEST_NAME ${TEST_REL})

            add_executable(sbox_test_${NAME}_${TEST_NAME} ${TEST_SOURCE})
            target_link_libraries(sbox_test_${NAME}_${TEST_NAME} PRIVATE sbox::${NAME} doctest)
            target_include_directories(sbox_test_${NAME}_${TEST_NAME} PRIVATE ${MOD_DIR}/src)
            sbox_apply_warnings(sbox_test_${NAME}_${TEST_NAME})

            add_test(NAME ${NAME}_${TEST_NAME} COMMAND sbox_test_${NAME}_${TEST_NAME})
            set_tests_properties(${NAME}_${TEST_NAME} PROPERTIES LABELS ${NAME} TIMEOUT 300)
        endforeach()
    endif()
endfunction()

# sbox_apply_warnings(<target>): libsbox's warning set (and sanitizer) for its own targets only.
function(sbox_apply_warnings TARGET)
    target_compile_options(${TARGET} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wno-missing-field-initializers)

    if(SBOX_WERROR)
        target_compile_options(${TARGET} PRIVATE -Werror)
    endif()

    if(SBOX_SANITIZER)
        target_compile_options(${TARGET} PRIVATE -fsanitize=${SBOX_SANITIZER} -fno-omit-frame-pointer)
        target_link_options(${TARGET} PRIVATE -fsanitize=${SBOX_SANITIZER})
    endif()
endfunction()

# sbox_add_tool(<target> <output name> SOURCES <file>... DEPENDS <module>...)
# Builds a command line tool from cli/.
function(sbox_add_tool TARGET OUTPUT)
    cmake_parse_arguments(TOOL "" "" "SOURCES;DEPENDS" ${ARGN})

    add_executable(${TARGET} ${TOOL_SOURCES})
    set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME ${OUTPUT} RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

    foreach(DEP ${TOOL_DEPENDS})
        target_link_libraries(${TARGET} PRIVATE sbox::${DEP})
    endforeach()

    sbox_apply_warnings(${TARGET})
endfunction()
