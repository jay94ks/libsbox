sbox_add_module(e2e DEPENDS box oci image vol net archive http tls)

# --> End-to-end tests: they drive the built CLI tools, put a helper program into images and
# sandboxes, and compile the C++ example of README.md exactly as written.
if(SBOX_BUILD_TESTS)
    set(SBOX_E2E_HELPER_DIR ${CMAKE_CURRENT_BINARY_DIR}/helpers)

    add_executable(sbox_e2e_helper ${CMAKE_CURRENT_SOURCE_DIR}/testhelpers/e2ehelper.c)
    set_target_properties(sbox_e2e_helper PROPERTIES
        OUTPUT_NAME e2ehelper
        RUNTIME_OUTPUT_DIRECTORY ${SBOX_E2E_HELPER_DIR}
    )

    # --> The first ```cpp block of README.md becomes a program of its own. When the host has
    # no python3 the interpreter is swapped for /bin/sh (the test then feeds a shell script).
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${SBOX_ROOT}/README.md)
    file(READ ${SBOX_ROOT}/README.md SBOX_E2E_README)
    string(FIND "${SBOX_E2E_README}" "```cpp\n" SBOX_E2E_BEGIN)
    set(SBOX_E2E_README_PYTHON 1)

    if(SBOX_E2E_BEGIN GREATER -1)
        math(EXPR SBOX_E2E_BEGIN "${SBOX_E2E_BEGIN} + 7")
        string(SUBSTRING "${SBOX_E2E_README}" ${SBOX_E2E_BEGIN} -1 SBOX_E2E_REST)
        string(FIND "${SBOX_E2E_REST}" "```" SBOX_E2E_END)
        string(SUBSTRING "${SBOX_E2E_REST}" 0 ${SBOX_E2E_END} SBOX_E2E_EXAMPLE)

        if(NOT EXISTS /usr/bin/python3)
            string(REPLACE "\"/usr/bin/python3\"" "\"/bin/sh\"" SBOX_E2E_EXAMPLE "${SBOX_E2E_EXAMPLE}")
            set(SBOX_E2E_README_PYTHON 0)
        endif()
    else()
        set(SBOX_E2E_EXAMPLE "#error README.md has no cpp block\n")
    endif()

    # --> configure_file only touches the output when the text changed (no rebuild every configure).
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/readme_example.cpp.in "${SBOX_E2E_EXAMPLE}")
    configure_file(${CMAKE_CURRENT_BINARY_DIR}/readme_example.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/readme_example.cpp COPYONLY)

    add_executable(sbox_e2e_readme_example ${CMAKE_CURRENT_BINARY_DIR}/readme_example.cpp)
    target_link_libraries(sbox_e2e_readme_example PRIVATE sbox::box)
    set_target_properties(sbox_e2e_readme_example PROPERTIES
        OUTPUT_NAME readme_example
        RUNTIME_OUTPUT_DIRECTORY ${SBOX_E2E_HELPER_DIR}
    )
    sbox_apply_warnings(sbox_e2e_readme_example)

    file(GLOB SBOX_E2E_TESTS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/tests CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)
    foreach(SBOX_E2E_TEST ${SBOX_E2E_TESTS})
        string(REGEX REPLACE "\\.cpp$" "" SBOX_E2E_TEST ${SBOX_E2E_TEST})
        set(SBOX_E2E_TARGET sbox_test_e2e_${SBOX_E2E_TEST})
        target_compile_definitions(${SBOX_E2E_TARGET} PRIVATE
            SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin"
            SBOX_E2E_HELPER="${SBOX_E2E_HELPER_DIR}/e2ehelper"
            SBOX_E2E_README_EXAMPLE="${SBOX_E2E_HELPER_DIR}/readme_example"
            SBOX_E2E_README_PYTHON=${SBOX_E2E_README_PYTHON})
        add_dependencies(${SBOX_E2E_TARGET} sbox_e2e_helper sbox_e2e_readme_example)

        # --> The CLI tools are declared after the modules; add_dependencies resolves the names
        # when the build system is generated.
        if(SBOX_BUILD_CLI)
            add_dependencies(${SBOX_E2E_TARGET} sbox_tool sboxrun_tool sbox_image_cli sbox_cni sboxvol)
        endif()

        # --> Containers, image unpacking and registries: allow more than the default 300 s.
        set_tests_properties(e2e_${SBOX_E2E_TEST} PROPERTIES TIMEOUT 600)
    endforeach()
endif()
