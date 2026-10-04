sbox_add_module(box PUBLIC_HEADERS_IN_ROOT DEPENDS core)

# --> Tiny programs the sandbox tests run inside the sandbox (fork bomb, memory hog, a denied
# system call, a CPU burner). They live in their own directory so the tests can bind it.
if(SBOX_BUILD_TESTS)
    set(SBOX_BOX_HELPER_DIR ${CMAKE_CURRENT_BINARY_DIR}/helpers)

    foreach(HELPER forkbomb memhog badsyscall cpuburn)
        add_executable(sbox_box_helper_${HELPER} ${CMAKE_CURRENT_SOURCE_DIR}/testhelpers/${HELPER}.c)
        set_target_properties(sbox_box_helper_${HELPER} PROPERTIES
            OUTPUT_NAME ${HELPER}
            RUNTIME_OUTPUT_DIRECTORY ${SBOX_BOX_HELPER_DIR}
        )
        add_dependencies(sbox_test_box_sandbox sbox_box_helper_${HELPER})
    endforeach()

    target_compile_definitions(sbox_test_box_sandbox PRIVATE SBOX_BOX_HELPERS="${SBOX_BOX_HELPER_DIR}")
endif()
