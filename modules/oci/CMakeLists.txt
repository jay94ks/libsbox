sbox_add_module(oci DEPENDS box)

# --> The CLI tests run the built sbox/sboxrun binaries (cli/sbox adds the build dependency) and
# the tests read fixtures (runc's default config, Docker's seccomp profile) from tests/data.
foreach(SBOX_OCI_TEST sbox_test_oci_spec sbox_test_oci_seccomp sbox_test_oci_state sbox_test_oci_runtime sbox_test_oci_cli sbox_test_oci_compat sbox_test_oci_docker)
    if(TARGET ${SBOX_OCI_TEST})
        target_compile_definitions(${SBOX_OCI_TEST} PRIVATE
            SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin"
            SBOX_OCI_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
    endif()
endforeach()
