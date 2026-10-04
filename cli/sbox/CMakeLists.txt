# --> One set of sources, two names: `sbox` for people, `sboxrun` for dockerd/containerd
# (registered as a runc-compatible runtime binary).
set(SBOX_CLI_SOURCES main.cpp commands.cpp console.cpp)

sbox_add_tool(sbox_tool sbox SOURCES ${SBOX_CLI_SOURCES} DEPENDS oci)
sbox_add_tool(sboxrun_tool sboxrun SOURCES ${SBOX_CLI_SOURCES} DEPENDS oci)

# --> The oci module's CLI tests execute both binaries.
foreach(SBOX_OCI_CLI_TEST sbox_test_oci_cli sbox_test_oci_compat)
    if(TARGET ${SBOX_OCI_CLI_TEST})
        add_dependencies(${SBOX_OCI_CLI_TEST} sbox_tool sboxrun_tool)
    endif()
endforeach()
