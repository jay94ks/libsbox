sbox_add_tool(sbox_wg sbox-wg SOURCES main.cpp DEPENDS vpn)

# --> modules/vpn's CLI test executes this binary.
if(TARGET sbox_test_vpn_wg_cli)
    add_dependencies(sbox_test_vpn_wg_cli sbox_wg)
    target_compile_definitions(sbox_test_vpn_wg_cli PRIVATE SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin")
endif()
