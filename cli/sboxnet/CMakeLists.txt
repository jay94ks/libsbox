sbox_add_tool(sboxnet sboxnet SOURCES main.cpp DEPENDS net http vpn)

# --> modules/vol's daemon test executes this binary.
if(TARGET sbox_test_vol_daemons)
    add_dependencies(sbox_test_vol_daemons sboxnet)
endif()

# --> modules/vpn's plugin test runs this binary with the wg-overlay driver.
if(TARGET sbox_test_vpn_wg_plugin)
    add_dependencies(sbox_test_vpn_wg_plugin sboxnet)
    target_compile_definitions(sbox_test_vpn_wg_plugin PRIVATE SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin")
endif()
