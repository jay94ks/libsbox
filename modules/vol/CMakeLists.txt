sbox_add_module(vol DEPENDS archive http)

# --> The daemon test runs the built sboxvol / sboxnet binaries (cli/ adds the build dependency).
if(TARGET sbox_test_vol_daemons)
    target_compile_definitions(sbox_test_vol_daemons PRIVATE SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin")
    target_link_libraries(sbox_test_vol_daemons PRIVATE sbox::net)
endif()
