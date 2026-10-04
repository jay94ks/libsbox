sbox_add_module(net DEPENDS core)

# --> The CNI test runs the built sbox-cni binary (cli/sbox-cni adds the build dependency).
if(TARGET sbox_test_net_cni)
    target_compile_definitions(sbox_test_net_cni PRIVATE SBOX_TEST_BIN_DIR="${CMAKE_BINARY_DIR}/bin")
endif()
