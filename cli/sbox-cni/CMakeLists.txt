sbox_add_tool(sbox_cni sbox-cni SOURCES main.cpp DEPENDS net)

# --> modules/net's CNI test executes this binary.
if(TARGET sbox_test_net_cni)
    add_dependencies(sbox_test_net_cni sbox_cni)
endif()
