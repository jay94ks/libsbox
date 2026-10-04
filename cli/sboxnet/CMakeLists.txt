sbox_add_tool(sboxnet sboxnet SOURCES main.cpp DEPENDS net http)

# --> modules/vol's daemon test executes this binary.
if(TARGET sbox_test_vol_daemons)
    add_dependencies(sbox_test_vol_daemons sboxnet)
endif()
