sbox_add_tool(sboxvol sboxvol SOURCES main.cpp DEPENDS vol)

# --> modules/vol's daemon test executes this binary.
if(TARGET sbox_test_vol_daemons)
    add_dependencies(sbox_test_vol_daemons sboxvol)
endif()
