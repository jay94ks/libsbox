# --> Every cli/<tool>/CMakeLists.txt is picked up; each declares its executables with
# sbox_add_tool(). Binaries land in <build>/bin.
file(GLOB SBOX_TOOL_LISTS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt)
list(SORT SBOX_TOOL_LISTS)

foreach(SBOX_TOOL_LIST ${SBOX_TOOL_LISTS})
    get_filename_component(SBOX_TOOL ${SBOX_TOOL_LIST} DIRECTORY)
    add_subdirectory(${SBOX_TOOL})
endforeach()
