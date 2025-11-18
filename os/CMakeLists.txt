add_library(os_linux
    linux/os_net_linux.c
    linux/os_tap_linux.c
)

target_include_directories(os_linux PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/linux
)