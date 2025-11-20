if (NOT APPLE AND NOT WIN32)
    add_library(os_linux
        linux/os_net_linux.c
        linux/os_tap_linux.c
    )

    target_include_directories(os_linux PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/linux
    )
endif()

if (APPLE)
    add_library(os_macos
        macos/os_net_macos.c
        macos/os_tap_macos.c
    )

    target_include_directories(os_macos PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/macos
    )
endif()

if (WIN32)
    add_library(os_windows
        windows/os_net_windows.c
        windows/os_tap_windows.c
    )

    target_include_directories(os_windows PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/windows
    )
endif()
