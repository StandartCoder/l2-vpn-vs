if (APPLE)
    # macOS: only build the vport daemon for now
    add_executable(vportd vportd.c)
    target_link_libraries(vportd core os_macos)
elseif (WIN32)
    # Windows: only build the vport daemon for now
    add_executable(vportd vportd.c)
    target_link_libraries(vportd core os_windows)
else()
    # Linux / other UNIX: build switchd + vportd with Linux backends
    add_executable(switchd switchd.c)
    add_executable(vportd vportd.c)
    target_link_libraries(switchd core os_linux)
    target_link_libraries(vportd core os_linux)
endif()
