add_executable(switchd switchd.c)
add_executable(vportd vportd.c)

target_link_libraries(switchd core)
target_link_libraries(vportd core)