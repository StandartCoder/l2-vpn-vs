cmake_minimum_required(VERSION 3.10)

project(vpnet LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

add_subdirectory(core)
add_subdirectory(src)