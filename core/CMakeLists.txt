add_library(core
    switch_core.c
    protocol.c
    debug.c
)

target_include_directories(core PUBLIC ../include)
