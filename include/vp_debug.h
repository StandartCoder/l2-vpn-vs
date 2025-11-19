#ifndef VP_DEBUG_H
#define VP_DEBUG_H

#include <stdarg.h>

typedef enum {
    VP_LOG_LEVEL_ERROR = 0,
    VP_LOG_LEVEL_WARN  = 1,
    VP_LOG_LEVEL_INFO  = 2,
    VP_LOG_LEVEL_DEBUG = 3,
    VP_LOG_LEVEL_TRACE = 4
} vp_log_level_t;

// Initialize logging from environment:
//   VP_DEBUG unset/empty  -> logging disabled
//   VP_DEBUG=N            -> enable with level N (0-4), default INFO when invalid
void vp_log_init_from_env(void);

// Explicit control (optional)
void vp_log_set_enabled(int enabled);
void vp_log_set_level(vp_log_level_t level);

// Core logging primitive
void vp_log_message(vp_log_level_t level,
                    const char *component,
                    const char *func,
                    const char *fmt,
                    ...);

// Convenience macro capturing function name
#define VP_LOG(level, component, fmt, ...) \
    vp_log_message((level), (component), __func__, fmt, ##__VA_ARGS__)

#endif

