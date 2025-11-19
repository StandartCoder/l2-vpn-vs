#include "../include/vp_debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

static int g_vp_log_enabled = 0;
static vp_log_level_t g_vp_log_level = VP_LOG_LEVEL_INFO;
static int g_vp_log_initialized = 0;

static const char *vp_log_level_to_str(vp_log_level_t level)
{
    switch (level) {
        case VP_LOG_LEVEL_ERROR: return "ERROR";
        case VP_LOG_LEVEL_WARN:  return "WARN";
        case VP_LOG_LEVEL_INFO:  return "INFO";
        case VP_LOG_LEVEL_DEBUG: return "DEBUG";
        case VP_LOG_LEVEL_TRACE: return "TRACE";
        default:                 return "?";
    }
}

void vp_log_set_enabled(int enabled)
{
    g_vp_log_enabled = enabled ? 1 : 0;
}

void vp_log_set_level(vp_log_level_t level)
{
    g_vp_log_level = level;
}

void vp_log_init_from_env(void)
{
    if (g_vp_log_initialized)
        return;

    g_vp_log_initialized = 1;

    const char *env = getenv("VP_DEBUG");
    if (!env || !env[0]) {
        g_vp_log_enabled = 0;
        return;
    }

    g_vp_log_enabled = 1;

    char *endptr = NULL;
    long val = strtol(env, &endptr, 10);
    if (endptr == env || val < VP_LOG_LEVEL_ERROR || val > VP_LOG_LEVEL_TRACE) {
        g_vp_log_level = VP_LOG_LEVEL_INFO;
    } else {
        g_vp_log_level = (vp_log_level_t)val;
    }
}

void vp_log_message(vp_log_level_t level,
                    const char *component,
                    const char *func,
                    const char *fmt,
                    ...)
{
    if (!g_vp_log_initialized)
        vp_log_init_from_env();

    if (!g_vp_log_enabled)
        return;

    if (level > g_vp_log_level)
        return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    char time_buf[32];
    if (tm) {
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);
    } else {
        strncpy(time_buf, "??:??:??", sizeof(time_buf));
        time_buf[sizeof(time_buf) - 1] = '\0';
    }

    const char *lvl = vp_log_level_to_str(level);
    const char *comp = component ? component : "?";
    const char *fn = func ? func : "?";

    fprintf(stderr, "%s [%s] (%s) %s: ", time_buf, comp, lvl, fn);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

