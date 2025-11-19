#include "../include/vp_debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>

#define VP_DEBUG_MAX_COMPONENTS 8

typedef struct {
    char name[16];
    vp_log_level_t level;
    int in_use;
} vp_log_component_level_t;

static int g_vp_log_enabled = 0;
static vp_log_level_t g_vp_log_default_level = VP_LOG_LEVEL_INFO;
static int g_vp_log_initialized = 0;
static vp_log_component_level_t g_vp_log_components[VP_DEBUG_MAX_COMPONENTS];

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
    g_vp_log_default_level = level;
}

static int vp_log_parse_level(const char *s, vp_log_level_t *out_level)
{
    if (!s || !*s)
        return 0;

    char *endptr = NULL;
    long v = strtol(s, &endptr, 10);
    if (endptr == s)
        return 0;

    if (v < VP_LOG_LEVEL_ERROR || v > VP_LOG_LEVEL_TRACE)
        return 0;

    *out_level = (vp_log_level_t)v;
    return 1;
}

static vp_log_level_t vp_log_get_effective_level(const char *component)
{
    if (!component || !component[0])
        return g_vp_log_default_level;

    for (int i = 0; i < VP_DEBUG_MAX_COMPONENTS; i++) {
        if (g_vp_log_components[i].in_use &&
            strcmp(g_vp_log_components[i].name, component) == 0) {
            return g_vp_log_components[i].level;
        }
    }

    return g_vp_log_default_level;
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

    // Allow disabling via "0" or "off"
    if (strcmp(env, "0") == 0 || strcasecmp(env, "off") == 0) {
        g_vp_log_enabled = 0;
        return;
    }

    g_vp_log_enabled = 1;
    g_vp_log_default_level = VP_LOG_LEVEL_INFO;

    // Copy to temp buffer for tokenizing
    char buf[256];
    strncpy(buf, env, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // Format:
    //   VP_DEBUG=3               -> global level INFO/DEBUG/...
    //   VP_DEBUG=switchd=4       -> per component
    //   VP_DEBUG=2,switchd=4     -> global=2, switchd override=4
    //
    // Unknown tokens are ignored.
    char *token = strtok(buf, ",");
    while (token) {
        // Trim leading spaces
        while (*token == ' ' || *token == '\t')
            token++;

        char *eq = strchr(token, '=');
        if (!eq) {
            // No "=", treat as global level if numeric
            vp_log_level_t lvl;
            if (vp_log_parse_level(token, &lvl))
                g_vp_log_default_level = lvl;
        } else {
            *eq = '\0';
            const char *name = token;
            const char *val_str = eq + 1;

            vp_log_level_t lvl;
            if (!vp_log_parse_level(val_str, &lvl)) {
                // invalid level → ignore
            } else {
                // Insert/update component override
                for (int i = 0; i < VP_DEBUG_MAX_COMPONENTS; i++) {
                    if (g_vp_log_components[i].in_use &&
                        strcmp(g_vp_log_components[i].name, name) == 0) {
                        g_vp_log_components[i].level = lvl;
                        name = NULL;
                        break;
                    }
                }

                if (name && *name) {
                    for (int i = 0; i < VP_DEBUG_MAX_COMPONENTS; i++) {
                        if (!g_vp_log_components[i].in_use) {
                            g_vp_log_components[i].in_use = 1;
                            strncpy(g_vp_log_components[i].name, name,
                                    sizeof(g_vp_log_components[i].name) - 1);
                            g_vp_log_components[i].name[sizeof(g_vp_log_components[i].name) - 1] = '\0';
                            g_vp_log_components[i].level = lvl;
                            break;
                        }
                    }
                }
            }
        }

        token = strtok(NULL, ",");
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

    vp_log_level_t effective = vp_log_get_effective_level(component);
    if (level > effective)
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

void vp_log_hexdump(vp_log_level_t level,
                    const char *component,
                    const char *func,
                    const char *prefix,
                    const unsigned char *data,
                    unsigned long len)
{
    if (!g_vp_log_initialized)
        vp_log_init_from_env();

    if (!g_vp_log_enabled)
        return;

    vp_log_level_t effective = vp_log_get_effective_level(component);
    if (level > effective)
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
    const char *pfx = prefix ? prefix : "hexdump";

    fprintf(stderr, "%s [%s] (%s) %s: %s len=%lu\n",
            time_buf, comp, lvl, fn, pfx, len);

    unsigned long offset = 0;
    while (offset < len) {
        fprintf(stderr, "  %04lx: ", offset);

        unsigned long line_end = offset + 16;
        for (unsigned long i = offset; i < line_end && i < len; i++) {
            fprintf(stderr, "%02x ", (unsigned int)data[i]);
        }

        // Optional ASCII column
        fprintf(stderr, " ");
        for (unsigned long i = offset; i < line_end && i < len; i++) {
            unsigned char c = data[i];
            if (c >= 32 && c <= 126)
                fputc(c, stderr);
            else
                fputc('.', stderr);
        }

        fprintf(stderr, "\n");
        offset = line_end;
    }
}
