#ifdef __APPLE__

#include "os_macos_common.h"
#include "../../include/os_tap.h"
#include "tap_emulator.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct vp_os_tap {
    int fd;
};

int vp_os_tap_open(struct vp_os_tap **tap, const char *hint)
{
    int fd = tap_emulator_open(hint ? hint : "tap0");
    if (fd < 0)
        return -1;

    struct vp_os_tap *t = calloc(1, sizeof(*t));
    if (!t) {
        tap_emulator_close(fd);
        return -1;
    }

    t->fd = fd;
    *tap = t;
    return 0;
}

int vp_os_tap_read(struct vp_os_tap *tap, uint8_t *buf, size_t max_len)
{
    if (!tap)
        return -1;

    ssize_t r = tap_emulator_read(tap->fd, buf, max_len);
    if (r < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    return (int)r;
}

int vp_os_tap_write(struct vp_os_tap *tap, const uint8_t *buf, size_t len)
{
    if (!tap)
        return -1;

    ssize_t w = tap_emulator_write(tap->fd, buf, len);
    if (w < 0)
        return -1;
    return (int)w;
}

void vp_os_tap_close(struct vp_os_tap *tap)
{
    if (!tap)
        return;
    tap_emulator_close(tap->fd);
    free(tap);
}

#endif // __APPLE__
