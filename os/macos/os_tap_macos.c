#include "os_macos_common.h"
#include "../../include/os_tap.h"

#include <stdlib.h>
#include <stdio.h>

// On macOS we require a /dev/tapX style device as provided
// by a tun/tap kernel extension (e.g. tuntaposx). The daemon
// expects to see raw Ethernet frames, same as on Linux.

struct vp_os_tap {
    int fd;
    char ifname[IFNAMSIZ];
};

static int vp_open_tap(const char *hint)
{
    char path[64];

    if (hint && hint[0]) {
        // Use the requested interface name directly, e.g. "tap0"
        snprintf(path, sizeof(path), "/dev/%s", hint);
    } else {
        // Default to tap0
        snprintf(path, sizeof(path), "/dev/tap0");
    }

    int fd = open(path, O_RDWR);
    if (fd < 0)
        return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int vp_os_tap_open(struct vp_os_tap **tap, const char *hint)
{
    int fd = vp_open_tap(hint);
    if (fd < 0)
        return -1;

    struct vp_os_tap *t = calloc(1, sizeof(*t));
    if (!t) {
        close(fd);
        return -1;
    }

    t->fd = fd;

    if (hint && hint[0]) {
        strncpy(t->ifname, hint, IFNAMSIZ);
        t->ifname[IFNAMSIZ - 1] = '\0';
    } else {
        strncpy(t->ifname, "tap0", IFNAMSIZ);
        t->ifname[IFNAMSIZ - 1] = '\0';
    }

    *tap = t;
    return 0;
}

int vp_os_tap_read(struct vp_os_tap *tap, uint8_t *buf, size_t max_len)
{
    for (;;) {
        ssize_t r = read(tap->fd, buf, max_len);
        if (r > 0)
            return (int)r;

        if (r == 0)
            return 0;

        if (errno == EINTR)
            continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        return -1;
    }
}

int vp_os_tap_write(struct vp_os_tap *tap, const uint8_t *buf, size_t len)
{
    for (;;) {
        ssize_t w = write(tap->fd, buf, len);
        if (w > 0) {
            if ((size_t)w == len)
                return (int)w;
            return -1;
        }

        if (w == 0)
            return 0;

        if (errno == EINTR)
            continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1;

        return -1;
    }
}

void vp_os_tap_close(struct vp_os_tap *tap)
{
    if (!tap) return;
    close(tap->fd);
    free(tap);
}
