#include "os_linux_common.h"
#include "../../include/os_tap.h"

#include <stdlib.h>

struct vp_os_tap {
    int fd;
    char ifname[IFNAMSIZ];
};

int vp_os_tap_open(struct vp_os_tap **tap, const char *hint)
{
    int fd = open(VP_LINUX_TAP_PATH, O_RDWR);

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

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (hint && hint[0])
        strncpy(ifr.ifr_name, hint, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    struct vp_os_tap *t = calloc(1, sizeof(*t));
    if (!t) {
        close(fd);
        return -1;
    }

    t->fd = fd;
    strncpy(t->ifname, ifr.ifr_name, IFNAMSIZ);

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
            // TAP expects whole frames; treat partial writes as failure.
            if ((size_t)w == len)
                return (int)w;
            return -1;
        }

        if (w == 0)
            return 0;

        if (errno == EINTR)
            continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Non-blocking TAP is temporarily full; treat as failure
            return -1;
        }

        return -1;
    }
}

void vp_os_tap_close(struct vp_os_tap *tap)
{
    if (!tap) return;
    close(tap->fd);
    free(tap);
}
