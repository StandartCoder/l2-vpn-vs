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
    
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (fd < 0)
        return -1;

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (hint && hint[0])
        strncpy(ifr.ifr_name, hint, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    struct vp_os_tap *t = calloc(1, sizeof(*t));
    t->fd = fd;
    strncpy(t->ifname, ifr.ifr_name, IFNAMSIZ);

    *tap = t;
    return 0;
}

int vp_os_tap_read(struct vp_os_tap *tap, uint8_t *buf, size_t max_len)
{
    return read(tap->fd, buf, max_len);
}

int vp_os_tap_write(struct vp_os_tap *tap, const uint8_t *buf, size_t len)
{
    return write(tap->fd, buf, len);
}

void vp_os_tap_close(struct vp_os_tap *tap)
{
    if (!tap) return;
    close(tap->fd);
    free(tap);
}