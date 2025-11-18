#include "os_linux_common.h"
#include "../../include/os_net.h"

#include <stdlib.h>

struct vp_os_socket {
    int fd;
};

int vp_os_udp_open(struct vp_os_socket **sock,
                   uint32_t bind_ip_be,
                   uint16_t bind_port_be)
{
    struct vp_os_socket *s = calloc(1, sizeof(*s));
    if (!s)
        return -1;

    s->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        free(s);
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = bind_ip_be;
    addr.sin_port = bind_port_be;

    if (bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s->fd);
        free(s);
        return -1;
    }

    *sock = s;
    return 0;
}

int vp_os_udp_send(struct vp_os_socket *sock,
                   const struct vp_os_addr *dst,
                   const uint8_t *buf,
                   size_t len)
{
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst->ip_be;
    addr.sin_port = dst->port_be;

    ssize_t s = sendto(sock->fd, buf, len, 0,
                       (struct sockaddr *)&addr, sizeof(addr));
    return (s == (ssize_t)len) ? 0 : -1;
}

int vp_os_udp_recv(struct vp_os_socket *sock,
                   struct vp_os_addr *src,
                   uint8_t *buf,
                   size_t max_len)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);

    ssize_t r = recvfrom(sock->fd, buf, max_len, 0,
                         (struct sockaddr *)&addr, &alen);
    if (r <= 0)
        return -1;

    src->ip_be = addr.sin_addr.s_addr;
    src->port_be = addr.sin_port;

    return (int)r;
}

void vp_os_udp_close(struct vp_os_socket *sock)
{
    if (!sock)
        return;
    close(sock->fd);
    free(sock);
}