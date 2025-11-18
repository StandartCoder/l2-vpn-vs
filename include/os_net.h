#ifndef VP_OS_NET_H
#define VP_OS_NET_H

#include <stdint.h>
#include <stddef.h>

struct vp_os_socket;
struct vp_os_addr {
    uint32_t ip_be;      // IPv4 in network byte order
    uint16_t port_be;    // Port in network byte order
};

// Create UDP socket bound to ip:port (ip_be = INADDR_ANY if 0)
int vp_os_udp_open(struct vp_os_socket **sock,
                   uint32_t bind_ip_be,
                   uint16_t bind_port_be);

// Send UDP packet
int vp_os_udp_send(struct vp_os_socket *sock,
                   const struct vp_os_addr *dst,
                   const uint8_t *buf,
                   size_t len);

// Receive UDP packet (blocking)
int vp_os_udp_recv(struct vp_os_socket *sock,
                   struct vp_os_addr *src,
                   uint8_t *buf,
                   size_t max_len);

// Cleanup
void vp_os_udp_close(struct vp_os_socket *sock);

#endif