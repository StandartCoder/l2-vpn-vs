#include "../core/switch_core.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: switchd <port>\n");
        return 1;
    }

    uint16_t port_be = htons(atoi(argv[1]));

    struct vp_os_socket *sock;
    if (vp_os_udp_open(&sock, htonl(INADDR_ANY), port_be) < 0) {
        printf("Failed to bind port\n");
        return 1;
    }

    vp_switch_init();

    uint8_t buf[2000];
    struct vp_os_addr src;

    printf("[switchd] Listening on UDP port %d\n", ntohs(port_be));

    while (1) {
        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r < 0) continue;

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0)
            continue;

        if (hdr.type == VP_PKT_DATA) {
            vp_switch_handle_frame(
                hdr.client_id,
                buf + sizeof(vp_header_t),
                r - sizeof(vp_header_t),
                NULL // TODO: real forwarder comes in Phase 3
            );
        }
    }

    return 0;
}