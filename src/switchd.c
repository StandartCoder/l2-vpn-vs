#include "../core/switch_core.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include <stdio.h>
#include <arpa/inet.h>

#include "../include/os_net.h"
#include "../core/protocol.h"
#include "../include/vp_types.h"

static struct vp_os_socket *g_sock;

static void forward_udp(uint32_t dst_client_id,
                        const uint8_t *frame,
                        size_t len)
{
    struct vp_os_addr dst;

    if (vp_switch_get_client_addr(dst_client_id, &dst) < 0)
        return;

    uint8_t pkt[2000];
    vp_header_t hdr = { VP_VERSION, VP_PKT_DATA, 0, dst_client_id, 0 };

    int hlen = vp_encode_header(pkt, sizeof(pkt), &hdr);
    memcpy(pkt + hlen, frame, len);

    vp_os_udp_send(g_sock, &dst, pkt, hlen + len);
}

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
            vp_switch_update_client(hdr.client_id, &src, 0);
            
            vp_switch_handle_frame(
                hdr.client_id,
                buf + sizeof(vp_header_t),
                r - sizeof(vp_header_t),
                forward_udp
            );
        }
    }

    return 0;
}