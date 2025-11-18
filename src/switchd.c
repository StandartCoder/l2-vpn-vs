#include "../core/switch_core.h"
#include "../os/linux/os_linux_common.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include "../include/vp_types.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static struct vp_os_socket *g_sock;

static void forward_udp(uint32_t src_client_id,
                        uint32_t dst_client_id,
                        const uint8_t *frame,
                        size_t len)
{
    struct vp_os_addr dst;

    if (vp_switch_get_client_addr(dst_client_id, &dst) < 0)
        return;

    uint8_t pkt[2000];
    vp_header_t hdr = {
        VP_VERSION,
        VP_PKT_DATA,
        0,
        src_client_id,
        0
    };

    int hlen = vp_encode_header(pkt, sizeof(pkt), &hdr);
    memcpy(pkt + hlen, frame, len);

    vp_os_udp_send(g_sock, &dst, pkt, hlen + len);
}

static uint32_t vp_alloc_client_id(void)
{
    static uint32_t next_id = 1;

    while (next_id < VP_MAX_CLIENTS) {
        uint32_t id = next_id++;
        // check unused:
        struct vp_os_addr tmp;
        if (vp_switch_get_client_addr(id, &tmp) < 0)
            return id;
    }

    return 0; // no free ID (full)
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

    g_sock = sock;

    vp_switch_init();

    uint8_t buf[2000];
    struct vp_os_addr src;

    printf("[switchd] Listening on UDP port %d\n", ntohs(port_be));

    while (1) {
        uint64_t now = vp_os_linux_get_time_ms();
        vp_switch_flush_stale(now);

        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r < 0) continue;

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0)
            continue;

        if (hdr.type == VP_PKT_DATA) {
            vp_switch_update_client(hdr.client_id, &src, now);

            vp_switch_handle_frame(
                hdr.client_id,
                buf + sizeof(vp_header_t),
                r - sizeof(vp_header_t),
                now,
                forward_udp
            );
        }

        if (hdr.type == VP_PKT_KEEPALIVE) {
            vp_switch_update_client(hdr.client_id, &src, now);
            continue; // no frame forwarding
        }

        if (hdr.type == VP_PKT_HELLO) {
            uint32_t new_id = vp_alloc_client_id();
            if (new_id == 0) {
                printf("[switchd] ERROR: client table full!\n");
                continue;
            }

            vp_switch_update_client(new_id, &src, now);

            vp_header_t ack = {
                VP_VERSION,
                VP_PKT_HELLO_ACK,
                0,
                new_id,
                0
            };

            vp_os_udp_send(g_sock, &src, (uint8_t*)&ack, sizeof(ack));
            continue;
        }
    }

    return 0;
}