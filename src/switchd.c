#include "../core/switch_core.h"
#include "../os/linux/os_linux_common.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include "../include/vp_types.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

static int g_running = 1;
static struct vp_os_socket *g_sock = NULL;

static void handle_sigint(int sig)
{
    printf("\n[switchd] Caught SIGINT, shutting down...\n");
    g_running = 0;

    if (g_sock) {
        vp_os_udp_close(g_sock);
        printf("[switchd] UDP socket closed\n");
    }

    exit(0);
}

static void forward_udp(uint32_t src_client_id,
                        uint32_t dst_client_id,
                        const uint8_t *frame,
                        size_t len)
{
    struct vp_os_addr dst;

    if (vp_switch_get_client_addr(dst_client_id, &dst) < 0)
        return;

    uint8_t pkt[2000];
    static uint32_t g_seq = 1;

    vp_header_t hdr = {
        .magic = VP_MAGIC,
        .version = VP_VERSION,
        .type = VP_PKT_DATA,
        .header_len = sizeof(vp_header_t),
        .payload_len = len,
        .flags = 0,
        .client_id = src_client_id,
        .seq = g_seq++,
        .checksum = vp_crc32(frame, len)
    };

    int total = vp_encode_packet(pkt, sizeof(pkt), &hdr, frame);
    vp_os_udp_send(g_sock, &dst, pkt, total);
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

    signal(SIGINT, handle_sigint);

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

    while (g_running) {
        uint64_t now = vp_os_linux_get_time_ms();
        vp_switch_flush_stale(now);

        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r < 0) continue;

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0)
            continue;

        int payload_len = hdr.payload_len;

        // Bounds check
        if (payload_len < 0 || payload_len > VP_MAX_FRAME_LEN)
            continue;

        // Verify checksum
        uint32_t crc = vp_crc32(buf + hdr.header_len, payload_len);
        if (crc != hdr.checksum)
            continue;

        if (hdr.type == VP_PKT_DATA) {
            vp_switch_update_client(hdr.client_id, &src, now);

            int payload_len = hdr.payload_len;

            // Header too small?
            if (r < hdr.header_len) continue;

            // invalid or overflow?
            if (payload_len < 0 || payload_len > VP_MAX_FRAME_LEN) {
                printf("[switchd] Drop bad frame: size=%d\n", payload_len);
                continue;
            }

            vp_switch_handle_frame(
                hdr.client_id,
                buf + hdr.header_len,
                payload_len,
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
                .magic = VP_MAGIC,
                .version = VP_VERSION,
                .type = VP_PKT_HELLO_ACK,
                .header_len = sizeof(vp_header_t),
                .payload_len = 0,
                .flags = 0,
                .client_id = new_id,
                .seq = 0,
                .checksum = 0
            };

            vp_os_udp_send(g_sock, &src, (uint8_t*)&ack, sizeof(vp_header_t));
            continue;
        }
    }

    return 0;
}