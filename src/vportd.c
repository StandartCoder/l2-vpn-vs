#include "../include/os_tap.h"
#include "../include/os_net.h"
#include "../os/linux/os_linux_common.h"
#include "../core/protocol.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

static struct vp_os_tap *g_tap = NULL;
static struct vp_os_socket *g_sock = NULL;
static int g_running = 1;

static uint32_t g_client_id = 0;

static void handle_sigint(int sig)
{
    printf("\n[vportd] Caught SIGINT, shutting down...\n");
    g_running = 0;

    if (g_tap) {
        vp_os_tap_close(g_tap);
        printf("[vportd] TAP closed\n");
    }

    if (g_sock) {
        vp_os_udp_close(g_sock);
        printf("[vportd] UDP socket closed\n");
    }

    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("Usage: vportd <server_ip> <server_port> <tapname>\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);

    const char *server_ip = argv[1];
    uint16_t sport_be = htons(atoi(argv[2]));
    const char *tapname = argv[3];

    struct vp_os_tap *tap;
    struct vp_os_socket *sock;
    struct vp_os_addr srv = { inet_addr(server_ip), sport_be };

    if (vp_os_tap_open(&tap, tapname) < 0) {
        printf("Failed to open TAP\n");
        return 1;
    }

    if (vp_os_udp_open(&sock, htonl(INADDR_ANY), 0) < 0) {
        printf("Failed to open UDP socket\n");
        return 1;
    }

    g_tap = tap;
    g_sock = sock;

    printf("[vportd] TAP: %s\n", tapname);

    vp_header_t hello = { VP_VERSION, VP_PKT_HELLO, 0, 0, 0 }; // client_id=0 for id request
    vp_os_udp_send(sock, &srv, (uint8_t*)&hello, sizeof(hello));

    while (g_client_id == 0) {
        struct vp_os_addr src;
        uint8_t buf[256];

        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r <= 0) continue;

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0) continue;

        if (hdr.type == VP_PKT_HELLO_ACK) {
            g_client_id = hdr.client_id;
            printf("[vportd] Assigned client_id = %u\n", g_client_id);
        }
    }

    uint8_t frame[2000];
    uint8_t pkt[2000 + sizeof(vp_header_t)];

    uint64_t last_keepalive = 0;
    uint64_t last_activity = 0;
    uint64_t last_recv = 0;

    int keepalive_interval = 5000;
    int keepalive_success = 0;

    while (g_running) {

        uint64_t now = vp_os_linux_get_time_ms();

        // -------------------------------
        // 1) ADAPTIVE KEEPALIVE LOGIC
        // -------------------------------

        // Increase interval if we managed 3 successful cycles
        if (keepalive_success >= 3 && keepalive_interval != 10000) {
            keepalive_interval = 10000;
            printf("[vportd] Keepalive raised to 10s\n");
        }

        // If no incoming/outgoing traffic in 20 seconds → drop back to 5s
        if (now - last_activity > 20000 && keepalive_interval != 5000) {
            keepalive_interval = 5000;
            keepalive_success = 0;
            printf("[vportd] Keepalive dropped to 5s (idle)\n");
        }

        // Send keepalive if needed
        if (now - last_keepalive >= (uint64_t)keepalive_interval) {
            vp_header_t keep = { VP_VERSION, VP_PKT_KEEPALIVE, 0, g_client_id, 0 };
            vp_os_udp_send(sock, &srv, (uint8_t*)&keep, sizeof(keep));

            last_keepalive = now;
            keepalive_success++;   // count each successful send
        }


        // -------------------------------
        // 2) UDP RECEIVE PATH
        // -------------------------------
        struct vp_os_addr src;
        uint8_t buf[2000];

        int u;
        while ((u = vp_os_udp_recv(sock, &src, buf, sizeof(buf))) > 0) {
            last_recv = now; // network activity

            vp_header_t hdr;
            if (vp_decode_header(buf, u, &hdr) >= 0 &&
                hdr.type == VP_PKT_DATA)
            {
                vp_os_tap_write(tap,
                                buf + sizeof(vp_header_t),
                                u - sizeof(vp_header_t));
            }
        }


        // -------------------------------
        // 3) TAP FRAME SEND PATH
        // -------------------------------
        int r;
        while ((r = vp_os_tap_read(tap, frame, sizeof(frame))) > 0) {

            last_activity = now;    // outbound traffic

            vp_header_t h = {
                VP_VERSION,
                VP_PKT_DATA,
                0,
                g_client_id,
                0
            };

            int hdr_len = vp_encode_header(pkt, sizeof(pkt), &h);
            memcpy(pkt + hdr_len, frame, r);
            vp_os_udp_send(sock, &srv, pkt, hdr_len + r);
        }

        // CPU relief
        usleep(1000);
    }
}