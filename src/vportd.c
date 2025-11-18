#include "../include/os_tap.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("Usage: vportd <server_ip> <server_port> <tapname>\n");
        return 1;
    }

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

    printf("[vportd] TAP: %s\n", tapname);

    uint8_t frame[2000];
    uint8_t pkt[2000 + sizeof(vp_header_t)];

    while (1) {
        int r = vp_os_tap_read(tap, frame, sizeof(frame));
        if (r > 0) {
            vp_header_t h = { VP_VERSION, VP_PKT_DATA, 0, 1, 0 }; // client_id=1 (temporary)

            int hdr_len = vp_encode_header(pkt, sizeof(pkt), &h);
            memcpy(pkt + hdr_len, frame, r);

            vp_os_udp_send(sock, &srv, pkt, hdr_len + r);
        }
    }
}