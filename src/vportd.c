#include "../include/os_tap.h"
#include "../include/os_net.h"
#include "../os/linux/os_linux_common.h"
#include "../core/protocol.h"
#include "../include/vp_types.h"
#include "../include/vp_debug.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define VP_COMP "vportd"

#define LOG_ERROR(fmt, ...) VP_LOG(VP_LOG_LEVEL_ERROR, VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  VP_LOG(VP_LOG_LEVEL_WARN,  VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  VP_LOG(VP_LOG_LEVEL_INFO,  VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) VP_LOG(VP_LOG_LEVEL_DEBUG, VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) VP_LOG(VP_LOG_LEVEL_TRACE, VP_COMP, fmt, ##__VA_ARGS__)

#define LOG_HEXDUMP_DEBUG(prefix, data, len) \
    VP_HEXDUMP(VP_LOG_LEVEL_DEBUG, VP_COMP, prefix, data, len)

#define LOG_HEXDUMP_TRACE(prefix, data, len) \
    VP_HEXDUMP(VP_LOG_LEVEL_TRACE, VP_COMP, prefix, data, len)

static struct vp_os_tap *g_tap = NULL;
static struct vp_os_socket *g_sock = NULL;
static int g_running = 1;

static uint32_t g_client_id = 0;
static uint32_t g_seq = 1;
static uint32_t g_rx_highest_seq = 0;
static uint64_t g_rx_replay_window = 0;

static int vp_check_replay_from_switch(uint32_t seq)
{
    if (seq == 0)
        return -1;

    if (g_rx_highest_seq == 0) {
        g_rx_highest_seq = seq;
        g_rx_replay_window = 1ULL;
        return 0;
    }

    if (seq > g_rx_highest_seq) {
        uint32_t delta = seq - g_rx_highest_seq;
        if (delta >= 64) {
            g_rx_replay_window = 1ULL;
        } else {
            g_rx_replay_window <<= delta;
            g_rx_replay_window |= 1ULL;
        }
        g_rx_highest_seq = seq;
        return 0;
    }

    uint32_t diff = g_rx_highest_seq - seq;
    if (diff >= 64)
        return -1;

    uint64_t mask = 1ULL << diff;
    if (g_rx_replay_window & mask)
        return -1;

    g_rx_replay_window |= mask;
    return 0;
}

static void handle_sigint(int sig)
{
    (void)sig;
    g_running = 0;
}

static int vp_do_handshake(struct vp_os_socket *sock,
                           struct vp_os_addr *srv,
                           uint64_t *last_recv,
                           uint64_t *last_activity,
                           uint64_t *last_keepalive,
                           uint64_t *last_hello,
                           int is_reconnect)
{
    uint64_t now = vp_os_linux_get_time_ms();

    // Use a per-handshake nonce in seq to bind HELLO_ACKs
    // to the corresponding HELLO and prevent replay of old ACKs.
    uint32_t hello_seq = (uint32_t)now;
    if (hello_seq == 0)
        hello_seq = 1;

    vp_header_t hello = {
        .magic      = VP_MAGIC,
        .version    = VP_VERSION,
        .type       = VP_PKT_HELLO,
        .header_len = VP_HEADER_WIRE_LEN,
        .payload_len= 0,
        .flags      = 0,
        .client_id  = 0,   // client_id never sent by client
        .seq        = hello_seq,
        .checksum   = 0
    };

    if (is_reconnect) {
        printf("[vportd] Re-HELLO → requesting new client_id\n");
    } else {
        printf("[vportd] Initial HELLO → requesting client_id\n");
    }

    uint8_t hello_pkt[VP_HEADER_WIRE_LEN];
    int hello_len = vp_encode_packet(hello_pkt, sizeof(hello_pkt), &hello, NULL);
    if (hello_len < 0) {
        printf("[vportd] Failed to encode HELLO packet\n");
        return -1;
    }

    if (vp_os_udp_send(sock, srv, hello_pkt, (size_t)hello_len) < 0) {
        LOG_WARN("UDP send HELLO failed");
        return -1;
    }
    *last_hello = now;

    uint64_t deadline = now + 3000; // 3s Timeout for HELLO_ACK

    while (g_running && vp_os_linux_get_time_ms() < deadline) {
        struct vp_os_addr src;
        uint8_t buf[256];

        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r <= 0) {
            usleep(1000);
            continue;
        }

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0)
            continue;

        if (hdr.type == VP_PKT_HELLO_ACK) {
            // Ignore stray or replayed ACKs for other sessions
            // by checking the handshake nonce.
            if (hdr.seq != hello_seq)
                continue;

            g_client_id = hdr.client_id;
            printf("[vportd] %s client_id = %u\n",
                   is_reconnect ? "Re-assigned" : "Assigned",
                   g_client_id);

            g_seq = 1;

            uint64_t t = vp_os_linux_get_time_ms();
            *last_recv      = t;
            *last_activity  = t;
            *last_keepalive = t;
            g_rx_highest_seq = 0;
            g_rx_replay_window = 0;
            return 0;
        }
    }

    printf("[vportd] HELLO handshake failed (no HELLO_ACK)\n");
    return -1;
}

int main(int argc, char **argv)
{
    vp_log_init_from_env();

    if (argc != 4) {
        printf("Usage: vportd <server_ip> <server_port> <tapname>\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);

    const char *server_ip = argv[1];
    uint16_t sport_be     = htons(atoi(argv[2]));
    const char *tapname   = argv[3];

    struct vp_os_tap *tap;
    struct vp_os_socket *sock;
    struct vp_os_addr srv = { inet_addr(server_ip), sport_be };

    if (vp_os_tap_open(&tap, tapname) < 0) {
        LOG_ERROR("Failed to open TAP %s", tapname);
        printf("Failed to open TAP\n");
        return 1;
    }

    if (vp_os_udp_open(&sock, htonl(INADDR_ANY), 0) < 0) {
        LOG_ERROR("Failed to open UDP socket");
        printf("Failed to open UDP socket\n");
        return 1;
    }

    g_tap  = tap;
    g_sock = sock;

    printf("[vportd] TAP: %s\n", tapname);
    LOG_INFO("Using TAP: %s", tapname);

    uint8_t frame[2000];
    uint8_t pkt[2000 + VP_HEADER_WIRE_LEN];

    uint64_t last_keepalive = 0;
    uint64_t last_activity  = 0;
    uint64_t last_recv      = 0;
    uint64_t last_hello     = 0;

    int keepalive_interval  = 5000;
    int keepalive_success   = 0;

    // -------------------------------
    // INITIAL HELLO HANDSHAKE
    // -------------------------------
    if (vp_do_handshake(sock, &srv,
                        &last_recv,
                        &last_activity,
                        &last_keepalive,
                        &last_hello,
                        0) < 0) {
        // comepletely failed → exit
        return 1;
    }

    while (g_running) {

        uint64_t now = vp_os_linux_get_time_ms();

        // -------------------------------
        // 1) ADAPTIVE KEEPALIVE LOGIC
        // -------------------------------

        // interval gets increased after 3 successful keepalives
        if (keepalive_success >= 3 && keepalive_interval != 10000) {
            keepalive_interval = 10000;
            printf("[vportd] Keepalive raised to 10s\n");
        }

        // If no traffic for 20s → back to 5s
        if (now - last_activity > 20000 && keepalive_interval != 5000) {
            keepalive_interval = 5000;
            keepalive_success = 0;
            printf("[vportd] Keepalive dropped to 5s (idle)\n");
        }

        // Send keepalive?
        if (now - last_keepalive >= (uint64_t)keepalive_interval &&
            g_client_id != 0)
        {
            vp_header_t keep = {
                .magic      = VP_MAGIC,
                .version    = VP_VERSION,
                .type       = VP_PKT_KEEPALIVE,
                .header_len = VP_HEADER_WIRE_LEN,
                .payload_len= 0,
                .flags      = 0,
                .client_id  = 0,   // never send client_id
                .seq        = g_seq++,
                .checksum   = 0
            };

            int keep_len = vp_encode_packet(pkt, sizeof(pkt), &keep, NULL);
            if (keep_len > 0) {
                if (vp_os_udp_send(sock, &srv, pkt, (size_t)keep_len) < 0)
                    LOG_WARN("UDP send KEEPALIVE failed");
            }

            last_keepalive = now;
            keepalive_success++;
        }

        // -------------------------------
        // 2) UDP RECEIVE PATH
        // -------------------------------
        struct vp_os_addr src;
        uint8_t buf[2000];

        int u;
        while (1) {
            u = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
            if (u <= 0) {
                if (u < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_WARN("UDP recv error from switch (errno=%d)", errno);
                }
                break;
            }
            last_recv = now; // something from the server

            vp_header_t hdr;
            if (u < (int)VP_HEADER_WIRE_LEN) continue; // too small

            if (vp_decode_header(buf, u, &hdr) < 0)
                continue;

            if (hdr.type == VP_PKT_DATA) {
                int payload_len = hdr.payload_len;
                size_t header_len = hdr.header_len;

                // Bounds
                if (payload_len <= 0 || payload_len > VP_MAX_FRAME_LEN)
                    continue;

                // Full packet bounds check: header + payload must fit into u
                if (header_len + (size_t)payload_len > (size_t)u)
                    continue;

                if (vp_check_replay_from_switch(hdr.seq) < 0) {
                    LOG_DEBUG("Drop RX DATA from switch: replay or out-of-window (seq=%u)", hdr.seq);
                    continue;
                }

                // CRC
                uint32_t crc = vp_crc32(buf + hdr.header_len, payload_len);
                if (crc != hdr.checksum)
                    continue;

                last_activity = now; // real data

                LOG_TRACE("RX DATA from switch len=%d", payload_len);
                LOG_HEXDUMP_TRACE("RX payload", buf + hdr.header_len, (size_t)payload_len);

                if (vp_os_tap_write(tap, buf + hdr.header_len, payload_len) < 0)
                    LOG_WARN("TAP write failed (len=%d)", payload_len);
            }

            if (hdr.type == VP_PKT_ERROR) {
                // Server explicitly reports an error for this client.
                // Drop current client_id and perform a reconnect HELLO.
                printf("[vportd] Received ERROR packet (type=%u) → re-HELLO\n", hdr.type);

                g_client_id = 0;
                g_seq = 1;

                if (vp_do_handshake(sock, &srv,
                                    &last_recv,
                                    &last_activity,
                                    &last_keepalive,
                                    &last_hello,
                                    1) < 0) {
                    // Handshake failed → short pause, then continue main loop
                    usleep(500 * 1000);
                }

                break; // leave UDP receive loop after ERROR handling
            }
        }

        // -------------------------------
        // 3) TAP FRAME SEND PATH
        // -------------------------------
        int r;
        while ((r = vp_os_tap_read(tap, frame, sizeof(frame))) > 0) {

            if (g_client_id == 0) {
                // we are currently "disconnected" → drop TAP frames
                printf("[vportd] Drop TAP frame (no valid client_id)\n");
                continue;
            }

            // --- BOUNDS CHECK: DROP ILLEGAL FRAMES ---
            if (r > VP_MAX_FRAME_LEN) {
                printf("[vportd] Drop TAP frame: too big (%d bytes)\n", r);
                LOG_DEBUG("Drop TAP frame: too big (%d bytes)", r);
                continue;
            }

            vp_header_t hdr = {
                .magic      = VP_MAGIC,
                .version    = VP_VERSION,
                .type       = VP_PKT_DATA,
                .header_len = VP_HEADER_WIRE_LEN,
                .payload_len= r,
                .flags      = 0,
                .client_id  = 0,   // never send client_id
                .seq        = g_seq++,
                .checksum   = vp_crc32(frame, r)
            };

            int total = vp_encode_packet(pkt, sizeof(pkt), &hdr, frame);
            if (total < 0)
                continue;

            LOG_TRACE("TX DATA to switch len=%d", r);
            LOG_HEXDUMP_TRACE("TX payload", frame, (size_t)r);

            if (vp_os_udp_send(sock, &srv, pkt, (size_t)total) < 0)
                LOG_WARN("UDP send DATA to switch failed");

            last_activity = now;
        }

        // CPU relief
        usleep(1000);
    }

    if (g_tap) {
        vp_os_tap_close(g_tap);
        printf("[vportd] TAP closed\n");
    }

    if (g_sock) {
        vp_os_udp_close(g_sock);
        printf("[vportd] UDP socket closed\n");
    }

    return 0;
}
