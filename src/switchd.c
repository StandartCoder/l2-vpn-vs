#include "../core/switch_core.h"
#include "../os/linux/os_linux_common.h"
#include "../include/os_net.h"
#include "../core/protocol.h"
#include "../include/vp_types.h"
#include "../include/vp_debug.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define VP_COMP "switchd"

#define LOG_ERROR(fmt, ...) VP_LOG(VP_LOG_LEVEL_ERROR, VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  VP_LOG(VP_LOG_LEVEL_WARN,  VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  VP_LOG(VP_LOG_LEVEL_INFO,  VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) VP_LOG(VP_LOG_LEVEL_DEBUG, VP_COMP, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) VP_LOG(VP_LOG_LEVEL_TRACE, VP_COMP, fmt, ##__VA_ARGS__)

#define LOG_HEXDUMP_DEBUG(prefix, data, len) \
    VP_HEXDUMP(VP_LOG_LEVEL_DEBUG, VP_COMP, prefix, data, len)

#define LOG_HEXDUMP_TRACE(prefix, data, len) \
    VP_HEXDUMP(VP_LOG_LEVEL_TRACE, VP_COMP, prefix, data, len)

static int g_running = 1;
static struct vp_os_socket *g_sock = NULL;

// Per-client TX rate limiting using a small timestamp ringbuffer per target.
// Limits how many packets we send to a single client per time window.
typedef struct {
    uint32_t client_id;
    uint64_t ts[8];  // small ring of send timestamps
    int      count;
    int      head;
} vp_tx_rate_entry_t;

static vp_tx_rate_entry_t g_tx_rate[VP_MAX_CLIENTS];

static int vp_tx_rate_allow(uint32_t client_id, uint64_t now_ms)
{
    const uint64_t window_ms = 100;  // time window
    // Max packets per window per client; must not exceed ts[] capacity (8).
    const int max_pkts = 8;

    // Find or allocate entry for this client_id
    vp_tx_rate_entry_t *e = NULL;
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (g_tx_rate[i].client_id == client_id) {
            e = &g_tx_rate[i];
            break;
        }
        if (g_tx_rate[i].client_id == 0 && e == NULL) {
            e = &g_tx_rate[i];
        }
    }

    if (!e)
        return 0;

    if (e->client_id == 0) {
        e->client_id = client_id;
        e->count = 0;
        e->head = 0;
    }

    // Drop timestamps older than window_ms
    int new_count = 0;
    for (int i = 0; i < e->count; i++) {
        int idx = (e->head + i) % 8;
        if (now_ms - e->ts[idx] <= window_ms) {
            e->ts[(e->head + new_count) % 8] = e->ts[idx];
            new_count++;
        }
    }
    e->head = e->head % 8;
    e->count = new_count;

    if (e->count >= max_pkts)
        return 0;

    // Record this send
    int idx = (e->head + e->count) % 8;
    e->ts[idx] = now_ms;
    if (e->count < 8)
        e->count++;
    else
        e->head = (e->head + 1) % 8;

    return 1;
}

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

    uint64_t now_ms = vp_os_linux_get_time_ms();
    if (!vp_tx_rate_allow(dst_client_id, now_ms))
        return;

    uint8_t pkt[2000];
    static uint32_t g_seq = 1;

    vp_header_t hdr = {
        .magic = VP_MAGIC,
        .version = VP_VERSION,
        .type = VP_PKT_DATA,
        .header_len = VP_HEADER_WIRE_LEN,
        .payload_len = len,
        .flags = 0,
        .client_id = src_client_id,
        .seq = g_seq++,
        .checksum = vp_crc32(frame, len)
    };

    int total = vp_encode_packet(pkt, sizeof(pkt), &hdr, frame);
    if (total < 0) return;
    
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
    vp_log_init_from_env();

    if (argc != 2) {
        printf("Usage: switchd <port>\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);

    uint16_t port_be = htons(atoi(argv[1]));

    struct vp_os_socket *sock;
    if (vp_os_udp_open(&sock, htonl(INADDR_ANY), port_be) < 0) {
        LOG_ERROR("Failed to bind UDP port");
        printf("Failed to bind port\n");
        return 1;
    }

    g_sock = sock;

    vp_switch_init();

    uint8_t buf[2000];
    struct vp_os_addr src;

    printf("[switchd] Listening on UDP port %d\n", ntohs(port_be));
    LOG_INFO("Listening on UDP port %d", ntohs(port_be));

    while (g_running) {
        uint64_t now = vp_os_linux_get_time_ms();
        vp_switch_flush_stale(now);

        int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Idle: non-blocking socket has no data right now.
                usleep(1000);
            } else {
                LOG_WARN("UDP recv error (errno=%d)", errno);
                usleep(1000);
            }
            continue;
        }

        vp_header_t hdr;
        if (vp_decode_header(buf, r, &hdr) < 0) {
            LOG_DEBUG("Drop: invalid header (len=%d)", r);
            continue;
        }

        int payload_len = hdr.payload_len;
        size_t header_len = hdr.header_len;

        // Bounds check
        if (payload_len < 0 || payload_len > VP_MAX_FRAME_LEN) {
            LOG_DEBUG("Drop: invalid payload_len=%d", payload_len);
            continue;
        }

        // Full packet bounds check: header + payload must fit into r
        if (header_len + (size_t)payload_len > (size_t)r) {
            LOG_DEBUG("Drop: header_len(%zu)+payload_len(%d) > packet_len(%d)",
                      header_len, payload_len, r);
            continue;
        }

        // Verify checksum
        uint32_t crc = vp_crc32(buf + hdr.header_len, payload_len);
        if (crc != hdr.checksum) {
            LOG_DEBUG("Drop: checksum mismatch");
            continue;
        }

        if (hdr.type == VP_PKT_DATA) {
            uint32_t src_client_id;
            if (vp_switch_get_client_id_for_addr(&src, &src_client_id) < 0) {
                LOG_DEBUG("Drop DATA: unknown client addr");
                continue;
            }

            vp_switch_update_client(src_client_id, &src, now);

            int payload_len = hdr.payload_len;

            // invalid or overflow?
            if (payload_len < 0 || payload_len > VP_MAX_FRAME_LEN) {
                printf("[switchd] Drop bad frame: size=%d\n", payload_len);
                LOG_DEBUG("Drop DATA: bad size=%d", payload_len);
                continue;
            }

            LOG_TRACE("RX DATA from client_id=%u len=%d", src_client_id, payload_len);
            LOG_HEXDUMP_TRACE("RX frame", buf + hdr.header_len, (size_t)payload_len);

            vp_switch_handle_frame(
                src_client_id,
                buf + hdr.header_len,
                payload_len,
                now,
                forward_udp
            );
        }

        if (hdr.type == VP_PKT_KEEPALIVE) {
            uint32_t src_client_id;
            if (vp_switch_get_client_id_for_addr(&src, &src_client_id) < 0)
                continue;

            vp_switch_update_client(src_client_id, &src, now);
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
                .header_len = VP_HEADER_WIRE_LEN,
                .payload_len = 0,
                .flags = 0,
                .client_id = new_id,
                .seq = 0,
                .checksum = 0
            };

            uint8_t pkt[VP_HEADER_WIRE_LEN];
            int ack_len = vp_encode_packet(pkt, sizeof(pkt), &ack, NULL);
            if (ack_len > 0)
                vp_os_udp_send(g_sock, &src, pkt, (size_t)ack_len);
            continue;
        }
    }

    return 0;
}
