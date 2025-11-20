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
#include <sys/select.h>

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
    int      in_use;
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
        if (g_tx_rate[i].in_use && g_tx_rate[i].client_id == client_id) {
            e = &g_tx_rate[i];
            break;
        }
    }

    if (!e) {
        // No existing entry → find a free slot
        for (int i = 0; i < VP_MAX_CLIENTS; i++) {
            if (!g_tx_rate[i].in_use) {
                e = &g_tx_rate[i];
                break;
            }
        }
        if (!e)
            return 0;
    }

    if (!e->in_use) {
        e->client_id = client_id;
        e->count = 0;
        e->head = 0;
        e->in_use = 1;
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
    (void)sig;
    g_running = 0;
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

    int total = vp_encode_packet(VP_CRYPTO_DIR_SWITCH_TO_CLIENT,
                                 pkt, sizeof(pkt), &hdr, frame);
    if (total < 0)
        return;

    if (vp_os_udp_send(g_sock, &dst, pkt, (size_t)total) < 0) {
        LOG_WARN("UDP send to client_id=%u failed", dst_client_id);
    }
}

static uint32_t vp_alloc_client_id(void)
{
    for (uint32_t id = 1; id < VP_CLIENT_MAX; ++id) {
        struct vp_os_addr tmp;
        if (vp_switch_get_client_addr(id, &tmp) < 0) {
            return id;
        }
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

    int udp_fd = vp_os_udp_get_fd(sock);

    while (g_running) {
        uint64_t now = vp_os_linux_get_time_ms();
        vp_switch_flush_stale(now);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(udp_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100 ms

        int n = select(udp_fd + 1, &rfds, NULL, NULL, &tv);
        if (!g_running)
            break;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            LOG_WARN("select() failed (errno=%d)", errno);
            continue;
        }

        if (n == 0 || !FD_ISSET(udp_fd, &rfds)) {
            // timeout, no UDP ready; continue to next iteration
            continue;
        }

        // Drain all pending UDP packets
        for (;;) {
            int r = vp_os_udp_recv(sock, &src, buf, sizeof(buf));
            if (r < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    LOG_WARN("UDP recv error (errno=%d)", errno);
                break;
            }

            vp_header_t hdr;
            if (vp_decode_packet(VP_CRYPTO_DIR_CLIENT_TO_SWITCH,
                                 buf, r, &hdr) < 0) {
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
                    // Inform client so it can re-HELLO after switch restart.
                    vp_header_t err = {
                        .magic      = VP_MAGIC,
                        .version    = VP_VERSION,
                        .type       = VP_PKT_ERROR,
                        .header_len = VP_HEADER_WIRE_LEN,
                        .payload_len= 0,
                        .flags      = 0,
                        .client_id  = 0,
                        .seq        = 0,
                        .checksum   = 0
                    };

                    uint8_t epkt[VP_HEADER_WIRE_LEN];
                    int elen = vp_encode_packet(VP_CRYPTO_DIR_SWITCH_TO_CLIENT,
                                                epkt, sizeof(epkt), &err, NULL);
                    if (elen > 0) {
                        if (vp_os_udp_send(g_sock, &src, epkt, (size_t)elen) < 0)
                            LOG_WARN("UDP send of ERROR (DATA unknown) failed");
                    }
                    continue;
                }

                if (vp_switch_check_replay(src_client_id, hdr.seq) < 0) {
                    LOG_DEBUG("Drop DATA: replay or out-of-window (seq=%u)", hdr.seq);
                    continue;
                }

                vp_switch_update_client(src_client_id, &src, now);

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
                if (vp_switch_get_client_id_for_addr(&src, &src_client_id) < 0) {
                    // Unknown address sending KEEPALIVE → tell client to re-HELLO.
                    vp_header_t err = {
                        .magic      = VP_MAGIC,
                        .version    = VP_VERSION,
                        .type       = VP_PKT_ERROR,
                        .header_len = VP_HEADER_WIRE_LEN,
                        .payload_len= 0,
                        .flags      = 0,
                        .client_id  = 0,
                        .seq        = 0,
                        .checksum   = 0
                    };

                    uint8_t epkt[VP_HEADER_WIRE_LEN];
                    int elen = vp_encode_packet(VP_CRYPTO_DIR_SWITCH_TO_CLIENT,
                                                epkt, sizeof(epkt), &err, NULL);
                    if (elen > 0) {
                        if (vp_os_udp_send(g_sock, &src, epkt, (size_t)elen) < 0)
                            LOG_WARN("UDP send of ERROR (KEEPALIVE unknown) failed");
                    }
                    continue;
                }

                if (vp_switch_check_replay(src_client_id, hdr.seq) < 0) {
                    LOG_DEBUG("Drop KEEPALIVE: replay or out-of-window (seq=%u)", hdr.seq);
                    continue;
                }

                vp_switch_update_client(src_client_id, &src, now);
                continue; // no frame forwarding
            }

        if (hdr.type == VP_PKT_HELLO) {
            // Reuse existing client_id for this address on reconnect to
            // keep MAC bindings stable and avoid stale entries. If none
            // exists, allocate a fresh client_id.
            uint32_t cid;
            if (vp_switch_get_client_id_for_addr(&src, &cid) == 0) {
                vp_switch_reset_client(cid);
            } else {
                cid = vp_alloc_client_id();
                if (cid == 0) {
                    printf("[switchd] ERROR: client table full!\n");
                    continue;
                }
            }

            if (hdr.payload_len != 16) {
                LOG_DEBUG("Drop HELLO: invalid payload_len=%u", hdr.payload_len);
                continue;
            }

            vp_switch_update_client(cid, &src, now);

            uint8_t session_id[32];
            uint8_t *client_nonce = buf + hdr.header_len;
            uint8_t server_nonce[16];
            uint64_t t = now;
            for (int i = 0; i < 8; i++)
                server_nonce[i] = (uint8_t)(t >> (8 * i));
            uint64_t mix = ((uint64_t)src.ip_be << 32) ^ (uint64_t)src.port_be;
            for (int i = 0; i < 8; i++)
                server_nonce[8 + i] = (uint8_t)(mix >> (8 * i));

            memcpy(session_id, client_nonce, 16);
            memcpy(session_id + 16, server_nonce, 16);
            vp_crypto_set_session(session_id);

            vp_header_t ack = {
                .magic = VP_MAGIC,
                .version = VP_VERSION,
                .type = VP_PKT_HELLO_ACK,
                .header_len = VP_HEADER_WIRE_LEN,
                .payload_len = (uint16_t)sizeof(server_nonce),
                .flags = 0,
                .client_id = cid,
                .seq = hdr.seq,
                .checksum = 0
            };

                uint8_t pkt[VP_HEADER_WIRE_LEN + 32];
                int ack_len = vp_encode_packet(VP_CRYPTO_DIR_SWITCH_TO_CLIENT,
                                               pkt, sizeof(pkt), &ack, server_nonce);
                if (ack_len > 0) {
                    if (vp_os_udp_send(g_sock, &src, pkt, (size_t)ack_len) < 0)
                        LOG_WARN("UDP send of HELLO_ACK failed");
                }
                continue;
            }
        }
    }

    if (g_sock) {
        vp_os_udp_close(g_sock);
        printf("[switchd] UDP socket closed\n");
    }

    return 0;
}
