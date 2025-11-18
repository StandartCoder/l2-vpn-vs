#include "switch_core.h"
#include <string.h>

#include "../include/os_net.h"

static vp_mac_entry_t mac_table[VP_MAX_CLIENTS];
static vp_client_entry_t client_table[VP_MAX_CLIENTS];

void vp_switch_update_client(uint32_t client_id,
                             const struct vp_os_addr *addr,
                             uint64_t now_ms)
{
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (client_table[i].in_use &&
            client_table[i].client_id == client_id) {
            client_table[i].addr = *addr;
            client_table[i].last_seen_ms = now_ms;
            return;
        }
    }

    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (!client_table[i].in_use) {
            client_table[i].in_use = 1;
            client_table[i].client_id = client_id;
            client_table[i].addr = *addr;
            client_table[i].last_seen_ms = now_ms;
            return;
        }
    }
}

int vp_switch_get_client_addr(uint32_t client_id,
                              struct vp_os_addr *out)
{
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (client_table[i].in_use &&
            client_table[i].client_id == client_id) {
            *out = client_table[i].addr;
            return 0;
        }
    }
    return -1;
}

static int mac_equal(const vp_mac_t *a, const vp_mac_t *b)
{
    return memcmp(a->b, b->b, 6) == 0;
}

void vp_switch_init(void)
{
    memset(mac_table, 0, sizeof(mac_table));
    memset(client_table, 0, sizeof(client_table));
}

static int mac_lookup(const vp_mac_t *mac)
{
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (mac_table[i].in_use && mac_equal(&mac_table[i].mac, mac))
            return i;
    }
    return -1;
}

static int mac_find_free_slot(void)
{
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (!mac_table[i].in_use)
            return i;
    }
    return -1;
}

void vp_switch_handle_frame(
    uint32_t src_client_id,
    const uint8_t *frame,
    size_t frame_len,
    uint64_t now_ms,
    vp_forward_cb forwarder
)
{
    if (frame_len < 14)
        return;

    vp_mac_t dst, src;
    memcpy(dst.b, frame + 0, 6);
    memcpy(src.b, frame + 6, 6);

    // 1. Learn source MAC -> client_id
    int src_idx = mac_lookup(&src);
    if (src_idx < 0) {
        src_idx = mac_find_free_slot();
        if (src_idx >= 0) {
            mac_table[src_idx].mac = src;
            mac_table[src_idx].client_id = src_client_id;
            mac_table[src_idx].last_seen_ms = now_ms;
            mac_table[src_idx].in_use = 1;
        }
    } else {
        mac_table[src_idx].client_id = src_client_id;
        mac_table[src_idx].last_seen_ms = now_ms;
    }

    // 2. Forwarding
    int dst_idx = mac_lookup(&dst);

    // Broadcast?
    int is_broadcast = 1;
    for (int i = 0; i < 6; i++) {
        if (dst.b[i] != 0xff) {
            is_broadcast = 0;
            break;
        }
    }

    if (is_broadcast || dst_idx < 0) {
        // Flood to all except source
        for (int i = 0; i < VP_MAX_CLIENTS; i++) {
            if (!mac_table[i].in_use)
                continue;

            uint32_t cid = mac_table[i].client_id;
            if (cid != src_client_id)
                forwarder(src_client_id, cid, frame, frame_len);
        }
    } else {
        uint32_t target = mac_table[dst_idx].client_id;
        forwarder(src_client_id, target, frame, frame_len);
    }
}

void vp_switch_flush_stale(uint64_t now_ms)
{
    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (!mac_table[i].in_use) continue;

        if (now_ms - mac_table[i].last_seen_ms > VP_MAC_TIMEOUT_MS) {
            mac_table[i].in_use = 0;
        }
    }

    for (int i = 0; i < VP_MAX_CLIENTS; i++) {
        if (!client_table[i].in_use) continue;

        if (now_ms - client_table[i].last_seen_ms > VP_MAC_TIMEOUT_MS) {
            client_table[i].in_use = 0;
        }
    }
}