#include "switch_core.h"
#include <string.h>

#include "../include/os_net.h"

// Hashing parameters
#define VP_MAC_BUCKETS        256
#define VP_MAC_BUCKET_SIZE      8
#define VP_CLIENT_MAX      VP_MAX_CLIENTS
#define VP_CLIENT_ADDR_BUCKETS 256
#define VP_CLIENT_ADDR_BUCKET_SIZE 4

static vp_mac_entry_t mac_table[VP_MAC_BUCKETS][VP_MAC_BUCKET_SIZE];
static vp_client_entry_t client_table[VP_CLIENT_MAX];

typedef struct {
    int in_use;
    struct vp_os_addr addr;
    uint32_t client_id;
} vp_client_addr_entry_t;

static vp_client_addr_entry_t client_addr_table[VP_CLIENT_ADDR_BUCKETS][VP_CLIENT_ADDR_BUCKET_SIZE];

// Global flood control (simple token bucket in packets)
static uint64_t g_flood_last_refill_ms = 0;
static int g_flood_tokens = 0;

static void vp_flood_maybe_refill(uint64_t now_ms)
{
    const uint64_t interval_ms = 100;          // refill every 100 ms
    const int max_tokens = 256;               // max flood packets per interval
    if (g_flood_last_refill_ms == 0 ||
        now_ms - g_flood_last_refill_ms >= interval_ms) {
        g_flood_last_refill_ms = now_ms;
        g_flood_tokens = max_tokens;
    }
}

static int mac_equal(const vp_mac_t *a, const vp_mac_t *b)
{
    return memcmp(a->b, b->b, 6) == 0;
}

static uint32_t vp_mac_hash(const vp_mac_t *mac)
{
    uint32_t h = 0;
    for (int i = 0; i < 6; i++)
        h = (h * 33u) ^ mac->b[i];
    return h;
}

static uint32_t vp_addr_hash(const struct vp_os_addr *addr)
{
    uint32_t v = addr->ip_be ^ ((uint32_t)addr->port_be << 16);
    v ^= v >> 16;
    v *= 0x7feb352dU;
    v ^= v >> 15;
    v *= 0x846ca68bU;
    v ^= v >> 16;
    return v;
}

static vp_mac_entry_t *mac_find_entry(const vp_mac_t *mac)
{
    uint32_t h = vp_mac_hash(mac);
    uint32_t bucket = h & (VP_MAC_BUCKETS - 1);

    for (int i = 0; i < VP_MAC_BUCKET_SIZE; i++) {
        vp_mac_entry_t *e = &mac_table[bucket][i];
        if (e->in_use && mac_equal(&e->mac, mac))
            return e;
    }
    return NULL;
}

static vp_mac_entry_t *mac_find_free_slot(uint32_t bucket)
{
    for (int i = 0; i < VP_MAC_BUCKET_SIZE; i++) {
        if (!mac_table[bucket][i].in_use)
            return &mac_table[bucket][i];
    }
    return NULL;
}

static vp_client_addr_entry_t *client_addr_find_entry(const struct vp_os_addr *addr)
{
    uint32_t h = vp_addr_hash(addr);
    uint32_t bucket = h & (VP_CLIENT_ADDR_BUCKETS - 1);

    for (int i = 0; i < VP_CLIENT_ADDR_BUCKET_SIZE; i++) {
        vp_client_addr_entry_t *e = &client_addr_table[bucket][i];
        if (e->in_use &&
            e->addr.ip_be == addr->ip_be &&
            e->addr.port_be == addr->port_be)
            return e;
    }
    return NULL;
}

static void client_addr_upsert(const struct vp_os_addr *addr, uint32_t client_id)
{
    uint32_t h = vp_addr_hash(addr);
    uint32_t bucket = h & (VP_CLIENT_ADDR_BUCKETS - 1);

    // Update existing
    for (int i = 0; i < VP_CLIENT_ADDR_BUCKET_SIZE; i++) {
        vp_client_addr_entry_t *e = &client_addr_table[bucket][i];
        if (e->in_use &&
            e->addr.ip_be == addr->ip_be &&
            e->addr.port_be == addr->port_be) {
            e->client_id = client_id;
            return;
        }
    }

    // Find free slot
    for (int i = 0; i < VP_CLIENT_ADDR_BUCKET_SIZE; i++) {
        vp_client_addr_entry_t *e = &client_addr_table[bucket][i];
        if (!e->in_use) {
            e->in_use = 1;
            e->addr = *addr;
            e->client_id = client_id;
            return;
        }
    }
    // Bucket full: keep existing mappings. New mapping will still be
    // discoverable via fallback scan in vp_switch_get_client_id_for_addr.
}

static void client_addr_remove(const struct vp_os_addr *addr, uint32_t client_id)
{
    uint32_t h = vp_addr_hash(addr);
    uint32_t bucket = h & (VP_CLIENT_ADDR_BUCKETS - 1);

    for (int i = 0; i < VP_CLIENT_ADDR_BUCKET_SIZE; i++) {
        vp_client_addr_entry_t *e = &client_addr_table[bucket][i];
        if (e->in_use &&
            e->client_id == client_id &&
            e->addr.ip_be == addr->ip_be &&
            e->addr.port_be == addr->port_be) {
            e->in_use = 0;
            return;
        }
    }
}

void vp_switch_update_client(uint32_t client_id,
                             const struct vp_os_addr *addr,
                             uint64_t now_ms)
{
    if (client_id == 0 || client_id >= VP_CLIENT_MAX)
        return;

    vp_client_entry_t *e = &client_table[client_id];

    if (e->in_use) {
        if (e->addr.ip_be != addr->ip_be ||
            e->addr.port_be != addr->port_be) {
            client_addr_remove(&e->addr, e->client_id);
        }
    } else {
        e->in_use = 1;
        e->client_id = client_id;
        e->highest_seq = 0;
        e->replay_window = 0;
    }

    e->addr = *addr;
    e->last_seen_ms = now_ms;

    client_addr_upsert(addr, client_id);
}

int vp_switch_get_client_addr(uint32_t client_id,
                              struct vp_os_addr *out)
{
    if (client_id == 0 || client_id >= VP_CLIENT_MAX)
        return -1;

    vp_client_entry_t *e = &client_table[client_id];
    if (!e->in_use)
        return -1;

    *out = e->addr;
    return 0;
}

int vp_switch_get_client_id_for_addr(const struct vp_os_addr *addr,
                                     uint32_t *out_client_id)
{
    vp_client_addr_entry_t *e = client_addr_find_entry(addr);
    if (e && e->in_use) {
        if (out_client_id)
            *out_client_id = e->client_id;
        return 0;
    }

    // Fallback: linear scan of client_table to handle hash bucket
    // saturation or collisions. This keeps semantics correct even
    // under adversarial address patterns, at the cost of O(N) in
    // rare cases.
    for (uint32_t cid = 1; cid < VP_CLIENT_MAX; cid++) {
        vp_client_entry_t *c = &client_table[cid];
        if (!c->in_use)
            continue;

        if (c->addr.ip_be == addr->ip_be &&
            c->addr.port_be == addr->port_be)
        {
            if (out_client_id)
                *out_client_id = cid;

            // Try to cache this mapping in the hash table for next time.
            client_addr_upsert(addr, cid);
            return 0;
        }
    }

    return -1;
}

int vp_switch_check_replay(uint32_t client_id, uint32_t seq)
{
    if (client_id == 0 || client_id >= VP_CLIENT_MAX)
        return -1;

    vp_client_entry_t *e = &client_table[client_id];
    if (!e->in_use)
        return -1;

    // Sequence numbers start at 1; 0 is reserved for control.
    if (seq == 0)
        return -1;

    uint32_t highest = e->highest_seq;

    if (highest == 0) {
        e->highest_seq = seq;
        e->replay_window = 1ULL;
        return 0;
    }

    if (seq > highest) {
        uint32_t delta = seq - highest;
        if (delta >= 64) {
            e->replay_window = 1ULL;
        } else {
            e->replay_window <<= delta;
            e->replay_window |= 1ULL;
        }
        e->highest_seq = seq;
        return 0;
    }

    uint32_t diff = highest - seq;
    if (diff >= 64)
        return -1;

    uint64_t mask = 1ULL << diff;
    if (e->replay_window & mask)
        return -1;

    e->replay_window |= mask;
    return 0;
}

void vp_switch_init(void)
{
    memset(mac_table, 0, sizeof(mac_table));
    memset(client_table, 0, sizeof(client_table));
    memset(client_addr_table, 0, sizeof(client_addr_table));
}

void vp_switch_handle_frame(
    uint32_t src_client_id,
    const uint8_t *frame,
    size_t frame_len,
    uint64_t now_ms,
    vp_forward_cb forwarder
)
{
    if (frame_len < 14 || frame_len > VP_MAX_FRAME_LEN)
        return;

    vp_mac_t dst, src;
    memcpy(dst.b, frame + 0, 6);
    memcpy(src.b, frame + 6, 6);

    // 1. Learn source MAC -> client_id
    uint32_t src_bucket = vp_mac_hash(&src) & (VP_MAC_BUCKETS - 1);
    vp_mac_entry_t *src_entry = mac_find_entry(&src);
    if (!src_entry) {
        src_entry = mac_find_free_slot(src_bucket);
        if (src_entry) {
            src_entry->mac = src;
            src_entry->client_id = src_client_id;
            src_entry->last_seen_ms = now_ms;
            src_entry->in_use = 1;
        }
    } else {
        // MAC already learned: only accept frames from the same client_id.
        // If a different client claims this MAC, drop the frame and keep
        // the existing mapping until it times out.
        if (src_entry->client_id != src_client_id)
            return;

        src_entry->last_seen_ms = now_ms;
    }

    // 2. Forwarding
    vp_mac_entry_t *dst_entry = mac_find_entry(&dst);

    // Broadcast?
    int is_broadcast = 1;
    for (int i = 0; i < 6; i++) {
        if (dst.b[i] != 0xff) {
            is_broadcast = 0;
            break;
        }
    }

    if (is_broadcast || !dst_entry) {
        // Global flood limit: drop if budget exhausted
        vp_flood_maybe_refill(now_ms);
        if (g_flood_tokens <= 0)
            return;

        g_flood_tokens--;

        // Flood to all except source
        for (int b = 0; b < VP_MAC_BUCKETS; b++) {
            for (int i = 0; i < VP_MAC_BUCKET_SIZE; i++) {
                if (!mac_table[b][i].in_use)
                    continue;

                uint32_t cid = mac_table[b][i].client_id;
                if (cid != src_client_id)
                    forwarder(src_client_id, cid, frame, frame_len);
            }
        }
    } else {
        uint32_t target = dst_entry->client_id;
        forwarder(src_client_id, target, frame, frame_len);
    }
}

void vp_switch_flush_stale(uint64_t now_ms)
{
    for (int b = 0; b < VP_MAC_BUCKETS; b++) {
        for (int i = 0; i < VP_MAC_BUCKET_SIZE; i++) {
            if (!mac_table[b][i].in_use)
                continue;

            if (now_ms - mac_table[b][i].last_seen_ms > VP_MAC_TIMEOUT_MS) {
                mac_table[b][i].in_use = 0;
            }
        }
    }

    for (uint32_t cid = 0; cid < VP_CLIENT_MAX; cid++) {
        vp_client_entry_t *e = &client_table[cid];
        if (!e->in_use)
            continue;

        if (now_ms - e->last_seen_ms > VP_MAC_TIMEOUT_MS) {
            client_addr_remove(&e->addr, e->client_id);
            e->in_use = 0;
        }
    }
}
