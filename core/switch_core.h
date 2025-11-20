#ifndef VP_SWITCH_CORE_H
#define VP_SWITCH_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "../include/vp_types.h"
#include "../include/os_net.h"

struct vp_os_addr; // forward declaration

typedef struct {
    int in_use;
    uint32_t client_id;
    struct vp_os_addr addr;
    uint64_t last_seen_ms;
    uint32_t highest_seq;
    uint64_t replay_window;
} vp_client_entry_t;

void vp_switch_update_client(uint32_t client_id,
                             const struct vp_os_addr *addr,
                             uint64_t now_ms);

int vp_switch_get_client_addr(uint32_t client_id,
                              struct vp_os_addr *out);

// Look up client_id by remote UDP address
int vp_switch_get_client_id_for_addr(const struct vp_os_addr *addr,
                                     uint32_t *out_client_id);

// Per-client replay protection (DATA / KEEPALIVE)
// Returns 0 on accept, <0 on replay/too-old/invalid.
int vp_switch_check_replay(uint32_t client_id, uint32_t seq);

// Reset per-client volatile state (replay window, MAC bindings) on reconnect.
void vp_switch_reset_client(uint32_t client_id);

// Callback used by switch_core to forward frames
typedef void (*vp_forward_cb)(
    uint32_t src_client_id,
    uint32_t dst_client_id,
    const uint8_t *frame,
    size_t len
);

// Switch entry representing learned MAC address
typedef struct {
    vp_mac_t mac;
    uint32_t client_id;
    uint64_t last_seen_ms;
    int      in_use;
} vp_mac_entry_t;

// Initialize switch core
void vp_switch_init(void);

// Process inbound frame from client
void vp_switch_handle_frame(
    uint32_t src_client_id,
    const uint8_t *frame,
    size_t frame_len,
    uint64_t now_ms,
    vp_forward_cb forwarder
);

// Manual flush (optional)
void vp_switch_flush_stale(uint64_t now_ms);

#endif
