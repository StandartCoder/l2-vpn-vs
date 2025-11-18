#ifndef VP_SWITCH_CORE_H
#define VP_SWITCH_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "../include/vp_types.h"

// Callback used by switch_core to forward frames
typedef void (*vp_forward_cb)(
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
    vp_forward_cb forwarder
);

// Manual flush (optional)
void vp_switch_flush_stale(uint64_t now_ms);

#endif