#ifndef VP_TYPES_H
#define VP_TYPES_H

#include <stdint.h>
#include <stddef.h>

// Packet types
enum vp_pkt_type {
    VP_PKT_HELLO      = 1,
    VP_PKT_HELLO_ACK  = 2,
    VP_PKT_DATA       = 3,
    VP_PKT_KEEPALIVE  = 4,
    VP_PKT_ERROR      = 5
};

// Max VPN payload size (bytes)
// Limited below full Ethernet MTU to avoid UDP fragmentation.
#define VP_MAX_FRAME_LEN 1514

// Max number of connected clients
#define VP_MAX_CLIENTS 1024

// MAC entry TTL in ms
#define VP_MAC_TIMEOUT_MS 60000

// 6-byte MAC
typedef struct {
    uint8_t b[6];
} vp_mac_t;

#endif
