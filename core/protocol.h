#ifndef VP_PROTOCOL_H
#define VP_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define VP_MAGIC 0x56504E32  // "VPN2"
#define VP_VERSION 2
#define VP_HEADER_WIRE_LEN 24

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;        // VP_MAGIC
    uint8_t  version;      // VP_VERSION
    uint8_t  type;         // VP_PKT_*
    uint16_t header_len;   // header length on wire (bytes)
    uint16_t payload_len;  // Length of Ethernet frame
    uint16_t flags;
    uint32_t client_id;
    uint32_t seq;          // anti-replay / reorder protection
    uint32_t checksum;     // CRC32 payload
} vp_header_t;
#pragma pack(pop)

// Calculate CRC32
uint32_t vp_crc32(const uint8_t *data, size_t len);

// Encode header + payload into buffer
int vp_encode_packet(uint8_t *buf, size_t buf_len,
                     const vp_header_t *hdr,
                     const uint8_t *payload);

// Decode header (and validate magic/version/bounds)
int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr);

#endif
