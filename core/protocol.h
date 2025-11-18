#ifndef VP_PROTOCOL_H
#define VP_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "../include/vp_types.h"

#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t client_id;
    uint32_t reserved;
} vp_header_t;
#pragma pack(pop)

// Encode header into buffer
int vp_encode_header(uint8_t *buf, size_t buf_len,
                     const vp_header_t *hdr);

// Decode header from buffer
int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr);

#endif