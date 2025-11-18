#include "protocol.h"
#include <string.h>

// --------------------------------------
// CRC32 IEEE (standard)
// --------------------------------------
uint32_t vp_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = ~0u;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
    }
    return ~crc;
}

// --------------------------------------
// Encode header + payload
// --------------------------------------
int vp_encode_packet(uint8_t *buf, size_t buf_len,
                     const vp_header_t *hdr,
                     const uint8_t *payload)
{
    size_t total_len = hdr->header_len + hdr->payload_len;
    if (buf_len < total_len)
        return -1;

    memcpy(buf, hdr, hdr->header_len);

    if (payload && hdr->payload_len > 0)
        memcpy(buf + hdr->header_len, payload, hdr->payload_len);

    return (int)total_len;
}

// --------------------------------------
// Decode + Validate header
// --------------------------------------
int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr)
{
    if (buf_len < sizeof(vp_header_t))
        return -1;

    memcpy(hdr, buf, sizeof(vp_header_t));

    if (hdr->magic != VP_MAGIC)
        return -2;

    if (hdr->version != VP_VERSION)
        return -3;

    if (buf_len < hdr->header_len + hdr->payload_len)
        return -4;

    return 0;
}