#include "protocol.h"
#include <string.h>

// --------------------------------------
// Helpers: fixed-endian (big endian) I/O
// --------------------------------------
static void vp_write_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static void vp_write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static uint16_t vp_read_u16_be(const uint8_t *p)
{
    return (uint16_t)((((uint16_t)p[0]) << 8) | ((uint16_t)p[1]));
}

static uint32_t vp_read_u32_be(const uint8_t *p)
{
    return (((uint32_t)p[0]) << 24) |
           (((uint32_t)p[1]) << 16) |
           (((uint32_t)p[2]) << 8)  |
           ((uint32_t)p[3]);
}

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
    size_t header_len = VP_HEADER_WIRE_LEN;
    size_t payload_len = hdr->payload_len;
    size_t total_len = header_len + payload_len;
    if (buf_len < total_len)
        return -1;

    // Serialize header in a stable, padding-independent way
    vp_write_u32_be(buf + 0, hdr->magic);
    buf[4] = hdr->version;
    buf[5] = hdr->type;
    vp_write_u16_be(buf + 6, (uint16_t)header_len);
    vp_write_u16_be(buf + 8, hdr->payload_len);
    vp_write_u16_be(buf + 10, hdr->flags);
    vp_write_u32_be(buf + 12, hdr->client_id);
    vp_write_u32_be(buf + 16, hdr->seq);
    vp_write_u32_be(buf + 20, hdr->checksum);

    if (payload && payload_len > 0)
        memcpy(buf + header_len, payload, payload_len);

    return (int)total_len;
}

// --------------------------------------
// Decode + Validate header
// --------------------------------------
int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr)
{
    if (buf_len < VP_HEADER_WIRE_LEN)
        return -1;

    hdr->magic = vp_read_u32_be(buf + 0);
    if (hdr->magic != VP_MAGIC)
        return -2;

    hdr->version = buf[4];
    if (hdr->version != VP_VERSION)
        return -3;

    hdr->type        = buf[5];
    hdr->header_len  = vp_read_u16_be(buf + 6);
    hdr->payload_len = vp_read_u16_be(buf + 8);
    hdr->flags       = vp_read_u16_be(buf + 10);
    hdr->client_id   = vp_read_u32_be(buf + 12);
    hdr->seq         = vp_read_u32_be(buf + 16);
    hdr->checksum    = vp_read_u32_be(buf + 20);

    // Basic bounds validation
    size_t header_len = hdr->header_len;
    size_t payload_len = hdr->payload_len;

    if (header_len < VP_HEADER_WIRE_LEN)
        return -4;

    if (buf_len < header_len + payload_len)
        return -4;

    return 0;
}
