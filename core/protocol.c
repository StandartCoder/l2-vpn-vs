#include "protocol.h"
#include "../include/vp_types.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// --------------------------------------
// Helpers: fixed-endian I/O
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

static void vp_write_u64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xFF);
    p[1] = (uint8_t)((v >> 48) & 0xFF);
    p[2] = (uint8_t)((v >> 40) & 0xFF);
    p[3] = (uint8_t)((v >> 32) & 0xFF);
    p[4] = (uint8_t)((v >> 24) & 0xFF);
    p[5] = (uint8_t)((v >> 16) & 0xFF);
    p[6] = (uint8_t)((v >> 8) & 0xFF);
    p[7] = (uint8_t)(v & 0xFF);
}

static uint64_t vp_read_u64_be(const uint8_t *p)
{
    return (((uint64_t)p[0]) << 56) |
           (((uint64_t)p[1]) << 48) |
           (((uint64_t)p[2]) << 40) |
           (((uint64_t)p[3]) << 32) |
           (((uint64_t)p[4]) << 24) |
           (((uint64_t)p[5]) << 16) |
           (((uint64_t)p[6]) << 8)  |
           ((uint64_t)p[7]);
}

// --------------------------------------
// Simple keyed MAC (SipHash-2-4)
// --------------------------------------
static uint8_t g_vp_psk[16];
static int g_vp_psk_loaded = 0;

// Derive a 128-bit key from an arbitrary-length passphrase using
// SipHash-based KDF with fixed public seeds and many iterations.
// This is NOT a replacement for a modern password hash, but it
// significantly raises the cost of offline guessing compared to
// using the raw passphrase bytes directly.
static void vp_kdf_from_psk(const char *pass, size_t pass_len, uint8_t out_key[16])
{
    static const uint8_t seed1[16] = {
        0x4B, 0x44, 0x46, 0x31, 0x21, 0x90, 0xAB, 0xCD,
        0xEF, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA
    };
    static const uint8_t seed2[16] = {
        0x53, 0x45, 0x43, 0x32, 0x42, 0xA1, 0xBC, 0xDE,
        0xF0, 0x12, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xCB
    };

    const uint8_t *p = (const uint8_t *)pass;

    // Initial mixing of passphrase into two 64-bit lanes
    uint64_t left  = vp_siphash24(seed1, p, pass_len);
    uint64_t right = vp_siphash24(seed2, p, pass_len);

    // Iterative strengthening: repeatedly fold lanes back through SipHash
    // to make each candidate guess more expensive to evaluate.
    const int rounds = 4096;
    uint8_t buf[8];

    for (int i = 0; i < rounds; i++) {
        // Mix 'left'
        for (int j = 0; j < 8; j++)
            buf[j] = (uint8_t)(left >> (8 * j));
        left = vp_siphash24(seed1, buf, sizeof(buf));

        // Mix 'right'
        for (int j = 0; j < 8; j++)
            buf[j] = (uint8_t)(right >> (8 * j));
        right = vp_siphash24(seed2, buf, sizeof(buf));
    }

    // Export as 16-byte little-endian key
    for (int i = 0; i < 8; i++) {
        out_key[i]      = (uint8_t)(left >> (8 * i));
        out_key[8 + i]  = (uint8_t)(right >> (8 * i));
    }
}

static uint64_t vp_load_u64_le(const uint8_t *p)
{
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint64_t vp_rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

static void vp_sipround(uint64_t *v0, uint64_t *v1,
                        uint64_t *v2, uint64_t *v3)
{
    *v0 += *v1;
    *v2 += *v3;
    *v1 = vp_rotl64(*v1, 13);
    *v3 = vp_rotl64(*v3, 16);
    *v1 ^= *v0;
    *v3 ^= *v2;
    *v0 = vp_rotl64(*v0, 32);
    *v2 += *v1;
    *v0 += *v3;
    *v1 = vp_rotl64(*v1, 17);
    *v3 = vp_rotl64(*v3, 21);
    *v1 ^= *v2;
    *v3 ^= *v0;
    *v2 = vp_rotl64(*v2, 32);
}

static uint64_t vp_siphash24(const uint8_t key[16],
                             const uint8_t *data,
                             size_t len)
{
    uint64_t k0 = vp_load_u64_le(key + 0);
    uint64_t k1 = vp_load_u64_le(key + 8);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *end = data + len - (len % 8);
    const uint8_t *p = data;

    while (p != end) {
        uint64_t m = vp_load_u64_le(p);
        v3 ^= m;
        vp_sipround(&v0, &v1, &v2, &v3);
        vp_sipround(&v0, &v1, &v2, &v3);
        v0 ^= m;
        p += 8;
    }

    uint64_t b = (uint64_t)len << 56;
    size_t left = len & 7;
    switch (left) {
        case 7: b |= ((uint64_t)p[6] << 48);
        case 6: b |= ((uint64_t)p[5] << 40);
        case 5: b |= ((uint64_t)p[4] << 32);
        case 4: b |= ((uint64_t)p[3] << 24);
        case 3: b |= ((uint64_t)p[2] << 16);
        case 2: b |= ((uint64_t)p[1] << 8);
        case 1: b |= ((uint64_t)p[0]);
        default: break;
    }

    v3 ^= b;
    vp_sipround(&v0, &v1, &v2, &v3);
    vp_sipround(&v0, &v1, &v2, &v3);
    v0 ^= b;

    v2 ^= 0xff;
    vp_sipround(&v0, &v1, &v2, &v3);
    vp_sipround(&v0, &v1, &v2, &v3);
    vp_sipround(&v0, &v1, &v2, &v3);
    vp_sipround(&v0, &v1, &v2, &v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

static void vp_auth_load_key(void)
{
    if (g_vp_psk_loaded)
        return;

    g_vp_psk_loaded = 1;

    const char *env = getenv("VP_PSK");
    memset(g_vp_psk, 0, sizeof(g_vp_psk));

    if (!env || !env[0]) {
        fprintf(stderr,
                "[vpnet] FATAL: VP_PSK environment variable is not set. "
                "A strong pre-shared key is required for authentication.\n");
        exit(1);
    }

    // Bound the length we feed into the KDF to avoid pathological env sizes.
    size_t pass_len = strlen(env);
    const size_t max_pass_len = 256;
    if (pass_len > max_pass_len)
        pass_len = max_pass_len;

    vp_kdf_from_psk(env, pass_len, g_vp_psk);
}

static void vp_pack_header(uint8_t *buf, const vp_header_t *hdr, uint64_t auth_tag)
{
    vp_write_u32_be(buf + 0, hdr->magic);
    buf[4] = hdr->version;
    buf[5] = hdr->type;
    vp_write_u16_be(buf + 6, (uint16_t)hdr->header_len);
    vp_write_u16_be(buf + 8, hdr->payload_len);
    vp_write_u16_be(buf + 10, hdr->flags);
    vp_write_u32_be(buf + 12, hdr->client_id);
    vp_write_u32_be(buf + 16, hdr->seq);
    vp_write_u32_be(buf + 20, hdr->checksum);
    vp_write_u64_be(buf + 24, auth_tag);
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
    vp_auth_load_key();

    size_t header_len = VP_HEADER_WIRE_LEN;
    size_t payload_len = hdr->payload_len;
    size_t total_len = header_len + payload_len;
    if (buf_len < total_len)
        return -1;

    // Serialize header with auth_tag=0 for MAC computation
    vp_header_t tmp = *hdr;
    tmp.header_len = (uint16_t)header_len;
    tmp.auth_tag = 0;
    vp_pack_header(buf, &tmp, 0);

    if (payload && payload_len > 0)
        memcpy(buf + header_len, payload, payload_len);

    // Compute MAC over header (with auth_tag=0) + payload
    uint64_t tag = vp_siphash24(g_vp_psk, buf, total_len);

    // Write final header including auth_tag
    tmp.auth_tag = tag;
    vp_pack_header(buf, &tmp, tag);

    return (int)total_len;
}

// --------------------------------------
// Decode + Validate header
// --------------------------------------
int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr)
{
    vp_auth_load_key();

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
    hdr->auth_tag    = vp_read_u64_be(buf + 24);

    // Basic bounds validation
    size_t header_len = hdr->header_len;
    size_t payload_len = hdr->payload_len;

    if (header_len < VP_HEADER_WIRE_LEN)
        return -4;

    if (buf_len < header_len + payload_len)
        return -4;

    // Verify MAC over header (with auth_tag=0) + payload
    vp_header_t tmp = *hdr;
    tmp.auth_tag = 0;

    uint8_t hdr_bytes[VP_HEADER_WIRE_LEN + VP_MAX_FRAME_LEN];
    if (header_len > VP_HEADER_WIRE_LEN)
        return -5;
    if (payload_len > VP_MAX_FRAME_LEN)
        return -6;

    vp_pack_header(hdr_bytes, &tmp, 0);
    if (payload_len > 0)
        memcpy(hdr_bytes + header_len, buf + header_len, payload_len);

    uint64_t expected = vp_siphash24(g_vp_psk, hdr_bytes, header_len + payload_len);
    if (expected != hdr->auth_tag)
        return -7;

    return 0;
}
