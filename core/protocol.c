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

// --------------------------------------
// Simple keyed MAC (SipHash-2-4) + keys
// --------------------------------------
// g_vp_psk      : 128-bit key used as root key for derivations
// g_vp_enc_key  : 256-bit key used for ChaCha20-Poly1305 AEAD
static uint8_t g_vp_psk[16];
static uint8_t g_vp_enc_key[32];
static int g_vp_psk_loaded = 0;

// Forward declaration for KDF
static uint64_t vp_siphash24(const uint8_t key[16],
                             const uint8_t *data,
                             size_t len);

// Derive a 128-bit key from an arbitrary-length passphrase using
// a SipHash-based PRF. This is *not* a password hardening function;
// VP_PSK must already be high-entropy. We keep this very simple and
// analyzable instead of trying to emulate a memory-hard KDF.
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

    uint64_t left  = vp_siphash24(seed1, p, pass_len);
    uint64_t right = vp_siphash24(seed2, p, pass_len);

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

// --------------------------------------
// ChaCha20 stream cipher (RFC 8439 core)
// --------------------------------------

static uint32_t vp_load_u32_le(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void vp_store_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t vp_rotl32(uint32_t x, int b)
{
    return (x << b) | (x >> (32 - b));
}

#define VP_CHACHA_QUARTERROUND(a,b,c,d) \
    do {                                \
        a += b; d ^= a; d = vp_rotl32(d, 16); \
        c += d; b ^= c; b = vp_rotl32(b, 12); \
        a += b; d ^= a; d = vp_rotl32(d, 8);  \
        c += d; b ^= c; b = vp_rotl32(b, 7);  \
    } while (0)

static void vp_chacha20_block(const uint8_t key[32],
                              const uint8_t nonce[12],
                              uint32_t counter,
                              uint8_t out[64])
{
    static const uint8_t sigma[16] = {
        'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
    };

    uint32_t state[16];
    state[0]  = vp_load_u32_le(sigma + 0);
    state[1]  = vp_load_u32_le(sigma + 4);
    state[2]  = vp_load_u32_le(sigma + 8);
    state[3]  = vp_load_u32_le(sigma + 12);
    state[4]  = vp_load_u32_le(key + 0);
    state[5]  = vp_load_u32_le(key + 4);
    state[6]  = vp_load_u32_le(key + 8);
    state[7]  = vp_load_u32_le(key + 12);
    state[8]  = vp_load_u32_le(key + 16);
    state[9]  = vp_load_u32_le(key + 20);
    state[10] = vp_load_u32_le(key + 24);
    state[11] = vp_load_u32_le(key + 28);
    state[12] = counter;
    state[13] = vp_load_u32_le(nonce + 0);
    state[14] = vp_load_u32_le(nonce + 4);
    state[15] = vp_load_u32_le(nonce + 8);

    uint32_t working[16];
    for (int i = 0; i < 16; i++)
        working[i] = state[i];

    for (int i = 0; i < 10; i++) {
        // odd round (column)
        VP_CHACHA_QUARTERROUND(working[0], working[4], working[8],  working[12]);
        VP_CHACHA_QUARTERROUND(working[1], working[5], working[9],  working[13]);
        VP_CHACHA_QUARTERROUND(working[2], working[6], working[10], working[14]);
        VP_CHACHA_QUARTERROUND(working[3], working[7], working[11], working[15]);
        // even round (diagonal)
        VP_CHACHA_QUARTERROUND(working[0], working[5], working[10], working[15]);
        VP_CHACHA_QUARTERROUND(working[1], working[6], working[11], working[12]);
        VP_CHACHA_QUARTERROUND(working[2], working[7], working[8],  working[13]);
        VP_CHACHA_QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t v = working[i] + state[i];
        vp_store_u32_le(out + 4 * i, v);
    }
}

static void vp_chacha20_xor(const uint8_t key[32],
                            const uint8_t nonce[12],
                            uint32_t counter,
                            uint8_t *data,
                            size_t len)
{
    uint8_t block[64];
    size_t offset = 0;

    while (offset < len) {
        vp_chacha20_block(key, nonce, counter, block);
        size_t chunk = len - offset;
        if (chunk > sizeof(block))
            chunk = sizeof(block);

        for (size_t i = 0; i < chunk; i++)
            data[offset + i] ^= block[i];

        offset += chunk;
        counter++;
    }
}

// Derive per-packet nonce from direction + client_id + seq.
// This is public, non-secret data; uniqueness (not secrecy)
// is what matters here.
static void vp_build_nonce(vp_crypto_dir_t dir,
                           const vp_header_t *hdr,
                           uint8_t nonce[12])
{
    uint32_t dir_word =
        (dir == VP_CRYPTO_DIR_CLIENT_TO_SWITCH) ? 0x43523331u : 0x53523332u; // "CR31"/"SR32"

    vp_store_u32_le(nonce + 0, dir_word);
    vp_store_u32_le(nonce + 4, hdr->client_id);
    vp_store_u32_le(nonce + 8, hdr->seq);
}

static void vp_auth_load_key(void);

// Update the per-session DATA key based on a caller-provided
// session identifier that is shared between both peers via the
// control-plane handshake.
void vp_crypto_set_session(const uint8_t session_id[32])
{
    (void)session_id;
    vp_auth_load_key();
}

static void vp_auth_load_key(void)
{
    if (g_vp_psk_loaded)
        return;

    g_vp_psk_loaded = 1;

    const char *env = getenv("VP_PSK");
    memset(g_vp_psk, 0, sizeof(g_vp_psk));
    memset(g_vp_enc_key, 0, sizeof(g_vp_enc_key));

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

    // First derive a 128-bit master key from the passphrase.
    vp_kdf_from_psk(env, pass_len, g_vp_psk);

    // Expand master key into a 256-bit encryption key using SipHash
    // as a simple PRF with domain separation.
    uint8_t label[4] = { 'E', 'N', 'C', 0 };
    for (int i = 0; i < 4; i++) {
        label[3] = (uint8_t)i;
        uint64_t v = vp_siphash24(g_vp_psk, label, sizeof(label));
        for (int b = 0; b < 8; b++) {
            g_vp_enc_key[i * 8 + b] = (uint8_t)(v >> (8 * b));
        }
    }
}

static void vp_pack_header(uint8_t *buf, const vp_header_t *hdr)
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
    // auth_tag starts at offset 24, 16 bytes
    memcpy(buf + 24, hdr->auth_tag, 16);
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
// Poly1305 (for ChaCha20-Poly1305 AEAD)
// --------------------------------------

typedef struct {
    uint64_t r0, r1, r2;
    uint64_t s1, s2;
    uint64_t h0, h1, h2;
    uint64_t pad0, pad1;
} vp_poly1305_state_t;

static void vp_poly1305_init(vp_poly1305_state_t *st, const uint8_t key[32])
{
    uint64_t t0 = ((uint64_t)vp_load_u32_le(key + 0)) |
                  ((uint64_t)vp_load_u32_le(key + 4) << 32);
    uint64_t t1 = ((uint64_t)vp_load_u32_le(key + 8)) |
                  ((uint64_t)vp_load_u32_le(key + 12) << 32);

    uint64_t r0 = (t0) & 0xffc0fffffffULL;
    uint64_t r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffULL;
    uint64_t r2 = (t1 >> 24) & 0x00ffffffc0fULL;

    st->r0 = r0;
    st->r1 = r1;
    st->r2 = r2;
    st->s1 = r1 * 5;
    st->s2 = r2 * 5;

    st->h0 = 0;
    st->h1 = 0;
    st->h2 = 0;

    uint64_t t2 = ((uint64_t)vp_load_u32_le(key + 16)) |
                  ((uint64_t)vp_load_u32_le(key + 20) << 32);
    uint64_t t3 = ((uint64_t)vp_load_u32_le(key + 24)) |
                  ((uint64_t)vp_load_u32_le(key + 28) << 32);

    st->pad0 = t2;
    st->pad1 = t3;
}

static void vp_poly1305_block(vp_poly1305_state_t *st,
                              const uint8_t *m,
                              size_t remaining,
                              int is_final)
{
    uint64_t t0, t1;

    if (remaining >= 16) {
        t0 = ((uint64_t)vp_load_u32_le(m + 0)) |
             ((uint64_t)vp_load_u32_le(m + 4) << 32);
        t1 = ((uint64_t)vp_load_u32_le(m + 8)) |
             ((uint64_t)vp_load_u32_le(m + 12) << 32);
    } else {
        uint8_t tmp[16] = {0};
        if (remaining > 0)
            memcpy(tmp, m, remaining);
        tmp[remaining] = 1;
        t0 = ((uint64_t)vp_load_u32_le(tmp + 0)) |
             ((uint64_t)vp_load_u32_le(tmp + 4) << 32);
        t1 = ((uint64_t)vp_load_u32_le(tmp + 8)) |
             ((uint64_t)vp_load_u32_le(tmp + 12) << 32);
    }

    uint64_t h0 = st->h0;
    uint64_t h1 = st->h1;
    uint64_t h2 = st->h2;

    h0 += ( t0                    ) & 0xfffffffffffULL;
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffffULL);
    h2 += ( (t1 >> 24)             & 0x3ffffffffffULL);
    if (!is_final)
        h2 += (1ULL << 40);

    uint64_t r0 = st->r0;
    uint64_t r1 = st->r1;
    uint64_t r2 = st->r2;
    uint64_t s1 = st->s1;
    uint64_t s2 = st->s2;

    __uint128_t d0 = (__uint128_t)h0 * r0 +
                     (__uint128_t)h1 * s2 +
                     (__uint128_t)h2 * s1;
    __uint128_t d1 = (__uint128_t)h0 * r1 +
                     (__uint128_t)h1 * r0 +
                     (__uint128_t)h2 * s2;
    __uint128_t d2 = (__uint128_t)h0 * r2 +
                     (__uint128_t)h1 * r1 +
                     (__uint128_t)h2 * r0;

    uint64_t c;

    h0 = (uint64_t)d0 & 0xfffffffffffULL;
    c  = (uint64_t)(d0 >> 44);
    d1 += c;
    h1 = (uint64_t)d1 & 0xfffffffffffULL;
    c  = (uint64_t)(d1 >> 44);
    d2 += c;
    h2 = (uint64_t)d2 & 0x3ffffffffffULL;
    c  = (uint64_t)(d2 >> 42);
    h0 += c * 5;
    c  = h0 >> 44;
    h0 &= 0xfffffffffffULL;
    h1 += c;

    st->h0 = h0;
    st->h1 = h1;
    st->h2 = h2;
}

static void vp_poly1305_update(vp_poly1305_state_t *st,
                               const uint8_t *m,
                               size_t bytes)
{
    while (bytes >= 16) {
        vp_poly1305_block(st, m, 16, 0);
        m     += 16;
        bytes -= 16;
    }
    if (bytes > 0)
        vp_poly1305_block(st, m, bytes, 0);
}

static void vp_poly1305_finish(vp_poly1305_state_t *st, uint8_t out[16])
{
    uint64_t h0 = st->h0;
    uint64_t h1 = st->h1;
    uint64_t h2 = st->h2;

    uint64_t c = h1 >> 44;
    h1 &= 0xfffffffffffULL;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffffULL;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffffULL;
    h1 += c;

    uint64_t g0 = h0 + 5;
    c  = g0 >> 44;
    g0 &= 0xfffffffffffULL;
    uint64_t g1 = h1 + c;
    c  = g1 >> 44;
    g1 &= 0xfffffffffffULL;
    uint64_t g2 = h2 + c - (1ULL << 42);

    uint64_t mask = (g2 >> 63) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;

    h0 = ((h0      )      ) | (h1 << 44);
    h1 = ((h1 >> 20)      ) | (h2 << 24);

    h0 += st->pad0;
    h1 += st->pad1;

    vp_store_u32_le(out + 0,  (uint32_t)(h0));
    vp_store_u32_le(out + 4,  (uint32_t)(h0 >> 32));
    vp_store_u32_le(out + 8,  (uint32_t)(h1));
    vp_store_u32_le(out + 12, (uint32_t)(h1 >> 32));
}

static void vp_poly1305_aead(uint8_t out_tag[16],
                             const uint8_t otk[32],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *cipher, size_t cipher_len)
{
    vp_poly1305_state_t st;
    vp_poly1305_init(&st, otk);

    if (aad_len > 0)
        vp_poly1305_update(&st, aad, aad_len);

    if (aad_len % 16) {
        uint8_t zero[16] = {0};
        vp_poly1305_update(&st, zero, 16 - (aad_len % 16));
    }

    if (cipher_len > 0)
        vp_poly1305_update(&st, cipher, cipher_len);

    if (cipher_len % 16) {
        uint8_t zero[16] = {0};
        vp_poly1305_update(&st, zero, 16 - (cipher_len % 16));
    }

    uint8_t len_block[16];
    vp_store_u32_le(len_block + 0,  (uint32_t)(aad_len & 0xffffffffu));
    vp_store_u32_le(len_block + 4,  (uint32_t)(aad_len >> 32));
    vp_store_u32_le(len_block + 8,  (uint32_t)(cipher_len & 0xffffffffu));
    vp_store_u32_le(len_block + 12, (uint32_t)(cipher_len >> 32));
    vp_poly1305_update(&st, len_block, sizeof(len_block));

    vp_poly1305_finish(&st, out_tag);
}

// --------------------------------------
// Encode header + payload (ChaCha20-Poly1305)
// --------------------------------------
int vp_encode_packet(vp_crypto_dir_t dir,
                     uint8_t *buf, size_t buf_len,
                     const vp_header_t *hdr,
                     const uint8_t *payload)
{
    vp_auth_load_key();

    size_t header_len = VP_HEADER_WIRE_LEN;
    size_t payload_len = hdr->payload_len;
    size_t total_len = header_len + payload_len;
    if (buf_len < total_len)
        return -1;

    vp_header_t tmp = *hdr;
    tmp.header_len = (uint16_t)header_len;
    memset(tmp.auth_tag, 0, sizeof(tmp.auth_tag));
    vp_pack_header(buf, &tmp);

    if (payload && payload_len > 0)
        memcpy(buf + header_len, payload, payload_len);

    const uint8_t *key = g_vp_enc_key;

    uint8_t nonce[12];
    vp_build_nonce(dir, &tmp, nonce);

    if (payload_len > 0 && hdr->type == VP_PKT_DATA) {
        vp_chacha20_xor(key, nonce, 1, buf + header_len, payload_len);
    }

    uint8_t block0[64];
    vp_chacha20_block(key, nonce, 0, block0);
    uint8_t otk[32];
    memcpy(otk, block0, sizeof(otk));

    uint8_t tag[16];
    vp_poly1305_aead(tag, otk, buf, header_len, buf + header_len, payload_len);

    memcpy(tmp.auth_tag, tag, sizeof(tmp.auth_tag));
    vp_pack_header(buf, &tmp);

    return (int)total_len;
}

// --------------------------------------
// Decode + authenticate + decrypt (ChaCha20-Poly1305)
// --------------------------------------
int vp_decode_packet(vp_crypto_dir_t dir,
                     uint8_t *buf, size_t buf_len,
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
    memcpy(hdr->auth_tag, buf + 24, 16);

    size_t header_len = hdr->header_len;
    size_t payload_len = hdr->payload_len;

    if (header_len != VP_HEADER_WIRE_LEN)
        return -4;
    if (buf_len < header_len + payload_len)
        return -4;
    if (payload_len > VP_MAX_FRAME_LEN)
        return -5;

    const uint8_t *key = g_vp_enc_key;

    uint8_t nonce[12];
    vp_build_nonce(dir, hdr, nonce);

    uint8_t block0[64];
    vp_chacha20_block(key, nonce, 0, block0);
    uint8_t otk[32];
    memcpy(otk, block0, sizeof(otk));

    uint8_t aad[VP_HEADER_WIRE_LEN];
    memcpy(aad, buf, header_len);
    memset(aad + 24, 0, 16);

    uint8_t tag[16];
    vp_poly1305_aead(tag, otk, aad, header_len, buf + header_len, payload_len);

    uint32_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= (uint32_t)(tag[i] ^ hdr->auth_tag[i]);
    if (diff != 0)
        return -6;

    if (payload_len > 0 && hdr->type == VP_PKT_DATA) {
        vp_chacha20_xor(key, nonce, 1, buf + header_len, payload_len);
    }

    return 0;
}
