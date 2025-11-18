#include "protocol.h"
#include <string.h>

int vp_encode_header(uint8_t *buf, size_t buf_len,
                     const vp_header_t *hdr)
{
    if (buf_len < sizeof(vp_header_t))
        return -1;

    memcpy(buf, hdr, sizeof(vp_header_t));
    return sizeof(vp_header_t);
}

int vp_decode_header(const uint8_t *buf, size_t buf_len,
                     vp_header_t *hdr)
{
    if (buf_len < sizeof(vp_header_t))
        return -1;

    memcpy(hdr, buf, sizeof(vp_header_t));
    return sizeof(vp_header_t);
}