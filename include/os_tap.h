#ifndef VP_OS_TAP_H
#define VP_OS_TAP_H

#include <stdint.h>
#include <stddef.h>

struct vp_os_tap;

// Create TAP interface (name optional, may be changed by OS)
int vp_os_tap_open(struct vp_os_tap **tap, const char *ifname_hint);

// Read/write
int vp_os_tap_read(struct vp_os_tap *tap, uint8_t *buf, size_t max_len);
int vp_os_tap_write(struct vp_os_tap *tap, const uint8_t *buf, size_t len);

// Cleanup
void vp_os_tap_close(struct vp_os_tap *tap);

#endif