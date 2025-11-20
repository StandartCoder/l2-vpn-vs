#pragma once

#ifdef __APPLE__
#include <vmnet/vmnet.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include <stdint.h>
#include <sys/types.h>

// Opaque backend context
struct vmnet_backend;

// Initialize vmnet backend (shared mode). Returns 0 on success.
int vmnet_backend_init(struct vmnet_backend **out);

// Blocking read from vmnet (Ethernet frame). Returns length or -1 on error/EAGAIN.
ssize_t vmnet_backend_read(struct vmnet_backend *ctx, uint8_t *buf, size_t len);

// Blocking write of a full Ethernet frame. Returns length or -1 on error.
ssize_t vmnet_backend_write(struct vmnet_backend *ctx, const uint8_t *buf, size_t len);

// Shutdown and free resources.
void vmnet_backend_close(struct vmnet_backend *ctx);

#endif // __APPLE__
