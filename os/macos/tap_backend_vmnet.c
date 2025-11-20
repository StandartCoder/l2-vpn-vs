#ifdef __APPLE__

#include "tap_backend_vmnet.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <pthread.h>

struct vmnet_backend {
    vmnet_interface_ref iface;
    dispatch_queue_t queue;
    xpc_object_t if_desc;
    pthread_mutex_t lock;
    int started;
    int stop;
};

static vmnet_return_t vmnet_start_blocking(struct vmnet_backend *ctx)
{
    __block vmnet_return_t start_ret = VMNET_FAILURE;

    vmnet_start_interface(ctx->if_desc, ctx->queue, ^(vmnet_return_t status, vmnet_interface_ref interface_ref) {
        start_ret = status;
        if (status == VMNET_SUCCESS)
            ctx->iface = interface_ref;
    });

    // Busy-wait until start_ret updated (on the same dispatch queue)
    // In practice vmnet_start_interface invokes callback before returning.
    return start_ret;
}

int vmnet_backend_init(struct vmnet_backend **out)
{
    if (!out)
        return -1;

    struct vmnet_backend *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->queue = dispatch_queue_create("vpnet.vmnet.queue", DISPATCH_QUEUE_SERIAL);
    if (!ctx->queue) {
        free(ctx);
        return -1;
    }

    pthread_mutex_init(&ctx->lock, NULL);

    // Shared mode interface description
    xpc_object_t if_desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(if_desc, vmnet_operation_mode_key, VMNET_SHARED_MODE);
    // Auto-generate MAC; vmnet will assign one.

    ctx->if_desc = if_desc;

    vmnet_return_t ret = vmnet_start_blocking(ctx);
    if (ret != VMNET_SUCCESS || ctx->iface == NULL) {
        vmnet_backend_close(ctx);
        return -1;
    }

    ctx->started = 1;
    *out = ctx;
    return 0;
}

ssize_t vmnet_backend_read(struct vmnet_backend *ctx, uint8_t *buf, size_t len)
{
    if (!ctx || !ctx->started || !buf || len == 0)
        return -1;

    // The vmnet_read() API uses iovec for scatter/gather reads.
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;

    ssize_t bytes_read = -1;
    vmnet_return_t ret = vmnet_read(ctx->iface, &iov, 1, &bytes_read);
    if (ret == VMNET_SUCCESS && bytes_read >= 0)
        return bytes_read;

    if (ret == VMNET_BUFFER_EXHAUSTED || ret == VMNET_WOULD_BLOCK) {
        errno = EAGAIN;
        return -1;
    }

    errno = EIO;
    return -1;
}

ssize_t vmnet_backend_write(struct vmnet_backend *ctx, const uint8_t *buf, size_t len)
{
    if (!ctx || !ctx->started || !buf || len == 0)
        return -1;

    struct iovec iov;
    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    ssize_t bytes_written = -1;
    vmnet_return_t ret = vmnet_write(ctx->iface, &iov, 1, &bytes_written);
    if (ret == VMNET_SUCCESS && bytes_written == (ssize_t)len)
        return bytes_written;

    if (ret == VMNET_WOULD_BLOCK || ret == VMNET_BUFFER_EXHAUSTED) {
        errno = EAGAIN;
        return -1;
    }

    errno = EIO;
    return -1;
}

void vmnet_backend_close(struct vmnet_backend *ctx)
{
    if (!ctx)
        return;

    ctx->stop = 1;

    if (ctx->iface) {
        vmnet_stop_interface(ctx->iface, NULL);
        ctx->iface = NULL;
    }

    if (ctx->if_desc) {
        xpc_release(ctx->if_desc);
        ctx->if_desc = NULL;
    }

    if (ctx->queue) {
        // Dispatch queues are reference counted; release it.
        dispatch_release(ctx->queue);
        ctx->queue = NULL;
    }

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

#endif // __APPLE__
