#ifdef __APPLE__

#include "tap_backend_vmnet.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

struct vmnet_backend {
    xpc_object_t iface;   // vmnet interface reference (opaque xpc_object_t)
    dispatch_queue_t queue;
    xpc_object_t if_desc;
    pthread_mutex_t lock;
    int started;
    int stop;
};

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

    __block vmnet_return_t start_ret = VMNET_FAILURE;
    __block xpc_object_t started_iface = NULL;

    vmnet_start_interface(ctx->if_desc, ctx->queue, ^(vmnet_return_t status, xpc_object_t interface_ref) {
        start_ret = status;
        if (status == VMNET_SUCCESS)
            started_iface = interface_ref;
    });

    if (start_ret != VMNET_SUCCESS || started_iface == NULL) {
        vmnet_backend_close(ctx);
        return -1;
    }

    ctx->iface = started_iface;
    ctx->started = 1;

    *out = ctx;
    return 0;
}

ssize_t vmnet_backend_read(struct vmnet_backend *ctx, uint8_t *buf, size_t len)
{
    if (!ctx || !ctx->started || !buf || len == 0)
        return -1;

    struct vmpktdesc pkt = {0};
    pkt.vm_pkt_iovcnt = 1;
    pkt.vm_pkt_size = len;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    pkt.vm_pkt_iov = &iov;

    int pkts = 1;
    vmnet_return_t ret = vmnet_read(ctx->iface, &pkt, &pkts);
    if (ret == VMNET_SUCCESS && pkts == 1)
        return (ssize_t)pkt.vm_pkt_size;

    if (ret == VMNET_BUFFER_EXHAUSTED) {
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

    struct vmpktdesc pkt = {0};
    pkt.vm_pkt_iovcnt = 1;
    pkt.vm_pkt_size = len;
    struct iovec iov;
    iov.iov_base = (void *)buf;
    iov.iov_len = len;
    pkt.vm_pkt_iov = &iov;

    int pkts = 1;
    vmnet_return_t ret = vmnet_write(ctx->iface, &pkt, &pkts);
    if (ret == VMNET_SUCCESS && pkts == 1)
        return (ssize_t)len;

    if (ret == VMNET_BUFFER_EXHAUSTED) {
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
        vmnet_stop_interface(ctx->iface, ctx->queue, ^(vmnet_return_t status) {
            (void)status;
        });
        ctx->iface = NULL;
    }

    if (ctx->if_desc) {
        xpc_release(ctx->if_desc);
        ctx->if_desc = NULL;
    }

    if (ctx->queue) {
        dispatch_release(ctx->queue);
        ctx->queue = NULL;
    }

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

#endif // __APPLE__
