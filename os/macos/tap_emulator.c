#ifdef __APPLE__

#include "tap_emulator.h"
#include "tap_backend_vmnet.h"

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

// Simple TAP emulator: socketpair() presents a FD to the app; internal threads
// shuttle frames to/from vmnet backend.

struct tap_emulator_ctx {
    int app_fd;
    int emu_fd;
    struct vmnet_backend *backend;
    pthread_t th_rx; // backend -> app
    pthread_t th_tx; // app -> backend
    int stop;
};

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

static void *rx_thread(void *arg)
{
    struct tap_emulator_ctx *ctx = (struct tap_emulator_ctx *)arg;
    uint8_t buf[2000];

    while (!ctx->stop) {
        ssize_t r = vmnet_backend_read(ctx->backend, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EAGAIN) {
                struct timespec ts = {0, 10 * 1000 * 1000}; // 10ms
                nanosleep(&ts, NULL);
                continue;
            }
            break;
        }

        ssize_t off = 0;
        while (off < r && !ctx->stop) {
            ssize_t w = write(ctx->emu_fd, buf + off, (size_t)(r - off));
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct timespec ts = {0, 5 * 1000 * 1000};
                    nanosleep(&ts, NULL);
                    continue;
                }
                break;
            }
            off += w;
        }
    }

    return NULL;
}

static void *tx_thread(void *arg)
{
    struct tap_emulator_ctx *ctx = (struct tap_emulator_ctx *)arg;
    uint8_t buf[2000];

    while (!ctx->stop) {
        struct pollfd pfd = {
            .fd = ctx->emu_fd,
            .events = POLLIN
        };
        int pr = poll(&pfd, 1, 50); // 50 ms
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR)
                break;
            continue;
        }
        if (!(pfd.revents & POLLIN))
            continue;

        ssize_t r = read(ctx->emu_fd, buf, sizeof(buf));
        if (r <= 0) {
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            break;
        }

        ssize_t off = 0;
        while (off < r && !ctx->stop) {
            ssize_t w = vmnet_backend_write(ctx->backend, buf + off, (size_t)(r - off));
            if (w < 0) {
                if (errno == EAGAIN) {
                    struct timespec ts = {0, 5 * 1000 * 1000};
                    nanosleep(&ts, NULL);
                    continue;
                }
                break;
            }
            off += w;
        }
    }

    return NULL;
}

static struct tap_emulator_ctx *g_ctx = NULL;

int tap_emulator_open(const char *ifname_hint)
{
    (void)ifname_hint; // currently unused; vmnet assigns the interface

    if (g_ctx) {
        // Only one emulator instance supported
        errno = EBUSY;
        return -1;
    }

    struct tap_emulator_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        free(ctx);
        return -1;
    }

    ctx->app_fd = sv[0];
    ctx->emu_fd = sv[1];

    set_nonblock(ctx->app_fd);
    set_nonblock(ctx->emu_fd);

    if (vmnet_backend_init(&ctx->backend) != 0) {
        close(ctx->app_fd);
        close(ctx->emu_fd);
        free(ctx);
        return -1;
    }

    if (pthread_create(&ctx->th_rx, NULL, rx_thread, ctx) != 0) {
        vmnet_backend_close(ctx->backend);
        close(ctx->app_fd);
        close(ctx->emu_fd);
        free(ctx);
        return -1;
    }
    if (pthread_create(&ctx->th_tx, NULL, tx_thread, ctx) != 0) {
        ctx->stop = 1;
        pthread_join(ctx->th_rx, NULL);
        vmnet_backend_close(ctx->backend);
        close(ctx->app_fd);
        close(ctx->emu_fd);
        free(ctx);
        return -1;
    }

    g_ctx = ctx;
    return ctx->app_fd;
}

ssize_t tap_emulator_read(int fd, void *buf, size_t len)
{
    (void)len;
    if (!g_ctx || fd != g_ctx->app_fd)
        return -1;
    return read(fd, buf, len);
}

ssize_t tap_emulator_write(int fd, const void *buf, size_t len)
{
    (void)len;
    if (!g_ctx || fd != g_ctx->app_fd)
        return -1;
    return write(fd, buf, len);
}

void tap_emulator_close(int fd)
{
    if (!g_ctx || fd != g_ctx->app_fd)
        return;

    g_ctx->stop = 1;
    pthread_join(g_ctx->th_tx, NULL);
    pthread_join(g_ctx->th_rx, NULL);

    vmnet_backend_close(g_ctx->backend);
    close(g_ctx->app_fd);
    close(g_ctx->emu_fd);

    free(g_ctx);
    g_ctx = NULL;
}

#endif // __APPLE__
