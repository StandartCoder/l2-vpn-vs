#ifndef VP_OS_LINUX_COMMON_H
#define VP_OS_LINUX_COMMON_H

#define _GNU_SOURCE

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define VP_LINUX_TAP_PATH "/dev/net/tun"

// Returns current time in milliseconds
static inline uint64_t vp_os_linux_get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

#endif
