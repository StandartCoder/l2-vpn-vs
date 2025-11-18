#ifndef VP_OS_LINUX_COMMON_H
#define VP_OS_LINUX_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define VP_LINUX_TAP_PATH "/dev/net/tun"

// Returns current time in milliseconds
static inline uint64_t vp_os_linux_get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#endif