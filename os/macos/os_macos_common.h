#ifndef VP_OS_MACOS_COMMON_H
#define VP_OS_MACOS_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <time.h>
#include <errno.h>

// Returns current time in milliseconds (monotonic)
static inline uint64_t vp_os_macos_get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

#endif
