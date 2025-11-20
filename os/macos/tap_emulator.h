#pragma once

#ifdef __APPLE__
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> // ssize_t

// Create an emulated TAP device backed by vmnet.
// Returns the file descriptor exposed to the application (like /dev/tap0), or -1 on error.
int tap_emulator_open(const char *ifname_hint);

// Read/write on the emulated TAP FD.
ssize_t tap_emulator_read(int fd, void *buf, size_t len);
ssize_t tap_emulator_write(int fd, const void *buf, size_t len);

// Close and cleanup emulator.
void tap_emulator_close(int fd);

#endif // __APPLE__
