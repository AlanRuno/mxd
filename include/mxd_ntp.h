#ifndef MXD_NTP_H
#define MXD_NTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// NTP time information structure
typedef struct {
    uint64_t timestamp;    // Current network time in milliseconds
    uint32_t precision;    // Time precision in microseconds
    uint32_t delay;        // Network delay in microseconds
} mxd_ntp_info_t;

// Initialize NTP synchronization
int mxd_init_ntp(void);

// Synchronize with NTP servers and get time information
int mxd_sync_time(mxd_ntp_info_t *info);

// Get current network time
int mxd_get_network_time(uint64_t *timestamp);

// Get current time in milliseconds (with fallback)
uint64_t mxd_now_ms(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_NTP_H
