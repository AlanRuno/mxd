#ifndef MXD_TEST_UTILS_H
#define MXD_TEST_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

// Get current time in milliseconds
static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Basic test utilities
#define TEST_START(name) do { \
    printf("\n=== Starting test: %s ===\n", name); \
    fflush(stdout); \
} while(0)

#define TEST_END(name) do { \
    printf("=== Test completed: %s ===\n\n", name); \
    fflush(stdout); \
} while(0)

#define TEST_ASSERT(condition, message) do { \
    assert(condition); \
} while(0)

#define TEST_VALUE(desc, fmt, val) do { \
    if (sizeof(val) == sizeof(uint32_t)) { \
        printf("  %s: %u\n", desc, (uint32_t)val); \
    } else { \
        printf("  %s: " fmt "\n", desc, val); \
    } \
    fflush(stdout); \
} while(0)

#define TEST_ARRAY(desc, arr, len) do { \
    printf("  %s: [", desc); \
    for(size_t i = 0; i < len; i++) { \
        printf("%02x%s", arr[i], i < len-1 ? " " : ""); \
    } \
    printf("]\n"); \
    fflush(stdout); \
} while(0)

// Transaction rate tracking
#define TEST_TX_RATE_START(name) do { \
    uint64_t tx_start_time = get_current_time_ms(); \
    uint32_t tx_count = 0; \
    printf("Starting transaction rate measurement: %s\n", name); \
} while(0)

#define TEST_TX_RATE_UPDATE(name, min_rate) do { \
    tx_count++; \
    uint64_t tx_current_time = get_current_time_ms(); \
    uint64_t tx_elapsed = tx_current_time - tx_start_time; \
    if (tx_elapsed >= 100) { \
        double rate = (double)tx_count * 1000.0 / (double)tx_elapsed; \
        printf("Transaction rate %s: %.2f tx/s\n", name, rate); \
        if (tx_count >= 10) { \
            assert(rate >= min_rate); \
        } \
        tx_start_time = tx_current_time; \
        tx_count = 0; \
    } \
} while(0)

// Latency tracking
#define TEST_LATENCY_START(name) do { \
    uint64_t start_time = get_current_time_ms(); \
    printf("Starting latency measurement: %s\n", name); \
} while(0)

#define TEST_LATENCY_END(name, max_ms) do { \
    uint64_t end_time = get_current_time_ms(); \
    uint64_t latency = end_time - start_time; \
    printf("Latency %s: %lums\n", name, latency); \
    assert(latency <= max_ms); \
} while(0)

// Error tracking
#define TEST_ERROR_COUNT(count, max) do { \
    printf("Consecutive errors: %d/%d\n", count, max); \
    assert(count <= max); \
} while(0)

#endif
