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

// Test helper for P2P initialization with default Ed25519 algorithm
#include "mxd_p2p.h"
#include "mxd_crypto.h"
#include "mxd_address.h"
#include "mxd_transaction.h"

static inline int test_init_p2p_ed25519(uint16_t port, const uint8_t *public_key, const uint8_t *private_key) {
    return mxd_init_p2p(port, MXD_SIGALG_ED25519, public_key, private_key);
}

// Test helper for adding transaction input with Ed25519
static inline int test_add_tx_input_ed25519(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                                            uint32_t output_index, const uint8_t *public_key) {
    return mxd_add_tx_input(tx, prev_tx_hash, output_index, MXD_SIGALG_ED25519, 
                           public_key, mxd_sig_pubkey_len(MXD_SIGALG_ED25519));
}

// Test helper for adding transaction output using pubkey (derives addr32).
// Note: mxd_add_tx_output still expects a 20-byte recipient field (Task 5 will
// widen it to 32 bytes).  We pass the first 20 bytes of addr32 for now, matching
// the behaviour of the legacy HASH160 path while keeping the build green.
static inline int test_add_tx_output_to_pubkey_ed25519(mxd_transaction_t *tx, const uint8_t *public_key, mxd_amount_t amount) {
    uint8_t addr32[MXD_ADDR32_LEN];
    if (mxd_derive_address(MXD_SIGALG_ED25519, public_key, mxd_sig_pubkey_len(MXD_SIGALG_ED25519), addr32) != 0) {
        return -1;
    }
    return mxd_add_tx_output(tx, addr32, amount);
}

// Test helper for signing transaction input with Ed25519
static inline int test_sign_tx_input_ed25519(mxd_transaction_t *tx, uint32_t input_index, const uint8_t *private_key) {
    return mxd_sign_tx_input(tx, input_index, MXD_SIGALG_ED25519, private_key);
}

#endif
