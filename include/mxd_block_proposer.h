#ifndef MXD_BLOCK_PROPOSER_H
#define MXD_BLOCK_PROPOSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include "mxd_transaction.h"
#include <stdint.h>

// Block proposer configuration
#define MXD_BLOCK_CLOSE_TIMEOUT_MS 2000      // 2 seconds (smaller blocks propagate faster via gossip)
// Bumped 10000→30000 after v7 testnet cutover (2026-05-06) produced a
// h=1 fork: primary's block didn't reach testnet-3 within 10s, testnet-3's
// fallback fired and produced a competing block at the same height. 30s
// is conservative for 5 GCP nodes in the same zone; revisit for WAN deploy.
// See AUDIT_2026-05-07_v7_pre_mainnet.md F7-6.
#define MXD_PROPOSER_TIMEOUT_MS 30000        // 30 seconds per proposer slot
#define MXD_MAX_FALLBACK_RETRIES 9           // Max 9 fallback proposers (10 total chances per height)
#define MXD_VALIDATOR_SIGN_TIMEOUT_MS 10000  // 10 seconds per validator before skip (mainnet: sparse blocks need longer window)

// Block proposer state
typedef struct {
    mxd_block_t* current_block;
    uint64_t block_start_time;
    uint8_t is_proposing;
    uint8_t proposer_id[32];            // v6: addr32 (was [20])
} mxd_block_proposer_t;

// Per-height timeout tracking
typedef struct {
    uint32_t height;                    // Height waiting for
    uint64_t wait_start_time;           // When we started waiting (ms)
    uint32_t retry_count;               // Number of fallback attempts
    uint8_t expected_proposer[32];      // v6: addr32 (was [20])
} mxd_height_timeout_t;

// Initialize block proposer
int mxd_init_block_proposer(const uint8_t proposer_id[32]);

// Start proposing a new block
int mxd_start_block_proposal(const uint8_t prev_hash[64], uint32_t height);

// Add transaction to current block
int mxd_add_transaction_to_block(const mxd_transaction_t* tx);

// Add v3 transaction to current block (bridge mints/burns)
int mxd_add_transaction_v3_to_block(const mxd_transaction_v3_t* tx);

// Check if block should be closed (5 second timeout)
int mxd_should_close_block(void);

// Manually close block (freeze transaction set)
int mxd_close_block(void);

// Get current block being proposed
mxd_block_t* mxd_get_current_block(void);

// Stop block proposal
int mxd_stop_block_proposal(void);

// Cleanup block proposer
void mxd_cleanup_block_proposer(void);

// Timeout tracking functions
int mxd_get_timeout_state(uint32_t *height, uint32_t *retry_count);
uint32_t mxd_get_timeout_retry_count(void);
uint32_t mxd_get_timeout_height(void);
int mxd_start_height_timeout(uint32_t height, const uint8_t *expected_proposer);
int mxd_check_timeout_expired(void);
int mxd_increment_retry_count(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCK_PROPOSER_H
