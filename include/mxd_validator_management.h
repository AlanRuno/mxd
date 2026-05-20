#ifndef MXD_VALIDATOR_MANAGEMENT_H
#define MXD_VALIDATOR_MANAGEMENT_H

#include "mxd_blockchain.h"
#include "mxd_rsc.h"
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

// Validator join request
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint8_t algo_id;                    // Signature algorithm
    uint8_t public_key[2592];           // Public key (max Dilithium5 size)
    uint16_t public_key_length;
    mxd_amount_t stake_amount;          // Declared stake
    uint64_t timestamp;                 // Request timestamp
    uint8_t signature[4627];            // Signature over request (FIPS 204 ML-DSA-87, was 4595)
    uint16_t signature_length;
} mxd_validator_join_request_t;

// Validator exit request
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint32_t exit_height;               // Height when exit takes effect
    uint64_t timestamp;
    uint8_t signature[4595];            // Signature over exit
    uint16_t signature_length;
} mxd_validator_exit_request_t;

// Pending requests pool
typedef struct {
    mxd_validator_join_request_t *join_requests;
    size_t join_count;
    size_t join_capacity;

    mxd_validator_exit_request_t *exit_requests;
    size_t exit_count;
    size_t exit_capacity;

    pthread_mutex_t mutex;
} mxd_validator_request_pool_t;

// Track validator liveness
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint32_t last_active_height;        // Last height this validator was seen
    uint32_t consecutive_misses;        // Consecutive missed proposals
    uint8_t marked_for_removal;         // Flag for removal
} mxd_validator_liveness_t;

#define MXD_MAX_CONSECUTIVE_MISSES 10    // Remove after 10 missed proposals

// API functions
int mxd_init_validator_request_pool(void);
int mxd_submit_validator_join_request(const uint8_t *node_address,
                                      const uint8_t *public_key,
                                      uint16_t public_key_length,
                                      uint8_t algo_id,
                                      const uint8_t *private_key);
int mxd_submit_validator_exit_request(const uint8_t *node_address,
                                      const uint8_t *private_key,
                                      uint8_t algo_id);
int mxd_get_pending_join_requests(mxd_validator_join_request_t **requests,
                                   size_t *count);
int mxd_validate_join_request(const mxd_validator_join_request_t *request,
                              mxd_amount_t total_supply);
int mxd_clear_processed_requests(const mxd_block_t *block);
int mxd_track_validator_liveness(mxd_rapid_table_t *table, uint32_t height,
                                 const uint8_t *actual_proposer);
int mxd_get_validators_to_remove(mxd_rapid_table_t *table, uint32_t current_height,
                                 uint8_t **addresses, size_t *count);

#endif // MXD_VALIDATOR_MANAGEMENT_H
