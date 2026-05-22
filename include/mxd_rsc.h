#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_types.h"
#include "mxd_crypto.h"
#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"
#include "common/mxd_metrics_types.h"

// Validator eviction policy
#define MXD_EVICTION_THRESHOLD     10   // Consecutive round-robin misses before eviction
#define MXD_MIN_VALIDATORS          3   // Never evict below this count

int mxd_get_validator_public_key(const uint8_t validator_id[32], uint8_t *out_key, size_t out_capacity, size_t *out_len);
int mxd_get_validator_algo_id(const uint8_t validator_id[32], uint8_t *out_algo_id);
int mxd_test_register_validator_pubkey(const uint8_t validator_id[32], const uint8_t *pub, size_t pub_len);
void mxd_test_clear_validator_pubkeys(void);

typedef struct {
    mxd_node_stake_t **nodes;
    size_t count;
    size_t capacity;
    uint64_t last_update;
} mxd_rapid_table_t;

// Accessor for the global rapid table (defined in node/main.c)
const mxd_rapid_table_t* mxd_get_rapid_table(void);

// Accessor functions for local validator credentials (used by sync/DHT modules)
const uint8_t* mxd_get_local_address(void);
const uint8_t* mxd_get_local_pubkey(void);
const uint8_t* mxd_get_local_privkey(void);
uint8_t mxd_get_local_algo_id(void);

// Get local node's identity (address, keys) for testing
int mxd_get_local_node_identity(uint8_t *address, uint8_t *pubkey, size_t *pubkey_len,
                                 uint8_t *privkey, size_t *privkey_len, uint8_t *algo_id);

typedef enum {
    MXD_VALIDATION_PENDING = 0,
    MXD_VALIDATION_IN_PROGRESS,
    MXD_VALIDATION_COMPLETE,
    MXD_VALIDATION_REJECTED,
    MXD_VALIDATION_EXPIRED
} mxd_validation_status_t;

typedef struct {
    uint32_t height;
    uint8_t block_hash[64];
    uint8_t proposer_id[32];              // v6: addr32 (was [20])
    mxd_validation_status_t status;
    uint32_t signature_count;
    uint32_t required_signatures;
    uint64_t start_time;
    uint64_t expiry_time;
    uint8_t waiting_for_validator[32];    // v6: addr32 (was [20])
    uint64_t waiting_since;               // When we started waiting (ms timestamp)
    uint32_t skip_count;                  // Number of validators skipped
    uint8_t skipped_validators[50][32];   // v6: addr32 (was [20])
} mxd_validation_context_t;

int mxd_validate_node_stake(const mxd_node_stake_t *node, mxd_amount_t total_stake);

int mxd_init_node_metrics(mxd_node_metrics_t *metrics);

int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp);

int mxd_calculate_node_rank(const mxd_node_stake_t *node, mxd_amount_t total_stake);

int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_tip);

int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_stake);

int mxd_update_rapid_table_rankings(mxd_rapid_table_t *table);

int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats);

int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time);

int mxd_init_rapid_table(mxd_rapid_table_t *table, size_t capacity);

int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node, const char *local_node_id);

int mxd_remove_from_rapid_table(mxd_rapid_table_t *table, const char *node_id);

mxd_node_stake_t *mxd_get_node_from_rapid_table(const mxd_rapid_table_t *table, const char *node_id);

// Find a node by its 32-byte addr32 in the rapid table (v6)
mxd_node_stake_t *mxd_get_node_by_address(const mxd_rapid_table_t *table, const uint8_t address[32]);

void mxd_free_rapid_table(mxd_rapid_table_t *table);

int mxd_init_validation_context(mxd_validation_context_t *context, const mxd_block_t *block,
                               const mxd_rapid_table_t *table);

int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[32],
                                        uint64_t timestamp, uint8_t algo_id, const uint8_t *signature,
                                        uint16_t signature_length, uint32_t chain_position);

int mxd_verify_validation_chain_integrity(const mxd_block_t *block);

int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table);

int mxd_block_has_min_relay_signatures(const mxd_block_t *block);

int mxd_resolve_fork_by_validation(const mxd_block_t *block1, const mxd_block_t *block2,
                                  const mxd_rapid_table_t *table);

double mxd_calculate_validation_latency_score(const mxd_block_t *block, const mxd_rapid_table_t *table);

int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[32], uint32_t height,
                                           const uint8_t block_hash[64]);

int mxd_blacklist_validator(const uint8_t validator_id[32], uint32_t duration);

int mxd_is_validator_blacklisted(const uint8_t validator_id[32]);

int mxd_get_next_validator(const mxd_block_t *block, const mxd_rapid_table_t *table,
                          uint8_t next_validator_id[32]);

int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context,
                                const mxd_rapid_table_t *table);

int mxd_apply_membership_deltas(mxd_rapid_table_t *table, const mxd_block_t *block,
                                const char *local_node_id);

// v8+: apply rapid_eviction_entries from a finalized block to the in-memory
// rapid_table. Removes each target validator's slot and compacts the table
// so round-robin proposer selection (height_hash % table->count) stays
// coherent across peers immediately after the block applies.
int mxd_apply_eviction_deltas(mxd_rapid_table_t *table, const mxd_block_t *block,
                              const char *local_node_id);

int mxd_remove_expired_nodes(mxd_rapid_table_t *table, uint64_t current_time);

// Check if the expected round-robin proposer missed this block; evict after MXD_EVICTION_THRESHOLD consecutive misses
int mxd_check_proposer_miss(mxd_rapid_table_t *table, const mxd_block_t *block);

// Chain-derived deterministic scoring
void mxd_accumulate_block_stats(mxd_rapid_table_t *table, const mxd_block_t *block);
void mxd_compute_chain_scores(mxd_rapid_table_t *table);
void mxd_sort_rapid_table_by_score(mxd_rapid_table_t *table);

// On-chain deterministic scoring (v4+)
int mxd_compute_block_validator_scores(const mxd_block_t *prev_block,
                                        const mxd_rapid_table_t *table,
                                        mxd_validator_score_entry_t **out_scores,
                                        uint32_t *out_count);
int mxd_verify_block_validator_scores(const mxd_block_t *block);
void mxd_load_scores_from_block(mxd_rapid_table_t *table, const mxd_block_t *block);

int mxd_should_add_to_rapid_table(const mxd_node_stake_t *node, mxd_amount_t total_supply, int is_genesis);

int mxd_rebuild_rapid_table_from_blockchain(mxd_rapid_table_t *table, uint32_t from_height, 
                                            uint32_t to_height, const char *local_node_id);

typedef struct {
    uint8_t node_address[32];   // v6: addr32 (was [20])
    uint8_t algo_id;
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint64_t timestamp;
    uint8_t signature[MXD_SIG_MAX_LEN];
    uint16_t signature_length;
} mxd_genesis_member_t;

int mxd_init_genesis_coordination(const uint8_t *local_address, const uint8_t *local_pubkey, const uint8_t *local_privkey, uint8_t algo_id);

void mxd_cleanup_genesis_coordination(void);

int mxd_broadcast_genesis_announce(void);

int mxd_handle_genesis_announce(uint8_t algo_id, const uint8_t *node_address, const uint8_t *public_key, 
                                 size_t pubkey_len, uint64_t timestamp, const uint8_t *signature, uint16_t signature_length);

int mxd_get_pending_genesis_count(void);

int mxd_is_genesis_locked(void);

void mxd_set_genesis_locked(int locked);

int mxd_sync_pending_genesis_to_rapid_table(mxd_rapid_table_t *table, const char *local_node_id);

int mxd_try_coordinate_genesis_block(void);

int mxd_rebuild_rapid_table_after_genesis(mxd_rapid_table_t *table, const char *local_node_id);

int mxd_send_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest,
                                   const uint8_t *proposer_id, uint32_t height,
                                   const mxd_genesis_member_t *members, size_t member_count);

int mxd_handle_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest,
                                     const uint8_t *proposer_id, uint32_t height,
                                     const mxd_genesis_member_t *members, size_t member_count);

int mxd_handle_genesis_sign_response(const uint8_t *signer_address, const uint8_t *proposer_id,
                                      const uint8_t *membership_digest,
                                      const uint8_t *signature, uint16_t signature_length);

int mxd_broadcast_genesis_sync(void);

int mxd_handle_genesis_sync(const uint8_t *node_address, size_t member_count, 
                             const uint8_t *member_list_hash, uint64_t timestamp);

int mxd_try_create_genesis_block(mxd_rapid_table_t *table, const uint8_t *node_address,
                                  const uint8_t *private_key, const uint8_t *public_key);

// Post-genesis consensus tick - drives block production after genesis
// Should be called periodically from the main loop when height > 0
// Parameters:
//   table: The rapid stake table
//   local_address: This node's 20-byte wallet address
//   local_pubkey: This node's public key
//   local_privkey: This node's private key
//   algo_id: The signature algorithm ID for this node
// Returns: 0 on success, -1 on error, 1 if a block was finalized
int mxd_consensus_tick(mxd_rapid_table_t *table, const uint8_t *local_address,
                       const uint8_t *local_pubkey, const uint8_t *local_privkey, uint8_t algo_id);

// Check if this node is the proposer for the given height
// For v5+, pass prev_block_hash for deterministic selection; NULL for pre-v5 fallback
int mxd_is_proposer_for_height(const mxd_rapid_table_t *table, const uint8_t *local_address,
                                uint32_t height, const uint8_t *prev_block_hash);

// Sequential signature chaining - signing order
// Compute deterministic signing order: proposer first, then non-proposers
// rotated by block_height for position diversity. v6: addr32 (32-byte).
int mxd_compute_signing_order(const mxd_rapid_table_t *table,
                              const uint8_t proposer_id[32],
                              uint64_t block_height,
                              uint8_t signing_order[][32],
                              uint32_t *order_count);

// Get this node's position in the signing order (-1 if not in table)
// Uses block_height to rotate non-proposer positions per block. v6: addr32.
int mxd_get_my_signing_position(const mxd_rapid_table_t *table,
                                const uint8_t proposer_id[32],
                                const uint8_t my_address[32],
                                uint64_t block_height);

// Compute chain_hash for a given position from the validation chain
// Position 0: chain_hash = SHA-512(block_hash)
// Position N: chain_hash = SHA-512(prev_chain_hash || prev_signature_bytes)
void mxd_compute_chain_hash(const mxd_block_t *block,
                            uint32_t position,
                            uint8_t chain_hash[64]);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H
