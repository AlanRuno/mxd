#ifndef MXD_BLOCKCHAIN_SYNC_H
#define MXD_BLOCKCHAIN_SYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"
#include "mxd_rsc.h"

int mxd_sync_blockchain(void);

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block);

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height);

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]);

// Walk back `lookback` recent blocks and, for any whose locally-stored
// validation_count is below the rapid-table 2/3 quorum threshold, fan out
// MXD_MSG_GET_VALIDATION_CHAIN requests so peers can fill the gaps.
// Self-heals state divergence after gossip drops, peer restarts, or
// brief HTTP/consensus stalls. Cheap when nothing is below quorum.
void mxd_reconcile_validation_chains(uint32_t lookback);

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64],
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count);

// skip_drift_check=0 enforces the live MXD_MAX_TIMESTAMP_DRIFT window
// (use for fresh validator broadcasts). =1 bypasses the freshness gate
// for catchup paths processing historical validation chains from peers.
int mxd_verify_and_add_validation_signature(mxd_block_t *block,
                                           const uint8_t validator_id[32],
                                           uint8_t algo_id,
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp,
                                           int skip_drift_check);

int mxd_check_block_relay_status(const uint8_t block_hash[64]);

// Sign the given block with the local validator's identity, store the
// updated chain to RocksDB, and broadcast it to peers. Defined in
// mxd_blockchain_sync.c.
int mxd_sign_and_broadcast_block(const mxd_block_t *block);

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id);

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64],
                                        const uint8_t block_hash2[64]);

int mxd_prune_expired_validation_chains(uint32_t current_height);

// Pull-based sync fallback - actively request missing blocks from peers
// Call this periodically to catch blocks that failed to broadcast
int mxd_pull_missing_blocks(void);

// Apply block transactions to UTXO state (deserializes and processes each tx)
// If supply_delta is non-NULL, outputs the net supply change (outputs - inputs)
int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta);

// Forward-propagate total_supply to subsequent blocks that have supply=0.
// Called after storing a block with valid (non-zero) supply.
void mxd_propagate_supply_forward(uint32_t from_height, uint64_t from_supply);

// Parallel sync configuration
#define MXD_SYNC_WORKERS_DEFAULT  4   // Default worker threads
#define MXD_SYNC_WORKERS_MAX      8   // Maximum worker threads
#define MXD_SYNC_CHUNK_SIZE       50  // Blocks per sub-range
#define MXD_SYNC_TIMEOUT_MS       15000 // Per-range timeout (ms)
#define MXD_SYNC_MAX_RETRIES      3   // Retries per range before fallback

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_SYNC_H
