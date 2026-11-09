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
//
// Requests for a given (height, block hash) are rate-limited with exponential
// backoff (MXD_RECONCILE_BASE_BACKOFF_MS, doubling up to
// MXD_RECONCILE_MAX_BACKOFF_MS). A block that never reached quorum on any node
// — e.g. one produced while a validator in its signing order was offline —
// has no missing signatures to fetch; without the backoff every node re-asked
// every peer every cycle and rejected every answer, forever (mainnet 2026-10/11).
void mxd_reconcile_validation_chains(uint32_t lookback);

#define MXD_RECONCILE_BASE_BACKOFF_MS   60000ULL   // after the first unanswered request
#define MXD_RECONCILE_MAX_BACKOFF_MS  3600000ULL   // retry cap: once an hour
#define MXD_RECONCILE_MAX_PER_CYCLE   32           // blocks requested per reconcile pass

// Selection half of mxd_reconcile_validation_chains (no network): scans the
// `lookback` most recent stored heights from the tip down and returns, newest
// first, those below `quorum` whose backoff has elapsed at `now_ms`, recording
// the attempt. Returns the number written to out_heights/out_hashes (<= max).
uint32_t mxd_reconcile_select_blocks(uint32_t lookback, uint32_t quorum, uint64_t now_ms,
                                     uint32_t *out_heights, uint8_t (*out_hashes)[64],
                                     uint32_t max);

// Forget all reconciliation backoff state (tests, or after a reorg/rollback).
void mxd_reconcile_reset_state(void);

// 1 if the peer's chain (`sigs`, in chain_position order) is a prefix-compatible
// extension of `local`'s validation chain — same validator and signature bytes
// at every position both sides have — 0 if it diverges, -1 on bad input. A
// divergent chain belongs to another view of the block (the block hash does not
// bind the proposer, so competing proposals can share a hash) and cannot be
// grafted onto ours: chain hashes are sequential.
int mxd_validation_chain_extends_local(const mxd_block_t *local,
                                       const mxd_validator_signature_t *sigs,
                                       uint32_t count);

// Merge a peer's validation chain into the local copy of the block. Returns 1
// if at least one signature was appended and stored, 0 if there was nothing
// new to add (shorter, equal or divergent chain), -1 on error (unknown block,
// store failure).
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

// v11: re-attempt to sign the tip block when it is below quorum. A validator
// whose rank is above 0 must wait rank * MXD_SIGN_SKIP_MS before it may take
// the next position, and nothing re-triggers the signer while it waits; the
// consensus thread calls this once a second. Cheap no-op otherwise.
void mxd_sign_tip_if_due(void);

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
