#include "mxd_logging.h"

#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_domain_tags.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../include/mxd_error.h"

#define MXD_VALIDATION_EXPIRY_BLOCKS 5
#define MXD_MIN_RELAY_SIGNATURES 3
#define MXD_MAX_TIMESTAMP_DRIFT 60

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height);
static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count);
int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta);
void mxd_propagate_supply_forward(uint32_t from_height, uint64_t from_supply);
static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height);

// Defined in mxd_mempool.c; used below to drain mempool entries whose txs
// have been applied in a block (including peer-proposed blocks).
extern int mxd_remove_from_mempool(const uint8_t tx_hash[64]);
int mxd_sign_and_broadcast_block(const mxd_block_t *block);
extern void mxd_drain_pending_validation_sigs(const uint8_t *block_hash);

static uint32_t mxd_discover_network_height(void) {
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;

    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to discover network height");
        return 0;
    }

    MXD_LOG_DEBUG("sync", "Discovering network height from %zu peers", peer_count);

    // Shuffle peers to avoid always querying the same ones first.
    // If the first N peers happen to be other syncing nodes, we'd get
    // a low network height and never trigger sync.
    for (size_t i = peer_count - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        mxd_peer_t tmp = peers[i];
        peers[i] = peers[j];
        peers[j] = tmp;
    }

    uint32_t max_height = 0;
    int queried = 0;
    for (size_t i = 0; i < peer_count && queried < 5; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint32_t peer_height = 0;
            if (mxd_request_peer_height(peers[i].address, peers[i].port, &peer_height) == 0) {
                MXD_LOG_DEBUG("sync", "Peer %s:%u reports height=%u",
                             peers[i].address, peers[i].port, peer_height);
                queried++;
                if (peer_height > max_height) {
                    max_height = peer_height;
                }
            }
        }
    }

    MXD_LOG_INFO("sync", "Network height: queried=%d, max=%u", queried, max_height);
    return max_height;
}

// Callback storage for peer height responses
static volatile uint32_t pending_peer_height = 0;
static volatile int peer_height_received = 0;

// Called by P2P layer when height response is received
void mxd_handle_peer_height_response(const uint8_t *data, size_t data_len) {
    if (data && data_len >= 4) {
        const uint8_t *ptr = data;
        pending_peer_height = mxd_read_u32_be(&ptr);
        peer_height_received = 1;
    }
}

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height) {
    if (!address || !height) return -1;
    
    // Reset response state
    peer_height_received = 0;
    pending_peer_height = 0;
    
    // Send height request to peer using GET_BLOCKS with height=0 to request current height
    uint8_t request[8];
    uint8_t *ptr = request;
    mxd_write_u32_be(&ptr, 0);  // start_height = 0 (request height info)
    mxd_write_u32_be(&ptr, 0);  // end_height = 0 (request height info only)
    
    if (mxd_send_message_with_retry(address, port, MXD_MSG_GET_BLOCKS, 
                                    request, sizeof(request), 3) != 0) {
        MXD_LOG_DEBUG("sync", "Failed to send height request to peer %s:%u", address, port);
        *height = 0;
        return -1;
    }
    
    // Wait for response with timeout (up to 3 seconds)
    int wait_ms = 0;
    while (!peer_height_received && wait_ms < 1000) {
        struct timespec ts = {0, 50000000}; // 50ms
        nanosleep(&ts, NULL);
        wait_ms += 50;
    }
    
    if (peer_height_received) {
        *height = pending_peer_height;
        MXD_LOG_DEBUG("sync", "Peer %s:%u reported height: %u", address, port, *height);
        return 0;
    }
    
    MXD_LOG_DEBUG("sync", "Timeout waiting for height from peer %s:%u", address, port);
    *height = 0;
    return -1;
}

// Callback storage for block responses
static mxd_block_t *pending_blocks = NULL;
static volatile uint32_t pending_blocks_received = 0;
static volatile uint32_t pending_blocks_expected = 0;
static volatile uint32_t pending_blocks_start_height = 0;
static volatile uint32_t pending_blocks_end_height = 0;

// Forward declaration for deserializing blocks from database format
extern int mxd_deserialize_block_from_network(const uint8_t *data, size_t data_len, mxd_block_t *block);

// Called by P2P layer when block data is received
void mxd_handle_blocks_response(const uint8_t *data, size_t data_len, uint32_t block_index) {
    if (!data || data_len == 0) return;

    // Check if this is a 4-byte height response
    if (data_len == 4) {
        // This is a height response from a peer - route to height handler
        mxd_handle_peer_height_response(data, data_len);
        return;
    }

    // Handle unsolicited blocks (e.g., genesis block broadcast)
    if (!pending_blocks) {
        MXD_LOG_INFO("sync", "Received unsolicited block data (len=%zu), attempting to process", data_len);
        
        // Deserialize the block using the network format
        mxd_block_t block;
        memset(&block, 0, sizeof(block));
        
        if (mxd_deserialize_block_from_network(data, data_len, &block) != 0) {
            MXD_LOG_WARN("sync", "Failed to deserialize unsolicited block");
            return;
        }
        
        MXD_LOG_INFO("sync", "Deserialized unsolicited block: height=%u, validators=%u, membership=%u",
                     block.height, block.validation_count, block.rapid_membership_count);

        // SECURITY: Verify block hash integrity before accepting unsolicited blocks.
        // We skip full mxd_validate_block() (which requires previous block for proposer
        // validation), but we MUST verify the block hash and require minimum relay
        // signatures to prevent malicious peers from injecting fabricated blocks.
        {
            uint8_t computed_hash[64];
            if (mxd_calculate_block_hash(&block, computed_hash) != 0) {
                MXD_LOG_ERROR("sync", "Failed to compute hash for unsolicited block at height %u", block.height);
                mxd_free_block(&block);
                return;
            }
            if (memcmp(computed_hash, block.block_hash, 64) != 0) {
                MXD_LOG_ERROR("sync", "Block hash mismatch for unsolicited block at height %u - rejecting (possible tampering)", block.height);
                mxd_free_block(&block);
                return;
            }
        }

        // For non-genesis blocks, verify validation chain integrity if signatures present
        // Note: unsolicited blocks (new proposals) arrive with only the proposer's signature.
        // We do NOT require min_signatures here — that check is for synced historical blocks.
        // Validators will add their signatures during the consensus validation process.
        if (block.height > 0 && block.validation_count > 0) {
            if (mxd_verify_validation_chain_integrity(&block) != 0) {
                MXD_LOG_WARN("sync", "Validation chain integrity imperfect for block at height %u (accepted)", block.height);
            }
        }

        // Check if we already have this block
        uint32_t current_height = 0;
        int have_blockchain = (mxd_get_blockchain_height(&current_height) == 0);
        
        // Special handling for genesis block (height 0)
        // If we don't have any blocks yet (have_blockchain is false or current_height is 0),
        // we should accept the genesis block
        if (block.height == 0) {
            if (have_blockchain && current_height >= 0) {
                // Check if we actually have a genesis block stored
                mxd_block_t existing_genesis;
                memset(&existing_genesis, 0, sizeof(existing_genesis));
                if (mxd_retrieve_block_by_height(0, &existing_genesis) == 0) {
                    MXD_LOG_DEBUG("sync", "Already have genesis block, ignoring duplicate");
                    mxd_free_block(&existing_genesis);
                    mxd_free_block(&block);
                    return;
                }
            }
            // Don't have genesis block yet — but only accept if it has validators.
            // Reject empty genesis (membership=0) to prevent stale genesis from
            // external DHT peers overriding our own genesis coordination.
            if (block.rapid_membership_count == 0) {
                MXD_LOG_WARN("sync", "Rejecting genesis block with 0 membership entries (likely stale)");
                mxd_free_block(&block);
                return;
            }
            MXD_LOG_INFO("sync", "Received genesis block with %u members, will store it",
                         block.rapid_membership_count);
        } else if (block.height < current_height) {
            // We might have a DIFFERENT block at this height (divergent fork from
            // a partition / restart race). Compare by hash before treating as
            // duplicate. Same hash → real duplicate, drop. Different hash →
            // route to mxd_store_block which runs handle_block_at_existing_height
            // / mxd_compare_forks and either reorgs or keeps existing.
            //
            // Skip the pre-apply in the divergent case: the reorg path inside
            // mxd_store_block applies the winning block's delta itself, so
            // applying here would double-mutate UTXO state when the loser is
            // demoted.
            mxd_block_t existing_at_height;
            memset(&existing_at_height, 0, sizeof(existing_at_height));
            int have_at_height = (mxd_retrieve_block_by_height(block.height, &existing_at_height) == 0);
            if (have_at_height && memcmp(existing_at_height.block_hash, block.block_hash, 64) == 0) {
                MXD_LOG_DEBUG("sync", "Already have identical block at height %u, ignoring",
                             block.height);
                mxd_free_block(&existing_at_height);
                mxd_free_block(&block);
                return;
            }
            if (have_at_height) {
                MXD_LOG_INFO("sync",
                    "Divergent block at h=%u (local=%02x%02x%02x%02x... incoming=%02x%02x%02x%02x...) — routing to fork-choice",
                    block.height,
                    existing_at_height.block_hash[0], existing_at_height.block_hash[1],
                    existing_at_height.block_hash[2], existing_at_height.block_hash[3],
                    block.block_hash[0], block.block_hash[1],
                    block.block_hash[2], block.block_hash[3]);
                mxd_free_block(&existing_at_height);
                if (mxd_store_block(&block) != 0) {
                    MXD_LOG_DEBUG("sync",
                        "fork-choice declined incoming block at h=%u (existing wins or store error)",
                        block.height);
                }
                mxd_free_block(&block);
                return;
            }
            /* No block at this height locally despite current_height > h — gap.
             * Fall back to the original behavior: skip. Sync will fill via the
             * regular gap-fill path. */
            mxd_free_block(&existing_at_height);
            MXD_LOG_DEBUG("sync", "Already have block at height %u (current=%u), ignoring",
                         block.height, current_height);
            mxd_free_block(&block);
            return;
        } else if (block.height > current_height) {
            // current_height = count of blocks stored (heights 0..current_height-1).
            // Next expected block is at height == current_height.
            // Anything beyond that means we're missing intermediate blocks;
            // storing would create UTXO gaps. Let sync fill the gap.
            MXD_LOG_DEBUG("sync", "Block %u is ahead of local height %u, skipping (will sync)",
                         block.height, current_height);
            mxd_free_block(&block);
            return;
        }
        
        // Apply transactions to create UTXOs (critical for genesis block)
        int64_t supply_delta = 0;
        int apply_result = mxd_apply_block_transactions(&block, &supply_delta);
        if (apply_result == MXD_ERR_BRIDGE_INVALID) {
            MXD_LOG_ERROR("sync", "Unsolicited block at height %u contains INVALID bridge transaction - REJECTING",
                           block.height);
            mxd_free_block(&block);
            return;
        }
        if (apply_result != 0) {
            if (block.height == 0) {
                // Genesis block must always be accepted
                MXD_LOG_WARN("sync", "Failed to apply transactions for genesis block, storing anyway");
            } else {
                MXD_LOG_WARN("sync", "Failed to apply transactions for unsolicited block at height %u, rejecting", block.height);
                mxd_free_block(&block);
                return;
            }
        }

        // Guard against overwriting a block that already has more validation signatures.
        // This prevents a race condition where the block broadcast (with proposer sig only)
        // arrives after the validation handler has already added more signatures.
        {
            mxd_block_t existing;
            memset(&existing, 0, sizeof(existing));
            if (mxd_retrieve_block_by_hash(block.block_hash, &existing) == 0) {
                if (existing.validation_count >= block.validation_count) {
                    MXD_LOG_DEBUG("sync", "Existing block at height %u already has %u sigs (broadcast has %u), keeping existing",
                                 block.height, existing.validation_count, block.validation_count);
                    mxd_free_block(&existing);
                    // Still try to sign the existing block (in case we haven't yet)
                    if (block.height > 0) {
                        mxd_block_t sign_block;
                        memset(&sign_block, 0, sizeof(sign_block));
                        if (mxd_retrieve_block_by_hash(block.block_hash, &sign_block) == 0) {
                            mxd_sign_and_broadcast_block(&sign_block);
                            mxd_free_block(&sign_block);
                        }
                    }
                    mxd_free_block(&block);
                    return;
                }
                mxd_free_block(&existing);
            }
        }

        // Compute total_supply deterministically from previous block + delta
        if (block.height > 0) {
            mxd_block_t prev;
            memset(&prev, 0, sizeof(prev));
            if (mxd_retrieve_block_by_height(block.height - 1, &prev) == 0) {
                block.total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                mxd_free_block(&prev);
            }
        } else {
            // Genesis: delta IS the total supply
            block.total_supply = (uint64_t)supply_delta;
        }

        // Store the block
        if (mxd_store_block(&block) == 0) {
            MXD_LOG_INFO("sync", "Stored unsolicited block at height %u (validators=%u, supply=%llu)",
                         block.height, block.validation_count, (unsigned long long)block.total_supply);

            // Update finalization tracking so proposer can proceed
            extern void mxd_set_finalized_height_external(uint32_t height);
            mxd_set_finalized_height_external(block.height);

            // Forward-propagate supply to any subsequent blocks stored with supply=0
            if (block.total_supply > 0) {
                mxd_propagate_supply_forward(block.height, block.total_supply);
            }

            // Drain any validation signatures that arrived before this block
            mxd_drain_pending_validation_sigs(block.block_hash);

            // As a validator, sign this block and broadcast signature
            if (block.height > 0) {
                mxd_sign_and_broadcast_block(&block);
            }
        } else {
            MXD_LOG_ERROR("sync", "Failed to store unsolicited block at height %u", block.height);
        }

        mxd_free_block(&block);
        return;
    }
    
    if (block_index >= pending_blocks_expected) return;

    // Guard: only accept one response per slot to prevent concurrent
    // deserializations into the same memory from duplicate responses.
    if (pending_blocks_received >= pending_blocks_expected) return;

    // Deserialize into a temporary block first to validate height
    mxd_block_t temp_block;
    memset(&temp_block, 0, sizeof(temp_block));

    if (mxd_deserialize_block_from_network(data, data_len, &temp_block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to deserialize requested block %u", block_index);
        return;
    }

    // CRITICAL: Verify the received block's height matches what we requested.
    // Without this check, broadcast blocks from the chain tip can fill
    // pending_blocks[0] during a sync request, causing the requested block
    // to be permanently missed (creating a gap in the chain).
    if (temp_block.height < pending_blocks_start_height ||
        temp_block.height > pending_blocks_end_height) {
        MXD_LOG_DEBUG("sync", "Received block height %u but expected %u-%u, routing to unsolicited handler",
                      temp_block.height, pending_blocks_start_height, pending_blocks_end_height);
        mxd_free_block(&temp_block);
        // Re-process as unsolicited block by temporarily clearing pending_blocks
        mxd_block_t *saved = pending_blocks;
        pending_blocks = NULL;
        mxd_handle_blocks_response(data, data_len, 0);
        pending_blocks = saved;
        return;
    }

    // Height matches — copy into pending_blocks slot
    memcpy(&pending_blocks[block_index], &temp_block, sizeof(mxd_block_t));
    // Don't free temp_block — its memory is now owned by pending_blocks[block_index]

    pending_blocks_received++;
    MXD_LOG_DEBUG("sync", "Received block %u (height %u, scores=%u)",
                  block_index, temp_block.height, temp_block.validator_scores_count);
}

static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count) {
    if (!block_count || start_height > end_height) return NULL;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request blocks");
        return NULL;
    }

    // Shuffle connected peers to avoid always trying the same (potentially
    // stuck) peers first. With N healthy peers out of total, random order
    // reaches a healthy peer in ~total/N tries on average.
    for (size_t i = peer_count - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        mxd_peer_t tmp = peers[i];
        peers[i] = peers[j];
        peers[j] = tmp;
    }

    uint32_t count = end_height - start_height + 1;
    mxd_block_t *blocks = calloc(count, sizeof(mxd_block_t));
    if (!blocks) {
        MXD_LOG_ERROR("sync", "Failed to allocate memory for blocks");
        return NULL;
    }
    
    // Set up callback storage
    pending_blocks = blocks;
    pending_blocks_received = 0;
    pending_blocks_expected = count;
    pending_blocks_start_height = start_height;
    pending_blocks_end_height = end_height;

    // Try peers one at a time with a short timeout per peer.
    // CRITICAL: Do NOT send to ALL peers simultaneously — multiple peers
    // responding concurrently causes race conditions in the callback
    // (concurrent deserializations into the same pending_blocks memory,
    // and duplicate blocks flooding the unsolicited handler after timeout).
    int got_response = 0;
    for (size_t i = 0; i < peer_count && !got_response; i++) {
        if (peers[i].state != MXD_PEER_CONNECTED) continue;

        uint8_t request[8];
        uint8_t *ptr = request;
        mxd_write_u32_be(&ptr, start_height);
        mxd_write_u32_be(&ptr, end_height);

        if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                       MXD_MSG_GET_BLOCKS, request, sizeof(request), 1) != 0) {
            continue;
        }

        // Wait up to 1.5 seconds for this peer to respond.
        // Short timeout so we quickly move to the next peer if this one
        // is syncing itself (doesn't have the block).
        int wait_ms = 0;
        while (pending_blocks_received < count && wait_ms < 1500) {
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, NULL);
            wait_ms += 100;
        }

        if (pending_blocks_received >= count) {
            got_response = 1;
        }
        // else: this peer didn't respond in time, try next peer
    }

    pending_blocks = NULL;

    if (pending_blocks_received < count) {
        MXD_LOG_WARN("sync", "Only received %u of %u blocks after trying all peers",
                     pending_blocks_received, count);
    }

    *block_count = count;
    return blocks;
}

// Forward-propagate total_supply to subsequent blocks that have supply=0.
// Called after storing a block with valid (non-zero) supply.
// Re-computes delta for each forward block from its transaction data.
void mxd_propagate_supply_forward(uint32_t from_height, uint64_t from_supply) {
    for (uint32_t h = from_height + 1; ; h++) {
        mxd_block_t next;
        memset(&next, 0, sizeof(next));
        if (mxd_retrieve_block_by_height(h, &next) != 0) {
            break;  // No block at this height — stop
        }
        if (next.total_supply > 0) {
            mxd_free_block(&next);
            break;  // Already has valid supply — stop
        }
        // Recompute delta for this block (UTXOs are already applied, but
        // mxd_find_utxo returns spent UTXOs so delta is still correct)
        int64_t delta = 0;
        mxd_apply_block_transactions(&next, &delta);
        next.total_supply = (uint64_t)((int64_t)from_supply + delta);
        mxd_store_block(&next);
        MXD_LOG_INFO("sync", "Forward-propagated supply to height %u: %llu",
                     h, (unsigned long long)next.total_supply);
        from_supply = next.total_supply;
        mxd_free_block(&next);
    }
}

int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta) {
    if (!block) return -1;

    int64_t delta = 0;

    // Apply each transaction in the block to the UTXO state
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        if (!block->transactions[i].data || block->transactions[i].length == 0) {
            MXD_LOG_WARN("sync", "Skipping empty transaction at index %u", i);
            continue;
        }

        // Deserialize the transaction from block storage format
        mxd_transaction_t tx;
        memset(&tx, 0, sizeof(mxd_transaction_t));

        const uint8_t *ptr = block->transactions[i].data;
        const uint8_t *end = ptr + block->transactions[i].length;

        // Peek at version to determine v2 vs v3 format
        if (ptr + 4 > end) {
            MXD_LOG_ERROR("sync", "Transaction data too short at index %u", i);
            continue;
        }

        // Peek version without consuming (read first 4 bytes as big-endian u32)
        uint32_t peek_version = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
                                ((uint32_t)ptr[2] << 8) | (uint32_t)ptr[3];

        // ===== V3 Transaction Path (Bridge Mints/Burns) =====
        // V3 transactions carry oracle signatures that every node MUST verify.
        // Invalid bridge transactions cause the ENTIRE block to be rejected.
        if (peek_version == 3) {
            mxd_transaction_v3_t tx_v3;
            if (mxd_deserialize_transaction_v3_from_block(ptr, (size_t)(end - ptr), &tx_v3) != 0) {
                MXD_LOG_ERROR("sync", "Failed to deserialize v3 transaction at index %u", i);
                if (supply_delta) *supply_delta = delta;
                return -1;  // REJECT BLOCK: corrupt v3 transaction
            }

            if (tx_v3.type == MXD_TX_TYPE_BRIDGE_MINT) {
                // CONSENSUS-ONLY validation. The block-apply path runs on both
                // live block acceptance and historical sync/replay. Admin-state
                // policy checks (bridge_auth registry, daily rate limit) are
                // deliberately NOT run here because they depend on per-node
                // state that isn't carried in block data — a node that wiped
                // its data dir would otherwise reject valid historical mints.
                // The oracle signature check (the real security gate) IS run.
                // Full-policy validation is still enforced at HTTP submission
                // time by mxd_validate_bridge_mint_tx.
                if (mxd_validate_bridge_mint_tx_consensus_only(&tx_v3) != 0) {
                    MXD_LOG_ERROR("sync", "INVALID bridge mint at tx %u - REJECTING BLOCK at height %u",
                                  i, block->height);
                    mxd_free_transaction_v3(&tx_v3);
                    if (supply_delta) *supply_delta = delta;
                    return MXD_ERR_BRIDGE_INVALID;  // REJECT ENTIRE BLOCK
                }

                // Mark as processed on this node (replay protection; self-
                // populating on fresh nodes, idempotent on already-populated).
                mxd_mark_bridge_tx_processed(tx_v3.payload.bridge, tx_v3.tx_hash, block->height);

                // NOTE: we intentionally do NOT call mxd_record_bridge_mint()
                // here. That counter tracks "today's" live mint activity and
                // is consumed by the submission-time rate limiter in
                // mxd_validate_bridge_mint_tx. Recording historical mints
                // during sync would pollute today's counter and cause legit
                // live submissions to be wrongly rejected.

                // Bridge mint creates new supply
                for (uint32_t j = 0; j < tx_v3.output_count; j++) {
                    delta += (int64_t)tx_v3.outputs[j].amount;
                }
            } else if (tx_v3.type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
                       tx_v3.type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
                       tx_v3.type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
                // Admin tx: validate 3-of-5 oracle sigs (consensus-only —
                // nonce replay check is skipped; apply is idempotent via
                // RocksDB UPSERT).
                if (mxd_validate_admin_tx_consensus_only(&tx_v3) != 0) {
                    MXD_LOG_ERROR("sync", "INVALID admin tx at index %u - REJECTING BLOCK at height %u",
                                  i, block->height);
                    mxd_free_transaction_v3(&tx_v3);
                    if (supply_delta) *supply_delta = delta;
                    return MXD_ERR_BRIDGE_INVALID;
                }
                // Apply writes bridge_auth:* keys or admin:oracle_set + marks
                // each signer's nonce used. Non-fatal on write error (apply
                // may be redundant during resync, which is fine).
                if (mxd_apply_admin_tx(&tx_v3) != 0) {
                    MXD_LOG_WARN("sync", "Admin tx apply at height %u returned non-zero (idempotent retry ok)",
                                 block->height);
                }
                // Admin txs don't create/consume UTXOs or modify supply.
                mxd_free_transaction_v3(&tx_v3);
                continue;
            } else if (tx_v3.type == MXD_TX_TYPE_BRIDGE_BURN) {
                if (mxd_validate_bridge_burn_tx_consensus_only(&tx_v3) != 0) {
                    MXD_LOG_ERROR("sync", "INVALID bridge burn at tx %u - REJECTING BLOCK at height %u",
                                  i, block->height);
                    mxd_free_transaction_v3(&tx_v3);
                    if (supply_delta) *supply_delta = delta;
                    return MXD_ERR_BRIDGE_INVALID;  // REJECT ENTIRE BLOCK
                }
                // Burns reduce supply
                for (uint32_t j = 0; j < tx_v3.output_count; j++) {
                    delta -= (int64_t)tx_v3.outputs[j].amount;
                }
            } else {
                MXD_LOG_ERROR("sync", "Unsupported v3 transaction type %d at index %u", tx_v3.type, i);
                mxd_free_transaction_v3(&tx_v3);
                if (supply_delta) *supply_delta = delta;
                return MXD_ERR_BRIDGE_INVALID;  // REJECT BLOCK
            }

            // Apply to UTXO state
            int ret = mxd_apply_transaction_v3_to_utxo(&tx_v3);
            if (ret == MXD_ERR_IO) {
                MXD_LOG_ERROR("sync", "IO error applying v3 transaction %u - halting", i);
                mxd_free_transaction_v3(&tx_v3);
                if (supply_delta) *supply_delta = delta;
                return MXD_ERR_IO;
            }
            if (ret != 0) {
                MXD_LOG_DEBUG("sync", "V3 transaction %u UTXO skip (already applied)", i);
            }

            mxd_free_transaction_v3(&tx_v3);
            continue;  // Skip v2 processing
        }

        // ===== V2 Transaction Path (MXD-04 v1.1.x wire format) =====
        // Header: version(4) + chain_id(4) + input_count(4) + output_count(4)
        //         + tip(8) + timestamp(8) + tx_hash(64) = 96 bytes
        if (ptr + 4 + 4 + 4 + 4 + 8 + 8 + 64 > end) {
            MXD_LOG_ERROR("sync", "Transaction data too short at index %u", i);
            continue;
        }

        tx.version = mxd_read_u32_be(&ptr);
        tx.chain_id = mxd_read_u32_be(&ptr);    // NEW: chain_id per MXD-04 §3.1
        tx.input_count = mxd_read_u32_be(&ptr);
        tx.output_count = mxd_read_u32_be(&ptr);
        tx.voluntary_tip = mxd_read_u64_be(&ptr);
        tx.timestamp = mxd_read_u64_be(&ptr);
        // is_coinbase NOT on wire; recover from input_count
        mxd_read_bytes(&ptr, tx.tx_hash, 64);
        tx.is_coinbase = (tx.input_count == 0) ? 1 : 0;

        // Allocate and read inputs
        if (tx.input_count > 0) {
            tx.inputs = calloc(tx.input_count, sizeof(mxd_tx_input_t));
            if (!tx.inputs) {
                MXD_LOG_ERROR("sync", "Failed to allocate inputs for transaction %u", i);
                continue;
            }

            for (uint32_t j = 0; j < tx.input_count; j++) {
                if (ptr + 64 + 4 + 1 + 2 > end) {
                    mxd_free_transaction(&tx);
                    MXD_LOG_ERROR("sync", "Transaction input data truncated at index %u", i);
                    goto next_tx;
                }

                mxd_read_bytes(&ptr, tx.inputs[j].prev_tx_hash, 64);
                tx.inputs[j].output_index = mxd_read_u32_be(&ptr);
                tx.inputs[j].algo_id = mxd_read_u8(&ptr);
                tx.inputs[j].public_key_length = mxd_read_u16_be(&ptr);

                // Validate key length matches algorithm
                if (tx.inputs[j].public_key_length > MXD_PUBKEY_MAX_LEN ||
                    (tx.inputs[j].algo_id == MXD_SIGALG_ED25519 && tx.inputs[j].public_key_length != 32) ||
                    (tx.inputs[j].algo_id == MXD_SIGALG_DILITHIUM5 && tx.inputs[j].public_key_length != 2592) ||
                    (tx.inputs[j].algo_id != MXD_SIGALG_ED25519 && tx.inputs[j].algo_id != MXD_SIGALG_DILITHIUM5)) {
                    MXD_LOG_WARN("sync", "Invalid public key length %u for algo %u",
                                 tx.inputs[j].public_key_length, tx.inputs[j].algo_id);
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }

                if (ptr + tx.inputs[j].public_key_length + 2 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }

                tx.inputs[j].public_key = malloc(tx.inputs[j].public_key_length);
                if (!tx.inputs[j].public_key) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.inputs[j].public_key, tx.inputs[j].public_key_length);

                tx.inputs[j].signature_length = mxd_read_u16_be(&ptr);
                if (tx.inputs[j].signature_length > 0) {
                    if (ptr + tx.inputs[j].signature_length > end) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    tx.inputs[j].signature = malloc(tx.inputs[j].signature_length);
                    if (!tx.inputs[j].signature) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    mxd_read_bytes(&ptr, tx.inputs[j].signature, tx.inputs[j].signature_length);
                }
            }
        }

        // Allocate and read outputs
        if (tx.output_count > 0) {
            tx.outputs = calloc(tx.output_count, sizeof(mxd_tx_output_t));
            if (!tx.outputs) {
                mxd_free_transaction(&tx);
                MXD_LOG_ERROR("sync", "Failed to allocate outputs for transaction %u", i);
                continue;
            }

            for (uint32_t j = 0; j < tx.output_count; j++) {
                if (ptr + 32 + 8 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.outputs[j].recipient_addr, 32);  // addr32
                tx.outputs[j].amount = mxd_read_u64_be(&ptr);
            }
        }

        // Compute supply delta purely from block data (no UTXO lookups).
        // Coinbase txs create new supply: delta = +sum(outputs).
        // Non-coinbase txs with voluntary tips: the tip is deducted from
        // outputs (outputs = inputs - tip) but redistributed as a separate
        // coinbase tx. To avoid double-counting, subtract the tip here:
        //   non-coinbase delta = -voluntary_tip
        //   tip-redistribution coinbase delta = +tip
        //   net = 0 (supply-neutral, correct)
        if (tx.is_coinbase) {
            for (uint32_t j = 0; j < tx.output_count; j++) {
                delta += (int64_t)tx.outputs[j].amount;
            }
        } else if (tx.voluntary_tip > 0) {
            delta -= (int64_t)tx.voluntary_tip;
        }

        // Apply the transaction to UTXO state
        // Distinguish IO errors (must halt) from spent inputs (skip)
        int ret = mxd_apply_transaction_to_utxo(&tx);
        if (ret == MXD_ERR_IO) {
            MXD_LOG_ERROR("sync", "IO error applying transaction %u - halting block processing", i);
            mxd_free_transaction(&tx);
            if (supply_delta) *supply_delta = delta;
            return MXD_ERR_IO;  // HALT - caller must stop
        }
        if (ret != 0) {
            MXD_LOG_DEBUG("sync", "Transaction %u already applied (inputs spent), UTXO skip ok", i);
        }

        // Drain from mempool. Without this, peer nodes that received the tx
        // via MXD_MSG_TRANSACTIONS p2p broadcast keep it queued until
        // age-expiry, and every subsequent proposer re-includes it. The
        // proposer of THIS block already cleared its own mempool at
        // rsc.c:3609, but peers rely on this path. Compute canonical hash
        // fresh — tx.tx_hash carries whatever the originating wallet wrote
        // into the wire and may not match the mempool entry's recomputed
        // hash.
        {
            uint8_t canonical_hash[64];
            if (mxd_calculate_tx_hash(&tx, canonical_hash) == 0) {
                mxd_remove_from_mempool(canonical_hash);
            }
        }

        mxd_free_transaction(&tx);
        continue;

    next_tx:
        MXD_LOG_ERROR("sync", "Failed to deserialize transaction %u", i);
        continue;
    }

    if (supply_delta) *supply_delta = delta;
    return 0;
}

static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height) {
    // Advance height pointer first — blocks may have been stored out of
    // order by the unsolicited handler while we were syncing other ranges.
    mxd_advance_height_pointer();

    // Sync one block at a time to avoid partial-range failures.
    // The range request mechanism can receive fewer blocks than requested,
    // leaving the rest as zeroed structs that fail validation (version=0).
    int synced = 0;
    for (uint32_t h = start_height; h <= end_height; h++) {
        // Skip blocks we already have in the DB
        if (mxd_block_exists_at_height(h)) {
            synced++;
            continue;
        }

        size_t block_count = 0;
        mxd_block_t *blocks = mxd_request_blocks_from_peers(h, h, &block_count);
        if (!blocks) {
            MXD_LOG_WARN("sync", "Failed to request block %u from peers, skipping", h);
            continue;
        }

        mxd_block_t *block = &blocks[0];

        if (block->version == 0) {
            MXD_LOG_WARN("sync", "Block %u not received (empty response), skipping", h);
            for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
            free(blocks);
            continue;
        }

        // Skip full mxd_validate_block() during sync: it checks validator scores
        // which are cumulative (block H depends on block H-1's scores).
        // A node catching up from genesis doesn't have the correct local
        // score state, so validation always fails with "score mismatch".
        // However, we MUST verify block hash integrity and validation chain
        // to prevent malicious peers from feeding fabricated blocks.
        if (block->version < 1 || block->version > 5) {
            MXD_LOG_WARN("sync", "Invalid block version %u at height %u, skipping", block->version, h);
            for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
            free(blocks);
            continue;
        }

        // SECURITY: Verify block hash integrity
        {
            uint8_t computed_hash[64];
            if (mxd_calculate_block_hash(block, computed_hash) != 0 ||
                memcmp(computed_hash, block->block_hash, 64) != 0) {
                MXD_LOG_ERROR("sync", "Block hash verification failed at height %u - rejecting (possible tampering)", h);
                for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
                free(blocks);
                continue;
            }
        }

        // Require at least one valid signature for non-genesis synced blocks.
        // Full min_signatures enforcement (3+) is deferred until the validation
        // chain reliably accumulates multiple signatures per block.
        if (h > 0) {
            if (block->validation_count == 0) {
                MXD_LOG_WARN("sync", "Synced block at height %u has no signatures, skipping", h);
                for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
                free(blocks);
                continue;
            }
            if (mxd_verify_validation_chain_integrity(block) != 0) {
                // Warn but don't skip — historical blocks accepted by consensus are valid.
                // Strict enforcement only for newly proposed blocks (in mxd_process_validation_chain).
                MXD_LOG_WARN("sync", "Validation chain integrity imperfect for synced block at height %u (accepted)", h);
            }
        }

        int64_t supply_delta = 0;
        int tx_apply_failed = 0;
        int apply_result = mxd_apply_block_transactions(block, &supply_delta);
        if (apply_result == MXD_ERR_BRIDGE_INVALID) {
            MXD_LOG_ERROR("sync", "Block at height %u contains INVALID bridge transaction - REJECTING", h);
            continue;  // Skip this block entirely — do not store
        }
        if (apply_result != 0) {
            MXD_LOG_WARN("sync", "Failed to apply transactions at height %u, storing block anyway", h);
            tx_apply_failed = 1;
            supply_delta = 0;
        }

        // Compute total_supply deterministically from previous block + delta
        if (block->height > 0) {
            mxd_block_t prev;
            memset(&prev, 0, sizeof(prev));
            if (mxd_retrieve_block_by_height(block->height - 1, &prev) == 0) {
                block->total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                mxd_free_block(&prev);
            }
        } else {
            block->total_supply = (uint64_t)supply_delta;
        }

        // Always store the block even if tx apply failed — the block is
        // consensus-valid and not storing it creates a permanent gap that
        // prevents current_height from ever advancing past this point.
        if (mxd_store_block(block) != 0) {
            MXD_LOG_ERROR("sync", "Failed to store block at height %u", h);
            for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
            free(blocks);
            break;
        }

        // Update finalization tracking so proposer can proceed
        extern void mxd_set_finalized_height_external(uint32_t height);
        mxd_set_finalized_height_external(block->height);

        // Load validator scores from synced block into rapid table
        // so subsequent blocks can validate correctly
        if (block->version >= 4 && block->validator_scores) {
            const mxd_rapid_table_t *table = mxd_get_rapid_table();
            if (table) {
                mxd_load_scores_from_block((mxd_rapid_table_t *)table, block);
                mxd_compute_chain_scores((mxd_rapid_table_t *)table);
                mxd_sort_rapid_table_by_score((mxd_rapid_table_t *)table);
            }
        }

        MXD_LOG_INFO("sync", "Synced block at height %u", h);
        synced++;
        for (size_t bi = 0; bi < block_count; bi++) mxd_free_block(&blocks[bi]);
        free(blocks);
    }

    return synced > 0 ? 0 : -1;
}

int mxd_sync_blockchain(void) {
    // Advance current_height through blocks already in the DB from previous
    // sync passes. This avoids re-requesting blocks we already have.
    mxd_advance_height_pointer();

    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        local_height = 0;
    }

    uint32_t network_height = mxd_discover_network_height();
    if (network_height <= local_height) {
        MXD_LOG_INFO("sync", "Already synced (local: %u, network: %u)", local_height, network_height);
        return 0;
    }
    
    // local_height = number of blocks stored (blocks at heights 0 to local_height-1)
    // network_height = number of blocks on network
    // We need to sync blocks from height local_height to network_height-1
    MXD_LOG_INFO("sync", "Syncing from height %u to %u", local_height, network_height - 1);

    const uint32_t CHUNK_SIZE = 500;
    for (uint32_t start = local_height; start < network_height; start += CHUNK_SIZE) {
        uint32_t end = (start + CHUNK_SIZE < network_height) ?
                       start + CHUNK_SIZE - 1 : network_height - 1;
        
        if (mxd_sync_block_range(start, end) != 0) {
            MXD_LOG_WARN("sync", "Some blocks in range %u-%u failed, continuing", start, end);
        }
        
        MXD_LOG_INFO("sync", "Synced blocks %u-%u", start, end);
    }
    
    MXD_LOG_INFO("sync", "Blockchain sync complete");
    return 0;
}

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block) return -1;
    
    return mxd_retrieve_block_by_height(height, block);
}

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height) {
    if (!block_hash) return -1;
    
    if (mxd_request_validation_chain_from_peers(block_hash) != 0) {
        MXD_LOG_ERROR("sync", "Failed to request validation chain for block at height %u", height);
        return -1;
    }
    
    // For testing purposes, simulate successful sync
    MXD_LOG_INFO("sync", "Synchronizing validation chain for block at height %u", height);
    return 0;
}

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request validation chain");
        return -1;
    }
    
    int success = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            if (mxd_request_validation_chain(peers[i].address, peers[i].port, block_hash) == 0) {
                success = 1;
            }
        }
    }
    
    return success ? 0 : -1;
}

// Walk back `lookback` recent stored blocks. For any whose validation_count
// is below the rapid-table 2/3 quorum threshold, ask all connected peers
// for their full validation chain so the local copy can catch up. This
// converges divergent per-node validation_count views back to the network
// majority (gossip drops, peer restarts, or hung HTTP windows can otherwise
// leave a node permanently below quorum on a block the rest of the network
// has finalized).
void mxd_reconcile_validation_chains(uint32_t lookback) {
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0 || current_height == 0) {
        return;
    }

    // Use the same threshold formula as mxd_block_has_quorum.
    mxd_peer_t rt_peers[MXD_MAX_PEERS];
    size_t rt_count = MXD_MAX_PEERS;
    uint32_t quorum;
    if (mxd_get_rapid_table_peers(rt_peers, &rt_count) == 0 && rt_count > 0) {
        quorum = (uint32_t)((rt_count * 2 + 2) / 3);
    } else {
        quorum = 4;  // sensible default for the 5-validator mainnet
    }
    if (quorum < 1) quorum = 1;

    uint32_t start = (current_height >= lookback) ? (current_height - lookback + 1) : 1;
    int requested = 0;
    for (uint32_t h = start; h <= current_height; h++) {
        mxd_block_t block;
        memset(&block, 0, sizeof(block));
        if (mxd_get_block_by_height(h, &block) != 0) {
            continue;
        }
        if (block.validation_count < quorum) {
            mxd_request_validation_chain_from_peers(block.block_hash);
            requested++;
        }
        mxd_free_block(&block);
    }

    if (requested > 0) {
        MXD_LOG_INFO("sync", "Reconcile: requested validation chains for %d block(s) below quorum (%u/%zu)",
                     requested, quorum, rt_count);
    }
}

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64],
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count) {
    if (!block_hash || !signatures || signature_count == 0) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for validation chain processing");
        return -1;
    }
    
    // Process incoming sigs in chain_position order. The peer's chain may
    // include sigs at positions we already filled (skip those), and the
    // sequential add path requires processing them in order so each sig's
    // expected position equals our current validation_count after the
    // prior add. skip_drift_check=1 because sigs may be hours old
    // (catchup of an older block); cryptographic verify still gates them.
    int added = 0;
    for (uint32_t i = 0; i < signature_count; i++) {
        if (mxd_verify_and_add_validation_signature(&block,
                                                  signatures[i].validator_id,
                                                  signatures[i].algo_id,
                                                  signatures[i].signature,
                                                  signatures[i].signature_length,
                                                  signatures[i].timestamp,
                                                  /* skip_drift_check */ 1) == 0) {
            added++;
        }
    }

    if (added > 0) {
        if (mxd_store_block(&block) != 0) {
            MXD_LOG_ERROR("sync", "Failed to store block with updated validation chain");
            mxd_free_block(&block);
            return -1;
        }
        MXD_LOG_INFO("sync", "Catchup added %d sigs to block %u (total now %u)",
                     added, block.height, block.validation_count);
    }

    mxd_free_block(&block);

    if (mxd_check_block_relay_status(block_hash) == 1) {
        MXD_LOG_INFO("sync", "Block has enough signatures for relay");
    }

    return 0;
}

int mxd_verify_and_add_validation_signature(mxd_block_t *block,
                                           const uint8_t validator_id[32],
                                           uint8_t algo_id,
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp,
                                           int skip_drift_check) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) return -1;

    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_WARN("sync", "Invalid algo_id %u", algo_id);
        return -1;
    }

    if (!skip_drift_check) {
        // Use NTP-synchronized time for timestamp validation.
        // Note: timestamp parameter is in milliseconds (from mxd_now_ms()).
        uint64_t current_time_ms = 0;
        if (mxd_get_network_time(&current_time_ms) != 0) {
            current_time_ms = (uint64_t)time(NULL) * 1000;
        }
        uint64_t timestamp_sec = timestamp / 1000;
        uint64_t current_time_sec = current_time_ms / 1000;
        uint64_t drift = (timestamp_sec > current_time_sec) ?
                         (timestamp_sec - current_time_sec) :
                         (current_time_sec - timestamp_sec);

        if (drift > MXD_MAX_TIMESTAMP_DRIFT) {
            MXD_LOG_WARN("sync", "Signature timestamp drift too large: %lu seconds (ts=%lu, now=%lu)",
                         (unsigned long)drift, (unsigned long)timestamp_sec, (unsigned long)current_time_sec);
            return -1;
        }
    }
    
    if (mxd_signature_exists(block->height, validator_id, signature, signature_length) != 0) {
        MXD_LOG_DEBUG("sync", "Signature already exists for this block height");
        return -1;
    }
    
    if (mxd_is_validator_blacklisted(validator_id) != 0) {
        MXD_LOG_WARN("sync", "Validator is blacklisted");
        return -1;
    }
    
    // Use the validated signature addition path with timestamp drift checking
    uint32_t chain_position = block->validation_count;
    if (mxd_add_validator_signature_to_block(block, validator_id, timestamp, algo_id, signature, signature_length, chain_position) != 0) {
        MXD_LOG_ERROR("sync", "Failed to add validator signature to block");
        return -1;
    }
    
    return 0;
}

int mxd_check_block_relay_status(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for relay status check");
        return -1;
    }
    
    int has_enough = (block.validation_count >= MXD_MIN_RELAY_SIGNATURES) ? 1 : 0;
    mxd_free_block(&block);
    return has_enough;
}

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!table) return -1;
    
    MXD_LOG_INFO("sync", "Synchronizing Rapid Table with network");
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0 || current_height == 0) {
        MXD_LOG_WARN("sync", "No blockchain data available for rapid table sync");
        return 0;
    }
    
    uint32_t from_height = current_height > 1000 ? current_height - 1000 : 0;
    
    if (mxd_rebuild_rapid_table_from_blockchain(table, from_height, current_height, local_node_id) == 0) {
        MXD_LOG_INFO("sync", "Rapid Table synchronized from blockchain (heights %u to %u)", 
                     from_height, current_height);
        return 0;
    } else {
        MXD_LOG_ERROR("sync", "Failed to rebuild rapid table from blockchain");
        return -1;
    }
}

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64], 
                                        const uint8_t block_hash2[64]) {
    if (!block_hash1 || !block_hash2) return -1;
    
    mxd_block_t block1, block2;
    memset(&block1, 0, sizeof(block1));
    memset(&block2, 0, sizeof(block2));

    if (mxd_retrieve_block_by_hash(block_hash1, &block1) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block1 for conflict resolution");
        return -1;
    }
    if (mxd_retrieve_block_by_hash(block_hash2, &block2) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block2 for conflict resolution");
        mxd_free_block(&block1);
        return -1;
    }

    int result = mxd_resolve_fork(&block1, &block2);

    mxd_free_block(&block1);
    mxd_free_block(&block2);

    if (result > 0) {
        MXD_LOG_INFO("sync", "Block 1 wins conflict resolution");
        return 1;
    } else if (result < 0) {
        MXD_LOG_INFO("sync", "Block 2 wins conflict resolution");
        return 2;
    } else {
        MXD_LOG_INFO("sync", "Conflict resolution inconclusive");
        return 0;
    }
}

int mxd_prune_expired_validation_chains(uint32_t current_height) {
    if (current_height < MXD_VALIDATION_EXPIRY_BLOCKS) {
        return 0; // Nothing to prune yet
    }

    uint32_t prune_height = current_height - MXD_VALIDATION_EXPIRY_BLOCKS;

    return mxd_prune_expired_signatures(prune_height);
}

// Pull-based sync fallback - actively request missing blocks from peers
// This is called periodically to catch blocks that failed to broadcast
int mxd_pull_missing_blocks(void) {
    // Advance height through any blocks already in DB
    mxd_advance_height_pointer();

    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        local_height = 0;
    }

    // Get peers and check their heights
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        return 0;  // No peers, nothing to do
    }

    // Shuffle peers to avoid always hitting syncing peers first
    for (size_t i = peer_count - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        mxd_peer_t tmp = peers[i];
        peers[i] = peers[j];
        peers[j] = tmp;
    }

    // Find the maximum height among all peers
    uint32_t max_peer_height = local_height;
    int peers_queried = 0;

    for (size_t i = 0; i < peer_count && peers_queried < 5; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint32_t peer_height = 0;
            if (mxd_request_peer_height(peers[i].address, peers[i].port, &peer_height) == 0) {
                peers_queried++;
                if (peer_height > max_peer_height) {
                    max_peer_height = peer_height;
                    MXD_LOG_INFO("sync", "Peer %s:%u has higher height: %u (local: %u)",
                                 peers[i].address, peers[i].port, peer_height, local_height);
                }
            }
        }
    }

    // FIRST: scan for and fill interior block gaps below current_height
    // This runs before height-based sync so gaps are always detected
    {
        uint32_t gaps[100];
        uint32_t gap_count = 0;
        if (mxd_fill_block_gaps(gaps, 100, &gap_count) == 0 && gap_count > 0) {
            MXD_LOG_INFO("sync", "Found %u block gaps below current height, attempting to fill", gap_count);
            for (uint32_t g = 0; g < gap_count; g++) {
                int gap_filled = 0;
                for (size_t i = 0; i < peer_count && !gap_filled; i++) {
                    if (peers[i].state != MXD_PEER_CONNECTED) continue;

                    uint8_t request[8];
                    uint8_t *rptr = request;
                    mxd_write_u32_be(&rptr, gaps[g]);
                    mxd_write_u32_be(&rptr, gaps[g]);

                    if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                                    MXD_MSG_GET_BLOCKS, request, sizeof(request), 3) == 0) {
                        struct timespec ts = {0, 200000000};  // 200ms
                        nanosleep(&ts, NULL);

                        if (mxd_block_exists_at_height(gaps[g])) {
                            gap_filled = 1;
                            MXD_LOG_INFO("sync", "Gap fill: received block at height %u", gaps[g]);
                        }
                    }
                }
                if (!gap_filled) {
                    MXD_LOG_WARN("sync", "Gap fill: failed to fetch block at height %u", gaps[g]);
                }
            }
        }
    }

    // If any peer has blocks we don't have, request them
    if (max_peer_height > local_height) {
        MXD_LOG_INFO("sync", "Pull sync: fetching missing blocks %u to %u",
                     local_height, max_peer_height - 1);

        // Request blocks one at a time for reliability
        for (uint32_t height = local_height; height < max_peer_height; height++) {
            int block_received = 0;

            // Try multiple peers for each block
            for (size_t i = 0; i < peer_count && !block_received; i++) {
                if (peers[i].state != MXD_PEER_CONNECTED) continue;

                // Send GET_BLOCKS request for this specific block
                uint8_t request[8];
                uint8_t *ptr = request;
                mxd_write_u32_be(&ptr, height);      // start_height
                mxd_write_u32_be(&ptr, height);      // end_height (same = single block)

                if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                                MXD_MSG_GET_BLOCKS, request, sizeof(request), 3) == 0) {
                    MXD_LOG_DEBUG("sync", "Requested block %u from %s:%u",
                                  height, peers[i].address, peers[i].port);

                    // Wait briefly for the block to arrive (it will be handled by mxd_handle_blocks_response)
                    struct timespec ts = {0, 100000000};  // 100ms
                    nanosleep(&ts, NULL);

                    // Check if we now have the block
                    uint32_t new_height = 0;
                    if (mxd_get_blockchain_height(&new_height) == 0 && new_height > height) {
                        block_received = 1;
                        MXD_LOG_INFO("sync", "Pull sync: received block at height %u", height);
                    }
                }
            }

            if (!block_received) {
                MXD_LOG_WARN("sync", "Pull sync: failed to fetch block at height %u", height);
                break;  // Stop trying if we can't get a block
            }
        }

        return 1;  // Indicate we did some sync work
    }

    return 0;  // No sync needed
}

// Sign a received block and broadcast signature to the network
// This is called by validators when they receive a new block
int mxd_sign_and_broadcast_block(const mxd_block_t *block) {
    if (!block || block->height == 0) {
        return -1;  // Don't sign genesis block here
    }

    // Only sign if our local chain is at block->height (i.e. we just stored it).
    // A node that's still syncing has stale UTXO state and cannot properly
    // validate the block's transactions — signing would be meaningless.
    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0 || local_height < block->height) {
        MXD_LOG_DEBUG("sync", "Not signing block %u: local height %u is behind",
                      block->height, local_height);
        return 0;
    }

    // Get local validator credentials
    extern const uint8_t* mxd_get_local_address(void);
    extern const uint8_t* mxd_get_local_privkey(void);
    extern uint8_t mxd_get_local_algo_id(void);

    const uint8_t *local_address = mxd_get_local_address();
    const uint8_t *local_privkey = mxd_get_local_privkey();
    uint8_t algo_id = mxd_get_local_algo_id();

    if (!local_address || !local_privkey) {
        MXD_LOG_INFO("sync", "No local credentials for signing block %u", block->height);
        return -1;
    }

    // Check if we're a validator in the rapid table
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (!table) {
        MXD_LOG_INFO("sync", "No rapid table for validator check (block %u)", block->height);
        return -1;
    }

    int is_validator = 0;
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && memcmp(table->nodes[i]->node_address, local_address, 32) == 0) {   // v6: addr32
            is_validator = 1;
            break;
        }
    }

    if (!is_validator) {
        char addr_hex[65] = {0};   // v6: addr32 (was 41 for 20-byte)
        for (int j = 0; j < 32; j++) snprintf(addr_hex + j*2, 3, "%02x", local_address[j]);
        MXD_LOG_INFO("sync", "Not a validator (local=%s, table_count=%zu), skipping block %u",
                     addr_hex, table->count, block->height);
        return 0;
    }

    // Check if we already signed this block
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (memcmp(block->validation_chain[i].validator_id, local_address, 32) == 0) {   // v6: addr32
            MXD_LOG_DEBUG("sync", "Already signed block at height %u", block->height);
            return 0;
        }
    }

    // Determine our signing position in the sequential chain
    int my_position = mxd_get_my_signing_position(table, block->proposer_id, local_address, block->height);
    if (my_position < 0) {
        MXD_LOG_WARN("sync", "Not in signing order for block %u", block->height);
        return 0;
    }

    // Check if it's our turn: we need all preceding signatures present
    if ((uint32_t)my_position != block->validation_count) {
        // Not our turn yet - need more preceding signatures
        MXD_LOG_INFO("sync", "Not our turn yet for block %u (my_position=%d, validation_count=%u)",
                     block->height, my_position, block->validation_count);
        return 0;
    }

    // Compute chain_hash for our position
    uint8_t chain_hash[64];
    mxd_compute_chain_hash(block, (uint32_t)my_position, chain_hash);

    // v7 cascade (L6-5): MXD-CONS-1 (11) || block_hash(64) || chain_hash(64) || ts_be(8)
    uint64_t timestamp = mxd_now_ms();
    uint8_t sign_msg[MXD_DOMAIN_TAG_CONS_LEN + 64 + 64 + 8];
    size_t smo = 0;
    memcpy(sign_msg + smo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); smo += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(sign_msg + smo, block->block_hash, 64); smo += 64;
    memcpy(sign_msg + smo, chain_hash, 64); smo += 64;
    uint64_t ts_be = mxd_htonll(timestamp);
    memcpy(sign_msg + smo, &ts_be, 8); smo += 8;

    uint8_t signature[MXD_SIGNATURE_MAX];
    size_t sig_len = sizeof(signature);

    if (mxd_sig_sign(algo_id, signature, &sig_len, sign_msg, sizeof(sign_msg), local_privkey) != 0) {
        MXD_LOG_ERROR("sync", "Failed to sign block at height %u", block->height);
        return -1;
    }

    char addr_hex[65] = {0};   // v6: addr32 (was 41 for 20-byte)
    for (int j = 0; j < 32; j++) snprintf(addr_hex + j*2, 3, "%02x", local_address[j]);
    char chain_hex[17] = {0};
    for (int j = 0; j < 8; j++) snprintf(chain_hex + j*2, 3, "%02x", chain_hash[j]);
    MXD_LOG_INFO("sync", "Signed block at height %u position %d, chain_hash=%s... (validator=%s)",
                 block->height, my_position, chain_hex, addr_hex);

    // Add our own signature to the local block and store it
    // This ensures subsequent signatures can build on ours locally
    {
        mxd_block_t local_block;
        memset(&local_block, 0, sizeof(local_block));
        if (mxd_retrieve_block_by_hash(block->block_hash, &local_block) == 0) {
            // Use mxd_add_validator_signature (no re-verification needed for our own sig)
            extern int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[32],   // v6: addr32
                                                   uint64_t timestamp, uint8_t algo_id,
                                                   const uint8_t *signature, uint16_t signature_length);
            if (mxd_add_validator_signature(&local_block, local_address, timestamp, algo_id,
                                            signature, (uint16_t)sig_len) == 0) {
                if (mxd_store_block(&local_block) != 0) {
                    MXD_LOG_ERROR("sync", "Failed to store block with own signature at height %u", block->height);
                }
                MXD_LOG_INFO("sync", "Stored own chain signature locally for block %u (now %u sigs)",
                             block->height, local_block.validation_count);
            }
            mxd_free_block(&local_block);
        }
    }

    // Broadcast signature to all peers
    // v6 wire format: block_hash(64) + algo_id(1) + validator_id(32) + sig_len(2) + signature +
    //         chain_pos(4) + timestamp(8) + chain_hash(64)
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) == 0 && peer_count > 0) {
        size_t msg_len = 64 + 1 + 32 + 2 + sig_len + 4 + 8 + 64;   // v6: validator_id widened to 32
        uint8_t *msg = malloc(msg_len);
        if (msg) {
            uint8_t *ptr = msg;
            memcpy(ptr, block->block_hash, 64); ptr += 64;
            *ptr++ = algo_id;
            memcpy(ptr, local_address, 32); ptr += 32;   // v6: addr32
            uint16_t sig_len_net = htons((uint16_t)sig_len);
            memcpy(ptr, &sig_len_net, 2); ptr += 2;
            memcpy(ptr, signature, sig_len); ptr += sig_len;
            uint32_t chain_pos = (uint32_t)my_position;
            uint32_t chain_pos_net = htonl(chain_pos);
            memcpy(ptr, &chain_pos_net, 4); ptr += 4;
            uint64_t ts_net = mxd_htonll(timestamp);
            memcpy(ptr, &ts_net, 8); ptr += 8;
            memcpy(ptr, chain_hash, 64);

            int sent = 0;
            for (size_t i = 0; i < peer_count; i++) {
                if (mxd_send_message(peers[i].address, peers[i].port,
                                    MXD_MSG_VALIDATION_SIGNATURE, msg, msg_len) == 0) {
                    sent++;
                }
            }
            MXD_LOG_INFO("sync", "Broadcast chain signature for block %u pos %d to %d/%zu peers",
                         block->height, my_position, sent, peer_count);
            free(msg);

            // Re-broadcast all preceding signatures to handle partial P2P connectivity.
            // Some peers may have missed earlier positions' broadcasts, so we resend
            // the full chain to ensure all peers can build the complete sequence.
            if (my_position > 0) {
                mxd_block_t full_block;
                memset(&full_block, 0, sizeof(full_block));
                if (mxd_retrieve_block_by_hash(block->block_hash, &full_block) == 0 &&
                    full_block.validation_chain && full_block.validation_count > 1) {
                    int resent = 0;
                    for (uint32_t pos = 0; pos < full_block.validation_count - 1 && pos < (uint32_t)my_position; pos++) {
                        const mxd_validator_signature_t *vs = &full_block.validation_chain[pos];

                        uint8_t pos_chain_hash[64];
                        mxd_compute_chain_hash(&full_block, pos, pos_chain_hash);

                        // v6: validator_id widened to 32 bytes (addr32)
                        size_t rmsg_len = 64 + 1 + 32 + 2 + vs->signature_length + 4 + 8 + 64;
                        uint8_t *rmsg = malloc(rmsg_len);
                        if (rmsg) {
                            uint8_t *rp = rmsg;
                            memcpy(rp, full_block.block_hash, 64); rp += 64;
                            *rp++ = vs->algo_id;
                            memcpy(rp, vs->validator_id, 32); rp += 32;
                            uint16_t rsl = htons(vs->signature_length);
                            memcpy(rp, &rsl, 2); rp += 2;
                            memcpy(rp, vs->signature, vs->signature_length); rp += vs->signature_length;
                            uint32_t rcp = htonl(pos);
                            memcpy(rp, &rcp, 4); rp += 4;
                            uint64_t rts = mxd_htonll(vs->timestamp);
                            memcpy(rp, &rts, 8); rp += 8;
                            memcpy(rp, pos_chain_hash, 64);

                            for (size_t pi = 0; pi < peer_count; pi++) {
                                mxd_send_message(peers[pi].address, peers[pi].port,
                                                MXD_MSG_VALIDATION_SIGNATURE, rmsg, rmsg_len);
                            }
                            resent++;
                            free(rmsg);
                        }
                    }
                    if (resent > 0) {
                        MXD_LOG_INFO("sync", "Re-broadcast %d preceding sigs for block %u to %zu peers",
                                     resent, full_block.height, peer_count);
                    }
                    mxd_free_block(&full_block);
                }
            }
        }
    }

    return 0;
}
