#include "../../include/mxd_rsc.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_blockchain_db.h"
#include "../../include/mxd_blockchain_sync.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_address.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_p2p.h"
#include "../../include/mxd_endian.h"
#include "../../include/mxd_rocksdb_globals.h"
#include "../../include/mxd_config.h"
#include "../../include/mxd_transaction.h"
#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_serialize.h"
#include "../../include/mxd_domain_tags.h"
#include "../../include/mxd_validator_management.h"
#include "../../include/mxd_block_proposer.h"
#include "../../include/mxd_protocol_version.h"
#include "../metrics/mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <rocksdb/c.h>

// Global rapid table for validator tracking
static mxd_rapid_table_t g_rapid_table = {0};
static pthread_mutex_t rapid_table_mutex = PTHREAD_MUTEX_INITIALIZER;

// Accessor function for rapid table (used by other modules)
const mxd_rapid_table_t* mxd_get_rapid_table(void) {
    return &g_rapid_table;
}

// Forward declarations for v5 consensus (defined later, used in process_validation_chain)
static uint32_t mxd_compute_proposer_index(const uint8_t prev_block_hash[64],
                                            uint32_t height, uint32_t validator_count);
static void set_finalized_height(uint32_t height);

// Performance thresholds
#define MXD_MAX_RESPONSE_TIME 120000   // Maximum acceptable response time (ms) - increased for testing
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses needed for ranking
#define MXD_INACTIVE_THRESHOLD 300000  // Node considered inactive after 5 minutes
#define MXD_RELIABILITY_WEIGHT 0.3     // Weight for reliability in ranking
#define MXD_SPEED_WEIGHT 0.4           // Weight for speed in ranking
#define MXD_STAKE_WEIGHT 0.3           // Weight for stake in ranking

// Validation chain thresholds
#define MXD_MIN_RELAY_SIGNATURES 3     // Minimum signatures required for relay (X=3)
#define MXD_VALIDATION_EXPIRY 5        // Validation signatures expire after 5 blocks
#define MXD_BLACKLIST_DURATION_DEFAULT 1000    // Default blacklist duration (in blocks) - Per Phase 4 spec: ban for 1000 blocks
#define MXD_MAX_TIMESTAMP_DRIFT_MS 60000ULL  // Maximum timestamp drift allowed (in milliseconds)

// Helper function to serialize a coinbase transaction for adding to a block
// Returns allocated buffer that must be freed by caller, or NULL on error
static uint8_t* serialize_coinbase_for_block(const mxd_transaction_t* tx, size_t* out_len) {
    if (!tx || !out_len || !tx->is_coinbase) return NULL;
    
    // Calculate total size needed for coinbase transaction
    // Coinbase transactions have no inputs, only outputs
    size_t size = 0;
    size += 4;  // version (u32)
    size += 4;  // chain_id (u32) — NEW per MXD-04 §3.1
    size += 4;  // input_count (u32) - always 0 for coinbase
    size += 4;  // output_count (u32)
    size += 8;  // voluntary_tip (u64)
    size += 8;  // timestamp (u64)
    // is_coinbase NOT serialized; recovered as (input_count == 0)
    size += 64; // tx_hash

    // Calculate output sizes (addr32)
    for (uint32_t i = 0; i < tx->output_count; i++) {
        size += 32;  // recipient_addr (addr32)
        size += 8;   // amount (u64)
    }
    
    uint8_t* buffer = malloc(size);
    if (!buffer) return NULL;
    
    uint8_t* ptr = buffer;
    
    // Serialize header fields (MXD-04 v1.1.x wire format)
    mxd_write_u32_be(&ptr, tx->version);
    mxd_write_u32_be(&ptr, tx->chain_id);   // NEW: chain_id per MXD-04 §3.1
    mxd_write_u32_be(&ptr, 0);  // input_count (0 for coinbase)
    mxd_write_u32_be(&ptr, tx->output_count);
    mxd_write_u64_be(&ptr, tx->voluntary_tip);
    mxd_write_u64_be(&ptr, tx->timestamp);
    // is_coinbase NOT serialized; recovered as (input_count == 0) on deserialize
    mxd_write_bytes(&ptr, tx->tx_hash, 64);

    // Serialize outputs (addr32)
    for (uint32_t i = 0; i < tx->output_count; i++) {
        mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 32);
        mxd_write_u64_be(&ptr, tx->outputs[i].amount);
    }
    
    *out_len = size;
    return buffer;
}

// Helper function to get blacklist duration from config or use default
static uint32_t get_blacklist_duration(void) {
    mxd_config_t *config = mxd_get_config();
    if (config && config->consensus.blacklist_duration_blocks > 0) {
        return config->consensus.blacklist_duration_blocks;
    }
    return MXD_BLACKLIST_DURATION_DEFAULT;
}

#include "../../include/mxd_rocksdb_globals.h"

// Initialize node metrics
int mxd_init_node_metrics(mxd_node_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }

    metrics->avg_response_time = 0;
    metrics->min_response_time = UINT64_MAX;
    metrics->max_response_time = 0;
    metrics->response_count = 0;
    metrics->tip_share = 0;
    // Initialize with current time so validators appear active from start
    metrics->last_update = mxd_now_ms();

    return 0;
}

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, mxd_amount_t total_stake) {
    if (!node || total_stake == 0) {
        return -1;
    }

    // Check minimum stake requirement (1% of total stake)
    return (node->stake_amount >= total_stake / 100) ? 0 : -1;
}

// Update node response metrics with NTP-synchronized timestamp
int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp) {
    if (!node || response_time > MXD_MAX_RESPONSE_TIME) {
        return -1;
    }

    mxd_node_metrics_t *metrics = &node->metrics;

    // Update response time statistics
    metrics->response_count++;
    double old_avg = metrics->avg_response_time;
    metrics->avg_response_time = old_avg + (response_time - old_avg) / metrics->response_count;
    metrics->min_response_time = response_time < metrics->min_response_time ?
                                response_time : metrics->min_response_time;
    metrics->max_response_time = response_time > metrics->max_response_time ?
                                response_time : metrics->max_response_time;
    metrics->last_update = timestamp;

    // Update reliability and performance scores so they're always current
    if (metrics->response_count >= MXD_MIN_RESPONSE_COUNT) {
        // Reliability: consistency of response times (low variance = high reliability)
        double variance_score = 1.0 - (metrics->max_response_time - metrics->min_response_time) /
                               (double)MXD_MAX_RESPONSE_TIME;
        if (variance_score < 0.0) variance_score = 0.0;
        metrics->reliability_score = variance_score;

        // Performance: speed score (lower avg response time = higher performance)
        double speed_score = 1.0 - (metrics->avg_response_time / (double)MXD_MAX_RESPONSE_TIME);
        if (speed_score < 0.0) speed_score = 0.0;
        metrics->performance_score = speed_score;
    }

    return 0;
}

// Calculate reliability score (0.0 to 1.0)
static double calculate_reliability(const mxd_node_metrics_t *metrics) {
    if (metrics->response_count < MXD_MIN_RESPONSE_COUNT) {
        return 0.0;
    }

    // Calculate consistency score based on response time variance
    double variance_score = 1.0 - (metrics->max_response_time - metrics->min_response_time) / 
                           (double)MXD_MAX_RESPONSE_TIME;
    if (variance_score < 0.0) variance_score = 0.0;

    return variance_score;
}

// Calculate node ranking based on stake, speed, and reliability
int mxd_calculate_node_rank(const mxd_node_stake_t *node, mxd_amount_t total_stake) {
    if (!node || total_stake == 0) {
        return -1;
    }

    const mxd_node_metrics_t *metrics = &node->metrics;
    
    // Node must have minimum responses and be active
    if (metrics->response_count < MXD_MIN_RESPONSE_COUNT || !node->active) {
        return -1;
    }

    // Calculate component scores (0.0 to 1.0)
    double speed_score = 1.0 - (metrics->avg_response_time / (double)MXD_MAX_RESPONSE_TIME);
    if (speed_score < 0.0) speed_score = 0.0;

    double stake_score = (double)node->stake_amount / (double)total_stake;
    double reliability_score = calculate_reliability(metrics);

    // Calculate weighted score
    double total_score = (speed_score * MXD_SPEED_WEIGHT) +
                        (stake_score * MXD_STAKE_WEIGHT) +
                        (reliability_score * MXD_RELIABILITY_WEIGHT);

    // Convert to integer rank (0-1000)
    return (int)(total_score * 1000.0);
}

// Compare function for node ranking
static int compare_nodes(const void *a, const void *b) {
    const mxd_node_stake_t *node_a = (const mxd_node_stake_t *)a;
    const mxd_node_stake_t *node_b = (const mxd_node_stake_t *)b;

    // Inactive nodes are ranked last
    if (node_a->active != node_b->active) {
        return node_a->active ? -1 : 1;
    }

    // Sort by rank (higher is better)
    if (node_a->rank != node_b->rank) {
        return (node_a->rank < node_b->rank) ? 1 : -1;
    }

    return 0;
}

// Compare function for node pointers (for qsort on pointer arrays)
static int compare_node_ptrs(const void *a, const void *b) {
    const mxd_node_stake_t *node_a = *(const mxd_node_stake_t * const *)a;
    const mxd_node_stake_t *node_b = *(const mxd_node_stake_t * const *)b;
    return compare_nodes(node_a, node_b);
}

// Distribute voluntary tips based on node performance
int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_tip) {
    if (!nodes || node_count == 0 || total_tip == 0) {
        return -1;
    }

    // Count active nodes with positive rank
    size_t active_count = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            active_count++;
        }
    }

    if (active_count == 0) {
        // If no nodes have positive rank, distribute to all active nodes equally
        // This handles the case where nodes are active but rank calculation failed
        for (size_t i = 0; i < node_count; i++) {
            if (nodes[i].active) {
                active_count++;
            }
        }
        
        if (active_count == 0) {
            return -1;
        }
        
        // Distribute using 50% geometric decay pattern to all active nodes
        mxd_amount_t remaining = total_tip;
        size_t distributed_count = 0;
        for (size_t i = 0; i < node_count; i++) {
            if (nodes[i].active) {
                distributed_count++;
                if (distributed_count == active_count || remaining <= 1) {
                    // Last active node gets remaining amount
                    nodes[i].metrics.tip_share = remaining;
                    remaining = 0;
                } else {
                    // Each node gets 50% of remaining (integer division)
                    nodes[i].metrics.tip_share = remaining / 2;
                    remaining -= nodes[i].metrics.tip_share;
                }
            } else {
                nodes[i].metrics.tip_share = 0;
            }
        }
        return 0;
    }

    // Sort nodes by rank (highest to lowest)
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

    // Distribute tips using 50% geometric decay pattern from whitepaper
    mxd_amount_t remaining = total_tip;
    size_t distributed_count = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            distributed_count++;
            if (distributed_count == active_count || remaining <= 1) {
                // Last active node gets remaining amount
                nodes[i].metrics.tip_share = remaining;
                remaining = 0;
            } else {
                // Each node gets 50% of remaining (integer division)
                nodes[i].metrics.tip_share = remaining / 2;
                remaining -= nodes[i].metrics.tip_share;
            }
        } else {
            nodes[i].metrics.tip_share = 0;
        }
    }

    return 0;
}

// Update rapid table entries and recalculate rankings
// CRITICAL FIX: Rapid table updates should be tied to block signing events
// This function should only be called when a block reaches quorum (not arbitrarily)
// The blockchain-based state requirement means rapid table modifications must occur
// at block signing events, not at arbitrary times.
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_stake) {
    if (!nodes || node_count == 0 || total_stake == 0) {
        return -1;
    }

    uint64_t current_time = mxd_now_ms();

    // Update node activity status and calculate ranks
    for (size_t i = 0; i < node_count; i++) {
        // Check if node is active based on last update time
        nodes[i].active = (current_time - nodes[i].metrics.last_update) < MXD_INACTIVE_THRESHOLD;
        
        // Calculate new rank
        nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
    }

    // Sort nodes by rank score (higher score = better position)
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

    // Assign ordinal positions (1-based) after sorting
    for (size_t i = 0; i < node_count; i++) {
        nodes[i].rapid_table_position = (uint32_t)(i + 1);
    }

    return 0;
}

int mxd_update_rapid_table_rankings(mxd_rapid_table_t *table) {
    if (!table || !table->nodes || table->count == 0) return -1;
    mxd_sort_rapid_table_by_score(table);
    return 0;
}

// Get node performance statistics
int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats) {
    if (!node || !stats) {
        return -1;
    }

    *stats = node->metrics;
    return 0;
}

// Check if node meets minimum performance requirements
int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time) {
    if (!node) {
        return -1;
    }

    // Check if node is active
    if (!node->active || 
        (current_time - node->metrics.last_update) >= MXD_INACTIVE_THRESHOLD) {
        return -1;
    }

    // Check minimum response count
    if (node->metrics.response_count < MXD_MIN_RESPONSE_COUNT) {
        return -1;
    }

    // Check average response time
    if (node->metrics.avg_response_time >= MXD_MAX_RESPONSE_TIME) {
        return -1;
    }

    return 0;
}

// Initialize Rapid Table
int mxd_init_rapid_table(mxd_rapid_table_t *table, size_t capacity) {
    if (!table || capacity == 0) {
        return -1;
    }
    
    table->nodes = malloc(capacity * sizeof(mxd_node_stake_t *));
    if (!table->nodes) {
        return -1;
    }
    
    memset(table->nodes, 0, capacity * sizeof(mxd_node_stake_t *));
    table->count = 0;
    table->capacity = capacity;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node, const char *local_node_id) {
    if (!table || !node || !table->nodes) {
        return -1;
    }
    
    // Check if we're in genesis mode (network height is 0)
    uint32_t blockchain_height = 0;
    int is_genesis = (mxd_get_blockchain_height(&blockchain_height) != 0 || blockchain_height == 0);
    
    // NOTE: Do NOT skip the local node in any mode. All nodes must have identical
    // rapid tables for deterministic proposer selection to agree across the network.
    (void)is_genesis;
    (void)local_node_id;
    
    // Check if node is already in table
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node->node_id) == 0) {
            return 0; // Node already in table
        }
    }
    
    // Check if table is full
    if (table->count >= table->capacity) {
        return -1;
    }
    
    table->nodes[table->count] = node;
    node->in_rapid_table = 1;
    node->rapid_table_position = table->count;
    table->count++;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

int mxd_remove_from_rapid_table(mxd_rapid_table_t *table, const char *node_id) {
    if (!table || !node_id || !table->nodes) {
        return -1;
    }
    
    size_t index = 0;
    int found = 0;
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node_id) == 0) {
            index = i;
            found = 1;
            break;
        }
    }
    
    if (!found) {
        return -1; // Node not in table
    }
    
    table->nodes[index]->in_rapid_table = 0;
    table->nodes[index]->rapid_table_position = 0;
    
    for (size_t i = index; i < table->count - 1; i++) {
        table->nodes[i] = table->nodes[i + 1];
        if (table->nodes[i]) {
            table->nodes[i]->rapid_table_position = i;
        }
    }
    
    table->nodes[table->count - 1] = NULL;
    table->count--;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

// Get node from Rapid Table by ID
mxd_node_stake_t *mxd_get_node_from_rapid_table(const mxd_rapid_table_t *table, const char *node_id) {
    if (!table || !node_id || !table->nodes) {
        return NULL;
    }

    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node_id) == 0) {
            return table->nodes[i];
        }
    }

    return NULL;
}

// Get node from Rapid Table by 20-byte address
mxd_node_stake_t *mxd_get_node_by_address(const mxd_rapid_table_t *table, const uint8_t address[32]) {
    if (!table || !address || !table->nodes) {
        return NULL;
    }

    // v6: addr32 (32-byte). node_address is now 32 bytes.
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && memcmp(table->nodes[i]->node_address, address, 32) == 0) {
            return table->nodes[i];
        }
    }

    return NULL;
}

void mxd_free_rapid_table(mxd_rapid_table_t *table) {
    if (!table) {
        return;
    }
    
    if (table->nodes) {
        free(table->nodes);
        table->nodes = NULL;
    }
    
    table->count = 0;
    table->capacity = 0;
}

// --- Sequential Signature Chaining ---

int mxd_compute_signing_order(const mxd_rapid_table_t *table,
                              const uint8_t proposer_id[32],
                              uint64_t block_height,
                              uint8_t signing_order[][32],
                              uint32_t *order_count) {
    if (!table || !proposer_id || !signing_order || !order_count) return -1;

    *order_count = 0;

    // Position 0: proposer (v6: addr32)
    memcpy(signing_order[0], proposer_id, 32);

    // Collect non-proposers in RST table order (v6: addr32)
    uint8_t tmp[64][32];
    uint32_t non_proposer_count = 0;
    for (size_t i = 0; i < table->count && non_proposer_count < 64; i++) {
        if (!table->nodes[i]) continue;
        if (memcmp(table->nodes[i]->node_address, proposer_id, 32) == 0) continue;
        memcpy(tmp[non_proposer_count], table->nodes[i]->node_address, 32);
        non_proposer_count++;
    }

    // Rotate by block_height so position 1 varies per block
    uint8_t (*others)[32] = signing_order + 1;
    if (non_proposer_count > 0) {
        uint32_t offset = (uint32_t)(block_height % non_proposer_count);
        for (uint32_t i = 0; i < non_proposer_count; i++) {
            memcpy(others[i], tmp[(i + offset) % non_proposer_count], 32);
        }
    }

    *order_count = 1 + non_proposer_count;
    return 0;
}

int mxd_get_my_signing_position(const mxd_rapid_table_t *table,
                                const uint8_t proposer_id[32],
                                const uint8_t my_address[32],
                                uint64_t block_height) {
    if (!table || !proposer_id || !my_address) return -1;

    // Position 0 is the proposer (v6: addr32)
    if (memcmp(my_address, proposer_id, 32) == 0) return 0;

    // Collect non-proposer indices in RST table order
    uint32_t indices[64];
    uint32_t count = 0;
    for (size_t i = 0; i < table->count && count < 64; i++) {
        if (!table->nodes[i]) continue;
        if (memcmp(table->nodes[i]->node_address, proposer_id, 32) == 0) continue;
        indices[count] = (uint32_t)i;
        count++;
    }

    if (count == 0) return -1;

    // Rotate by block_height so position 1 varies per block
    uint32_t offset = (uint32_t)(block_height % count);
    for (uint32_t pos = 0; pos < count; pos++) {
        uint32_t idx = indices[(pos + offset) % count];
        if (memcmp(table->nodes[idx]->node_address, my_address, 32) == 0)
            return (int)(pos + 1);
    }

    return -1;  // Not in table
}

void mxd_compute_chain_hash(const mxd_block_t *block,
                            uint32_t position,
                            uint8_t chain_hash[64]) {
    if (!block || !chain_hash) return;

    if (position == 0) {
        // chain_hash_0 = SHA-512(block_hash)
        mxd_sha512(block->block_hash, 64, chain_hash);
        return;
    }

    // For position N: chain_hash_N = SHA-512(prev_chain_hash || prev_signature_bytes)
    // We must compute chain hashes iteratively from position 0
    uint8_t prev_hash[64];
    mxd_sha512(block->block_hash, 64, prev_hash);  // chain_hash_0

    for (uint32_t i = 1; i <= position; i++) {
        if (i - 1 >= block->validation_count) {
            // Not enough signatures in chain yet - use what we have
            memcpy(chain_hash, prev_hash, 64);
            return;
        }
        const mxd_validator_signature_t *prev_sig = &block->validation_chain[i - 1];
        // SHA-512(prev_chain_hash[64] || prev_signature_bytes[sig_len])
        size_t input_len = 64 + prev_sig->signature_length;
        uint8_t *input = malloc(input_len);
        if (!input) {
            memcpy(chain_hash, prev_hash, 64);
            return;
        }
        memcpy(input, prev_hash, 64);
        memcpy(input + 64, prev_sig->signature, prev_sig->signature_length);

        uint8_t current_hash[64];
        mxd_sha512(input, input_len, current_hash);
        free(input);

        memcpy(prev_hash, current_hash, 64);
    }

    memcpy(chain_hash, prev_hash, 64);
}

// Initialize validation context for a block
int mxd_init_validation_context(mxd_validation_context_t *context, const mxd_block_t *block,
                               const mxd_rapid_table_t *table) {
    if (!context || !block || !table) {
        return -1;
    }
    
    // Initialize context
    memset(context, 0, sizeof(mxd_validation_context_t));
    context->height = block->height;
    memcpy(context->block_hash, block->block_hash, 64);
    memcpy(context->proposer_id, block->proposer_id, 32);   // v6: addr32
    context->status = MXD_VALIDATION_PENDING;
    context->signature_count = block->validation_count;
    
    // Calculate required signatures (2/3 supermajority for BFT safety)
    context->required_signatures = (table->count * 2 + 2) / 3;
    
    uint64_t current_time = mxd_now_ms();
    context->start_time = current_time;
    
    context->expiry_time = current_time + (5 * 60 * 1000);
    
    return 0;
}

int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[32],
                                        uint64_t timestamp, uint8_t algo_id, const uint8_t *signature,
                                        uint16_t signature_length, uint32_t chain_position) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    // Validate algo_id
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_ERROR("rsc", "Invalid algo_id %u in validator signature", algo_id);
        return -1;
    }
    
    // Validate signature length matches algorithm
    size_t expected_sig_len = mxd_sig_signature_len(algo_id);
    if (signature_length != expected_sig_len) {
        MXD_LOG_ERROR("rsc", "Signature length %u doesn't match algo_id %u (expected %zu)", 
                      signature_length, algo_id, expected_sig_len);
        return -1;
    }
    
    // Note: timestamp drift check is intentionally NOT done here. The
    // caller (mxd_verify_and_add_validation_signature) enforces drift for
    // live signatures, but catchup paths fetching historical chains from
    // peers must be able to add hours-old sigs to repair divergent local
    // validation_count views. Cryptographic signature verification below
    // is the only protection against forged sigs; the timestamp is bound
    // into the signed message so an attacker cannot rewrite it.

    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (memcmp(block->validation_chain[i].validator_id, validator_id, 32) == 0) {   // v6: addr32
            MXD_LOG_WARN("rsc", "Duplicate signature from validator for block height %u", block->height);
            return -1;
        }
    }
    
    // Verify sequential signing order: chain_position must match current validation_count
    if (chain_position != block->validation_count) {
        MXD_LOG_WARN("rsc", "Out-of-order signature: chain_position=%u but validation_count=%u (block %u)",
                     chain_position, block->validation_count, block->height);
        return -1;
    }

    // Verify the signer is the expected validator at this position in the signing order
    const mxd_rapid_table_t *order_table = mxd_get_rapid_table();
    if (order_table && order_table->count > 0) {
        int expected_pos = mxd_get_my_signing_position(order_table, block->proposer_id, validator_id, block->height);
        if (expected_pos < 0) {
            MXD_LOG_WARN("rsc", "Signer not in signing order for block %u", block->height);
            return -1;
        }
        if ((uint32_t)expected_pos != chain_position) {
            MXD_LOG_WARN("rsc", "Signer at wrong position: expected %d, got %u (block %u)",
                         expected_pos, chain_position, block->height);
            return -1;
        }
    }

    // Compute chain_hash for this position
    uint8_t chain_hash[64];
    mxd_compute_chain_hash(block, chain_position, chain_hash);

    // v7 canonical: MXD-CONS-1 (11) || block_hash(64) || chain_hash(64) || ts_be(8) = 147 bytes.
    // Must match the signer shape used by both the proposer (mxd_rsc.c:3793-3801)
    // and the chain follower (mxd_blockchain_sync.c:1411+) so that signatures
    // produced by other validators verify on ingest.
    uint8_t msg[MXD_DOMAIN_TAG_CONS_LEN + 64 + 64 + 8];
    size_t mo = 0;
    memcpy(msg + mo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); mo += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(msg + mo, block->block_hash, 64); mo += 64;
    memcpy(msg + mo, chain_hash, 64); mo += 64;
    uint64_t ts_be = mxd_htonll(timestamp);
    memcpy(msg + mo, &ts_be, 8); mo += 8;

    // Get validator's public key
    uint8_t pubbuf[4096];
    size_t publen = 0;
    if (mxd_get_validator_public_key(validator_id, pubbuf, sizeof(pubbuf), &publen) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to get validator public key for signature verification");
        return -1;
    }

    // Verify signature
    if (mxd_sig_verify(algo_id, signature, signature_length, msg, sizeof(msg), pubbuf) != 0) {
        MXD_LOG_ERROR("rsc", "Chain signature verification failed for validator at position %u", chain_position);
        return -1;
    }
    
    if (!block->validation_chain) {
        block->validation_capacity = 10;
        block->validation_chain = malloc(block->validation_capacity * sizeof(mxd_validator_signature_t));
        if (!block->validation_chain) {
            return -1;
        }
    } else if (block->validation_count >= block->validation_capacity) {
        size_t new_capacity = block->validation_capacity * 2;
        mxd_validator_signature_t *new_chain = realloc(block->validation_chain, 
                                                     new_capacity * sizeof(mxd_validator_signature_t));
        if (!new_chain) {
            return -1;
        }
        block->validation_chain = new_chain;
        block->validation_capacity = new_capacity;
    }
    
    mxd_validator_signature_t *sig = &block->validation_chain[block->validation_count];
    memcpy(sig->validator_id, validator_id, 32);   // v6: addr32
    sig->timestamp = timestamp;
    sig->algo_id = algo_id;
    sig->signature_length = signature_length;
    memcpy(sig->signature, signature, sig->signature_length);
    sig->chain_position = chain_position;
    
    block->validation_count++;

    mxd_store_signature(block->height, validator_id, signature, signature_length);

    // Update validator's metrics in the rapid table
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (table) {
        mxd_node_stake_t *validator_node = mxd_get_node_by_address(table, validator_id);
        if (validator_node) {
            // Response time = time from block creation to signature
            // Note: block->timestamp is in seconds, signature timestamp is in milliseconds
            uint64_t block_ts_ms = block->timestamp * 1000;
            uint64_t response_time = (timestamp > block_ts_ms) ?
                                     (timestamp - block_ts_ms) : 0;
            mxd_update_node_metrics(validator_node, response_time, timestamp);
            MXD_LOG_DEBUG("rsc", "Updated metrics for validator (response_time=%llu ms, count=%u)",
                         (unsigned long long)response_time, validator_node->metrics.response_count);
        }
    }

    return 0;
}

int mxd_verify_validation_chain_integrity(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return -1;
    }

    // Structural invariants
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (block->validation_chain[i].chain_position != i) {
            return -1; // Chain positions not sequential
        }
    }

    for (uint32_t i = 1; i < block->validation_count; i++) {
        if (block->validation_chain[i].timestamp < block->validation_chain[i-1].timestamp) {
            return -1; // Timestamps not monotonically increasing
        }
    }

    // Cryptographic verification of every signature in the chain.
    // Without this, a block delivered directly (bypassing the
    // signature-by-signature P2P ingest path that does call
    // mxd_add_validator_signature_to_block) would be stored with
    // forged signatures as long as the structural invariants held.
    // mxd_verify_validation_chain rebuilds the v7 canonical
    // (MXD-CONS-1 + block_hash + chain_hash + ts_be) per position
    // and verifies each against the validator's registered pubkey.
    if (mxd_verify_validation_chain(block) != 0) {
        return -1;
    }

    return 0;
}

// Check if block has reached validation quorum (2/3 supermajority of Rapid Table)
int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table) {
    if (!block || !table) {
        return -1;
    }

    // Calculate required signatures (2/3 supermajority for BFT safety)
    uint32_t required_signatures = (table->count * 2 + 2) / 3;

    // Check if block has enough signatures
    return (block->validation_count >= required_signatures) ? 1 : 0;
}

// Check if block has minimum signatures for relay (X=3)
int mxd_block_has_min_relay_signatures(const mxd_block_t *block) {
    if (!block) {
        return -1;
    }
    
    // Special handling for genesis block (height 0)
    // Genesis blocks use membership signatures instead of validation chain signatures
    if (block->height == 0) {
        // For genesis blocks, check membership quorum instead of validation signatures
        // Genesis blocks need at least 3 membership signatures to be valid
        return (block->rapid_membership_count >= 3) ? 1 : 0;
    }
    
    // Check if block has minimum required signatures for relay
    return (block->validation_count >= MXD_MIN_RELAY_SIGNATURES) ? 1 : 0;
}

int mxd_resolve_fork_by_validation(const mxd_block_t *block1, const mxd_block_t *block2, 
                                  const mxd_rapid_table_t *table) {
    if (!block1 || !block2 || !table) {
        return -1;
    }
    
    // Check if blocks are at the same height
    if (block1->height != block2->height) {
        return (block1->height > block2->height) ? 1 : 2;
    }
    
    if (block1->validation_count != block2->validation_count) {
        return (block1->validation_count > block2->validation_count) ? 1 : 2;
    }
    
    double score1 = mxd_calculate_validation_latency_score(block1, table);
    double score2 = mxd_calculate_validation_latency_score(block2, table);
    
    if (fabs(score1 - score2) > 0.0001) { // Avoid floating point equality comparison
        return (score1 > score2) ? 1 : 2;
    }
    
    int cmp = memcmp(block1->block_hash, block2->block_hash, 64);
    return (cmp < 0) ? 1 : 2;
}

// Calculate cumulative latency score for fork resolution
double mxd_calculate_validation_latency_score(const mxd_block_t *block, const mxd_rapid_table_t *table) {
    if (!block || !block->validation_chain || block->validation_count == 0 || !table) {
        return 0.0;
    }
    
    // Calculate cumulative latency score using formula: Σ (1 / latency_i)
    double score = 0.0;
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        const uint8_t *validator_id = block->validation_chain[i].validator_id;
        
        for (size_t j = 0; j < table->count; j++) {
            if (table->nodes[j] && memcmp(table->nodes[j]->node_address, validator_id, MXD_ADDR32_LEN) == 0) {   // v6: addr32
                uint64_t latency = table->nodes[j]->metrics.avg_response_time;
                if (latency < 1) latency = 1; // Avoid division by zero
                
                score += 1.0 / (double)latency;
                break;
            }
        }
    }
    
    return score;
}

// Check if validator has signed conflicting blocks (for blacklisting)
int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[32], uint32_t height,
                                           const uint8_t block_hash[64]) {
    if (!validator_id || !block_hash) {
        return -1;
    }
    
    mxd_validator_signature_t *signatures = NULL;
    uint32_t *heights = NULL;
    size_t signature_count = 0;
    
    if (mxd_get_signatures_by_validator(validator_id, &signatures, &heights, &signature_count) != 0) {
        return -1;
    }
    
    if (!signatures || !heights || signature_count == 0) {
        return 0;
    }
    
    int conflict_found = 0;
    for (size_t i = 0; i < signature_count; i++) {
        if (heights[i] == height) {
            mxd_block_t block;
            memset(&block, 0, sizeof(mxd_block_t));
            
            if (mxd_retrieve_block_by_height(height, &block) == 0) {
                if (memcmp(block.block_hash, block_hash, 64) != 0) {
                    conflict_found = 1;
                    MXD_LOG_WARN("rsc", "Double-signing detected: validator signed conflicting blocks at height %u", height);
                    mxd_metrics_increment("validator_double_sign_detected_total");
                    
                    uint32_t blacklist_duration = get_blacklist_duration();
                    if (mxd_blacklist_validator(validator_id, blacklist_duration) == 0) {
                        MXD_LOG_INFO("rsc", "Validator automatically blacklisted for %u blocks due to double-signing", blacklist_duration);
                    }
                }
                
                if (block.validation_chain) {
                    free(block.validation_chain);
                }
            }
            
            if (conflict_found) {
                break;
            }
        }
    }
    
    free(signatures);
    free(heights);
    
    return conflict_found;
}

int mxd_blacklist_validator(const uint8_t validator_id[32], uint32_t duration) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    uint32_t expiry_height = current_height + (duration > 0 ? duration : get_blacklist_duration());

    uint8_t key[10 + MXD_ADDR32_LEN];   // v6: addr32 (was [10 + 20])
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, MXD_ADDR32_LEN);

    char value[10];
    snprintf(value, sizeof(value), "%u", expiry_height);
    
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("rsc", "Blockchain DB not initialized");
        return -1;
    }
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)key, sizeof(key), 
               value, strlen(value), &err);
    
    if (err) {
        MXD_LOG_ERROR("rsc", "Failed to blacklist validator: %s", err);
        free(err);
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Validator blacklisted until height %u (duration: %u blocks)", expiry_height, duration);
    mxd_metrics_increment("validator_blacklisted_total");
    return 0;
}

// Check if validator is blacklisted
int mxd_is_validator_blacklisted(const uint8_t validator_id[32]) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    uint8_t key[10 + MXD_ADDR32_LEN];   // v6: addr32 (was [10 + 20])
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, MXD_ADDR32_LEN);

    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("rsc", "Blockchain DB not initialized");
        return -1;
    }

    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, sizeof(key), &value_len, &err);
    
    if (err) {
        MXD_LOG_ERROR("rsc", "Failed to check blacklist status: %s", err);
        free(err);
        return -1;
    }
    
    if (value && value_len > 0) {
        uint32_t expiry_height = atoi(value);
        free(value);
        
        if (expiry_height > current_height) {
            return 1; // Validator is blacklisted
        }
    }
    
    return 0; // Not blacklisted
}

int mxd_get_next_validator(const mxd_block_t *block, const mxd_rapid_table_t *table,
                          uint8_t next_validator_id[32]) {
    if (!block || !table || !next_validator_id) {
        return -1;
    }
    
    if (block->validation_count == 0) {
        if (table->count == 0) {
            return -1; // No validators in Rapid Table
        }

        memcpy(next_validator_id, table->nodes[0]->node_address, 32);   // v6: addr32
        return 0;
    }
    
    uint32_t last_position = 0;
    int found = 0;

    // v6: addr32 (32-byte node_address and validator_id)
    for (size_t i = 0; i < table->count; i++) {
        if (memcmp(table->nodes[i]->node_address,
                  block->validation_chain[block->validation_count - 1].validator_id, 32) == 0) {
            last_position = i;
            found = 1;
            break;
        }
    }

    if (!found) {
        return -1; // Last validator not in Rapid Table
    }

    uint32_t next_position = (last_position + 1) % table->count;

    // Check if we've gone full circle
    if (next_position == 0 && block->validation_count > 0) {
        return -1; // All validators have signed
    }

    memcpy(next_validator_id, table->nodes[next_position]->node_address, 32);
    
    return 0;
}

int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context, 
                                const mxd_rapid_table_t *table) {
    if (!block || !context || !table) {
        return -1;
    }

    // If a new signature arrived, clear the waiting state (will be set again for next validator)
    if (block->validation_count > context->signature_count) {
        context->waiting_since = 0;
    }

    // Check if validation is already complete
    if (context->status == MXD_VALIDATION_COMPLETE) {
        return 0;
    }

    // Check if validation has expired
    uint64_t current_time = mxd_now_ms();

    if (current_time > context->expiry_time) {
        context->status = MXD_VALIDATION_EXPIRED;
        return -1;
    }

    // Update signature count
    context->signature_count = block->validation_count;

    // v5+: verify next_proposer matches expected value
    if (block->version >= 5 && table->count > 0) {
        uint32_t expected_idx = mxd_compute_proposer_index(
            block->prev_block_hash, block->height + 1, table->count);
        if (table->nodes[expected_idx] == NULL) {
            MXD_LOG_ERROR("rsc", "Block %u: table->nodes[%u] is NULL during next_proposer validation",
                          block->height, expected_idx);
            context->status = MXD_VALIDATION_REJECTED;
            return -1;
        }
        if (memcmp(block->next_proposer, table->nodes[expected_idx]->node_address, 32) != 0) {   // v6: addr32 — table widening in H-2
            MXD_LOG_ERROR("rsc", "Block %u has invalid next_proposer (expected table[%u])",
                          block->height, expected_idx);
            context->status = MXD_VALIDATION_REJECTED;
            return -1;
        }
    }

    // Check if block has reached quorum
    if (mxd_block_has_validation_quorum(block, table)) {
        context->status = MXD_VALIDATION_COMPLETE;
        set_finalized_height(block->height);

        // Distribute tips to validators in the validation chain
        if (block->validation_count > 0) {
            mxd_node_stake_t *validators = malloc(block->validation_count * sizeof(mxd_node_stake_t));
            if (validators) {
                // Initialize validators from validation chain
                for (uint32_t i = 0; i < block->validation_count; i++) {
                    memset(&validators[i], 0, sizeof(mxd_node_stake_t));
                    memcpy(validators[i].node_address, block->validation_chain[i].validator_id, 32);   // v6: addr32
                    validators[i].active = 1;
                }
                
                // Calculate tip distribution using 50% pattern
                mxd_amount_t total_tip = mxd_calculate_total_tip_from_frozen_set(block);
                
                if (total_tip > 0) {
                    mxd_distribute_tips(validators, block->validation_count, total_tip);
                    
                    mxd_transaction_t tip_tx;
                    if (mxd_create_transaction(&tip_tx) == 0) {
                        tip_tx.is_coinbase = 1;
                        
                        // v6 (H-4): node_address is now 32-byte addr32 — pass directly
                        // to mxd_add_tx_output, no pad-and-copy hack.
                        for (uint32_t i = 0; i < block->validation_count; i++) {
                            if (validators[i].metrics.tip_share > 0) {
                                if (mxd_add_tx_output(&tip_tx, validators[i].node_address,
                                                     validators[i].metrics.tip_share) != 0) {
                                    break;
                                }
                            }
                        }
                        
                        // Calculate transaction hash
                        mxd_calculate_tx_hash(&tip_tx, tip_tx.tx_hash);

                        // Guard: only create tip UTXOs if they don't already exist
                        // (prevents double-creation when validation chain is reprocessed)
                        mxd_utxo_t check_utxo;
                        if (mxd_get_utxo(tip_tx.tx_hash, 0, &check_utxo) != 0) {
                            mxd_create_utxos_from_tx(&tip_tx, tip_tx.tx_hash);
                        } else {
                            MXD_LOG_DEBUG("rsc", "Tip UTXOs already exist for block %u, skipping", block->height);
                        }

                        // Free transaction resources
                        mxd_free_transaction(&tip_tx);
                    }
                }
                
                free(validators);
            }
        }
        
        // Apply block transactions to UTXO state BEFORE storing.
        // Without this, the proposer's UTXO database becomes stale and
        // allows accepting transactions that reference already-spent UTXOs,
        // causing supply inflation via double-spend.
        {
            int64_t supply_delta = 0;
            mxd_apply_block_transactions(block, &supply_delta);
            // Compute total_supply deterministically from previous block + delta
            if (block->height > 0) {
                mxd_block_t prev;
                memset(&prev, 0, sizeof(prev));
                if (mxd_retrieve_block_by_height(block->height - 1, &prev) == 0) {
                    block->total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                    mxd_free_block(&prev);
                }
            }
        }

        if (mxd_store_block(block) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to store relayed block at height %u", block->height);
        } else if (block->total_supply > 0) {
            mxd_propagate_supply_forward(block->height, block->total_supply);
        }

        // Check for validator eviction after storing block
        mxd_check_proposer_miss((mxd_rapid_table_t *)table, block);

        // Update chain-derived deterministic scoring
        if (block->version >= 4 && block->validator_scores) {
            mxd_load_scores_from_block((mxd_rapid_table_t *)table, block);
        } else {
            mxd_accumulate_block_stats((mxd_rapid_table_t *)table, block);
        }
        mxd_compute_chain_scores((mxd_rapid_table_t *)table);
        mxd_sort_rapid_table_by_score((mxd_rapid_table_t *)table);

        return 0;
    }

    if (mxd_verify_validation_chain_integrity(block) != 0) {
        context->status = MXD_VALIDATION_REJECTED;
        return -1;
    }
    
    uint8_t next_validator_id[MXD_ADDR32_LEN];   // v6: addr32 (was 20)
    if (mxd_get_next_validator(block, table, next_validator_id) != 0) {
        if (context->signature_count >= context->required_signatures) {
            context->status = MXD_VALIDATION_COMPLETE;
            set_finalized_height(block->height);

            {
                int64_t supply_delta = 0;
                mxd_apply_block_transactions(block, &supply_delta);
                if (block->height > 0) {
                    mxd_block_t prev;
                    memset(&prev, 0, sizeof(prev));
                    if (mxd_retrieve_block_by_height(block->height - 1, &prev) == 0) {
                        block->total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                        mxd_free_block(&prev);
                    }
                }
            }
            if (mxd_store_block(block) != 0) {
                MXD_LOG_ERROR("rsc", "Failed to store validated block at height %u", block->height);
            } else if (block->total_supply > 0) {
                mxd_propagate_supply_forward(block->height, block->total_supply);
            }

            // Check for validator eviction after storing block
            mxd_check_proposer_miss((mxd_rapid_table_t *)table, block);

            // Update chain-derived deterministic scoring
            if (block->version >= 4 && block->validator_scores) {
                mxd_load_scores_from_block((mxd_rapid_table_t *)table, block);
            } else {
                mxd_accumulate_block_stats((mxd_rapid_table_t *)table, block);
            }
            mxd_compute_chain_scores((mxd_rapid_table_t *)table);
            mxd_sort_rapid_table_by_score((mxd_rapid_table_t *)table);

            return 0;
        } else {
            context->status = MXD_VALIDATION_REJECTED;
            return -1;
        }
    }

    // Update status to in progress
    context->status = MXD_VALIDATION_IN_PROGRESS;

    // Track which validator we're waiting for (for skip timeout) — v6: addr32
    memcpy(context->waiting_for_validator, next_validator_id, 32);
    context->waiting_since = mxd_now_ms();

    return 0;
}
static struct {
    uint8_t id[32];   // v6: addr32 validator identity
    uint8_t algo_id;
    uint8_t pub[4096];
    size_t len;
} mxd_pubkey_registry[1024];

static size_t mxd_pubkey_registry_count;
static pthread_mutex_t mxd_pubkey_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

int mxd_test_register_validator_pubkey(const uint8_t *validator_id, const uint8_t *pub, size_t pub_len) {
    uint8_t algo_id = MXD_SIGALG_ED25519;
    if (pub_len == 2592) {
        algo_id = MXD_SIGALG_DILITHIUM5;
    } else if (pub_len == 32) {
        algo_id = MXD_SIGALG_ED25519;
    }
    
    if (!validator_id || !pub || pub_len == 0 || pub_len > sizeof(mxd_pubkey_registry[0].pub)) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    if (mxd_pubkey_registry_count >= 1024) {
        pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
        return -1;
    }
    
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].id, validator_id, 32);   // v6: addr32
    mxd_pubkey_registry[mxd_pubkey_registry_count].algo_id = algo_id;
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].pub, pub, pub_len);
    mxd_pubkey_registry[mxd_pubkey_registry_count].len = pub_len;
    mxd_pubkey_registry_count++;
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    
    if (mxd_store_validator_metadata(validator_id, algo_id, pub, pub_len) != 0) {
        MXD_LOG_WARN("rsc", "Failed to persist validator metadata to RocksDB");
    }
    
    return 0;
}

void mxd_test_clear_validator_pubkeys(void) {
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    mxd_pubkey_registry_count = 0;
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
}

int mxd_get_validator_public_key(const uint8_t *validator_id, uint8_t *out_key, size_t out_capacity, size_t *out_len) {
    if (!validator_id || !out_key || !out_len) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    for (size_t i = 0; i < mxd_pubkey_registry_count; i++) {
        if (memcmp(mxd_pubkey_registry[i].id, validator_id, 32) == 0) {   // v6: addr32
            if (out_capacity < mxd_pubkey_registry[i].len) {
                pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
                return -1;
            }
            memcpy(out_key, mxd_pubkey_registry[i].pub, mxd_pubkey_registry[i].len);
            *out_len = mxd_pubkey_registry[i].len;
            pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    return -1;
}

int mxd_get_validator_algo_id(const uint8_t *validator_id, uint8_t *out_algo_id) {
    if (!validator_id || !out_algo_id) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    for (size_t i = 0; i < mxd_pubkey_registry_count; i++) {
        if (memcmp(mxd_pubkey_registry[i].id, validator_id, 32) == 0) {   // v6: addr32
            *out_algo_id = mxd_pubkey_registry[i].algo_id;
            pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    return -1;
}

int mxd_should_add_to_rapid_table(const mxd_node_stake_t *node, mxd_amount_t total_supply, int is_genesis) {
    if (!node) {
        return 0;
    }
    
    if (is_genesis || total_supply == 0) {
        return 1;
    }
    
    // Check if stake is at least 0.10% of total supply
    if (node->stake_amount < total_supply / 1000) {
        return 0;
    }
    
    if (!node->active) {
        return 0;
    }
    
    if (node->metrics.response_count < MXD_MIN_RESPONSE_COUNT) {
        return 0;
    }
    
    if (node->metrics.avg_response_time >= MXD_MAX_RESPONSE_TIME) {
        return 0;
    }
    
    return 1;
}

// MINOR FIX: Document time unit consistency - MXD_NODE_EXPIRY_TIME is in seconds (1 week = 604800 seconds)
#define MXD_NODE_EXPIRY_TIME 604800

int mxd_apply_membership_deltas(mxd_rapid_table_t *table, const mxd_block_t *block, 
                                const char *local_node_id) {
    if (!table || !block) {
        return -1;
    }
    
    if (!block->rapid_membership_entries || block->rapid_membership_count == 0) {
        return 0; // No deltas to apply
    }
    
    for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
        const mxd_rapid_membership_entry_t *entry = &block->rapid_membership_entries[i];
        
        MXD_LOG_INFO("rsc", "Processing membership entry %u: timestamp=%lu, algo_id=%u, pk_len=%u, sig_len=%u",
                     i, entry->timestamp, entry->algo_id, entry->public_key_length, entry->signature_length);
        
        // NOTE: Do NOT skip the local node. All nodes must have identical rapid tables
        // for deterministic proposer selection (height % count) to agree across the network.
        // Previously this skipped local_node_id, causing each node to have a different
        // 9-of-10 table, breaking round-robin consensus.
        (void)local_node_id;
        
        // Check if node already exists in table
        int found = 0;
        for (size_t j = 0; j < table->count; j++) {
            // Compare node_address fields directly (both are 32-byte addr32 binary, v6)
            if (table->nodes[j] && memcmp(table->nodes[j]->node_address, entry->node_address, 32) == 0) {   // v6: addr32
                // Node already exists - don't update last_update from blockchain
                // timestamp as it would make the node appear inactive. The last_update
                // is properly updated when validators sign blocks.
                found = 1;
                break;
            }
        }

        if (!found && table->count < table->capacity) {
            if (!table->nodes[table->count]) {
                table->nodes[table->count] = malloc(sizeof(mxd_node_stake_t));
                if (!table->nodes[table->count]) {
                    continue;
                }
            }

            // Initialize new node
            memset(table->nodes[table->count], 0, sizeof(mxd_node_stake_t));
            // Convert binary address to hex string for node_id (node_id is char[64], needs 64 hex chars + null per v6 addr32)
            for (int j = 0; j < 32; j++) {
                snprintf(table->nodes[table->count]->node_id + (j * 2), 3, "%02x", entry->node_address[j]);
            }
            table->nodes[table->count]->node_id[64] = '\0';
            // Also copy the binary address for direct comparisons (v6: addr32)
            memcpy(table->nodes[table->count]->node_address, entry->node_address, 32);
            // Get stake amount from UTXO balance
            table->nodes[table->count]->stake_amount = mxd_get_balance(entry->node_address);
            table->nodes[table->count]->active = 1;
            // Initialize metrics with current time - this makes new/restored nodes
            // appear active. The last_update will be updated when validators sign blocks.
            mxd_init_node_metrics(&table->nodes[table->count]->metrics);
            // Use current time for last_update so nodes appear active after restart.
            // Historical metrics are not stored on-chain, so using entry->timestamp
            // would make nodes appear inactive after 5 minutes of startup.
            // table->nodes[table->count]->metrics.last_update = entry->timestamp;

            MXD_LOG_INFO("rsc", "Added node to rapid table: last_update=%lu (current time)",
                         table->nodes[table->count]->metrics.last_update);

            table->count++;
        }

        // Register validator public key from membership entry (needed for signature verification)
        if (entry->public_key_length > 0) {
            mxd_test_register_validator_pubkey(entry->node_address, entry->public_key, entry->public_key_length);
        }
    }
    
    return 0;
}

int mxd_remove_expired_nodes(mxd_rapid_table_t *table, uint64_t current_time) {
    if (!table) {
        return -1;
    }
    
    size_t initial_count = table->count;
    size_t write_idx = 0;
    size_t expired_count = 0;
    for (size_t read_idx = 0; read_idx < table->count; read_idx++) {
        if (table->nodes[read_idx]) {
            uint64_t last_update = table->nodes[read_idx]->metrics.last_update;
            
            // Check if node has expired (1 week of inactivity)
            // Note: Both current_time and last_update should be in milliseconds
            MXD_LOG_INFO("rsc", "Checking node expiry: last_update=%lu, current_time=%lu, diff=%lu, expiry_threshold=%lu",
                         last_update, current_time, 
                         (current_time > last_update) ? (current_time - last_update) : 0,
                         MXD_NODE_EXPIRY_TIME * 1000ULL);
            if (current_time > last_update && (current_time - last_update) > (MXD_NODE_EXPIRY_TIME * 1000ULL)) {
                MXD_LOG_INFO("rsc", "Expiring node: last_update=%lu, current_time=%lu, diff=%lu ms, expiry=%lu ms",
                             last_update, current_time, current_time - last_update, MXD_NODE_EXPIRY_TIME * 1000ULL);
                free(table->nodes[read_idx]);
                table->nodes[read_idx] = NULL;
                expired_count++;
            } else {
                if (write_idx != read_idx) {
                    table->nodes[write_idx] = table->nodes[read_idx];
                    table->nodes[read_idx] = NULL;
                }
                write_idx++;
            }
        }
    }
    
    table->count = write_idx;
    MXD_LOG_INFO("rsc", "Remove expired nodes: initial=%zu, expired=%zu, remaining=%zu",
                 initial_count, expired_count, table->count);
    return 0;
}

int mxd_check_proposer_miss(mxd_rapid_table_t *table, const mxd_block_t *block) {
    if (!table || !block || table->count == 0) return 0;

    // Track miss statistics for scoring, but DO NOT evict.
    //
    // Eviction is disabled because it is a local decision: each node independently
    // decides who "missed" based on its own view of the chain. With fallback
    // proposers, different nodes can receive blocks from different proposers for
    // the same height, causing them to track different miss counts. After the
    // eviction threshold, nodes evict different validators, their table sizes
    // diverge, and height % count produces different proposer indices — permanent
    // irreversible fork.
    //
    // The fallback proposer mechanism (MXD_MAX_FALLBACK_RETRIES) already handles
    // missed slots gracefully. Eviction should only be re-enabled as a consensus
    // decision (embedded in blocks and voted on by quorum).

    uint32_t expected_index = block->height % table->count;
    if (expected_index >= table->count || !table->nodes[expected_index]) return 0;

    mxd_node_stake_t *expected = table->nodes[expected_index];

    if (memcmp(expected->node_address, block->proposer_id, 32) == 0) {   // v6: addr32
        // Expected proposer produced the block — reset their counter
        expected->consecutive_misses = 0;
    } else {
        // Mismatch: expected proposer didn't produce this block (timeout/fallback)
        expected->consecutive_misses++;
    }

    return 0;  // Never evict
}

void mxd_accumulate_block_stats(mxd_rapid_table_t *table, const mxd_block_t *block) {
    if (!table || !block) return;

    // Increment blocks_since_joined for all current table members
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i]) {
            table->nodes[i]->blocks_since_joined++;
        }
    }

    // Credit the proposer
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && memcmp(table->nodes[i]->node_address, block->proposer_id, 32) == 0) {   // v6: addr32
            table->nodes[i]->blocks_proposed++;
            break;
        }
    }

    // Credit signers and accumulate latency from validation chain
    if (block->validation_chain && block->validation_count > 0) {
        for (uint32_t v = 0; v < block->validation_count; v++) {
            const mxd_validator_signature_t *sig = &block->validation_chain[v];
            for (size_t i = 0; i < table->count; i++) {
                if (table->nodes[i] && memcmp(table->nodes[i]->node_address, sig->validator_id, MXD_ADDR32_LEN) == 0) {   // v6: addr32
                    table->nodes[i]->blocks_signed++;
                    // Latency: sig->timestamp is NTP ms, block->timestamp is seconds
                    if (sig->timestamp > block->timestamp * 1000) {
                        table->nodes[i]->total_latency_ms += (sig->timestamp - block->timestamp * 1000);
                    } else if (sig->timestamp > block->timestamp) {
                        // block->timestamp might already be in ms for newer blocks
                        table->nodes[i]->total_latency_ms += (sig->timestamp - block->timestamp);
                    }
                    break;
                }
            }
        }
    }
}

void mxd_compute_chain_scores(mxd_rapid_table_t *table) {
    if (!table || table->count == 0) return;

    // Check if we're in v4+ mode — if so, stake comes from on-chain data,
    // skip the UTXO refresh to maintain determinism
    mxd_network_type_t network = mxd_get_network_type();
    uint32_t blockchain_height = 0;
    mxd_get_blockchain_height(&blockchain_height);
    uint32_t current_version = mxd_get_required_protocol_version(
        blockchain_height > 0 ? blockchain_height - 1 : 0, network);
    int is_v4 = (current_version >= 4);

    // Get total stake from UTXO state (or sum on-chain stakes for v4+)
    mxd_amount_t total_stake = 0;
    if (is_v4) {
        // For v4+, total_stake = sum of all validator stake_amounts (already loaded from block)
        for (size_t i = 0; i < table->count; i++) {
            if (table->nodes[i]) {
                total_stake += table->nodes[i]->stake_amount;
            }
        }
        if (total_stake == 0) total_stake = 1;
    } else {
        size_t tc, pc;
        if (mxd_get_utxo_stats(&tc, &pc, &total_stake) != 0 || total_stake == 0) {
            total_stake = 1; // Prevent division by zero
        }

        // Pre-v4: Refresh each validator's stake from current UTXO balance
        for (size_t i = 0; i < table->count; i++) {
            if (!table->nodes[i]) continue;
            table->nodes[i]->stake_amount = mxd_get_balance(table->nodes[i]->node_address);
        }
    }

    for (size_t i = 0; i < table->count; i++) {
        if (!table->nodes[i]) continue;
        mxd_node_stake_t *n = table->nodes[i];

        uint64_t bsj = n->blocks_since_joined > 0 ? n->blocks_since_joined : 1;

        // Stake score: (stake * 10000) / total_stake
        // Avoid overflow: if stake_amount > UINT64_MAX/10000, divide first
        uint64_t stake_score;
        if (n->stake_amount > UINT64_MAX / 10000ULL) {
            stake_score = (n->stake_amount / total_stake) * 10000ULL;
        } else {
            stake_score = (n->stake_amount * 10000ULL) / total_stake;
        }
        if (stake_score > 10000) stake_score = 10000;

        // Proposal success: (blocks_proposed * 10000) / blocks_since_joined
        uint64_t proposal_score;
        if ((uint64_t)n->blocks_proposed > UINT64_MAX / 10000ULL) {
            proposal_score = ((uint64_t)n->blocks_proposed / bsj) * 10000ULL;
        } else {
            proposal_score = ((uint64_t)n->blocks_proposed * 10000ULL) / bsj;
        }
        if (proposal_score > 10000) proposal_score = 10000;

        // Validation participation: (blocks_signed * 10000) / blocks_since_joined
        uint64_t participation_score;
        if ((uint64_t)n->blocks_signed > UINT64_MAX / 10000ULL) {
            participation_score = ((uint64_t)n->blocks_signed / bsj) * 10000ULL;
        } else {
            participation_score = ((uint64_t)n->blocks_signed * 10000ULL) / bsj;
        }
        if (participation_score > 10000) participation_score = 10000;

        // Latency score: 10000 - min(avg_latency_ms, 10000)
        uint64_t avg_latency = n->blocks_signed > 0 ? n->total_latency_ms / n->blocks_signed : 10000;
        uint64_t latency_score = (avg_latency >= 10000) ? 0 : (10000 - avg_latency);

        // Weighted composite: (30*stake + 25*proposal + 25*participation + 20*latency) / 100
        n->chain_score = (stake_score * 30 + proposal_score * 25 +
                          participation_score * 25 + latency_score * 20) / 100;

        // Also update the rank field for display purposes
        n->rank = (uint32_t)n->chain_score;
    }
}

static int compare_chain_score(const void *a, const void *b) {
    const mxd_node_stake_t *na = *(const mxd_node_stake_t * const *)a;
    const mxd_node_stake_t *nb = *(const mxd_node_stake_t * const *)b;
    // Higher score first
    if (na->chain_score != nb->chain_score) {
        return (na->chain_score > nb->chain_score) ? -1 : 1;
    }
    // Tiebreaker: address lexicographic (lower address first)
    return memcmp(na->node_address, nb->node_address, 32);   // v6: addr32
}

void mxd_sort_rapid_table_by_score(mxd_rapid_table_t *table) {
    if (!table || table->count < 2) return;
    qsort(table->nodes, table->count, sizeof(mxd_node_stake_t *), compare_chain_score);
    // Update positional fields
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i]) {
            table->nodes[i]->rapid_table_position = (uint32_t)(i + 1);
            table->nodes[i]->in_rapid_table = 1;
        }
    }
}

// Compare validator score entries by address (for deterministic sorting)
static int compare_score_entry_by_address(const void *a, const void *b) {
    const mxd_validator_score_entry_t *ea = (const mxd_validator_score_entry_t *)a;
    const mxd_validator_score_entry_t *eb = (const mxd_validator_score_entry_t *)b;
    return memcmp(ea->validator_address, eb->validator_address, 32);   // v6: addr32
}

// Compute validator score entries for a new block from the previous block's data + deltas.
// prev_block: the block at height H-1 (scores reflect state after H-2)
// table: current rapid table (for membership, used to get current validator set)
// out_scores: receives allocated array of score entries for the new block
// out_count: receives number of entries
// Returns 0 on success, -1 on error.
int mxd_compute_block_validator_scores(const mxd_block_t *prev_block,
                                        const mxd_rapid_table_t *table,
                                        mxd_validator_score_entry_t **out_scores,
                                        uint32_t *out_count) {
    if (!prev_block || !table || !out_scores || !out_count) {
        return -1;
    }

    // Start from prev_block's validator_scores (or empty if pre-v4/genesis)
    uint32_t base_count = 0;
    mxd_validator_score_entry_t *base = NULL;
    if (prev_block->version >= 4 && prev_block->validator_scores_count > 0 && prev_block->validator_scores) {
        base_count = prev_block->validator_scores_count;
        base = prev_block->validator_scores;
    }

    // Count new validators from prev_block's membership entries (not already in base)
    // v6: 32-byte addr32 compare
    uint32_t new_count = 0;
    if (prev_block->rapid_membership_entries && prev_block->rapid_membership_count > 0) {
        for (uint32_t m = 0; m < prev_block->rapid_membership_count; m++) {
            int found = 0;
            for (uint32_t j = 0; j < base_count; j++) {
                if (memcmp(base[j].validator_address, prev_block->rapid_membership_entries[m].node_address, 32) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) new_count++;
        }
    }

    uint32_t total = base_count + new_count;
    if (total == 0) {
        *out_scores = NULL;
        *out_count = 0;
        return 0;
    }

    mxd_validator_score_entry_t *scores = calloc(total, sizeof(mxd_validator_score_entry_t));
    if (!scores) return -1;

    // Copy base entries
    if (base_count > 0) {
        memcpy(scores, base, base_count * sizeof(mxd_validator_score_entry_t));
    }

    // Add new validators from prev_block's membership entries (initialized to zeros)
    // v6: 32-byte addr32
    uint32_t idx = base_count;
    if (prev_block->rapid_membership_entries && prev_block->rapid_membership_count > 0) {
        for (uint32_t m = 0; m < prev_block->rapid_membership_count; m++) {
            int found = 0;
            for (uint32_t j = 0; j < base_count; j++) {
                if (memcmp(base[j].validator_address, prev_block->rapid_membership_entries[m].node_address, 32) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found && idx < total) {
                memset(&scores[idx], 0, sizeof(mxd_validator_score_entry_t));
                memcpy(scores[idx].validator_address,
                       prev_block->rapid_membership_entries[m].node_address, 32);
                idx++;
            }
        }
    }

    // Apply deltas from prev_block (H-1):
    // 1. All validators: blocks_since_joined++
    for (uint32_t i = 0; i < total; i++) {
        scores[i].blocks_since_joined++;
    }

    // 2. prev_block's proposer: blocks_proposed++ (v6: 32-byte addr32 compare)
    for (uint32_t i = 0; i < total; i++) {
        if (memcmp(scores[i].validator_address, prev_block->proposer_id, 32) == 0) {
            scores[i].blocks_proposed++;
            break;
        }
    }

    // 3. Each signer in prev_block's validation_chain: blocks_signed++, total_latency_ms += latency
    if (prev_block->validation_chain && prev_block->validation_count > 0) {
        for (uint32_t v = 0; v < prev_block->validation_count; v++) {
            const mxd_validator_signature_t *sig = &prev_block->validation_chain[v];
            for (uint32_t i = 0; i < total; i++) {
                if (memcmp(scores[i].validator_address, sig->validator_id, 32) == 0) {   // v6: addr32
                    scores[i].blocks_signed++;
                    // Latency: sig->timestamp is NTP ms, prev_block->timestamp is seconds
                    if (sig->timestamp > prev_block->timestamp * 1000) {
                        scores[i].total_latency_ms += (sig->timestamp - prev_block->timestamp * 1000);
                    } else if (sig->timestamp > prev_block->timestamp) {
                        scores[i].total_latency_ms += (sig->timestamp - prev_block->timestamp);
                    }
                    break;
                }
            }
        }
    }

    // 4. Snapshot each validator's stake_amount from current UTXO balance
    for (uint32_t i = 0; i < total; i++) {
        scores[i].stake_amount = mxd_get_balance(scores[i].validator_address);
    }

    // 5. Sort entries by address for deterministic serialization
    qsort(scores, total, sizeof(mxd_validator_score_entry_t), compare_score_entry_by_address);

    *out_scores = scores;
    *out_count = total;
    return 0;
}

// Verify that a received block's validator scores match expected values
// computed from the previous block. Called during validation.
int mxd_verify_block_validator_scores(const mxd_block_t *block) {
    if (!block || block->version < 4) {
        return 0; // Nothing to verify for pre-v4 blocks
    }

    if (block->height == 0) {
        // Genesis block: all entries should be zero-initialized for genesis validators
        // We trust the scores root hash verification already done in mxd_validate_block
        return 0;
    }

    // Retrieve previous block
    mxd_block_t prev_block;
    memset(&prev_block, 0, sizeof(prev_block));
    if (mxd_retrieve_block_by_height(block->height - 1, &prev_block) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to retrieve previous block for score verification at height %u", block->height);
        return -1;
    }

    // Compute expected scores
    // Note: we need a temporary table for the computation, but we only use it for
    // membership tracking. The actual score computation only needs the prev_block data.
    mxd_validator_score_entry_t *expected_scores = NULL;
    uint32_t expected_count = 0;

    // Build expected scores from prev_block data
    // Start from prev_block's scores
    uint32_t base_count = 0;
    mxd_validator_score_entry_t *base = NULL;
    if (prev_block.version >= 4 && prev_block.validator_scores_count > 0 && prev_block.validator_scores) {
        base_count = prev_block.validator_scores_count;
        base = prev_block.validator_scores;
    }

    // Count new validators from prev_block's membership (v6: 32-byte addr32)
    uint32_t new_count = 0;
    if (prev_block.rapid_membership_entries && prev_block.rapid_membership_count > 0) {
        for (uint32_t m = 0; m < prev_block.rapid_membership_count; m++) {
            int found = 0;
            for (uint32_t j = 0; j < base_count; j++) {
                if (memcmp(base[j].validator_address, prev_block.rapid_membership_entries[m].node_address, 32) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) new_count++;
        }
    }

    expected_count = base_count + new_count;
    if (expected_count != block->validator_scores_count) {
        MXD_LOG_ERROR("rsc", "Score count mismatch at height %u: expected %u, got %u",
                     block->height, expected_count, block->validator_scores_count);
        mxd_free_block(&prev_block);
        return -1;
    }

    if (expected_count == 0) {
        mxd_free_block(&prev_block);
        return 0;
    }

    expected_scores = calloc(expected_count, sizeof(mxd_validator_score_entry_t));
    if (!expected_scores) {
        mxd_free_block(&prev_block);
        return -1;
    }

    // Copy base + add new entries
    if (base_count > 0) {
        memcpy(expected_scores, base, base_count * sizeof(mxd_validator_score_entry_t));
    }
    // v6: 32-byte addr32 throughout
    uint32_t idx = base_count;
    if (prev_block.rapid_membership_entries && prev_block.rapid_membership_count > 0) {
        for (uint32_t m = 0; m < prev_block.rapid_membership_count; m++) {
            int found = 0;
            for (uint32_t j = 0; j < base_count; j++) {
                if (memcmp(base[j].validator_address, prev_block.rapid_membership_entries[m].node_address, 32) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found && idx < expected_count) {
                memset(&expected_scores[idx], 0, sizeof(mxd_validator_score_entry_t));
                memcpy(expected_scores[idx].validator_address, prev_block.rapid_membership_entries[m].node_address, 32);
                idx++;
            }
        }
    }

    // Apply deltas from prev_block
    for (uint32_t i = 0; i < expected_count; i++) {
        expected_scores[i].blocks_since_joined++;
    }
    for (uint32_t i = 0; i < expected_count; i++) {
        if (memcmp(expected_scores[i].validator_address, prev_block.proposer_id, 32) == 0) {   // v6: addr32
            expected_scores[i].blocks_proposed++;
            break;
        }
    }
    if (prev_block.validation_chain && prev_block.validation_count > 0) {
        for (uint32_t v = 0; v < prev_block.validation_count; v++) {
            const mxd_validator_signature_t *sig = &prev_block.validation_chain[v];
            for (uint32_t i = 0; i < expected_count; i++) {
                if (memcmp(expected_scores[i].validator_address, sig->validator_id, 32) == 0) {   // v6: addr32
                    expected_scores[i].blocks_signed++;
                    if (sig->timestamp > prev_block.timestamp * 1000) {
                        expected_scores[i].total_latency_ms += (sig->timestamp - prev_block.timestamp * 1000);
                    } else if (sig->timestamp > prev_block.timestamp) {
                        expected_scores[i].total_latency_ms += (sig->timestamp - prev_block.timestamp);
                    }
                    break;
                }
            }
        }
    }

    // Sort by address
    qsort(expected_scores, expected_count, sizeof(mxd_validator_score_entry_t), compare_score_entry_by_address);

    // Compare non-stake fields (stake is a snapshot — we verify the root hash covers it)
    int match = 1;
    for (uint32_t i = 0; i < expected_count && match; i++) {
        if (memcmp(expected_scores[i].validator_address, block->validator_scores[i].validator_address, 32) != 0 ||   // v6: addr32
            expected_scores[i].blocks_proposed != block->validator_scores[i].blocks_proposed ||
            expected_scores[i].blocks_signed != block->validator_scores[i].blocks_signed ||
            expected_scores[i].total_latency_ms != block->validator_scores[i].total_latency_ms ||
            expected_scores[i].blocks_since_joined != block->validator_scores[i].blocks_since_joined) {
            match = 0;
        }
    }

    free(expected_scores);
    mxd_free_block(&prev_block);

    if (!match) {
        MXD_LOG_ERROR("rsc", "Validator score values mismatch at height %u", block->height);
        return -1;
    }

    return 0;
}

// Copy on-chain score entries into rapid table node structs.
// Replaces mxd_accumulate_block_stats() for v4+ blocks.
void mxd_load_scores_from_block(mxd_rapid_table_t *table, const mxd_block_t *block) {
    if (!table || !block || !block->validator_scores || block->validator_scores_count == 0) {
        return;
    }

    for (uint32_t s = 0; s < block->validator_scores_count; s++) {
        const mxd_validator_score_entry_t *entry = &block->validator_scores[s];
        for (size_t i = 0; i < table->count; i++) {
            // v6: validator_address is 32 bytes; node_address widening lands in H-2.
            // Until then comparing 32 bytes only matches if upper 12 are zero on both sides.
            if (table->nodes[i] && memcmp(table->nodes[i]->node_address, entry->validator_address, 32) == 0) {
                table->nodes[i]->stake_amount = entry->stake_amount;
                table->nodes[i]->blocks_proposed = entry->blocks_proposed;
                table->nodes[i]->blocks_signed = entry->blocks_signed;
                table->nodes[i]->total_latency_ms = entry->total_latency_ms;
                table->nodes[i]->blocks_since_joined = entry->blocks_since_joined;
                break;
            }
        }
    }
}

// Structure to preserve metrics during rebuild
typedef struct {
    uint8_t node_address[32];   // v6: addr32
    mxd_node_metrics_t metrics;
} preserved_metrics_t;

int mxd_rebuild_rapid_table_from_blockchain(mxd_rapid_table_t *table, uint32_t from_height,
                                            uint32_t to_height, const char *local_node_id) {
    if (!table) {
        return -1;
    }

    // Preserve metrics from existing nodes before rebuilding
    size_t preserved_count = table->count;
    preserved_metrics_t *preserved = NULL;
    if (preserved_count > 0) {
        preserved = malloc(preserved_count * sizeof(preserved_metrics_t));
        if (preserved) {
            for (size_t i = 0; i < preserved_count; i++) {
                if (table->nodes[i]) {
                    memcpy(preserved[i].node_address, table->nodes[i]->node_address, 32);   // v6: addr32
                    preserved[i].metrics = table->nodes[i]->metrics;
                } else {
                    memset(&preserved[i], 0, sizeof(preserved_metrics_t));
                }
            }
            MXD_LOG_INFO("rsc", "Preserved metrics for %zu nodes during rebuild", preserved_count);
        }
    }

    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i]) {
            free(table->nodes[i]);
            table->nodes[i] = NULL;
        }
    }
    table->count = 0;
    
    for (uint32_t height = from_height; height <= to_height; height++) {
        mxd_block_t block;
        memset(&block, 0, sizeof(mxd_block_t));

        if (mxd_retrieve_block_by_height(height, &block) != 0) {
            MXD_LOG_WARN("rsc", "Failed to retrieve block at height %u", height);
            continue;
        }

        MXD_LOG_INFO("rsc", "Retrieved block at height %u: rapid_membership_count=%u, rapid_membership_entries=%p",
                     height, block.rapid_membership_count, (void*)block.rapid_membership_entries);

        size_t count_before = table->count;
        mxd_apply_membership_deltas(table, &block, local_node_id);
        mxd_check_proposer_miss(table, &block);

        // v4+ optimization: only load scores from the LAST block (cumulative data),
        // skip intermediate v4 blocks since the last one's scores already reflect all history.
        if (block.version >= 4 && block.validator_scores) {
            if (height == to_height) {
                mxd_load_scores_from_block(table, &block);
            }
            // else: skip score loading for intermediate v4 blocks
        } else {
            mxd_accumulate_block_stats(table, &block);
        }
        MXD_LOG_INFO("rsc", "After applying deltas from height %u: table count %zu -> %zu (local_node_id=%s)",
                     height, count_before, table->count, local_node_id ? local_node_id : "NULL");

        mxd_free_validation_chain(&block);
    }
    
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) == 0) {
        mxd_remove_expired_nodes(table, current_time);
    }

    // Restore preserved metrics to matching nodes
    if (preserved) {
        size_t restored_count = 0;
        for (size_t i = 0; i < preserved_count; i++) {
            mxd_node_stake_t *node = mxd_get_node_by_address(table, preserved[i].node_address);
            if (node && preserved[i].metrics.response_count > 0) {
                node->metrics = preserved[i].metrics;
                restored_count++;
            }
        }
        MXD_LOG_INFO("rsc", "Restored metrics for %zu of %zu nodes after rebuild", restored_count, preserved_count);
        free(preserved);
    }

    // Compute chain-derived scores and sort by deterministic ranking
    mxd_compute_chain_scores(table);
    mxd_sort_rapid_table_by_score(table);

    return 0;
}

typedef struct mxd_pending_node_data_s {
    uint8_t node_address[32];   // v6: addr32
    uint8_t algo_id;
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint16_t public_key_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
    uint16_t signature_length;
    int received;
} mxd_genesis_signature_t;

static mxd_genesis_member_t *pending_genesis_members = NULL;
static size_t pending_genesis_count = 0;
static size_t pending_genesis_capacity = 0;
static uint8_t local_genesis_address[MXD_ADDR32_LEN] = {0};
static uint8_t local_genesis_algo_id = MXD_SIGALG_ED25519;
static uint8_t local_genesis_pubkey[MXD_PUBKEY_MAX_LEN] = {0};
static uint8_t local_genesis_privkey[MXD_PRIVKEY_MAX_LEN] = {0};
static int genesis_coordination_initialized = 0;

// Accessor functions for local node identity (for testing/API)
int mxd_get_local_node_identity(uint8_t *address, uint8_t *pubkey, size_t *pubkey_len,
                                 uint8_t *privkey, size_t *privkey_len, uint8_t *algo_id) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    if (address) memcpy(address, local_genesis_address, MXD_ADDR32_LEN);
    if (pubkey && pubkey_len) {
        size_t len = mxd_sig_pubkey_len(local_genesis_algo_id);
        memcpy(pubkey, local_genesis_pubkey, len);
        *pubkey_len = len;
    }
    if (privkey && privkey_len) {
        size_t len = mxd_sig_privkey_len(local_genesis_algo_id);
        memcpy(privkey, local_genesis_privkey, len);
        *privkey_len = len;
    }
    if (algo_id) *algo_id = local_genesis_algo_id;
    return 0;
}
static mxd_genesis_signature_t collected_signatures[10];
static size_t collected_signature_count = 0;
static uint8_t pending_genesis_digest[64] = {0};
static int genesis_sign_request_sent = 0;
static int genesis_locked = 0;
static int already_signed_genesis = 0;  // Track if we've signed a genesis request from another proposer
static pthread_mutex_t genesis_mutex = PTHREAD_MUTEX_INITIALIZER;

// Genesis sync phase tracking
#define MXD_GENESIS_SYNC_TIMEOUT_MS 10000  // 10 seconds to wait for sync confirmations
#define MXD_GENESIS_SYNC_MIN_CONFIRMATIONS 3  // Minimum nodes that must agree on member list
#define MXD_GENESIS_MEMBER_COLLECTION_WAIT_MS 30000  // 30 seconds to wait for more validators to join

typedef struct {
    uint8_t node_address[32];      // v6: addr32 (was [20])
    uint8_t member_list_hash[64];  // SHA-512 hash of sorted member addresses
    size_t member_count;
    uint64_t timestamp;
} mxd_genesis_sync_t;

static mxd_genesis_sync_t genesis_sync_confirmations[20];
static size_t genesis_sync_count = 0;
static uint64_t genesis_sync_started_time = 0;
static int genesis_sync_phase_complete = 0;
static uint8_t local_member_list_hash[64] = {0};

// Forward declaration for compare_addresses (defined later in file)
static int compare_addresses(const void *a, const void *b);

// Calculate hash of sorted member list for sync comparison (v6: addr32)
static int calculate_member_list_hash(uint8_t *hash_out) {
    if (!hash_out || pending_genesis_count == 0) {
        return -1;
    }

    // Create sorted copy of member addresses (v6: 32-byte addr32 each)
    uint8_t sorted_addresses[20][32];
    for (size_t i = 0; i < pending_genesis_count && i < 20; i++) {
        memcpy(sorted_addresses[i], pending_genesis_members[i].node_address, 32);
    }

    // Sort addresses
    size_t count = pending_genesis_count < 20 ? pending_genesis_count : 20;
    qsort(sorted_addresses, count, 32, compare_addresses);

    // Hash the sorted addresses
    return mxd_sha512((uint8_t*)sorted_addresses, count * 32, hash_out);
}

// Broadcast genesis sync message with current member list hash
int mxd_broadcast_genesis_sync(void) {
    if (!genesis_coordination_initialized || pending_genesis_count < 3) {
        return -1;
    }
    
    pthread_mutex_lock(&genesis_mutex);
    
    // Calculate current member list hash
    if (calculate_member_list_hash(local_member_list_hash) != 0) {
        pthread_mutex_unlock(&genesis_mutex);
        return -1;
    }
    
    size_t count = pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    
    // Build sync message (v6): [node_address(32)] [member_count(4)] [member_list_hash(64)] [timestamp(8)]
    uint8_t message[32 + 4 + 64 + 8];
    size_t offset = 0;

    memcpy(message + offset, local_genesis_address, 32);
    offset += 32;
    
    uint32_t count_net = htonl((uint32_t)count);
    memcpy(message + offset, &count_net, 4);
    offset += 4;
    
    memcpy(message + offset, local_member_list_hash, 64);
    offset += 64;
    
    uint64_t timestamp = mxd_now_ms();
    uint64_t timestamp_net = mxd_htonll(timestamp);
    memcpy(message + offset, &timestamp_net, 8);
    offset += 8;
    
    MXD_LOG_INFO("rsc", "Broadcasting genesis sync: member_count=%zu", count);
    
    return mxd_broadcast_message(MXD_MSG_GENESIS_SYNC, message, offset);
}

// Handle incoming genesis sync message
int mxd_handle_genesis_sync(const uint8_t *node_address, size_t member_count, 
                            const uint8_t *member_list_hash, uint64_t timestamp) {
    if (!genesis_coordination_initialized || !node_address || !member_list_hash) {
        return -1;
    }
    
    pthread_mutex_lock(&genesis_mutex);
    
    // Check if we already have a sync from this node (v6: addr32)
    for (size_t i = 0; i < genesis_sync_count; i++) {
        if (memcmp(genesis_sync_confirmations[i].node_address, node_address, 32) == 0) {
            // Update existing entry if newer
            if (timestamp > genesis_sync_confirmations[i].timestamp) {
                genesis_sync_confirmations[i].member_count = member_count;
                memcpy(genesis_sync_confirmations[i].member_list_hash, member_list_hash, 64);
                genesis_sync_confirmations[i].timestamp = timestamp;
            }
            pthread_mutex_unlock(&genesis_mutex);
            return 0;
        }
    }
    
    // Add new sync confirmation (v6: addr32)
    if (genesis_sync_count < 20) {
        mxd_genesis_sync_t *sync = &genesis_sync_confirmations[genesis_sync_count];
        memcpy(sync->node_address, node_address, 32);
        sync->member_count = member_count;
        memcpy(sync->member_list_hash, member_list_hash, 64);
        sync->timestamp = timestamp;
        genesis_sync_count++;

        char addr_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            snprintf(addr_hex + (i * 2), 3, "%02x", node_address[i]);
        }
        MXD_LOG_INFO("rsc", "Received genesis sync from %s: member_count=%zu (total syncs: %zu)",
                     addr_hex, member_count, genesis_sync_count);
    }
    
    pthread_mutex_unlock(&genesis_mutex);
    return 0;
}

// Check if sync phase is complete (enough nodes agree on member list)
static int check_genesis_sync_complete(void) {
    if (genesis_sync_phase_complete) {
        return 1;
    }
    
    // Calculate our current member list hash
    uint8_t our_hash[64];
    if (calculate_member_list_hash(our_hash) != 0) {
        return 0;
    }
    
    // Count how many nodes agree with our member list
    int matching_count = 1;  // Count ourselves
    
    for (size_t i = 0; i < genesis_sync_count; i++) {
        if (memcmp(genesis_sync_confirmations[i].member_list_hash, our_hash, 64) == 0 &&
            genesis_sync_confirmations[i].member_count == pending_genesis_count) {
            matching_count++;
        }
    }
    
    if (matching_count >= MXD_GENESIS_SYNC_MIN_CONFIRMATIONS) {
        MXD_LOG_INFO("rsc", "Genesis sync complete: %d nodes agree on member list (%zu members)", 
                     matching_count, pending_genesis_count);
        genesis_sync_phase_complete = 1;
        return 1;
    }
    
    return 0;
}

int mxd_init_genesis_coordination(const uint8_t *local_address, const uint8_t *local_pubkey, const uint8_t *local_privkey, uint8_t algo_id) {
    if (!local_address || !local_pubkey || !local_privkey) {
        return -1;
    }
    
    // Validate algo_id
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_ERROR("rsc", "Invalid algo_id %u for genesis coordination", algo_id);
        return -1;
    }
    
    // Reset genesis_locked to allow new members to be added
    genesis_locked = 0;
    
    local_genesis_algo_id = algo_id;
    
    size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
    size_t privkey_len = mxd_sig_privkey_len(local_genesis_algo_id);
    
    memcpy(local_genesis_address, local_address, MXD_ADDR32_LEN);
    memcpy(local_genesis_pubkey, local_pubkey, pubkey_len);
    memcpy(local_genesis_privkey, local_privkey, privkey_len);
    
    pending_genesis_capacity = 10;
    pending_genesis_members = calloc(pending_genesis_capacity, sizeof(mxd_genesis_member_t));
    if (!pending_genesis_members) {
        return -1;
    }
    
    genesis_coordination_initialized = 1;
    
    // Automatically add local node to pending genesis members
    // This ensures the local node is counted as a genesis validator
    mxd_genesis_member_t *local_member = &pending_genesis_members[0];
    memcpy(local_member->node_address, local_address, MXD_ADDR32_LEN);   // v6: addr32 (was 20)
    local_member->algo_id = algo_id;
    memcpy(local_member->public_key, local_pubkey, pubkey_len);
    local_member->timestamp = mxd_now_ms();
    // Sign the announce payload for consistency (must match mxd_broadcast_genesis_announce format)
    // v7 cascade (L6-5): MXD-CONS-1 (11) || addr32(32) || pubkey || timestamp_be(8)
    uint8_t announce_payload[MXD_DOMAIN_TAG_CONS_LEN + MXD_ADDR32_LEN + MXD_PUBKEY_MAX_LEN + 8];
    uint64_t timestamp_net = mxd_htonll(local_member->timestamp);
    size_t apo = 0;
    memcpy(announce_payload + apo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); apo += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(announce_payload + apo, local_address, MXD_ADDR32_LEN); apo += MXD_ADDR32_LEN;
    memcpy(announce_payload + apo, local_pubkey, pubkey_len); apo += pubkey_len;
    memcpy(announce_payload + apo, &timestamp_net, 8); apo += 8;
    size_t announce_payload_len = apo;
    size_t sig_len = sizeof(local_member->signature);
    if (mxd_sig_sign(algo_id, local_member->signature, &sig_len, announce_payload, announce_payload_len, local_privkey) == 0) {
        local_member->signature_length = (uint16_t)sig_len;
        pending_genesis_count = 1;
        
        // Register local node's public key for validation
        if (mxd_test_register_validator_pubkey(local_address, local_pubkey, pubkey_len) != 0) {
            MXD_LOG_WARN("rsc", "Failed to register local validator pubkey");
        }
        
        MXD_LOG_INFO("rsc", "Local node automatically added to pending genesis members");
    } else {
        MXD_LOG_WARN("rsc", "Failed to sign local genesis announce, local node not added to pending members");
    }
    
    MXD_LOG_INFO("rsc", "Genesis coordination initialized with %s", mxd_sig_alg_name(local_genesis_algo_id));
    return 0;
}

void mxd_cleanup_genesis_coordination(void) {
    if (pending_genesis_members) {
        free(pending_genesis_members);
        pending_genesis_members = NULL;
    }
    pending_genesis_count = 0;
    pending_genesis_capacity = 0;
    genesis_coordination_initialized = 0;
}

int mxd_broadcast_genesis_announce(void) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
    
    uint64_t current_time_ms = mxd_now_ms();
    uint64_t current_time_net = mxd_htonll(current_time_ms);
    
    // v7 cascade (L6-5): MXD-CONS-1 (11) || addr32(32) || pubkey || timestamp_be(8)
    uint8_t announce_payload[MXD_DOMAIN_TAG_CONS_LEN + 32 + MXD_PUBKEY_MAX_LEN + 8];
    size_t apo = 0;
    memcpy(announce_payload + apo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); apo += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(announce_payload + apo, local_genesis_address, 32); apo += 32;
    memcpy(announce_payload + apo, local_genesis_pubkey, pubkey_len); apo += pubkey_len;
    memcpy(announce_payload + apo, &current_time_net, 8); apo += 8;

    size_t announce_payload_len = apo;
    
    uint8_t signature[MXD_SIG_MAX_LEN];
    size_t signature_len = sizeof(signature);
    if (mxd_sig_sign(local_genesis_algo_id, signature, &signature_len, announce_payload, announce_payload_len, local_genesis_privkey) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to sign genesis announce");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Generated genesis announce signature: algo=%s, sig_len=%zu, timestamp_ms=%lu", 
                 mxd_sig_alg_name(local_genesis_algo_id), signature_len, current_time_ms);
    
    // v6 wire format: algo_id(1) + node_address(32) + pubkey_len(2) + pubkey + timestamp(8) + sig_len(2) + sig
    uint8_t message[1 + 32 + 2 + MXD_PUBKEY_MAX_LEN + 8 + 2 + MXD_SIG_MAX_LEN];
    size_t offset = 0;

    message[offset] = local_genesis_algo_id;
    offset += 1;

    memcpy(message + offset, local_genesis_address, 32);
    offset += 32;
    
    uint16_t pubkey_len_net = htons((uint16_t)pubkey_len);
    memcpy(message + offset, &pubkey_len_net, 2);
    offset += 2;
    
    memcpy(message + offset, local_genesis_pubkey, pubkey_len);
    offset += pubkey_len;
    
    memcpy(message + offset, &current_time_net, 8);
    offset += 8;
    
    uint16_t sig_len_net = htons((uint16_t)signature_len);
    memcpy(message + offset, &sig_len_net, 2);
    offset += 2;
    
    memcpy(message + offset, signature, signature_len);
    offset += signature_len;
    
    MXD_LOG_INFO("rsc", "Constructed genesis announce message: total_size=%zu (algo=1, addr=32, pubkey_len=2, pubkey=%zu, time=8, sig_len=2, sig=%zu)",
                offset, pubkey_len, signature_len);
    
    if (mxd_broadcast_message(MXD_MSG_GENESIS_ANNOUNCE, message, offset) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to broadcast genesis announce");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Broadcast genesis announce: message_size=%zu", offset);
    return 0;
}

int mxd_handle_genesis_announce(uint8_t algo_id, const uint8_t *node_address, const uint8_t *public_key, 
                                 size_t pubkey_len, uint64_t timestamp, const uint8_t *signature, uint16_t signature_length) {
    if (!genesis_coordination_initialized || !node_address || !public_key || !signature) {
        MXD_LOG_WARN("rsc", "Genesis announce validation failed: initialized=%d, node_address=%p, public_key=%p, signature=%p",
                    genesis_coordination_initialized, (void*)node_address, (void*)public_key, (void*)signature);
        return -1;
    }
    
    size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
    if (expected_pubkey_len == 0 || pubkey_len != expected_pubkey_len) {
        MXD_LOG_WARN("rsc", "Invalid pubkey length %zu for algo %u (expected %zu)", 
                     pubkey_len, algo_id, expected_pubkey_len);
        return -1;
    }
    
    char addr_hex[65] = {0};   // v6: addr32 (was 41)
    for (int i = 0; i < MXD_ADDR32_LEN; i++) {
        snprintf(addr_hex + (i * 2), 3, "%02x", node_address[i]);
    }
    MXD_LOG_INFO("rsc", "Processing genesis announce from address: %s, algo=%s, timestamp=%lu, sig_len=%u",
                 addr_hex, mxd_sig_alg_name(algo_id), timestamp, signature_length);

    uint8_t derived_address[MXD_ADDR32_LEN];
    if (mxd_derive_address(algo_id, public_key, pubkey_len, derived_address) != 0) {
        MXD_LOG_WARN("rsc", "Failed to derive address from public key");
        return -1;
    }

    char derived_hex[65] = {0};   // v6: addr32 (was 41)
    for (int i = 0; i < MXD_ADDR32_LEN; i++) {
        snprintf(derived_hex + (i * 2), 3, "%02x", derived_address[i]);
    }

    if (memcmp(node_address, derived_address, MXD_ADDR32_LEN) != 0) {   // v6: addr32 (was 20)
        MXD_LOG_WARN("rsc", "Node address mismatch: announced=%s, derived=%s", addr_hex, derived_hex);
        return -1;
    }
    
    uint64_t current_time_ms = mxd_now_ms();
    
    int64_t drift_ms = llabs((int64_t)timestamp - (int64_t)current_time_ms);
    if (drift_ms > (int64_t)MXD_MAX_TIMESTAMP_DRIFT_MS) {
        MXD_LOG_WARN("rsc", "Genesis announce timestamp drift too large: drift=%ld ms (max=%llu ms)", 
                     drift_ms, MXD_MAX_TIMESTAMP_DRIFT_MS);
        return -1;
    }
    MXD_LOG_INFO("rsc", "Timestamp validation passed: drift=%ld ms", drift_ms);
    
    // v7 cascade (L6-5): MXD-CONS-1 (11) || addr32(32) || pubkey || timestamp_be(8)
    uint64_t timestamp_net = mxd_htonll(timestamp);
    uint8_t announce_payload[MXD_DOMAIN_TAG_CONS_LEN + 32 + MXD_PUBKEY_MAX_LEN + 8];
    size_t apo = 0;
    memcpy(announce_payload + apo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); apo += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(announce_payload + apo, node_address, 32); apo += 32;
    memcpy(announce_payload + apo, public_key, pubkey_len); apo += pubkey_len;
    memcpy(announce_payload + apo, &timestamp_net, 8); apo += 8;

    size_t announce_payload_len = apo;
    
    MXD_LOG_INFO("rsc", "Verifying signature: payload_size=%zu, sig_len=%u", announce_payload_len, signature_length);
    if (mxd_sig_verify(algo_id, signature, signature_length, announce_payload, announce_payload_len, public_key) != 0) {
        MXD_LOG_WARN("rsc", "Invalid genesis announce signature from %s", addr_hex);
        return -1;
    }
    MXD_LOG_INFO("rsc", "Signature verification passed for %s", addr_hex);
    
    // Protect genesis globals with mutex
    pthread_mutex_lock(&genesis_mutex);
    
    // Check if genesis coordination is locked (no new members allowed)
    if (genesis_locked) {
        MXD_LOG_DEBUG("rsc", "Genesis coordination locked, ignoring new member announce from %s", addr_hex);
        pthread_mutex_unlock(&genesis_mutex);
        return 0;
    }
    
    for (size_t i = 0; i < pending_genesis_count; i++) {
        if (memcmp(pending_genesis_members[i].node_address, node_address, 32) == 0) {   // v6: addr32
            MXD_LOG_DEBUG("rsc", "Genesis member already registered");
            pthread_mutex_unlock(&genesis_mutex);
            return 0;
        }
    }
    
    if (pending_genesis_count >= pending_genesis_capacity) {
        size_t new_capacity = pending_genesis_capacity * 2;
        mxd_genesis_member_t *new_members = realloc(pending_genesis_members, new_capacity * sizeof(mxd_genesis_member_t));
        if (!new_members) {
            pthread_mutex_unlock(&genesis_mutex);
            return -1;
        }
        pending_genesis_members = new_members;
        pending_genesis_capacity = new_capacity;
    }
    
    mxd_genesis_member_t *member = &pending_genesis_members[pending_genesis_count];
    memcpy(member->node_address, node_address, 32);   // v6: addr32
    member->algo_id = algo_id;
    memcpy(member->public_key, public_key, pubkey_len);
    member->timestamp = timestamp;
    memcpy(member->signature, signature, signature_length);
    member->signature_length = signature_length;
    pending_genesis_count++;
    
    size_t count = pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    
    if (mxd_test_register_validator_pubkey(node_address, public_key, pubkey_len) != 0) {
        MXD_LOG_WARN("rsc", "Failed to register validator pubkey for genesis member");
    }
    
    MXD_LOG_INFO("rsc", "Registered genesis member (%zu/%d)", count, 3);
    return 0;
}

int mxd_get_pending_genesis_count(void) {
    pthread_mutex_lock(&genesis_mutex);
    int count = (int)pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    return count;
}

int mxd_is_genesis_locked(void) {
    pthread_mutex_lock(&genesis_mutex);
    int locked = genesis_locked;
    pthread_mutex_unlock(&genesis_mutex);
    return locked;
}

void mxd_set_genesis_locked(int locked) {
    pthread_mutex_lock(&genesis_mutex);
    genesis_locked = locked;
    pthread_mutex_unlock(&genesis_mutex);
}

int mxd_sync_pending_genesis_to_rapid_table(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!genesis_coordination_initialized || !table) {
        return -1;
    }
    
    if (genesis_locked) {
        MXD_LOG_DEBUG("rsc", "Genesis coordination locked, skipping sync to rapid table");
        return 0;
    }
    
    for (size_t i = 0; i < pending_genesis_count; i++) {
        mxd_genesis_member_t *member = &pending_genesis_members[i];

        // Convert node address to hex string for node_id (v6: addr32, 64 hex chars)
        char node_id_hex[65] = {0};
        for (int j = 0; j < 32; j++) {
            snprintf(node_id_hex + (j * 2), 3, "%02x", member->node_address[j]);
        }
        
        // Check if already in rapid table
        int found = 0;
        for (size_t j = 0; j < table->count; j++) {
            if (table->nodes[j] && strcmp(table->nodes[j]->node_id, node_id_hex) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            mxd_node_stake_t *node = malloc(sizeof(mxd_node_stake_t));
            if (!node) {
                continue;
            }
            
            memset(node, 0, sizeof(mxd_node_stake_t));
            strncpy(node->node_id, node_id_hex, sizeof(node->node_id) - 1);
            memcpy(node->node_address, member->node_address, 32);   // v6: addr32
            // Get stake amount from UTXO balance
            node->stake_amount = mxd_get_balance(member->node_address);
            node->active = 1;
            node->in_rapid_table = 1;
            
            // Initialize metrics
            mxd_init_node_metrics(&node->metrics);
            
            if (mxd_add_to_rapid_table(table, node, local_node_id) == 0) {
                MXD_LOG_INFO("rsc", "Added pre-genesis member %s to rapid table", node_id_hex);
            } else {
                free(node);
            }
        }
    }
    
    return 0;
}

static int compare_addresses(const void *a, const void *b) {
    return memcmp(a, b, 32);   // v6: addr32
}

int mxd_send_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest, 
                                   const uint8_t *proposer_id, uint32_t height,
                                   const mxd_genesis_member_t *members, size_t member_count) {
    if (!members || member_count == 0 || member_count > 10) {
        MXD_LOG_ERROR("rsc", "Invalid member list for genesis sign request");
        return -1;
    }
    
    // v6 wire format: 32-byte addr32 (target/proposer/per-member node_address)
    size_t max_message_size = 32 + 64 + 32 + 4 + 1 + (member_count * (32 + 1 + 2 + MXD_PUBKEY_MAX_LEN));
    uint8_t *message = malloc(max_message_size);
    if (!message) {
        MXD_LOG_ERROR("rsc", "Failed to allocate memory for genesis sign request");
        return -1;
    }

    size_t offset = 0;

    memcpy(message + offset, target_address, 32);
    offset += 32;
    memcpy(message + offset, membership_digest, 64);
    offset += 64;
    memcpy(message + offset, proposer_id, 32);
    offset += 32;
    memcpy(message + offset, &height, 4);
    offset += 4;

    uint8_t count = (uint8_t)member_count;
    memcpy(message + offset, &count, 1);
    offset += 1;

    for (size_t i = 0; i < member_count; i++) {
        const mxd_genesis_member_t *m = &members[i];

        memcpy(message + offset, m->node_address, 32);
        offset += 32;
        
        memcpy(message + offset, &m->algo_id, 1);
        offset += 1;
        
        size_t pubkey_len = mxd_sig_pubkey_len(m->algo_id);
        uint16_t pubkey_len_net = htons((uint16_t)pubkey_len);
        memcpy(message + offset, &pubkey_len_net, 2);
        offset += 2;
        
        memcpy(message + offset, m->public_key, pubkey_len);
        offset += pubkey_len;
    }
    
    MXD_LOG_INFO("rsc", "Sending genesis sign request with %zu members, message size=%zu", member_count, offset);
    
    int result = mxd_broadcast_message(MXD_MSG_GENESIS_SIGN_REQUEST, message, offset);
    free(message);
    
    if (result != 0) {
        MXD_LOG_ERROR("rsc", "Failed to send genesis sign request");
        return -1;
    }
    
    return 0;
}

int mxd_handle_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest,
                                     const uint8_t *proposer_id, uint32_t height,
                                     const mxd_genesis_member_t *members, size_t member_count) {
    if (!genesis_coordination_initialized) {
        MXD_LOG_INFO("rsc", "Genesis sign request rejected: coordination not initialized");
        return -1;
    }
    
    // Log target address vs local address for debugging (v6: addr32, 64 hex chars)
    char target_hex[65] = {0}, local_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        snprintf(target_hex + i*2, 3, "%02x", target_address[i]);
        snprintf(local_hex + i*2, 3, "%02x", local_genesis_address[i]);
    }
    MXD_LOG_INFO("rsc", "Genesis sign request: target=%s, local=%s", target_hex, local_hex);

    if (memcmp(target_address, local_genesis_address, 32) != 0) {
        MXD_LOG_INFO("rsc", "Genesis sign request not for this node (address mismatch)");
        return 0;
    }
    
    if (height != 0) {
        MXD_LOG_WARN("rsc", "Genesis sign request for non-zero height");
        return -1;
    }
    
    if (already_signed_genesis) {
        MXD_LOG_WARN("rsc", "Already signed genesis block");
        return -1;
    }
    
    // Accept sign requests if:
    // 1. Member count is at least 3 (minimum for genesis)
    // 2. This node is included in the member list
    // We trust the proposer's member list to ensure consistency across the network
    if (member_count < 3) {
        MXD_LOG_WARN("rsc", "Genesis sign request has insufficient members: %zu (need at least 3)", member_count);
        return -1;
    }
    
    // Verify this node is included in the member list (v6: addr32)
    int self_included = 0;
    for (size_t i = 0; i < member_count; i++) {
        if (memcmp(members[i].node_address, local_genesis_address, 32) == 0) {
            // Verify our public key matches
            size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
            if (members[i].algo_id != local_genesis_algo_id) {
                MXD_LOG_WARN("rsc", "Genesis sign request has wrong algo_id for this node");
                return -1;
            }
            if (memcmp(members[i].public_key, local_genesis_pubkey, pubkey_len) != 0) {
                MXD_LOG_WARN("rsc", "Genesis sign request has wrong public_key for this node");
                return -1;
            }
            self_included = 1;
            break;
        }
    }
    
    if (!self_included) {
        MXD_LOG_DEBUG("rsc", "Genesis sign request does not include this node - ignoring");
        return 0;
    }
    
    MXD_LOG_INFO("rsc", "Accepting genesis sign request with %zu members (trusting proposer's list)", member_count);
    
    MXD_LOG_INFO("rsc", "Genesis sign request member list validated (%zu members)", member_count);
    
    genesis_locked = 1;
    MXD_LOG_INFO("rsc", "Genesis coordination locked - no new members will be accepted");
    
    uint8_t signature[MXD_SIGNATURE_MAX];
    size_t signature_len = sizeof(signature);
    if (mxd_sig_sign(local_genesis_algo_id, signature, &signature_len, membership_digest, 64, local_genesis_privkey) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to sign membership digest");
        return -1;
    }
    
    already_signed_genesis = 1;
    
    // Response format (v6): signer_address (32) + proposer_id (32) + membership_digest (64) + sig_len (2) + signature
    uint8_t response[32 + 32 + 64 + 2 + 4096];
    size_t offset = 0;
    memcpy(response + offset, local_genesis_address, 32);
    offset += 32;
    memcpy(response + offset, proposer_id, 32);  // Include proposer_id so proposer can verify this response is for them
    offset += 32;
    memcpy(response + offset, membership_digest, 64);
    offset += 64;
    uint16_t sig_len = htons((uint16_t)signature_len);
    memcpy(response + offset, &sig_len, 2);
    offset += 2;
    memcpy(response + offset, signature, signature_len);
    offset += signature_len;
    
    if (mxd_broadcast_message(MXD_MSG_GENESIS_SIGN_RESPONSE, response, offset) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to send genesis sign response");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Sent genesis signature response for proposer");
    return 0;
}

int mxd_handle_genesis_sign_response(const uint8_t *signer_address, const uint8_t *proposer_id,
                                      const uint8_t *membership_digest,
                                      const uint8_t *signature, uint16_t signature_length) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    if (!genesis_sign_request_sent) {
        MXD_LOG_INFO("rsc", "Ignoring genesis sign response (not active proposer, genesis_sign_request_sent=%d)", genesis_sign_request_sent);
        return 0;
    }
    
    // Verify this response is for our sign request (not another proposer's). v6: addr32.
    if (memcmp(proposer_id, local_genesis_address, 32) != 0) {
        char proposer_hex[65] = {0}, local_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            snprintf(proposer_hex + i*2, 3, "%02x", proposer_id[i]);
            snprintf(local_hex + i*2, 3, "%02x", local_genesis_address[i]);
        }
        MXD_LOG_INFO("rsc", "Ignoring genesis sign response for different proposer: got=%s, local=%s", proposer_hex, local_hex);
        return 0;
    }
    
    if (memcmp(membership_digest, pending_genesis_digest, 64) != 0) {
        MXD_LOG_WARN("rsc", "Genesis sign response digest mismatch");
        return -1;
    }
    
    for (size_t i = 0; i < collected_signature_count; i++) {
        if (memcmp(collected_signatures[i].node_address, signer_address, 32) == 0) {   // v6: addr32
            MXD_LOG_DEBUG("rsc", "Already have signature from this node");
            return 0;
        }
    }
    
    // Look up signer's public key from pending_genesis_members (not the registry, which may not have it yet)
    uint8_t signer_pubkey[MXD_PUBKEY_MAX_LEN];
    size_t pubkey_len = 0;
    uint8_t signer_algo_id = 0;
    int found_signer = 0;
    
    for (size_t i = 0; i < pending_genesis_count; i++) {
        if (memcmp(pending_genesis_members[i].node_address, signer_address, 32) == 0) {   // v6: addr32
            signer_algo_id = pending_genesis_members[i].algo_id;
            pubkey_len = mxd_sig_pubkey_len(signer_algo_id);
            memcpy(signer_pubkey, pending_genesis_members[i].public_key, pubkey_len);
            found_signer = 1;
            break;
        }
    }
    
    if (!found_signer) {
        MXD_LOG_WARN("rsc", "Signer not found in pending genesis members");
        return -1;
    }
    
    if (mxd_sig_verify(signer_algo_id, signature, signature_length, membership_digest, 64, signer_pubkey) != 0) {
        MXD_LOG_WARN("rsc", "Invalid genesis signature");
        return -1;
    }
    
    pthread_mutex_lock(&genesis_mutex);
    if (collected_signature_count >= 10) {
        pthread_mutex_unlock(&genesis_mutex);
        MXD_LOG_WARN("rsc", "Too many collected signatures");
        return -1;
    }

    mxd_genesis_signature_t *sig = &collected_signatures[collected_signature_count];
    memcpy(sig->node_address, signer_address, 32);   // v6: addr32
    sig->algo_id = signer_algo_id;
    memcpy(sig->public_key, signer_pubkey, pubkey_len);
    sig->public_key_length = (uint16_t)pubkey_len;
    memcpy(sig->signature, signature, signature_length);
    sig->signature_length = signature_length;
    sig->received = 1;
    collected_signature_count++;
    pthread_mutex_unlock(&genesis_mutex);

    MXD_LOG_INFO("rsc", "Collected genesis signature (%zu)", collected_signature_count);
    return 0;
}

// Track when we first had 3+ genesis members for timeout-based proposer fallback
static uint64_t genesis_quorum_reached_time = 0;
#define MXD_GENESIS_PROPOSER_TIMEOUT_MS 30000  // 30 seconds timeout for proposer fallback

int mxd_try_coordinate_genesis_block(void) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    uint32_t blockchain_height = 0;
    if (mxd_get_blockchain_height(&blockchain_height) == 0 && blockchain_height > 0) {
        return 0;
    }
    
    // Use mutex to safely read and modify genesis coordination state
    pthread_mutex_lock(&genesis_mutex);
    
    size_t local_pending_count = pending_genesis_count;
    
    if (local_pending_count < 3) {
        genesis_quorum_reached_time = 0;  // Reset timeout tracking
        pthread_mutex_unlock(&genesis_mutex);
        return 0;
    }
    
    // Track when we first reached quorum
    uint64_t current_time = mxd_now_ms();
    if (genesis_quorum_reached_time == 0) {
        genesis_quorum_reached_time = current_time;
        MXD_LOG_INFO("rsc", "Genesis quorum reached with %zu members, waiting %d seconds for more validators to join",
                    local_pending_count, MXD_GENESIS_MEMBER_COLLECTION_WAIT_MS / 1000);
    }
    
    // Wait for member collection period before locking (allows more validators to join)
    // Lock early if we already have 10 validators (maximum)
    if (!genesis_locked) {
        if (local_pending_count >= 5) {
            genesis_locked = 1;
            genesis_sync_started_time = current_time;
            MXD_LOG_INFO("rsc", "Maximum validators reached (%zu), locking member list", local_pending_count);
        } else if (current_time - genesis_quorum_reached_time >= MXD_GENESIS_MEMBER_COLLECTION_WAIT_MS) {
            genesis_locked = 1;
            genesis_sync_started_time = current_time;
            MXD_LOG_INFO("rsc", "Member collection period complete, locking with %zu validators", local_pending_count);
        } else {
            // Still waiting for more validators
            uint64_t remaining_ms = MXD_GENESIS_MEMBER_COLLECTION_WAIT_MS - (current_time - genesis_quorum_reached_time);
            static uint64_t last_wait_log = 0;
            if (current_time - last_wait_log > 5000) {  // Log every 5 seconds
                MXD_LOG_INFO("rsc", "Waiting for more validators: %zu current, %llu seconds remaining",
                            local_pending_count, (unsigned long long)(remaining_ms / 1000));
                last_wait_log = current_time;
            }
            pthread_mutex_unlock(&genesis_mutex);
            return 0;  // Keep waiting
        }
    }
    
    // Make a local copy of pending genesis members while holding the lock
    mxd_genesis_member_t local_members[10];
    size_t local_member_count = local_pending_count < 10 ? local_pending_count : 10;
    for (size_t i = 0; i < local_member_count; i++) {
        local_members[i] = pending_genesis_members[i];
    }
    
    pthread_mutex_unlock(&genesis_mutex);
    
    // Sync phase: broadcast our member list hash and wait for confirmations
    if (!genesis_sync_phase_complete) {
        // Periodically broadcast sync message (every 2 seconds)
        static uint64_t last_sync_broadcast = 0;
        if (current_time - last_sync_broadcast > 2000) {
            mxd_broadcast_genesis_sync();
            last_sync_broadcast = current_time;
        }
        
        // Check if sync is complete
        if (!check_genesis_sync_complete()) {
            // Check for sync timeout
            if (current_time - genesis_sync_started_time > MXD_GENESIS_SYNC_TIMEOUT_MS) {
                MXD_LOG_WARN("rsc", "Genesis sync timeout after %llu ms, proceeding with %zu sync confirmations",
                            (unsigned long long)(current_time - genesis_sync_started_time), genesis_sync_count);
                genesis_sync_phase_complete = 1;
            } else {
                return 0;  // Still waiting for sync
            }
        }
        MXD_LOG_INFO("rsc", "Genesis sync phase complete, proceeding to sign request phase");
    }
    
    // v6: addr32 (32 bytes per address)
    uint8_t addresses[10][32];
    size_t addr_count = 0;

    // Use local copy of members instead of accessing shared state
    for (size_t i = 0; i < local_member_count && addr_count < 10; i++) {
        memcpy(addresses[addr_count], local_members[i].node_address, 32);
        addr_count++;
    }

    qsort(addresses, addr_count, 32, compare_addresses);

    // DEBUG: Log the sorted addresses and local address for genesis coordinator debugging
    {
        char local_hex[65] = {0};
        char first_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            snprintf(local_hex + i*2, 3, "%02x", local_genesis_address[i]);
            if (addr_count > 0) {
                snprintf(first_hex + i*2, 3, "%02x", addresses[0][i]);
            }
        }
        MXD_LOG_INFO("rsc", "Genesis coordinator: addr_count=%zu, local=%s, first=%s",
                     addr_count, local_hex, addr_count > 0 ? first_hex : "(none)");
    }

    // DETERMINISTIC GENESIS: Only include validators that actually signed
    // This ensures coinbase recipients match membership entries (no ghost validators)
    // Minimum 3 validators required for quorum, maximum 10 for genesis
    size_t genesis_validator_count = addr_count;

    // Check if this node is in the genesis validator set (v6: addr32)
    int is_genesis_validator = 0;
    for (size_t i = 0; i < genesis_validator_count; i++) {
        if (memcmp(local_genesis_address, addresses[i], 32) == 0) {
            is_genesis_validator = 1;
            break;
        }
    }

    if (!is_genesis_validator) {
        // This node is not in the genesis validator set, wait for genesis block from others
        MXD_LOG_WARN("rsc", "Genesis coordinator: local address not found in validator set!");
        return 0;
    }

    // Check if this node is the designated proposer (lexicographically smallest address)
    // ONLY the designated proposer creates the genesis block - NO fallback proposers
    // This ensures deterministic genesis block creation with identical proposer_id
    int is_designated_proposer = (memcmp(local_genesis_address, addresses[0], 32) == 0);   // v6: addr32

    MXD_LOG_INFO("rsc", "Genesis coordinator: is_genesis_validator=%d, is_designated_proposer=%d",
                 is_genesis_validator, is_designated_proposer);

    if (!is_designated_proposer) {
        // Not the designated proposer - wait for sign request from the proposer
        // Do NOT become a fallback proposer as this causes multiple incompatible genesis blocks
        return 0;
    }
    
    if (!genesis_sign_request_sent) {
        MXD_LOG_INFO("rsc", "This node is the designated proposer for genesis block");
        
        mxd_block_t genesis_block;
        uint8_t prev_hash[64] = {0};
        
        if (mxd_init_block(&genesis_block, prev_hash) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to initialize genesis block");
            return -1;
        }
        
        genesis_block.height = 0;
        genesis_block.total_supply = 0; // Genesis has no supply yet
        memcpy(genesis_block.proposer_id, local_genesis_address, 32);   // v6: addr32

        if (mxd_freeze_transaction_set(&genesis_block) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to freeze genesis block transaction set");
            mxd_free_validation_chain(&genesis_block);
            return -1;
        }
        
        if (mxd_calculate_membership_digest(&genesis_block, pending_genesis_digest) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to calculate membership digest");
            mxd_free_validation_chain(&genesis_block);
            return -1;
        }
        
        mxd_free_validation_chain(&genesis_block);
        
        uint8_t self_signature[MXD_SIGNATURE_MAX];
        size_t self_sig_len = sizeof(self_signature);
        if (mxd_sig_sign(local_genesis_algo_id, self_signature, &self_sig_len, pending_genesis_digest, 64, local_genesis_privkey) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to sign own membership");
            return -1;
        }
        
        mxd_genesis_signature_t *self_sig = &collected_signatures[collected_signature_count];
        memcpy(self_sig->node_address, local_genesis_address, 32);   // v6: addr32
        self_sig->algo_id = local_genesis_algo_id;
        size_t local_pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
        memcpy(self_sig->public_key, local_genesis_pubkey, local_pubkey_len);
        self_sig->public_key_length = (uint16_t)local_pubkey_len;
        memcpy(self_sig->signature, self_signature, self_sig_len);
        self_sig->signature_length = (uint16_t)self_sig_len;
        self_sig->received = 1;
        collected_signature_count++;
        
        // Send sign requests to ALL pending genesis members (not just first 3)
        // This ensures we get enough responses even if some nodes don't respond
        for (size_t i = 0; i < local_member_count; i++) {
            if (memcmp(local_members[i].node_address, local_genesis_address, 32) != 0) {   // v6: addr32
                mxd_send_genesis_sign_request(local_members[i].node_address,
                                              pending_genesis_digest, local_genesis_address, 0,
                                              local_members, local_member_count);
            }
        }
        
        genesis_sign_request_sent = 1;
        MXD_LOG_INFO("rsc", "Sent genesis sign requests to peers");
        return 0;
    }
    
    // Need at least 1 signature (proposer's own) to start
    if (collected_signature_count < 1) {
        return 0;
    }

    // Wait for ALL expected signatures before creating genesis block.
    // This ensures all validators get membership entries in genesis.
    // 60 second timeout allows for nodes booting at different times.
    static uint64_t genesis_sig_wait_start = 0;
    if (collected_signature_count < local_member_count) {
        if (genesis_sig_wait_start == 0) {
            genesis_sig_wait_start = mxd_now_ms();
        }
        uint64_t waited = mxd_now_ms() - genesis_sig_wait_start;
        if (waited % 5000 < 250) {  // Log every ~5 seconds
            MXD_LOG_INFO("rsc", "Waiting for genesis signatures: have %zu of %zu (%.0fs elapsed, 60s max)",
                         collected_signature_count, local_member_count, waited / 1000.0);
        }
        if (waited < 60000) {
            return 0;  // Keep waiting up to 60 seconds
        }
        MXD_LOG_WARN("rsc", "Genesis timeout after %llu ms: proceeding with %zu of %zu signatures",
                     (unsigned long long)waited, collected_signature_count, local_member_count);
    }

    static int genesis_creation_attempted = 0;
    if (genesis_creation_attempted) {
        return 0;
    }
    genesis_creation_attempted = 1;

    // Snapshot the signature count and data under lock to prevent partial reads
    // while the P2P thread is writing a new signature entry
    pthread_mutex_lock(&genesis_mutex);
    const size_t genesis_sig_count = collected_signature_count;
    mxd_genesis_signature_t genesis_sigs[10];
    memcpy(genesis_sigs, collected_signatures, genesis_sig_count * sizeof(mxd_genesis_signature_t));
    pthread_mutex_unlock(&genesis_mutex);

    MXD_LOG_INFO("rsc", "Have %zu of %zu signatures, creating genesis block",
                 genesis_sig_count, local_member_count);

    mxd_block_t genesis_block;
    uint8_t prev_hash[64] = {0};
    
    if (mxd_init_block(&genesis_block, prev_hash) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to initialize genesis block");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    genesis_block.height = 0;
    memcpy(genesis_block.proposer_id, local_genesis_address, 32);   // v6: addr32
    
    // Get initial stake amount from config for minting genesis validator balances
    mxd_config_t *config = mxd_get_config();
    mxd_amount_t initial_stake = config ? config->initial_stake : 0;
    mxd_amount_t total_minted = 0;

    MXD_LOG_INFO("rsc", "Genesis block creation: config=%p, initial_stake=%llu, genesis_validator_count=%zu",
                 (void*)config, (unsigned long long)initial_stake, genesis_validator_count);

    // Create coinbase transactions ONLY for validators that signed (from snapshot)
    // This ensures coinbase recipients exactly match membership entries — no ghost validators
    for (size_t i = 0; i < genesis_sig_count; i++) {
        if (initial_stake > 0) {
            mxd_transaction_t coinbase_tx;
            memset(&coinbase_tx, 0, sizeof(coinbase_tx));

            // v6: genesis_sigs[i].node_address is now 32-byte addr32 — pass directly
            if (mxd_create_coinbase_transaction(&coinbase_tx, genesis_sigs[i].node_address, initial_stake) == 0) {
                // Serialize the coinbase transaction for block storage
                size_t tx_len = 0;
                uint8_t *tx_data = serialize_coinbase_for_block(&coinbase_tx, &tx_len);
                
                if (tx_data && tx_len > 0) {
                    if (mxd_add_transaction(&genesis_block, tx_data, tx_len) == 0) {
                        // CRITICAL: Create UTXOs from the coinbase transaction so validators have spendable balance
                        // This must be done here because mxd_store_block does not process transactions
                        if (mxd_create_utxos_from_tx(&coinbase_tx, coinbase_tx.tx_hash) == 0) {
                            total_minted += initial_stake;
                            MXD_LOG_INFO("rsc", "Added genesis coinbase tx for validator %zu: %llu base units (UTXO created)",
                                        i, (unsigned long long)initial_stake);
                        } else {
                            MXD_LOG_ERROR("rsc", "CRITICAL: Failed to create UTXO for genesis validator %zu - tokens NOT minted", i);
                            // Do NOT count as minted - the tokens don't exist without a UTXO
                        }
                    } else {
                        MXD_LOG_WARN("rsc", "Failed to add coinbase tx to genesis block for validator %zu", i);
                    }
                    free(tx_data);
                }
                
                // Free transaction resources
                mxd_free_transaction(&coinbase_tx);
            } else {
                MXD_LOG_WARN("rsc", "Failed to create coinbase tx for genesis validator %zu", i);
            }
        }
    }
    
    // Set total supply to the amount actually minted (only successful UTXO creations)
    genesis_block.total_supply = total_minted;
    size_t successful_mints = initial_stake > 0 ? (size_t)(total_minted / initial_stake) : 0;
    MXD_LOG_INFO("rsc", "Genesis block total_supply set to %llu base units (%zu of %zu validators received %llu each)",
                (unsigned long long)total_minted,
                successful_mints,
                genesis_validator_count,
                (unsigned long long)initial_stake);

    // For v4+ genesis: create zero-initialized score entries for all genesis validators
    if (genesis_block.version >= 4 && genesis_sig_count > 0) {
        genesis_block.validator_scores = calloc(genesis_sig_count, sizeof(mxd_validator_score_entry_t));
        if (genesis_block.validator_scores) {
            genesis_block.validator_scores_count = (uint32_t)genesis_sig_count;
            genesis_block.validator_scores_capacity = (uint32_t)genesis_sig_count;
            for (size_t i = 0; i < genesis_sig_count; i++) {
                memcpy(genesis_block.validator_scores[i].validator_address,
                       genesis_sigs[i].node_address, 32);   // v6: addr32
                genesis_block.validator_scores[i].stake_amount =
                    mxd_get_balance(genesis_sigs[i].node_address);
                // All other fields are zero (calloc)
            }
            // Sort by address for deterministic serialization
            qsort(genesis_block.validator_scores, genesis_block.validator_scores_count,
                  sizeof(mxd_validator_score_entry_t), compare_score_entry_by_address);
            MXD_LOG_INFO("rsc", "Created %u zero-initialized v4 score entries for genesis",
                        genesis_block.validator_scores_count);
        }
    }

    if (mxd_freeze_transaction_set(&genesis_block) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to freeze genesis block transaction set");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = mxd_now_ms(); // Use NTP-synchronized time in milliseconds
    }
    
    // Add ALL collected signatures to membership entries (from snapshot)
    // This ensures all participating validators are included in the genesis block
    for (size_t i = 0; i < genesis_sig_count; i++) {
        mxd_genesis_signature_t *sig = &genesis_sigs[i];
        
        if (mxd_append_membership_entry(&genesis_block, sig->node_address, 
                                        sig->algo_id, sig->public_key, sig->public_key_length,
                                        sig->signature, sig->signature_length, current_time) != 0) {
            MXD_LOG_WARN("rsc", "Failed to append membership entry for signature %zu", i);
            continue;
        }
    }
    
    // Genesis block establishes the initial validator set — skip quorum check.
    // All pending genesis members are included as membership entries regardless
    // of how many responded to the sign request.
    MXD_LOG_INFO("rsc", "Genesis block has %u membership entries from %zu collected signatures",
                 genesis_block.rapid_membership_count, collected_signature_count);
    
    if (mxd_calculate_block_hash(&genesis_block, genesis_block.block_hash) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to calculate genesis block hash");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    if (mxd_store_block(&genesis_block) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to store genesis block");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Genesis block created successfully with %u validators",
                 genesis_block.rapid_membership_count);
    
    if (mxd_broadcast_block(&genesis_block) != 0) {
        MXD_LOG_WARN("rsc", "Failed to broadcast genesis block to network");
    } else {
        MXD_LOG_INFO("rsc", "Genesis block broadcast to network");
    }
    
    mxd_free_validation_chain(&genesis_block);
    
    return 1;
}

int mxd_rebuild_rapid_table_after_genesis(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!table) {
        return -1;
    }
    
    uint32_t blockchain_height = 0;
    if (mxd_get_blockchain_height(&blockchain_height) != 0 || blockchain_height == 0) {
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Rebuilding rapid table from genesis block");
    return mxd_rebuild_rapid_table_from_blockchain(table, 0, blockchain_height, local_node_id);
}

int mxd_try_create_genesis_block(mxd_rapid_table_t *table, const uint8_t *node_address,
                                  const uint8_t *private_key, const uint8_t *public_key) {
    return mxd_try_coordinate_genesis_block();
}

// Block proposer functions are now declared in mxd_block_proposer.h (included above)

// Forward declarations for mempool functions
extern size_t mxd_get_mempool_size(void);
extern int mxd_get_priority_transactions(void *txs, size_t *tx_count, int min_priority);
extern int mxd_remove_from_mempool(const uint8_t tx_hash[64]);

// Static state for consensus tick
static int consensus_initialized = 0;
static uint8_t consensus_local_address[MXD_ADDR32_LEN] = {0};   // v6: addr32 (was 20)
static uint8_t consensus_local_pubkey[MXD_PUBKEY_MAX_LEN] = {0};
static uint8_t consensus_local_privkey[MXD_PRIVKEY_MAX_LEN] = {0};
static uint8_t consensus_algo_id = 0;
static uint32_t last_proposed_height = 0;

// Active validation tracking for skip timeout
static mxd_validation_context_t g_proposer_val_context;
static mxd_validation_context_t *g_active_val_ctx = NULL;
static mxd_block_t *g_active_val_block = NULL;
static const mxd_rapid_table_t *g_active_val_table = NULL;
static pthread_mutex_t g_active_val_mutex = PTHREAD_MUTEX_INITIALIZER;

// Finalization tracking: gate next proposal on previous block reaching quorum
static uint32_t last_finalized_height = 0;
static pthread_mutex_t finalized_height_mutex = PTHREAD_MUTEX_INITIALIZER;

static void set_finalized_height(uint32_t height) {
    pthread_mutex_lock(&finalized_height_mutex);
    if (height > last_finalized_height) {
        last_finalized_height = height;
        MXD_LOG_INFO("rsc", "Block %u finalized (quorum reached)", height);
    }
    pthread_mutex_unlock(&finalized_height_mutex);

    // Clear active validation tracking on finalization
    pthread_mutex_lock(&g_active_val_mutex);
    g_active_val_ctx = NULL;
    g_active_val_block = NULL;
    g_active_val_table = NULL;
    pthread_mutex_unlock(&g_active_val_mutex);
}

static uint32_t get_finalized_height(void) {
    pthread_mutex_lock(&finalized_height_mutex);
    uint32_t h = last_finalized_height;
    pthread_mutex_unlock(&finalized_height_mutex);
    return h;
}

// Public wrapper for external callers (sync path)
void mxd_set_finalized_height_external(uint32_t height) {
    set_finalized_height(height);
}

// Accessor functions for local validator credentials (used by sync module for signing)
const uint8_t* mxd_get_local_address(void) {
    return consensus_initialized ? consensus_local_address : NULL;
}

const uint8_t* mxd_get_local_privkey(void) {
    return consensus_initialized ? consensus_local_privkey : NULL;
}

const uint8_t* mxd_get_local_pubkey(void) {
    return consensus_initialized ? consensus_local_pubkey : NULL;
}

uint8_t mxd_get_local_algo_id(void) {
    return consensus_algo_id;
}

// Compute deterministic proposer index from previous block hash and target height.
// v7 cascade (L6-2): hash family switched from SHA-256 to SHA-512 to align with
// the rest of the protocol. Output shape unchanged — still first 4 bytes mod
// validator_count; consensus-critical, every v7 peer must compute the same value.
// SHA-512(prev_block_hash(64) || height_be(4)) -> first 4 bytes as index.
static uint32_t mxd_compute_proposer_index(const uint8_t prev_block_hash[64],
                                            uint32_t height,
                                            uint32_t validator_count) {
    if (validator_count == 0) return 0;

    uint8_t input[68];
    memcpy(input, prev_block_hash, 64);
    uint32_t h_be = htonl(height);
    memcpy(input + 64, &h_be, 4);

    uint8_t hash[64];
    mxd_sha512(input, 68, hash);

    uint32_t raw_index = ((uint32_t)hash[0] << 24) |
                         ((uint32_t)hash[1] << 16) |
                         ((uint32_t)hash[2] << 8)  |
                         ((uint32_t)hash[3]);

    return raw_index % validator_count;
}

// Check if this node is the proposer for the given height
// Primary proposer = validators[height % validator_count]
// After MXD_PROPOSER_TIMEOUT_MS, allows 1 fallback proposer to prevent permanent stalls
int mxd_is_proposer_for_height(const mxd_rapid_table_t *table, const uint8_t *local_address,
                                uint32_t height, const uint8_t *prev_block_hash) {
    if (!table || !local_address || table->count == 0) {
        return 0;
    }

    uint32_t primary_index;
    if (prev_block_hash) {
        // v5: deterministic from on-chain data
        primary_index = mxd_compute_proposer_index(prev_block_hash, height, table->count);
    } else {
        // Pre-v5 fallback
        primary_index = height % table->count;
    }

    // Check primary proposer (always allowed, no timeout needed) — v6: addr32
    if (table->nodes[primary_index] &&
        memcmp(local_address, table->nodes[primary_index]->node_address, 32) == 0) {
        MXD_LOG_INFO("rsc", "This node is PRIMARY proposer for height %u (index %u of %zu validators)",
                     height, primary_index, table->count);
        return 1;
    }

    // After timeout, allow fallback proposers to prevent permanent chain stalls.
    // At each retry, exactly ONE validator is eligible — the one at cycle_offset
    // positions past primary. Cycle_offset is retry_count mod table->count, which
    // guarantees no wrap-around duplicates (a previous version iterated r=1..9 with
    // modular wrap, causing every validator to match at retry >= table->count and
    // creating simultaneous-proposer forks). After a full cycle the retry counter
    // resets in mxd_increment_retry_count, and the primary gets another chance.
    uint32_t retry_count = mxd_get_timeout_retry_count();
    uint32_t max_fallbacks = (table->count > 1) ? (table->count - 1) : 0;
    if (max_fallbacks > MXD_MAX_FALLBACK_RETRIES) {
        max_fallbacks = MXD_MAX_FALLBACK_RETRIES;
    }
    uint32_t cycle_offset = (table->count > 0) ? (retry_count % table->count) : 0;
    if (cycle_offset >= 1 && cycle_offset <= max_fallbacks) {
        uint32_t fallback_index = (primary_index + cycle_offset) % table->count;
        if (table->nodes[fallback_index] &&
            memcmp(local_address, table->nodes[fallback_index]->node_address, 32) == 0) {   // v6: addr32
            MXD_LOG_INFO("rsc", "This node is FALLBACK #%u proposer for height %u (index %u of %zu validators)",
                         cycle_offset, height, fallback_index, table->count);
            return 1;
        }
    }

    return 0;
}

// Post-genesis consensus tick - drives block production after genesis
int mxd_consensus_tick(mxd_rapid_table_t *table, const uint8_t *local_address,
                       const uint8_t *local_pubkey, const uint8_t *local_privkey, uint8_t algo_id) {
    if (!table || !local_address || !local_pubkey || !local_privkey) {
        return -1;
    }

    // Cannot do consensus with no validators
    if (table->count == 0) {
        return 0;
    }
    
    // Get current blockchain height
    // Note: mxd_get_blockchain_height returns "number of blocks" (not "highest height")
    // So after genesis (height 0), it returns 1. The next block to produce is at that height.
    uint32_t block_count = 0;
    if (mxd_get_blockchain_height(&block_count) != 0) {
        // No height stored - check if genesis exists
        mxd_block_t genesis_check;
        if (mxd_retrieve_block_by_height(0, &genesis_check) != 0) {
            return 0; // No genesis, nothing to do
        }
        mxd_free_block(&genesis_check);
        block_count = 1; // Genesis exists, so we have 1 block
    }

    // Initialize consensus state if needed
    if (!consensus_initialized) {
        memcpy(consensus_local_address, local_address, MXD_ADDR32_LEN);   // v6: addr32 (was 20)
        memcpy(consensus_local_pubkey, local_pubkey, mxd_sig_pubkey_len(algo_id));
        memcpy(consensus_local_privkey, local_privkey, mxd_sig_privkey_len(algo_id));
        consensus_algo_id = algo_id;

        if (mxd_init_block_proposer(local_address) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to initialize block proposer");
            return -1;
        }

        consensus_initialized = 1;
        // Initialize finalized height to current chain tip (all existing blocks are finalized)
        set_finalized_height(block_count > 0 ? block_count - 1 : 0);
        MXD_LOG_INFO("rsc", "Consensus tick initialized for post-genesis operation");
    }

    // next_height is the height of the block we want to produce
    // block_count = number of existing blocks, so next_height = block_count
    uint32_t next_height = block_count;
    uint32_t latest_height = block_count - 1;  // Height of the most recent block

    // Get current block being proposed (if any)
    mxd_block_t *current_block = (mxd_block_t *)mxd_get_current_block();

    // Debug: log consensus tick state periodically (every 10 seconds)
    {
        static uint64_t last_tick_debug = 0;
        uint64_t now_debug = mxd_now_ms();
        if (now_debug - last_tick_debug >= 10000) {
            last_tick_debug = now_debug;
            uint32_t pidx = (table->count > 0) ? (next_height % table->count) : 0;
            char local_hex[65] = {0}, expected_hex[65] = {0};   // v6: addr32 (was 41)
            for (int i = 0; i < 32; i++) snprintf(&local_hex[i*2], 3, "%02x", local_address[i]);
            if (table->count > 0 && table->nodes[pidx]) {
                for (int i = 0; i < 32; i++) snprintf(&expected_hex[i*2], 3, "%02x", table->nodes[pidx]->node_address[i]);
            }
            uint32_t retries = mxd_get_timeout_retry_count();
            MXD_LOG_INFO("rsc", "Consensus tick debug: next_height=%u, table_count=%zu, proposer_idx=%u, local=%s, expected=%s, last_proposed=%u, retries=%u",
                         next_height, table->count, pidx, local_hex, expected_hex, last_proposed_height, retries);
        }
    }

    // Timeout tracking: if we're not proposing and no block is being built,
    // track how long we've been waiting for the current height's proposer.
    // After MXD_PROPOSER_TIMEOUT_MS (30s), allow fallback proposers.
    if (!current_block && next_height > last_proposed_height) {
        uint32_t timeout_height = mxd_get_timeout_height();
        if (timeout_height != next_height) {
            // Start tracking timeout for this new height
            uint32_t pidx = next_height % table->count;
            const uint8_t *expected = (table->nodes[pidx]) ? table->nodes[pidx]->node_address : local_address;
            mxd_start_height_timeout(next_height, expected);
        } else if (mxd_check_timeout_expired()) {
            // Always increment — increment handles wrap-back to 0 internally
            // when it exceeds MXD_MAX_FALLBACK_RETRIES, ensuring liveness.
            uint32_t new_retry = mxd_increment_retry_count();
            MXD_LOG_WARN("rsc", "Proposer timeout expired for height %u, activating fallback #%u",
                         next_height, new_retry);
        }
    }

    // Get prev block hash for v5 proposer selection
    // Use latest_stored_height (not current_height) to handle non-contiguous storage
    const uint8_t *prev_hash_for_proposer = NULL;
    mxd_block_t prev_for_proposer;
    int prev_loaded = 0;
    {
        memset(&prev_for_proposer, 0, sizeof(prev_for_proposer));
        mxd_activation_heights_t act = mxd_get_activation_heights(mxd_get_network_type());

        // Try latest_stored_height first (always reflects highest block stored)
        uint32_t best_height = latest_height;
        uint32_t stored_height = 0;
        if (mxd_get_latest_stored_height(&stored_height) == 0 && stored_height > 0) {
            uint32_t actual_latest = stored_height - 1;  // stored_height is count, latest is count-1
            if (actual_latest > best_height) {
                best_height = actual_latest;
            }
        }

        if (best_height >= act.v5_activation_height) {
            if (mxd_retrieve_block_by_height(best_height, &prev_for_proposer) == 0) {
                prev_hash_for_proposer = prev_for_proposer.block_hash;
                prev_loaded = 1;
                // Update next_height to match actual chain tip
                if (best_height + 1 > next_height) {
                    next_height = best_height + 1;
                    latest_height = best_height;
                }
            }
        }
    }

    // Check if we're the proposer for the next block (primary or fallback after timeout)
    int is_proposer = mxd_is_proposer_for_height(table, local_address, next_height, prev_hash_for_proposer);

    if (prev_loaded) {
        mxd_free_block(&prev_for_proposer);
    }

    // Log proposal conditions
    if (is_proposer) {
        MXD_LOG_INFO("rsc", "Proposer check: current_block=%p, next_height=%u, last_proposed=%u, will_propose=%s",
                     (void*)current_block, next_height, last_proposed_height,
                     (!current_block && next_height > last_proposed_height) ? "YES" : "NO");
    }

    // Finalization tracking (metrics only — does NOT gate block proposal).
    // Blocking on finalization gives a minority veto to halt the chain.
    // Instead, we track finalization for health monitoring and scoring.
    // The chain continues producing blocks regardless of previous block's quorum status.

    if (is_proposer && !current_block && next_height > last_proposed_height) {
        // Only propose blocks when there are transactions to include.
        // This keeps the chain dormant when there's no activity, saving storage
        // and making block height meaningful (every block has real transactions).
        size_t pending_txs_count = mxd_get_mempool_size() + mxd_pending_bridge_count();
        if (pending_txs_count == 0) {
            return 0;  // Nothing to do — wait for transactions
        }

        // Start a new block proposal
        mxd_block_t latest_block;
        memset(&latest_block, 0, sizeof(latest_block));

        if (mxd_retrieve_block_by_height(latest_height, &latest_block) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to retrieve latest block at height %u for proposal", latest_height);
            return -1;
        }

        if (mxd_start_block_proposal(latest_block.block_hash, next_height) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to start block proposal at height %u", next_height);
            mxd_free_block(&latest_block);
            return -1;
        }

        last_proposed_height = next_height;
        mxd_free_block(&latest_block);

        MXD_LOG_INFO("rsc", "Started block proposal for height %u", next_height);
        current_block = (mxd_block_t *)mxd_get_current_block();
    }
    
    // If we have an active proposal, try to add transactions from mempool
    if (current_block && !current_block->transaction_set_frozen) {
        size_t mempool_size = mxd_get_mempool_size();
        if (mempool_size > 0) {
            // Add up to 100 transactions per tick
            size_t max_txs = mempool_size < 100 ? mempool_size : 100;
            mxd_transaction_t *pending_txs = calloc(max_txs, sizeof(mxd_transaction_t));
            if (pending_txs) {
                size_t tx_count = max_txs;
                if (mxd_get_priority_transactions(pending_txs, &tx_count, 0) == 0 && tx_count > 0) {
                    MXD_LOG_INFO("rsc", "Adding %zu transactions from mempool to block", tx_count);
                    for (size_t i = 0; i < tx_count; i++) {
                        if (mxd_add_transaction_to_block(&pending_txs[i]) == 0) {
                            // Remove from mempool after successful inclusion
                            mxd_remove_from_mempool(pending_txs[i].tx_hash);
                            MXD_LOG_DEBUG("rsc", "Added transaction %zu to block", i);
                        } else {
                            MXD_LOG_WARN("rsc", "Failed to add transaction %zu to block", i);
                        }
                        mxd_free_transaction(&pending_txs[i]);
                    }
                }
                free(pending_txs);
            }
        }

        // Add pending bridge mint v3 transactions to block
        {
            size_t bridge_count = mxd_pending_bridge_count();
            if (bridge_count > 0) {
                size_t max_bridge = bridge_count < 16 ? bridge_count : 16;
                mxd_transaction_v3_t *bridge_txs = calloc(max_bridge, sizeof(mxd_transaction_v3_t));
                if (bridge_txs) {
                    size_t dequeued = 0;
                    if (mxd_dequeue_bridge_mints(bridge_txs, max_bridge, &dequeued) == 0 && dequeued > 0) {
                        MXD_LOG_INFO("rsc", "Adding %zu bridge mint transactions to block", dequeued);
                        for (size_t i = 0; i < dequeued; i++) {
                            if (mxd_add_transaction_v3_to_block(&bridge_txs[i]) == 0) {
                                MXD_LOG_INFO("rsc", "Bridge mint tx added to block");
                            } else {
                                MXD_LOG_WARN("rsc", "Failed to add bridge mint tx to block, re-queueing");
                                mxd_queue_bridge_mint(&bridge_txs[i]);
                            }
                            mxd_free_transaction_v3(&bridge_txs[i]);
                        }
                    }
                    free(bridge_txs);
                }
            }
        }

        // Process pending validator join requests
        // SECURITY: Requests are returned as a deep copy to prevent TOCTOU (Issue #3)
        mxd_validator_join_request_t *requests = NULL;
        size_t request_count = 0;

        if (mxd_get_pending_join_requests(&requests, &request_count) == 0 && request_count > 0) {
            MXD_LOG_INFO("rsc", "Processing %zu validator join requests", request_count);

            for (size_t i = 0; i < request_count; i++) {
                // Validate request against current total supply
                if (mxd_validate_join_request(&requests[i], current_block->total_supply) != 0) {
                    continue;
                }

                // Check not already in validator set
                int already_validator = 0;
                for (size_t j = 0; j < table->count; j++) {
                    if (memcmp(table->nodes[j]->node_address, requests[i].node_address, 32) == 0) {   // v6: addr32
                        already_validator = 1;
                        break;
                    }
                }

                if (already_validator) {
                    continue;
                }

                // Add to block membership
                if (mxd_append_membership_entry(current_block,
                                               requests[i].node_address,
                                               requests[i].algo_id,
                                               requests[i].public_key,
                                               requests[i].public_key_length,
                                               requests[i].signature,
                                               requests[i].signature_length,
                                               requests[i].timestamp) == 0) {
                    MXD_LOG_INFO("rsc", "Added validator %02x%02x...%02x%02x to block membership",
                                requests[i].node_address[0], requests[i].node_address[1],
                                requests[i].node_address[18], requests[i].node_address[19]);
                }
            }

            // Free the deep copy (SECURITY: Issue #3)
            free(requests);
        }
    }

    // Check if block should be closed
    if (current_block && mxd_should_close_block()) {
        // For v4+ blocks, compute and embed validator scores before freeze
        if (current_block->version >= 4 && !current_block->validator_scores) {
            mxd_block_t prev_block;
            memset(&prev_block, 0, sizeof(prev_block));
            if (mxd_retrieve_block_by_height(current_block->height - 1, &prev_block) == 0) {
                mxd_validator_score_entry_t *scores = NULL;
                uint32_t score_count = 0;
                if (mxd_compute_block_validator_scores(&prev_block, table, &scores, &score_count) == 0) {
                    current_block->validator_scores = scores;
                    current_block->validator_scores_count = score_count;
                    current_block->validator_scores_capacity = score_count;
                    MXD_LOG_INFO("rsc", "Embedded %u validator score entries in block %u",
                                score_count, current_block->height);
                } else {
                    MXD_LOG_ERROR("rsc", "Failed to compute validator scores for block %u",
                                 current_block->height);
                }
                mxd_free_block(&prev_block);
            } else {
                MXD_LOG_ERROR("rsc", "Failed to retrieve prev block for score computation at height %u",
                             current_block->height);
            }
        }

        if (mxd_close_block() != 0) {
            MXD_LOG_ERROR("rsc", "Failed to close block");
            goto block_finalize_cleanup;
        }

        // After close_block, the transaction set is frozen and cannot be reopened.
        // If any subsequent step fails, we MUST still stop the proposal to avoid
        // a permanent stall where current_block stays non-NULL forever.
        int finalize_ok = 0;

        // v5+: compute next_proposer from prev_block_hash (the PREVIOUS block, not this one)
        // next_proposer = who should propose block at (current_height + 1)
        // Derived from: SHA256(this_block's_prev_hash || height+1)
        {
            mxd_activation_heights_t act = mxd_get_activation_heights(mxd_get_network_type());
            if (current_block->version >= 5 || current_block->height >= act.v5_activation_height) {
                current_block->version = (current_block->version < 5) ? 5 : current_block->version;
                if (table->count > 0) {
                    uint32_t next_idx = mxd_compute_proposer_index(
                        current_block->prev_block_hash, current_block->height + 1, table->count);
                    // v6: addr32 — copy 32 bytes from table->nodes[].node_address.
                    if (table->nodes[next_idx]) {
                        memcpy(current_block->next_proposer, table->nodes[next_idx]->node_address, 32);
                    } else {
                        memset(current_block->next_proposer, 0, 32);
                    }
                }
            }
        }

        // Calculate block hash
        if (mxd_calculate_block_hash(current_block, current_block->block_hash) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to calculate block hash");
            goto block_finalize_cleanup;
        }

        // Sign the block as proposer (position 0) using chain_hash format
        {
            uint64_t timestamp = mxd_now_ms();
            uint8_t signature[MXD_SIGNATURE_MAX];
            size_t sig_len = sizeof(signature);

            // chain_hash_0 = SHA-512(block_hash) for position 0
            uint8_t chain_hash_0[64];
            mxd_compute_chain_hash(current_block, 0, chain_hash_0);

            // v7 cascade (L6-5): MXD-CONS-1 (11) || block_hash(64) || chain_hash(64) || ts_be(8)
            uint8_t sign_msg[MXD_DOMAIN_TAG_CONS_LEN + 64 + 64 + 8];
            size_t smo = 0;
            memcpy(sign_msg + smo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); smo += MXD_DOMAIN_TAG_CONS_LEN;
            memcpy(sign_msg + smo, current_block->block_hash, 64); smo += 64;
            memcpy(sign_msg + smo, chain_hash_0, 64); smo += 64;
            uint64_t ts_be = mxd_htonll(timestamp);
            memcpy(sign_msg + smo, &ts_be, 8); smo += 8;

            if (mxd_sig_sign(algo_id, signature, &sig_len, sign_msg, sizeof(sign_msg), local_privkey) != 0) {
                MXD_LOG_ERROR("rsc", "Failed to sign block");
                goto block_finalize_cleanup;
            }

            if (mxd_add_validator_signature(current_block, local_address, timestamp, algo_id,
                                            signature, (uint16_t)sig_len) != 0) {
                MXD_LOG_ERROR("rsc", "Failed to add proposer signature to block");
                goto block_finalize_cleanup;
            }
        }

        // Compute total_supply before storing so it's correct from the start.
        // total_supply is NOT part of the block hash, so setting it here is safe.
        {
            int64_t supply_delta = 0;
            mxd_apply_block_transactions(current_block, &supply_delta);
            if (current_block->height > 0) {
                mxd_block_t prev;
                memset(&prev, 0, sizeof(prev));
                if (mxd_retrieve_block_by_height(current_block->height - 1, &prev) == 0) {
                    current_block->total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                    mxd_free_block(&prev);
                }
            } else {
                current_block->total_supply = (uint64_t)supply_delta;
            }
        }

        // Store the block
        if (mxd_store_block(current_block) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to store proposed block");
            goto block_finalize_cleanup;
        }

        // Forward-propagate supply to any subsequent blocks stored with supply=0
        if (current_block->total_supply > 0) {
            mxd_propagate_supply_forward(current_block->height, current_block->total_supply);
        }

        MXD_LOG_INFO("rsc", "Block at height %u closed, signed, and stored with %u transactions (supply=%llu)",
                     current_block->height, current_block->transaction_count,
                     (unsigned long long)current_block->total_supply);

        // Broadcast the block to the network
        if (mxd_broadcast_block(current_block) != 0) {
            MXD_LOG_WARN("rsc", "Failed to broadcast block at height %u", current_block->height);
        } else {
            MXD_LOG_INFO("rsc", "Block at height %u broadcast to network", current_block->height);
        }

        // Update chain-derived deterministic scoring after block finalization
        if (current_block->version >= 4 && current_block->validator_scores) {
            mxd_load_scores_from_block((mxd_rapid_table_t *)table, current_block);
        } else {
            mxd_accumulate_block_stats((mxd_rapid_table_t *)table, current_block);
        }
        mxd_compute_chain_scores((mxd_rapid_table_t *)table);
        mxd_sort_rapid_table_by_score((mxd_rapid_table_t *)table);

        // Check eviction (own block — fallback proposer case)
        mxd_check_proposer_miss((mxd_rapid_table_t *)table, current_block);

        // Register active validation for skip timeout monitoring.
        // Initialize the file-scope validation context so it outlives mxd_stop_block_proposal().
        {
            memset(&g_proposer_val_context, 0, sizeof(g_proposer_val_context));
            g_proposer_val_context.height = current_block->height;
            memcpy(g_proposer_val_context.block_hash, current_block->block_hash, 64);
            memcpy(g_proposer_val_context.proposer_id, local_address, 32);   // v6: addr32
            g_proposer_val_context.status = MXD_VALIDATION_IN_PROGRESS;
            g_proposer_val_context.signature_count = current_block->validation_count;
            g_proposer_val_context.required_signatures = (uint32_t)((table->count * 2 + 2) / 3);
            g_proposer_val_context.start_time = mxd_now_ms();
            g_proposer_val_context.expiry_time = g_proposer_val_context.start_time + 300000; // 5 min

            // Find the next validator to wait for (v6: addr32)
            uint8_t next_val[32];
            if (mxd_get_next_validator(current_block, table, next_val) == 0) {
                memcpy(g_proposer_val_context.waiting_for_validator, next_val, 32);
                g_proposer_val_context.waiting_since = mxd_now_ms();
            }

            pthread_mutex_lock(&g_active_val_mutex);
            g_active_val_ctx = &g_proposer_val_context;
            g_active_val_block = current_block;  // still valid until mxd_stop_block_proposal
            g_active_val_table = table;
            pthread_mutex_unlock(&g_active_val_mutex);
        }

        finalize_ok = 1;

    block_finalize_cleanup:
        // Always stop the proposal after close_block to prevent permanent stall
        // NOTE: This frees the block. The skip timeout will only operate while
        // g_active_val_block is still valid (cleared on finalization).
        mxd_stop_block_proposal();

        return finalize_ok ? 1 : -1;
    }

    // v5+: Check for validator sign timeout (skip unresponsive validators)
    {
        mxd_activation_heights_t heights = mxd_get_activation_heights(mxd_get_network_type());
        uint32_t current_height = 0;
        mxd_get_blockchain_height(&current_height);

        if (current_height >= heights.v5_activation_height) {
            pthread_mutex_lock(&g_active_val_mutex);
            if (g_active_val_ctx && g_active_val_block && g_active_val_table &&
                g_active_val_ctx->status == MXD_VALIDATION_IN_PROGRESS &&
                g_active_val_ctx->waiting_since > 0) {

                uint64_t now = mxd_now_ms();
                if (now - g_active_val_ctx->waiting_since >= MXD_VALIDATOR_SIGN_TIMEOUT_MS) {
                    // Record the skip (v6: addr32)
                    if (g_active_val_ctx->skip_count < 50) {
                        memcpy(g_active_val_ctx->skipped_validators[g_active_val_ctx->skip_count],
                               g_active_val_ctx->waiting_for_validator, 32);
                        g_active_val_ctx->skip_count++;
                    }

                    char skip_hex[65] = {0};   // v6: 64 hex chars + NUL
                    for (int si = 0; si < 32; si++)
                        snprintf(&skip_hex[si*2], 3, "%02x", g_active_val_ctx->waiting_for_validator[si]);
                    MXD_LOG_WARN("rsc", "Validator %s sign timeout (%u ms), skipping (skip #%u)",
                                 skip_hex, MXD_VALIDATOR_SIGN_TIMEOUT_MS, g_active_val_ctx->skip_count);

                    // Find next non-skipped, non-signed validator (v6: node_address is addr32)
                    int found_next = 0;
                    for (size_t vi = 0; vi < g_active_val_table->count; vi++) {
                        const uint8_t *candidate = g_active_val_table->nodes[vi]->node_address;

                        // Skip if already signed (v6: addr32 compare; sig->validator_id is 32 bytes)
                        int already_signed = 0;
                        for (uint32_t sv = 0; sv < g_active_val_block->validation_count; sv++) {
                            if (memcmp(g_active_val_block->validation_chain[sv].validator_id, candidate, 32) == 0) {
                                already_signed = 1;
                                break;
                            }
                        }
                        if (already_signed) continue;

                        // Skip if in skipped list
                        int was_skipped = 0;
                        for (uint32_t sk = 0; sk < g_active_val_ctx->skip_count; sk++) {
                            if (memcmp(g_active_val_ctx->skipped_validators[sk], candidate, 32) == 0) {
                                was_skipped = 1;
                                break;
                            }
                        }
                        if (was_skipped) continue;

                        // Found a valid next validator (v6: addr32)
                        memcpy(g_active_val_ctx->waiting_for_validator, candidate, MXD_ADDR32_LEN);
                        g_active_val_ctx->waiting_since = now;
                        found_next = 1;

                        char next_hex[65] = {0};   // v6: addr32 (was 41)
                        for (int ni = 0; ni < MXD_ADDR32_LEN; ni++)
                            snprintf(&next_hex[ni*2], 3, "%02x", candidate[ni]);
                        MXD_LOG_INFO("rsc", "Validation chain advancing to validator %s", next_hex);
                        break;
                    }

                    if (!found_next) {
                        // All validators either signed or skipped
                        g_active_val_ctx->waiting_since = 0;
                        MXD_LOG_INFO("rsc", "All validators attempted (%u signed, %u skipped)",
                                     g_active_val_block->validation_count, g_active_val_ctx->skip_count);
                    }
                }
            }
            pthread_mutex_unlock(&g_active_val_mutex);
        }
    }

    return 0;
}
