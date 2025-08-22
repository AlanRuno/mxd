#include "../../include/mxd_rsc.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_blockchain_db.h"
#include "../../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <rocksdb/c.h>

// Performance thresholds
#define MXD_MAX_RESPONSE_TIME 5000     // Maximum acceptable response time (ms)
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses needed for ranking
#define MXD_INACTIVE_THRESHOLD 300000  // Node considered inactive after 5 minutes
#define MXD_RELIABILITY_WEIGHT 0.3     // Weight for reliability in ranking
#define MXD_SPEED_WEIGHT 0.4           // Weight for speed in ranking
#define MXD_STAKE_WEIGHT 0.3           // Weight for stake in ranking

// Validation chain thresholds
#define MXD_MIN_RELAY_SIGNATURES 3     // Minimum signatures required for relay (X=3)
#define MXD_VALIDATION_EXPIRY 5        // Validation signatures expire after 5 blocks
#define MXD_BLACKLIST_DURATION 100     // Default blacklist duration (in blocks)
#define MXD_MAX_TIMESTAMP_DRIFT 60     // Maximum timestamp drift allowed (in seconds)

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
    metrics->tip_share = 0.0;
    metrics->last_update = 0;

    return 0;
}

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake) {
    if (!node || total_stake <= 0) {
        return -1;
    }

    // Calculate stake percentage
    double stake_percent = (node->stake_amount / total_stake) * 100.0;

    // Check minimum stake requirement (0.1%)
    return stake_percent >= 0.1 ? 0 : -1;
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
int mxd_calculate_node_rank(const mxd_node_stake_t *node, double total_stake) {
    if (!node || total_stake <= 0) {
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

    double stake_score = (node->stake_amount / total_stake);
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

// Distribute voluntary tips based on node performance
int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, double total_tip) {
    if (!nodes || node_count == 0 || total_tip <= 0) {
        return -1;
    }

    // Calculate total rank points of active nodes
    uint32_t total_rank = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            total_rank += nodes[i].rank;
        }
    }

    if (total_rank == 0) {
        return -1;
    }

    // Sort nodes by rank (highest to lowest)
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

    // Distribute tips using 50% pattern from whitepaper
    double remaining = total_tip;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            if (i == node_count - 1) {
                // Last active node gets remaining amount
                nodes[i].metrics.tip_share = remaining;
            } else {
                // Each node gets 50% of remaining
                nodes[i].metrics.tip_share = remaining * 0.5;
                remaining -= nodes[i].metrics.tip_share;
            }
        } else {
            nodes[i].metrics.tip_share = 0.0;
        }
    }

    return 0;
}

// Update rapid table entries and recalculate rankings
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, double total_stake) {
    if (!nodes || node_count == 0 || total_stake <= 0) {
        return -1;
    }

    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        return -1;
    }

    // Update node activity status and calculate ranks
    for (size_t i = 0; i < node_count; i++) {
        // Check if node is active based on last update time
        nodes[i].active = (current_time - nodes[i].metrics.last_update) < MXD_INACTIVE_THRESHOLD;
        
        // Calculate new rank
        nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
    }

    // Sort nodes by rank
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

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
    
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    table->last_update = current_time;
    
    return 0;
}

int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node) {
    if (!table || !node || !table->nodes) {
        return -1;
    }
    
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
    
    // Update table timestamp
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    table->last_update = current_time;
    
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
    
    // Update table timestamp
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    table->last_update = current_time;
    
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
    memcpy(context->proposer_id, block->proposer_id, 20);
    context->status = MXD_VALIDATION_PENDING;
    context->signature_count = block->validation_count;
    
    // Calculate required signatures (50% of Rapid Table)
    context->required_signatures = (table->count + 1) / 2;
    
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    context->start_time = current_time;
    
    context->expiry_time = current_time + (5 * 60);
    
    return 0;
}

int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[20], 
                                        uint64_t timestamp, const uint8_t *signature,
                                        uint16_t signature_length, uint32_t chain_position) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    
    if (labs((int64_t)timestamp - (int64_t)current_time) > MXD_MAX_TIMESTAMP_DRIFT) {
        return -1;
    }
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (memcmp(block->validation_chain[i].validator_id, validator_id, 20) == 0) {
            return -1;
        }
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
    memcpy(sig->validator_id, validator_id, 20);
    sig->timestamp = timestamp;
    sig->signature_length = signature_length;
    memcpy(sig->signature, signature, sig->signature_length);
    sig->chain_position = chain_position;
    
    block->validation_count++;
    
    mxd_store_signature(block->height, validator_id, signature, signature_length);
    
    return 0;
}

int mxd_verify_validation_chain_integrity(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return -1;
    }
    
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
    
    return 0;
}

// Check if block has reached validation quorum (≥50% of Rapid Table)
int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table) {
    if (!block || !table) {
        return -1;
    }
    
    // Calculate required signatures (50% of Rapid Table)
    uint32_t required_signatures = (table->count + 1) / 2;
    
    // Check if block has enough signatures
    return (block->validation_count >= required_signatures) ? 1 : 0;
}

// Check if block has minimum signatures for relay (X=3)
int mxd_block_has_min_relay_signatures(const mxd_block_t *block) {
    if (!block) {
        return -1;
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
            if (table->nodes[j] && memcmp(table->nodes[j]->public_key, validator_id, 20) == 0) {
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
int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[20], uint32_t height, 
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
        return 0; // No signatures found
    }
    
    int conflict_found = 0;
    for (size_t i = 0; i < signature_count; i++) {
        if (heights[i] == height) {
            mxd_block_t block;
            memset(&block, 0, sizeof(mxd_block_t));
            
            if (mxd_retrieve_block_by_height(height, &block) == 0) {
                // Check if block hash is different
                if (memcmp(block.block_hash, block_hash, 64) != 0) {
                    conflict_found = 1;
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

int mxd_blacklist_validator(const uint8_t validator_id[20], uint32_t duration) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    // Calculate expiry height
    uint32_t expiry_height = current_height + (duration > 0 ? duration : MXD_BLACKLIST_DURATION);
    
    uint8_t key[10 + 20];
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, 20);
    
    char value[10];
    snprintf(value, sizeof(value), "%u", expiry_height);
    
    if (mxd_init_blockchain_db(NULL) != 0) {
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
    
    MXD_LOG_INFO("rsc", "Validator blacklisted until height %u", expiry_height);
    return 0;
}

// Check if validator is blacklisted
int mxd_is_validator_blacklisted(const uint8_t validator_id[20]) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    uint8_t key[10 + 20];
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, 20);
    
    if (mxd_init_blockchain_db(NULL) != 0) {
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
                          uint8_t next_validator_id[20]) {
    if (!block || !table || !next_validator_id) {
        return -1;
    }
    
    if (block->validation_count == 0) {
        if (table->count == 0) {
            return -1; // No validators in Rapid Table
        }
        
        memcpy(next_validator_id, table->nodes[0]->public_key, 20);
        return 0;
    }
    
    uint32_t last_position = 0;
    int found = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        if (memcmp(table->nodes[i]->public_key, 
                  block->validation_chain[block->validation_count - 1].validator_id, 20) == 0) {
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
    
    memcpy(next_validator_id, table->nodes[next_position]->public_key, 20);
    
    return 0;
}

int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context, 
                                const mxd_rapid_table_t *table) {
    if (!block || !context || !table) {
        return -1;
    }
    
    // Check if validation is already complete
    if (context->status == MXD_VALIDATION_COMPLETE) {
        return 0;
    }
    
    // Check if validation has expired
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = time(NULL);
    }
    
    if (current_time > context->expiry_time) {
        context->status = MXD_VALIDATION_EXPIRED;
        return -1;
    }
    
    // Update signature count
    context->signature_count = block->validation_count;
    
    // Check if block has reached quorum
    if (mxd_block_has_validation_quorum(block, table)) {
        context->status = MXD_VALIDATION_COMPLETE;
        
        mxd_store_block(block);
        
        return 0;
    }
    
    if (mxd_verify_validation_chain_integrity(block) != 0) {
        context->status = MXD_VALIDATION_REJECTED;
        return -1;
    }
    
    uint8_t next_validator_id[20];
    if (mxd_get_next_validator(block, table, next_validator_id) != 0) {
        if (context->signature_count >= context->required_signatures) {
            context->status = MXD_VALIDATION_COMPLETE;
            
            mxd_store_block(block);
            
            return 0;
        } else {
            context->status = MXD_VALIDATION_REJECTED;
            return -1;
        }
    }
    
    // Update status to in progress
    context->status = MXD_VALIDATION_IN_PROGRESS;
    
    return 0;
}
static struct {
    uint8_t id[20];
    uint8_t pub[4096];
    size_t len;
} mxd_pubkey_registry[64];

static size_t mxd_pubkey_registry_count;

int mxd_test_register_validator_pubkey(const uint8_t validator_id[20], const uint8_t *pub, size_t pub_len) {
    if (!validator_id || !pub || pub_len == 0 || pub_len > sizeof(mxd_pubkey_registry[0].pub)) return -1;
    if (mxd_pubkey_registry_count >= 64) return -1;
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].id, validator_id, 20);
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].pub, pub, pub_len);
    mxd_pubkey_registry[mxd_pubkey_registry_count].len = pub_len;
    mxd_pubkey_registry_count++;
    return 0;
}

void mxd_test_clear_validator_pubkeys(void) {
    mxd_pubkey_registry_count = 0;
}

int mxd_get_validator_public_key(const uint8_t validator_id[20], uint8_t *out_key, size_t out_capacity, size_t *out_len) {
    if (!validator_id || !out_key || !out_len) return -1;
    for (size_t i = 0; i < mxd_pubkey_registry_count; i++) {
        if (memcmp(mxd_pubkey_registry[i].id, validator_id, 20) == 0) {
            if (out_capacity < mxd_pubkey_registry[i].len) return -1;
            memcpy(out_key, mxd_pubkey_registry[i].pub, mxd_pubkey_registry[i].len);
            *out_len = mxd_pubkey_registry[i].len;
            return 0;
        }
    }
    return -1;
}
