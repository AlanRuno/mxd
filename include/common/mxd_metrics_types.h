#ifndef MXD_METRICS_TYPES_H
#define MXD_METRICS_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "mxd_types.h"

// Node performance metrics
typedef struct {
    uint64_t avg_response_time;    // Average response time in milliseconds
    uint64_t min_response_time;    // Minimum response time observed
    uint64_t max_response_time;    // Maximum response time observed
    uint32_t response_count;       // Number of responses recorded
    uint32_t message_success;      // Successful message count
    uint32_t message_total;        // Total message count
    double reliability_score;      // 0.0 to 1.0 reliability rating
    double performance_score;      // Combined performance metric
    uint64_t last_update;         // NTP synchronized timestamp
    mxd_amount_t tip_share;       // Node's share of voluntary tips (in base units)
    size_t peer_count;           // Number of connected peers
} mxd_node_metrics_t;

// Node stake information
typedef struct {
    char node_id[64];
    mxd_amount_t stake_amount;    // Stake amount in base units
    uint8_t node_address[32];     // v6: addr32 (was [20])
    mxd_node_metrics_t metrics;
    uint32_t rank;
    uint8_t active;
    uint8_t in_rapid_table;
    uint32_t rapid_table_position;
    uint32_t consecutive_misses;  // Consecutive round-robin misses (for eviction)
    // Chain-derived deterministic scoring fields
    uint32_t blocks_proposed;      // Blocks where this validator was proposer
    uint32_t blocks_signed;        // Blocks where this validator appears in validation chain
    uint64_t total_latency_ms;     // Cumulative (sig_timestamp - block_timestamp) for latency avg
    uint32_t blocks_since_joined;  // Number of blocks processed since this node joined the table
    uint64_t chain_score;          // Deterministic composite score (0-10000)
    uint64_t added_at_block_time_ms;  // v8+: block timestamp (ms) when this node was added to
                                      // the rapid_table. Used by the EVICT grace-period rule —
                                      // a node added within the last 5 min is protected. 0 for
                                      // genesis validators (no grace needed, they've always been here).
} mxd_node_stake_t;

#ifdef __cplusplus
}
#endif

#endif // MXD_METRICS_TYPES_H
