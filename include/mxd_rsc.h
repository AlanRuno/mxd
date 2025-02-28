#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Node performance metrics
typedef struct {
    uint64_t avg_response_time;    // Average response time in milliseconds
    uint64_t min_response_time;    // Minimum response time observed
    uint64_t max_response_time;    // Maximum response time observed
    uint32_t response_count;       // Number of responses recorded
    double tip_share;              // Node's share of distributed tips
    uint64_t last_update;          // Last update timestamp (NTP synchronized)
} mxd_node_metrics_t;

// Node stake information
typedef struct {
    char node_id[64];              // Unique node identifier
    double stake_amount;           // Amount of stake held
    uint8_t public_key[256];       // Node's public key
    mxd_node_metrics_t metrics;    // Node performance metrics
    uint32_t rank;                 // Current node rank
    uint8_t active;                // Node activity status
} mxd_node_stake_t;

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake);

// Initialize node metrics
int mxd_init_node_metrics(mxd_node_metrics_t *metrics);

// Update node response metrics with NTP-synchronized timestamp
int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp);

// Calculate node ranking based on stake, speed, and reliability
int mxd_calculate_node_rank(const mxd_node_stake_t *node, double total_stake);

// Distribute voluntary tips based on node performance
int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, double total_tip);

// Update rapid table entries and recalculate rankings
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, double total_stake);

// Get node performance statistics
int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats);

// Check if node meets minimum performance requirements
int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H
