#include "../../include/mxd_rsc.h"
#include "../../include/mxd_ntp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Performance thresholds
#define MXD_MAX_RESPONSE_TIME 5000    // Maximum acceptable response time (ms)
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses needed for ranking
#define MXD_INACTIVE_THRESHOLD 300000  // Node considered inactive after 5 minutes
#define MXD_RELIABILITY_WEIGHT 0.3     // Weight for reliability in ranking
#define MXD_SPEED_WEIGHT 0.4          // Weight for speed in ranking
#define MXD_STAKE_WEIGHT 0.3          // Weight for stake in ranking

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
