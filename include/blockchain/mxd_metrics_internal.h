#ifndef MXD_METRICS_INTERNAL_H
#define MXD_METRICS_INTERNAL_H

#include "../common/mxd_metrics_types.h"

// Performance thresholds
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses for valid metrics
#define MXD_MAX_RESPONSE_TIME 5000     // Maximum acceptable response time (ms)
#define MXD_MIN_SUCCESS_RATE 0.8       // Minimum message success rate
#define MXD_RELIABILITY_WINDOW 86400   // Time window for reliability (24 hours)

// Scoring weights
#define MXD_RESPONSE_WEIGHT 0.4        // Weight for response time in scoring
#define MXD_SUCCESS_WEIGHT 0.3         // Weight for message success rate
#define MXD_STAKE_WEIGHT 0.3           // Weight for stake amount

// Internal functions
double calculate_reliability_score(uint32_t success, uint32_t total);
double calculate_performance_score(const mxd_node_metrics_t *metrics, double stake);
int update_node_ranking(mxd_node_stake_t *nodes, size_t count);

#endif // MXD_METRICS_INTERNAL_H
