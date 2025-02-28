#include "../include/mxd_metrics.h"
#include "../include/blockchain/mxd_metrics_internal.h"
#include "../include/mxd_ntp.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

// Initialize node metrics
int mxd_init_metrics(mxd_node_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }

    metrics->avg_response_time = 0;
    metrics->min_response_time = UINT64_MAX;
    metrics->max_response_time = 0;
    metrics->response_count = 0;
    metrics->message_success = 0;
    metrics->message_total = 0;
    metrics->reliability_score = 0.0;
    metrics->performance_score = 0.0;
    metrics->last_update = 0;
    metrics->peer_count = 0;  // Initialize peer count

    return 0;
}

// Update node metrics with new response time
int mxd_update_metrics(mxd_node_metrics_t *metrics, uint64_t response_time) {
    if (!metrics || response_time > MXD_MAX_RESPONSE_TIME) {
        return -1;
    }

    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        return -1;
    }

    // Update response time statistics
    metrics->response_count++;
    double old_avg = metrics->avg_response_time;
    metrics->avg_response_time = old_avg + (response_time - old_avg) / metrics->response_count;
    
    if (response_time < metrics->min_response_time) {
        metrics->min_response_time = response_time;
    }
    if (response_time > metrics->max_response_time) {
        metrics->max_response_time = response_time;
    }

    metrics->last_update = current_time;
    return 0;
}

// Record message success/failure
int mxd_record_message_result(mxd_node_metrics_t *metrics, int success) {
    if (!metrics) {
        return -1;
    }

    metrics->message_total++;
    if (success) {
        metrics->message_success++;
    }

    // Update reliability score
    metrics->reliability_score = calculate_reliability_score(
        metrics->message_success, 
        metrics->message_total
    );

    return 0;
}

// Calculate reliability score (0.0 to 1.0)
double calculate_reliability_score(uint32_t success, uint32_t total) {
    if (total < MXD_MIN_RESPONSE_COUNT) {
        return 0.0;
    }

    double success_rate = (double)success / total;
    if (success_rate < MXD_MIN_SUCCESS_RATE) {
        return 0.0;
    }

    return success_rate;
}

// Calculate node performance score
double mxd_calculate_score(const mxd_node_metrics_t *metrics, double stake) {
    if (!metrics || stake <= 0.0) {
        return 0.0;
    }

    // Response time score (lower is better)
    double response_score = 1.0;
    if (metrics->response_count >= MXD_MIN_RESPONSE_COUNT) {
        response_score = 1.0 - (metrics->avg_response_time / (double)MXD_MAX_RESPONSE_TIME);
        if (response_score < 0.0) response_score = 0.0;
    }

    // Message success rate score
    double success_score = calculate_reliability_score(
        metrics->message_success,
        metrics->message_total
    );

    // Normalize stake to 0.0-1.0 range (assuming max stake of 100)
    double stake_score = stake / 100.0;
    if (stake_score > 1.0) stake_score = 1.0;

    // Calculate weighted score
    double total_score = (response_score * MXD_RESPONSE_WEIGHT) +
                        (success_score * MXD_SUCCESS_WEIGHT) +
                        (stake_score * MXD_STAKE_WEIGHT);

    return total_score;
}

// Get node reliability score
double mxd_get_reliability(const mxd_node_metrics_t *metrics) {
    if (!metrics) {
        return 0.0;
    }
    return metrics->reliability_score;
}

// Check if node meets minimum performance requirements
int mxd_validate_performance(const mxd_node_metrics_t *metrics) {
    if (!metrics) {
        return 0;
    }

    // Must have minimum number of responses
    if (metrics->response_count < MXD_MIN_RESPONSE_COUNT) {
        return 0;
    }

    // Must meet minimum success rate
    if (metrics->reliability_score < MXD_MIN_SUCCESS_RATE) {
        return 0;
    }

    // Must have recent activity
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) != 0) {
        return 0;
    }

    if (current_time - metrics->last_update > MXD_RELIABILITY_WINDOW) {
        return 0;
    }

    return 1;
}

// Get formatted metrics string for logging
int mxd_format_metrics(const mxd_node_metrics_t *metrics, char *buffer, size_t size) {
    if (!metrics || !buffer || size == 0) {
        return -1;
    }

    return snprintf(buffer, size,
        "Response Time (avg/min/max): %lu/%lu/%lu ms, "
        "Messages (success/total): %u/%u, "
        "Peers: %zu, "
        "Reliability: %.2f, Performance: %.2f",
        metrics->avg_response_time,
        metrics->min_response_time,
        metrics->max_response_time,
        metrics->message_success,
        metrics->message_total,
        metrics->peer_count,
        metrics->reliability_score,
        metrics->performance_score
    );
}
