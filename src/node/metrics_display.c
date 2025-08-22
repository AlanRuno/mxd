#include "../include/mxd_logging.h"
#include <time.h>
#include <string.h>
#include "metrics_display.h"

void clear_console(void) {
    MXD_LOG_DEBUG("metrics_display", "Clear console");
}

void display_node_metrics(const mxd_node_metrics_t* metrics, const mxd_node_stake_t* stake) {
    if (!metrics || !stake) {
        MXD_LOG_ERROR("metrics_display", "Invalid metrics or stake data");
        return;
    }

    clear_console();
    
    // Get current timestamp
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
    
    // Calculate TPS from message success rate
    double tps = metrics->message_success;
    
    // Update network status based on metrics
    int is_active = metrics->reliability_score > 0.95 && tps >= 10.0;
    
    MXD_LOG_DEBUG("metrics_display", "TPS=%.2f, Success=%u/%u, Reliability=%.2f, Active=%d", 
                  tps, metrics->message_success, metrics->message_total,
                  metrics->reliability_score, is_active);
    
    // Header
    MXD_LOG_INFO("metrics_display", "=== MXD Node Status === %s", time_str);
    MXD_LOG_INFO("metrics_display", "Node ID: %s", stake->node_id);
    MXD_LOG_INFO("metrics_display", "Stake Amount: %.2f MXD", stake->stake_amount);
    
    // Performance metrics
    MXD_LOG_INFO("metrics_display", "=== Performance ===");
    MXD_LOG_INFO("metrics_display", "Response Time: %lu ms (min: %lu, max: %lu)",
           metrics->avg_response_time,
           metrics->min_response_time,
           metrics->max_response_time);
    MXD_LOG_INFO("metrics_display", "TPS: %.2f (target: \xE2\x89\xA5 10.0)", tps);
    MXD_LOG_INFO("metrics_display", "Messages: %u total", metrics->message_total);
    MXD_LOG_INFO("metrics_display", "Reliability: %.2f%%", metrics->reliability_score * 100.0);
    MXD_LOG_INFO("metrics_display", "Performance Score: %.2f", metrics->performance_score);
    
    // Network status
    MXD_LOG_INFO("metrics_display", "=== Network Position ===");
    MXD_LOG_INFO("metrics_display", "Connected Peers: %zu", metrics->peer_count);
    MXD_LOG_INFO("metrics_display", "Rank: %d", stake->rank);
    MXD_LOG_INFO("metrics_display", "Active: %s", is_active ? "Yes" : "No");
    MXD_LOG_INFO("metrics_display", "Earnings (Tips): %.6f MXD", metrics->tip_share);
    
    // Performance indicators
    MXD_LOG_INFO("metrics_display", "=== Health Indicators ===");
    MXD_LOG_INFO("metrics_display", "Response Time: %s", 
           metrics->avg_response_time < 3000 ? "✓ Good" : "✗ High");
    MXD_LOG_INFO("metrics_display", "Transaction Rate: %s", 
           tps >= 10.0 ? "✓ Good" : "✗ Low");
    MXD_LOG_INFO("metrics_display", "Network Status: %s",
           stake->active ? "✓ Connected" : "✗ Disconnected");
    
    MXD_LOG_INFO("metrics_display", "Press Ctrl+C to exit");
}
