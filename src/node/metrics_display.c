#include <stdio.h>
#include <time.h>
#include <string.h>
#include "metrics_display.h"

void clear_console(void) {
    printf("\033[2J\033[H");  // ANSI escape codes to clear screen and move cursor to top
}

void display_node_metrics(const mxd_node_metrics_t* metrics, const mxd_node_stake_t* stake) {
    if (!metrics || !stake) {
        printf("Error: Invalid metrics or stake data\n");
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
    
    // Debug metrics
    printf("Debug: Display - TPS=%.2f, Success=%u/%u, Reliability=%.2f, Active=%d\n", 
           tps, metrics->message_success, metrics->message_total,
           metrics->reliability_score, is_active);
    
    // Header
    printf("=== MXD Node Status === %s\n", time_str);
    printf("Node ID: %s\n", stake->node_id);
    printf("Stake Amount: %.2f MXD\n", stake->stake_amount);
    
    // Performance metrics
    printf("\n=== Performance ===\n");
    printf("Response Time: %lu ms (min: %lu, max: %lu)\n",
           metrics->avg_response_time,
           metrics->min_response_time,
           metrics->max_response_time);
    printf("TPS: %.2f (target: ≥10.0)\n", tps);
    printf("Messages: %u total\n", metrics->message_total);
    printf("Reliability: %.2f%%\n", metrics->reliability_score * 100.0);
    printf("Performance Score: %.2f\n", metrics->performance_score);
    
    // Network status
    printf("\n=== Network Position ===\n");
    printf("Connected Peers: %zu\n", metrics->peer_count);  // Move to top
    printf("Rank: %d\n", stake->rank);
    printf("Active: %s\n", is_active ? "Yes" : "No");
    printf("Earnings (Tips): %.6f MXD\n", metrics->tip_share);
    
    // Performance indicators
    printf("\n=== Health Indicators ===\n");
    printf("Response Time: %s\n", 
           metrics->avg_response_time < 3000 ? "✓ Good" : "✗ High");
    printf("Transaction Rate: %s\n", 
           tps >= 10.0 ? "✓ Good" : "✗ Low");
    printf("Network Status: %s\n",
           stake->active ? "✓ Connected" : "✗ Disconnected");
    
    printf("\nPress Ctrl+C to exit\n");
    fflush(stdout);
}
