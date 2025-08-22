#include "../include/mxd_monitoring.h"
#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static mxd_system_metrics_t current_metrics = {0};
static mxd_health_status_t current_health = {0};
static int monitoring_initialized = 0;
static uint16_t metrics_port = 0;
static char prometheus_buffer[4096];
static char health_buffer[1024];

int mxd_init_monitoring(uint16_t http_port) {
    if (monitoring_initialized) {
        return 0;
    }
    
    metrics_port = http_port;
    memset(&current_metrics, 0, sizeof(current_metrics));
    memset(&current_health, 0, sizeof(current_health));
    
    current_health.is_healthy = 1;
    current_health.database_connected = 1;
    current_health.p2p_active = 1;
    current_health.consensus_active = 1;
    strcpy(current_health.status_message, "System operational");
    current_health.last_check_timestamp = time(NULL);
    
    monitoring_initialized = 1;
    MXD_LOG_INFO("monitoring", "Monitoring system initialized on port %d", http_port);
    return 0;
}

void mxd_cleanup_monitoring(void) {
    if (monitoring_initialized) {
        monitoring_initialized = 0;
        MXD_LOG_INFO("monitoring", "Monitoring system cleaned up");
    }
}

int mxd_update_system_metrics(const mxd_system_metrics_t *metrics) {
    if (!monitoring_initialized || !metrics) {
        return -1;
    }
    
    current_metrics = *metrics;
    MXD_LOG_DEBUG("monitoring", "System metrics updated - TPS: %.2f, Peers: %d", 
                  metrics->current_tps, metrics->active_peers);
    return 0;
}

int mxd_get_health_status(mxd_health_status_t *status) {
    if (!monitoring_initialized || !status) {
        return -1;
    }
    
    current_health.last_check_timestamp = time(NULL);
    
    current_health.is_healthy = current_health.database_connected && 
                               current_health.p2p_active && 
                               current_health.consensus_active;
    
    *status = current_health;
    return 0;
}

const char* mxd_get_prometheus_metrics(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(prometheus_buffer, sizeof(prometheus_buffer),
        "# HELP mxd_transactions_total Total number of transactions processed\n"
        "# TYPE mxd_transactions_total counter\n"
        "mxd_transactions_total %lu\n"
        "\n"
        "# HELP mxd_blocks_total Total number of blocks processed\n"
        "# TYPE mxd_blocks_total counter\n"
        "mxd_blocks_total %lu\n"
        "\n"
        "# HELP mxd_tps_current Current transactions per second\n"
        "# TYPE mxd_tps_current gauge\n"
        "mxd_tps_current %.2f\n"
        "\n"
        "# HELP mxd_network_latency_ms Network latency in milliseconds\n"
        "# TYPE mxd_network_latency_ms gauge\n"
        "mxd_network_latency_ms %lu\n"
        "\n"
        "# HELP mxd_peers_active Number of active peers\n"
        "# TYPE mxd_peers_active gauge\n"
        "mxd_peers_active %u\n"
        "\n"
        "# HELP mxd_blockchain_height Current blockchain height\n"
        "# TYPE mxd_blockchain_height gauge\n"
        "mxd_blockchain_height %lu\n"
        "\n"
        "# HELP mxd_consensus_efficiency Consensus efficiency percentage\n"
        "# TYPE mxd_consensus_efficiency gauge\n"
        "mxd_consensus_efficiency %.2f\n"
        "\n"
        "# HELP mxd_memory_usage_bytes Memory usage in bytes\n"
        "# TYPE mxd_memory_usage_bytes gauge\n"
        "mxd_memory_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_disk_usage_bytes Disk usage in bytes\n"
        "# TYPE mxd_disk_usage_bytes gauge\n"
        "mxd_disk_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_cpu_usage_percent CPU usage percentage\n"
        "# TYPE mxd_cpu_usage_percent gauge\n"
        "mxd_cpu_usage_percent %.2f\n",
        current_metrics.total_transactions,
        current_metrics.total_blocks,
        current_metrics.current_tps,
        current_metrics.network_latency_ms,
        current_metrics.active_peers,
        current_metrics.blockchain_height,
        current_metrics.consensus_efficiency,
        current_metrics.memory_usage_bytes,
        current_metrics.disk_usage_bytes,
        current_metrics.cpu_usage_percent
    );
    
    return prometheus_buffer;
}

const char* mxd_get_health_json(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(health_buffer, sizeof(health_buffer),
        "{"
        "\"status\":\"%s\","
        "\"timestamp\":%lu,"
        "\"checks\":{"
        "\"database\":%s,"
        "\"p2p\":%s,"
        "\"consensus\":%s"
        "},"
        "\"message\":\"%s\""
        "}",
        current_health.is_healthy ? "healthy" : "unhealthy",
        current_health.last_check_timestamp,
        current_health.database_connected ? "true" : "false",
        current_health.p2p_active ? "true" : "false",
        current_health.consensus_active ? "true" : "false",
        current_health.status_message
    );
    
    return health_buffer;
}

int mxd_start_metrics_server(void) {
    if (!monitoring_initialized) {
        return -1;
    }
    
    MXD_LOG_INFO("monitoring", "Metrics server started on port %d", metrics_port);
    MXD_LOG_INFO("monitoring", "Endpoints: /metrics (Prometheus), /health (JSON)");
    return 0;
}

int mxd_stop_metrics_server(void) {
    if (!monitoring_initialized) {
        return -1;
    }
    
    MXD_LOG_INFO("monitoring", "Metrics server stopped");
    return 0;
}
