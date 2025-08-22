#ifndef MXD_MONITORING_H
#define MXD_MONITORING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_metrics.h"

typedef struct {
    uint64_t total_transactions;
    uint64_t total_blocks;
    double current_tps;
    uint64_t network_latency_ms;
    uint32_t active_peers;
    uint64_t blockchain_height;
    double consensus_efficiency;
    uint64_t memory_usage_bytes;
    uint64_t disk_usage_bytes;
    double cpu_usage_percent;
} mxd_system_metrics_t;

typedef struct {
    int is_healthy;
    int database_connected;
    int p2p_active;
    int consensus_active;
    char status_message[256];
    uint64_t last_check_timestamp;
} mxd_health_status_t;

int mxd_init_monitoring(uint16_t http_port);
void mxd_cleanup_monitoring(void);
int mxd_update_system_metrics(const mxd_system_metrics_t *metrics);
int mxd_get_health_status(mxd_health_status_t *status);
int mxd_start_metrics_server(void);
int mxd_stop_metrics_server(void);

const char* mxd_get_prometheus_metrics(void);
const char* mxd_get_health_json(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_MONITORING_H
