#include "mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static mxd_metrics_registry_t global_registry = {0};
static int registry_initialized = 0;

int mxd_metrics_init(void) {
    if (registry_initialized) {
        return 0;
    }
    
    memset(&global_registry, 0, sizeof(mxd_metrics_registry_t));
    pthread_mutex_init(&global_registry.mutex, NULL);
    global_registry.metric_count = 0;
    registry_initialized = 1;
    
    mxd_metrics_register("mxd_http_auth_failures_total", "Total HTTP authentication failures", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_http_wallet_requests_total", "Total wallet endpoint requests", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_tls_verification_failures_total", "Total TLS verification failures", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_bootstrap_pin_mismatch_total", "Total certificate pin mismatches", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_signatures_tracked", "Number of signatures tracked", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_double_sign_events_total", "Total double-signing events detected", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_blacklisted_validators", "Number of blacklisted validators", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_active_blacklists", "Number of active blacklists", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_mempool_size", "Current mempool size", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_mempool_evictions_total", "Total mempool evictions", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_peer_rate_limit_violations_total", "Total peer rate limit violations", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_handshake_replay_detected_total", "Total handshake replay attacks detected", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_sessions_active", "Number of active P2P sessions", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_contract_oom_or_oog_total", "Total contract out-of-memory or out-of-gas events", MXD_METRIC_COUNTER);
    mxd_metrics_register("mxd_tx_validation_rate", "Transaction validation rate (tx/sec)", MXD_METRIC_GAUGE);
    mxd_metrics_register("mxd_p2p_round_trip_seconds", "P2P round trip time in seconds", MXD_METRIC_HISTOGRAM);
    
    return 0;
}

void mxd_metrics_cleanup(void) {
    if (!registry_initialized) {
        return;
    }
    
    pthread_mutex_destroy(&global_registry.mutex);
    registry_initialized = 0;
}

int mxd_metrics_register(const char* name, const char* help, mxd_metric_type_t type) {
    if (!registry_initialized) {
        mxd_metrics_init();
    }
    
    pthread_mutex_lock(&global_registry.mutex);
    
    for (int i = 0; i < global_registry.metric_count; i++) {
        if (strcmp(global_registry.metrics[i].name, name) == 0) {
            pthread_mutex_unlock(&global_registry.mutex);
            return 0;
        }
    }
    
    if (global_registry.metric_count >= MXD_MAX_METRICS) {
        pthread_mutex_unlock(&global_registry.mutex);
        return -1;
    }
    
    mxd_metric_t* metric = &global_registry.metrics[global_registry.metric_count];
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    strncpy(metric->help, help, sizeof(metric->help) - 1);
    metric->type = type;
    metric->value = 0.0;
    metric->count = 0;
    metric->active = 1;
    
    global_registry.metric_count++;
    
    pthread_mutex_unlock(&global_registry.mutex);
    return 0;
}

void mxd_metrics_increment(const char* name) {
    if (!registry_initialized) {
        mxd_metrics_init();
    }
    
    pthread_mutex_lock(&global_registry.mutex);
    
    for (int i = 0; i < global_registry.metric_count; i++) {
        if (strcmp(global_registry.metrics[i].name, name) == 0) {
            if (global_registry.metrics[i].type == MXD_METRIC_COUNTER) {
                global_registry.metrics[i].value += 1.0;
                global_registry.metrics[i].count++;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&global_registry.mutex);
}

void mxd_metrics_set_gauge(const char* name, double value) {
    if (!registry_initialized) {
        mxd_metrics_init();
    }
    
    pthread_mutex_lock(&global_registry.mutex);
    
    for (int i = 0; i < global_registry.metric_count; i++) {
        if (strcmp(global_registry.metrics[i].name, name) == 0) {
            if (global_registry.metrics[i].type == MXD_METRIC_GAUGE) {
                global_registry.metrics[i].value = value;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&global_registry.mutex);
}

void mxd_metrics_record_histogram(const char* name, double value) {
    if (!registry_initialized) {
        mxd_metrics_init();
    }
    
    pthread_mutex_lock(&global_registry.mutex);
    
    for (int i = 0; i < global_registry.metric_count; i++) {
        if (strcmp(global_registry.metrics[i].name, name) == 0) {
            if (global_registry.metrics[i].type == MXD_METRIC_HISTOGRAM) {
                global_registry.metrics[i].value += value;
                global_registry.metrics[i].count++;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&global_registry.mutex);
}

char* mxd_metrics_export_prometheus(void) {
    if (!registry_initialized) {
        mxd_metrics_init();
    }
    
    size_t buffer_size = 64 * 1024;
    char* buffer = malloc(buffer_size);
    if (!buffer) {
        return NULL;
    }
    
    buffer[0] = '\0';
    size_t offset = 0;
    
    pthread_mutex_lock(&global_registry.mutex);
    
    for (int i = 0; i < global_registry.metric_count; i++) {
        mxd_metric_t* metric = &global_registry.metrics[i];
        if (!metric->active) {
            continue;
        }
        
        int written = snprintf(buffer + offset, buffer_size - offset,
                              "# HELP %s %s\n", metric->name, metric->help);
        if (written < 0 || (size_t)written >= buffer_size - offset) {
            break;
        }
        offset += written;
        
        const char* type_str = "counter";
        if (metric->type == MXD_METRIC_GAUGE) {
            type_str = "gauge";
        } else if (metric->type == MXD_METRIC_HISTOGRAM) {
            type_str = "histogram";
        }
        
        written = snprintf(buffer + offset, buffer_size - offset,
                          "# TYPE %s %s\n", metric->name, type_str);
        if (written < 0 || (size_t)written >= buffer_size - offset) {
            break;
        }
        offset += written;
        
        if (metric->type == MXD_METRIC_HISTOGRAM && metric->count > 0) {
            written = snprintf(buffer + offset, buffer_size - offset,
                              "%s_sum %.2f\n%s_count %lu\n",
                              metric->name, metric->value,
                              metric->name, metric->count);
        } else {
            written = snprintf(buffer + offset, buffer_size - offset,
                              "%s %.2f\n", metric->name, metric->value);
        }
        
        if (written < 0 || (size_t)written >= buffer_size - offset) {
            break;
        }
        offset += written;
    }
    
    pthread_mutex_unlock(&global_registry.mutex);
    
    return buffer;
}
