#ifndef MXD_PROMETHEUS_H
#define MXD_PROMETHEUS_H

#include <stdint.h>
#include <pthread.h>

// Prometheus-style metrics for security monitoring

// Metric types
typedef enum {
    MXD_METRIC_COUNTER,
    MXD_METRIC_GAUGE,
    MXD_METRIC_HISTOGRAM
} mxd_metric_type_t;

// Maximum number of metrics
#define MXD_MAX_METRICS 100

// Metric structure
typedef struct {
    char name[128];
    char help[256];
    mxd_metric_type_t type;
    double value;
    uint64_t count;
    int active;
} mxd_metric_t;

// Metrics registry
typedef struct {
    mxd_metric_t metrics[MXD_MAX_METRICS];
    int metric_count;
    pthread_mutex_t mutex;
} mxd_metrics_registry_t;

// Initialize metrics registry
int mxd_metrics_init(void);

// Cleanup metrics registry
void mxd_metrics_cleanup(void);

// Increment a counter metric
void mxd_metrics_increment(const char* name);

// Set a gauge metric
void mxd_metrics_set_gauge(const char* name, double value);

// Record a histogram value
void mxd_metrics_record_histogram(const char* name, double value);

// Get metrics in Prometheus format
char* mxd_metrics_export_prometheus(void);

// Register a new metric
int mxd_metrics_register(const char* name, const char* help, mxd_metric_type_t type);

#endif // MXD_PROMETHEUS_H
