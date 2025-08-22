#ifndef MXD_LOAD_TESTING_H
#define MXD_LOAD_TESTING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t target_tps;
    uint32_t duration_seconds;
    uint32_t concurrent_connections;
    uint32_t ramp_up_seconds;
    int enable_stress_mode;
} mxd_load_test_config_t;

typedef struct {
    uint64_t total_requests;
    uint64_t successful_requests;
    uint64_t failed_requests;
    double average_response_time;
    double min_response_time;
    double max_response_time;
    double actual_tps;
    uint64_t memory_peak_usage;
    double cpu_peak_usage;
    uint32_t error_count;
} mxd_load_test_results_t;

typedef struct {
    uint64_t timestamp;
    double response_time;
    int success;
    uint32_t memory_usage;
    double cpu_usage;
} mxd_load_test_sample_t;

int mxd_init_load_testing(void);
void mxd_cleanup_load_testing(void);

int mxd_run_transaction_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results);
int mxd_run_p2p_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results);
int mxd_run_consensus_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results);

int mxd_benchmark_crypto_operations(uint32_t iterations, double *ops_per_second);
int mxd_benchmark_database_operations(uint32_t iterations, double *ops_per_second);

int mxd_stress_test_memory_usage(uint32_t max_nodes, uint64_t *peak_memory);
int mxd_stress_test_network_capacity(uint32_t max_peers, uint32_t *max_throughput);

void mxd_print_load_test_results(const mxd_load_test_results_t *results);

#ifdef __cplusplus
}
#endif

#endif // MXD_LOAD_TESTING_H
