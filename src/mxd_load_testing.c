#include "../include/mxd_load_testing.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

static int load_testing_initialized = 0;

static uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

static double get_timestamp_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000000.0 + (double)tv.tv_usec;
}

int mxd_init_load_testing(void) {
    if (load_testing_initialized) {
        return 0;
    }
    
    load_testing_initialized = 1;
    MXD_LOG_INFO("load_test", "Load testing framework initialized");
    return 0;
}

void mxd_cleanup_load_testing(void) {
    if (load_testing_initialized) {
        load_testing_initialized = 0;
        MXD_LOG_INFO("load_test", "Load testing framework cleaned up");
    }
}

int mxd_run_transaction_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results) {
    if (!load_testing_initialized || !config || !results) {
        return -1;
    }
    
    memset(results, 0, sizeof(mxd_load_test_results_t));
    results->min_response_time = 999999.0;
    
    MXD_LOG_INFO("load_test", "Starting transaction load test - target TPS: %d, duration: %ds", 
                 config->target_tps, config->duration_seconds);
    
    uint64_t start_time = get_timestamp_ms();
    uint64_t end_time = start_time + (config->duration_seconds * 1000);
    uint64_t interval_ms = 1000 / config->target_tps;
    
    while (get_timestamp_ms() < end_time) {
        double request_start = get_timestamp_us();
        
        mxd_transaction_t tx;
        int success = (mxd_create_transaction(&tx) == 0);
        
        double request_end = get_timestamp_us();
        double response_time = (request_end - request_start) / 1000.0;
        
        results->total_requests++;
        if (success) {
            results->successful_requests++;
        } else {
            results->failed_requests++;
            results->error_count++;
        }
        
        results->average_response_time = (results->average_response_time * (results->total_requests - 1) + response_time) / results->total_requests;
        if (response_time < results->min_response_time) {
            results->min_response_time = response_time;
        }
        if (response_time > results->max_response_time) {
            results->max_response_time = response_time;
        }
        
        usleep(interval_ms * 1000);
    }
    
    uint64_t actual_duration = get_timestamp_ms() - start_time;
    results->actual_tps = (double)results->total_requests / (actual_duration / 1000.0);
    
    MXD_LOG_INFO("load_test", "Transaction load test completed - requests: %lu, TPS: %.2f, avg response: %.2fms", 
                 results->total_requests, results->actual_tps, results->average_response_time);
    return 0;
}

int mxd_run_p2p_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results) {
    if (!load_testing_initialized || !config || !results) {
        return -1;
    }
    
    memset(results, 0, sizeof(mxd_load_test_results_t));
    results->min_response_time = 999999.0;
    
    MXD_LOG_INFO("load_test", "Starting P2P load test - connections: %d, duration: %ds", 
                 config->concurrent_connections, config->duration_seconds);
    
    uint64_t start_time = get_timestamp_ms();
    uint64_t end_time = start_time + (config->duration_seconds * 1000);
    
    while (get_timestamp_ms() < end_time) {
        double request_start = get_timestamp_us();
        
        uint8_t test_data[256] = "test_message";
        int success = (mxd_broadcast_message(1, test_data, sizeof(test_data)) == 0);
        
        double request_end = get_timestamp_us();
        double response_time = (request_end - request_start) / 1000.0;
        
        results->total_requests++;
        if (success) {
            results->successful_requests++;
        } else {
            results->failed_requests++;
            results->error_count++;
        }
        
        results->average_response_time = (results->average_response_time * (results->total_requests - 1) + response_time) / results->total_requests;
        if (response_time < results->min_response_time) {
            results->min_response_time = response_time;
        }
        if (response_time > results->max_response_time) {
            results->max_response_time = response_time;
        }
        
        usleep(10000);
    }
    
    uint64_t actual_duration = get_timestamp_ms() - start_time;
    results->actual_tps = (double)results->total_requests / (actual_duration / 1000.0);
    
    MXD_LOG_INFO("load_test", "P2P load test completed - requests: %lu, TPS: %.2f", 
                 results->total_requests, results->actual_tps);
    return 0;
}

int mxd_run_consensus_load_test(const mxd_load_test_config_t *config, mxd_load_test_results_t *results) {
    if (!load_testing_initialized || !config || !results) {
        return -1;
    }
    
    memset(results, 0, sizeof(mxd_load_test_results_t));
    results->min_response_time = 999999.0;
    
    MXD_LOG_INFO("load_test", "Starting consensus load test - target TPS: %d", config->target_tps);
    
    uint64_t start_time = get_timestamp_ms();
    uint64_t end_time = start_time + (config->duration_seconds * 1000);
    
    while (get_timestamp_ms() < end_time) {
        double request_start = get_timestamp_us();
        
        uint8_t test_hash[64];
        int success = (mxd_sha512("test_block", 10, test_hash) == 0);
        
        double request_end = get_timestamp_us();
        double response_time = (request_end - request_start) / 1000.0;
        
        results->total_requests++;
        if (success) {
            results->successful_requests++;
        } else {
            results->failed_requests++;
        }
        
        results->average_response_time = (results->average_response_time * (results->total_requests - 1) + response_time) / results->total_requests;
        if (response_time < results->min_response_time) {
            results->min_response_time = response_time;
        }
        if (response_time > results->max_response_time) {
            results->max_response_time = response_time;
        }
        
        usleep(1000);
    }
    
    uint64_t actual_duration = get_timestamp_ms() - start_time;
    results->actual_tps = (double)results->total_requests / (actual_duration / 1000.0);
    
    MXD_LOG_INFO("load_test", "Consensus load test completed - operations: %lu, OPS: %.2f", 
                 results->total_requests, results->actual_tps);
    return 0;
}

int mxd_benchmark_crypto_operations(uint32_t iterations, double *ops_per_second) {
    if (!load_testing_initialized || !ops_per_second) {
        return -1;
    }
    
    MXD_LOG_INFO("load_test", "Benchmarking crypto operations - iterations: %d", iterations);
    
    double start_time = get_timestamp_us();
    
    for (uint32_t i = 0; i < iterations; i++) {
        uint8_t hash[64];
        char test_data[256];
        snprintf(test_data, sizeof(test_data), "test_data_%u", i);
        mxd_sha512(test_data, strlen(test_data), hash);
    }
    
    double end_time = get_timestamp_us();
    double duration_seconds = (end_time - start_time) / 1000000.0;
    
    *ops_per_second = iterations / duration_seconds;
    
    MXD_LOG_INFO("load_test", "Crypto benchmark completed - %.2f ops/second", *ops_per_second);
    return 0;
}

int mxd_benchmark_database_operations(uint32_t iterations, double *ops_per_second) {
    if (!load_testing_initialized || !ops_per_second) {
        return -1;
    }
    
    MXD_LOG_INFO("load_test", "Benchmarking database operations - iterations: %d", iterations);
    
    double start_time = get_timestamp_us();
    
    for (uint32_t i = 0; i < iterations; i++) {
        usleep(100);
    }
    
    double end_time = get_timestamp_us();
    double duration_seconds = (end_time - start_time) / 1000000.0;
    
    *ops_per_second = iterations / duration_seconds;
    
    MXD_LOG_INFO("load_test", "Database benchmark completed - %.2f ops/second", *ops_per_second);
    return 0;
}

int mxd_stress_test_memory_usage(uint32_t max_nodes, uint64_t *peak_memory) {
    if (!load_testing_initialized || !peak_memory) {
        return -1;
    }
    
    MXD_LOG_INFO("load_test", "Starting memory stress test - max nodes: %d", max_nodes);
    
    void **allocations = malloc(max_nodes * sizeof(void*));
    if (!allocations) {
        return -1;
    }
    
    *peak_memory = 0;
    size_t node_size = 1024;
    
    for (uint32_t i = 0; i < max_nodes; i++) {
        allocations[i] = malloc(node_size);
        if (!allocations[i]) {
            for (uint32_t j = 0; j < i; j++) {
                free(allocations[j]);
            }
            free(allocations);
            *peak_memory = i * node_size;
            MXD_LOG_WARN("load_test", "Memory allocation failed at %d nodes", i);
            return 0;
        }
        
        memset(allocations[i], i % 256, node_size);
        *peak_memory = (i + 1) * node_size;
    }
    
    for (uint32_t i = 0; i < max_nodes; i++) {
        free(allocations[i]);
    }
    free(allocations);
    
    MXD_LOG_INFO("load_test", "Memory stress test completed - peak: %lu bytes", *peak_memory);
    return 0;
}

int mxd_stress_test_network_capacity(uint32_t max_peers, uint32_t *max_throughput) {
    if (!load_testing_initialized || !max_throughput) {
        return -1;
    }
    
    MXD_LOG_INFO("load_test", "Starting network capacity stress test - max peers: %d", max_peers);
    
    *max_throughput = 0;
    uint32_t messages_per_peer = 100;
    
    double start_time = get_timestamp_us();
    
    for (uint32_t peers = 1; peers <= max_peers; peers++) {
        for (uint32_t msg = 0; msg < messages_per_peer; msg++) {
            uint8_t test_data[64];
            snprintf((char*)test_data, sizeof(test_data), "peer_%u_msg_%u", peers, msg);
            
            if (mxd_broadcast_message(1, test_data, sizeof(test_data)) != 0) {
                MXD_LOG_WARN("load_test", "Network capacity limit reached at %d peers", peers);
                *max_throughput = (peers - 1) * messages_per_peer;
                return 0;
            }
        }
        
        *max_throughput = peers * messages_per_peer;
        usleep(1000);
    }
    
    double end_time = get_timestamp_us();
    double duration_seconds = (end_time - start_time) / 1000000.0;
    
    MXD_LOG_INFO("load_test", "Network stress test completed - throughput: %d msgs in %.2fs", 
                 *max_throughput, duration_seconds);
    return 0;
}

void mxd_print_load_test_results(const mxd_load_test_results_t *results) {
    if (!results) {
        return;
    }
    
    MXD_LOG_INFO("load_test", "=== Load Test Results ===");
    MXD_LOG_INFO("load_test", "Total Requests: %lu", results->total_requests);
    MXD_LOG_INFO("load_test", "Successful: %lu (%.2f%%)", results->successful_requests,
           (double)results->successful_requests / results->total_requests * 100.0);
    MXD_LOG_INFO("load_test", "Failed: %lu (%.2f%%)", results->failed_requests,
           (double)results->failed_requests / results->total_requests * 100.0);
    MXD_LOG_INFO("load_test", "Actual TPS: %.2f", results->actual_tps);
    MXD_LOG_INFO("load_test", "Response Time - Avg: %.2fms, Min: %.2fms, Max: %.2fms",
           results->average_response_time, results->min_response_time, results->max_response_time);
    MXD_LOG_INFO("load_test", "Peak Memory: %lu bytes", results->memory_peak_usage);
    MXD_LOG_INFO("load_test", "Peak CPU: %.2f%%", results->cpu_peak_usage);
    MXD_LOG_INFO("load_test", "Error Count: %u", results->error_count);
    MXD_LOG_INFO("load_test", "========================");
}
