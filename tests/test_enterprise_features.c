#include "../include/mxd_logging.h"
#include "../include/mxd_secrets.h"
#include "../include/mxd_monitoring.h"
#include "../include/mxd_backup.h"
#include "../include/mxd_load_testing.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_logging_system(void) {
    TEST_START("Logging System");
    
    mxd_log_config_t config = {
        .level = MXD_LOG_DEBUG,
        .output_file = "test_log.txt",
        .enable_console = 1,
        .enable_json = 0
    };
    
    TEST_ASSERT(mxd_init_logging(&config) == 0, "Logging initialization successful");
    
    MXD_LOG_INFO("test", "Test info message");
    MXD_LOG_WARN("test", "Test warning message");
    MXD_LOG_ERROR("test", "Test error message");
    MXD_LOG_DEBUG("test", "Test debug message");
    
    mxd_cleanup_logging();
    
    FILE *log_file = fopen("test_log.txt", "r");
    TEST_ASSERT(log_file != NULL, "Log file created successfully");
    if (log_file) {
        fclose(log_file);
        unlink("test_log.txt");
    }
    
    TEST_END("Logging System");
}

static void test_secrets_management(void) {
    TEST_START("Secrets Management");
    
    setenv("MXD_NETWORK_MAGIC", "0x12345678", 1);
    setenv("MXD_CRYPTO_SALT", "test_salt_value", 1);
    
    TEST_ASSERT(mxd_init_secrets(NULL) == 0, "Secrets initialization successful");
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    TEST_ASSERT(secrets != NULL, "Secrets retrieved successfully");
    TEST_ASSERT(secrets->network_magic != 0, "Network magic loaded");
    
    mxd_cleanup_secrets();
    
    unsetenv("MXD_NETWORK_MAGIC");
    unsetenv("MXD_CRYPTO_SALT");
    
    TEST_END("Secrets Management");
}

static void test_monitoring_system(void) {
    TEST_START("Monitoring System");
    
    TEST_ASSERT(mxd_init_monitoring(8080) == 0, "Monitoring initialization successful");
    
    mxd_system_metrics_t metrics = {
        .total_transactions = 1000,
        .total_blocks = 100,
        .current_tps = 25.5,
        .network_latency_ms = 150,
        .active_peers = 5,
        .blockchain_height = 12345,
        .consensus_efficiency = 0.95,
        .memory_usage_bytes = 1024 * 1024,
        .disk_usage_bytes = 10 * 1024 * 1024,
        .cpu_usage_percent = 15.5
    };
    
    TEST_ASSERT(mxd_update_system_metrics(&metrics) == 0, "Metrics update successful");
    
    mxd_health_status_t health;
    TEST_ASSERT(mxd_get_health_status(&health) == 0, "Health status retrieval successful");
    TEST_ASSERT(health.is_healthy == 1, "System reports healthy status");
    
    const char *prometheus_metrics = mxd_get_prometheus_metrics();
    TEST_ASSERT(prometheus_metrics != NULL, "Prometheus metrics generated");
    TEST_ASSERT(strstr(prometheus_metrics, "mxd_tps_current 25.50") != NULL, "TPS metric present");
    
    const char *health_json = mxd_get_health_json();
    TEST_ASSERT(health_json != NULL, "Health JSON generated");
    TEST_ASSERT(strstr(health_json, "\"status\":\"healthy\"") != NULL, "Health status correct");
    
    mxd_cleanup_monitoring();
    
    TEST_END("Monitoring System");
}

static void test_backup_system(void) {
    TEST_START("Backup System");
    
    mxd_backup_config_t config = {
        .backup_dir = "/tmp/mxd_test_backups",
        .retention_days = 7,
        .enable_compression = 1,
        .enable_encryption = 0,
        .backup_interval_hours = 24
    };
    
    TEST_ASSERT(mxd_init_backup_system(&config) == 0, "Backup system initialization successful");
    
    FILE *test_db = fopen("/tmp/test_blockchain.db", "w");
    if (test_db) {
        fprintf(test_db, "test blockchain data");
        fclose(test_db);
    }
    
    mxd_backup_info_t backup_info;
    TEST_ASSERT(mxd_create_blockchain_backup("/tmp/test_blockchain.db", &backup_info) == 0, 
                "Blockchain backup creation successful");
    TEST_ASSERT(backup_info.is_valid == 1, "Backup marked as valid");
    TEST_ASSERT(backup_info.backup_size > 0, "Backup has non-zero size");
    
    TEST_ASSERT(mxd_verify_backup_integrity(backup_info.backup_path) == 0, 
                "Backup integrity verification successful");
    
    TEST_ASSERT(mxd_restore_blockchain_backup(backup_info.backup_path, "/tmp/restored_blockchain.db") == 0,
                "Blockchain backup restoration successful");
    
    unlink("/tmp/test_blockchain.db");
    unlink("/tmp/restored_blockchain.db");
    unlink(backup_info.backup_path);
    
    mxd_cleanup_backup_system();
    
    TEST_END("Backup System");
}

static void test_load_testing_framework(void) {
    TEST_START("Load Testing Framework");
    
    TEST_ASSERT(mxd_init_load_testing() == 0, "Load testing initialization successful");
    
    mxd_load_test_config_t config = {
        .target_tps = 50,
        .duration_seconds = 2,
        .concurrent_connections = 10,
        .ramp_up_seconds = 1,
        .enable_stress_mode = 0
    };
    
    mxd_load_test_results_t results;
    
    TEST_ASSERT(mxd_run_transaction_load_test(&config, &results) == 0, 
                "Transaction load test execution successful");
    TEST_ASSERT(results.total_requests > 0, "Load test generated requests");
    TEST_ASSERT(results.actual_tps > 0, "Load test measured TPS");
    
    double crypto_ops_per_sec;
    TEST_ASSERT(mxd_benchmark_crypto_operations(1000, &crypto_ops_per_sec) == 0,
                "Crypto operations benchmark successful");
    TEST_ASSERT(crypto_ops_per_sec > 100, "Crypto operations performance acceptable");
    
    uint64_t peak_memory;
    TEST_ASSERT(mxd_stress_test_memory_usage(100, &peak_memory) == 0,
                "Memory stress test successful");
    TEST_ASSERT(peak_memory > 0, "Memory usage measured");
    
    mxd_print_load_test_results(&results);
    
    mxd_cleanup_load_testing();
    
    TEST_END("Load Testing Framework");
}

int main(void) {
    TEST_START("Enterprise Features Tests");
    
    test_logging_system();
    test_secrets_management();
    test_monitoring_system();
    test_backup_system();
    test_load_testing_framework();
    
    TEST_END("Enterprise Features Tests");
    return 0;
}
