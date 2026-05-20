#include "../include/mxd_ntp.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

// Test NTP initialization
static void test_ntp_init(void) {
    TEST_START("NTP Initialization");
    TEST_ASSERT(mxd_init_ntp() == 0, "NTP system initialization successful");
    TEST_END("NTP Initialization");
}

// Test time synchronization
static void test_time_sync(void) {
    TEST_START("Time Synchronization");
    mxd_ntp_info_t info;
    
    TEST_ASSERT(mxd_sync_time(&info) == 0, "Time synchronization successful");
    TEST_VALUE("Timestamp", "%lu", info.timestamp);
    TEST_VALUE("Precision", "%lu", info.precision);
    TEST_VALUE("Delay", "%lu", info.delay);
    TEST_ASSERT(info.timestamp > 0, "Timestamp is positive");
    TEST_ASSERT(info.precision > 0, "Precision is positive");
    TEST_ASSERT(info.delay >= 0, "Delay is non-negative");
    
    TEST_END("Time Synchronization");
}

// Test network time retrieval
static void test_network_time(void) {
    TEST_START("Network Time Retrieval");
    uint64_t time1, time2;
    
    TEST_ASSERT(mxd_get_network_time(&time1) == 0, "First time retrieval successful");
    TEST_VALUE("Initial time", "%lu", time1);
    TEST_ASSERT(time1 > 0, "Initial time is positive");
    
    TEST_VALUE("Sleeping for", "%d seconds", 1);
    sleep(1);
    
    TEST_ASSERT(mxd_get_network_time(&time2) == 0, "Second time retrieval successful");
    TEST_VALUE("Later time", "%lu", time2);
    TEST_ASSERT(time2 > time1, "Time increases monotonically");
    TEST_VALUE("Time difference", "%lu ms", time2 - time1);
    TEST_ASSERT(time2 - time1 >= 1000, "At least 1 second has passed");
    
    TEST_END("Network Time Retrieval");
}

// Test error handling
static void test_error_handling(void) {
    TEST_START("Error Handling");
    
    TEST_ASSERT(mxd_sync_time(NULL) == -1, "Sync with NULL pointer rejected");
    TEST_ASSERT(mxd_get_network_time(NULL) == -1, "Get time with NULL pointer rejected");
    
    TEST_END("Error Handling");
}

// Network simulation test
static void test_network_conditions(void) {
    TEST_START("Network Conditions");
    
    // Test with multiple consecutive syncs
    TEST_VALUE("Number of syncs", "%d", 5);
    for (int i = 0; i < 5; i++) {
        mxd_ntp_info_t info;
        TEST_ASSERT(mxd_sync_time(&info) == 0, "Sync successful");
        TEST_ASSERT(info.delay < 5000000, "Delay within acceptable range (< 5s)");
        TEST_VALUE("Sync delay", "%lu", info.delay);
        usleep(100000); // 100ms between syncs
    }
    
    // Test time consistency
    uint64_t times[10];
    TEST_VALUE("Time consistency checks", "%d", 10);
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(mxd_get_network_time(&times[i]) == 0, "Time retrieval successful");
        if (i > 0) {
            TEST_ASSERT(times[i] >= times[i-1], "Time increases monotonically");
            TEST_ASSERT(times[i] - times[i-1] <= 1000, "Time difference within bounds (≤ 1s)");
            TEST_VALUE("Time difference", "%lu ms", times[i] - times[i-1]);
        }
        usleep(50000); // 50ms between checks
    }
    
    TEST_END("Network Conditions");
}

// Performance benchmark
static void benchmark_ntp_operations(void) {
    TEST_START("NTP Performance Benchmark");
    
    struct timespec start, end;
    uint64_t total_sync_time = 0;
    uint64_t total_get_time = 0;
    const int iterations = 100;
    
    TEST_VALUE("Number of iterations", "%d", iterations);
    
    // Benchmark sync_time
    for (int i = 0; i < iterations; i++) {
        mxd_ntp_info_t info;
        clock_gettime(CLOCK_MONOTONIC, &start);
        TEST_ASSERT(mxd_sync_time(&info) == 0, "Sync operation successful");
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_sync_time += (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
        usleep(10000); // 10ms between syncs
    }
    
    // Benchmark get_network_time
    uint64_t timestamp;
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        TEST_ASSERT(mxd_get_network_time(&timestamp) == 0, "Time retrieval successful");
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_get_time += (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    }
    
    TEST_VALUE("Average sync_time operation", "%lu ns", total_sync_time / iterations);
    TEST_VALUE("Average get_network_time operation", "%lu ns", total_get_time / iterations);
    
    TEST_END("NTP Performance Benchmark");
}

int main(void) {
    TEST_START("NTP Tests");
    
    test_ntp_init();
    test_time_sync();
    test_network_time();
    test_error_handling();
    test_network_conditions();
    benchmark_ntp_operations();
    
    TEST_END("NTP Tests");
    return 0;
}
