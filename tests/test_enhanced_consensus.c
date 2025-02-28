#include "../include/mxd_rsc.h"
#include "../include/mxd_ntp.h"
#include "../include/blockchain/mxd_rsc_internal.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

// Test node metrics initialization
static void test_node_metrics_init(void) {
    mxd_node_metrics_t metrics;
    
    TEST_START("Node Metrics Initialization");
    
    TEST_ASSERT(mxd_init_node_metrics(&metrics) == 0, "Initialize metrics structure");
    TEST_ASSERT(metrics.avg_response_time == 0, "Average response time initialized to 0");
    TEST_ASSERT(metrics.min_response_time == UINT64_MAX, "Minimum response time initialized to max");
    TEST_ASSERT(metrics.max_response_time == 0, "Maximum response time initialized to 0");
    TEST_ASSERT(metrics.response_count == 0, "Response count initialized to 0");
    TEST_ASSERT(metrics.tip_share == 0.0, "Tip share initialized to 0");
    TEST_ASSERT(metrics.last_update == 0, "Last update initialized to 0");
    
    TEST_END("Node Metrics Initialization");
}

// Test node metrics updates
static void test_node_metrics_update(void) {
    printf("Testing node metrics updates...\n");
    
    mxd_node_stake_t node;
    memset(&node, 0, sizeof(node));
    assert(mxd_init_node_metrics(&node.metrics) == 0);
    
    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);
    
    // Test single update
    assert(mxd_update_node_metrics(&node, 100, timestamp) == 0);
    assert(node.metrics.avg_response_time == 100);
    assert(node.metrics.min_response_time == 100);
    assert(node.metrics.max_response_time == 100);
    assert(node.metrics.response_count == 1);
    
    // Test multiple updates
    assert(mxd_update_node_metrics(&node, 200, timestamp + 1000) == 0);
    assert(node.metrics.avg_response_time == 150); // (100 + 200) / 2
    assert(node.metrics.min_response_time == 100);
    assert(node.metrics.max_response_time == 200);
    assert(node.metrics.response_count == 2);
    
    // Test invalid response time
    assert(mxd_update_node_metrics(&node, MXD_MAX_RESPONSE_TIME + 1, timestamp) == -1);
    
    printf("Node metrics update tests passed\n");
}

// Test node ranking calculation
static void test_node_ranking(void) {
    printf("Testing node ranking calculation...\n");
    
    mxd_node_stake_t node;
    memset(&node, 0, sizeof(node));
    node.stake_amount = 1000.0;
    node.active = 1;
    assert(mxd_init_node_metrics(&node.metrics) == 0);
    
    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);
    
    // Add enough responses to meet minimum requirement
    for (int i = 0; i < MXD_MIN_RESPONSE_COUNT; i++) {
        assert(mxd_update_node_metrics(&node, 100, timestamp + i * 1000) == 0);
    }
    
    // Test ranking calculation
    int rank = mxd_calculate_node_rank(&node, 10000.0);
    assert(rank >= 0);
    assert(rank <= 1000);
    
    // Test inactive node
    node.active = 0;
    assert(mxd_calculate_node_rank(&node, 10000.0) == -1);
    
    printf("Node ranking tests passed\n");
}

// Test tip distribution
static void test_tip_distribution(void) {
    printf("Testing tip distribution...\n");
    
    const size_t node_count = 3;
    mxd_node_stake_t nodes[node_count];
    memset(nodes, 0, sizeof(nodes));
    
    // Initialize nodes with different performance profiles
    for (size_t i = 0; i < node_count; i++) {
        nodes[i].stake_amount = 1000.0 * (i + 1);
        nodes[i].active = 1;
        assert(mxd_init_node_metrics(&nodes[i].metrics) == 0);
        
        uint64_t timestamp;
        assert(mxd_get_network_time(&timestamp) == 0);
        
        // Add responses with varying performance
        for (int j = 0; j < MXD_MIN_RESPONSE_COUNT; j++) {
            assert(mxd_update_node_metrics(&nodes[i], 100 * (i + 1), timestamp + j * 1000) == 0);
        }
    }
    
    // Calculate ranks and distribute tips
    double total_stake = 6000.0; // Sum of all stake amounts
    for (size_t i = 0; i < node_count; i++) {
        nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
        assert(nodes[i].rank >= 0);
    }
    
    double total_tip = 100.0;
    assert(mxd_distribute_tips(nodes, node_count, total_tip) == 0);
    
    // Verify tip distribution
    double total_distributed = 0.0;
    for (size_t i = 0; i < node_count; i++) {
        assert(nodes[i].metrics.tip_share >= 0.0);
        assert(nodes[i].metrics.tip_share <= total_tip);
        total_distributed += nodes[i].metrics.tip_share;
    }
    
    // Check total distributed amount (allowing for floating-point imprecision)
    assert(fabs(total_distributed - total_tip) < 0.0001);
    
    printf("Tip distribution tests passed\n");
}

// Test rapid table updates
static void test_rapid_table_update(void) {
    printf("Testing rapid table updates...\n");
    
    const size_t node_count = 5;
    mxd_node_stake_t nodes[node_count];
    memset(nodes, 0, sizeof(nodes));
    
    // Initialize nodes with varying performance profiles
    for (size_t i = 0; i < node_count; i++) {
        nodes[i].stake_amount = 1000.0;
        nodes[i].active = 1;
        assert(mxd_init_node_metrics(&nodes[i].metrics) == 0);
        
        uint64_t timestamp;
        assert(mxd_get_network_time(&timestamp) == 0);
        
        // Add responses with varying performance
        for (int j = 0; j < MXD_MIN_RESPONSE_COUNT; j++) {
            uint64_t response_time = 100 * (i + 1); // Different performance levels
            assert(mxd_update_node_metrics(&nodes[i], response_time, timestamp + j * 1000) == 0);
        }
    }
    
    // Update rapid table
    assert(mxd_update_rapid_table(nodes, node_count, 5000.0) == 0);
    
    // Verify sorting order
    for (size_t i = 1; i < node_count; i++) {
        // Active nodes should be first
        if (nodes[i-1].active && !nodes[i].active) {
            continue;
        }
        // Higher ranks should be first
        if (nodes[i-1].active == nodes[i].active) {
            assert(nodes[i-1].rank >= nodes[i].rank);
        }
    }
    
    printf("Rapid table update tests passed\n");
}

// Test node performance validation
static void test_performance_validation(void) {
    printf("Testing node performance validation...\n");
    
    mxd_node_stake_t node;
    memset(&node, 0, sizeof(node));
    node.active = 1;
    assert(mxd_init_node_metrics(&node.metrics) == 0);
    
    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);
    
    // Test insufficient responses
    assert(mxd_validate_node_performance(&node, timestamp) == -1);
    
    // Add minimum required responses
    for (int i = 0; i < MXD_MIN_RESPONSE_COUNT; i++) {
        assert(mxd_update_node_metrics(&node, 100, timestamp + i * 1000) == 0);
    }
    
    // Test valid performance
    assert(mxd_validate_node_performance(&node, timestamp + MXD_MIN_RESPONSE_COUNT * 1000) == 0);
    
    // Test inactive node
    node.active = 0;
    assert(mxd_validate_node_performance(&node, timestamp + MXD_MIN_RESPONSE_COUNT * 1000) == -1);
    
    printf("Performance validation tests passed\n");
}

int main(void) {
    printf("Running enhanced consensus tests...\n");
    
    // Initialize NTP synchronization
    assert(mxd_init_ntp() == 0);
    
    test_node_metrics_init();
    test_node_metrics_update();
    test_node_ranking();
    test_tip_distribution();
    test_rapid_table_update();
    test_performance_validation();
    
    printf("All enhanced consensus tests passed!\n");
    return 0;
}
