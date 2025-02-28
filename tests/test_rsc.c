#include "../include/mxd_rsc.h"
#include "../include/mxd_ntp.h"
#include "../include/blockchain/mxd_rsc_internal.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

// Initialize test node with metrics
static void init_test_node(mxd_node_stake_t *node, double stake_amount) {
    memset(node, 0, sizeof(*node));
    node->stake_amount = stake_amount;
    node->active = 1;
    TEST_ASSERT(mxd_init_node_metrics(&node->metrics) == 0, "Node metrics initialization successful");
}

// Test node stake validation
static void test_node_validation(void) {
    mxd_node_stake_t node;
    
    TEST_START("Node Stake Validation");
    
    TEST_VALUE("Initial stake amount", "%.2f", 1.0);
    init_test_node(&node, 1.0);

    // Test valid stake (1% of 100)
    TEST_ASSERT(mxd_validate_node_stake(&node, 100.0) == 0, "Valid stake (1%) accepted");

    // Test invalid stake (0.05% of 100)
    TEST_VALUE("Invalid stake amount", "%.2f", 0.05);
    node.stake_amount = 0.05;
    TEST_ASSERT(mxd_validate_node_stake(&node, 100.0) == -1, "Invalid stake (0.05%) rejected");

    TEST_END("Node Stake Validation");
}

// Test node metrics initialization and updates
static void test_node_metrics(void) {
    mxd_node_stake_t node;
    init_test_node(&node, 1.0);

    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);

    // Test initial metrics
    assert(node.metrics.avg_response_time == 0);
    assert(node.metrics.min_response_time == UINT64_MAX);
    assert(node.metrics.max_response_time == 0);
    assert(node.metrics.response_count == 0);

    // Test metric updates
    assert(mxd_update_node_metrics(&node, 100, timestamp) == 0);
    assert(node.metrics.avg_response_time == 100);
    assert(node.metrics.min_response_time == 100);
    assert(node.metrics.max_response_time == 100);
    assert(node.metrics.response_count == 1);

    // Test average calculation
    assert(mxd_update_node_metrics(&node, 200, timestamp + 1000) == 0);
    assert(node.metrics.avg_response_time == 150); // (100 + 200) / 2
    assert(node.metrics.min_response_time == 100);
    assert(node.metrics.max_response_time == 200);
    assert(node.metrics.response_count == 2);

    printf("Node metrics test passed\n");
}

// Test node ranking calculation
static void test_node_ranking(void) {
    mxd_node_stake_t node;
    init_test_node(&node, 1.0);

    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);

    // Add minimum required responses
    for (int i = 0; i < 10; i++) {
        assert(mxd_update_node_metrics(&node, 100, timestamp + i * 1000) == 0);
    }

    // Test valid ranking
    int rank = mxd_calculate_node_rank(&node, 10.0);
    assert(rank >= 0);
    assert(rank <= 1000);

    // Test inactive node
    node.active = 0;
    assert(mxd_calculate_node_rank(&node, 10.0) == -1);

    printf("Node ranking test passed\n");
}

// Test tip distribution
static void test_tip_distribution(void) {
    const size_t node_count = 3;
    mxd_node_stake_t nodes[node_count];
    double total_stake = 0.0;

    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);

    // Initialize nodes with different performance profiles
    for (size_t i = 0; i < node_count; i++) {
        init_test_node(&nodes[i], 1.0 + i);
        total_stake += nodes[i].stake_amount;

        // Add responses with varying performance
        for (int j = 0; j < 10; j++) {
            assert(mxd_update_node_metrics(&nodes[i], 100 * (i + 1),
                                         timestamp + j * 1000) == 0);
        }
    }

    // Calculate ranks
    for (size_t i = 0; i < node_count; i++) {
        nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
        assert(nodes[i].rank >= 0);
    }

    // Test tip distribution
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

    printf("Tip distribution test passed\n");
}

// Test rapid table management
static void test_rapid_table(void) {
    const size_t node_count = 3;
    mxd_node_stake_t nodes[node_count];
    double total_stake = 0.0;

    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);

    // Initialize nodes with different performance profiles
    for (size_t i = 0; i < node_count; i++) {
        init_test_node(&nodes[i], 1.0 + i);
        total_stake += nodes[i].stake_amount;

        // Add responses with varying performance
        for (int j = 0; j < 10; j++) {
            assert(mxd_update_node_metrics(&nodes[i], 100 * (i + 1),
                                         timestamp + j * 1000) == 0);
        }
    }

    // Test table update
    assert(mxd_update_rapid_table(nodes, node_count, total_stake) == 0);

    // Verify sorting order (active nodes first, then by rank)
    for (size_t i = 1; i < node_count; i++) {
        if (nodes[i-1].active == nodes[i].active) {
            assert(nodes[i-1].rank >= nodes[i].rank);
        }
    }

    printf("Rapid table test passed\n");
}

// Test performance validation
static void test_performance_validation(void) {
    mxd_node_stake_t node;
    init_test_node(&node, 1.0);

    uint64_t timestamp;
    assert(mxd_get_network_time(&timestamp) == 0);

    // Test insufficient responses
    assert(mxd_validate_node_performance(&node, timestamp) == -1);

    // Add minimum required responses
    for (int i = 0; i < 10; i++) {
        assert(mxd_update_node_metrics(&node, 100, timestamp + i * 1000) == 0);
    }

    // Test valid performance
    assert(mxd_validate_node_performance(&node, timestamp + 10000) == 0);

    // Test inactive node
    node.active = 0;
    assert(mxd_validate_node_performance(&node, timestamp + 10000) == -1);

    printf("Performance validation test passed\n");
}

int main(void) {
    printf("Starting RSC tests...\n");

    // Initialize NTP synchronization
    assert(mxd_init_ntp() == 0);

    test_node_validation();
    test_node_metrics();
    test_node_ranking();
    test_tip_distribution();
    test_rapid_table();
    test_performance_validation();

    printf("All RSC tests passed\n");
    return 0;
}
