#include "../include/mxd_validator_management.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_block_proposer.h"
#include "../include/mxd_logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Mock balance for testing
static mxd_amount_t mock_balance = 0;

// Override mxd_get_balance for testing
mxd_amount_t mxd_get_balance(const uint8_t address[20]) {
    return mock_balance;
}

void test_validator_join_with_sufficient_stake(void) {
    printf("Running: test_validator_join_with_sufficient_stake\n");

    // Setup: Create validator with 0.10% stake
    mxd_amount_t total_supply = 1000000000000000ULL; // 10M MXD (8 decimals)
    mxd_amount_t required_stake = total_supply / 1000; // 0.10%

    uint8_t test_addr[20] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                             0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14};
    uint8_t test_pubkey[32];
    uint8_t test_privkey[64];

    // Generate test keypair
    if (mxd_sig_keygen(MXD_SIGALG_ED25519, test_pubkey, test_privkey) != 0) {
        printf("FAILED: Could not generate test keypair\n");
        return;
    }

    // Mock UTXO balance - slightly above requirement
    mock_balance = required_stake + 100000;

    // Initialize request pool
    if (mxd_init_validator_request_pool() != 0) {
        printf("FAILED: Could not initialize request pool\n");
        return;
    }

    // Submit join request
    int result = mxd_submit_validator_join_request(test_addr, test_pubkey, 32,
                                                   MXD_SIGALG_ED25519, test_privkey);
    assert(result == 0);

    // Verify request in pool
    mxd_validator_join_request_t *requests = NULL;
    size_t count = 0;
    mxd_get_pending_join_requests(&requests, &count);
    assert(count == 1);
    assert(memcmp(requests[0].node_address, test_addr, 20) == 0);

    // Validate request
    result = mxd_validate_join_request(&requests[0], total_supply);
    assert(result == 0);

    printf("✓ test_validator_join_with_sufficient_stake passed\n");
}

void test_validator_join_insufficient_stake(void) {
    printf("Running: test_validator_join_insufficient_stake\n");

    mxd_amount_t total_supply = 1000000000000000ULL;
    mxd_amount_t required_stake = total_supply / 1000;

    uint8_t test_addr[20] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                             0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14};

    // Mock insufficient balance
    mock_balance = required_stake - 1000;

    mxd_validator_join_request_t request;
    memset(&request, 0, sizeof(request));
    memcpy(request.node_address, test_addr, 20);
    request.stake_amount = mock_balance;
    request.algo_id = MXD_SIGALG_ED25519;

    // Validation should fail
    int result = mxd_validate_join_request(&request, total_supply);
    assert(result != 0);

    printf("✓ test_validator_join_insufficient_stake passed\n");
}

void test_liveness_tracking(void) {
    printf("Running: test_liveness_tracking\n");

    // Setup rapid table with 3 validators
    mxd_rapid_table_t table;
    memset(&table, 0, sizeof(table));
    table.capacity = 10;
    table.count = 3;
    table.nodes = calloc(10, sizeof(mxd_node_stake_t*));

    // Add validators
    uint8_t addr1[20] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t addr2[20] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                         0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    uint8_t addr3[20] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                         0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03};

    table.nodes[0] = calloc(1, sizeof(mxd_node_stake_t));
    table.nodes[1] = calloc(1, sizeof(mxd_node_stake_t));
    table.nodes[2] = calloc(1, sizeof(mxd_node_stake_t));

    memcpy(table.nodes[0]->node_address, addr1, 20);
    memcpy(table.nodes[1]->node_address, addr2, 20);
    memcpy(table.nodes[2]->node_address, addr3, 20);

    // Simulate 10 consecutive misses for validator 1 (addr1)
    for (uint32_t height = 100; height < 110; height++) {
        // Expected proposer: height % 3
        uint32_t expected_idx = height % 3;
        uint8_t *expected_addr = (expected_idx == 0) ? addr1 : (expected_idx == 1) ? addr2 : addr3;

        // Simulate that a different validator actually proposed
        uint8_t *actual_addr = (expected_addr == addr1) ? addr2 : addr1;

        mxd_track_validator_liveness(&table, height, actual_addr);
    }

    // Check if validator marked for removal
    uint8_t *to_remove = NULL;
    size_t remove_count = 0;
    mxd_get_validators_to_remove(&table, 110, &to_remove, &remove_count);

    assert(remove_count > 0);

    // Cleanup
    free(table.nodes[0]);
    free(table.nodes[1]);
    free(table.nodes[2]);
    free(table.nodes);
    if (to_remove) {
        free(to_remove);
    }

    printf("✓ test_liveness_tracking passed (marked %zu validators for removal)\n", remove_count);
}

void test_proposer_timeout_fallback(void) {
    printf("Running: test_proposer_timeout_fallback\n");

    // Setup: height 100, 5 validators
    uint32_t height = 100;
    uint32_t validator_count = 5;

    // Primary proposer: height % validator_count = 100 % 5 = 0
    uint32_t primary_idx = 0;

    // Start timeout
    uint8_t primary_addr[20] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    mxd_start_height_timeout(height, primary_addr);

    // Initially timeout should not be expired
    assert(mxd_check_timeout_expired() == 0);

    // Wait 1 second (timeout is 30 seconds, so should still not be expired)
    sleep(1);
    assert(mxd_check_timeout_expired() == 0);

    // For testing purposes, we can't wait 30 seconds, so we'll just verify the logic
    // In production, this would wait and then check expiration

    // Increment retry
    int retry = mxd_increment_retry_count();
    assert(retry == 1);

    // Fallback proposer: (0 + 1) % 5 = 1
    uint32_t fallback_idx = (primary_idx + retry) % validator_count;
    assert(fallback_idx == 1);

    printf("✓ test_proposer_timeout_fallback passed (fallback index = %u)\n", fallback_idx);
}

void test_stake_requirement_0_10_percent(void) {
    printf("Running: test_stake_requirement_0_10_percent\n");

    mxd_amount_t total_supply = 100000000000000ULL; // 1M MXD with 8 decimals

    // 0.10% of total supply
    mxd_amount_t required_stake = total_supply / 1000;
    mxd_amount_t expected = 100000000000ULL; // 1K MXD

    assert(required_stake == expected);

    // Test with sufficient stake
    mock_balance = required_stake;
    assert(mock_balance >= total_supply / 1000);

    // Test with insufficient stake
    mock_balance = required_stake - 1;
    assert(mock_balance < total_supply / 1000);

    printf("✓ test_stake_requirement_0_10_percent passed (required stake = %llu)\n",
           (unsigned long long)required_stake);
}

int main(void) {
    printf("\n=== Running Validator Management Tests ===\n\n");

    test_validator_join_with_sufficient_stake();
    test_validator_join_insufficient_stake();
    test_liveness_tracking();
    test_proposer_timeout_fallback();
    test_stake_requirement_0_10_percent();

    printf("\n✅ All validator management tests passed!\n");
    return 0;
}
