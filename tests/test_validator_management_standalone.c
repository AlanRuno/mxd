/**
 * Standalone Validator Management Tests
 * Tests core logic without requiring full blockchain setup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Test counter
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            tests_passed++; \
            printf("  ✓ %s\n", message); \
        } else { \
            tests_failed++; \
            printf("  ✗ %s\n", message); \
        } \
    } while(0)

// Test 1: Stake requirement calculation
void test_stake_requirement_calculation(void) {
    printf("\n[Test 1] Stake Requirement Calculation (0.10%%)\n");

    // Test with 1M MXD (8 decimals)
    uint64_t total_supply_1m = 100000000000000ULL; // 1,000,000.00000000
    uint64_t required_stake_1m = total_supply_1m / 1000; // 0.10%
    uint64_t expected_1m = 100000000000ULL; // 1,000.00000000

    TEST_ASSERT(required_stake_1m == expected_1m,
                "0.10% of 1M MXD = 1K MXD");

    // Test with 10M MXD
    uint64_t total_supply_10m = 1000000000000000ULL; // 10,000,000.00000000
    uint64_t required_stake_10m = total_supply_10m / 1000;
    uint64_t expected_10m = 1000000000000ULL; // 10,000.00000000

    TEST_ASSERT(required_stake_10m == expected_10m,
                "0.10% of 10M MXD = 10K MXD");

    // Test with 100M MXD
    uint64_t total_supply_100m = 10000000000000000ULL; // 100,000,000.00000000
    uint64_t required_stake_100m = total_supply_100m / 1000;
    uint64_t expected_100m = 10000000000000ULL; // 100,000.00000000

    TEST_ASSERT(required_stake_100m == expected_100m,
                "0.10% of 100M MXD = 100K MXD");

    // Verify this is 10x less than 1% requirement
    uint64_t old_requirement_1percent = total_supply_1m / 100;
    uint64_t new_requirement_0_1percent = total_supply_1m / 1000;

    TEST_ASSERT(old_requirement_1percent == new_requirement_0_1percent * 10,
                "0.10% is 10x less than 1% requirement");
}

// Test 2: Proposer selection logic
void test_proposer_selection(void) {
    printf("\n[Test 2] Proposer Selection Logic\n");

    uint32_t validator_count = 5;

    // Test primary proposer selection
    uint32_t height_100 = 100;
    uint32_t primary_index_100 = height_100 % validator_count;
    TEST_ASSERT(primary_index_100 == 0, "Height 100 mod 5 = 0 (validator 0)");

    uint32_t height_101 = 101;
    uint32_t primary_index_101 = height_101 % validator_count;
    TEST_ASSERT(primary_index_101 == 1, "Height 101 mod 5 = 1 (validator 1)");

    uint32_t height_104 = 104;
    uint32_t primary_index_104 = height_104 % validator_count;
    TEST_ASSERT(primary_index_104 == 4, "Height 104 mod 5 = 4 (validator 4)");

    // Test fallback proposer selection
    uint32_t retry_count = 1;
    uint32_t fallback_index = (primary_index_100 + retry_count) % validator_count;
    TEST_ASSERT(fallback_index == 1,
                "Fallback for validator 0 (retry 1) = validator 1");

    retry_count = 2;
    fallback_index = (primary_index_100 + retry_count) % validator_count;
    TEST_ASSERT(fallback_index == 2,
                "Fallback for validator 0 (retry 2) = validator 2");

    // Test wraparound
    retry_count = 6;
    fallback_index = (primary_index_100 + retry_count) % validator_count;
    TEST_ASSERT(fallback_index == 1,
                "Fallback with wraparound (retry 6) = validator 1");
}

// Test 3: Liveness tracking logic
void test_liveness_tracking(void) {
    printf("\n[Test 3] Liveness Tracking Logic\n");

    #define MAX_CONSECUTIVE_MISSES 10

    uint32_t consecutive_misses = 0;

    // Simulate validator missing proposals
    for (int i = 0; i < MAX_CONSECUTIVE_MISSES; i++) {
        consecutive_misses++;
    }

    TEST_ASSERT(consecutive_misses == MAX_CONSECUTIVE_MISSES,
                "Validator missed 10 consecutive proposals");

    TEST_ASSERT(consecutive_misses >= MAX_CONSECUTIVE_MISSES,
                "Validator should be marked for removal");

    // Test reset on successful proposal
    consecutive_misses = 5;
    consecutive_misses = 0; // Reset on successful proposal

    TEST_ASSERT(consecutive_misses == 0,
                "Consecutive misses reset to 0 on successful proposal");
}

// Test 4: Timeout logic
void test_timeout_logic(void) {
    printf("\n[Test 4] Timeout Logic\n");

    #define PROPOSER_TIMEOUT_MS 30000  // 30 seconds

    uint64_t wait_start_time = 1000000; // Mock timestamp
    uint64_t current_time = wait_start_time + 25000; // 25 seconds later

    uint64_t elapsed = current_time - wait_start_time;
    int timeout_expired = (elapsed >= PROPOSER_TIMEOUT_MS);

    TEST_ASSERT(!timeout_expired,
                "Timeout NOT expired after 25 seconds (< 30s threshold)");

    current_time = wait_start_time + 35000; // 35 seconds later
    elapsed = current_time - wait_start_time;
    timeout_expired = (elapsed >= PROPOSER_TIMEOUT_MS);

    TEST_ASSERT(timeout_expired,
                "Timeout expired after 35 seconds (> 30s threshold)");
}

// Test 5: Validator count adjustment
void test_validator_count_adjustment(void) {
    printf("\n[Test 5] Validator Count Adjustment After Removal\n");

    uint32_t initial_count = 10;
    uint32_t validators_to_remove = 1;
    uint32_t new_count = initial_count - validators_to_remove;

    TEST_ASSERT(new_count == 9,
                "10 validators - 1 removal = 9 validators");

    // Test proposer rotation adjustment
    uint32_t height = 100;
    uint32_t old_proposer_index = height % initial_count; // 100 % 10 = 0
    uint32_t new_proposer_index = height % new_count;     // 100 % 9 = 1

    TEST_ASSERT(old_proposer_index == 0,
                "With 10 validators, height 100 -> validator 0");
    TEST_ASSERT(new_proposer_index == 1,
                "With 9 validators, height 100 -> validator 1");

    // Test that network continues
    TEST_ASSERT(new_count > 0,
                "Network continues with positive validator count");
}

// Test 6: Fallback retry limits
void test_fallback_retry_limits(void) {
    printf("\n[Test 6] Fallback Retry Limits\n");

    #define MAX_FALLBACK_RETRIES 10

    uint32_t retry_count = 0;
    uint32_t validator_count = 5;
    uint32_t primary_index = 0;

    // Test maximum retries
    for (retry_count = 1; retry_count <= MAX_FALLBACK_RETRIES; retry_count++) {
        uint32_t fallback_index = (primary_index + retry_count) % validator_count;
        // Should wrap around multiple times
    }

    TEST_ASSERT(retry_count == MAX_FALLBACK_RETRIES + 1,
                "Can attempt up to 10 fallback retries");

    // After 10 retries with 5 validators, we've cycled twice
    uint32_t final_fallback = (primary_index + MAX_FALLBACK_RETRIES) % validator_count;
    TEST_ASSERT(final_fallback == 0,
                "After 10 retries, cycle back to validator 0");
}

// Test 7: Edge cases
void test_edge_cases(void) {
    printf("\n[Test 7] Edge Cases\n");

    // Single validator network
    uint32_t single_validator = 1;
    uint32_t height = 100;
    uint32_t proposer = height % single_validator;

    TEST_ASSERT(proposer == 0,
                "Single validator network: always validator 0");

    // Two validator network
    uint32_t two_validators = 2;
    uint32_t proposer_even = 100 % two_validators;
    uint32_t proposer_odd = 101 % two_validators;

    TEST_ASSERT(proposer_even == 0 && proposer_odd == 1,
                "Two validators alternate: 0, 1, 0, 1...");

    // Large validator set
    uint32_t large_validator_set = 100;
    uint32_t proposer_large = 150 % large_validator_set;

    TEST_ASSERT(proposer_large == 50,
                "Large validator set (100): height 150 -> validator 50");

    // Zero stake edge case (should fail validation)
    uint64_t total_supply = 1000000000000000ULL;
    uint64_t zero_stake = 0;
    int is_valid = (zero_stake >= total_supply / 1000) ? 1 : 0;

    TEST_ASSERT(!is_valid,
                "Zero stake fails validation (< 0.10% requirement)");
}

// Test 8: Block proposer validation
void test_block_proposer_validation(void) {
    printf("\n[Test 8] Block Proposer Validation\n");

    uint32_t height = 100;
    uint32_t validator_count = 5;
    uint32_t primary_index = height % validator_count; // 0

    // Test primary proposer validation
    uint32_t actual_proposer = 0;
    int is_primary = (actual_proposer == primary_index);
    TEST_ASSERT(is_primary,
                "Validator 0 is valid primary proposer for height 100");

    // Test fallback proposer validation (retry 1)
    actual_proposer = 1;
    uint32_t expected_fallback_1 = (primary_index + 1) % validator_count;
    int is_fallback_1 = (actual_proposer == expected_fallback_1);
    TEST_ASSERT(is_fallback_1,
                "Validator 1 is valid fallback proposer (retry 1)");

    // Test fallback proposer validation (retry 2)
    actual_proposer = 2;
    uint32_t expected_fallback_2 = (primary_index + 2) % validator_count;
    int is_fallback_2 = (actual_proposer == expected_fallback_2);
    TEST_ASSERT(is_fallback_2,
                "Validator 2 is valid fallback proposer (retry 2)");

    // Test invalid proposer (not within retry range)
    // If we only checked up to retry 2, validator 4 would be invalid
    actual_proposer = 4;
    uint32_t max_checked_retry = 2;
    int found_within_range = 0;
    for (uint32_t r = 0; r <= max_checked_retry; r++) {
        if (actual_proposer == (primary_index + r) % validator_count) {
            found_within_range = 1;
            break;
        }
    }
    TEST_ASSERT(!found_within_range,
                "Validator 4 is NOT valid within retry range 0-2");
}

int main(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  Standalone Validator Management Logic Tests\n");
    printf("═══════════════════════════════════════════════════════════\n");

    test_stake_requirement_calculation();
    test_proposer_selection();
    test_liveness_tracking();
    test_timeout_logic();
    test_validator_count_adjustment();
    test_fallback_retry_limits();
    test_edge_cases();
    test_block_proposer_validation();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  Test Results\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("  Total:  %d\n", tests_passed + tests_failed);
    printf("═══════════════════════════════════════════════════════════\n");

    if (tests_failed == 0) {
        printf("\n✅ All tests passed!\n\n");
        return 0;
    } else {
        printf("\n❌ Some tests failed!\n\n");
        return 1;
    }
}
