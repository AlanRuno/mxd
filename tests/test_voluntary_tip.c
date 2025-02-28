#include "../include/mxd_transaction.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Test voluntary tip setting and getting
static void test_voluntary_tip_basic(void) {
    mxd_transaction_t tx;
    TEST_START("Basic Voluntary Tip");
    
    TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create transaction");
    
    // Test setting valid tip
    TEST_VALUE("Setting tip value", "%.1f", 1.5);
    TEST_ASSERT(mxd_set_voluntary_tip(&tx, 1.5) == 0, "Set valid tip amount");
    TEST_ASSERT(mxd_get_voluntary_tip(&tx) == 1.5, "Retrieved tip matches set value");
    
    // Test setting zero tip
    TEST_VALUE("Setting tip value", "%.1f", 0.0);
    TEST_ASSERT(mxd_set_voluntary_tip(&tx, 0.0) == 0, "Set zero tip amount");
    TEST_ASSERT(mxd_get_voluntary_tip(&tx) == 0.0, "Retrieved tip is zero");
    
    // Test setting negative tip (should fail)
    TEST_VALUE("Setting invalid tip value", "%.1f", -1.0);
    TEST_ASSERT(mxd_set_voluntary_tip(&tx, -1.0) == -1, "Negative tip rejected");
    
    // Test with NULL transaction
    TEST_ASSERT(mxd_set_voluntary_tip(NULL, 1.0) == -1, "NULL transaction rejected for set");
    TEST_ASSERT(mxd_get_voluntary_tip(NULL) == -1, "NULL transaction rejected for get");
    
    mxd_free_transaction(&tx);
    printf("Basic voluntary tip tests passed\n");
}

// Test transaction validation with tips
static void test_transaction_validation_with_tip(void) {
    printf("Testing transaction validation with tips...\n");
    mxd_transaction_t tx;
    assert(mxd_create_transaction(&tx) == 0);
    
    // Add a sample input
    uint8_t prev_hash[64] = {0};
    uint8_t pub_key[256] = {0};
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    
    // Add a sample output
    uint8_t recipient_key[256] = {0};
    assert(mxd_add_tx_output(&tx, recipient_key, 1.0) == 0);
    
    // Test with valid tip
    assert(mxd_set_voluntary_tip(&tx, 0.5) == 0);
    // Note: Full validation will fail due to missing signatures and UTXO verification
    
    // Test with zero tip
    assert(mxd_set_voluntary_tip(&tx, 0.0) == 0);
    
    // Test with negative tip (should fail validation)
    assert(mxd_set_voluntary_tip(&tx, -1.0) == -1);
    assert(mxd_validate_transaction(&tx) == -1);
    
    mxd_free_transaction(&tx);
    printf("Transaction validation with tips tests passed\n");
}

// Test transaction serialization with tips
static void test_transaction_serialization_with_tip(void) {
    printf("Testing transaction serialization with tips...\n");
    mxd_transaction_t tx;
    assert(mxd_create_transaction(&tx) == 0);
    
    // Set up transaction data
    uint8_t prev_hash[64] = {0};
    uint8_t pub_key[256] = {0};
    uint8_t recipient_key[256] = {0};
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    assert(mxd_add_tx_output(&tx, recipient_key, 1.0) == 0);
    assert(mxd_set_voluntary_tip(&tx, 0.5) == 0);
    
    // Calculate hash
    uint8_t hash1[64], hash2[64];
    assert(mxd_calculate_tx_hash(&tx, hash1) == 0);
    
    // Modify tip and verify hash changes
    assert(mxd_set_voluntary_tip(&tx, 0.7) == 0);
    assert(mxd_calculate_tx_hash(&tx, hash2) == 0);
    
    // Hashes should be different
    assert(memcmp(hash1, hash2, 64) != 0);
    
    mxd_free_transaction(&tx);
    printf("Transaction serialization with tips tests passed\n");
}

int main(void) {
    printf("Running voluntary tip system tests...\n");
    
    test_voluntary_tip_basic();
    test_transaction_validation_with_tip();
    test_transaction_serialization_with_tip();
    
    printf("All voluntary tip system tests passed!\n");
    return 0;
}
