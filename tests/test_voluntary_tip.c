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
    
    // Test setting valid tip (1.5 MXD = 150000000 base units)
    TEST_VALUE("Setting tip value", "%lu", 150000000ULL);
    TEST_ASSERT(mxd_set_voluntary_tip(&tx, 150000000ULL) == 0, "Set valid tip amount");
    TEST_ASSERT(mxd_get_voluntary_tip(&tx) == 150000000ULL, "Retrieved tip matches set value");
    
    // Test setting zero tip
    TEST_VALUE("Setting tip value", "%lu", 0ULL);
    TEST_ASSERT(mxd_set_voluntary_tip(&tx, 0ULL) == 0, "Set zero tip amount");
    TEST_ASSERT(mxd_get_voluntary_tip(&tx) == 0ULL, "Retrieved tip is zero");
    
    // Test with NULL transaction
    TEST_ASSERT(mxd_set_voluntary_tip(NULL, 100000000ULL) == -1, "NULL transaction rejected for set");
    TEST_ASSERT(mxd_get_voluntary_tip(NULL) == 0, "NULL transaction rejected for get");
    
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
    uint8_t pub_key[32] = {0};
    assert(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0);
    
    // Add a sample output (1.0 MXD = 100000000 base units)
    uint8_t recipient_key[32] = {0};
    assert(test_add_tx_output_to_pubkey_ed25519(&tx, recipient_key, 100000000ULL) == 0);
    
    // Test with valid tip (0.5 MXD = 50000000 base units)
    assert(mxd_set_voluntary_tip(&tx, 50000000ULL) == 0);
    
    // Test with zero tip
    assert(mxd_set_voluntary_tip(&tx, 0ULL) == 0);
    
    mxd_free_transaction(&tx);
    printf("Transaction validation with tips tests passed\n");
}

// Test transaction serialization with tips
static void test_transaction_serialization_with_tip(void) {
    printf("Testing transaction serialization with tips...\n");
    mxd_transaction_t tx;
    assert(mxd_create_transaction(&tx) == 0);
    
    // Set up transaction data (1.0 MXD = 100000000 base units)
    uint8_t prev_hash[64] = {0};
    uint8_t pub_key[32] = {0};
    uint8_t recipient_key[32] = {0};
    assert(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0);
    assert(test_add_tx_output_to_pubkey_ed25519(&tx, recipient_key, 100000000ULL) == 0);
    assert(mxd_set_voluntary_tip(&tx, 50000000ULL) == 0);
    
    // Calculate hash
    uint8_t hash1[64], hash2[64];
    assert(mxd_calculate_tx_hash(&tx, hash1) == 0);
    
    // Modify tip and verify hash changes (0.7 MXD = 70000000 base units)
    assert(mxd_set_voluntary_tip(&tx, 70000000ULL) == 0);
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
