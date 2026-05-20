#include "../include/mxd_blockchain.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void test_v3_block_with_contracts_state_root() {
    printf("\n=== Test: V3 Block with Contracts State Root ===\n");

    mxd_block_t block;
    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);

    // Initialize v3 block
    assert(mxd_init_block(&block, prev_hash) == 0);
    block.version = 3;  // Upgrade to v3

    // Add some dummy transactions (simulating contract executions)
    uint8_t tx1[] = "contract_deploy_tx_1";
    uint8_t tx2[] = "contract_call_tx_2";
    uint8_t tx3[] = "contract_call_tx_3";

    assert(mxd_add_transaction(&block, tx1, sizeof(tx1)) == 0);
    assert(mxd_add_transaction(&block, tx2, sizeof(tx2)) == 0);
    assert(mxd_add_transaction(&block, tx3, sizeof(tx3)) == 0);

    // Freeze transaction set (should compute contracts_state_root)
    assert(mxd_freeze_transaction_set(&block) == 0);

    // Verify contracts_state_root is not zero
    uint8_t zero_hash[64];
    memset(zero_hash, 0, 64);
    int is_zero = (memcmp(block.contracts_state_root, zero_hash, 64) == 0);

    printf("Contracts state root is %s\n", is_zero ? "zero (no contracts)" : "non-zero (has contracts)");
    printf("First 16 bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", block.contracts_state_root[i]);
    }
    printf("\n");

    // Validate block (should verify contracts_state_root)
    int validation_result = mxd_validate_block(&block);
    printf("Block validation result: %d (0 = success)\n", validation_result);

    // Calculate block hash (should include contracts_state_root)
    uint8_t block_hash[64];
    assert(mxd_calculate_block_hash(&block, block_hash) == 0);

    printf("Block hash (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", block_hash[i]);
    }
    printf("\n");

    printf("✓ V3 block with contracts state root test passed\n");

    mxd_free_block(&block);
}

void test_contracts_state_root_calculation() {
    printf("\n=== Test: Contracts State Root Calculation ===\n");

    mxd_block_t block;
    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);

    assert(mxd_init_block(&block, prev_hash) == 0);
    block.version = 3;

    // Test with 0 transactions
    uint8_t root_0[64];
    assert(mxd_calculate_contracts_state_root(&block, root_0) == 0);
    printf("0 transactions: root is zero = %d\n",
           memcmp(root_0, (uint8_t[64]){0}, 64) == 0);

    // Test with 1 transaction
    uint8_t tx1[] = "single_contract_tx";
    assert(mxd_add_transaction(&block, tx1, sizeof(tx1)) == 0);

    uint8_t root_1[64];
    assert(mxd_calculate_contracts_state_root(&block, root_1) == 0);
    printf("1 transaction: root computed\n");

    // Test with 3 transactions
    uint8_t tx2[] = "contract_tx_2";
    uint8_t tx3[] = "contract_tx_3";
    assert(mxd_add_transaction(&block, tx2, sizeof(tx2)) == 0);
    assert(mxd_add_transaction(&block, tx3, sizeof(tx3)) == 0);

    uint8_t root_3[64];
    assert(mxd_calculate_contracts_state_root(&block, root_3) == 0);
    printf("3 transactions: root computed\n");

    // Verify roots are different
    assert(memcmp(root_0, root_1, 64) != 0);
    assert(memcmp(root_1, root_3, 64) != 0);

    printf("✓ Contracts state root calculation test passed\n");

    mxd_free_block(&block);
}

void test_v3_block_validation() {
    printf("\n=== Test: V3 Block Validation ===\n");

    mxd_block_t block;
    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);

    assert(mxd_init_block(&block, prev_hash) == 0);
    block.version = 3;

    // Add transaction
    uint8_t tx1[] = "test_contract_tx";
    assert(mxd_add_transaction(&block, tx1, sizeof(tx1)) == 0);

    // Freeze transaction set
    assert(mxd_freeze_transaction_set(&block) == 0);

    // Validation should succeed
    int result = mxd_validate_block(&block);
    printf("Valid block validation: %d (expected 0)\n", result);

    // Corrupt contracts_state_root
    uint8_t original_root[64];
    memcpy(original_root, block.contracts_state_root, 64);
    block.contracts_state_root[0] ^= 0xFF; // Flip bits

    // Validation should fail
    result = mxd_validate_block(&block);
    printf("Corrupted state root validation: %d (expected non-zero)\n", result);
    assert(result != 0);

    // Restore and verify
    memcpy(block.contracts_state_root, original_root, 64);
    result = mxd_validate_block(&block);
    assert(result == 0);

    printf("✓ V3 block validation test passed\n");

    mxd_free_block(&block);
}

void test_v1_v3_block_hash_difference() {
    printf("\n=== Test: V1 vs V3 Block Hash Difference ===\n");

    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);

    // Create v1 block
    mxd_block_t block_v1;
    assert(mxd_init_block(&block_v1, prev_hash) == 0);
    block_v1.version = 1;

    uint8_t tx[] = "test_transaction";
    assert(mxd_add_transaction(&block_v1, tx, sizeof(tx)) == 0);
    assert(mxd_freeze_transaction_set(&block_v1) == 0);

    uint8_t hash_v1[64];
    assert(mxd_calculate_block_hash(&block_v1, hash_v1) == 0);

    // Create v3 block with same data
    mxd_block_t block_v3;
    assert(mxd_init_block(&block_v3, prev_hash) == 0);
    block_v3.version = 3;
    block_v3.timestamp = block_v1.timestamp; // Same timestamp
    block_v3.difficulty = block_v1.difficulty;
    block_v3.nonce = block_v1.nonce;

    assert(mxd_add_transaction(&block_v3, tx, sizeof(tx)) == 0);
    assert(mxd_freeze_transaction_set(&block_v3) == 0);

    uint8_t hash_v3[64];
    assert(mxd_calculate_block_hash(&block_v3, hash_v3) == 0);

    // Hashes should be different (v3 includes contracts_state_root)
    int hashes_differ = (memcmp(hash_v1, hash_v3, 64) != 0);
    printf("V1 vs V3 block hashes differ: %s\n", hashes_differ ? "YES" : "NO");
    assert(hashes_differ);

    printf("V1 hash (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02x", hash_v1[i]);
    printf("\n");

    printf("V3 hash (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02x", hash_v3[i]);
    printf("\n");

    printf("✓ V1 vs V3 block hash difference test passed\n");

    mxd_free_block(&block_v1);
    mxd_free_block(&block_v3);
}

int main() {
    printf("Starting Contract State Root Integration Tests\n");
    printf("=============================================\n");

    test_contracts_state_root_calculation();
    test_v3_block_with_contracts_state_root();
    test_v3_block_validation();
    test_v1_v3_block_hash_difference();

    printf("\n=============================================\n");
    printf("All contract state root integration tests passed!\n");

    return 0;
}
