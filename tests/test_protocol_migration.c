#include "../include/mxd_protocol_version.h"
#include "../include/mxd_migration.h"
#include "../include/mxd_blockchain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void test_activation_heights() {
    printf("\n=== Test: Activation Heights ===\n");

    // Test mainnet activation heights
    mxd_activation_heights_t mainnet = mxd_get_activation_heights(MXD_NETWORK_MAINNET);
    printf("Mainnet: v2 at %u, v3 at %u\n",
           mainnet.v2_activation_height, mainnet.v3_activation_height);
    assert(mainnet.v2_activation_height < mainnet.v3_activation_height);

    // Test testnet activation heights
    mxd_activation_heights_t testnet = mxd_get_activation_heights(MXD_NETWORK_TESTNET);
    printf("Testnet: v2 at %u, v3 at %u\n",
           testnet.v2_activation_height, testnet.v3_activation_height);
    assert(testnet.v2_activation_height < testnet.v3_activation_height);

    // Test devnet activation heights
    mxd_activation_heights_t devnet = mxd_get_activation_heights(MXD_NETWORK_DEVNET);
    printf("Devnet: v2 at %u, v3 at %u\n",
           devnet.v2_activation_height, devnet.v3_activation_height);
    assert(devnet.v2_activation_height == 0);
    assert(devnet.v3_activation_height == 0);

    printf("✓ Activation heights test passed\n");
}

void test_required_protocol_version() {
    printf("\n=== Test: Required Protocol Version ===\n");

    // Set to testnet for testing
    mxd_set_network_type(MXD_NETWORK_TESTNET);
    mxd_activation_heights_t testnet = mxd_get_activation_heights(MXD_NETWORK_TESTNET);

    // Test v1 heights
    uint32_t height_v1 = testnet.v2_activation_height - 1;
    uint32_t version_v1 = mxd_get_required_protocol_version(height_v1, MXD_NETWORK_TESTNET);
    printf("Height %u requires v%u (expected v1)\n", height_v1, version_v1);
    assert(version_v1 == 1);

    // Test v2 heights
    uint32_t height_v2 = testnet.v2_activation_height;
    uint32_t version_v2 = mxd_get_required_protocol_version(height_v2, MXD_NETWORK_TESTNET);
    printf("Height %u requires v%u (expected v2)\n", height_v2, version_v2);
    assert(version_v2 == 2);

    // Test v3 heights
    uint32_t height_v3 = testnet.v3_activation_height;
    uint32_t version_v3 = mxd_get_required_protocol_version(height_v3, MXD_NETWORK_TESTNET);
    printf("Height %u requires v%u (expected v3)\n", height_v3, version_v3);
    assert(version_v3 == 3);

    printf("✓ Required protocol version test passed\n");
}

void test_block_version_validation() {
    printf("\n=== Test: Block Version Validation ===\n");

    mxd_set_network_type(MXD_NETWORK_TESTNET);
    mxd_activation_heights_t testnet = mxd_get_activation_heights(MXD_NETWORK_TESTNET);

    // Test valid v1 block before v2 activation
    uint32_t height_v1 = testnet.v2_activation_height - 1;
    int valid_v1 = mxd_is_valid_block_version(1, height_v1, MXD_NETWORK_TESTNET);
    printf("v1 block at height %u: %s\n", height_v1, valid_v1 ? "VALID" : "INVALID");
    assert(valid_v1 == 1);

    // Test invalid v2 block before v2 activation
    int invalid_v2_early = mxd_is_valid_block_version(2, height_v1, MXD_NETWORK_TESTNET);
    printf("v2 block at height %u: %s (should be INVALID)\n",
           height_v1, invalid_v2_early ? "VALID" : "INVALID");
    assert(invalid_v2_early == 0);

    // Test valid v2 block at v2 activation
    uint32_t height_v2 = testnet.v2_activation_height;
    int valid_v2 = mxd_is_valid_block_version(2, height_v2, MXD_NETWORK_TESTNET);
    printf("v2 block at height %u: %s\n", height_v2, valid_v2 ? "VALID" : "INVALID");
    assert(valid_v2 == 1);

    // Test invalid v1 block after v2 activation
    int invalid_v1_late = mxd_is_valid_block_version(1, height_v2, MXD_NETWORK_TESTNET);
    printf("v1 block at height %u: %s (should be INVALID)\n",
           height_v2, invalid_v1_late ? "VALID" : "INVALID");
    assert(invalid_v1_late == 0);

    // Test valid v3 block at v3 activation
    uint32_t height_v3 = testnet.v3_activation_height;
    int valid_v3 = mxd_is_valid_block_version(3, height_v3, MXD_NETWORK_TESTNET);
    printf("v3 block at height %u: %s\n", height_v3, valid_v3 ? "VALID" : "INVALID");
    assert(valid_v3 == 1);

    // Test invalid v2 block after v3 activation
    int invalid_v2_late = mxd_is_valid_block_version(2, height_v3, MXD_NETWORK_TESTNET);
    printf("v2 block at height %u: %s (should be INVALID)\n",
           height_v3, invalid_v2_late ? "VALID" : "INVALID");
    assert(invalid_v2_late == 0);

    printf("✓ Block version validation test passed\n");
}

void test_automatic_version_assignment() {
    printf("\n=== Test: Automatic Version Assignment ===\n");

    mxd_set_network_type(MXD_NETWORK_TESTNET);
    mxd_activation_heights_t testnet = mxd_get_activation_heights(MXD_NETWORK_TESTNET);

    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);
    uint8_t proposer_id[20];
    memset(proposer_id, 1, 20);

    // Test block created before v2 activation gets v1
    uint32_t height_v1 = testnet.v2_activation_height - 1;
    mxd_block_t block_v1;
    assert(mxd_init_block_with_validation(&block_v1, prev_hash, proposer_id, height_v1) == 0);
    printf("Block at height %u automatically assigned v%u (expected v1)\n",
           height_v1, block_v1.version);
    assert(block_v1.version == 1);
    mxd_free_block(&block_v1);

    // Test block created at v2 activation gets v2
    uint32_t height_v2 = testnet.v2_activation_height;
    mxd_block_t block_v2;
    assert(mxd_init_block_with_validation(&block_v2, prev_hash, proposer_id, height_v2) == 0);
    printf("Block at height %u automatically assigned v%u (expected v2)\n",
           height_v2, block_v2.version);
    assert(block_v2.version == 2);
    mxd_free_block(&block_v2);

    // Test block created at v3 activation gets v3
    uint32_t height_v3 = testnet.v3_activation_height;
    mxd_block_t block_v3;
    assert(mxd_init_block_with_validation(&block_v3, prev_hash, proposer_id, height_v3) == 0);
    printf("Block at height %u automatically assigned v%u (expected v3)\n",
           height_v3, block_v3.version);
    assert(block_v3.version == 3);
    mxd_free_block(&block_v3);

    printf("✓ Automatic version assignment test passed\n");
}

void test_block_migration_to_v3() {
    printf("\n=== Test: Block Migration to V3 ===\n");

    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);

    // Create a v1 block
    mxd_block_t block;
    assert(mxd_init_block(&block, prev_hash) == 0);
    block.version = 1;
    block.height = 100;

    // Add some transactions
    uint8_t tx1[] = "transaction_1";
    uint8_t tx2[] = "transaction_2";
    assert(mxd_add_transaction(&block, tx1, sizeof(tx1)) == 0);
    assert(mxd_add_transaction(&block, tx2, sizeof(tx2)) == 0);

    printf("Original block: v%u at height %u\n", block.version, block.height);

    // Migrate to v3
    assert(mxd_migrate_block_to_v3(&block) == 0);

    printf("Migrated block: v%u at height %u\n", block.version, block.height);
    assert(block.version == 3);

    // Verify contracts_state_root was computed
    uint8_t zero_hash[64];
    memset(zero_hash, 0, 64);
    int has_state_root = (memcmp(block.contracts_state_root, zero_hash, 64) != 0);
    printf("Contracts state root computed: %s\n", has_state_root ? "YES" : "NO");

    printf("Contracts state root (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", block.contracts_state_root[i]);
    }
    printf("\n");

    // Test idempotency - migrating again should succeed without changes
    uint8_t original_root[64];
    memcpy(original_root, block.contracts_state_root, 64);
    assert(mxd_migrate_block_to_v3(&block) == 0);
    assert(memcmp(original_root, block.contracts_state_root, 64) == 0);
    printf("Migration is idempotent: YES\n");

    printf("✓ Block migration test passed\n");

    mxd_free_block(&block);
}

void test_devnet_genesis_v3() {
    printf("\n=== Test: Devnet Genesis with V3 ===\n");

    // Devnet should support v3 from genesis (height 0)
    mxd_set_network_type(MXD_NETWORK_DEVNET);

    uint8_t prev_hash[64];
    memset(prev_hash, 0, 64);
    uint8_t proposer_id[20];
    memset(proposer_id, 1, 20);

    // Genesis block on devnet should be v3
    mxd_block_t genesis;
    assert(mxd_init_block_with_validation(&genesis, prev_hash, proposer_id, 0) == 0);
    printf("Devnet genesis block version: v%u (expected v3)\n", genesis.version);
    assert(genesis.version == 3);

    printf("✓ Devnet genesis V3 test passed\n");

    mxd_free_block(&genesis);
}

void test_cross_network_differences() {
    printf("\n=== Test: Cross-Network Differences ===\n");

    uint32_t height = 10000;

    // Mainnet at height 10000 should be v2
    uint32_t mainnet_version = mxd_get_required_protocol_version(height, MXD_NETWORK_MAINNET);
    printf("Mainnet at height %u: v%u\n", height, mainnet_version);
    assert(mainnet_version == 2);

    // Testnet at height 10000 should be v3 (if v3_activation is < 10000)
    uint32_t testnet_version = mxd_get_required_protocol_version(height, MXD_NETWORK_TESTNET);
    printf("Testnet at height %u: v%u\n", height, testnet_version);
    assert(testnet_version == 3);

    // Devnet at any height should be v3
    uint32_t devnet_version = mxd_get_required_protocol_version(height, MXD_NETWORK_DEVNET);
    printf("Devnet at height %u: v%u\n", height, devnet_version);
    assert(devnet_version == 3);

    printf("✓ Cross-network differences test passed\n");
}

int main() {
    printf("Starting Protocol Migration Tests\n");
    printf("==================================\n");

    test_activation_heights();
    test_required_protocol_version();
    test_block_version_validation();
    test_automatic_version_assignment();
    test_block_migration_to_v3();
    test_devnet_genesis_v3();
    test_cross_network_differences();

    printf("\n==================================\n");
    printf("All protocol migration tests passed!\n");
    printf("\nMigration Summary:\n");
    printf("- Mainnet v3 activation: height 100,000\n");
    printf("- Testnet v3 activation: height 5,000\n");
    printf("- Devnet v3 activation: height 0 (genesis)\n");

    return 0;
}
