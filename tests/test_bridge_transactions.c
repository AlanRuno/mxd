/**
 * @file test_bridge_transactions.c
 * @brief Comprehensive tests for bridge transactions (v3)
 */

#include "../include/mxd_transaction.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define TEST_DB_PATH "./test_bridge_tx.db"

// Test helper: create a mock authorized bridge contract
static void setup_authorized_bridge(const uint8_t contract_hash[64]) {
    rocksdb_t *db = mxd_get_rocksdb_db();
    assert(db != NULL);

    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, contract_hash, 64);

    rocksdb_writeoptions_t *writeopts = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(db, writeopts, (const char *)key, 76, "1", 1, &err);

    rocksdb_writeoptions_destroy(writeopts);
    assert(err == NULL);
}

// Test 1: Create bridge mint transaction
void test_create_bridge_mint_tx() {
    printf("Test 1: Create bridge mint transaction\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    // Set bridge contract hash
    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xAA;
    }

    // Set source chain ID (BNB testnet = 97)
    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    // Set source transaction hash
    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0xBB;
    }

    payload.source_block_number = 12345;

    // Set recipient address
    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = 0xCC;
    }

    payload.amount = 100000000000;  // 100 MXD in base units
    payload.proof_length = 256;

    // Create transaction
    mxd_transaction_v3_t tx;
    int result = mxd_create_bridge_mint_tx(&tx, &payload);
    assert(result == 0);

    // Verify transaction structure
    assert(tx.version == 3);
    assert(tx.type == MXD_TX_TYPE_BRIDGE_MINT);
    assert(tx.input_count == 0);
    assert(tx.output_count == 1);
    assert(tx.payload.bridge != NULL);
    assert(memcmp(tx.payload.bridge->bridge_contract, payload.bridge_contract, 64) == 0);
    assert(tx.outputs[0].amount == payload.amount);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Bridge mint transaction created successfully\n");
}

// Test 2: Validate bridge mint transaction
void test_validate_bridge_mint_tx() {
    printf("Test 2: Validate bridge mint transaction\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    // Set bridge contract hash
    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xDD;
    }

    // Authorize this bridge contract
    setup_authorized_bridge(payload.bridge_contract);

    // Set source chain ID (BNB mainnet = 56)
    uint32_t chain_id = 56;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    // Set unique source transaction hash
    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0xEE;
    }

    payload.source_block_number = 54321;

    // Set recipient address (non-zero)
    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 1;
    }

    payload.amount = 50000000000;  // 50 MXD
    payload.proof_length = 512;

    // Create and validate transaction
    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    int result = mxd_validate_bridge_mint_tx(&tx);
    assert(result == 0);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Bridge mint transaction validated successfully\n");
}

// Test 3: Reject unauthorized bridge contract
void test_reject_unauthorized_bridge() {
    printf("Test 3: Reject unauthorized bridge contract\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    // Set bridge contract hash (NOT authorized)
    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xFF;
    }

    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0x11;
    }

    payload.source_block_number = 999;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 10;
    }

    payload.amount = 10000000000;
    payload.proof_length = 128;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    // Should fail validation (unauthorized contract)
    int result = mxd_validate_bridge_mint_tx(&tx);
    assert(result != 0);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Unauthorized bridge contract rejected\n");
}

// Test 4: Replay attack prevention
void test_replay_attack_prevention() {
    printf("Test 4: Replay attack prevention\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0x22;
    }

    setup_authorized_bridge(payload.bridge_contract);

    uint32_t chain_id = 56;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    // Unique source tx hash for replay test
    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0x33;
    }

    payload.source_block_number = 11111;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 20;
    }

    payload.amount = 25000000000;
    payload.proof_length = 256;

    // First transaction should succeed
    mxd_transaction_v3_t tx1;
    assert(mxd_create_bridge_mint_tx(&tx1, &payload) == 0);
    assert(mxd_validate_bridge_mint_tx(&tx1) == 0);

    // Mark as processed
    uint8_t mxd_tx_hash[64] = {0x44};
    assert(mxd_mark_bridge_tx_processed(&payload, mxd_tx_hash, 1000) == 0);

    // Second transaction with same source_tx_hash should fail
    mxd_transaction_v3_t tx2;
    assert(mxd_create_bridge_mint_tx(&tx2, &payload) == 0);

    int result = mxd_validate_bridge_mint_tx(&tx2);
    assert(result != 0);  // Should fail due to replay

    mxd_free_transaction_v3(&tx1);
    mxd_free_transaction_v3(&tx2);

    printf("  ✓ Replay attack prevented\n");
}

// Test 5: Invalid chain ID rejection
void test_invalid_chain_id() {
    printf("Test 5: Invalid chain ID rejection\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0x55;
    }

    setup_authorized_bridge(payload.bridge_contract);

    // Invalid chain ID (not 56 or 97)
    uint32_t chain_id = 1;  // Ethereum mainnet (not supported)
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0x66;
    }

    payload.source_block_number = 22222;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 30;
    }

    payload.amount = 15000000000;
    payload.proof_length = 256;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    int result = mxd_validate_bridge_mint_tx(&tx);
    assert(result != 0);  // Should fail

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Invalid chain ID rejected\n");
}

// Test 6: Zero amount rejection
void test_zero_amount_rejection() {
    printf("Test 6: Zero amount rejection\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0x77;
    }

    setup_authorized_bridge(payload.bridge_contract);

    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0x88;
    }

    payload.source_block_number = 33333;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 40;
    }

    payload.amount = 0;  // Invalid!
    payload.proof_length = 256;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    int result = mxd_validate_bridge_mint_tx(&tx);
    assert(result != 0);  // Should fail

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Zero amount rejected\n");
}

// Test 7: Create bridge burn transaction
void test_create_bridge_burn_tx() {
    printf("Test 7: Create bridge burn transaction\n");

    uint8_t sender_addr[20];
    for (int i = 0; i < 20; i++) {
        sender_addr[i] = i + 50;
    }

    uint8_t bridge_contract[64];
    for (int i = 0; i < 64; i++) {
        bridge_contract[i] = 0x99;
    }

    uint32_t dest_chain_id = 56;

    uint8_t dest_recipient[20];
    for (int i = 0; i < 20; i++) {
        dest_recipient[i] = i + 60;
    }

    mxd_amount_t burn_amount = 75000000000;

    mxd_transaction_v3_t tx;
    int result = mxd_create_bridge_burn_tx(&tx, sender_addr, burn_amount,
                                            bridge_contract, dest_chain_id, dest_recipient);
    assert(result == 0);

    // Verify transaction structure
    assert(tx.version == 3);
    assert(tx.type == MXD_TX_TYPE_BRIDGE_BURN);
    assert(tx.output_count == 1);
    assert(tx.payload.bridge != NULL);

    // Verify burn output (to zero address)
    uint8_t zero_addr[20] = {0};
    assert(memcmp(tx.outputs[0].recipient_addr, zero_addr, 20) == 0);
    assert(tx.outputs[0].amount == burn_amount);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ Bridge burn transaction created successfully\n");
}

// Test 8: Calculate v3 transaction hash
void test_calculate_tx_hash_v3() {
    printf("Test 8: Calculate v3 transaction hash\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xAB;
    }

    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0xCD;
    }

    payload.source_block_number = 44444;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 70;
    }

    payload.amount = 35000000000;
    payload.proof_length = 256;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    uint8_t hash1[64];
    assert(mxd_calculate_tx_hash_v3(&tx, hash1) == 0);

    // Calculate again - should produce same hash
    uint8_t hash2[64];
    assert(mxd_calculate_tx_hash_v3(&tx, hash2) == 0);

    assert(memcmp(hash1, hash2, 64) == 0);

    // Verify hash is not all zeros
    int all_zero = 1;
    for (int i = 0; i < 64; i++) {
        if (hash1[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    assert(!all_zero);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ v3 transaction hash calculated correctly\n");
}

// Test 9: Validate v3 transaction (dispatch)
void test_validate_transaction_v3() {
    printf("Test 9: Validate v3 transaction dispatch\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xDE;
    }

    setup_authorized_bridge(payload.bridge_contract);

    uint32_t chain_id = 56;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0xEF;
    }

    payload.source_block_number = 55555;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 80;
    }

    payload.amount = 40000000000;
    payload.proof_length = 256;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    // Validate using general v3 validation (dispatches to mint validation)
    int result = mxd_validate_transaction_v3(&tx);
    assert(result == 0);

    mxd_free_transaction_v3(&tx);

    printf("  ✓ v3 transaction validation dispatch works\n");
}

// Test 10: Free v3 transaction
void test_free_transaction_v3() {
    printf("Test 10: Free v3 transaction\n");

    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    for (int i = 0; i < 64; i++) {
        payload.bridge_contract[i] = 0xFA;
    }

    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    for (int i = 0; i < 32; i++) {
        payload.source_tx_hash[i] = 0xFB;
    }

    payload.source_block_number = 66666;

    for (int i = 0; i < 20; i++) {
        payload.recipient_addr[i] = i + 90;
    }

    payload.amount = 45000000000;
    payload.proof_length = 256;

    mxd_transaction_v3_t tx;
    assert(mxd_create_bridge_mint_tx(&tx, &payload) == 0);

    // Free should not crash and should zero out memory
    mxd_free_transaction_v3(&tx);

    assert(tx.payload.bridge == NULL);
    assert(tx.outputs == NULL);

    printf("  ✓ v3 transaction freed successfully\n");
}

int main() {
    printf("Bridge Transaction Tests\n");
    printf("========================\n\n");

    // Remove test database if exists
    unlink(TEST_DB_PATH);

    // Initialize logging
    mxd_set_log_level(MXD_LOG_LEVEL_ERROR);

    // Initialize database
    rocksdb_options_t *options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 1);

    char *err = NULL;
    rocksdb_t *db = rocksdb_open(options, TEST_DB_PATH, &err);

    if (err) {
        fprintf(stderr, "Failed to open database: %s\n", err);
        free(err);
        rocksdb_options_destroy(options);
        return 1;
    }

    mxd_set_rocksdb_db(db);

    // Initialize transaction validation
    assert(mxd_init_transaction_validation() == 0);

    // Run tests
    test_create_bridge_mint_tx();
    test_validate_bridge_mint_tx();
    test_reject_unauthorized_bridge();
    test_replay_attack_prevention();
    test_invalid_chain_id();
    test_zero_amount_rejection();
    test_create_bridge_burn_tx();
    test_calculate_tx_hash_v3();
    test_validate_transaction_v3();
    test_free_transaction_v3();

    // Cleanup
    rocksdb_close(db);
    rocksdb_options_destroy(options);

    printf("\n========================\n");
    printf("All tests passed! ✓\n");

    return 0;
}
