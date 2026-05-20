#include "mxd_crypto.h"

#include "mxd_rsc.h"
#include "mxd_ntp.h"
#include "mxd_endian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include "mxd_p2p.h"
#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"
#include "mxd_blockchain_sync.h"
#include "mxd_rsc.h"
#include "test_utils.h"

#define TEST_PORT_1 12345
#define TEST_PORT_2 12346
#define TEST_PORT_3 12347
#define MAX_LATENCY_MS 3000  // 3 second maximum latency requirement
#define MIN_VALIDATORS 3     // Minimum validators for testing
#define TEST_BLOCK_HEIGHT 100
#define MAX_TEST_VALIDATORS 10

// Forward declarations
static int add_validator_signatures_with_algo(mxd_block_t *block, int count, uint8_t algo_id);
static int add_real_validator_signatures_with_algo(mxd_block_t *block, int count, uint8_t algo_id);

// Test validator key storage (for real signature tests)
typedef struct {
    uint8_t validator_id[20];
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint8_t secret_key[MXD_PRIVKEY_MAX_LEN];
    size_t pubkey_len;
    size_t seckey_len;
    uint8_t algo_id;
} test_validator_keys_t;

static test_validator_keys_t g_test_validators[MAX_TEST_VALIDATORS];
static int g_test_validator_count = 0;

static int create_test_block_with_validation(mxd_block_t *block, uint32_t height) {
    if (!block) return -1;
    
    uint8_t prev_hash[64] = {0};
    for (int i = 0; i < 64; i++) {
        prev_hash[i] = i;
    }
    
    uint8_t proposer_id[20] = {0};
    for (int i = 0; i < 20; i++) {
        proposer_id[i] = i + 10;
    }
    
    if (mxd_init_block_with_validation(block, prev_hash, proposer_id, height) != 0) {
        printf("Failed to initialize block with validation\n");
        return -1;
    }
    
    block->height = height;
    block->timestamp = time(NULL);
    block->nonce = 12345;
    
    
    return 0;
}

static int add_validator_signatures(mxd_block_t *block, int count) {
    return add_validator_signatures_with_algo(block, count, MXD_SIGALG_ED25519);
}

// Add validator signatures with specified algorithm (supports variable-length signatures)
static int add_validator_signatures_with_algo(mxd_block_t *block, int count, uint8_t algo_id) {
    if (!block || count <= 0) return -1;
    
    // Get the correct signature length for the specified algorithm
    size_t sig_len = mxd_sig_signature_len(algo_id);
    if (sig_len == 0 || sig_len > MXD_SIGNATURE_MAX) {
        printf("Invalid signature length for algo_id=%u: %zu\n", algo_id, sig_len);
        return -1;
    }
    
    // Use max-sized buffer for safety
    uint8_t signature[MXD_SIGNATURE_MAX];
    
    for (int i = 0; i < count; i++) {
        uint8_t validator_id[20] = {0};
        for (int j = 0; j < 20; j++) {
            validator_id[j] = (uint8_t)(j + i + 20);
        }
        
        // Fill only the bytes needed for this algorithm
        memset(signature, 0, sizeof(signature));
        for (size_t j = 0; j < sig_len; j++) {
            signature[j] = (uint8_t)(j + i);
        }
        
        if (mxd_add_validator_signature(block, validator_id, time(NULL), algo_id, signature, (uint16_t)sig_len) != 0) {
            printf("Failed to add validator signature %d (algo_id=%u, len=%zu)\n", i, algo_id, sig_len);
            return -1;
        }
    }
    
    return 0;
}

// Setup test validators with real keypairs for cryptographic verification tests
static int setup_test_validators(int count, uint8_t algo_id) {
    if (count <= 0 || count > MAX_TEST_VALIDATORS) return -1;
    
    // Clear any existing validator registrations
    mxd_test_clear_validator_pubkeys();
    g_test_validator_count = 0;
    
    size_t pubkey_len = mxd_sig_pubkey_len(algo_id);
    size_t seckey_len = mxd_sig_privkey_len(algo_id);
    
    if (pubkey_len == 0 || seckey_len == 0) {
        printf("Invalid key lengths for algo_id=%u\n", algo_id);
        return -1;
    }
    
    for (int i = 0; i < count; i++) {
        test_validator_keys_t *v = &g_test_validators[i];
        v->algo_id = algo_id;
        v->pubkey_len = pubkey_len;
        v->seckey_len = seckey_len;
        
        // Generate real keypair
        if (mxd_sig_keygen(algo_id, v->public_key, v->secret_key) != 0) {
            printf("Failed to generate keypair for validator %d\n", i);
            return -1;
        }
        
        // Derive addr32 and copy first 20 bytes to legacy validator_id field
        { uint8_t _a32[MXD_ADDR32_LEN];
          if (mxd_derive_address(algo_id, v->public_key, pubkey_len, _a32) != 0) {
              printf("Failed to derive address for validator %d\n", i);
              return -1;
          }
          memcpy(v->validator_id, _a32, 20); }
        
        // Register the public key so mxd_get_validator_public_key can find it
        if (mxd_test_register_validator_pubkey(v->validator_id, v->public_key, pubkey_len) != 0) {
            printf("Failed to register validator pubkey %d\n", i);
            return -1;
        }
        
        g_test_validator_count++;
    }
    
    return 0;
}

// Cleanup test validators
static void cleanup_test_validators(void) {
    mxd_test_clear_validator_pubkeys();
    g_test_validator_count = 0;
}

// Add real validator signatures with specified algorithm (cryptographically valid)
static int add_real_validator_signatures_with_algo(mxd_block_t *block, int count, uint8_t algo_id) {
    if (!block || count <= 0 || count > g_test_validator_count) return -1;
    
    // First, compute the block hash (needed for signing)
    if (mxd_calculate_block_hash(block, block->block_hash) != 0) {
        printf("Failed to calculate block hash\n");
        return -1;
    }
    
    size_t sig_len = mxd_sig_signature_len(algo_id);
    if (sig_len == 0 || sig_len > MXD_SIGNATURE_MAX) {
        printf("Invalid signature length for algo_id=%u: %zu\n", algo_id, sig_len);
        return -1;
    }
    
    uint8_t signature[MXD_SIGNATURE_MAX];
    
    for (int i = 0; i < count; i++) {
        test_validator_keys_t *v = &g_test_validators[i];
        
        if (v->algo_id != algo_id) {
            printf("Validator %d has wrong algo_id (expected %u, got %u)\n", i, algo_id, v->algo_id);
            return -1;
        }
        
        // Build the message to sign: block_hash + prev_validator_id + timestamp_be
        // This must match exactly what mxd_verify_validation_chain expects
        uint8_t msg[64 + 20 + 8];
        memcpy(msg, block->block_hash, 64);
        
        if (i == 0) {
            memset(msg + 64, 0, 20);  // First validator has no previous
        } else {
            memcpy(msg + 64, g_test_validators[i - 1].validator_id, 20);
        }
        
        // Use NTP-synchronized time for timestamp (within ±60s tolerance)
        uint64_t timestamp = mxd_now_ms() / 1000;
        uint64_t ts_be = mxd_htonll(timestamp);
        memcpy(msg + 64 + 20, &ts_be, 8);
        
        // Sign the message
        size_t actual_sig_len = 0;
        if (mxd_sig_sign(algo_id, signature, &actual_sig_len, msg, sizeof(msg), v->secret_key) != 0) {
            printf("Failed to sign message for validator %d\n", i);
            return -1;
        }
        
        if (actual_sig_len != sig_len) {
            printf("Unexpected signature length for validator %d: expected %zu, got %zu\n", 
                   i, sig_len, actual_sig_len);
            return -1;
        }
        
        // Add the real signature to the block
        if (mxd_add_validator_signature(block, v->validator_id, timestamp, algo_id, signature, (uint16_t)sig_len) != 0) {
            printf("Failed to add validator signature %d (algo_id=%u, len=%zu)\n", i, algo_id, sig_len);
            return -1;
        }
    }
    
    return 0;
}

// Wrapper for real Ed25519 signatures (default)
static int add_real_validator_signatures(mxd_block_t *block, int count) {
    return add_real_validator_signatures_with_algo(block, count, MXD_SIGALG_ED25519);
}

static void test_validation_chain_creation(void) {
    TEST_START("Validation Chain Creation");
    
    // Setup test validators with real Ed25519 keypairs
    TEST_ASSERT(setup_test_validators(MIN_VALIDATORS, MXD_SIGALG_ED25519) == 0,
                "Setup test validators with Ed25519 keys");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization with validation chain");
    
    block.validation_capacity = 6;
    
    // Use real cryptographic signatures for full verification
    TEST_ASSERT(add_real_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding real validator signatures (Ed25519, 64 bytes)");
    
    TEST_ASSERT(mxd_verify_validation_chain(&block) == 0, 
                "Validation chain cryptographic verification");
    
    TEST_ASSERT(mxd_block_has_quorum(&block) == 1, 
                "Block has quorum of validators");
    
    // Cleanup
    cleanup_test_validators();
    mxd_free_validation_chain(&block);
    
    TEST_END("Validation Chain Creation");
}

static void test_validation_chain_persistence(void) {
    TEST_START("Validation Chain Persistence");
    
    TEST_ASSERT(mxd_init_blockchain_db("test_blockchain_db") == 0, 
                "Blockchain database initialization");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization");
    
    TEST_ASSERT(add_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding validator signatures");
    
    TEST_ASSERT(mxd_store_block(&block) == 0, 
                "Block storage with validation chain");
    
    mxd_block_t retrieved_block;
    TEST_ASSERT(mxd_retrieve_block_by_height(TEST_BLOCK_HEIGHT, &retrieved_block) == 0, 
                "Block retrieval by height");
    
    TEST_ASSERT(retrieved_block.validation_count == block.validation_count, 
                "Validation count preserved");
    
    for (uint32_t i = 0; i < block.validation_count; i++) {
        TEST_ASSERT(memcmp(retrieved_block.validation_chain[i].validator_id, 
                          block.validation_chain[i].validator_id, 20) == 0, 
                    "Validator ID preserved");
        // Use stored signature_length for variable-length signature comparison
        uint16_t sig_len = block.validation_chain[i].signature_length;
        TEST_ASSERT(retrieved_block.validation_chain[i].signature_length == sig_len,
                    "Signature length preserved");
        TEST_ASSERT(memcmp(retrieved_block.validation_chain[i].signature, 
                          block.validation_chain[i].signature, sig_len) == 0, 
                    "Signature preserved");
    }
    
    mxd_close_blockchain_db();
    
    TEST_END("Validation Chain Persistence");
}

static void test_validation_chain_propagation(void) {
    TEST_START("Validation Chain Propagation");
    
    printf("  SKIPPED: This test requires multiple physical nodes to be meaningful.\n");
    printf("  Block propagation and relay cannot be properly tested in a single-process\n");
    printf("  environment. Use MXDTestSuite with multiple GCP nodes for propagation testing.\n");
    printf("  The mxd_relay_block_by_validation_count() function requires real peer\n");
    printf("  connections which cannot be simulated with two P2P stacks in one process.\n");
    
    TEST_END("Validation Chain Propagation");
}

static void test_validation_chain_fork_resolution(void) {
    TEST_START("Validation Chain Fork Resolution");
    
    TEST_ASSERT(mxd_init_blockchain_db("test_blockchain_db") == 0, 
                "Blockchain database initialization");
    
    mxd_block_t block1, block2;
    TEST_ASSERT(create_test_block_with_validation(&block1, TEST_BLOCK_HEIGHT) == 0, 
                "Block 1 initialization");
    TEST_ASSERT(create_test_block_with_validation(&block2, TEST_BLOCK_HEIGHT) == 0, 
                "Block 2 initialization");
    
    TEST_ASSERT(add_validator_signatures(&block1, MIN_VALIDATORS) == 0, 
                "Adding validator signatures to block 1");
    TEST_ASSERT(add_validator_signatures(&block2, MIN_VALIDATORS + 2) == 0, 
                "Adding validator signatures to block 2");
    
    double score1 = mxd_calculate_latency_score(&block1);
    double score2 = mxd_calculate_latency_score(&block2);
    printf("  Block 1 latency score: %f\n", score1);
    printf("  Block 2 latency score: %f\n", score2);
    
    int resolution = mxd_resolve_fork(&block1, &block2);
    printf("  Fork resolution result: %d\n", resolution);
    TEST_ASSERT(resolution < 0, "Block 2 should win with more signatures");
    
    mxd_close_blockchain_db();
    
    TEST_END("Validation Chain Fork Resolution");
}

static void test_validation_chain_expiry(void) {
    TEST_START("Validation Chain Expiry");
    
    TEST_ASSERT(mxd_init_blockchain_db("test_blockchain_db") == 0, 
                "Blockchain database initialization");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization");
    
    TEST_ASSERT(add_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding validator signatures");
    
    TEST_ASSERT(mxd_store_block(&block) == 0, 
                "Block storage with validation chain");
    
    for (uint32_t i = 0; i < block.validation_count; i++) {
        TEST_ASSERT(mxd_store_signature(block.height, 
                                      block.validation_chain[i].validator_id, 
                                      block.validation_chain[i].signature,
                                      block.validation_chain[i].signature_length) == 0, 
                    "Signature storage for replay protection");
    }
    
    for (uint32_t i = 0; i < block.validation_count; i++) {
        TEST_ASSERT(mxd_signature_exists(block.height, 
                                       block.validation_chain[i].validator_id, 
                                       block.validation_chain[i].signature,
                                       block.validation_chain[i].signature_length) == 1, 
                    "Signature exists check");
    }
    
    TEST_ASSERT(mxd_prune_expired_signatures(block.height + 6) == 0, 
                "Pruning expired signatures");
    
    for (uint32_t i = 0; i < block.validation_count; i++) {
        TEST_ASSERT(mxd_signature_exists(block.height, 
                                       block.validation_chain[i].validator_id, 
                                       block.validation_chain[i].signature,
                                       block.validation_chain[i].signature_length) == 0, 
                    "Signature should be pruned");
    }
    
    mxd_close_blockchain_db();
    
    TEST_END("Validation Chain Expiry");
}

static void test_validation_chain_sync(void) {
    TEST_START("Validation Chain Sync");
    
    printf("  SKIPPED: This test requires multiple physical nodes to be meaningful.\n");
    printf("  Validation chain sync (mxd_sync_validation_chain) and peer requests\n");
    printf("  (mxd_request_validation_chain_from_peers) require actual connected peers.\n");
    printf("  Use MXDTestSuite with multiple GCP nodes for sync testing.\n");
    
    TEST_END("Validation Chain Sync");
}

static void test_validation_chain_network(void) {
    printf("Starting Validation Chain Network Tests...\n");
    
    test_validation_chain_creation();
    test_validation_chain_persistence();
    test_validation_chain_propagation();
    test_validation_chain_fork_resolution();
    test_validation_chain_expiry();
    test_validation_chain_sync();
    
    printf("Validation Chain Network Tests completed successfully\n");
}




int main(int argc, char** argv) {
    TEST_START("Validation Chain Network Tests");
    
    int network_mode = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0) {
            network_mode = 1;
        }
    }
    
    if (network_mode) {
        test_validation_chain_network();
    } else {
        TEST_VALUE("Status", "%s", "No tests run - use --network for network tests");
    }
    



    TEST_END("Validation Chain Network Tests");
    return 0;
}
