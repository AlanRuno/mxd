#include "mxd_crypto.h"

#include "mxd_rsc.h"
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
    if (!block || count <= 0) return -1;
    
    for (int i = 0; i < count; i++) {
        uint8_t validator_id[20] = {0};
        for (int j = 0; j < 20; j++) {
            validator_id[j] = j + i + 20;
        }
        
        uint8_t signature[128] = {0};
        for (int j = 0; j < 128; j++) {
            signature[j] = j + i;
        }
        
        if (mxd_add_validator_signature(block, validator_id, time(NULL), signature, 128) != 0) {
            printf("Failed to add validator signature %d\n", i);
            return -1;
        }
    }
    
    return 0;
}

static void test_validation_chain_creation(void) {
    TEST_START("Validation Chain Creation");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization with validation chain");
    
    block.validation_capacity = 6;
    
    TEST_ASSERT(add_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding validator signatures");
    
    TEST_ASSERT(mxd_verify_validation_chain(&block) == 0, 
                "Validation chain verification");
    
    TEST_ASSERT(mxd_block_has_quorum(&block) == 1, 
                "Block has quorum of validators");
    
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
        TEST_ASSERT(memcmp(retrieved_block.validation_chain[i].signature, 
                          block.validation_chain[i].signature, 128) == 0, 
                    "Signature preserved");
    }
    
    mxd_close_blockchain_db();
    
    TEST_END("Validation Chain Persistence");
}

static void test_validation_chain_propagation(void) {
    TEST_START("Validation Chain Propagation");
    
    uint8_t public_key_1[32] = {0};
    uint8_t public_key_2[32] = {0};
    for (int i = 0; i < 32; i++) {
        public_key_1[i] = i;
        public_key_2[i] = i + 32;
    }
    
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_1, public_key_1) == 0, "Node 1 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 1 P2P startup");
    
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_2, public_key_2) == 0, "Node 2 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 2 P2P startup");
    
    TEST_ASSERT(mxd_add_peer("127.0.0.1", TEST_PORT_1) == 0, "Node connection");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization");
    
    TEST_ASSERT(add_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding validator signatures");
    
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(mxd_broadcast_block_with_validation(&block, sizeof(block), 
                                                  block.validation_chain, 
                                                  block.validation_count * sizeof(mxd_validator_signature_t)) == 0, 
                "Block broadcast with validation chain");
    uint64_t end_time = get_current_time_ms();
    uint64_t propagation_latency = end_time - start_time;
    
    printf("  Block propagation latency: %lums\n", propagation_latency);
    TEST_ASSERT(propagation_latency <= MAX_LATENCY_MS, 
                "Block propagation must complete within 3 seconds");
    
    TEST_ASSERT(mxd_set_min_relay_signatures(MIN_VALIDATORS) == 0, 
                "Set minimum relay signatures");
    TEST_ASSERT(mxd_get_min_relay_signatures() == MIN_VALIDATORS, 
                "Get minimum relay signatures");
    
    TEST_ASSERT(mxd_relay_block_by_validation_count(&block, sizeof(block), 
                                                  block.validation_count) == 0, 
                "Block relay by validation count");
    
    mxd_stop_p2p();  // Stop second node
    mxd_init_p2p(TEST_PORT_1, public_key_1);  // Switch back to first node
    mxd_stop_p2p();  // Stop first node
    
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
    
    TEST_ASSERT(mxd_init_blockchain_db("test_blockchain_db") == 0, 
                "Blockchain database initialization");
    
    mxd_block_t block;
    TEST_ASSERT(create_test_block_with_validation(&block, TEST_BLOCK_HEIGHT) == 0, 
                "Block initialization");
    
    TEST_ASSERT(add_validator_signatures(&block, MIN_VALIDATORS) == 0, 
                "Adding validator signatures");
    
    TEST_ASSERT(mxd_store_block(&block) == 0, 
                "Block storage with validation chain");
    
    uint8_t public_key[32] = {0};
    for (int i = 0; i < 32; i++) {
        public_key[i] = i;
    }
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_3, public_key) == 0, "P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "P2P startup");
    
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(mxd_sync_validation_chain(block.block_hash, block.height) == 0, 
                "Validation chain sync");
    uint64_t end_time = get_current_time_ms();
    uint64_t sync_latency = end_time - start_time;
    
    printf("  Validation chain sync latency: %lums\n", sync_latency);
    TEST_ASSERT(sync_latency <= MAX_LATENCY_MS, 
                "Validation chain sync must complete within 3 seconds");
    
    TEST_ASSERT(mxd_request_validation_chain_from_peers(block.block_hash) == 0, 
                "Validation chain request from peers");
    
    mxd_stop_p2p();
    mxd_close_blockchain_db();
    



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
