#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_PORT_1 13100
#define TEST_PORT_2 13101
#define MAX_LATENCY_MS 3000  // 3 second maximum latency requirement
#define MIN_TX_RATE 10       // Minimum 10 transactions per second

static void test_blockchain_data_retrieval(void) {
    TEST_START("Blockchain Data Retrieval Test");
    
    uint8_t public_key_1[32] = {0};
    uint8_t public_key_2[32] = {0};
    uint8_t private_key_1[64] = {0};
    uint8_t private_key_2[64] = {0};
    
    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, public_key_1, private_key_1) == 0,
                "Node 1 keypair generation");
    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, public_key_2, private_key_2) == 0,
                "Node 2 keypair generation");
    
    // Start first node
    TEST_ASSERT(test_init_p2p_ed25519(TEST_PORT_1, public_key_1, private_key_1) == 0, "Node 1 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 1 P2P startup");
    
    // Create and add test blocks to first node
    mxd_block_t blocks[5];
    uint8_t prev_hash[64] = {0};
    uint8_t transaction_data[32] = {1, 2, 3, 4};
    
    // Create test blocks
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(mxd_init_block(&blocks[i], prev_hash) == 0, "Block initialization");
        TEST_ASSERT(mxd_add_transaction(&blocks[i], transaction_data, sizeof(transaction_data)) == 0, 
                   "Transaction addition");
        TEST_ASSERT(mxd_calculate_block_hash(&blocks[i], prev_hash) == 0, "Hash calculation");
        memcpy(blocks[i].block_hash, prev_hash, 64);  // Store block hash
    }
    
    // Start second node and test data retrieval
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(test_init_p2p_ed25519(TEST_PORT_2, public_key_2, private_key_2) == 0, "Node 2 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 2 P2P startup");
    uint64_t end_time = get_current_time_ms();
    uint64_t init_latency = end_time - start_time;
    printf("  Node initialization latency: %lums\n", init_latency);
    TEST_ASSERT(init_latency <= MAX_LATENCY_MS, "Node initialization must complete within 3 seconds");
    
    // Connect nodes
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_add_peer("127.0.0.1", TEST_PORT_1) == 0, "Node connection successful");
    end_time = get_current_time_ms();
    uint64_t connect_latency = end_time - start_time;
    printf("  Node connection latency: %lums\n", connect_latency);
    TEST_ASSERT(connect_latency <= MAX_LATENCY_MS, "Node connection must complete within 3 seconds");
    
    // Test blockchain data synchronization
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_sync_blockchain() == 0, "Blockchain synchronization successful");
    end_time = get_current_time_ms();
    uint64_t sync_latency = end_time - start_time;
    printf("  Blockchain sync latency: %lums\n", sync_latency);
    TEST_ASSERT(sync_latency <= MAX_LATENCY_MS, "Blockchain sync must complete within 3 seconds");
    
    // Verify synchronized data
    uint32_t error_count = 0;
    for (int i = 0; i < 5; i++) {
        mxd_block_t retrieved_block;
        if (mxd_get_block_by_height(i, &retrieved_block) != 0) {
            error_count++;
            TEST_ERROR_COUNT(error_count, 10);
            continue;
        }
        
        uint8_t retrieved_hash[64];
        TEST_ASSERT(mxd_calculate_block_hash(&retrieved_block, retrieved_hash) == 0, 
                   "Retrieved block hash calculation");
        
        // Compare hashes
        uint8_t block_hash[64];
        TEST_ASSERT(mxd_calculate_block_hash(&blocks[i], block_hash) == 0, "Original block hash calculation");
        if (memcmp(retrieved_hash, block_hash, 64) != 0) {
            error_count++;
            TEST_ERROR_COUNT(error_count, 10);
        }
        
        mxd_free_block(&retrieved_block);
    }
    
    // Free test blocks
    for (int i = 0; i < 5; i++) {
        mxd_free_block(&blocks[i]);
    }
    
    // Cleanup
    mxd_stop_p2p();  // Stop second node
    test_init_p2p_ed25519(TEST_PORT_1, public_key_1, private_key_1);  // Switch back to first node
    mxd_stop_p2p();  // Stop first node
    
    TEST_END("Blockchain Data Retrieval Test");
}

int main(void) {
    test_blockchain_data_retrieval();
    return 0;
}
