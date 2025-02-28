#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include "mxd_p2p.h"
#include "mxd_config.h"
#include "mxd_blockchain.h"
#include "mxd_blockchain_sync.h"
#include "mxd_rsc.h"
#include "mxd_transaction.h"
#include "mxd_ntp.h"
#include "mxd_utxo.h"
#include "mxd_crypto.h"
#include "mxd_address.h"
#include "blockchain/mxd_rsc_internal.h"
#include "test_utils.h"
#include <stdlib.h>
#include <unistd.h>

#define TEST_NODE_COUNT 5
#define MIN_TX_RATE 10
#define MAX_LATENCY_MS 3000
#define MAX_CONSECUTIVE_ERRORS 10
#define TEST_TRANSACTIONS 20

static void test_node_lifecycle(void) {
    TEST_START("Node Lifecycle Integration Test");
    
    // Initialize test nodes
    mxd_node_stake_t nodes[TEST_NODE_COUNT];
    static uint8_t node_private_keys[TEST_NODE_COUNT][128];
    double total_stake = 0.0;
    uint32_t error_count = 0;
    mxd_transaction_t transactions[TEST_TRANSACTIONS];
    uint8_t genesis_hash[64] = {0};
    mxd_transaction_t genesis_tx;
    
    // Initialize UTXO database
    TEST_ASSERT(mxd_init_utxo_db() == 0, "UTXO database initialization");
    
    // Create and configure nodes
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        // Generate unique address for each node
        char passphrase[256];
        uint8_t property_key[64];
        uint8_t public_key[256];
        uint8_t private_key[128];
        char address[42];
        
        TEST_ASSERT(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0,
                    "Passphrase generation");
        TEST_ASSERT(mxd_derive_property_key(passphrase, "1234", property_key) == 0,
                    "Property key derivation");
        TEST_ASSERT(mxd_generate_keypair(property_key, public_key, private_key) == 0,
                    "Keypair generation");
        TEST_ASSERT(mxd_generate_address(public_key, address, sizeof(address)) == 0,
                    "Address generation");
        TEST_ASSERT(mxd_validate_address(address) == 0, "Address validation");
        
        // Store private key and initialize node configuration
        memcpy(node_private_keys[i], private_key, sizeof(private_key));
        memset(&nodes[i], 0, sizeof(mxd_node_stake_t));
        
        // Initialize node ID and keys first
        snprintf(nodes[i].node_id, sizeof(nodes[i].node_id), "node-%zu", i);
        nodes[i].stake_amount = 100.0 + (i * 10.0);  // Significant stakes
        memcpy(nodes[i].public_key, public_key, sizeof(public_key));
        
        // Initialize metrics
        TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                   "Node metrics initialization");
        nodes[i].metrics.avg_response_time = 150;
        nodes[i].metrics.min_response_time = 100;
        nodes[i].metrics.max_response_time = 200;
        nodes[i].metrics.response_count = MXD_MIN_RESPONSE_COUNT;
        nodes[i].metrics.tip_share = 0.0;
        nodes[i].metrics.last_update = get_current_time_ms();
        
        // Set node status
        nodes[i].rank = 0;
        nodes[i].active = 1;
        
        total_stake += nodes[i].stake_amount;
    }
    
    // Test P2P network setup
    uint64_t start_time = get_current_time_ms();
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        uint16_t port = 12345 + i;
        TEST_ASSERT(mxd_init_p2p(port, nodes[i].public_key) == 0,
                   "P2P initialization");
        TEST_ASSERT(mxd_start_p2p() == 0, "P2P startup");
        
        // Connect to previous nodes
        for (size_t j = 0; j < i; j++) {
            TEST_ASSERT(mxd_add_peer("127.0.0.1", 12345 + j) == 0,
                       "Peer connection");
        }
        
        mxd_stop_p2p();  // Stop before next node starts
    }
    uint64_t network_latency = get_current_time_ms() - start_time;
    TEST_ASSERT(network_latency <= MAX_LATENCY_MS,
               "Network setup within latency limit");
    
    // Test blockchain synchronization
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_sync_blockchain() == 0, "Blockchain synchronization");
    uint64_t sync_latency = get_current_time_ms() - start_time;
    TEST_ASSERT(sync_latency <= MAX_LATENCY_MS,
               "Blockchain sync within latency limit");
    
    // Test transaction processing
    // Initialize transaction validation system
    TEST_ASSERT(mxd_init_transaction_validation() == 0, "Transaction validation init");
    
    // Create genesis transaction
    TEST_ASSERT(mxd_create_transaction(&genesis_tx) == 0,
               "Genesis transaction creation");
    TEST_ASSERT(mxd_add_tx_output(&genesis_tx, nodes[0].public_key, 1000.0) == 0,
               "Genesis output addition");
    TEST_ASSERT(mxd_calculate_tx_hash(&genesis_tx, genesis_hash) == 0,
               "Genesis hash calculation");
    
    // Pre-create all transactions
    for (int i = 0; i < TEST_TRANSACTIONS; i++) {
        TEST_ASSERT(mxd_create_transaction(&transactions[i]) == 0,
                   "Transaction creation");
        TEST_ASSERT(mxd_add_tx_input(&transactions[i], genesis_hash, 0,
                   nodes[0].public_key) == 0, "Input addition");
        TEST_ASSERT(mxd_add_tx_output(&transactions[i], nodes[1].public_key,
                   10.0) == 0, "Output addition");
        transactions[i].timestamp = get_current_time_ms();
        TEST_ASSERT(mxd_sign_tx_input(&transactions[i], 0, node_private_keys[0]) == 0,
                   "Transaction signing");
        TEST_ASSERT(mxd_set_voluntary_tip(&transactions[i], 1.0) == 0,
                   "Voluntary tip setting");
    }
    
    // Reset validation state before processing
    mxd_reset_transaction_validation();
    int total_transactions = TEST_TRANSACTIONS;
    
    // Process transactions in batches to maintain rate
    const int TX_BATCH_SIZE = 5; // Larger batches for better throughput
    int remaining = total_transactions;
    uint32_t tx_count = 0;
    uint64_t tx_start_time = 0;
    
    printf("Starting batch processing with %d transactions\n", total_transactions);
    TEST_TX_RATE_START("Transaction Processing");
    
    while (remaining > 0) {
        int batch = (remaining < TX_BATCH_SIZE) ? remaining : TX_BATCH_SIZE;
        
        // Process batch immediately
        
        // Process batch
        for (int i = 0; i < batch; i++) {
            int tx_idx = total_transactions - remaining + i;
            
            printf("Processing transaction %d/%d\n", tx_idx + 1, total_transactions);
            
            // Validate transaction across nodes
            bool valid = true;
            for (size_t j = 0; j < TEST_NODE_COUNT && valid; j++) {
                printf("  Validating on node %zu...\n", j);
                int result = mxd_validate_transaction(&transactions[tx_idx]);
                
                if (result != 0) {
                    printf("  Node %zu validation failed (error %d)\n", j, result);
                    error_count++;
                    if (error_count > MAX_CONSECUTIVE_ERRORS) {
                        TEST_ERROR_COUNT(error_count, MAX_CONSECUTIVE_ERRORS);
                        valid = false;
                    }
                } else {
                    printf("  Node %zu validation succeeded\n", j);
                    error_count = 0;
                }
            }
            
            if (valid) {
                printf("Valid transaction processed\n");
                TEST_TX_RATE_UPDATE("Transaction Processing", MIN_TX_RATE);
            }
        }
        
        remaining -= batch;
        
        // No delay needed - validation is slow enough
    }
    
    // Initialize NTP for time synchronization
    TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");
    
    // Initialize node metrics for tip distribution
    uint64_t current_time;
    TEST_ASSERT(mxd_get_network_time(&current_time) == 0, "Get network time");
    
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        nodes[i].metrics.tip_share = 0.0;
        nodes[i].metrics.response_count = MXD_MIN_RESPONSE_COUNT + i * 10;
        nodes[i].metrics.min_response_time = 50;  // Fast responses
        nodes[i].metrics.max_response_time = 150; // Good latency
        nodes[i].metrics.avg_response_time = 100; // Consistent performance
        nodes[i].metrics.last_update = current_time;
        nodes[i].active = 1;  // Ensure nodes are marked active
    }
    
    // Test rapid stake consensus
    TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
               "Rapid stake table update");
    
    // Test tip distribution
    double total_tip = 100.0;
    
    // Initialize tip shares
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        nodes[i].metrics.tip_share = 0.0;
    }
    
    // Sort nodes by stake amount and reliability for tip distribution
    for (size_t i = 0; i < TEST_NODE_COUNT - 1; i++) {
        for (size_t j = 0; j < TEST_NODE_COUNT - i - 1; j++) {
            // Calculate combined scores
            double reliability_j = (double)nodes[j].metrics.response_count / (j + 1);
            double performance_j = 1.0 - ((double)nodes[j].metrics.avg_response_time / MAX_LATENCY_MS);
            double score_j = nodes[j].stake_amount * ((reliability_j * 0.6) + (performance_j * 0.4));
            
            double reliability_j1 = (double)nodes[j + 1].metrics.response_count / (j + 2);
            double performance_j1 = 1.0 - ((double)nodes[j + 1].metrics.avg_response_time / MAX_LATENCY_MS);
            double score_j1 = nodes[j + 1].stake_amount * ((reliability_j1 * 0.6) + (performance_j1 * 0.4));
            if (score_j < score_j1) {
                mxd_node_stake_t temp = nodes[j];
                nodes[j] = nodes[j + 1];
                nodes[j + 1] = temp;
            }
        }
    }
    
    // Update rapid stake table and ranks
    TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
               "Rapid stake table update");
    
    // Print node ranks for debugging
    printf("\nNode ranks before tip distribution:\n");
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        printf("Node %zu: rank=%d active=%d stake=%.2f\n", 
               i, nodes[i].rank, nodes[i].active, nodes[i].stake_amount);
    }
    
    // Now distribute tips according to ranks
    TEST_ASSERT(mxd_distribute_tips(nodes, TEST_NODE_COUNT, total_tip) == 0,
               "Tip distribution");
    
    // Verify tip distribution follows whitepaper pattern
    double remaining_tip = total_tip;
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        double expected_tip;
        if (i == TEST_NODE_COUNT - 1) {
            expected_tip = remaining_tip;
        } else {
            expected_tip = remaining_tip * 0.5;
            remaining_tip -= expected_tip;
        }
        TEST_ASSERT(fabs(nodes[i].metrics.tip_share - expected_tip) < 0.0001,
                   "Tip distribution matches whitepaper pattern");
    }
    
    // Cleanup
    for (int i = 0; i < TEST_TRANSACTIONS; i++) {
        mxd_free_transaction(&transactions[i]);
    }
    mxd_free_transaction(&genesis_tx);
    mxd_init_utxo_db();
    
    TEST_END("Node Lifecycle Integration Test");
}

int main(void) {
    // Initialize NTP for time synchronization
    TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");
    
    test_node_lifecycle();
    
    return 0;
}
