#include "../include/blockchain/mxd_rsc_internal.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "test_utils.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define TEST_NODE_COUNT        5
#define MIN_TX_RATE            10
#define MAX_LATENCY_MS         3000
#define MAX_CONSECUTIVE_ERRORS 10
#define TEST_TRANSACTIONS      20

static void test_mining_validation(void) {
  TEST_START("Mining and Validation Test");

  // Initialize test nodes with different stakes
  mxd_node_stake_t nodes[TEST_NODE_COUNT];
  double total_stake = 0.0;
  uint32_t error_count = 0;
  uint64_t tx_start_time = get_current_time_ms();
  uint32_t tx_count = 0;

  // Initialize UTXO database
  TEST_ASSERT(mxd_init_utxo_db("./mining_test_utxo.db") == 0, "UTXO database initialization");
  
  // Initialize transaction validation system
  TEST_ASSERT(mxd_init_transaction_validation() == 0, "Transaction validation initialization");

  // Initialize nodes with stakes and metrics
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    memset(&nodes[i], 0, sizeof(mxd_node_stake_t));
    snprintf(nodes[i].node_id, sizeof(nodes[i].node_id), "node-%zu", i);
    nodes[i].stake_amount = 100.0 + (i * 10.0); // Significant stakes
    nodes[i].active = 1;                        // Mark node as active
    // Initialize unique 20-byte address per node
    for (int j = 0; j < 20; j++) {
      nodes[i].node_address[j] = j + i; // Unique address per node
    }
    TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                "Node metrics initialization");
    nodes[i].metrics.response_count = 0;             // Reset response count
    nodes[i].metrics.min_response_time = UINT64_MAX; // Initialize min time
    nodes[i].metrics.max_response_time = 0;          // Initialize max time
    nodes[i].metrics.avg_response_time = 0;          // Initialize avg time
    total_stake += nodes[i].stake_amount;
    TEST_ASSERT(mxd_validate_node_stake(&nodes[i], total_stake) == 0,
                "Node stake validation");
  }

  // Create test transactions and keys
  mxd_transaction_t transactions[TEST_TRANSACTIONS];
  uint8_t recipient_key[32] = {0};
  uint8_t private_key[64] = {0};
  uint8_t public_key[32] = {0};
  uint8_t prev_hash[64] = {0};

  // Generate valid Ed25519 keys for testing
  TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, public_key, private_key) == 0,
              "Key generation");
  memcpy(recipient_key, public_key, 32);

  // Create valid previous transaction hash
  for (int i = 0; i < 64; i++) {
    prev_hash[i] = i;
  }

  printf("Starting transaction rate measurement\n");

  // Create initial UTXO for testing
  mxd_transaction_t genesis_tx;
  mxd_utxo_t genesis_utxo;
  uint8_t genesis_hash[64] = {0};

  TEST_ASSERT(mxd_create_transaction(&genesis_tx) == 0,
              "Genesis transaction creation");
  TEST_ASSERT(test_add_tx_output_to_pubkey_ed25519(&genesis_tx, public_key, 1000.0) == 0,
              "Genesis output addition");
  TEST_ASSERT(mxd_calculate_tx_hash(&genesis_tx, genesis_hash) == 0,
              "Genesis hash calculation");
  memcpy(genesis_tx.tx_hash, genesis_hash, sizeof(genesis_hash));

  // Create and add UTXO with addr32 derived from pubkey (full 32-byte copy)
  memset(&genesis_utxo, 0, sizeof(mxd_utxo_t));
  memcpy(genesis_utxo.tx_hash, genesis_hash, sizeof(genesis_hash));
  genesis_utxo.output_index = 0;
  genesis_utxo.amount = 1000.0;
  { uint8_t _a32[MXD_ADDR32_LEN];
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, public_key, 32, _a32) == 0,
                "Address derivation for genesis UTXO");
    memcpy(genesis_utxo.owner_key, _a32, MXD_ADDR32_LEN); }
  TEST_ASSERT(mxd_add_utxo(&genesis_utxo) == 0, "Genesis UTXO addition");

  uint8_t prev_tx_hash[64];
  memcpy(prev_tx_hash, genesis_hash, 64);
  uint32_t prev_output_index = 0;
  double remaining_amount = 1000.0;

  printf("Starting transaction rate measurement\n");

  for (int i = 0; i < TEST_TRANSACTIONS; i++) {
    printf("Creating transaction %d/%d\n", i + 1, TEST_TRANSACTIONS);
    
    TEST_ASSERT(mxd_create_transaction(&transactions[i]) == 0,
                "Transaction creation");
    TEST_ASSERT(test_add_tx_input_ed25519(&transactions[i], prev_tx_hash, prev_output_index,
                                 public_key) == 0,
                "Input addition");
    
    if (i == 0) {
      transactions[i].inputs[0].amount = 1000.0;
    } else if (prev_output_index == 1) {
      transactions[i].inputs[0].amount = remaining_amount;
    } else {
      transactions[i].inputs[0].amount = 10.0;
    }
    
    double tx_amount = (i == TEST_TRANSACTIONS - 1) ? 
                      (remaining_amount - 2.0) : 10.0;
    
    TEST_ASSERT(test_add_tx_output_to_pubkey_ed25519(&transactions[i], recipient_key, tx_amount) == 0,
                "Output addition");
    
    if (i < TEST_TRANSACTIONS - 1) {
      double change_amount = remaining_amount - tx_amount - 1.0;
      TEST_ASSERT(test_add_tx_output_to_pubkey_ed25519(&transactions[i], public_key,
                 change_amount) == 0, "Change output addition");
      prev_output_index = 1;
      remaining_amount = change_amount;
    } else {
      prev_output_index = 0;
    }

    transactions[i].timestamp = get_current_time_ms();
    TEST_ASSERT(test_sign_tx_input_ed25519(&transactions[i], 0, private_key) == 0,
                "Input signing");
    
    TEST_ASSERT(mxd_calculate_tx_hash(&transactions[i], prev_tx_hash) == 0,
                "Transaction hash calculation");
    memcpy(transactions[i].tx_hash, prev_tx_hash, 64);

    printf("Transaction %d created, now validating...\n", i + 1);

    // Validate through node chain with latency tracking
    int validation_success = 0;
    for (size_t j = 0; j < TEST_NODE_COUNT; j++) {
      uint64_t validation_start = get_current_time_ms();

      int validation_result = mxd_validate_transaction(&transactions[i]);
      if (validation_result != 0) {
        printf("  Node %zu validation failed (error %d)\n", j, validation_result);
        error_count++;
        if (error_count > MAX_CONSECUTIVE_ERRORS) {
          TEST_ERROR_COUNT(error_count, MAX_CONSECUTIVE_ERRORS);
          break;
        }
      } else {
        printf("  Node %zu validation succeeded\n", j);
        error_count = 0;
        validation_success = 1;

        // Update node metrics
        uint64_t validation_end = get_current_time_ms();
        uint64_t validation_time = validation_end - validation_start;
        TEST_ASSERT(validation_time <= MAX_LATENCY_MS,
                    "Node validation within latency limit");

        TEST_ASSERT(mxd_update_node_metrics(&nodes[j], validation_time,
                                            validation_end) == 0,
                    "Metrics update");
      }
    }
    
    if (validation_success) {
      TEST_ASSERT(mxd_apply_transaction_to_utxo(&transactions[i]) == 0,
                  "Apply transaction to UTXO database");
      
      printf("Transaction %d validated and applied\n", i + 1);
      
      tx_count++;
      uint64_t tx_current_time = get_current_time_ms();
      uint64_t tx_elapsed = tx_current_time - tx_start_time;
      if (tx_elapsed >= 100) {
        double rate = (double)tx_count * 1000.0 / (double)tx_elapsed;
        printf("Transaction rate: %.2f tx/s\n", rate);
        if (tx_count >= 10) {
          TEST_ASSERT(rate >= MIN_TX_RATE,
                      "Transaction rate meets minimum requirement");
        }
        tx_start_time = tx_current_time;
        tx_count = 0;
      }
    } else {
      printf("Transaction %d validation failed, stopping test\n", i + 1);
      break;
    }
  }

  // Test rapid stake table updates
  uint64_t start_time = get_current_time_ms();
  TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
              "Rapid table update");
  uint64_t update_latency = get_current_time_ms() - start_time;
  printf("Rapid table update latency: %lums\n", update_latency);
  TEST_ASSERT(update_latency <= MAX_LATENCY_MS,
              "Table update within latency limit");

  // Verify node ranking by performance score
  for (size_t i = 1; i < TEST_NODE_COUNT; i++) {
    TEST_ASSERT(nodes[i - 1].metrics.avg_response_time <=
                    nodes[i].metrics.avg_response_time,
                "Node ranking order");
  }

  // Update rapid stake table with performance data
  uint64_t current_time = get_current_time_ms();
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    // Ensure node is active and has valid stake
    nodes[i].active = 1;
    nodes[i].stake_amount = 100.0 + (i * 10.0); // Significant stakes
    TEST_ASSERT(mxd_validate_node_stake(&nodes[i], total_stake) == 0,
                "Node stake validation");

    // Reset metrics
    TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                "Node metrics initialization");

    // Add minimum required responses (10) with response time under
    // MXD_MAX_RESPONSE_TIME
    for (int j = 0; j < MXD_MIN_RESPONSE_COUNT; j++) {
      uint64_t response_time = 100 + (i * 50); // Increasing but under 5000ms
      TEST_ASSERT(response_time < MXD_MAX_RESPONSE_TIME,
                  "Response time within limits");
      TEST_ASSERT(mxd_update_node_metrics(&nodes[i], response_time,
                                          current_time + j * 1000) == 0,
                  "Metrics update");
    }

    // Validate node performance after stake validation
    TEST_ASSERT(
        mxd_validate_node_performance(&nodes[i], current_time + 10000) == 0,
        "Node performance validation");
  }

  // Update rapid stake table to rank nodes
  TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
              "Rapid table update");

  // Test tip distribution
  double total_tip = 100.0;
  uint32_t total_rank = 0;

  // Ensure all nodes meet minimum stake requirement (0.1% of total)
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    // Set significant stake (1-5% of total)
    nodes[i].stake_amount = (total_stake * 0.01) * (i + 1);
    TEST_ASSERT(mxd_validate_node_stake(&nodes[i], total_stake) == 0,
                "Node stake validation for tips");
  }

  // Add performance data meeting requirements
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    // Reset metrics
    TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                "Node metrics initialization");

    // Add minimum required responses with good performance
    for (int j = 0; j < MXD_MIN_RESPONSE_COUNT; j++) {
      uint64_t response_time = 100; // Fast response time
      TEST_ASSERT(mxd_update_node_metrics(&nodes[i], response_time,
                                          current_time - (j * 1000)) == 0,
                  "Metrics update");
    }

    // Mark node as active
    nodes[i].active = 1;
    nodes[i].metrics.last_update = current_time;

    // Verify performance
    TEST_ASSERT(mxd_validate_node_performance(&nodes[i], current_time) == 0,
                "Node performance validation for tips");

    // Calculate rank
    nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
    TEST_ASSERT(nodes[i].rank >= 0, "Node rank calculation");
    total_rank += nodes[i].rank;
  }

  // Ensure we have valid total rank
  TEST_ASSERT(total_rank > 0, "Total rank must be positive");

  // Update rapid stake table to calculate ranks
  TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
              "Rapid table update for tip distribution");

  // Ensure all nodes have valid stake and performance before sorting
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    // Set required metrics
    nodes[i].active = 1;
    nodes[i].metrics.response_count = MXD_MIN_RESPONSE_COUNT;
    nodes[i].metrics.avg_response_time = 100;                        // Fast response time
    nodes[i].stake_amount = (total_stake / 100) * (i + 1);          // 1-5% stake (integer arithmetic)
    nodes[i].metrics.last_update = current_time;

    // Verify requirements
    TEST_ASSERT(nodes[i].active == 1, "Node must be active");
    TEST_ASSERT(nodes[i].metrics.response_count >= MXD_MIN_RESPONSE_COUNT,
                "Node must have minimum responses");
    TEST_ASSERT(nodes[i].metrics.avg_response_time <= MXD_MAX_RESPONSE_TIME,
                "Node response time must be within limits");
    TEST_ASSERT(nodes[i].stake_amount >= total_stake * 0.001,
                "Node must have minimum stake (0.1%)");
  }

  // Sort nodes by rank (highest to lowest)
  for (size_t i = 0; i < TEST_NODE_COUNT - 1; i++) {
    for (size_t j = i + 1; j < TEST_NODE_COUNT; j++) {
      if (nodes[j].rank > nodes[i].rank) {
        mxd_node_stake_t temp = nodes[i];
        nodes[i] = nodes[j];
        nodes[j] = temp;
      }
    }
  }

  // Calculate expected tips based on 50% pattern from whitepaper using integer arithmetic
  mxd_amount_t expected_tips[TEST_NODE_COUNT];
  mxd_amount_t remaining = total_tip;
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    if (i == TEST_NODE_COUNT - 1 || remaining <= 1) {
      // Last node gets remaining amount (accumulates all rounding remainders)
      expected_tips[i] = remaining;
      remaining = 0;
    } else {
      // Each node gets 50% of remaining (integer division)
      expected_tips[i] = remaining / 2;
      remaining -= expected_tips[i];
    }
    // Initialize tip share to 0
    nodes[i].metrics.tip_share = 0;
  }

  // Distribute tips based on ranking
  TEST_ASSERT(mxd_distribute_tips(nodes, TEST_NODE_COUNT, total_tip) == 0,
              "Tip distribution");

  // Verify tip distribution matches whitepaper pattern (exact integer equality)
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    TEST_ASSERT(nodes[i].metrics.tip_share == expected_tips[i],
                "Tip share matches whitepaper pattern");
  }

  // Cleanup
  for (int i = 0; i < TEST_TRANSACTIONS; i++) {
    mxd_free_transaction(&transactions[i]);
  }
  mxd_free_transaction(&genesis_tx);
  
  mxd_close_utxo_db();
  mxd_init_utxo_db("./mining_test_utxo.db"); // Re-initialize to clean state

  TEST_END("Mining and Validation Test");
}

int main(void) {
  uint8_t test_pub_key[32] = {0};
  uint8_t test_priv_key[64] = {0};
  
  TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, test_pub_key, test_priv_key) == 0,
              "Test keypair generation");

  TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");
  TEST_ASSERT(test_init_p2p_ed25519(12345, test_pub_key, test_priv_key) == 0, "P2P initialization");

  test_mining_validation();

  mxd_stop_p2p();
  return 0;
}
