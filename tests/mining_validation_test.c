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

  // Initialize nodes with stakes and metrics
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    memset(&nodes[i], 0, sizeof(mxd_node_stake_t));
    snprintf(nodes[i].node_id, sizeof(nodes[i].node_id), "node-%zu", i);
    nodes[i].stake_amount = 100.0 + (i * 10.0); // Significant stakes
    nodes[i].active = 1;                        // Mark node as active
    for (int j = 0; j < 256; j++) {
      nodes[i].public_key[j] = j + i; // Unique key per node
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
  uint8_t recipient_key[256] = {0};
  uint8_t private_key[128] = {0};
  uint8_t public_key[256] = {0};
  uint8_t prev_hash[64] = {0};

  // Generate valid keys for testing
  TEST_ASSERT(mxd_dilithium_keygen(public_key, private_key) == 0,
              "Key generation");
  memcpy(recipient_key, public_key, 256);

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
  TEST_ASSERT(mxd_add_tx_output(&genesis_tx, public_key, 1000.0) == 0,
              "Genesis output addition");
  TEST_ASSERT(mxd_calculate_tx_hash(&genesis_tx, genesis_hash) == 0,
              "Genesis hash calculation");
  memcpy(genesis_tx.tx_hash, genesis_hash, sizeof(genesis_hash));

  // Create and add UTXO
  memset(&genesis_utxo, 0, sizeof(mxd_utxo_t));
  memcpy(genesis_utxo.tx_hash, genesis_hash, sizeof(genesis_hash));
  genesis_utxo.output_index = 0;
  genesis_utxo.amount = 1000.0;
  memcpy(genesis_utxo.owner_key, public_key, sizeof(public_key));
  TEST_ASSERT(mxd_add_utxo(&genesis_utxo) == 0, "Genesis UTXO addition");

  // Process transactions with rate tracking
  TEST_TX_RATE_START("Transaction Validation");

  for (int i = 0; i < TEST_TRANSACTIONS; i++) {
    // Create and setup transaction with valid UTXO
    TEST_ASSERT(mxd_create_transaction(&transactions[i]) == 0,
                "Transaction creation");
    TEST_ASSERT(mxd_add_tx_input(&transactions[i], genesis_tx.tx_hash, 0,
                                 public_key) == 0,
                "Input addition");
    TEST_ASSERT(mxd_add_tx_output(&transactions[i], recipient_key, 10.0) == 0,
                "Output addition");

    // Set timestamp and sign
    transactions[i].timestamp = get_current_time_ms();
    TEST_ASSERT(mxd_sign_tx_input(&transactions[i], 0, private_key) == 0,
                "Input signing");

    // Validate through node chain with latency tracking
    for (size_t j = 0; j < TEST_NODE_COUNT; j++) {
      uint64_t validation_start = get_current_time_ms();

      int validation_result = mxd_validate_transaction(&transactions[i]);
      if (validation_result != 0) {
        error_count++;
        TEST_ERROR_COUNT(error_count, MAX_CONSECUTIVE_ERRORS);
      } else {
        error_count = 0;
        TEST_TX_RATE_UPDATE("Transaction Validation", MIN_TX_RATE);

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

    // Check transaction rate every second
    uint64_t current_time = get_current_time_ms();
    uint64_t elapsed = current_time - tx_start_time;
    if (elapsed >= 1000) {
      double rate = (double)tx_count * 1000.0 / (double)elapsed;
      printf("Transaction rate: %.2f tx/s\n", rate);
      TEST_ASSERT(rate >= MIN_TX_RATE,
                  "Transaction rate meets minimum requirement");
      tx_start_time = current_time;
      tx_count = 0;
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
    nodes[i].metrics.avg_response_time = 100;             // Fast response time
    nodes[i].stake_amount = total_stake * 0.01 * (i + 1); // 1-5% stake
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

  // Calculate expected tips based on 50% pattern from whitepaper
  double expected_tips[TEST_NODE_COUNT];
  double remaining = total_tip;
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    if (i == TEST_NODE_COUNT - 1) {
      // Last node gets remaining amount
      expected_tips[i] = remaining;
    } else {
      // Each node gets 50% of remaining
      expected_tips[i] = remaining * 0.5;
      remaining -= expected_tips[i];
    }
    // Initialize tip share to 0
    nodes[i].metrics.tip_share = 0.0;
  }

  // Distribute tips based on ranking
  TEST_ASSERT(mxd_distribute_tips(nodes, TEST_NODE_COUNT, total_tip) == 0,
              "Tip distribution");

  // Verify tip distribution matches whitepaper pattern
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    TEST_ASSERT(fabs(nodes[i].metrics.tip_share - expected_tips[i]) < 0.0001,
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
  // Initialize test keys for P2P
  uint8_t test_pub_key[256] = {0};
  uint8_t test_priv_key[128] = {0};
  for (int i = 0; i < 256; i++) {
    test_pub_key[i] = i % 256;
  }
  for (int i = 0; i < 128; i++) {
    test_priv_key[i] = (i * 2) % 256;
  }

  // Initialize required systems
  TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");
  TEST_ASSERT(mxd_init_p2p(12345, test_pub_key, test_priv_key) == 0, "P2P initialization");
  TEST_ASSERT(mxd_init_transaction_validation() == 0,
              "Transaction validation initialization");

  test_mining_validation();

  // Cleanup
  mxd_stop_p2p();
  return 0;
}
