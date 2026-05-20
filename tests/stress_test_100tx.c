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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_NODE_COUNT        6
#define MIN_TX_RATE            10
#define MAX_LATENCY_MS         3000
#define MAX_CONSECUTIVE_ERRORS 10
#define TEST_TRANSACTIONS      100

static void test_stress_100_transactions(void) {
  TEST_START("Stress Test: 100 Transactions with 6 Nodes");

  // Initialize test nodes with different stakes
  mxd_node_stake_t nodes[TEST_NODE_COUNT];
  double total_stake = 0.0;
  uint32_t error_count = 0;
  uint64_t tx_start_time = get_current_time_ms();
  uint32_t tx_count = 0;
  uint32_t successful_tx = 0;

  // Initialize UTXO database
  TEST_ASSERT(mxd_init_utxo_db("./stress_test_utxo.db") == 0, "UTXO database initialization");
  
  // Initialize transaction validation system
  TEST_ASSERT(mxd_init_transaction_validation() == 0, "Transaction validation initialization");

  // Initialize nodes with stakes and metrics
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    memset(&nodes[i], 0, sizeof(mxd_node_stake_t));
    snprintf(nodes[i].node_id, sizeof(nodes[i].node_id), "node-%zu", i);
    nodes[i].stake_amount = 100 + (i * 10); // Stakes: 100, 110, 120, 130, 140, 150
    nodes[i].active = 1;
    // Initialize unique 20-byte address per node
    for (int j = 0; j < 20; j++) {
      nodes[i].node_address[j] = j + i;
    }
    TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                "Node metrics initialization");
    nodes[i].metrics.response_count = 0;
    nodes[i].metrics.min_response_time = UINT64_MAX;
    nodes[i].metrics.max_response_time = 0;
    nodes[i].metrics.avg_response_time = 0;
    total_stake += nodes[i].stake_amount;
    TEST_ASSERT(mxd_validate_node_stake(&nodes[i], total_stake) == 0,
                "Node stake validation");
  }

  printf("Initialized %d nodes with total stake: %.0f\n", TEST_NODE_COUNT, total_stake);

  // Create test transactions and keys
  mxd_transaction_t *transactions = malloc(TEST_TRANSACTIONS * sizeof(mxd_transaction_t));
  TEST_ASSERT(transactions != NULL, "Transaction array allocation");
  
  uint8_t recipient_key[32] = {0};
  uint8_t private_key[64] = {0};
  uint8_t public_key[32] = {0};

  // Generate valid Ed25519 keys for testing
  TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, public_key, private_key) == 0,
              "Key generation");
  memcpy(recipient_key, public_key, 32);

  printf("Starting stress test with %d transactions\n", TEST_TRANSACTIONS);

  // Create initial UTXO for testing with large amount
  mxd_transaction_t genesis_tx;
  mxd_utxo_t genesis_utxo;
  uint8_t genesis_hash[64] = {0};

  TEST_ASSERT(mxd_create_transaction(&genesis_tx) == 0,
              "Genesis transaction creation");
  // Large initial amount to support 100 transactions
  TEST_ASSERT(test_add_tx_output_to_pubkey_ed25519(&genesis_tx, public_key, 10000.0) == 0,
              "Genesis output addition");
  TEST_ASSERT(mxd_calculate_tx_hash(&genesis_tx, genesis_hash) == 0,
              "Genesis hash calculation");
  memcpy(genesis_tx.tx_hash, genesis_hash, sizeof(genesis_hash));

  // Create and add UTXO with addr32 derived from pubkey (full 32-byte copy)
  memset(&genesis_utxo, 0, sizeof(mxd_utxo_t));
  memcpy(genesis_utxo.tx_hash, genesis_hash, sizeof(genesis_hash));
  genesis_utxo.output_index = 0;
  genesis_utxo.amount = 10000.0;
  { uint8_t _a32[MXD_ADDR32_LEN];
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, public_key, 32, _a32) == 0,
                "Address derivation for genesis UTXO");
    memcpy(genesis_utxo.owner_key, _a32, MXD_ADDR32_LEN); }
  TEST_ASSERT(mxd_add_utxo(&genesis_utxo) == 0, "Genesis UTXO addition");

  uint8_t prev_tx_hash[64];
  memcpy(prev_tx_hash, genesis_hash, 64);
  uint32_t prev_output_index = 0;
  double remaining_amount = 10000.0;

  printf("\n=== Starting Transaction Processing ===\n");
  tx_start_time = get_current_time_ms();

  for (int i = 0; i < TEST_TRANSACTIONS; i++) {
    if (i % 10 == 0) {
      printf("Processing transactions %d-%d...\n", i + 1, i + 10 < TEST_TRANSACTIONS ? i + 10 : TEST_TRANSACTIONS);
    }
    
    TEST_ASSERT(mxd_create_transaction(&transactions[i]) == 0,
                "Transaction creation");
    TEST_ASSERT(test_add_tx_input_ed25519(&transactions[i], prev_tx_hash, prev_output_index,
                                 public_key) == 0,
                "Input addition");
    
    if (i == 0) {
      transactions[i].inputs[0].amount = 10000.0;
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
    
    // IMPORTANT: Set voluntary tip BEFORE signing
    TEST_ASSERT(mxd_set_voluntary_tip(&transactions[i], 1.0) == 0,
                "Voluntary tip setting");
    
    TEST_ASSERT(test_sign_tx_input_ed25519(&transactions[i], 0, private_key) == 0,
                "Input signing");
    
    TEST_ASSERT(mxd_calculate_tx_hash(&transactions[i], prev_tx_hash) == 0,
                "Transaction hash calculation");
    memcpy(transactions[i].tx_hash, prev_tx_hash, 64);

    // Validate through node chain
    int validation_success = 0;
    for (size_t j = 0; j < TEST_NODE_COUNT; j++) {
      uint64_t validation_start = get_current_time_ms();

      int validation_result = mxd_validate_transaction(&transactions[i]);
      if (validation_result != 0) {
        error_count++;
        if (error_count > MAX_CONSECUTIVE_ERRORS) {
          printf("ERROR: Too many consecutive validation errors at tx %d\n", i + 1);
          TEST_ERROR_COUNT(error_count, MAX_CONSECUTIVE_ERRORS);
          break;
        }
      } else {
        error_count = 0;
        validation_success = 1;

        // Update node metrics
        uint64_t validation_end = get_current_time_ms();
        uint64_t validation_time = validation_end - validation_start;

        TEST_ASSERT(mxd_update_node_metrics(&nodes[j], validation_time,
                                            validation_end) == 0,
                    "Metrics update");
        break; // One successful validation is enough
      }
    }
    
    if (validation_success) {
      TEST_ASSERT(mxd_apply_transaction_to_utxo(&transactions[i]) == 0,
                  "Apply transaction to UTXO database");
      
      successful_tx++;
      tx_count++;
    } else {
      printf("Transaction %d validation failed on all nodes\n", i + 1);
      break;
    }
  }

  uint64_t tx_end_time = get_current_time_ms();
  uint64_t total_time = tx_end_time - tx_start_time;
  double tx_rate = (double)successful_tx * 1000.0 / (double)total_time;

  printf("\n=== Stress Test Results ===\n");
  printf("Total transactions attempted: %d\n", TEST_TRANSACTIONS);
  printf("Successful transactions: %d\n", successful_tx);
  printf("Total time: %lu ms\n", (unsigned long)total_time);
  printf("Transaction rate: %.2f tx/s\n", tx_rate);
  printf("Nodes used: %d\n", TEST_NODE_COUNT);
  
  TEST_ASSERT(successful_tx == TEST_TRANSACTIONS, "All transactions should succeed");
  TEST_ASSERT(tx_rate >= MIN_TX_RATE, "Transaction rate meets minimum requirement");

  // Test rapid stake table updates
  uint64_t start_time = get_current_time_ms();
  TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
              "Rapid table update");
  uint64_t update_latency = get_current_time_ms() - start_time;
  printf("Rapid table update latency: %lu ms\n", (unsigned long)update_latency);

  // Test tip distribution
  mxd_amount_t total_tip = 100;
  
  // Ensure all nodes meet requirements for tip distribution
  // Use mxd_now_ms() which is what mxd_update_rapid_table uses internally
  uint64_t current_time = mxd_now_ms();
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    nodes[i].active = 1;
    nodes[i].metrics.response_count = MXD_MIN_RESPONSE_COUNT;
    nodes[i].metrics.avg_response_time = 100;
    nodes[i].stake_amount = (mxd_amount_t)((total_stake / 100) * (i + 1));
    nodes[i].metrics.last_update = current_time;
  }

  // Update rapid stake table to calculate ranks
  TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, (mxd_amount_t)total_stake) == 0,
              "Rapid table update for tip distribution");

  // Distribute tips
  TEST_ASSERT(mxd_distribute_tips(nodes, TEST_NODE_COUNT, total_tip) == 0,
              "Tip distribution");

  printf("\n=== Tip Distribution Results ===\n");
  mxd_amount_t total_distributed = 0;
  for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
    printf("Node %zu: tip_share=%lu\n", i, (unsigned long)nodes[i].metrics.tip_share);
    total_distributed += nodes[i].metrics.tip_share;
  }
  printf("Total distributed: %lu (expected: %lu)\n", (unsigned long)total_distributed, (unsigned long)total_tip);
  TEST_ASSERT(total_distributed == total_tip, "All tips should be distributed");

  // Cleanup
  for (int i = 0; i < successful_tx; i++) {
    mxd_free_transaction(&transactions[i]);
  }
  free(transactions);
  mxd_free_transaction(&genesis_tx);
  
  mxd_close_utxo_db();

  printf("\n=== STRESS TEST PASSED ===\n");
  TEST_END("Stress Test: 100 Transactions with 6 Nodes");
}

int main(void) {
  printf("MXD Blockchain Stress Test\n");
  printf("==========================\n\n");
  
  uint8_t test_pub_key[32] = {0};
  uint8_t test_priv_key[64] = {0};
  
  TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, test_pub_key, test_priv_key) == 0,
              "Test keypair generation");

  TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");

  test_stress_100_transactions();

  return 0;
}
