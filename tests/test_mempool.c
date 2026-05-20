#include "../include/mxd_crypto.h"
#include "../include/mxd_mempool.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // For sleep

static void test_mempool_initialization(void) {
  TEST_START("Mempool Initialization");
  TEST_ASSERT(mxd_init_mempool() == 0, "Initialize mempool");
  TEST_ASSERT(mxd_get_mempool_size() == 0, "Initial mempool size is zero");
  TEST_END("Mempool Initialization");
}

static void test_transaction_management(void) {
  TEST_START("Transaction Management");
  mxd_init_mempool(); // Reset mempool

  mxd_transaction_t tx;
  uint8_t tx_hash[64];
  uint8_t pub_key[2592];
  uint8_t priv_key[4864];

  // Generate keypair
  TEST_ASSERT(mxd_dilithium_keygen(pub_key, priv_key) == 0, "Generate keypair");
  TEST_ARRAY("Public key", pub_key, 2592);

  // Create and sign transaction
  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create transaction");
  TEST_ASSERT(mxd_add_tx_output(&tx, pub_key, 1.0) == 0, "Add transaction output");
  TEST_VALUE("Transaction amount", "%.1f", 1.0);
  TEST_ASSERT(mxd_calculate_tx_hash(&tx, tx_hash) == 0, "Calculate transaction hash");
  TEST_ARRAY("Transaction hash", tx_hash, 64);

  // Add to mempool
  TEST_ASSERT(mxd_add_to_mempool(&tx, MXD_PRIORITY_HIGH) == 0, "Add transaction to mempool");
  TEST_ASSERT(mxd_get_mempool_size() == 1, "Mempool size is 1 after addition");

  // Get from mempool
  mxd_transaction_t found_tx;
  TEST_ASSERT(mxd_get_from_mempool(tx_hash, &found_tx) == 0, "Retrieve transaction from mempool");

  // Remove from mempool
  TEST_ASSERT(mxd_remove_from_mempool(tx_hash) == 0, "Remove transaction from mempool");
  TEST_ASSERT(mxd_get_mempool_size() == 0, "Mempool size is 0 after removal");

  mxd_free_transaction(&tx);
  mxd_free_transaction(&found_tx);
  TEST_END("Transaction Management");
}

static void test_priority_handling(void) {
  mxd_init_mempool(); // Reset mempool

  mxd_transaction_t tx1, tx2, tx3;
  uint8_t pub_key[2592];
  uint8_t priv_key[4864];

  // Generate keypair
  assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);

  // Create transactions with different outputs
  assert(mxd_create_transaction(&tx1) == 0);
  assert(mxd_add_tx_output(&tx1, pub_key, 1.0) == 0);

  assert(mxd_create_transaction(&tx2) == 0);
  assert(mxd_add_tx_output(&tx2, pub_key, 2.0) == 0);

  assert(mxd_create_transaction(&tx3) == 0);
  assert(mxd_add_tx_output(&tx3, pub_key, 3.0) == 0);

  // Add to mempool with different priorities
  assert(mxd_add_to_mempool(&tx1, MXD_PRIORITY_LOW) == 0);
  assert(mxd_add_to_mempool(&tx2, MXD_PRIORITY_HIGH) == 0);
  assert(mxd_add_to_mempool(&tx3, MXD_PRIORITY_MEDIUM) == 0);

  // Get high priority transactions
  mxd_transaction_t priority_txs[3];
  size_t count = 3;
  assert(mxd_get_priority_transactions(priority_txs, &count,
                                       MXD_PRIORITY_HIGH) == 0);
  assert(count == 1); // Only one high priority transaction

  // Clean up
  mxd_free_transaction(&tx1);
  mxd_free_transaction(&tx2);
  mxd_free_transaction(&tx3);
  for (size_t i = 0; i < count; i++) {
    mxd_free_transaction(&priority_txs[i]);
  }
  printf("Priority handling test passed\n");
}

static void test_mempool_cleaning(void) {
  mxd_init_mempool(); // Reset mempool

  mxd_transaction_t tx;
  uint8_t tx_hash[64];
  uint8_t pub_key[2592];
  uint8_t priv_key[4864];

  // Generate keypair
  assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);

  // Create and add transaction
  assert(mxd_create_transaction(&tx) == 0);
  assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);
  assert(mxd_calculate_tx_hash(&tx, tx_hash) == 0);
  assert(mxd_add_to_mempool(&tx, MXD_PRIORITY_MEDIUM) == 0);

  // Clean expired transactions (none should be removed)
  assert(mxd_clean_mempool(3600) == 0); // 1 hour max age
  assert(mxd_get_mempool_size() == 1);

  // Sleep for 1 second
  sleep(1);

  // Clean with very short age (should remove all)
  assert(mxd_clean_mempool(0) == 0);
  assert(mxd_get_mempool_size() == 0);

  mxd_free_transaction(&tx);
  printf("Mempool cleaning test passed\n");
}

int main(void) {
  printf("Starting mempool tests...\n");

  test_mempool_initialization();
  test_transaction_management();
  test_priority_handling();
  test_mempool_cleaning();

  printf("All mempool tests passed\n");
  return 0;
}
