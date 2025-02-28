#include "../include/mxd_crypto.h"
#include "../include/mxd_transaction.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_transaction_creation(void) {
  mxd_transaction_t tx;

  TEST_START("Transaction Creation");

  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create new transaction");
  TEST_ASSERT(tx.version == 1, "Transaction version is 1");
  TEST_ASSERT(tx.input_count == 0, "Input count initialized to 0");
  TEST_ASSERT(tx.output_count == 0, "Output count initialized to 0");
  TEST_ASSERT(tx.inputs == NULL, "Input array initialized to NULL");
  TEST_ASSERT(tx.outputs == NULL, "Output array initialized to NULL");

  mxd_free_transaction(&tx);
  TEST_END("Transaction Creation");
}

static void test_input_output_management(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[256] = {2};
  uint8_t recv_key[256] = {3};

  TEST_START("Input/Output Management");

  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create new transaction");

  // Add input
  TEST_ARRAY("Previous hash", prev_hash, 64);
  TEST_ARRAY("Public key", pub_key, 256);
  TEST_ASSERT(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0,
              "Add transaction input");
  TEST_ASSERT(tx.input_count == 1, "Input count is 1");
  TEST_ASSERT(memcmp(tx.inputs[0].prev_tx_hash, prev_hash, 64) == 0,
              "Previous hash matches");
  TEST_ASSERT(tx.inputs[0].output_index == 0, "Output index is 0");
  TEST_ASSERT(memcmp(tx.inputs[0].public_key, pub_key, 256) == 0,
              "Public key matches");

  // Add output
  TEST_ARRAY("Recipient key", recv_key, 256);
  TEST_VALUE("Output amount", "%.1f", 1.0);
  TEST_ASSERT(mxd_add_tx_output(&tx, recv_key, 1.0) == 0,
              "Add transaction output");
  TEST_ASSERT(tx.output_count == 1, "Output count is 1");
  TEST_ASSERT(memcmp(tx.outputs[0].recipient_key, recv_key, 256) == 0,
              "Recipient key matches");
  TEST_ASSERT(tx.outputs[0].amount == 1.0, "Amount matches");

  mxd_free_transaction(&tx);
  TEST_END("Input/Output Management");
}

static void test_transaction_signing(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[256];
  uint8_t priv_key[128];

  // Generate keypair
  assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);

  // Create and sign transaction
  assert(mxd_create_transaction(&tx) == 0);
  assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
  assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);

  // Sign input
  assert(mxd_sign_tx_input(&tx, 0, priv_key) == 0);

  // Verify signature
  assert(mxd_verify_tx_input(&tx, 0) == 0);

  mxd_free_transaction(&tx);
  printf("Transaction signing test passed\n");
}

static void test_transaction_validation(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[256];
  uint8_t priv_key[128];

  // Generate keypair
  assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);

  // Create valid transaction
  assert(mxd_create_transaction(&tx) == 0);
  assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
  assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);
  assert(mxd_set_voluntary_tip(&tx, 0.1) == 0);
  tx.timestamp = 1708198204; // Set a valid timestamp
  assert(mxd_sign_tx_input(&tx, 0, priv_key) == 0);

  // Validate transaction
  assert(mxd_validate_transaction(&tx) == 0);

  // Test invalid cases
  tx.version = 0;
  assert(mxd_validate_transaction(&tx) == -1);

  mxd_free_transaction(&tx);
  printf("Transaction validation test passed\n");
}

static void test_transaction_hashing(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[256] = {2};
  uint8_t hash[64];

  assert(mxd_create_transaction(&tx) == 0);
  assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
  assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);

  // Calculate hash
  assert(mxd_calculate_tx_hash(&tx, hash) == 0);

  // Hash should not be all zeros
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (hash[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  assert(!is_zero);

  mxd_free_transaction(&tx);
  printf("Transaction hashing test passed\n");
}

int main(void) {
  printf("Starting transaction tests...\n");

  // Initialize transaction validation system
  assert(mxd_init_transaction_validation() == 0);

  test_transaction_creation();
  test_input_output_management();
  test_transaction_signing();
  test_transaction_validation();
  test_transaction_hashing();

  printf("All transaction tests passed\n");
  return 0;
}
