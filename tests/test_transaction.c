#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_chain.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_transaction_creation(void) {
  mxd_transaction_t tx;

  TEST_START("Transaction Creation");

  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create new transaction");
  TEST_ASSERT(tx.version == 2, "Transaction version is 2");
  TEST_ASSERT(tx.input_count == 0, "Input count initialized to 0");
  TEST_ASSERT(tx.output_count == 0, "Output count initialized to 0");
  TEST_ASSERT(tx.inputs == NULL, "Input array initialized to NULL");
  TEST_ASSERT(tx.outputs == NULL, "Output array initialized to NULL");

  mxd_free_transaction(&tx);
  TEST_END("Transaction Creation");
}

static void test_create_tx_initializes_tip_to_zero(void) {
  mxd_transaction_t tx;

  TEST_START("Create TX Initializes Tip To Zero");

  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create new transaction");
  TEST_ASSERT(tx.voluntary_tip == (mxd_amount_t)0, "voluntary_tip initialized to 0");

  mxd_free_transaction(&tx);
  TEST_END("Create TX Initializes Tip To Zero");
}

static void test_input_output_management(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[32] = {2};
  uint8_t recv_key[32] = {3};

  TEST_START("Input/Output Management");

  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create new transaction");

  // Add input
  TEST_ARRAY("Previous hash", prev_hash, 64);
  TEST_ARRAY("Public key", pub_key, 32);
  TEST_ASSERT(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0,
              "Add transaction input");
  TEST_ASSERT(tx.input_count == 1, "Input count is 1");
  TEST_ASSERT(memcmp(tx.inputs[0].prev_tx_hash, prev_hash, 64) == 0,
              "Previous hash matches");
  TEST_ASSERT(tx.inputs[0].output_index == 0, "Output index is 0");
  TEST_ASSERT(memcmp(tx.inputs[0].public_key, pub_key, 32) == 0,
              "Public key matches");

  // Add output
  TEST_ARRAY("Recipient key", recv_key, 32);
  TEST_VALUE("Output amount", "%lu", 100000000ULL);
  TEST_ASSERT(test_add_tx_output_to_pubkey_ed25519(&tx, recv_key, 100000000ULL) == 0,
              "Add transaction output");
  TEST_ASSERT(tx.output_count == 1, "Output count is 1");
  // addr32 derivation — compare full 32 bytes
  uint8_t expected_addr32[MXD_ADDR32_LEN];
  mxd_derive_address(MXD_SIGALG_ED25519, recv_key, 32, expected_addr32);
  TEST_ASSERT(memcmp(tx.outputs[0].recipient_addr, expected_addr32, MXD_ADDR32_LEN) == 0,
              "Recipient address matches (addr32)");
  TEST_ASSERT(tx.outputs[0].amount == 100000000ULL, "Amount matches");

  mxd_free_transaction(&tx);
  TEST_END("Input/Output Management");
}

static void test_transaction_signing(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[32];
  uint8_t priv_key[64];

  // Generate keypair
  assert(mxd_sig_keygen(MXD_SIGALG_ED25519, pub_key, priv_key) == 0);

  // Create and sign transaction
  assert(mxd_create_transaction(&tx) == 0);
  assert(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0);
  assert(test_add_tx_output_to_pubkey_ed25519(&tx, pub_key, 100000000ULL) == 0);

  // Sign input
  assert(test_sign_tx_input_ed25519(&tx, 0, priv_key) == 0);

  // Verify signature
  assert(mxd_verify_tx_input(&tx, 0) == 0);

  mxd_free_transaction(&tx);
  printf("Transaction signing test passed\n");
}

static void test_transaction_validation(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[32];
  uint8_t priv_key[64];

  // Generate keypair
  assert(mxd_sig_keygen(MXD_SIGALG_ED25519, pub_key, priv_key) == 0);

  // Create a test UTXO for validation
  mxd_utxo_t test_utxo = {0};
  memcpy(test_utxo.tx_hash, prev_hash, 64);
  test_utxo.output_index = 0;
  // Derive addr32 and copy all 32 bytes to owner_key
  { uint8_t _a32[MXD_ADDR32_LEN]; assert(mxd_derive_address(MXD_SIGALG_ED25519, pub_key, 32, _a32) == 0); memcpy(test_utxo.owner_key, _a32, MXD_ADDR32_LEN); }
  test_utxo.amount = 200000000ULL; // More than enough for our test transaction
  
  assert(mxd_add_utxo(&test_utxo) == 0);

  // Create valid transaction
  assert(mxd_create_transaction(&tx) == 0);
  assert(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0);
  tx.inputs[0].amount = 200000000ULL;
  assert(test_add_tx_output_to_pubkey_ed25519(&tx, pub_key, 100000000ULL) == 0);
  assert(mxd_set_voluntary_tip(&tx, 10000000ULL) == 0);
  tx.timestamp = 1708198204;
  assert(test_sign_tx_input_ed25519(&tx, 0, priv_key) == 0);

  // Validate transaction
  assert(mxd_validate_transaction(&tx) == 0);

  // Test invalid cases
  tx.version = 0;
  assert(mxd_validate_transaction(&tx) == -1);

  assert(mxd_remove_utxo(prev_hash, 0) == 0);
  mxd_free_transaction(&tx);
  printf("Transaction validation test passed\n");
}

static void test_transaction_hashing(void) {
  mxd_transaction_t tx;
  uint8_t prev_hash[64] = {1};
  uint8_t pub_key[32] = {2};
  uint8_t hash[64];

  assert(mxd_create_transaction(&tx) == 0);
  assert(test_add_tx_input_ed25519(&tx, prev_hash, 0, pub_key) == 0);
  assert(test_add_tx_output_to_pubkey_ed25519(&tx, pub_key, 100000000ULL) == 0);

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

static void test_sighash_includes_domain_tag(void) {
  TEST_START("Sighash Includes MXD-TX-V1 Domain Tag");
  mxd_transaction_t tx;
  mxd_create_transaction(&tx);
  uint8_t pub32[32] = {0};
  uint8_t prev[64] = {0};
  mxd_add_tx_input(&tx, prev, 0, MXD_SIGALG_ED25519, pub32, 32);
  uint8_t recipient[32];
  for (int i = 0; i < 32; i++) recipient[i] = 0xAA;
  mxd_add_tx_output(&tx, recipient, 100);
  tx.timestamp = 1745625600ULL;

  uint8_t h[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&tx, h) == 0, "tx hash succeeds");
  uint8_t z64[64] = {0};
  TEST_ASSERT(memcmp(h, z64, 64) != 0, "sighash is non-zero");

  mxd_free_transaction(&tx);
  TEST_END("Sighash Includes MXD-TX-V1 Domain Tag");
}

static void test_sighash_changes_with_chain_id(void) {
  TEST_START("Sighash Changes With chain_id");
  mxd_transaction_t mainnet_tx, testnet_tx;
  mxd_create_transaction(&mainnet_tx);
  mxd_create_transaction(&testnet_tx);
  mainnet_tx.chain_id = MXD_CHAIN_ID_MAINNET;
  testnet_tx.chain_id = MXD_CHAIN_ID_TESTNET;
  mainnet_tx.timestamp = testnet_tx.timestamp = 1745625600ULL;

  uint8_t recipient[32];
  for (int i = 0; i < 32; i++) recipient[i] = (uint8_t)i;
  mxd_add_tx_output(&mainnet_tx, recipient, 100);
  mxd_add_tx_output(&testnet_tx, recipient, 100);

  uint8_t h_main[64], h_test[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&mainnet_tx, h_main) == 0, "mainnet hash");
  TEST_ASSERT(mxd_calculate_tx_hash(&testnet_tx, h_test) == 0, "testnet hash");
  TEST_ASSERT(memcmp(h_main, h_test, 64) != 0, "sighashes differ across chains");

  mxd_free_transaction(&mainnet_tx);
  mxd_free_transaction(&testnet_tx);
  TEST_END("Sighash Changes With chain_id");
}

int main(void) {
  printf("Starting transaction tests...\n");

  // Initialize UTXO database first
  assert(mxd_init_utxo_db("./transaction_test_utxo.db") == 0);
  
  // Initialize transaction validation system
  assert(mxd_init_transaction_validation() == 0);

  test_transaction_creation();
  test_create_tx_initializes_tip_to_zero();
  test_input_output_management();
  test_transaction_signing();
  test_transaction_validation();
  test_transaction_hashing();
  test_sighash_includes_domain_tag();
  test_sighash_changes_with_chain_id();

  mxd_close_utxo_db();

  printf("All transaction tests passed\n");
  return 0;
}
