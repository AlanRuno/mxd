#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_utxo_initialization(void) {
  TEST_START("UTXO Initialization");
  TEST_ASSERT(mxd_init_utxo_db("./test_utxo.db") == 0, "Initialize UTXO database");
  TEST_END("UTXO Initialization");
}

static void test_utxo_management(void) {
  mxd_utxo_t utxo = {0};
  uint8_t tx_hash[64] = {1};
  uint8_t owner_key[256] = {2};

  TEST_START("UTXO Management");
  
  // Initialize UTXO
  TEST_ARRAY("Transaction hash", tx_hash, 64);
  TEST_ARRAY("Owner key", owner_key, 256);
  TEST_VALUE("Output index", "%u", 0);
  TEST_VALUE("Amount", "%.1f", 1.0);
  
  memcpy(utxo.tx_hash, tx_hash, 64);
  utxo.output_index = 0;
  memcpy(utxo.owner_key, owner_key, 256);
  utxo.amount = 1.0;
  
  TEST_ASSERT(mxd_hash160(owner_key, 256, utxo.pubkey_hash) == 0, "Calculate pubkey hash");

  // Add UTXO
  TEST_ASSERT(mxd_add_utxo(&utxo) == 0, "Add UTXO to database");

  // Find UTXO
  mxd_utxo_t found_utxo;
  TEST_ASSERT(mxd_find_utxo(tx_hash, 0, &found_utxo) == 0, "Find UTXO in database");
  TEST_ASSERT(memcmp(found_utxo.tx_hash, tx_hash, 64) == 0, "Found UTXO hash matches");
  TEST_ASSERT(found_utxo.amount == 1.0, "Found UTXO amount matches");

  // Verify UTXO
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, owner_key) == 0, "Verify UTXO ownership");

  // Get balance
  TEST_ASSERT(mxd_get_balance(owner_key) == 1.0, "Owner balance is correct");

  // Remove UTXO
  TEST_ASSERT(mxd_remove_utxo(tx_hash, 0) == 0, "Remove UTXO from database");
  TEST_ASSERT(mxd_find_utxo(tx_hash, 0, &found_utxo) == -1, "UTXO no longer exists");

  TEST_END("UTXO Management");
}

static void test_multisig_utxo(void) {
  mxd_utxo_t utxo = {0};
  uint8_t tx_hash[64] = {1};
  uint8_t owner_key[256] = {2};
  uint8_t cosigner_keys[2 * 256] = {3, 4};

  TEST_START("Multi-signature UTXO");
  
  // Initialize UTXO
  TEST_ARRAY("Transaction hash", tx_hash, 64);
  TEST_ARRAY("Owner key", owner_key, 256);
  TEST_ARRAY("Cosigner keys", cosigner_keys, 2 * 256);
  TEST_VALUE("Output index", "%u", 0);
  TEST_VALUE("Amount", "%.1f", 1.0);
  
  memcpy(utxo.tx_hash, tx_hash, 64);
  utxo.output_index = 0;
  memcpy(utxo.owner_key, owner_key, 256);
  utxo.amount = 1.0;
  
  TEST_ASSERT(mxd_hash160(owner_key, 256, utxo.pubkey_hash) == 0, "Calculate pubkey hash");

  // Create multi-sig UTXO
  TEST_ASSERT(mxd_create_multisig_utxo(&utxo, cosigner_keys, 2, 2) == 0, "Multi-sig UTXO creation successful");
  TEST_ASSERT(utxo.required_signatures == 2, "Required signatures set correctly");
  TEST_ASSERT(utxo.cosigner_count == 2, "Cosigner count set correctly");

  // Add UTXO
  TEST_ASSERT(mxd_add_utxo(&utxo) == 0, "Multi-sig UTXO added to database");

  // Verify cosigners can spend
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, cosigner_keys) == 0, "First cosigner can spend");
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, cosigner_keys + 256) == 0, "Second cosigner can spend");

  // Clean up
  mxd_free_utxo(&utxo);
  TEST_END("Multi-signature UTXO");
}

int main(void) {
  TEST_START("UTXO Tests");

  test_utxo_initialization();
  test_utxo_management();
  test_multisig_utxo();

  mxd_close_utxo_db();

  TEST_END("UTXO Tests");
  return 0;
}
