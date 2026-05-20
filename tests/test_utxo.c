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
  uint8_t pub_key[32] = {2};
  uint8_t owner_addr32[MXD_ADDR32_LEN];

  TEST_START("UTXO Management");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pub_key, 32, owner_addr32) == 0, "Derive address from pubkey");

  // Initialize UTXO
  TEST_ARRAY("Transaction hash", tx_hash, 64);
  TEST_ARRAY("Owner address (first 20 bytes)", owner_addr32, 20);
  TEST_VALUE("Output index", "%u", 0);
  TEST_VALUE("Amount", "%.1f", 1.0);

  memcpy(utxo.tx_hash, tx_hash, 64);
  utxo.output_index = 0;
  memcpy(utxo.owner_key, owner_addr32, MXD_ADDR32_LEN);  // full 32-byte addr32
  utxo.amount = 1.0;

  // Add UTXO
  TEST_ASSERT(mxd_add_utxo(&utxo) == 0, "Add UTXO to database");

  // Find UTXO
  mxd_utxo_t found_utxo;
  TEST_ASSERT(mxd_find_utxo(tx_hash, 0, &found_utxo) == 0, "Find UTXO in database");
  TEST_ASSERT(memcmp(found_utxo.tx_hash, tx_hash, 64) == 0, "Found UTXO hash matches");
  TEST_ASSERT(found_utxo.amount == 1.0, "Found UTXO amount matches");

  // Verify UTXO
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, owner_addr32) == 0, "Verify UTXO ownership");

  // Get balance (mxd_get_balance reads only 20 bytes from address — safe with 32-byte buf)
  TEST_ASSERT(mxd_get_balance(owner_addr32) == 1.0, "Owner balance is correct");

  // Remove UTXO
  TEST_ASSERT(mxd_remove_utxo(tx_hash, 0) == 0, "Remove UTXO from database");
  TEST_ASSERT(mxd_find_utxo(tx_hash, 0, &found_utxo) == -1, "UTXO no longer exists");

  TEST_END("UTXO Management");
}

static void test_multisig_utxo(void) {
  mxd_utxo_t utxo = {0};
  uint8_t tx_hash[64] = {1};
  uint8_t pub_key[32] = {2};
  uint8_t owner_addr32[MXD_ADDR32_LEN];
  uint8_t cosigner_pub1[32] = {3};
  uint8_t cosigner_pub2[32] = {4};
  uint8_t cosigner_addr1[MXD_ADDR32_LEN];
  uint8_t cosigner_addr2[MXD_ADDR32_LEN];
  uint8_t cosigner_addrs[2 * MXD_ADDR32_LEN];

  TEST_START("Multi-signature UTXO");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pub_key, 32, owner_addr32) == 0, "Derive owner address");
  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, cosigner_pub1, 32, cosigner_addr1) == 0, "Derive cosigner 1 address");
  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, cosigner_pub2, 32, cosigner_addr2) == 0, "Derive cosigner 2 address");
  // Copy full 32-byte addr32 for cosigners
  memcpy(cosigner_addrs, cosigner_addr1, MXD_ADDR32_LEN);
  memcpy(cosigner_addrs + MXD_ADDR32_LEN, cosigner_addr2, MXD_ADDR32_LEN);

  // Initialize UTXO
  TEST_ARRAY("Transaction hash", tx_hash, 64);
  TEST_ARRAY("Owner address (first 20 bytes)", owner_addr32, 20);
  TEST_ARRAY("Cosigner addresses", cosigner_addrs, 2 * MXD_ADDR32_LEN);
  TEST_VALUE("Output index", "%u", 0);
  TEST_VALUE("Amount", "%.1f", 1.0);

  memcpy(utxo.tx_hash, tx_hash, 64);
  utxo.output_index = 0;
  memcpy(utxo.owner_key, owner_addr32, MXD_ADDR32_LEN);  // full 32-byte addr32
  utxo.amount = 1.0;

  // Create multi-sig UTXO
  TEST_ASSERT(mxd_create_multisig_utxo(&utxo, cosigner_addrs, 2, 2) == 0, "Multi-sig UTXO creation successful");
  TEST_ASSERT(utxo.required_signatures == 2, "Required signatures set correctly");
  TEST_ASSERT(utxo.cosigner_count == 2, "Cosigner count set correctly");

  // Add UTXO
  TEST_ASSERT(mxd_add_utxo(&utxo) == 0, "Multi-sig UTXO added to database");

  // Verify cosigners can spend
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, cosigner_addr1) == 0, "First cosigner can spend");
  TEST_ASSERT(mxd_verify_utxo(tx_hash, 0, cosigner_addr2) == 0, "Second cosigner can spend");

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
