#include "../include/mxd_blockchain.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_block_initialization(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};

  TEST_START("Block Initialization");
  TEST_ARRAY("Previous hash", prev_hash, 64);
  
  TEST_ASSERT(mxd_init_block(&block, prev_hash) == 0, "Block initialization successful");
  TEST_ASSERT(block.version == 1, "Block version is 1");
  TEST_ASSERT(block.difficulty > 0, "Block difficulty is positive");
  
  TEST_VALUE("Block version", "%d", block.version);
  TEST_VALUE("Block difficulty", "%u", block.difficulty);
  
  TEST_END("Block Initialization");
}

static void test_transaction_handling(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t transaction_data[32] = {1, 2, 3, 4};

  TEST_START("Transaction Handling");
  TEST_ARRAY("Transaction data", transaction_data, 32);
  
  TEST_ASSERT(mxd_init_block(&block, prev_hash) == 0, "Block initialization successful");
  TEST_ASSERT(mxd_add_transaction(&block, transaction_data,
                             sizeof(transaction_data)) == 0, "Transaction added successfully");

  // Verify merkle root was updated
  TEST_ARRAY("Updated merkle root", block.merkle_root, 64);
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (block.merkle_root[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(!is_zero, "Merkle root was updated");
  
  TEST_END("Transaction Handling");
}

static void test_block_validation(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t transaction_data[32] = {1, 2, 3, 4};

  TEST_START("Block Validation");
  
  TEST_ASSERT(mxd_init_block(&block, prev_hash) == 0, "Block initialization successful");
  TEST_ASSERT(mxd_add_transaction(&block, transaction_data,
                             sizeof(transaction_data)) == 0, "Transaction added successfully");
  TEST_ASSERT(mxd_validate_block(&block) == 0, "Valid block validation successful");

  // Test invalid version
  TEST_VALUE("Setting invalid version", "%d", 0);
  block.version = 0;
  TEST_ASSERT(mxd_validate_block(&block) == -1, "Invalid block correctly rejected");
  
  TEST_END("Block Validation");
}

static void test_block_hashing(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t hash[64];

  TEST_START("Block Hashing");
  
  TEST_ASSERT(mxd_init_block(&block, prev_hash) == 0, "Block initialization successful");
  TEST_ASSERT(mxd_calculate_block_hash(&block, hash) == 0, "Hash calculation successful");

  TEST_ARRAY("Calculated block hash", hash, 64);
  
  // Hash should not be all zeros
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (hash[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(!is_zero, "Hash is not empty");
  
  TEST_END("Block Hashing");
}

int main(void) {
  TEST_START("Blockchain Tests");

  test_block_initialization();
  test_transaction_handling();
  test_block_validation();
  test_block_hashing();

  TEST_END("Blockchain Tests");
  return 0;
}
