#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Internal transaction storage
typedef struct {
  uint8_t *data;
  size_t length;
} transaction_t;

static transaction_t *transactions = NULL;
static size_t transaction_count = 0;

// Initialize a new block
int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]) {
  if (!block || !prev_hash) {
    return -1;
  }

  // Initialize block structure
  memset(block, 0, sizeof(mxd_block_t));
  block->version = 1; // Current version
  memcpy(block->prev_block_hash, prev_hash, 64);
  block->timestamp = time(NULL);
  block->difficulty = 1; // Initial difficulty
  block->nonce = 0;

  // Reset transaction storage
  if (transactions) {
    for (size_t i = 0; i < transaction_count; i++) {
      free(transactions[i].data);
    }
    free(transactions);
    transactions = NULL;
  }
  transaction_count = 0;

  return 0;
}

// Add transaction to block
int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length) {
  if (!block || !transaction_data || transaction_length == 0) {
    return -1;
  }

  // Allocate or reallocate transaction array
  transaction_t *new_transactions =
      realloc(transactions, (transaction_count + 1) * sizeof(transaction_t));
  if (!new_transactions) {
    return -1;
  }
  transactions = new_transactions;

  // Allocate memory for transaction data
  transactions[transaction_count].data = malloc(transaction_length);
  if (!transactions[transaction_count].data) {
    return -1;
  }

  // Copy transaction data
  memcpy(transactions[transaction_count].data, transaction_data,
         transaction_length);
  transactions[transaction_count].length = transaction_length;
  transaction_count++;

  // Update merkle root
  uint8_t hash_buffer[64];
  if (mxd_sha512(transaction_data, transaction_length, hash_buffer) != 0) {
    return -1;
  }
  memcpy(block->merkle_root, hash_buffer, 64);

  return 0;
}

// Calculate block hash
int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]) {
  if (!block || !hash) {
    return -1;
  }

  // Create buffer for block header
  uint8_t header[sizeof(uint32_t) + 64 + 64 + sizeof(time_t) +
                 sizeof(uint32_t) + sizeof(uint64_t)];
  size_t offset = 0;

  // Serialize block header
  memcpy(header + offset, &block->version, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(header + offset, block->prev_block_hash, 64);
  offset += 64;
  memcpy(header + offset, block->merkle_root, 64);
  offset += 64;
  memcpy(header + offset, &block->timestamp, sizeof(time_t));
  offset += sizeof(time_t);
  memcpy(header + offset, &block->difficulty, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(header + offset, &block->nonce, sizeof(uint64_t));

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  if (mxd_sha512(header, sizeof(header), temp_hash) != 0) {
    return -1;
  }
  return mxd_sha512(temp_hash, 64, hash);
}

// Validate block structure and contents
int mxd_validate_block(const mxd_block_t *block) {
  if (!block) {
    return -1;
  }

  // Verify block version
  if (block->version != 1) {
    return -1;
  }

  // Verify timestamp
  time_t current_time = time(NULL);
  if (block->timestamp > current_time + 7200 ||  // Max 2 hours in future
      block->timestamp < current_time - 86400) { // Max 24 hours in past
    return -1;
  }

  // Verify block hash meets difficulty
  uint8_t hash[64];
  if (mxd_calculate_block_hash(block, hash) != 0) {
    return -1;
  }

  // For now, just check if first byte meets difficulty
  return hash[0] >= block->difficulty ? 0 : -1;
}
