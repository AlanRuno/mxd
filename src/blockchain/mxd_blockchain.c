#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_rsc.h"
#include "../../include/mxd_utxo.h"
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
  block->rapid_membership_entries = NULL;
  block->rapid_membership_count = 0;
  block->rapid_membership_capacity = 0;
  block->total_supply = 0.0;
  block->transaction_set_frozen = 0;

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

  // Verify block hash is computable
  uint8_t hash[64];
  if (mxd_calculate_block_hash(block, hash) != 0) {
    return -1;
  }

  if (block->difficulty <= 1) {
    return 0;
  }

  return hash[0] >= block->difficulty ? 0 : -1;
}

// Freeze transaction set and calculate final merkle root
int mxd_freeze_transaction_set(mxd_block_t *block) {
  if (!block) {
    return -1;
  }
  
  if (block->transaction_set_frozen) {
    return 0; // Already frozen
  }
  
  // Mark as frozen - merkle_root is now immutable
  block->transaction_set_frozen = 1;
  return 0;
}

// Calculate membership digest over frozen transaction set
// Digest = hash(version || prev_block_hash || merkle_root || proposer_id || height || difficulty)
// Explicitly excludes: validation_chain, rapid_membership_entries, timestamp, nonce, block_hash
int mxd_calculate_membership_digest(const mxd_block_t *block, uint8_t digest[64]) {
  if (!block || !digest) {
    return -1;
  }
  
  if (!block->transaction_set_frozen) {
    return -1; // Transaction set must be frozen before calculating digest
  }
  
  // Create buffer for digest calculation
  size_t buffer_size = sizeof(uint32_t) + 64 + 64 + 20 + sizeof(uint32_t) + sizeof(uint32_t);
  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }
  
  size_t offset = 0;
  
  // Serialize immutable fields
  memcpy(buffer + offset, &block->version, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  memcpy(buffer + offset, block->prev_block_hash, 64);
  offset += 64;
  
  memcpy(buffer + offset, block->merkle_root, 64);
  offset += 64;
  
  memcpy(buffer + offset, block->proposer_id, 20);
  offset += 20;
  
  memcpy(buffer + offset, &block->height, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  memcpy(buffer + offset, &block->difficulty, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  // Calculate SHA-512 hash
  int result = mxd_sha512(buffer, buffer_size, digest);
  free(buffer);
  
  return result;
}

// Append membership entry to block with validation
int mxd_append_membership_entry(mxd_block_t *block, const uint8_t node_address[20],
                                const uint8_t *signature, uint16_t signature_length,
                                uint64_t timestamp) {
  if (!block || !node_address || !signature || signature_length == 0) {
    return -1;
  }
  
  if (!block->transaction_set_frozen) {
    return -1; // Transaction set must be frozen before accepting membership entries
  }
  
  // Check for duplicate address
  for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
    if (memcmp(block->rapid_membership_entries[i].node_address, node_address, 20) == 0) {
      return -1; // Duplicate entry
    }
  }
  
  // Verify signature over membership digest
  uint8_t digest[64];
  if (mxd_calculate_membership_digest(block, digest) != 0) {
    return -1;
  }
  
  // Get validator public key
  uint8_t pubkey[4096];
  size_t pubkey_len = 0;
  if (mxd_get_validator_public_key(node_address, pubkey, sizeof(pubkey), &pubkey_len) != 0) {
    return -1; // Public key not registered
  }
  
  // Verify signature using Dilithium
  if (mxd_dilithium_verify(signature, signature_length, digest, 64, pubkey) != 0) {
    return -1; // Invalid signature
  }
  
  // Verify stake requirement (1% of total supply, or genesis mode)
  if (block->total_supply > 0.0) {
    double balance = mxd_get_balance(pubkey);
    double stake_percentage = (balance / block->total_supply) * 100.0;
    if (stake_percentage < 1.0) {
      return -1; // Insufficient stake
    }
  }
  // In genesis mode (total_supply == 0), any address can join
  
  // Allocate or reallocate membership entries array
  if (block->rapid_membership_count >= block->rapid_membership_capacity) {
    uint32_t new_capacity = block->rapid_membership_capacity == 0 ? 10 : block->rapid_membership_capacity * 2;
    mxd_rapid_membership_entry_t *new_entries = realloc(block->rapid_membership_entries,
                                                         new_capacity * sizeof(mxd_rapid_membership_entry_t));
    if (!new_entries) {
      return -1;
    }
    block->rapid_membership_entries = new_entries;
    block->rapid_membership_capacity = new_capacity;
  }
  
  // Add entry
  mxd_rapid_membership_entry_t *entry = &block->rapid_membership_entries[block->rapid_membership_count];
  memcpy(entry->node_address, node_address, 20);
  entry->timestamp = timestamp;
  entry->signature_length = signature_length;
  if (signature_length > MXD_SIGNATURE_MAX) {
    return -1; // Signature too large
  }
  memcpy(entry->signature, signature, signature_length);
  
  block->rapid_membership_count++;
  
  return 0;
}

// Check if block has membership quorum (2/3 of rapid table size)
int mxd_block_has_membership_quorum(const mxd_block_t *block, size_t rapid_table_size) {
  if (!block) {
    return 0;
  }
  
  if (rapid_table_size == 0) {
    return block->rapid_membership_count >= 3 ? 1 : 0;
  }
  
  // Calculate 2/3 threshold
  size_t required = (rapid_table_size * 2 + 2) / 3; // Ceiling division
  
  return block->rapid_membership_count >= required ? 1 : 0;
}

// Check if block is in pre-signed state (has membership entries but no validation chain)
int mxd_block_is_presigned(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  return block->transaction_set_frozen && 
         block->rapid_membership_count > 0 && 
         block->validation_count == 0;
}

// Check if block is ready for validation chain (has membership quorum)
int mxd_block_is_ready(const mxd_block_t *block, size_t rapid_table_size) {
  if (!block) {
    return 0;
  }
  
  return block->transaction_set_frozen && 
         mxd_block_has_membership_quorum(block, rapid_table_size) &&
         block->validation_count == 0;
}

// Check if block is finalized (validation chain complete)
int mxd_block_is_finalized(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  // Block is finalized if it has validation chain signatures
  // The exact quorum check is done by mxd_block_has_validation_quorum in mxd_rsc.c
  return block->validation_count > 0;
}
