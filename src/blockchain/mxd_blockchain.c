#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_block_proposer.h"
#include "../../include/mxd_address.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_rsc.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_transaction.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_serialize.h"
#include "../../include/mxd_protocol_version.h"
#include "../../include/mxd_domain_tags.h"
#include "../../include/mxd_endian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// Initialize a new block
int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]) {
  if (!block || !prev_hash) {
    return -1;
  }

  // Initialize block structure
  memset(block, 0, sizeof(mxd_block_t));
  block->version = 1; // Current version (will be 3 after protocol upgrade)
  memcpy(block->prev_block_hash, prev_hash, 64);
  memset(block->contracts_state_root, 0, 64); // Initialize to zero (v3+)
  memset(block->validator_scores_root, 0, 64); // Initialize to zero (v4+)
  block->timestamp = mxd_now_ms() / 1000; // NTP-synchronized time in seconds
  block->difficulty = 1; // Initial difficulty
  block->nonce = 0;
  block->rapid_membership_entries = NULL;
  block->rapid_membership_count = 0;
  block->rapid_membership_capacity = 0;
  block->total_supply = 0;
  block->validator_scores = NULL;
  block->validator_scores_count = 0;
  block->validator_scores_capacity = 0;
  block->transaction_set_frozen = 0;
  block->transactions = NULL;
  block->transaction_count = 0;
  block->transaction_capacity = 0;

  return 0;
}

// Add transaction to block
int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length) {
  if (!block || !transaction_data || transaction_length == 0) {
    return -1;
  }

  if (block->transaction_set_frozen) {
    return -1; // Cannot add transactions to frozen block
  }

  // Allocate or reallocate transaction array
  if (block->transaction_count >= block->transaction_capacity) {
    uint32_t new_capacity = block->transaction_capacity == 0 ? 10 : block->transaction_capacity * 2;
    if (new_capacity < block->transaction_capacity ||
        (size_t)new_capacity > SIZE_MAX / sizeof(mxd_block_transaction_t)) {
      return -1; // overflow
    }
    mxd_block_transaction_t *new_transactions =
        realloc(block->transactions, new_capacity * sizeof(mxd_block_transaction_t));
    if (!new_transactions) {
      return -1;
    }
    block->transactions = new_transactions;
    block->transaction_capacity = new_capacity;
  }

  // Allocate memory for transaction data
  block->transactions[block->transaction_count].data = malloc(transaction_length);
  if (!block->transactions[block->transaction_count].data) {
    return -1;
  }

  // Copy transaction data
  memcpy(block->transactions[block->transaction_count].data, transaction_data,
         transaction_length);
  block->transactions[block->transaction_count].length = transaction_length;
  block->transaction_count++;

  // Merkle root will be calculated when transaction set is frozen
  return 0;
}

// Calculate block hash
// MINOR FIX: Document merkle root simplification
// NOTE: The merkle_root field currently contains a simplified hash of all transactions
// rather than a full merkle tree structure. This is acceptable for the current implementation
// but should be upgraded to a proper merkle tree for production use to enable efficient
// transaction verification and SPV (Simplified Payment Verification) support.
int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]) {
  if (!block || !hash) {
    return -1;
  }

  // Calculate buffer size based on version
  // v3+ includes contracts_state_root, v4+ also includes validator_scores_root
  // v5+ also includes next_proposer (v5: 20 bytes, v6: 32 bytes addr32)
  size_t header_size = sizeof(uint32_t) + 64 + 64 + sizeof(uint64_t) +
                       sizeof(uint32_t) + sizeof(uint64_t);
  if (block->version >= 3) {
    header_size += 64; // contracts_state_root
  }
  if (block->version >= 4) {
    header_size += 64; // validator_scores_root
  }
  if (block->version >= 6) {
    header_size += 32; // next_proposer (addr32)
  } else if (block->version >= 5) {
    header_size += 20; // next_proposer (legacy 20 bytes)
  }

  uint8_t *header = malloc(header_size);
  if (!header) {
    return -1;
  }
  size_t offset = 0;

  // Serialize block header with big-endian byte order for deterministic hashing
  uint32_t version_be = htonl(block->version);
  memcpy(header + offset, &version_be, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  memcpy(header + offset, block->prev_block_hash, 64);
  offset += 64;

  memcpy(header + offset, block->merkle_root, 64);
  offset += 64;

  // Include contracts_state_root for v3+ blocks
  if (block->version >= 3) {
    memcpy(header + offset, block->contracts_state_root, 64);
    offset += 64;
  }

  // Include validator_scores_root for v4+ blocks
  if (block->version >= 4) {
    memcpy(header + offset, block->validator_scores_root, 64);
    offset += 64;
  }

  // v5+: include next_proposer in hash. v5 = 20 bytes; v6 = 32 bytes (addr32).
  if (block->version >= 6) {
    memcpy(header + offset, block->next_proposer, 32);
    offset += 32;
  } else if (block->version >= 5) {
    memcpy(header + offset, block->next_proposer, 20);
    offset += 20;
  }

  uint64_t timestamp_be = mxd_htonll(block->timestamp);
  memcpy(header + offset, &timestamp_be, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  uint32_t difficulty_be = htonl(block->difficulty);
  memcpy(header + offset, &difficulty_be, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  uint64_t nonce_be = mxd_htonll(block->nonce);
  memcpy(header + offset, &nonce_be, sizeof(uint64_t));

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  int result = mxd_sha512(header, header_size, temp_hash);
  free(header);

  if (result != 0) {
    return -1;
  }
  return mxd_sha512(temp_hash, 64, hash);
}

// Helper struct for score-sorted proposer validation (v4+)
typedef struct {
  uint8_t address[32];   // v6: addr32
  uint64_t chain_score;
} scored_validator_t;

static int compare_scored_validators(const void *a, const void *b) {
  const scored_validator_t *va = (const scored_validator_t *)a;
  const scored_validator_t *vb = (const scored_validator_t *)b;
  // Higher score first
  if (va->chain_score != vb->chain_score) {
    return (va->chain_score > vb->chain_score) ? -1 : 1;
  }
  // Tiebreaker: address lexicographic (lower address first) — v6: 32 bytes
  return memcmp(va->address, vb->address, 32);
}

// Validate that the block proposer is valid (primary or fallback)
static int mxd_validate_block_proposer(const mxd_block_t *block) {
  if (!block) {
    return -1;
  }

  // Skip proposer validation for genesis block
  if (block->height == 0) {
    return 0;
  }

  // Get membership from previous block to determine valid proposers
  mxd_block_t prev_block;
  memset(&prev_block, 0, sizeof(prev_block));

  if (mxd_retrieve_block_by_height(block->height - 1, &prev_block) != 0) {
    MXD_LOG_ERROR("blockchain", "Failed to retrieve previous block for proposer validation");
    return -1;
  }

  // For v4+ blocks: use score-sorted order from previous block's on-chain scores
  if (block->version >= 4 && prev_block.validator_scores_count > 0 && prev_block.validator_scores) {
    uint32_t count = prev_block.validator_scores_count;

    scored_validator_t *sorted = malloc(count * sizeof(scored_validator_t));
    if (!sorted) {
      mxd_free_block(&prev_block);
      return -1;
    }

    // Compute chain_score for each validator using the same formula as mxd_compute_chain_scores
    // total_stake = sum of all stakes
    uint64_t total_stake = 0;
    for (uint32_t i = 0; i < count; i++) {
      total_stake += prev_block.validator_scores[i].stake_amount;
    }
    if (total_stake == 0) total_stake = 1;

    for (uint32_t i = 0; i < count; i++) {
      const mxd_validator_score_entry_t *e = &prev_block.validator_scores[i];
      memcpy(sorted[i].address, e->validator_address, 32);   // v6: addr32

      uint64_t bsj = e->blocks_since_joined > 0 ? e->blocks_since_joined : 1;
      // Avoid overflow: if multiplicand > UINT64_MAX/10000, divide first
      uint64_t stake_score;
      if (e->stake_amount > UINT64_MAX / 10000ULL) {
          stake_score = (e->stake_amount / total_stake) * 10000ULL;
      } else {
          stake_score = (e->stake_amount * 10000ULL) / total_stake;
      }
      if (stake_score > 10000) stake_score = 10000;
      uint64_t proposal_score;
      if ((uint64_t)e->blocks_proposed > UINT64_MAX / 10000ULL) {
          proposal_score = ((uint64_t)e->blocks_proposed / bsj) * 10000ULL;
      } else {
          proposal_score = ((uint64_t)e->blocks_proposed * 10000ULL) / bsj;
      }
      if (proposal_score > 10000) proposal_score = 10000;
      uint64_t participation_score;
      if ((uint64_t)e->blocks_signed > UINT64_MAX / 10000ULL) {
          participation_score = ((uint64_t)e->blocks_signed / bsj) * 10000ULL;
      } else {
          participation_score = ((uint64_t)e->blocks_signed * 10000ULL) / bsj;
      }
      if (participation_score > 10000) participation_score = 10000;
      uint64_t avg_latency = e->blocks_signed > 0 ? e->total_latency_ms / e->blocks_signed : 10000;
      uint64_t latency_score = (avg_latency >= 10000) ? 0 : (10000 - avg_latency);

      sorted[i].chain_score = (stake_score * 30 + proposal_score * 25 +
                                participation_score * 25 + latency_score * 20) / 100;
    }

    // Sort by score descending, address tiebreaker
    qsort(sorted, count, sizeof(scored_validator_t), compare_scored_validators);

    // Check primary proposer and fallbacks
    uint32_t primary_index = block->height % count;
    int valid = 0;
    for (uint32_t r = 0; r <= MXD_MAX_FALLBACK_RETRIES; r++) {
      uint32_t check_index = (primary_index + r) % count;
      if (memcmp(block->proposer_id, sorted[check_index].address, MXD_ADDR32_LEN) == 0) {   // v6: addr32
        if (r > 0) {
          MXD_LOG_INFO("blockchain", "Block %u accepted from fallback proposer (v4 score-sorted index %u)",
                       block->height, check_index);
        }
        valid = 1;
        break;
      }
    }

    free(sorted);
    mxd_free_block(&prev_block);
    if (!valid) {
      MXD_LOG_ERROR("blockchain", "Block %u has invalid proposer (v4 score-sorted check failed)", block->height);
    }
    return valid ? 0 : -1;
  }

  // Pre-v4: use raw membership insertion order
  uint32_t membership_count = prev_block.rapid_membership_count;
  mxd_rapid_membership_entry_t *membership = prev_block.rapid_membership_entries;

  if (membership_count == 0) {
    // Fall back to genesis membership
    mxd_free_block(&prev_block);
    if (mxd_retrieve_block_by_height(0, &prev_block) != 0) {
      return -1;
    }
    membership_count = prev_block.rapid_membership_count;
    membership = prev_block.rapid_membership_entries;
  }

  if (membership_count == 0) {
    MXD_LOG_ERROR("blockchain", "No validator set found for proposer validation");
    mxd_free_block(&prev_block);
    return -1;
  }

  // Accept primary proposer or 1 fallback (prevents permanent stalls from ghost validators)
  uint32_t primary_index = block->height % membership_count;

  for (uint32_t r = 0; r <= MXD_MAX_FALLBACK_RETRIES; r++) {
    uint32_t check_index = (primary_index + r) % membership_count;
    // v6: membership[].node_address and proposer_id are both 32-byte addr32
    if (memcmp(block->proposer_id, membership[check_index].node_address, MXD_ADDR32_LEN) == 0) {
      if (r > 0) {
        MXD_LOG_INFO("blockchain", "Block %u accepted from fallback proposer (index %u)",
                     block->height, check_index);
      }
      mxd_free_block(&prev_block);
      return 0; // Valid proposer
    }
  }

  MXD_LOG_ERROR("blockchain", "Block %u has invalid proposer (not primary at index %u or fallback)",
               block->height, primary_index);
  mxd_free_block(&prev_block);
  return -1;
}

int mxd_validate_block(const mxd_block_t *block) {
  if (!block) {
    return -1;
  }

  // Validate proposer (primary or fallback)
  if (mxd_validate_block_proposer(block) != 0) {
    return -1;
  }

  // Verify block version is within valid range (v1-v6)
  if (block->version < 1 || block->version > 6) {
    MXD_LOG_ERROR("blockchain", "Invalid block version: %u", block->version);
    return -1;
  }

  // Verify block version matches required version for its height
  mxd_network_type_t network = mxd_get_network_type();
  if (!mxd_is_valid_block_version(block->version, block->height, network)) {
    uint32_t required_version = mxd_get_required_protocol_version(block->height, network);
    MXD_LOG_ERROR("blockchain",
                  "Block version mismatch at height %u: expected v%u, got v%u",
                  block->height, required_version, block->version);
    return -1;
  }

  // For v3+ blocks, verify contracts_state_root
  if (block->version >= 3) {
    uint8_t computed_state_root[64];
    if (mxd_calculate_contracts_state_root(block, computed_state_root) != 0) {
      MXD_LOG_ERROR("blockchain", "Failed to compute contracts state root");
      return -1;
    }

    if (memcmp(computed_state_root, block->contracts_state_root, 64) != 0) {
      MXD_LOG_ERROR("blockchain", "Contracts state root mismatch");
      return -1;
    }
  }

  // For v4+ blocks, verify validator_scores_root
  if (block->version >= 4) {
    uint8_t computed_scores_root[64];
    if (mxd_calculate_validator_scores_root(block, computed_scores_root) != 0) {
      MXD_LOG_ERROR("blockchain", "Failed to compute validator scores root");
      return -1;
    }

    if (memcmp(computed_scores_root, block->validator_scores_root, 64) != 0) {
      MXD_LOG_ERROR("blockchain", "Validator scores root mismatch at height %u", block->height);
      return -1;
    }

    // Verify score values match expected computation from previous block
    if (mxd_verify_block_validator_scores(block) != 0) {
      MXD_LOG_ERROR("blockchain", "Validator score values verification failed at height %u", block->height);
      return -1;
    }
  }

  // Verify timestamp using NTP-synchronized time
  uint64_t current_time = mxd_now_ms() / 1000;
  if (block->timestamp > current_time + 300 ||   // Max 5 minutes in future
      block->timestamp < current_time - 7200) {  // Max 2 hours in past
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

// Calculate contracts state root from all contract executions in block
// This function computes the Merkle root of all contract state changes
// that occurred during transaction processing in this block
int mxd_calculate_contracts_state_root(const mxd_block_t *block, uint8_t root[64]) {
  if (!block || !root) {
    return -1;
  }

  // For blocks without smart contract transactions, use zero hash
  // Version 3+ blocks must include this field
  if (block->transaction_count == 0) {
    memset(root, 0, 64);
    return 0;
  }

  // Collect contract state hashes from all transactions
  // In a full implementation, this would:
  // 1. Deserialize each transaction
  // 2. Identify contract deployment/execution transactions
  // 3. Extract the resulting contract state hash
  // 4. Build a Merkle tree of all state hashes

  // For now, create a simplified implementation:
  // - Hash all transaction data together as a placeholder
  // - This will be replaced with proper Merkle trie integration

  // Create a temporary buffer to accumulate transaction hashes
  if (block->transaction_count > SIZE_MAX / 64) {
    return -1;
  }
  uint8_t *state_buffer = malloc(block->transaction_count * 64);
  if (!state_buffer) {
    return -1;
  }

  uint32_t contract_count = 0;

  // Extract state hashes from contract transactions
  for (uint32_t i = 0; i < block->transaction_count; i++) {
    // Check if transaction involves contracts
    // This is a placeholder - proper implementation would parse transaction type
    if (block->transactions[i].length > 0) {
      // Hash transaction data as placeholder for contract state
      if (mxd_sha512(block->transactions[i].data,
                     block->transactions[i].length,
                     state_buffer + (contract_count * 64)) != 0) {
        free(state_buffer);
        return -1;
      }
      contract_count++;
    }
  }

  if (contract_count == 0) {
    // No contract transactions
    memset(root, 0, 64);
    free(state_buffer);
    return 0;
  }

  if (contract_count == 1) {
    // Single contract state
    memcpy(root, state_buffer, 64);
    free(state_buffer);
    return 0;
  }

  // Build Merkle tree of contract states (similar to transaction merkle tree)
  uint8_t *current_level = state_buffer;
  uint32_t level_size = contract_count;

  while (level_size > 1) {
    uint32_t next_level_size = (level_size + 1) / 2;
    uint8_t *next_level = malloc(next_level_size * 64);
    if (!next_level) {
      free(current_level);
      return -1;
    }

    for (uint32_t i = 0; i < next_level_size; i++) {
      uint32_t left_idx = i * 2;
      uint32_t right_idx = left_idx + 1;

      uint8_t pair_buffer[128];
      memcpy(pair_buffer, current_level + (left_idx * 64), 64);

      if (right_idx < level_size) {
        memcpy(pair_buffer + 64, current_level + (right_idx * 64), 64);
      } else {
        // Duplicate left hash for odd number of nodes
        memcpy(pair_buffer + 64, current_level + (left_idx * 64), 64);
      }

      if (mxd_sha512(pair_buffer, 128, next_level + (i * 64)) != 0) {
        free(next_level);
        free(current_level);
        return -1;
      }
    }

    if (current_level != state_buffer) {
      free(current_level);
    }
    current_level = next_level;
    level_size = next_level_size;
  }

  // Copy root hash
  memcpy(root, current_level, 64);

  if (current_level != state_buffer) {
    free(current_level);
  }
  free(state_buffer);

  return 0;
}

// Calculate validator scores root for v4+ blocks
// root = SHA-512(serialized score entries sorted by address)
int mxd_calculate_validator_scores_root(const mxd_block_t *block, uint8_t root[64]) {
  if (!block || !root) {
    return -1;
  }

  if (block->validator_scores_count == 0 || !block->validator_scores) {
    memset(root, 0, 64);
    return 0;
  }

  // Serialize all entries.
  //   v4-v5 entry = 48 bytes: address[20] + stake[8] + bp[4] + bs[4] + latency[8] + bsj[4]
  //   v6 entry    = 60 bytes: address[32] + ...
  size_t addr_len   = (block->version >= 6) ? 32 : 20;
  size_t entry_size = (block->version >= 6) ? 60 : 48;
  size_t buf_size = (size_t)block->validator_scores_count * entry_size;
  uint8_t *buf = malloc(buf_size);
  if (!buf) {
    return -1;
  }

  uint8_t *ptr = buf;
  for (uint32_t i = 0; i < block->validator_scores_count; i++) {
    const mxd_validator_score_entry_t *e = &block->validator_scores[i];
    memcpy(ptr, e->validator_address, addr_len); ptr += addr_len;
    uint64_t stake_be = mxd_htonll(e->stake_amount);
    memcpy(ptr, &stake_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    uint32_t bp_be = htonl(e->blocks_proposed);
    memcpy(ptr, &bp_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    uint32_t bs_be = htonl(e->blocks_signed);
    memcpy(ptr, &bs_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    uint64_t lat_be = mxd_htonll(e->total_latency_ms);
    memcpy(ptr, &lat_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    uint32_t bsj_be = htonl(e->blocks_since_joined);
    memcpy(ptr, &bsj_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
  }

  int result = mxd_sha512(buf, buf_size, root);
  free(buf);
  return result;
}

// Freeze transaction set and calculate final merkle root
// MINOR FIX: Document block closing time enforcement
// NOTE: Blocks should close after 5 seconds if they contain transactions.
// This enforcement is currently handled at the node/application level rather than
// in this library function. The 5-second timeout should be implemented in the
// block proposal and validation logic in the node application.
int mxd_freeze_transaction_set(mxd_block_t *block) {
  if (!block) {
    return -1;
  }
  
  if (block->transaction_set_frozen) {
    return 0; // Already frozen
  }
  
  // Calculate merkle root over all transactions using a proper binary merkle tree
  // This enables SPV (Simplified Payment Verification) proofs
  if (block->transaction_count == 0) {
    // No transactions - use zero hash
    memset(block->merkle_root, 0, 64);
  } else if (block->transaction_count == 1) {
    // Single transaction - hash it directly
    if (mxd_sha512(block->transactions[0].data, block->transactions[0].length, block->merkle_root) != 0) {
      return -1;
    }
  } else {
    // Multiple transactions - build proper binary merkle tree for SPV support
    // Each level pairs adjacent hashes; odd nodes are duplicated
    
    // Calculate number of leaf nodes (round up to power of 2 for balanced tree)
    uint32_t leaf_count = block->transaction_count;
    
    // Allocate buffer for current level hashes
    uint8_t *current_level = malloc(leaf_count * 64);
    if (!current_level) {
      return -1;
    }
    
    // Hash each transaction to create leaf nodes
    for (uint32_t i = 0; i < leaf_count; i++) {
      if (mxd_sha512(block->transactions[i].data, block->transactions[i].length, 
                     current_level + (i * 64)) != 0) {
        free(current_level);
        return -1;
      }
    }
    
    // Build tree level by level until we reach the root
    uint32_t level_size = leaf_count;
    while (level_size > 1) {
      // Calculate next level size (ceiling division by 2)
      uint32_t next_level_size = (level_size + 1) / 2;
      uint8_t *next_level = malloc(next_level_size * 64);
      if (!next_level) {
        free(current_level);
        return -1;
      }
      
      // Pair adjacent hashes and hash them together
      for (uint32_t i = 0; i < next_level_size; i++) {
        uint32_t left_idx = i * 2;
        uint32_t right_idx = left_idx + 1;
        
        // Concatenate left and right hashes (duplicate left if odd)
        uint8_t pair_buffer[128];
        memcpy(pair_buffer, current_level + (left_idx * 64), 64);
        
        if (right_idx < level_size) {
          memcpy(pair_buffer + 64, current_level + (right_idx * 64), 64);
        } else {
          // Odd number of nodes - duplicate the last one
          memcpy(pair_buffer + 64, current_level + (left_idx * 64), 64);
        }
        
        // Hash the pair to create parent node
        if (mxd_sha512(pair_buffer, 128, next_level + (i * 64)) != 0) {
          free(current_level);
          free(next_level);
          return -1;
        }
      }
      
      free(current_level);
      current_level = next_level;
      level_size = next_level_size;
    }
    
    // Copy root hash
    memcpy(block->merkle_root, current_level, 64);
    free(current_level);
  }

  // Calculate contracts state root for v3+ blocks
  if (block->version >= 3) {
    if (mxd_calculate_contracts_state_root(block, block->contracts_state_root) != 0) {
      MXD_LOG_ERROR("blockchain", "Failed to calculate contracts state root during freeze");
      return -1;
    }
  }

  // Calculate validator scores root for v4+ blocks
  if (block->version >= 4) {
    if (mxd_calculate_validator_scores_root(block, block->validator_scores_root) != 0) {
      MXD_LOG_ERROR("blockchain", "Failed to calculate validator scores root during freeze");
      return -1;
    }
  }

  // Mark as frozen - merkle_root, contracts_state_root, and validator_scores_root are now immutable
  block->transaction_set_frozen = 1;
  return 0;
}

// Calculate total tip from frozen transaction set
mxd_amount_t mxd_calculate_total_tip_from_frozen_set(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  if (!block->transaction_set_frozen) {
    return 0;
  }
  
  mxd_amount_t total_tip = 0;

  for (uint32_t i = 0; i < block->transaction_count; i++) {
    mxd_amount_t tip = 0;
    if (mxd_peek_voluntary_tip_from_bytes(block->transactions[i].data, block->transactions[i].length, &tip) == 0) {
      // Saturate on overflow instead of wrapping
      if (total_tip > UINT64_MAX - tip) {
        return UINT64_MAX;
      }
      total_tip += tip;
    }
  }

  return total_tip;
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
  
  // Create buffer for digest calculation (v6: proposer_id widened to 32 bytes)
  size_t buffer_size = sizeof(uint32_t) + 64 + 64 + 32 + sizeof(uint32_t) + sizeof(uint32_t);
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

  memcpy(buffer + offset, block->proposer_id, 32);   // v6: addr32
  offset += 32;
  
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
int mxd_append_membership_entry(mxd_block_t *block, const uint8_t node_address[32],
                                uint8_t algo_id, const uint8_t *public_key, uint16_t public_key_length,
                                const uint8_t *signature, uint16_t signature_length,
                                uint64_t timestamp) {
  if (!block || !node_address || !public_key || !signature || signature_length == 0 || public_key_length == 0) {
    return -1;
  }

  // Allow membership entries to be added during block proposal (not just after freeze)
  // This enables dynamic validator admission in post-genesis blocks
  
  // Validate algo_id
  if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
    return -1; // Invalid algorithm ID
  }
  
  // Validate public_key_length matches algo_id
  size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
  if (public_key_length != expected_pubkey_len) {
    return -1; // Invalid public key length for algorithm
  }
  
  // Validate signature_length matches algo_id
  size_t expected_sig_len = mxd_sig_signature_len(algo_id);
  if (signature_length != expected_sig_len) {
    return -1; // Invalid signature length for algorithm
  }
  
  // Check for duplicate address
  if (block->rapid_membership_entries) {
    for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
      if (memcmp(block->rapid_membership_entries[i].node_address, node_address, 32) == 0) {   // v6: addr32
        return -1; // Duplicate entry
      }
    }
  }
  
  // Signature-verification dispatch by block height:
  //
  // - height == 0 (genesis): signatures were collected over a digest computed
  //   from an empty block at consensus time; current block now has coinbase
  //   txs (different merkle root), so re-verifying is impossible. The
  //   responses were already verified inbound, so accept here.
  //
  // - height > 0 (post-genesis, permissionless JOIN per Phase 1+4): the
  //   validator signed MXD-VAL-V1 canonical bytes
  //   (domain_tag || op_type=0x00=JOIN || addr32 || timestamp_be) — NOT a
  //   block digest. The proposer's mxd_validate_join_request already passed
  //   the same verify upstream; we redo it here so that peers applying the
  //   block on receipt re-derive the same authentication independently
  //   (otherwise they couldn't tell a forged membership entry from a real
  //   one). The membership digest path was a leftover from the genesis-only
  //   design and could never accept a JOIN-signed entry.
  if (block->height > 0) {
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN);
    off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x00; /* op_type = JOIN */
    memcpy(sign_data + off, node_address, 32);
    off += 32;
    uint64_t ts_be = mxd_htonll(timestamp);
    memcpy(sign_data + off, &ts_be, 8);

    if (mxd_sig_verify(algo_id, signature, signature_length,
                       sign_data, sizeof(sign_data), public_key) != 0) {
      return -1; // Invalid JOIN signature
    }
  }
  
  // Verify node_address matches derived address from public key
  uint8_t derived_addr[MXD_ADDR32_LEN];
  if (mxd_derive_address(algo_id, public_key, public_key_length, derived_addr) != 0) {
    return -1;
  }
  // v6: compare full 32-byte addr32 (membership entry node_address widened to addr32)
  if (memcmp(node_address, derived_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("blockchain", "Membership node_address doesn't match derived address");
    return -1;
  }

  // Verify stake requirement (1% of total supply)
  // Skip for genesis blocks (height == 0) - genesis validators create the initial supply
  if (block->height > 0 && block->total_supply > 0) {
    uint8_t addr32_stake[MXD_ADDR32_LEN];
    if (mxd_derive_address(algo_id, public_key, public_key_length, addr32_stake) != 0) {
      return -1; // Failed to derive address
    }
    mxd_amount_t balance = mxd_get_balance(addr32_stake);
    // Check if balance >= 0.10% of total supply (balance * 1000 >= total_supply)
    if (balance < block->total_supply / 1000) {
      return -1; // Insufficient stake
    }
  }
  // Genesis blocks skip stake check - validators are the founders of the network
  
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
  
  // Add entry with algo_id and public_key
  mxd_rapid_membership_entry_t *entry = &block->rapid_membership_entries[block->rapid_membership_count];
  memcpy(entry->node_address, node_address, 32);   // v6: addr32
  entry->timestamp = timestamp;
  entry->algo_id = algo_id;
  entry->public_key_length = public_key_length;
  memcpy(entry->public_key, public_key, public_key_length);
  entry->signature_length = signature_length;
  if (signature_length > MXD_SIGNATURE_MAX) {
    return -1; // Signature too large
  }
  memcpy(entry->signature, signature, signature_length);
  
  block->rapid_membership_count++;
  
  return 0;
}

// v8+: Append a peer-signed EVICT entry to the block. Verifies the
// evictor's signature against MXD-VAL-V1 EVICT canonical bytes (84 B):
//   "MXD-VAL-V1\0" || 0x02 || target_addr32(32) || evictor_addr32(32) ||
//   timestamp_be(8)
//
// The proposer-side admission checks (signer ∈ rapid_table, target ∈
// rapid_table, balance < threshold, grace period, floor) live in
// mxd_rsc.c's drain code. This helper handles ONLY the cryptographic
// authentication that runs on every node that applies the block —
// proposer at propose-time AND peer at finalize-time.
int mxd_append_eviction_entry(mxd_block_t *block,
                              const uint8_t target_addr[32],
                              const uint8_t evictor_addr[32],
                              uint8_t evictor_algo_id,
                              const uint8_t *evictor_public_key,
                              uint16_t evictor_public_key_length,
                              const uint8_t *signature,
                              uint16_t signature_length,
                              uint64_t timestamp) {
  if (!block || !target_addr || !evictor_addr || !evictor_public_key ||
      !signature || signature_length == 0 || evictor_public_key_length == 0) {
    return -1;
  }
  if (block->version < 8) {
    return -1; // EVICT entries are v8+
  }

  // Algo + length sanity
  if (evictor_algo_id != MXD_SIGALG_ED25519 && evictor_algo_id != MXD_SIGALG_DILITHIUM5) {
    return -1;
  }
  size_t expected_pk = mxd_sig_pubkey_len(evictor_algo_id);
  if (evictor_public_key_length != expected_pk) {
    return -1;
  }
  size_t expected_sig = mxd_sig_signature_len(evictor_algo_id);
  if (signature_length != expected_sig) {
    return -1;
  }

  // Duplicate guard: same (target_addr, evictor_addr) tuple appearing twice
  if (block->rapid_eviction_entries) {
    for (uint32_t i = 0; i < block->rapid_eviction_count; i++) {
      const mxd_rapid_eviction_entry_t *e = &block->rapid_eviction_entries[i];
      if (memcmp(e->target_addr, target_addr, 32) == 0 &&
          memcmp(e->evictor_addr, evictor_addr, 32) == 0) {
        return -1;
      }
    }
  }

  // Storage-path crypto verify against MXD-VAL-V1 EVICT canonical bytes
  uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 32 + 8];
  size_t off = 0;
  memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN);
  off += MXD_DOMAIN_TAG_VAL_LEN;
  sign_data[off++] = 0x02; /* op_type = EVICT */
  memcpy(sign_data + off, target_addr, 32);  off += 32;
  memcpy(sign_data + off, evictor_addr, 32); off += 32;
  uint64_t ts_be = mxd_htonll(timestamp);
  memcpy(sign_data + off, &ts_be, 8);

  if (mxd_sig_verify(evictor_algo_id, signature, signature_length,
                     sign_data, sizeof(sign_data), evictor_public_key) != 0) {
    return -1; // Invalid EVICT signature
  }

  // evictor_addr32 == SHA-512(algo_id || pubkey)[0..31]
  uint8_t derived_addr[MXD_ADDR32_LEN];
  if (mxd_derive_address(evictor_algo_id, evictor_public_key,
                          evictor_public_key_length, derived_addr) != 0) {
    return -1;
  }
  if (memcmp(evictor_addr, derived_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("blockchain", "EVICT evictor_addr doesn't match derived address");
    return -1;
  }

  // Grow the array if needed (bootstrap-from-0 pattern matches join pool fix)
  if (block->rapid_eviction_count >= block->rapid_eviction_capacity) {
    uint32_t new_capacity = block->rapid_eviction_capacity == 0
                                ? 4
                                : block->rapid_eviction_capacity * 2;
    mxd_rapid_eviction_entry_t *new_entries = realloc(block->rapid_eviction_entries,
                                                       new_capacity * sizeof(mxd_rapid_eviction_entry_t));
    if (!new_entries) {
      return -1;
    }
    block->rapid_eviction_entries = new_entries;
    block->rapid_eviction_capacity = new_capacity;
  }

  mxd_rapid_eviction_entry_t *entry =
      &block->rapid_eviction_entries[block->rapid_eviction_count];
  memcpy(entry->target_addr, target_addr, 32);
  memcpy(entry->evictor_addr, evictor_addr, 32);
  entry->timestamp = timestamp;
  entry->evictor_algo_id = evictor_algo_id;
  entry->evictor_public_key_length = evictor_public_key_length;
  memcpy(entry->evictor_public_key, evictor_public_key, evictor_public_key_length);
  entry->signature_length = signature_length;
  if (signature_length > MXD_SIGNATURE_MAX) {
    return -1;
  }
  memcpy(entry->signature, signature, signature_length);

  block->rapid_eviction_count++;
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

// Free all dynamically allocated memory in a block
void mxd_free_block(mxd_block_t *block) {
  if (!block) {
    return;
  }

  // Free transaction data buffers
  for (uint32_t i = 0; i < block->transaction_count; i++) {
    if (block->transactions[i].data) {
      free(block->transactions[i].data);
      block->transactions[i].data = NULL;
    }
    block->transactions[i].length = 0;
  }

  // Free transactions array
  if (block->transactions) {
    free(block->transactions);
    block->transactions = NULL;
  }
  block->transaction_count = 0;
  block->transaction_capacity = 0;

  // Reuse existing cleanup for validation chain + membership entries
  mxd_free_validation_chain(block);
}
