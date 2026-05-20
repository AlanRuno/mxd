#include "../../include/mxd_checkpoints.h"
#include "../../include/mxd_crypto.h"
#include <stdlib.h>
#include <string.h>

// Initialize checkpoint manager
int mxd_init_checkpoints(mxd_checkpoint_manager_t *manager,
                         size_t initial_capacity) {
  if (!manager || initial_capacity == 0) {
    return -1;
  }

  manager->checkpoints = calloc(initial_capacity, sizeof(mxd_checkpoint_t));
  if (!manager->checkpoints) {
    return -1;
  }

  manager->count = 0;
  manager->capacity = initial_capacity;
  manager->last_height = 0;

  return 0;
}

// Create a new checkpoint
int mxd_create_checkpoint(mxd_checkpoint_manager_t *manager,
                          const uint8_t *state_data, size_t state_size,
                          uint64_t block_height, uint64_t timestamp) {
  if (!manager || !state_data || state_size == 0 ||
      block_height <= manager->last_height) {
    return -1;
  }

  // Ensure capacity
  if (manager->count >= manager->capacity) {
    size_t new_capacity = manager->capacity * 2;
    mxd_checkpoint_t *new_checkpoints =
        realloc(manager->checkpoints, new_capacity * sizeof(mxd_checkpoint_t));
    if (!new_checkpoints) {
      return -1;
    }
    manager->checkpoints = new_checkpoints;
    manager->capacity = new_capacity;
  }

  // Create new checkpoint
  mxd_checkpoint_t *checkpoint = &manager->checkpoints[manager->count];

  // Calculate state hash
  mxd_sha512(state_data, state_size, checkpoint->state_hash);

  checkpoint->block_height = block_height;
  checkpoint->timestamp = timestamp;

  // Set previous checkpoint hash
  if (manager->count > 0) {
    memcpy(checkpoint->prev_hash,
           manager->checkpoints[manager->count - 1].state_hash, 64);
  } else {
    memset(checkpoint->prev_hash, 0, 64);
  }

  // Calculate MMR root (simplified for now)
  mxd_sha512(checkpoint->state_hash, 64, checkpoint->mmr_root);

  manager->count++;
  manager->last_height = block_height;

  return 0;
}

// Validate checkpoint state transition
int mxd_validate_checkpoint(const mxd_checkpoint_manager_t *manager,
                            const mxd_checkpoint_t *checkpoint) {
  if (!manager || !checkpoint || manager->count == 0) {
    return -1;
  }

  // Validate block height
  if (checkpoint->block_height <= manager->last_height) {
    return -1;
  }

  // Validate previous hash
  const mxd_checkpoint_t *last_checkpoint =
      &manager->checkpoints[manager->count - 1];
  if (memcmp(checkpoint->prev_hash, last_checkpoint->state_hash, 64) != 0) {
    return -1;
  }

  // Validate MMR root (simplified for now)
  uint8_t computed_root[64];
  mxd_sha512(checkpoint->state_hash, 64, computed_root);
  if (memcmp(computed_root, checkpoint->mmr_root, 64) != 0) {
    return -1;
  }

  return 0;
}

// Prune old checkpoints
int mxd_prune_checkpoints(mxd_checkpoint_manager_t *manager,
                          uint64_t min_height) {
  if (!manager || manager->count == 0 || min_height == 0) {
    return -1;
  }

  // Find first checkpoint to keep
  size_t keep_index = 0;
  while (keep_index < manager->count &&
         manager->checkpoints[keep_index].block_height < min_height) {
    keep_index++;
  }

  if (keep_index == 0) {
    return 0; // Nothing to prune
  }

  // Move remaining checkpoints to start of array
  size_t remaining = manager->count - keep_index;
  if (remaining > 0) {
    memmove(manager->checkpoints, &manager->checkpoints[keep_index],
            remaining * sizeof(mxd_checkpoint_t));
  }

  manager->count = remaining;
  return 0;
}

// Recover state from checkpoint
int mxd_recover_from_checkpoint(const mxd_checkpoint_manager_t *manager,
                                uint64_t target_height, uint8_t *state_data,
                                size_t *state_size) {
  if (!manager || !state_data || !state_size || manager->count == 0) {
    return -1;
  }

  // Find closest checkpoint before target height
  size_t checkpoint_index = manager->count - 1;
  while (checkpoint_index > 0 &&
         manager->checkpoints[checkpoint_index].block_height > target_height) {
    checkpoint_index--;
  }

  const mxd_checkpoint_t *checkpoint = &manager->checkpoints[checkpoint_index];

  // For now, we just copy the state hash as the recovered state
  // In a real implementation, we would need to replay transactions
  if (*state_size < 64) {
    return -1;
  }
  memcpy(state_data, checkpoint->state_hash, 64);
  *state_size = 64;

  return 0;
}

// Free checkpoint manager resources
void mxd_free_checkpoints(mxd_checkpoint_manager_t *manager) {
  if (manager) {
    free(manager->checkpoints);
    memset(manager, 0, sizeof(mxd_checkpoint_manager_t));
  }
}
