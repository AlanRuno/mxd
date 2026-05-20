#ifndef MXD_CHECKPOINTS_H
#define MXD_CHECKPOINTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Maximum checkpoint interval (in blocks)
#define MXD_MAX_CHECKPOINT_INTERVAL 10000

// Checkpoint state
typedef struct {
  uint8_t state_hash[64]; // SHA-512 hash of state
  uint64_t block_height;  // Block height of checkpoint
  uint64_t timestamp;     // Timestamp of checkpoint
  uint8_t prev_hash[64];  // Previous checkpoint hash
  uint8_t mmr_root[64];   // Merkle Mountain Range root
} mxd_checkpoint_t;

// Checkpoint manager
typedef struct {
  mxd_checkpoint_t *checkpoints; // Array of checkpoints
  size_t count;                  // Number of checkpoints
  size_t capacity;               // Capacity of checkpoints array
  uint64_t last_height;          // Last checkpoint height
} mxd_checkpoint_manager_t;

// Initialize checkpoint manager
int mxd_init_checkpoints(mxd_checkpoint_manager_t *manager,
                         size_t initial_capacity);

// Create a new checkpoint
int mxd_create_checkpoint(mxd_checkpoint_manager_t *manager,
                          const uint8_t *state_data, size_t state_size,
                          uint64_t block_height, uint64_t timestamp);

// Validate checkpoint state transition
int mxd_validate_checkpoint(const mxd_checkpoint_manager_t *manager,
                            const mxd_checkpoint_t *checkpoint);

// Prune old checkpoints
int mxd_prune_checkpoints(mxd_checkpoint_manager_t *manager,
                          uint64_t min_height);

// Recover state from checkpoint
int mxd_recover_from_checkpoint(const mxd_checkpoint_manager_t *manager,
                                uint64_t target_height, uint8_t *state_data,
                                size_t *state_size);

// Free checkpoint manager resources
void mxd_free_checkpoints(mxd_checkpoint_manager_t *manager);

#ifdef __cplusplus
}
#endif

#endif // MXD_CHECKPOINTS_H
