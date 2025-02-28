#ifndef MXD_BLOCKCHAIN_H
#define MXD_BLOCKCHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>

// Block structure
typedef struct {
  uint32_t version;
  uint8_t prev_block_hash[64];
  uint8_t merkle_root[64];
  time_t timestamp;
  uint32_t difficulty;
  uint64_t nonce;
  uint8_t block_hash[64];
} mxd_block_t;

// Initialize a new block
int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]);

// Add transaction to block
int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length);

// Validate block structure and contents
int mxd_validate_block(const mxd_block_t *block);

// Calculate block hash
int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_H
