#ifndef MXD_BLOCKCHAIN_DB_H
#define MXD_BLOCKCHAIN_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include <stdint.h>

int mxd_init_blockchain_db(const char *db_path);

int mxd_close_blockchain_db(void);

int mxd_store_block(const mxd_block_t *block);

int mxd_retrieve_block_by_height(uint32_t height, mxd_block_t *block);

int mxd_retrieve_block_by_hash(const uint8_t hash[64], mxd_block_t *block);

int mxd_get_blockchain_height(uint32_t *height);
int mxd_get_latest_stored_height(uint32_t *height);  // Highest block stored (may have gaps)

int mxd_store_signature(uint32_t height, const uint8_t validator_id[32], const uint8_t *signature, uint16_t signature_length);

int mxd_signature_exists(uint32_t height, const uint8_t validator_id[32], const uint8_t *signature, uint16_t signature_length);

int mxd_prune_expired_signatures(uint32_t current_height);

int mxd_get_signatures_by_height(uint32_t height, mxd_validator_signature_t **signatures, size_t *signature_count);

int mxd_get_signatures_by_validator(const uint8_t validator_id[32], mxd_validator_signature_t **signatures,
                                   uint32_t **heights, size_t *signature_count);

double mxd_calculate_block_latency_score(const mxd_block_t *block);

int mxd_flush_blockchain_db(void);

int mxd_compact_blockchain_db(void);

int mxd_store_validator_metadata(const uint8_t validator_id[32], uint8_t algo_id,
                                  const uint8_t *public_key, size_t pubkey_len);

int mxd_retrieve_validator_metadata(const uint8_t validator_id[32], uint8_t *out_algo_id,
                                     uint8_t *out_public_key, size_t out_capacity, size_t *out_len);

int mxd_load_all_validator_metadata(void);

const char *mxd_get_blockchain_db_path(void);
int mxd_broadcast_block(const mxd_block_t *block);

int mxd_deserialize_block_from_network(const uint8_t *data, size_t data_len, mxd_block_t *block);

int mxd_serialize_block_for_network(const mxd_block_t *block, uint8_t **data, size_t *data_len);

int mxd_block_exists_at_height(uint32_t height);

int mxd_fill_block_gaps(uint32_t *gaps, uint32_t max_gaps, uint32_t *gap_count);

// Advance current_height through any contiguous blocks already in the DB.
// Call before sync to avoid re-requesting blocks we already have.
void mxd_advance_height_pointer(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_DB_H
