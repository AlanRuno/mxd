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

int mxd_store_signature(uint32_t height, const uint8_t validator_id[20], const uint8_t *signature, uint16_t signature_length);

int mxd_signature_exists(uint32_t height, const uint8_t validator_id[20], const uint8_t *signature, uint16_t signature_length);

int mxd_prune_expired_signatures(uint32_t current_height);

int mxd_get_signatures_by_height(uint32_t height, mxd_validator_signature_t **signatures, size_t *signature_count);

int mxd_get_signatures_by_validator(const uint8_t validator_id[20], mxd_validator_signature_t **signatures,
                                   uint32_t **heights, size_t *signature_count);

double mxd_calculate_block_latency_score(const mxd_block_t *block);

int mxd_flush_blockchain_db(void);

int mxd_compact_blockchain_db(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_DB_H
