#ifndef MXD_BLOCKCHAIN_SYNC_H
#define MXD_BLOCKCHAIN_SYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"
#include "mxd_rsc.h"

int mxd_sync_blockchain(void);

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block);

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height);

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]);

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64],
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count);

int mxd_verify_and_add_validation_signature(mxd_block_t *block,
                                           const uint8_t validator_id[20],
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp);

int mxd_check_block_relay_status(const uint8_t block_hash[64]);

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id);

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64],
                                        const uint8_t block_hash2[64]);

int mxd_prune_expired_validation_chains(uint32_t current_height);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_SYNC_H
