#ifndef MXD_BLOCKCHAIN_H
#define MXD_BLOCKCHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef MXD_PQC_DILITHIUM
#define MXD_SIGNATURE_MAX 3400
#else
#define MXD_SIGNATURE_MAX 128
#endif

typedef struct {
    uint8_t validator_id[20];
    uint64_t timestamp;
    uint16_t signature_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
    uint32_t chain_position;
} mxd_validator_signature_t;

typedef struct {
    uint8_t node_address[20];
    uint64_t timestamp;
    uint16_t signature_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
} mxd_rapid_membership_entry_t;

typedef struct {
    uint32_t version;
    uint8_t prev_block_hash[64];
    uint8_t merkle_root[64];
    time_t timestamp;
    uint32_t difficulty;
    uint64_t nonce;
    uint8_t block_hash[64];
    uint8_t proposer_id[20];
    uint32_t height;
    mxd_validator_signature_t *validation_chain;
    uint32_t validation_count;
    uint32_t validation_capacity;
    mxd_rapid_membership_entry_t *rapid_membership_entries;
    uint32_t rapid_membership_count;
    uint32_t rapid_membership_capacity;
    double total_supply;
    uint8_t transaction_set_frozen;
} mxd_block_t;

int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]);

int mxd_init_block_with_validation(mxd_block_t *block, const uint8_t prev_hash[64],
                                  const uint8_t proposer_id[20], uint32_t height);

int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length);

int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[20],
                                uint64_t timestamp, const uint8_t *signature, uint16_t signature_length);

int mxd_validate_block(const mxd_block_t *block);

int mxd_verify_validation_chain(const mxd_block_t *block);

int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]);

int mxd_calculate_membership_digest(const mxd_block_t *block, uint8_t digest[64]);

int mxd_append_membership_entry(mxd_block_t *block, const uint8_t node_address[20],
                                const uint8_t *signature, uint16_t signature_length,
                                uint64_t timestamp);

int mxd_block_has_membership_quorum(const mxd_block_t *block, size_t rapid_table_size);

int mxd_block_is_presigned(const mxd_block_t *block);

int mxd_block_is_ready(const mxd_block_t *block, size_t rapid_table_size);

int mxd_block_is_finalized(const mxd_block_t *block);

int mxd_freeze_transaction_set(mxd_block_t *block);

int mxd_block_has_quorum(const mxd_block_t *block);

int mxd_block_has_min_signatures(const mxd_block_t *block);

int mxd_resolve_fork(const mxd_block_t *block1, const mxd_block_t *block2);

double mxd_calculate_latency_score(const mxd_block_t *block);

void mxd_free_validation_chain(mxd_block_t *block);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_H
