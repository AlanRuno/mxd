#ifndef MXD_BLOCKCHAIN_H
#define MXD_BLOCKCHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_types.h"

// MXD_SIGNATURE_MAX must accommodate ML-DSA-87 (FIPS 204) signatures (4627 bytes)
// for hybrid cryptography support (Ed25519 + ML-DSA-87). Updated Task 7.3 from 4595 (Round-3).
#define MXD_SIGNATURE_MAX 4627

typedef struct {
    uint8_t validator_id[32];   // v6: addr32 validator identity (was [20])
    uint64_t timestamp;
    uint8_t algo_id;
    uint16_t signature_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
    uint32_t chain_position;
} mxd_validator_signature_t;

typedef struct {
    uint8_t node_address[32];   // v6: addr32 (was [20]). Block-embedded.
    uint64_t timestamp;
    uint8_t algo_id;
    uint16_t public_key_length;
    uint8_t public_key[2592];  // Max size for Dilithium5
    uint16_t signature_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
} mxd_rapid_membership_entry_t;

// Transaction storage within block
typedef struct {
    uint8_t *data;
    size_t length;
} mxd_block_transaction_t;

// Per-validator cumulative scoring data embedded in blocks (v4+)
// v4-v5: 48 bytes per validator: address(20) + stake(8) + bp(4) + bs(4) + latency(8) + bsj(4)
// v6:    60 bytes per validator: address(32) + stake(8) + bp(4) + bs(4) + latency(8) + bsj(4)
typedef struct {
    uint8_t  validator_address[32];   // v6: addr32 (was [20])
    uint64_t stake_amount;            //  8 bytes - balance snapshot
    uint32_t blocks_proposed;         //  4 bytes - cumulative
    uint32_t blocks_signed;           //  4 bytes - cumulative
    uint64_t total_latency_ms;        //  8 bytes - cumulative signing latency
    uint32_t blocks_since_joined;     //  4 bytes - cumulative
} mxd_validator_score_entry_t;

typedef struct {
    uint32_t version;
    uint8_t prev_block_hash[64];
    uint8_t merkle_root[64];
    uint8_t contracts_state_root[64]; // SHA-512 of all contract states (v3+)
    uint64_t timestamp;           // Unix timestamp in seconds (was time_t)
    uint32_t difficulty;
    uint64_t nonce;
    uint8_t block_hash[64];
    uint8_t proposer_id[32];                 // v6: addr32 validator identity (was [20])
    uint32_t height;
    mxd_validator_signature_t *validation_chain;
    uint32_t validation_count;
    uint32_t validation_capacity;
    mxd_rapid_membership_entry_t *rapid_membership_entries;
    uint32_t rapid_membership_count;
    uint32_t rapid_membership_capacity;
    mxd_amount_t total_supply;   // Total supply in base units (was double)
    uint8_t validator_scores_root[64];            // SHA-512 of scoring data (v4+)
    mxd_validator_score_entry_t *validator_scores; // Per-validator cumulative scores (v4+)
    uint32_t validator_scores_count;
    uint32_t validator_scores_capacity;
    uint8_t next_proposer[32];              // v6: addr32 (was [20]). Proposer for the NEXT block.
    uint8_t transaction_set_frozen;
    mxd_block_transaction_t *transactions;
    uint32_t transaction_count;
    uint32_t transaction_capacity;
} mxd_block_t;

int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]);

int mxd_init_block_with_validation(mxd_block_t *block, const uint8_t prev_hash[64],
                                  const uint8_t proposer_id[32], uint32_t height);

int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length);

int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[32],
                                uint64_t timestamp, uint8_t algo_id, const uint8_t *signature, uint16_t signature_length);

int mxd_validate_block(const mxd_block_t *block);

int mxd_verify_validation_chain(const mxd_block_t *block);

int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]);

int mxd_calculate_contracts_state_root(const mxd_block_t *block, uint8_t root[64]);

int mxd_calculate_validator_scores_root(const mxd_block_t *block, uint8_t root[64]);

int mxd_calculate_membership_digest(const mxd_block_t *block, uint8_t digest[64]);

int mxd_append_membership_entry(mxd_block_t *block, const uint8_t node_address[32],
                                uint8_t algo_id, const uint8_t *public_key, uint16_t public_key_length,
                                const uint8_t *signature, uint16_t signature_length,
                                uint64_t timestamp);

int mxd_block_has_membership_quorum(const mxd_block_t *block, size_t rapid_table_size);

int mxd_block_is_presigned(const mxd_block_t *block);

int mxd_block_is_ready(const mxd_block_t *block, size_t rapid_table_size);

int mxd_block_is_finalized(const mxd_block_t *block);

int mxd_freeze_transaction_set(mxd_block_t *block);

mxd_amount_t mxd_calculate_total_tip_from_frozen_set(const mxd_block_t *block);

int mxd_block_has_quorum(const mxd_block_t *block);

int mxd_block_has_min_signatures(const mxd_block_t *block);

int mxd_resolve_fork(const mxd_block_t *block1, const mxd_block_t *block2);

double mxd_calculate_latency_score(const mxd_block_t *block);  // Returns score, not amount

void mxd_free_validation_chain(mxd_block_t *block);

void mxd_free_block(mxd_block_t *block);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_H
