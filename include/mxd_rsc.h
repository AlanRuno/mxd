#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"

int mxd_get_validator_public_key(const uint8_t validator_id[20], uint8_t *out_key, size_t out_capacity, size_t *out_len);
int mxd_test_register_validator_pubkey(const uint8_t validator_id[20], const uint8_t *pub, size_t pub_len);
void mxd_test_clear_validator_pubkeys(void);

typedef struct {
    uint64_t avg_response_time;
    uint64_t min_response_time;
    uint64_t max_response_time;
    uint32_t response_count;
    double tip_share;
    uint64_t last_update;
} mxd_node_metrics_t;

typedef struct {
    char node_id[64];
    double stake_amount;
    uint8_t public_key[256];
    mxd_node_metrics_t metrics;
    uint32_t rank;
    uint8_t active;
    uint8_t in_rapid_table;
    uint32_t rapid_table_position;
} mxd_node_stake_t;

typedef struct {
    mxd_node_stake_t **nodes;
    size_t count;
    size_t capacity;
    uint64_t last_update;
} mxd_rapid_table_t;

typedef enum {
    MXD_VALIDATION_PENDING = 0,
    MXD_VALIDATION_IN_PROGRESS,
    MXD_VALIDATION_COMPLETE,
    MXD_VALIDATION_REJECTED,
    MXD_VALIDATION_EXPIRED
} mxd_validation_status_t;

typedef struct {
    uint32_t height;
    uint8_t block_hash[64];
    uint8_t proposer_id[20];
    mxd_validation_status_t status;
    uint32_t signature_count;
    uint32_t required_signatures;
    uint64_t start_time;
    uint64_t expiry_time;
} mxd_validation_context_t;

int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake);

int mxd_init_node_metrics(mxd_node_metrics_t *metrics);

int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp);

int mxd_calculate_node_rank(const mxd_node_stake_t *node, double total_stake);

int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, double total_tip);

int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, double total_stake);

int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats);

int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time);

int mxd_init_rapid_table(mxd_rapid_table_t *table, size_t capacity);

int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node);

int mxd_remove_from_rapid_table(mxd_rapid_table_t *table, const char *node_id);

mxd_node_stake_t *mxd_get_node_from_rapid_table(const mxd_rapid_table_t *table, const char *node_id);

void mxd_free_rapid_table(mxd_rapid_table_t *table);

int mxd_init_validation_context(mxd_validation_context_t *context, const mxd_block_t *block,
                               const mxd_rapid_table_t *table);

int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[20],
                                        uint64_t timestamp, const uint8_t *signature,
                                        uint16_t signature_length, uint32_t chain_position);

int mxd_verify_validation_chain_integrity(const mxd_block_t *block);

int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table);

int mxd_block_has_min_relay_signatures(const mxd_block_t *block);

int mxd_resolve_fork_by_validation(const mxd_block_t *block1, const mxd_block_t *block2,
                                  const mxd_rapid_table_t *table);

double mxd_calculate_validation_latency_score(const mxd_block_t *block, const mxd_rapid_table_t *table);

int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[20], uint32_t height,
                                           const uint8_t block_hash[64]);

int mxd_blacklist_validator(const uint8_t validator_id[20], uint32_t duration);

int mxd_is_validator_blacklisted(const uint8_t validator_id[20]);

int mxd_get_next_validator(const mxd_block_t *block, const mxd_rapid_table_t *table,
                          uint8_t next_validator_id[20]);

int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context,
                                const mxd_rapid_table_t *table);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H
