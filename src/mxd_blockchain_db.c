#include "mxd_logging.h"

#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/blockchain/mxd_rsc.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_fork_choice.h"
#include "../include/mxd_block_delta.h"
#include "../include/mxd_mempool.h"
#include "../include/mxd_transaction.h"
#include <rocksdb/c.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "../include/mxd_error.h"

/* v7.1: forward declaration. Implemented further down — extracts the UTXO
 * delta from the block's tx data without consulting the UTXO state. */
static int extract_block_delta(const mxd_block_t *block, mxd_block_delta_t *out);

/* v7.1: forward declaration of reorg machinery. Both handle_block_at_existing
 * and reorg_to_candidate live below mxd_store_block, but mxd_store_block
 * needs to call them. */
static int handle_block_at_existing_height(const mxd_block_t *new_block);
static int reorg_to_candidate(const mxd_block_t *candidate);

static rocksdb_options_t *options = NULL;
static char *db_path_global = NULL;

static uint32_t current_height = 0;
static uint32_t latest_stored_height = 0;  // Highest block ever stored (may have gaps below)
static pthread_mutex_t height_mutex = PTHREAD_MUTEX_INITIALIZER;

// BLOCKER FIX: Serialize validator signature with proper endian conversion
// v6: validator_id widened to 32 bytes (addr32)
static void serialize_validator_signature(const mxd_validator_signature_t *sig, uint8_t **ptr) {
    memcpy(*ptr, sig->validator_id, 32); *ptr += 32;
    uint64_t ts_be = mxd_htonll(sig->timestamp);
    memcpy(*ptr, &ts_be, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    memcpy(*ptr, &sig->algo_id, 1); *ptr += 1;
    uint16_t sig_len_be = htons(sig->signature_length);
    memcpy(*ptr, &sig_len_be, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    memcpy(*ptr, sig->signature, sig->signature_length); *ptr += sig->signature_length;
    uint32_t pos_be = htonl(sig->chain_position);
    memcpy(*ptr, &pos_be, sizeof(uint32_t)); *ptr += sizeof(uint32_t);
}

// BLOCKER FIX: Serialize membership entry with proper endian conversion
// v6: node_address widened to 32 bytes (addr32). Block-format change.
static void serialize_membership_entry(const mxd_rapid_membership_entry_t *entry, uint8_t **ptr) {
    memcpy(*ptr, entry->node_address, 32); *ptr += 32;
    uint64_t ts_be = mxd_htonll(entry->timestamp);
    memcpy(*ptr, &ts_be, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    memcpy(*ptr, &entry->algo_id, 1); *ptr += 1;
    uint16_t pk_len_be = htons(entry->public_key_length);
    memcpy(*ptr, &pk_len_be, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    memcpy(*ptr, entry->public_key, entry->public_key_length); *ptr += entry->public_key_length;
    uint16_t sig_len_be = htons(entry->signature_length);
    memcpy(*ptr, &sig_len_be, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    memcpy(*ptr, entry->signature, entry->signature_length); *ptr += entry->signature_length;
}

// v8+ eviction-entry serialize/deserialize. Layout mirrors membership but
// adds the target_addr separate from evictor_addr — the entry binds an
// evictor's signed assertion ("validator X should leave") to the target
// validator being removed. See mxd_blockchain.h::mxd_rapid_eviction_entry_t
// and MXD-CONS-01 v1.2.x §4.x (forthcoming).
static void serialize_eviction_entry(const mxd_rapid_eviction_entry_t *entry, uint8_t **ptr) {
    memcpy(*ptr, entry->target_addr, 32);  *ptr += 32;
    memcpy(*ptr, entry->evictor_addr, 32); *ptr += 32;
    uint64_t ts_be = mxd_htonll(entry->timestamp);
    memcpy(*ptr, &ts_be, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    memcpy(*ptr, &entry->evictor_algo_id, 1); *ptr += 1;
    uint16_t pk_len_be = htons(entry->evictor_public_key_length);
    memcpy(*ptr, &pk_len_be, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    memcpy(*ptr, entry->evictor_public_key, entry->evictor_public_key_length);
    *ptr += entry->evictor_public_key_length;
    uint16_t sig_len_be = htons(entry->signature_length);
    memcpy(*ptr, &sig_len_be, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    memcpy(*ptr, entry->signature, entry->signature_length); *ptr += entry->signature_length;
}

static int deserialize_eviction_entry(mxd_rapid_eviction_entry_t *entry,
                                       const uint8_t **ptr, const uint8_t *end) {
    if (*ptr + 32 + 32 + 8 + 1 + 2 > end) return -1;
    memcpy(entry->target_addr, *ptr, 32);  *ptr += 32;
    memcpy(entry->evictor_addr, *ptr, 32); *ptr += 32;
    uint64_t ts_be;
    memcpy(&ts_be, *ptr, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    entry->timestamp = mxd_ntohll(ts_be);
    memcpy(&entry->evictor_algo_id, *ptr, 1); *ptr += 1;
    uint16_t pk_len_be;
    memcpy(&pk_len_be, *ptr, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    entry->evictor_public_key_length = ntohs(pk_len_be);
    if (entry->evictor_public_key_length > 2592) return -1;
    if (*ptr + entry->evictor_public_key_length + 2 > end) return -1;
    memcpy(entry->evictor_public_key, *ptr, entry->evictor_public_key_length);
    *ptr += entry->evictor_public_key_length;
    uint16_t sig_len_be;
    memcpy(&sig_len_be, *ptr, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    entry->signature_length = ntohs(sig_len_be);
    if (entry->signature_length > MXD_SIGNATURE_MAX) return -1;
    if (*ptr + entry->signature_length > end) return -1;
    memcpy(entry->signature, *ptr, entry->signature_length); *ptr += entry->signature_length;
    return 0;
}

static int serialize_block(const mxd_block_t *block, uint8_t **data, size_t *data_len) {
    if (!block || !data || !data_len) {
        return -1;
    }

    size_t size = 0;
    
    size += sizeof(uint32_t);  // version
    size += 64;                // prev_block_hash
    size += 64;                // merkle_root
    size += sizeof(uint64_t);  // timestamp (fixed-size uint64_t)
    size += sizeof(uint32_t);  // difficulty
    size += sizeof(uint64_t);  // nonce
    size += 64;                // block_hash
    size += 32;                // proposer_id (v6: addr32, was 20)
    size += sizeof(uint32_t);  // height
    size += sizeof(uint32_t);  // validation_count
    size += sizeof(uint32_t);  // rapid_membership_count
    size += sizeof(uint64_t);  // total_supply (fixed to uint64_t)
    if (block->version >= 3) {
        size += 64;            // contracts_state_root (v3+)
    }
    if (block->version >= 4) {
        size += 64;            // validator_scores_root (v4+)
    }
    size += sizeof(uint8_t);   // transaction_set_frozen
    
    // BLOCKER FIX: Calculate size with field-by-field serialization
    // v6: validator_id widened to 32 bytes (addr32)
    if (block->validation_count > 0 && block->validation_chain) {
        for (uint32_t i = 0; i < block->validation_count; i++) {
            size += 32 + 8 + 1 + 2 + block->validation_chain[i].signature_length + 4;
        }
    }

    // v6: node_address in rapid_membership_entries widened to 32 bytes (addr32).
    if (block->rapid_membership_count > 0 && block->rapid_membership_entries) {
        for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
            size += 32 + 8 + 1 + 2 + block->rapid_membership_entries[i].public_key_length +
                    2 + block->rapid_membership_entries[i].signature_length;
        }
    }

    // v8+: rapid_eviction_count u32 + per-entry size. Entry layout:
    //   target_addr(32) + evictor_addr(32) + timestamp(8) + algo_id(1) +
    //   pk_len(2) + pk(N) + sig_len(2) + sig(M)
    if (block->version >= 8) {
        size += sizeof(uint32_t);  // rapid_eviction_count
        if (block->rapid_eviction_count > 0 && block->rapid_eviction_entries) {
            for (uint32_t i = 0; i < block->rapid_eviction_count; i++) {
                size += 32 + 32 + 8 + 1 + 2 +
                        block->rapid_eviction_entries[i].evictor_public_key_length +
                        2 + block->rapid_eviction_entries[i].signature_length;
            }
        }
    }

    // Add validator scores size (v4+):
    //   count(4) + N entries
    //   v4-v5 entry = 48 bytes: address(20) + stake(8) + bp(4) + bs(4) + latency(8) + bsj(4)
    //   v6 entry    = 60 bytes: address(32) + stake(8) + bp(4) + bs(4) + latency(8) + bsj(4)
    if (block->version >= 4) {
        size += sizeof(uint32_t);  // validator_scores_count
        if (block->validator_scores_count > 0 && block->validator_scores) {
            size_t entry_size = (block->version >= 6) ? 60 : 48;
            size += block->validator_scores_count * entry_size;
        }
    }

    // v5+: next_proposer. v5 = 20 bytes, v6 = 32 bytes (addr32).
    if (block->version >= 6) {
        size += 32;
    } else if (block->version >= 5) {
        size += 20;
    }

    // Add transaction count and transaction data sizes
    size += sizeof(uint32_t);  // transaction_count
    if (block->transaction_count > 0 && block->transactions) {
        for (uint32_t i = 0; i < block->transaction_count; i++) {
            size += sizeof(uint32_t);  // transaction length
            size += block->transactions[i].length;  // transaction data
        }
    }

    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    uint8_t *ptr = *data;
    
    // Serialize with big-endian byte order for cross-platform compatibility
    uint32_t version_be = htonl(block->version);
    memcpy(ptr, &version_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    memcpy(ptr, block->prev_block_hash, 64); ptr += 64;
    memcpy(ptr, block->merkle_root, 64); ptr += 64;
    
    uint64_t timestamp_be = mxd_htonll(block->timestamp);
    memcpy(ptr, &timestamp_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    
    uint32_t difficulty_be = htonl(block->difficulty);
    memcpy(ptr, &difficulty_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    uint64_t nonce_be = mxd_htonll(block->nonce);
    memcpy(ptr, &nonce_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    
    memcpy(ptr, block->block_hash, 64); ptr += 64;
    memcpy(ptr, block->proposer_id, 32); ptr += 32;   // v6: addr32 (was 20)
    
    uint32_t height_be = htonl(block->height);
    memcpy(ptr, &height_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    uint32_t validation_count_be = htonl(block->validation_count);
    memcpy(ptr, &validation_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    uint32_t membership_count_be = htonl(block->rapid_membership_count);
    memcpy(ptr, &membership_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    uint64_t total_supply_be = mxd_htonll(block->total_supply);
    memcpy(ptr, &total_supply_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    if (block->version >= 3) {
        memcpy(ptr, block->contracts_state_root, 64); ptr += 64;
    }
    if (block->version >= 4) {
        memcpy(ptr, block->validator_scores_root, 64); ptr += 64;
    }

    memcpy(ptr, &block->transaction_set_frozen, sizeof(uint8_t)); ptr += sizeof(uint8_t);
    
    // BLOCKER FIX: Serialize validation chain with field-by-field endian conversion
    if (block->validation_count > 0 && block->validation_chain) {
        for (uint32_t i = 0; i < block->validation_count; i++) {
            serialize_validator_signature(&block->validation_chain[i], &ptr);
        }
    }
    
    // BLOCKER FIX: Serialize membership entries with field-by-field endian conversion
    if (block->rapid_membership_count > 0 && block->rapid_membership_entries) {
        for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
            serialize_membership_entry(&block->rapid_membership_entries[i], &ptr);
        }
    }

    // v8+: rapid eviction count + entries
    if (block->version >= 8) {
        uint32_t evict_count_be = htonl(block->rapid_eviction_count);
        memcpy(ptr, &evict_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        if (block->rapid_eviction_count > 0 && block->rapid_eviction_entries) {
            for (uint32_t i = 0; i < block->rapid_eviction_count; i++) {
                serialize_eviction_entry(&block->rapid_eviction_entries[i], &ptr);
            }
        }
    }

    // Serialize validator scores (v4+)
    if (block->version >= 4) {
        uint32_t vs_count_be = htonl(block->validator_scores_count);
        memcpy(ptr, &vs_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        if (block->validator_scores_count > 0 && block->validator_scores) {
            // v6: validator_address widened to 32 bytes (entry size 48 -> 60).
            size_t addr_len = (block->version >= 6) ? 32 : 20;
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
        }
    }

    // v5+: next_proposer. v5 = 20 bytes, v6 = 32 bytes (addr32).
    if (block->version >= 6) {
        memcpy(ptr, block->next_proposer, 32);
        ptr += 32;
    } else if (block->version >= 5) {
        memcpy(ptr, block->next_proposer, 20);
        ptr += 20;
    }

    // Serialize transactions
    uint32_t tx_count_be = htonl(block->transaction_count);
    memcpy(ptr, &tx_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);

    if (block->transaction_count > 0 && block->transactions) {
        for (uint32_t i = 0; i < block->transaction_count; i++) {
            uint32_t tx_len_be = htonl((uint32_t)block->transactions[i].length);
            memcpy(ptr, &tx_len_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
            if (block->transactions[i].data && block->transactions[i].length > 0) {
                memcpy(ptr, block->transactions[i].data, block->transactions[i].length);
                ptr += block->transactions[i].length;
            }
        }
    }

    *data_len = size;
    return 0;
}

// BLOCKER FIX: Deserialize validator signature with proper endian conversion
// v6: validator_id widened to 32 bytes (addr32)
static int deserialize_validator_signature(mxd_validator_signature_t *sig, const uint8_t **ptr, const uint8_t *end) {
    if (*ptr + 32 + 8 + 1 + 2 > end) return -1;
    memcpy(sig->validator_id, *ptr, 32); *ptr += 32;
    uint64_t ts_be;
    memcpy(&ts_be, *ptr, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    sig->timestamp = mxd_ntohll(ts_be);
    memcpy(&sig->algo_id, *ptr, 1); *ptr += 1;
    uint16_t sig_len_be;
    memcpy(&sig_len_be, *ptr, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    sig->signature_length = ntohs(sig_len_be);
    if (sig->signature_length > MXD_SIGNATURE_MAX) return -1;  // Signature too large for fixed buffer
    if (*ptr + sig->signature_length + 4 > end) return -1;
    memcpy(sig->signature, *ptr, sig->signature_length); *ptr += sig->signature_length;
    uint32_t pos_be;
    memcpy(&pos_be, *ptr, sizeof(uint32_t)); *ptr += sizeof(uint32_t);
    sig->chain_position = ntohl(pos_be);
    return 0;
}

// BLOCKER FIX: Deserialize membership entry with proper endian conversion
// v6: node_address widened to 32 bytes (addr32). Block-format change.
static int deserialize_membership_entry(mxd_rapid_membership_entry_t *entry, const uint8_t **ptr, const uint8_t *end) {
    if (*ptr + 32 + 8 + 1 + 2 > end) return -1;
    memcpy(entry->node_address, *ptr, 32); *ptr += 32;
    uint64_t ts_be;
    memcpy(&ts_be, *ptr, sizeof(uint64_t)); *ptr += sizeof(uint64_t);
    entry->timestamp = mxd_ntohll(ts_be);
    memcpy(&entry->algo_id, *ptr, 1); *ptr += 1;
    uint16_t pk_len_be;
    memcpy(&pk_len_be, *ptr, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    entry->public_key_length = ntohs(pk_len_be);
    if (entry->public_key_length > 2592) return -1;  // Public key too large for fixed buffer (max Dilithium5 size)
    if (*ptr + entry->public_key_length + 2 > end) return -1;
    memcpy(entry->public_key, *ptr, entry->public_key_length); *ptr += entry->public_key_length;
    uint16_t sig_len_be;
    memcpy(&sig_len_be, *ptr, sizeof(uint16_t)); *ptr += sizeof(uint16_t);
    entry->signature_length = ntohs(sig_len_be);
    if (entry->signature_length > MXD_SIGNATURE_MAX) return -1;  // Signature too large for fixed buffer
    if (*ptr + entry->signature_length > end) return -1;
    memcpy(entry->signature, *ptr, entry->signature_length); *ptr += entry->signature_length;
    return 0;
}

static int deserialize_block(const uint8_t *data, size_t data_len, mxd_block_t *block) {
    if (!data || !block) {
        return -1;
    }

    // v6: proposer_id widened to 32 bytes (addr32). min_size grows by 12.
    size_t min_size = sizeof(uint32_t) + 64 + 64 + sizeof(uint64_t) + sizeof(uint32_t) +
                      sizeof(uint64_t) + 64 + 32 + sizeof(uint32_t) + sizeof(uint32_t) +
                      sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint8_t);
    
    if (data_len < min_size) {
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;
    
    // Deserialize with big-endian byte order conversion
    uint32_t version_be;
    memcpy(&version_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    block->version = ntohl(version_be);
    
    memcpy(block->prev_block_hash, ptr, 64); ptr += 64;
    memcpy(block->merkle_root, ptr, 64); ptr += 64;
    
    uint64_t timestamp_be;
    memcpy(&timestamp_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    block->timestamp = mxd_ntohll(timestamp_be);
    
    uint32_t difficulty_be;
    memcpy(&difficulty_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    block->difficulty = ntohl(difficulty_be);
    
    uint64_t nonce_be;
    memcpy(&nonce_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    block->nonce = mxd_ntohll(nonce_be);
    
    memcpy(block->block_hash, ptr, 64); ptr += 64;
    memcpy(block->proposer_id, ptr, 32); ptr += 32;   // v6: addr32 (was 20)
    
    uint32_t height_be;
    memcpy(&height_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    block->height = ntohl(height_be);
    
    uint32_t validation_count_be;
    memcpy(&validation_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    block->validation_count = ntohl(validation_count_be);
    if (block->validation_count > 1000) {
        return -1;
    }

    uint32_t membership_count_be;
    memcpy(&membership_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    block->rapid_membership_count = ntohl(membership_count_be);
    if (block->rapid_membership_count > 1000) {
        return -1;
    }
    
    uint64_t total_supply_be;
    memcpy(&total_supply_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    block->total_supply = mxd_ntohll(total_supply_be);

    memset(block->contracts_state_root, 0, 64);
    if (block->version >= 3) {
        if (ptr + 64 > end) return -1;
        memcpy(block->contracts_state_root, ptr, 64); ptr += 64;
    }

    block->validator_scores = NULL;
    block->validator_scores_count = 0;
    block->validator_scores_capacity = 0;
    memset(block->validator_scores_root, 0, 64);

    if (block->version >= 4) {
        if (ptr + 64 > end) return -1;
        memcpy(block->validator_scores_root, ptr, 64); ptr += 64;
    }

    memcpy(&block->transaction_set_frozen, ptr, sizeof(uint8_t)); ptr += sizeof(uint8_t);

    block->validation_chain = NULL;
    block->validation_capacity = 0;
    block->rapid_membership_entries = NULL;
    block->rapid_membership_capacity = 0;
    
    // BLOCKER FIX: Deserialize validation chain with field-by-field endian conversion
    if (block->validation_count > 0) {
        block->validation_chain = malloc(block->validation_count * sizeof(mxd_validator_signature_t));
        if (!block->validation_chain) {
            return -1;
        }
        for (uint32_t i = 0; i < block->validation_count; i++) {
            if (deserialize_validator_signature(&block->validation_chain[i], &ptr, end) != 0) {
                free(block->validation_chain);
                block->validation_chain = NULL;
                return -1;
            }
        }
        block->validation_capacity = block->validation_count;
    }
    
    // BLOCKER FIX: Deserialize membership entries with field-by-field endian conversion
    if (block->rapid_membership_count > 0) {
        block->rapid_membership_entries = malloc(block->rapid_membership_count * sizeof(mxd_rapid_membership_entry_t));
        if (!block->rapid_membership_entries) {
            if (block->validation_chain) {
                free(block->validation_chain);
                block->validation_chain = NULL;
            }
            return -1;
        }
        for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
            if (deserialize_membership_entry(&block->rapid_membership_entries[i], &ptr, end) != 0) {
                free(block->rapid_membership_entries);
                block->rapid_membership_entries = NULL;
                if (block->validation_chain) {
                    free(block->validation_chain);
                    block->validation_chain = NULL;
                }
                return -1;
            }
        }
        block->rapid_membership_capacity = block->rapid_membership_count;
    }

    // v8+: rapid eviction count + entries
    block->rapid_eviction_entries = NULL;
    block->rapid_eviction_count = 0;
    block->rapid_eviction_capacity = 0;
    if (block->version >= 8 && ptr + sizeof(uint32_t) <= end) {
        uint32_t evict_count_be;
        memcpy(&evict_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        block->rapid_eviction_count = ntohl(evict_count_be);
        if (block->rapid_eviction_count > 100) {
            MXD_LOG_ERROR("blockchain_db", "Block %u eviction_count %u > 100 cap",
                          block->height, block->rapid_eviction_count);
            if (block->validation_chain) { free(block->validation_chain); block->validation_chain = NULL; }
            if (block->rapid_membership_entries) { free(block->rapid_membership_entries); block->rapid_membership_entries = NULL; }
            return -1;
        }
        if (block->rapid_eviction_count > 0) {
            block->rapid_eviction_entries = malloc(block->rapid_eviction_count * sizeof(mxd_rapid_eviction_entry_t));
            if (!block->rapid_eviction_entries) {
                if (block->validation_chain) { free(block->validation_chain); block->validation_chain = NULL; }
                if (block->rapid_membership_entries) { free(block->rapid_membership_entries); block->rapid_membership_entries = NULL; }
                return -1;
            }
            for (uint32_t i = 0; i < block->rapid_eviction_count; i++) {
                if (deserialize_eviction_entry(&block->rapid_eviction_entries[i], &ptr, end) != 0) {
                    free(block->rapid_eviction_entries);
                    block->rapid_eviction_entries = NULL;
                    if (block->validation_chain) { free(block->validation_chain); block->validation_chain = NULL; }
                    if (block->rapid_membership_entries) { free(block->rapid_membership_entries); block->rapid_membership_entries = NULL; }
                    return -1;
                }
            }
            block->rapid_eviction_capacity = block->rapid_eviction_count;
        }
    }

    // Deserialize validator scores (v4+)
    // v4-v5 entry = 48 bytes (address[20] + stake/bp/bs/latency/bsj),
    // v6 entry    = 60 bytes (address[32] + ...).
    if (block->version >= 4 && ptr + sizeof(uint32_t) <= end) {
        uint32_t vs_count_be;
        memcpy(&vs_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        block->validator_scores_count = ntohl(vs_count_be);
        size_t entry_size = (block->version >= 6) ? 60 : 48;
        size_t addr_len  = (block->version >= 6) ? 32 : 20;
        if (block->validator_scores_count > 0) {
            if (ptr + (size_t)block->validator_scores_count * entry_size > end) {
                MXD_LOG_ERROR("blockchain_db", "Block %u has truncated validator_scores data", block->height);
                if (block->validation_chain) { free(block->validation_chain); block->validation_chain = NULL; }
                if (block->rapid_membership_entries) { free(block->rapid_membership_entries); block->rapid_membership_entries = NULL; }
                return -1;  // Reject malformed block
            } else {
                block->validator_scores = malloc(block->validator_scores_count * sizeof(mxd_validator_score_entry_t));
                if (!block->validator_scores) {
                    block->validator_scores_count = 0;
                } else {
                    block->validator_scores_capacity = block->validator_scores_count;
                    for (uint32_t i = 0; i < block->validator_scores_count; i++) {
                        mxd_validator_score_entry_t *e = &block->validator_scores[i];
                        memset(e->validator_address, 0, 32);   // zero upper bytes for legacy v4-v5 entries
                        memcpy(e->validator_address, ptr, addr_len); ptr += addr_len;
                        uint64_t stake_be;
                        memcpy(&stake_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
                        e->stake_amount = mxd_ntohll(stake_be);
                        uint32_t bp_be;
                        memcpy(&bp_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
                        e->blocks_proposed = ntohl(bp_be);
                        uint32_t bs_be;
                        memcpy(&bs_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
                        e->blocks_signed = ntohl(bs_be);
                        uint64_t lat_be;
                        memcpy(&lat_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
                        e->total_latency_ms = mxd_ntohll(lat_be);
                        uint32_t bsj_be;
                        memcpy(&bsj_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
                        e->blocks_since_joined = ntohl(bsj_be);
                    }
                }
            }
        }
    }

    // v5+: next_proposer. v5 = 20 bytes, v6 = 32 bytes (addr32).
    memset(block->next_proposer, 0, 32);
    if (block->version >= 6 && ptr + 32 <= end) {
        memcpy(block->next_proposer, ptr, 32);
        ptr += 32;
    } else if (block->version >= 5 && ptr + 20 <= end) {
        memcpy(block->next_proposer, ptr, 20);
        ptr += 20;
    }

    // Deserialize transactions
    block->transactions = NULL;
    block->transaction_count = 0;
    block->transaction_capacity = 0;

    if (ptr + sizeof(uint32_t) <= end) {
        uint32_t tx_count_be;
        memcpy(&tx_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
        block->transaction_count = ntohl(tx_count_be);

        if (block->transaction_count > 0) {
            block->transactions = calloc(block->transaction_count, sizeof(mxd_block_transaction_t));
            if (!block->transactions) {
                block->transaction_count = 0;
                // Clean up previously allocated arrays
                if (block->validation_chain) { free(block->validation_chain); block->validation_chain = NULL; }
                if (block->validator_scores) { free(block->validator_scores); block->validator_scores = NULL; }
                return -1;
            } else {
                block->transaction_capacity = block->transaction_count;
                for (uint32_t i = 0; i < block->transaction_count; i++) {
                    if (ptr + sizeof(uint32_t) > end) {
                        // Truncated - stop reading transactions
                        block->transaction_count = i;
                        break;
                    }
                    uint32_t tx_len_be;
                    memcpy(&tx_len_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
                    uint32_t tx_len = ntohl(tx_len_be);

                    if (tx_len > 0 && ptr + tx_len <= end) {
                        block->transactions[i].data = malloc(tx_len);
                        if (block->transactions[i].data) {
                            memcpy(block->transactions[i].data, ptr, tx_len);
                            block->transactions[i].length = tx_len;
                        }
                        ptr += tx_len;
                    }
                }
            }
        }
    }

    return 0;
}

static void create_block_height_key(uint32_t height, uint8_t *key, size_t *key_len) {
    mxd_create_key_with_u32(key, key_len, "block:height:", height);
}

static void create_block_hash_key(const uint8_t hash[64], uint8_t *key, size_t *key_len) {
    memcpy(key, "block:hash:", 11);
    memcpy(key + 11, hash, 64);
    *key_len = 11 + 64;
}

// v6: validator_id widened to 32 bytes (addr32). DB keys grow accordingly.
static void create_signature_key(uint32_t height, const uint8_t validator_id[32], uint8_t *key, size_t *key_len) {
    memcpy(key, "sig:", 4);
    uint32_t height_be = htonl(height);
    memcpy(key + 4, &height_be, sizeof(uint32_t));
    memcpy(key + 4 + sizeof(uint32_t), validator_id, 32);
    *key_len = 4 + sizeof(uint32_t) + 32;
}

static void create_validator_key(const uint8_t validator_id[32], uint8_t *key, size_t *key_len) {
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 32);
    *key_len = 10 + 32;
}

int mxd_init_blockchain_db(const char *db_path) {
    if (!db_path) return -1;
    
    if (db_path_global) free(db_path_global);
    db_path_global = strdup(db_path);
    
    options = rocksdb_options_create();
    mxd_set_rocksdb_readoptions(rocksdb_readoptions_create());
    mxd_set_rocksdb_writeoptions(rocksdb_writeoptions_create());
    
    rocksdb_options_set_create_if_missing(options, 1);
    rocksdb_options_set_compression(options, rocksdb_lz4_compression);
    
    size_t write_buffer_size = 32 * 1024 * 1024; // 32MB (reduced from 128MB)
    int max_write_buffer_number = 2; // 2 (reduced from 4)
    size_t block_cache_size = 64 * 1024 * 1024; // 64MB (reduced from 256MB)
    
    rocksdb_options_set_write_buffer_size(options, write_buffer_size);
    rocksdb_options_set_max_write_buffer_number(options, max_write_buffer_number);
    rocksdb_options_set_target_file_size_base(options, 32 * 1024 * 1024); // 32MB (reduced from 64MB)
    rocksdb_options_set_level_compaction_dynamic_level_bytes(options, 1);
    rocksdb_options_set_max_open_files(options, -1); // Keep all SST files open to prevent fd reuse races
    rocksdb_options_set_max_background_jobs(options, 2); // Limit concurrent compaction memory
    
    MXD_LOG_INFO("blockchain_db", "RocksDB Blockchain settings: write_buffer=%zu MB, max_buffers=%d, block_cache=%zu MB, total_est=%zu MB",
                 write_buffer_size / (1024*1024), max_write_buffer_number, block_cache_size / (1024*1024),
                 (write_buffer_size * max_write_buffer_number + block_cache_size) / (1024*1024));
    
    rocksdb_cache_t *cache = rocksdb_cache_create_lru(block_cache_size);
    rocksdb_block_based_table_options_t *table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(table_options, cache);
    rocksdb_options_set_block_based_table_factory(options, table_options);
    
    rocksdb_readoptions_set_verify_checksums(mxd_get_rocksdb_readoptions(), 1);
    
    rocksdb_writeoptions_set_sync(mxd_get_rocksdb_writeoptions(), 1);
    
    char *err = NULL;
    mxd_set_rocksdb_db(rocksdb_open(options, db_path, &err));
    if (err) {
        MXD_LOG_ERROR("db", "Failed to open blockchain database: %s", err);
        free(err);
        return -1;
    }
    
    mxd_get_blockchain_height(&current_height);

    // Load latest_stored_height
    {
        char *err = NULL;
        size_t val_len = 0;
        char *val = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                                "latest_stored_height", 21, &val_len, &err);
        if (val && val_len == sizeof(uint32_t)) {
            uint32_t lsh_be;
            memcpy(&lsh_be, val, sizeof(uint32_t));
            latest_stored_height = ntohl(lsh_be);
        } else {
            latest_stored_height = current_height;  // fallback
        }
        if (val) free(val);
        if (err) free(err);
        MXD_LOG_INFO("db", "Blockchain init: current_height=%u, latest_stored_height=%u",
                     current_height, latest_stored_height);
    }

    mxd_load_all_validator_metadata();
    
    return 0;
}

int mxd_close_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_close(mxd_get_rocksdb_db());
    mxd_set_rocksdb_db(NULL);
    
    rocksdb_options_destroy(options);
    rocksdb_readoptions_destroy(mxd_get_rocksdb_readoptions());
    rocksdb_writeoptions_destroy(mxd_get_rocksdb_writeoptions());
    options = NULL;
    mxd_set_rocksdb_readoptions(NULL);
    mxd_set_rocksdb_writeoptions(NULL);
    
    free(db_path_global);
    db_path_global = NULL;
    
    return 0;
}

/*
 * Raw block-store: writes block to (height, hash) keys, advances current_height
 * if contiguous, persists the UTXO delta. NO fork-choice or reorg logic.
 *
 * v7.1 reorg machinery calls this directly to avoid recursion.
 */
static int store_block_unconditional(const mxd_block_t *block) {
    if (!block || !mxd_get_rocksdb_db()) {
        return -1;
    }

    // Defensive guard: preserve membership entries on genesis block overwrites.
    // The genesis block's membership entries are critical for rapid table rebuild
    // but are not covered by the block hash. If this store would overwrite a
    // genesis block that has membership entries with one that doesn't, merge them.
    mxd_block_t merged_block;
    int using_merged = 0;
    if (block->height == 0 && block->rapid_membership_count == 0) {
        mxd_block_t existing;
        memset(&existing, 0, sizeof(existing));
        if (mxd_retrieve_block_by_height(0, &existing) == 0 && existing.rapid_membership_count > 0) {
            // Copy the incoming block and attach existing membership entries
            memcpy(&merged_block, block, sizeof(mxd_block_t));
            merged_block.rapid_membership_count = existing.rapid_membership_count;
            merged_block.rapid_membership_capacity = existing.rapid_membership_capacity;
            merged_block.rapid_membership_entries = existing.rapid_membership_entries;
            // Null out existing's pointer so free doesn't release them
            existing.rapid_membership_entries = NULL;
            existing.rapid_membership_count = 0;
            block = &merged_block;
            using_merged = 1;
            MXD_LOG_INFO("db", "Preserved %u membership entries during genesis block overwrite",
                         merged_block.rapid_membership_count);
        }
        mxd_free_block(&existing);
    }

    uint8_t height_key[13 + sizeof(uint32_t)];
    size_t height_key_len;
    create_block_height_key(block->height, height_key, &height_key_len);

    uint8_t hash_key[11 + 64];
    size_t hash_key_len;
    create_block_hash_key(block->block_hash, hash_key, &hash_key_len);

    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_block(block, &data, &data_len) != 0) {
        if (using_merged) {
            free(merged_block.rapid_membership_entries);
        }
        return -1;
    }
    
    /* v7.1 F8-1: extract + serialize the UTXO delta BEFORE the WriteBatch so
     * the block-put and the delta-put commit atomically. A crash mid-write
     * is then impossible to leave a block on disk without its delta — either
     * the whole batch lands or none of it does. This matches the atomicity
     * MXD-CONS-02 §6 promises. */
    uint8_t *delta_buf = NULL;
    size_t delta_buf_len = 0;
    uint8_t delta_key[MXD_BLOCK_DELTA_KEY_LEN];
    int have_delta = 0;
    {
        mxd_block_delta_t delta;
        mxd_block_delta_init(&delta);
        if (extract_block_delta(block, &delta) == 0) {
            if (mxd_block_delta_serialize(&delta, &delta_buf, &delta_buf_len) == 0) {
                mxd_block_delta_make_key(block->block_hash, delta_key);
                have_delta = 1;
            } else {
                MXD_LOG_WARN("db", "Failed to serialize UTXO delta for block %u — reorg over this block disabled",
                             block->height);
            }
        } else {
            MXD_LOG_WARN("db", "Failed to extract UTXO delta for block %u", block->height);
        }
        mxd_block_delta_free(&delta);
    }

    // Use WriteBatch for atomic block storage (height key + hash key + delta + optional height update)
    rocksdb_writebatch_t *batch = rocksdb_writebatch_create();
    rocksdb_writebatch_put(batch, (char *)height_key, height_key_len, (char *)data, data_len);
    rocksdb_writebatch_put(batch, (char *)hash_key, hash_key_len, (char *)data, data_len);
    if (have_delta) {
        rocksdb_writebatch_put(batch, (char *)delta_key, MXD_BLOCK_DELTA_KEY_LEN,
                               (char *)delta_buf, delta_buf_len);
    }

    // Include current_height update in the same atomic batch
    // Only advance height contiguously: block must be exactly at current_height
    pthread_mutex_lock(&height_mutex);
    int updating_height = 0;
    uint32_t new_height = current_height;
    if (block->height == current_height) {
        new_height = current_height + 1;
        updating_height = 1;
    }
    if (updating_height) {
        uint32_t height_be = htonl(new_height);
        rocksdb_writebatch_put(batch, "current_height", 14, (char *)&height_be, sizeof(height_be));
    }

    char *err = NULL;
    rocksdb_write(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), batch, &err);
    rocksdb_writebatch_destroy(batch);
    free(delta_buf);  /* serialized buffer no longer needed; batch copied the bytes */

    if (err) {
        pthread_mutex_unlock(&height_mutex);
        int is_io = mxd_is_io_error(err);
        MXD_LOG_ERROR("db", "Failed to store block: %s", err);
        free(err);
        free(data);
        if (using_merged) free(merged_block.rapid_membership_entries);
        return is_io ? MXD_ERR_IO : MXD_ERR_GENERIC;
    }

    // Update in-memory height after successful write
    if (updating_height) {
        current_height = new_height;
    }

    // Track highest block ever stored (for proposer selection)
    if (block->height >= latest_stored_height) {
        latest_stored_height = block->height + 1;  // +1 to match current_height semantics (count, not index)
        uint32_t lsh_be = htonl(latest_stored_height);
        char *err_lsh = NULL;
        rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                    "latest_stored_height", 21, (char *)&lsh_be, sizeof(lsh_be), &err_lsh);
        // Best-effort housekeeping write — log + continue on failure.
        // Bug B (NULL errptr): rocksdb 6.x tolerates NULL here, but
        // rocksdb 8.x aborts via assertion. Always pass a real errptr.
        if (err_lsh) {
            MXD_LOG_WARN("db", "rocksdb_put(latest_stored_height) failed: %s", err_lsh);
            free(err_lsh);
        }
    }

    // Always scan forward: advance height through any contiguous blocks.
    // This handles both normal sequential stores AND out-of-order gap fills
    // where a previously missing block is finally stored, unblocking the
    // entire range of blocks that were already stored beyond the gap.
    while (1) {
        uint8_t probe_key[13 + sizeof(uint32_t)];
        size_t probe_key_len;
        create_block_height_key(current_height, probe_key, &probe_key_len);
        size_t probe_len = 0;
        char *err_probe = NULL;
        char *probe = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                                  (char *)probe_key, probe_key_len, &probe_len, &err_probe);
        // Bug B (NULL errptr): always pass a real errptr; rocksdb 8.x aborts otherwise.
        // On error, treat as "not found" so the advance loop terminates cleanly.
        if (err_probe) {
            MXD_LOG_WARN("db", "rocksdb_get(probe height=%u) failed: %s", current_height, err_probe);
            free(err_probe);
            if (probe) { free(probe); probe = NULL; }
        }
        if (probe) {
            free(probe);
            current_height++;
            // Persist the new height
            uint32_t h_be = htonl(current_height);
            char *err_h = NULL;
            rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                        "current_height", 14, (char *)&h_be, sizeof(h_be), &err_h);
            if (err_h) {
                MXD_LOG_WARN("db", "rocksdb_put(current_height=%u) failed: %s", current_height, err_h);
                free(err_h);
            }
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&height_mutex);

    // Signatures stored separately (non-critical, can be re-fetched)
    for (uint32_t i = 0; i < block->validation_count; i++) {
        mxd_store_signature(block->height,
                            block->validation_chain[i].validator_id,
                            block->validation_chain[i].signature,
                            block->validation_chain[i].signature_length);
    }

    /* v7.1 F8-1: delta now written atomically with the block in the WriteBatch
     * above, so a separate post-write `mxd_store_block_delta` call is no longer
     * needed. Atomicity holds: either the block + delta both land, or neither. */

    free(data);
    if (using_merged) free(merged_block.rapid_membership_entries);
    return 0;
}

/*
 * v7.1 public mxd_store_block — wraps store_block_unconditional with
 * fork-choice + reorg logic. The flow:
 *
 *   - Genesis (height 0): always store as-is (no fork-choice possible).
 *   - No existing block at this height in the DB: today's path.
 *   - Existing block with same hash: idempotent re-store (e.g. a re-broadcast
 *     with more sigs); fall through and let store_block_unconditional update
 *     the record.
 *   - Different hash at same height: forks detected. Apply fork-choice rule
 *     in handle_block_at_existing_height.
 */
int mxd_store_block(const mxd_block_t *block) {
    if (!block || !mxd_get_rocksdb_db()) return -1;

    /* Genesis is special-cased: never reorg over it. */
    if (block->height == 0) {
        return store_block_unconditional(block);
    }

    /* Check whether a block already exists at this height — if so, this is
     * either an idempotent re-store or a fork. */
    mxd_block_t existing;
    memset(&existing, 0, sizeof(existing));
    int have_existing = (mxd_retrieve_block_by_height(block->height, &existing) == 0);

    if (!have_existing) {
        /* Normal path: no block at this height yet. */
        return store_block_unconditional(block);
    }

    /* Same hash → idempotent. Update the record (sigs may have grown). */
    if (memcmp(existing.block_hash, block->block_hash, 64) == 0) {
        mxd_free_block(&existing);
        return store_block_unconditional(block);
    }

    /* Different hash at the same height — fork. */
    MXD_LOG_WARN("fork_choice",
                 "Fork detected at height %u: existing hash %02x%02x%02x... vs incoming %02x%02x%02x...",
                 block->height,
                 existing.block_hash[0], existing.block_hash[1], existing.block_hash[2],
                 block->block_hash[0], block->block_hash[1], block->block_hash[2]);

    int rc = handle_block_at_existing_height(block);
    mxd_free_block(&existing);
    return rc;
}

/*
 * Extract a UTXO delta from the block's tx data (no UTXO state lookups).
 *
 *   - Coinbase + tip-redistribution + bridge mint outputs: created entries.
 *   - User tx inputs: spent entries.
 *   - User tx outputs: created entries.
 *   - Burn outputs: created entries (they DO produce UTXOs at the burn
 *     address; they just don't increase total supply).
 *   - Admin txs: no UTXO impact.
 *
 * The block's transaction[] entries are wire-format byte buffers. We use the
 * same minimal parser as mxd_apply_block_transactions.
 */
static int extract_block_delta(const mxd_block_t *block, mxd_block_delta_t *out) {
    if (!block || !out) return -1;

    for (uint32_t i = 0; i < block->transaction_count; i++) {
        const uint8_t *ptr = block->transactions[i].data;
        size_t len = block->transactions[i].length;
        if (!ptr || len < 4) continue;

        /* Peek version. */
        uint32_t version = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
                           ((uint32_t)ptr[2] << 8)  | (uint32_t)ptr[3];

        if (version == 3) {
            /* v3 admin/bridge tx — use the v3 deserializer. */
            mxd_transaction_v3_t tx_v3;
            if (mxd_deserialize_transaction_v3_from_block(ptr, len, &tx_v3) != 0) {
                continue;  /* skip malformed */
            }
            if (tx_v3.type == MXD_TX_TYPE_BRIDGE_MINT ||
                tx_v3.type == MXD_TX_TYPE_BRIDGE_BURN) {
                /* Bridge txs have outputs but the block-level v3 struct uses
                 * a different layout. The output address is in tx_v3.outputs. */
                for (uint32_t j = 0; j < tx_v3.output_count; j++) {
                    mxd_block_delta_append_created(out, tx_v3.tx_hash, j,
                                                   tx_v3.outputs[j].recipient_addr,
                                                   tx_v3.outputs[j].amount);
                }
            }
            /* Admin txs: no UTXO impact. */
            mxd_free_transaction_v3(&tx_v3);
            continue;
        }

        /* v2 path — header is version(4) + chain_id(4) + input_count(4) +
         * output_count(4) + tip(8) + ts(8) + tx_hash(64) = 96 bytes. */
        if (len < 96) continue;
        const uint8_t *p = ptr;
        const uint8_t *end = ptr + len;
        p += 4; /* version */
        p += 4; /* chain_id */
        uint32_t input_count = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                               ((uint32_t)p[2] << 8) | (uint32_t)p[3]; p += 4;
        uint32_t output_count = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                ((uint32_t)p[2] << 8) | (uint32_t)p[3]; p += 4;
        p += 8; /* tip */
        p += 8; /* timestamp */
        uint8_t tx_hash[64];
        memcpy(tx_hash, p, 64); p += 64;

        /* Inputs (spent). */
        for (uint32_t j = 0; j < input_count; j++) {
            if (p + 64 + 4 + 1 + 2 > end) goto malformed;
            uint8_t prev_hash[64];
            memcpy(prev_hash, p, 64); p += 64;
            uint32_t output_index = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                    ((uint32_t)p[2] << 8) | (uint32_t)p[3]; p += 4;
            p += 1;  /* algo_id */
            uint16_t pk_len = ((uint16_t)p[0] << 8) | (uint16_t)p[1]; p += 2;
            if (p + pk_len > end) goto malformed;
            p += pk_len;
            if (p + 2 > end) goto malformed;
            uint16_t sig_len = ((uint16_t)p[0] << 8) | (uint16_t)p[1]; p += 2;
            if (p + sig_len > end) goto malformed;
            p += sig_len;
            mxd_block_delta_append_spent(out, prev_hash, output_index);
        }

        /* Outputs (created). */
        for (uint32_t j = 0; j < output_count; j++) {
            if (p + 32 + 8 > end) goto malformed;
            uint8_t addr[32];
            memcpy(addr, p, 32); p += 32;
            uint64_t amt = 0;
            for (int k = 0; k < 8; k++) amt = (amt << 8) | p[k];
            p += 8;
            mxd_block_delta_append_created(out, tx_hash, j, addr, amt);
        }
        continue;

malformed:
        MXD_LOG_DEBUG("db", "extract_block_delta: malformed tx %u in block %u (skipped)",
                      i, block->height);
        continue;
    }
    return 0;
}

/*
 * Fork detected at this height. Apply fork-choice rule and either
 *   a) keep existing (incoming loses), or
 *   b) reorg to incoming (incoming wins).
 */
static int handle_block_at_existing_height(const mxd_block_t *new_block) {
    if (!new_block) return -1;

    mxd_block_t existing;
    memset(&existing, 0, sizeof(existing));
    if (mxd_retrieve_block_by_height(new_block->height, &existing) != 0) {
        /* Race — should not happen, our caller verified existence. Fall back
         * to unconditional store. */
        return store_block_unconditional(new_block);
    }

    int cmp = mxd_compare_forks(&existing, new_block);
    if (cmp <= 0) {
        /* Existing wins (cmp<0) or equal (cmp==0, same hash). Keep existing.
         * Persist the loser under its hash key only — useful for diagnostics.
         * We do NOT advance current_height for it. */
        MXD_LOG_INFO("fork_choice",
                     "Fork at h=%u: existing wins (sigs=%u vs %u). Storing loser under hash key only.",
                     new_block->height, existing.validation_count, new_block->validation_count);

        /* Store under hash key only (no height key, no height advancement,
         * no delta — the loser doesn't get applied to UTXO state). */
        uint8_t hash_key[11 + 64];
        size_t hash_key_len;
        create_block_hash_key(new_block->block_hash, hash_key, &hash_key_len);
        uint8_t *data = NULL;
        size_t data_len = 0;
        if (serialize_block(new_block, &data, &data_len) == 0) {
            char *err = NULL;
            rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                        (char *)hash_key, hash_key_len, (char *)data, data_len, &err);
            if (err) free(err);
            free(data);
        }
        mxd_free_block(&existing);
        return 0;
    }

    /* New wins. Trigger reorg. */
    MXD_LOG_WARN("fork_choice",
                 "Fork at h=%u: incoming wins (sigs=%u vs %u). Initiating reorg.",
                 new_block->height, new_block->validation_count, existing.validation_count);
    mxd_free_block(&existing);
    return reorg_to_candidate(new_block);
}

/*
 * Reorg the canonical chain so that `candidate` becomes the new head.
 *
 * Sequence:
 *   1. Find common ancestor of current head and candidate.
 *   2. Reject if depth > MXD_MAX_REORG_DEPTH.
 *   3. Walk current head down to ancestor: for each demoted block, reverse
 *      its UTXO delta and re-add user txs to the mempool.
 *   4. Walk candidate's chain forward from ancestor: for each promoted block,
 *      apply its UTXO delta. The candidate IS the head of the new fork so it
 *      gets stored last.
 *   5. Update canonical head pointer.
 */
static int reorg_to_candidate(const mxd_block_t *candidate) {
    if (!candidate || candidate->height == 0) return -1;

    uint32_t my_height = 0;
    if (mxd_get_blockchain_height(&my_height) != 0) return -1;
    if (my_height == 0) {
        /* No prior head; trivially store. */
        return store_block_unconditional(candidate);
    }

    /* Current head = block at height (my_height - 1). */
    mxd_block_t current_head;
    memset(&current_head, 0, sizeof(current_head));
    if (mxd_retrieve_block_by_height(my_height - 1, &current_head) != 0) {
        MXD_LOG_ERROR("fork_choice", "Reorg: cannot read current head at h=%u", my_height - 1);
        return -1;
    }

    /* Find common ancestor between current head and candidate's parent
     * (candidate hasn't been stored yet, so we walk up via candidate->prev_hash). */
    uint32_t anc_h = 0;
    uint8_t anc_hash[64];
    /* Walking from candidate's prev_hash at height (candidate->height - 1)
     * is equivalent to walking from the candidate itself for ancestor purposes —
     * and avoids needing the candidate to be in DB. */
    int common_ok = mxd_find_common_ancestor(
        my_height - 1, current_head.block_hash,
        candidate->height - 1, candidate->prev_block_hash,
        &anc_h, anc_hash);
    if (common_ok != 0) {
        MXD_LOG_ERROR("fork_choice", "Reorg: cannot find common ancestor — refusing reorg");
        mxd_free_block(&current_head);
        return -1;
    }

    /* Depth = number of blocks demoted. */
    if (current_head.height < anc_h) {
        mxd_free_block(&current_head);
        return -1;
    }
    uint32_t depth = current_head.height - anc_h;
    if (depth > MXD_MAX_REORG_DEPTH) {
        MXD_LOG_ERROR("fork_choice",
                      "Reorg too deep: depth=%u > MXD_MAX_REORG_DEPTH=%d. Refusing.",
                      depth, MXD_MAX_REORG_DEPTH);
        mxd_free_block(&current_head);
        return -1;
    }

    MXD_LOG_WARN("fork_choice", "Reorg: common ancestor h=%u, demoting %u block(s).",
                 anc_h, depth);

    /* Phase 1: walk current head down to ancestor (exclusive), demote each. */
    {
        uint32_t h = current_head.height;
        uint8_t walk_hash[64];
        memcpy(walk_hash, current_head.block_hash, 64);
        while (h > anc_h) {
            mxd_block_t blk;
            memset(&blk, 0, sizeof(blk));
            if (mxd_retrieve_block_by_hash(walk_hash, &blk) != 0 &&
                mxd_retrieve_block_by_height(h, &blk) != 0) {
                MXD_LOG_ERROR("fork_choice", "Reorg phase1: cannot read demoted block at h=%u", h);
                mxd_free_block(&current_head);
                return -1;
            }

            /* Re-add user (v2 non-coinbase) txs to mempool. v3 admin/bridge txs
             * deliberately not re-pooled — they're sourced from the bridge
             * pending queue / oracle and will be re-submitted naturally.
             * Coinbase + tip-redist txs are intentionally dropped. */
            for (uint32_t i = 0; i < blk.transaction_count; i++) {
                const uint8_t *p = blk.transactions[i].data;
                size_t plen = blk.transactions[i].length;
                if (!p || plen < 4) continue;
                uint32_t version = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                   ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
                if (version == 3) continue;  /* skip v3 */

                mxd_transaction_t tx;
                memset(&tx, 0, sizeof(tx));
                if (mxd_deserialize_transaction(p, plen, &tx) != 0) {
                    continue;
                }
                if (!tx.is_coinbase) {
                    /* Best-effort. If validation later fails (double-spend),
                     * mempool's add path will reject and we move on. */
                    int rc = mxd_add_to_mempool(&tx, MXD_PRIORITY_MEDIUM);
                    if (rc != 0) {
                        MXD_LOG_DEBUG("fork_choice",
                                      "Reorg: tx from demoted block already in mempool or invalid");
                    } else {
                        MXD_LOG_INFO("fork_choice",
                                     "Reorg: re-pooled tx from demoted block at h=%u", h);
                    }
                }
                mxd_free_transaction(&tx);
            }

            /* Reverse UTXO state for this block. */
            mxd_block_delta_t delta;
            mxd_block_delta_init(&delta);
            if (mxd_load_block_delta(blk.block_hash, &delta) == 0) {
                if (mxd_reverse_utxo_delta(&delta) != 0) {
                    MXD_LOG_ERROR("fork_choice", "Reorg: reverse_utxo_delta failed at h=%u", h);
                }
                mxd_delete_block_delta(blk.block_hash);
            } else {
                MXD_LOG_WARN("fork_choice",
                             "Reorg: no delta stored for demoted block h=%u — UTXO state may diverge",
                             h);
            }
            mxd_block_delta_free(&delta);

            /* Remove the height key for this block (so the new fork can take
             * over the slot). The hash key stays for lookup. */
            uint8_t height_key[13 + sizeof(uint32_t)];
            size_t height_key_len;
            create_block_height_key(h, height_key, &height_key_len);
            char *err = NULL;
            rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                           (char *)height_key, height_key_len, &err);
            if (err) {
                MXD_LOG_WARN("fork_choice", "Reorg: failed to delete height key h=%u: %s", h, err);
                free(err);
            }

            uint8_t prev_hash[64];
            memcpy(prev_hash, blk.prev_block_hash, 64);
            mxd_free_block(&blk);
            memcpy(walk_hash, prev_hash, 64);
            if (h == 0) break;
            h--;
        }
    }
    mxd_free_block(&current_head);

    /* Phase 2: roll the canonical head back to the ancestor. */
    pthread_mutex_lock(&height_mutex);
    current_height = anc_h + 1;  /* ancestor inclusive — heights 0..anc_h are valid */
    uint32_t h_be = htonl(current_height);
    char *err_reorg = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                "current_height", 14, (char *)&h_be, sizeof(h_be), &err_reorg);
    if (err_reorg) {
        MXD_LOG_WARN("db", "rocksdb_put(current_height=%u) after reorg failed: %s", current_height, err_reorg);
        free(err_reorg);
    }
    pthread_mutex_unlock(&height_mutex);

    /* Phase 3: walk the candidate's chain forward from ancestor+1 up to and
     * including the candidate. Any blocks already in the alternates pool
     * (stored by hash on the previous loser-store path) get promoted by
     * applying their delta and re-storing under their height key.
     *
     * For now, we only have the candidate itself in hand. Intermediate blocks
     * (heights anc_h+1 .. candidate->height-1) on the new fork are not
     * guaranteed to be in our DB. If they are, fetch by parent hash.
     */
    {
        uint32_t target_h = anc_h + 1;
        uint8_t want_prev[64];
        memcpy(want_prev, anc_hash, 64);

        while (target_h < candidate->height) {
            /* Look up a block at target_h whose prev_block_hash == want_prev.
             * We scan by hash key first (alternates) then by height key. The
             * brute-force approach is OK in this code path because reorg depth
             * is capped at MXD_MAX_REORG_DEPTH (10). */
            mxd_block_t found;
            memset(&found, 0, sizeof(found));
            int got = -1;

            /* Try height key first (in case it's already there). */
            if (mxd_retrieve_block_by_height(target_h, &found) == 0) {
                if (memcmp(found.prev_block_hash, want_prev, 64) == 0) {
                    got = 0;
                } else {
                    mxd_free_block(&found);
                    memset(&found, 0, sizeof(found));
                }
            }

            if (got != 0) {
                /* Fall back: iterate hash-keyed blocks (limited range, OK). */
                rocksdb_iterator_t *it = rocksdb_create_iterator(
                    mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
                rocksdb_iter_seek(it, "block:hash:", 11);
                while (rocksdb_iter_valid(it)) {
                    size_t klen = 0;
                    const char *k = rocksdb_iter_key(it, &klen);
                    if (klen < 11 || memcmp(k, "block:hash:", 11) != 0) break;
                    size_t vlen = 0;
                    const char *v = rocksdb_iter_value(it, &vlen);
                    mxd_block_t cand;
                    memset(&cand, 0, sizeof(cand));
                    if (deserialize_block((const uint8_t *)v, vlen, &cand) == 0 &&
                        cand.height == target_h &&
                        memcmp(cand.prev_block_hash, want_prev, 64) == 0) {
                        memcpy(&found, &cand, sizeof(cand));
                        got = 0;
                        break;
                    } else {
                        mxd_free_block(&cand);
                    }
                    rocksdb_iter_next(it);
                }
                rocksdb_iter_destroy(it);
            }

            if (got != 0) {
                MXD_LOG_WARN("fork_choice",
                             "Reorg: missing intermediate block at h=%u on new fork — promote stalls",
                             target_h);
                /* We can still store the candidate itself if its parent is the
                 * ancestor — but here a gap remains. Return success anyway:
                 * the chain will heal via normal sync once peers serve the gap. */
                break;
            }

            /* Apply UTXO delta and re-store under height key. */
            mxd_block_delta_t delta;
            mxd_block_delta_init(&delta);
            if (mxd_load_block_delta(found.block_hash, &delta) == 0) {
                mxd_apply_utxo_delta(&delta);
            } else {
                /* Re-extract from block data (delta may have been deleted on
                 * a previous demote of THIS block). */
                if (extract_block_delta(&found, &delta) == 0) {
                    mxd_apply_utxo_delta(&delta);
                    mxd_store_block_delta(found.block_hash, &delta);
                }
            }
            mxd_block_delta_free(&delta);

            /* Re-store under height key. We use the unconditional path since
             * we already know nothing at this height key (we just deleted it). */
            store_block_unconditional(&found);

            uint8_t next_prev[64];
            memcpy(next_prev, found.block_hash, 64);
            mxd_free_block(&found);
            memcpy(want_prev, next_prev, 64);
            target_h++;
        }
    }

    /* Phase 4: store the candidate itself. We must apply its UTXO delta first
     * (extracted from the candidate's tx data) — store_block_unconditional
     * does NOT apply UTXOs, that's the caller's job in normal flow. But on
     * reorg we promoted from a fresh block so its UTXO state hasn't been
     * applied yet on this node. */
    {
        mxd_block_delta_t delta;
        mxd_block_delta_init(&delta);
        if (extract_block_delta(candidate, &delta) == 0) {
            mxd_apply_utxo_delta(&delta);
        }
        mxd_block_delta_free(&delta);
    }
    int rc = store_block_unconditional(candidate);
    if (rc == 0) {
        MXD_LOG_WARN("fork_choice", "Reorg: completed. New head h=%u, sigs=%u",
                     candidate->height, candidate->validation_count);
    } else {
        MXD_LOG_ERROR("fork_choice", "Reorg: failed to store new head at h=%u", candidate->height);
    }
    return rc;
}

int mxd_retrieve_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[13 + sizeof(uint32_t)];
    size_t key_len;
    create_block_height_key(height, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve block by height: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return -1; // Block not found
    }
    
    int result = deserialize_block((uint8_t *)value, value_len, block);
    
    free(value);
    return result;
}

int mxd_retrieve_block_by_hash(const uint8_t hash[64], mxd_block_t *block) {
    if (!hash || !block || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[11 + 64];
    size_t key_len;
    create_block_hash_key(hash, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve block by hash: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return -1; // Block not found
    }
    
    int result = deserialize_block((uint8_t *)value, value_len, block);
    
    free(value);
    return result;
}

int mxd_get_blockchain_height(uint32_t *height) {
    if (!height || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[] = "current_height";
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, sizeof(key) - 1, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve current height: %s", err);
        free(err);
        *height = 0;
        return 0;
    }
    
    // CRITICAL FIX: Deserialize current_height with endian conversion for cross-platform compatibility
    pthread_mutex_lock(&height_mutex);
    if (value && value_len == sizeof(uint32_t)) {
        uint32_t height_be;
        memcpy(&height_be, value, sizeof(uint32_t));
        *height = ntohl(height_be);
        current_height = *height;
        free(value);
    } else {
        *height = 0;
        current_height = 0;
        if (value) free(value);
    }
    pthread_mutex_unlock(&height_mutex);

    return 0;
}

int mxd_get_latest_stored_height(uint32_t *height) {
    if (!height) return -1;
    *height = latest_stored_height;
    return 0;
}

int mxd_store_signature(uint32_t height, const uint8_t validator_id[32], const uint8_t *signature, uint16_t signature_length) {
    if (!validator_id || !signature || !mxd_get_rocksdb_db() || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }

    uint8_t sig_key[4 + sizeof(uint32_t) + 32];   // v6: 32-byte addr32
    size_t sig_key_len;
    create_signature_key(height, validator_id, sig_key, &sig_key_len);

    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)sig_key, sig_key_len, (char *)signature, signature_length, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store signature: %s", err);
        free(err);
        return -1;
    }

    uint8_t validator_key[10 + 32 + sizeof(uint32_t)];
    size_t validator_key_len;
    create_validator_key(validator_id, validator_key, &validator_key_len);
    memcpy(validator_key + validator_key_len, &height, sizeof(uint32_t));
    validator_key_len += sizeof(uint32_t);

    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)validator_key, validator_key_len, "", 0, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store validator signature index: %s", err);
        free(err);
        return -1;
    }

    return 0;
}

int mxd_signature_exists(uint32_t height, const uint8_t validator_id[32], const uint8_t *signature, uint16_t signature_length) {
    if (!validator_id || !signature || !mxd_get_rocksdb_db() || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }

    uint8_t key[4 + sizeof(uint32_t) + 32];   // v6: 32-byte addr32
    size_t key_len;
    create_signature_key(height, validator_id, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to check signature: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return 0; // Signature does not exist
    }
    
    int result = (value_len == signature_length && memcmp(value, signature, value_len) == 0) ? 1 : 0;
    
    free(value);
    return result;
}

int mxd_prune_expired_signatures(uint32_t current_height) {
    if (!mxd_get_rocksdb_db() || current_height < 5) {
        return -1;
    }
    
    uint32_t expiry_height = current_height - 5;
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, "sig:", 4);
    
    size_t pruned = 0;
    
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len > 4 && memcmp(key, "sig:", 4) == 0) {
            uint32_t height;
            memcpy(&height, key + 4, sizeof(uint32_t));
            height = ntohl(height);  // Convert from big-endian (stored by create_signature_key)
            
            if (height < expiry_height) {
                uint8_t validator_id[32];   // v6: addr32
                memcpy(validator_id, key + 4 + sizeof(uint32_t), 32);

                uint8_t validator_key[10 + 32 + sizeof(uint32_t)];
                size_t validator_key_len;
                create_validator_key(validator_id, validator_key, &validator_key_len);
                memcpy(validator_key + validator_key_len, &height, sizeof(uint32_t));
                validator_key_len += sizeof(uint32_t);
                
                char *err = NULL;
                rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)validator_key, validator_key_len, &err);
                if (err) {
                    MXD_LOG_ERROR("db", "Failed to remove validator signature index: %s", err);
                    free(err);
                }
                
                rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), key, key_len, &err);
                if (err) {
                    MXD_LOG_ERROR("db", "Failed to remove signature: %s", err);
                    free(err);
                } else {
                    pruned++;
                }
            }
        } else {
            break; // No more signatures
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    
    return 0;
}

int mxd_get_signatures_by_height(uint32_t height, mxd_validator_signature_t **signatures, size_t *signature_count) {
    if (!signatures || !signature_count || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t prefix_key[4 + sizeof(uint32_t)];
    memcpy(prefix_key, "sig:", 4);
    uint32_t height_be = htonl(height);  // Convert to big-endian to match create_signature_key
    memcpy(prefix_key + 4, &height_be, sizeof(uint32_t));
    size_t prefix_key_len = 4 + sizeof(uint32_t);
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t count = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        count++;
        rocksdb_iter_next(iter);
    }
    
    *signatures = NULL;
    *signature_count = 0;
    if (count == 0) {
        rocksdb_iter_destroy(iter);
        return 0; // No signatures found
    }
    
    *signatures = malloc(count * sizeof(mxd_validator_signature_t));
    if (!*signatures) {
        rocksdb_iter_destroy(iter);
        return -1;
    }
    memset(*signatures, 0, count * sizeof(mxd_validator_signature_t));
    
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t index = 0;
    while (rocksdb_iter_valid(iter) && index < count) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        memcpy((*signatures)[index].validator_id, key + prefix_key_len, 32);   // v6: addr32
        
        size_t value_len;
        const char *value = rocksdb_iter_value(iter, &value_len);
        if (value && value_len > 0 && value_len <= MXD_SIGNATURE_MAX) {
            (*signatures)[index].signature_length = (uint16_t)value_len;
            memcpy((*signatures)[index].signature, value, (*signatures)[index].signature_length);
            (*signatures)[index].chain_position = index;
            
            (*signatures)[index].timestamp = 0;
            
            index++;
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    *signature_count = index;
    
    return 0;
}

int mxd_get_signatures_by_validator(const uint8_t validator_id[32], mxd_validator_signature_t **signatures,
                                   uint32_t **heights, size_t *signature_count) {
    if (!validator_id || !signatures || !heights || !signature_count || !mxd_get_rocksdb_db()) {
        return -1;
    }

    uint8_t prefix_key[10 + 32];   // v6: 32-byte addr32
    size_t prefix_key_len;
    create_validator_key(validator_id, prefix_key, &prefix_key_len);
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t count = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        count++;
        rocksdb_iter_next(iter);
    }
    
    *signatures = NULL;
    *heights = NULL;
    *signature_count = 0;
    if (count == 0) {
        rocksdb_iter_destroy(iter);
        return 0; // No signatures found
    }
    
    *signatures = malloc(count * sizeof(mxd_validator_signature_t));
    if (!*signatures) {
        rocksdb_iter_destroy(iter);
        return -1;
    }
    memset(*signatures, 0, count * sizeof(mxd_validator_signature_t));
    
    *heights = malloc(count * sizeof(uint32_t));
    if (!*heights) {
        free(*signatures);
        *signatures = NULL;
        rocksdb_iter_destroy(iter);
        return -1;
    }
    
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t index = 0;
    while (rocksdb_iter_valid(iter) && index < count) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        uint32_t height;
        memcpy(&height, key + prefix_key_len, sizeof(uint32_t));
        (*heights)[index] = height;
        
        memcpy((*signatures)[index].validator_id, validator_id, 32);   // v6: addr32

        uint8_t sig_key[4 + sizeof(uint32_t) + 32];
        size_t sig_key_len;
        create_signature_key(height, validator_id, sig_key, &sig_key_len);
        
        char *err = NULL;
        char *value = NULL;
        size_t value_len = 0;
        value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)sig_key, sig_key_len, &value_len, &err);
        if (err) {
            MXD_LOG_ERROR("db", "Failed to retrieve signature: %s", err);
            free(err);
        } else if (value && value_len > 0 && value_len <= MXD_SIGNATURE_MAX) {
            (*signatures)[index].signature_length = (uint16_t)value_len;
            memcpy((*signatures)[index].signature, value, (*signatures)[index].signature_length);
            (*signatures)[index].chain_position = 0; // Unknown position
            (*signatures)[index].timestamp = 0; // Unknown timestamp
            
            index++;
        }
        
        if (value) free(value);
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    *signature_count = index;
    
    return 0;
}

double mxd_calculate_block_latency_score(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return 0.0;
    }
    
    double score = 0.0;
    for (uint32_t i = 0; i < block->validation_count; i++) {
        double latency = 50.0 + (10.0 * block->validation_chain[i].chain_position);
        score += 1.0 / latency;
    }
    
    return score;
}

int mxd_flush_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    char *err = NULL;
    rocksdb_flushoptions_t *flushoptions = rocksdb_flushoptions_create();
    rocksdb_flushoptions_set_wait(flushoptions, 1);
    
    rocksdb_flush(mxd_get_rocksdb_db(), flushoptions, &err);
    rocksdb_flushoptions_destroy(flushoptions);
    
    if (err) {
        MXD_LOG_ERROR("db", "Failed to flush blockchain database: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_compact_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_compact_range(mxd_get_rocksdb_db(), NULL, 0, NULL, 0);
    
    MXD_LOG_INFO("db", "Blockchain database compaction completed");
    return 0;
}

int mxd_store_validator_metadata(const uint8_t validator_id[32], uint8_t algo_id,
                                  const uint8_t *public_key, size_t pubkey_len) {
    if (!validator_id || !public_key || pubkey_len == 0) {
        return -1;
    }

    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("db", "Database not initialized");
        return -1;
    }

    // v6: validator_id widened to 32 bytes (addr32). Key is "validator:" (10) + 32 = 42 bytes.
    uint8_t key[42];
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 32);
    size_t key_len = 42;
    
    size_t value_len = 1 + 2 + pubkey_len;
    uint8_t *value = malloc(value_len);
    if (!value) {
        return -1;
    }
    
    value[0] = algo_id;
    uint16_t len_field = htons((uint16_t)pubkey_len);
    memcpy(value + 1, &len_field, 2);
    memcpy(value + 3, public_key, pubkey_len);
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), 
                (char *)key, key_len, (char *)value, value_len, &err);
    
    free(value);
    
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store validator metadata: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_retrieve_validator_metadata(const uint8_t validator_id[32], uint8_t *out_algo_id,
                                     uint8_t *out_public_key, size_t out_capacity, size_t *out_len) {
    if (!validator_id || !out_algo_id || !out_public_key || !out_len) {
        return -1;
    }

    if (!mxd_get_rocksdb_db()) {
        return -1;
    }

    // v6: validator_id widened to 32 bytes (addr32). Key is "validator:" (10) + 32 = 42 bytes.
    uint8_t key[42];
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 32);
    size_t key_len = 42;
    
    char *err = NULL;
    size_t value_len = 0;
    char *value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                              (char *)key, key_len, &value_len, &err);
    
    if (err) {
        free(err);
        return -1;
    }
    
    if (!value || value_len < 3) {
        if (value) free(value);
        return -1;
    }
    
    *out_algo_id = (uint8_t)value[0];
    uint16_t pubkey_len_net = 0;
    memcpy(&pubkey_len_net, value + 1, 2);
    uint16_t pubkey_len = ntohs(pubkey_len_net);
    
    if (pubkey_len > out_capacity || value_len < 3 + pubkey_len) {
        free(value);
        return -1;
    }
    
    memcpy(out_public_key, value + 3, pubkey_len);
    *out_len = pubkey_len;
    
    free(value);
    return 0;
}

int mxd_load_all_validator_metadata(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), 
                                                        mxd_get_rocksdb_readoptions());
    if (!iter) {
        return -1;
    }
    
    uint8_t prefix[10];
    memcpy(prefix, "validator:", 10);
    
    int loaded_count = 0;
    
    for (rocksdb_iter_seek(iter, (char *)prefix, 10);
         rocksdb_iter_valid(iter);
         rocksdb_iter_next(iter)) {
        
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len != 42 || memcmp(key, prefix, 10) != 0) {   // v6: key now 42 bytes (10 prefix + 32 addr32)
            break;
        }

        size_t value_len = 0;
        const char *value = rocksdb_iter_value(iter, &value_len);

        if (!value || value_len < 3) {
            continue;
        }

        uint8_t validator_id[32];   // v6: addr32
        memcpy(validator_id, key + 10, 32);
        
        uint8_t algo_id = (uint8_t)value[0];
        uint16_t pubkey_len_net = 0;
        memcpy(&pubkey_len_net, value + 1, 2);
        uint16_t pubkey_len = ntohs(pubkey_len_net);
        
        if (value_len < 3 + pubkey_len) {
            continue;
        }
        
        if (mxd_test_register_validator_pubkey(validator_id, (const uint8_t *)(value + 3), pubkey_len) == 0) {
            loaded_count++;
        }
    }
    
    rocksdb_iter_destroy(iter);
    
    MXD_LOG_INFO("db", "Loaded %d validator metadata entries from database", loaded_count);
    return 0;
}

int mxd_broadcast_block(const mxd_block_t *block) {
    if (!block) {
        return -1;
    }

    uint8_t *data = NULL;
    size_t data_len = 0;

    if (serialize_block(block, &data, &data_len) != 0) {
        MXD_LOG_ERROR("db", "Failed to serialize block for broadcast");
        return -1;
    }

    // Retry logic with exponential backoff
    const int max_retries = 3;
    int retry_delay_ms = 500;  // Start with 500ms
    int result = -1;

    for (int attempt = 1; attempt <= max_retries; attempt++) {
        result = mxd_broadcast_message(MXD_MSG_BLOCKS, data, data_len);

        if (result == 0) {
            MXD_LOG_INFO("db", "Broadcast block at height %u to network (attempt %d/%d)",
                         block->height, attempt, max_retries);
            break;
        }

        if (attempt < max_retries) {
            MXD_LOG_WARN("db", "Block broadcast attempt %d/%d failed for height %u, retrying in %d ms",
                         attempt, max_retries, block->height, retry_delay_ms);
            usleep(retry_delay_ms * 1000);  // Convert ms to us
            retry_delay_ms *= 2;  // Exponential backoff
        } else {
            MXD_LOG_ERROR("db", "Failed to broadcast block at height %u after %d attempts",
                          block->height, max_retries);
        }
    }

    free(data);
    return result;
}

int mxd_deserialize_block_from_network(const uint8_t *data, size_t data_len, mxd_block_t *block) {
    if (!data || !block || data_len == 0) {
        return -1;
    }
    return deserialize_block(data, data_len, block);
}

int mxd_serialize_block_for_network(const mxd_block_t *block, uint8_t **data, size_t *data_len) {
    if (!block || !data || !data_len) {
        return -1;
    }
    return serialize_block(block, data, data_len);
}

int mxd_block_exists_at_height(uint32_t height) {
    if (!mxd_get_rocksdb_db()) return 0;
    uint8_t key[13 + sizeof(uint32_t)];
    size_t key_len;
    create_block_height_key(height, key, &key_len);
    size_t value_len = 0;
    char *err = NULL;
    char *value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                              (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_WARN("db", "rocksdb_get(height=%u) for existence check failed: %s", height, err);
        free(err);
        if (value) { free(value); value = NULL; }
    }
    if (value) {
        free(value);
        return 1;
    }
    return 0;
}

int mxd_fill_block_gaps(uint32_t *gaps, uint32_t max_gaps, uint32_t *gap_count) {
    if (!gaps || !gap_count) return -1;
    *gap_count = 0;
    uint32_t height = 0;
    if (mxd_get_blockchain_height(&height) != 0 || height == 0) return 0;
    for (uint32_t h = 0; h < height && *gap_count < max_gaps; h++) {
        if (!mxd_block_exists_at_height(h)) {
            gaps[*gap_count] = h;
            (*gap_count)++;
        }
    }
    return 0;
}

void mxd_advance_height_pointer(void) {
    if (!mxd_get_rocksdb_db()) return;
    pthread_mutex_lock(&height_mutex);
    uint32_t start = current_height;
    while (1) {
        uint8_t probe_key[13 + sizeof(uint32_t)];
        size_t probe_key_len;
        create_block_height_key(current_height, probe_key, &probe_key_len);
        size_t probe_len = 0;
        char *err_probe = NULL;
        char *probe = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                                  (char *)probe_key, probe_key_len, &probe_len, &err_probe);
        if (err_probe) {
            MXD_LOG_WARN("db", "rocksdb_get(advance probe height=%u) failed: %s", current_height, err_probe);
            free(err_probe);
            if (probe) { free(probe); probe = NULL; }
        }
        if (probe) {
            free(probe);
            current_height++;
            uint32_t h_be = htonl(current_height);
            char *err_h = NULL;
            rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                        "current_height", 14, (char *)&h_be, sizeof(h_be), &err_h);
            if (err_h) {
                MXD_LOG_WARN("db", "rocksdb_put(advance current_height=%u) failed: %s", current_height, err_h);
                free(err_h);
            }
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&height_mutex);
    if (current_height > start) {
        MXD_LOG_INFO("db", "Advanced height pointer from %u to %u (%u blocks)",
                     start, current_height, current_height - start);
    }
}

const char *mxd_get_blockchain_db_path(void) {
    return db_path_global;
}
