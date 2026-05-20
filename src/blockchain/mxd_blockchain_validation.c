#include "../../include/mxd_rsc.h"
#include "../../include/mxd_logging.h"

#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_p2p.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_endian.h"
#include "../../include/mxd_protocol_version.h"
#include "../../include/mxd_domain_tags.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int mxd_init_block_with_validation(mxd_block_t *block, const uint8_t prev_hash[64],
                                  const uint8_t proposer_id[32], uint32_t height) {
    if (!block || !prev_hash || !proposer_id) {
        return -1;
    }

    if (mxd_init_block(block, prev_hash) != 0) {
        return -1;
    }

    memcpy(block->proposer_id, proposer_id, 32);   // v6: addr32
    block->height = height;

    // Set protocol version based on height and network
    mxd_network_type_t network = mxd_get_network_type();
    uint32_t required_version = mxd_get_required_protocol_version(height, network);
    block->version = required_version;

    MXD_LOG_DEBUG("blockchain", "Initialized block at height %u with protocol v%u",
                  height, required_version);

    block->validation_count = 0;
    block->validation_capacity = 10; // Initial capacity for 10 validators
    block->validation_chain = malloc(block->validation_capacity * sizeof(mxd_validator_signature_t));

    if (!block->validation_chain) {
        return -1;
    }

    return 0;
}

int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[32],
                              uint64_t timestamp, uint8_t algo_id, const uint8_t *signature, uint16_t signature_length) {
    if (!block || !validator_id || !signature) {
        return -1;
    }
    if (signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    // Validate algo_id
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        return -1;
    }
    
    // Validate signature length matches algorithm
    size_t expected_sig_len = mxd_sig_signature_len(algo_id);
    if (signature_length != expected_sig_len) {
        return -1;
    }

    if (block->validation_count >= block->validation_capacity) {
        uint32_t new_capacity = block->validation_capacity * 2;
        mxd_validator_signature_t *new_chain = realloc(block->validation_chain,
                                                     new_capacity * sizeof(mxd_validator_signature_t));
        if (!new_chain) {
            return -1;
        }

        block->validation_chain = new_chain;
        block->validation_capacity = new_capacity;
    }

    mxd_validator_signature_t *sig = &block->validation_chain[block->validation_count];
    memcpy(sig->validator_id, validator_id, 32);   // v6: addr32
    sig->timestamp = timestamp;
    sig->algo_id = algo_id;
    sig->signature_length = signature_length;
    memcpy(sig->signature, signature, signature_length);
    sig->chain_position = block->validation_count;

    block->validation_count++;

    // Update validator's metrics in the rapid table
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (table) {
        char vid_hex[65] = {0};   // v6: addr32 = 64 hex chars + NUL
        for (int j = 0; j < 32; j++) snprintf(vid_hex + j*2, 3, "%02x", validator_id[j]);
        MXD_LOG_INFO("rsc", "Metrics update: looking for validator %s in table (count=%zu)", vid_hex, table->count);

        mxd_node_stake_t *validator_node = mxd_get_node_by_address(table, validator_id);
        if (validator_node) {
            // Response time = time from block creation to signature
            // Note: block->timestamp is in seconds, signature timestamp is in milliseconds
            uint64_t block_ts_ms = block->timestamp * 1000;
            uint64_t response_time = (timestamp > block_ts_ms) ?
                                     (timestamp - block_ts_ms) : 0;
            mxd_update_node_metrics(validator_node, response_time, timestamp);
            MXD_LOG_INFO("rsc", "Metrics updated for validator %s: response_count=%u, response_time=%llu",
                         vid_hex, validator_node->metrics.response_count, (unsigned long long)response_time);
        } else {
            MXD_LOG_WARN("rsc", "Metrics update: validator %s NOT FOUND in rapid table", vid_hex);
        }
    } else {
        MXD_LOG_WARN("rsc", "Metrics update: rapid table is NULL");
    }

    return 0;
}

int mxd_verify_validation_chain(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return -1;
    }

    for (uint32_t i = 0; i < block->validation_count; i++) {
        const mxd_validator_signature_t *sig_i = &block->validation_chain[i];

        if (sig_i->chain_position != i) {
            return -1;
        }

        uint64_t now = mxd_now_ms() / 1000; // NTP-synchronized time in seconds
        if (sig_i->timestamp > now + 60 || sig_i->timestamp + 60 < now) {
            // F7-3: log the actual delta so operators can diagnose clock drift
            // from the journal without re-running the validator under a debugger.
            int64_t delta = (int64_t)sig_i->timestamp - (int64_t)now;
            MXD_LOG_WARN("validation",
                         "Validation chain[%u] timestamp out of ±60s window: "
                         "sig.timestamp=%llu now=%llu delta=%lld s (likely clock drift; check NTP)",
                         i,
                         (unsigned long long)sig_i->timestamp,
                         (unsigned long long)now,
                         (long long)delta);
            return -1;
        }

        for (uint32_t j = i + 1; j < block->validation_count; j++) {
            const mxd_validator_signature_t *sig_j = &block->validation_chain[j];
            if (memcmp(sig_i->validator_id, sig_j->validator_id, 32) == 0) {
                return -1;
            }
        }

        // v7 canonical: MXD-CONS-1 (11) || block_hash(64) || chain_hash(64) || ts_be(8) = 147 bytes
        // chain_hash is the strong cumulative commitment to all prior signatures
        // (chain_hash_0 = SHA-512(block_hash); chain_hash_N = SHA-512(prev_chain_hash || prev_signature_bytes)).
        // This matches the shape produced by both signers — the proposer at
        // mxd_rsc.c:732-735 and the chain follower at mxd_blockchain_sync.c:1411+.
        uint8_t chain_hash[64];
        mxd_compute_chain_hash(block, sig_i->chain_position, chain_hash);

        uint8_t msg[MXD_DOMAIN_TAG_CONS_LEN + 64 + 64 + 8];
        size_t mo = 0;
        memcpy(msg + mo, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); mo += MXD_DOMAIN_TAG_CONS_LEN;
        memcpy(msg + mo, block->block_hash, 64); mo += 64;
        memcpy(msg + mo, chain_hash, 64); mo += 64;
        // big-endian encoding for timestamp (consistent with rest of codebase)
        uint64_t ts_be = mxd_htonll(sig_i->timestamp);
        memcpy(msg + mo, &ts_be, 8); mo += 8;

        uint8_t pubbuf[4096];
        size_t publen = 0;
        if (mxd_get_validator_public_key(sig_i->validator_id, pubbuf, sizeof(pubbuf), &publen) != 0) {
            return -1;
        }

        uint8_t algo_id = sig_i->algo_id;
        
        // Validate algo_id
        if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
            return -1;
        }

        if (mxd_sig_verify(algo_id, sig_i->signature, sig_i->signature_length, msg, sizeof(msg), pubbuf) != 0) {
            return -1;
        }
    }

    return 0;
}

int mxd_block_has_quorum(const mxd_block_t *block) {
    if (!block || !block->validation_chain) {
        return 0;
    }

    uint32_t quorum_threshold = 0;

    // Use 2/3 supermajority for BFT-safe quorum (matches membership quorum)
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_rapid_table_peers(peers, &peer_count) == 0 && peer_count > 0) {
        quorum_threshold = (uint32_t)((peer_count * 2 + 2) / 3);
    } else {
        // Fallback to reasonable default if rapid table not available
        uint32_t rapid_table_size = 6;
        quorum_threshold = (uint32_t)((rapid_table_size * 2 + 2) / 3);
    }

    if (quorum_threshold < 1) quorum_threshold = 1;

    return (block->validation_count >= quorum_threshold) ? 1 : 0;
}

int mxd_block_has_min_signatures(const mxd_block_t *block) {
    if (!block || !block->validation_chain) {
        return 0;
    }
    
    const uint32_t min_signatures = 3;
    
    return (block->validation_count >= min_signatures) ? 1 : 0;
}

int mxd_resolve_fork(const mxd_block_t *block1, const mxd_block_t *block2) {
    if (!block1 || !block2) {
        return 0;
    }
    
    if (block1->validation_count > block2->validation_count) {
        return 1;  // block1 wins
    } else if (block2->validation_count > block1->validation_count) {
        return -1; // block2 wins
    }
    
    double score1 = mxd_calculate_validation_latency_score(block1, NULL);
    double score2 = mxd_calculate_validation_latency_score(block2, NULL);
    
    if (score1 > score2) {
        return 1;  // block1 wins
    } else if (score2 > score1) {
        return -1; // block2 wins
    }
    
    int cmp = memcmp(block1->block_hash, block2->block_hash, 64);
    return cmp;
}

double mxd_calculate_latency_score(const mxd_block_t *block) {
    return mxd_calculate_validation_latency_score(block, NULL);
}


void mxd_free_validation_chain(mxd_block_t *block) {
    if (block && block->validation_chain) {
        free(block->validation_chain);
        block->validation_chain = NULL;
        block->validation_count = 0;
        block->validation_capacity = 0;
    }
    if (block && block->rapid_membership_entries) {
        free(block->rapid_membership_entries);
        block->rapid_membership_entries = NULL;
        block->rapid_membership_count = 0;
        block->rapid_membership_capacity = 0;
    }
    if (block && block->validator_scores) {
        free(block->validator_scores);
        block->validator_scores = NULL;
        block->validator_scores_count = 0;
        block->validator_scores_capacity = 0;
    }
}
