#include "../../include/mxd_rsc.h"

#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_p2p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int mxd_init_block_with_validation(mxd_block_t *block, const uint8_t prev_hash[64], 
                                  const uint8_t proposer_id[20], uint32_t height) {
    if (!block || !prev_hash || !proposer_id) {
        return -1;
    }
    
    if (mxd_init_block(block, prev_hash) != 0) {
        return -1;
    }
    
    memcpy(block->proposer_id, proposer_id, 20);
    block->height = height;
    
    block->validation_count = 0;
    block->validation_capacity = 10; // Initial capacity for 10 validators
    block->validation_chain = malloc(block->validation_capacity * sizeof(mxd_validator_signature_t));
    
    if (!block->validation_chain) {
        return -1;
    }
    
    return 0;
}

int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[20],
                              uint64_t timestamp, const uint8_t *signature, uint16_t signature_length) {
    if (!block || !validator_id || !signature) {
        return -1;
    }
    if (signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
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
    memcpy(sig->validator_id, validator_id, 20);
    sig->timestamp = timestamp;
    sig->signature_length = signature_length;
    memcpy(sig->signature, signature, signature_length);
    sig->chain_position = block->validation_count;

    block->validation_count++;

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

        time_t now = time(NULL);
        if (sig_i->timestamp > (uint64_t)(now + 60) || sig_i->timestamp + 60 < (uint64_t)now) {
            return -1;
        }

        for (uint32_t j = i + 1; j < block->validation_count; j++) {
            const mxd_validator_signature_t *sig_j = &block->validation_chain[j];
            if (memcmp(sig_i->validator_id, sig_j->validator_id, 20) == 0) {
                return -1;
            }
        }

        uint8_t msg[64 + 20 + 8];
        memcpy(msg, block->block_hash, 64);
        if (i == 0) {
            memset(msg + 64, 0, 20);
        } else {
            memcpy(msg + 64, block->validation_chain[i - 1].validator_id, 20);
        }
        uint64_t ts = sig_i->timestamp;
        for (int b = 0; b < 8; b++) {
            msg[64 + 20 + b] = (uint8_t)((ts >> (8 * b)) & 0xFF);
        }

        uint8_t pubbuf[4096];
        size_t publen = 0;
        if (mxd_get_validator_public_key(sig_i->validator_id, pubbuf, sizeof(pubbuf), &publen) != 0) {
            return -1;
        }

        if (mxd_dilithium_verify(sig_i->signature, (size_t)sig_i->signature_length, msg, sizeof(msg), pubbuf) != 0) {
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

    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_rapid_table_peers(peers, &peer_count) == 0 && peer_count > 0) {
        quorum_threshold = (uint32_t)(peer_count / 2);
    } else {
        uint32_t rapid_table_size = 6;
        if (block->validation_capacity > 0) {
            rapid_table_size = block->validation_capacity;
        }
        quorum_threshold = (uint32_t)(rapid_table_size / 2);
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
}
