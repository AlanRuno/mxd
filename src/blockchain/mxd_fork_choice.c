/*
 * mxd_fork_choice.c — v7.1 deterministic fork-choice rule.
 *
 * Per the v7.1 dispatch (2026-05-08):
 *   1. Quorum first.    A "at quorum" iff validation_count >= ceil(2/3*N)+1.
 *      With 5 validators -> 4 sigs.
 *   2. Else, sig count. More validation_count wins.
 *   3. Else (sig-tied), lower block_hash (lex-smaller, bytewise memcmp) wins.
 */

#include "../../include/mxd_fork_choice.h"
#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_blockchain_db.h"
#include "../../include/mxd_rsc.h"
#include "../../include/mxd_logging.h"

#include <string.h>
#include <stdlib.h>

uint32_t mxd_quorum_threshold(uint32_t validator_count) {
    /* Quorum = ceil(2/3 * N), matching the live mxd_block_has_quorum
     * formula at mxd_blockchain_validation.c:200: (peer_count*2 + 2) / 3.
     *
     *   N=3 -> 8/3   = 2  (note: BFT-unsafe — only 2 of 3)
     *   N=4 -> 10/3  = 3
     *   N=5 -> 12/3  = 4  ← matches v7.1 dispatch's "4 of 5"
     *   N=6 -> 14/3  = 4
     *   N=7 -> 16/3  = 5
     *
     * This is the 2/3 BFT supermajority (deterministic across nodes).
     */
    if (validator_count == 0) return 1;
    uint32_t q = (validator_count * 2 + 2) / 3;
    if (q < 1) q = 1;
    return q;
}

/*
 * Determine the validator-set size relevant for `block`.
 *
 * Preference order:
 *   1. block->rapid_membership_count if non-zero (from-block snapshot, v6+).
 *   2. block->validator_scores_count if non-zero (v4+ on-chain set).
 *   3. live mxd_get_rapid_table()->count (current peer set).
 *   4. Hardcoded 5 for testnet/mainnet (defensive default).
 *
 * Conservative: if validator_count is unknown we'd rather under-estimate (no
 * quorum claim) than declare quorum on a weak block. Use the largest of the
 * three sources to avoid that.
 */
static uint32_t infer_validator_count(const mxd_block_t *block) {
    uint32_t n = 0;

    if (block) {
        if (block->rapid_membership_count > n) n = block->rapid_membership_count;
        if (block->validator_scores_count > n) n = block->validator_scores_count;
    }

    const mxd_rapid_table_t *t = mxd_get_rapid_table();
    if (t && t->count > 0 && (uint32_t)t->count > n) n = (uint32_t)t->count;

    if (n == 0) n = 5;  /* sensible default for the live testnet */
    return n;
}

static int block_at_quorum(const mxd_block_t *block) {
    if (!block) return 0;
    uint32_t n = infer_validator_count(block);
    uint32_t threshold = mxd_quorum_threshold(n);
    return (block->validation_count >= threshold) ? 1 : 0;
}

int mxd_compare_forks(const mxd_block_t *a, const mxd_block_t *b) {
    if (!a && !b) return 0;
    if (!a) return 1;   /* B wins (A is null) */
    if (!b) return -1;  /* A wins */

    /* Identity check: byte-equal block_hash means same block. */
    if (memcmp(a->block_hash, b->block_hash, 64) == 0) return 0;

    /* Rule 1: quorum first. */
    int a_q = block_at_quorum(a);
    int b_q = block_at_quorum(b);
    if (a_q && !b_q) return -1;
    if (b_q && !a_q) return 1;

    /* Rule 2: more sigs wins. */
    if (a->validation_count > b->validation_count) return -1;
    if (b->validation_count > a->validation_count) return 1;

    /* Rule 3: tie-break on lower block_hash. */
    int cmp = memcmp(a->block_hash, b->block_hash, 64);
    /* memcmp returns negative if a<b. Lower hash wins -> a wins -> return <0. */
    return cmp;
}

/*
 * Walk back through the prev_hash chain. Both forks must descend from genesis;
 * we stop on the first hash that appears in both walks.
 *
 * Strategy:
 *   1. Build a set of (height, hash) pairs along chain A back to height 0.
 *   2. Walk chain B; first hash in the set is the ancestor.
 *
 * Genesis (height 0) is always a common ancestor — both chains end there.
 */
typedef struct {
    uint32_t height;
    uint8_t  hash[64];
} ancestor_entry_t;

int mxd_find_common_ancestor(uint32_t height_a, const uint8_t hash_a[64],
                             uint32_t height_b, const uint8_t hash_b[64],
                             uint32_t *out_height, uint8_t out_hash[64]) {
    if (!hash_a || !hash_b || !out_height || !out_hash) return -1;

    /* Capacity covers the full ancestor chain — bounded by max(height_a, height_b)+1. */
    uint32_t cap = (height_a > height_b ? height_a : height_b) + 1;
    if (cap == 0) cap = 1;
    ancestor_entry_t *chain_a = calloc(cap, sizeof(ancestor_entry_t));
    if (!chain_a) return -1;
    uint32_t a_count = 0;

    /* Walk A back to genesis. */
    {
        uint32_t cur_h = height_a;
        uint8_t  cur_hash[64];
        memcpy(cur_hash, hash_a, 64);
        for (;;) {
            chain_a[a_count].height = cur_h;
            memcpy(chain_a[a_count].hash, cur_hash, 64);
            a_count++;
            if (cur_h == 0) break;
            mxd_block_t blk;
            memset(&blk, 0, sizeof(blk));
            if (mxd_retrieve_block_by_hash(cur_hash, &blk) != 0) {
                /* Missing parent — fall back to height-keyed retrieval, which
                 * may return a different block on the canonical fork. That's
                 * OK as long as we eventually hit a hash on both chains. */
                if (mxd_retrieve_block_by_height(cur_h, &blk) != 0) {
                    MXD_LOG_WARN("fork_choice", "Common ancestor walk: missing block at height %u", cur_h);
                    free(chain_a);
                    return -1;
                }
            }
            uint8_t prev_hash[64];
            memcpy(prev_hash, blk.prev_block_hash, 64);
            mxd_free_block(&blk);
            if (cur_h == 0) break;
            cur_h--;
            memcpy(cur_hash, prev_hash, 64);
            if (a_count >= cap) break;  /* safety */
        }
    }

    /* Walk B and look for a hit. */
    {
        uint32_t cur_h = height_b;
        uint8_t  cur_hash[64];
        memcpy(cur_hash, hash_b, 64);
        for (;;) {
            for (uint32_t i = 0; i < a_count; i++) {
                if (chain_a[i].height == cur_h && memcmp(chain_a[i].hash, cur_hash, 64) == 0) {
                    *out_height = cur_h;
                    memcpy(out_hash, cur_hash, 64);
                    free(chain_a);
                    return 0;
                }
            }
            if (cur_h == 0) break;
            mxd_block_t blk;
            memset(&blk, 0, sizeof(blk));
            if (mxd_retrieve_block_by_hash(cur_hash, &blk) != 0) {
                if (mxd_retrieve_block_by_height(cur_h, &blk) != 0) {
                    MXD_LOG_WARN("fork_choice", "Common ancestor walk B: missing block at height %u", cur_h);
                    free(chain_a);
                    return -1;
                }
            }
            uint8_t prev_hash[64];
            memcpy(prev_hash, blk.prev_block_hash, 64);
            mxd_free_block(&blk);
            cur_h--;
            memcpy(cur_hash, prev_hash, 64);
        }
    }

    /* No common ancestor found — should be impossible if both forks descend
     * from genesis. Treat as failure. */
    MXD_LOG_WARN("fork_choice", "No common ancestor between (h=%u) and (h=%u) — orphan forks?",
                 height_a, height_b);
    free(chain_a);
    return -1;
}

int mxd_compute_reorg_depth(const mxd_block_t *current_head,
                            const mxd_block_t *candidate) {
    if (!current_head || !candidate) return -1;
    if (current_head->height == 0 || candidate->height == 0) {
        /* Genesis is hard-special-cased to never reorg. */
        return -1;
    }
    uint32_t anc_h = 0;
    uint8_t anc_hash[64];
    if (mxd_find_common_ancestor(current_head->height, current_head->block_hash,
                                 candidate->height, candidate->block_hash,
                                 &anc_h, anc_hash) != 0) {
        return -1;
    }
    /* Depth = number of blocks demoted from the current canonical head down
     * to (but not including) the common ancestor. */
    if (current_head->height < anc_h) return -1;
    return (int)(current_head->height - anc_h);
}
