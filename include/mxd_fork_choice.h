#ifndef MXD_FORK_CHOICE_H
#define MXD_FORK_CHOICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include <stdint.h>

/*
 * v7.1 fork-choice + reorg.
 *
 * Hierarchical fork-choice rule (deterministic; identical on every node):
 *   1. Quorum first.    A "at quorum" iff validation_count >= ceil(2N/3)
 *                       (5 validators -> 4 sigs). Matches MXD-CONS-02 §3.1
 *                       and the existing mxd_block_has_quorum formula
 *                       (2N+2)/3. If A has quorum and B does not, A wins.
 *                       Symmetric for B.
 *   2. Else, sig count. More validation_count wins.
 *   3. Else (sig-tied), lower block_hash (lex-smaller, bytewise memcmp) wins.
 *
 * Return values match qsort()-style: <0 if A wins, >0 if B wins, 0 only if
 * the blocks are byte-identical at the fork-choice level (same hash). Different
 * hashes always break ties via rule 3, so a return of 0 means they are equal.
 */

#define MXD_MAX_REORG_DEPTH 10

int mxd_compare_forks(const mxd_block_t *a, const mxd_block_t *b);

/*
 * Walk back through prev_hash pointers in stored blocks to find the deepest
 * common ancestor of (height_a, hash_a) and (height_b, hash_b).
 *
 * Both forks must share genesis at height 0 — this function fails (returns -1)
 * only on disk error or if a referenced parent is missing from storage.
 *
 * On success, *out_height = height of common ancestor and out_hash[0..63] is
 * its block_hash.
 */
int mxd_find_common_ancestor(uint32_t height_a, const uint8_t hash_a[64],
                             uint32_t height_b, const uint8_t hash_b[64],
                             uint32_t *out_height, uint8_t out_hash[64]);

/*
 * Compute the reorg depth (current head height minus common ancestor height)
 * if we were to switch the canonical head from current to candidate.
 * Returns -1 on failure (e.g. genesis untouchable, missing parents).
 * 0 means no reorg needed (already same fork).
 */
int mxd_compute_reorg_depth(const mxd_block_t *current_head,
                            const mxd_block_t *candidate);

/*
 * Quorum threshold for a given validator set size N: ceil(2/3 * N) + 1.
 */
uint32_t mxd_quorum_threshold(uint32_t validator_count);

#ifdef __cplusplus
}
#endif

#endif // MXD_FORK_CHOICE_H
