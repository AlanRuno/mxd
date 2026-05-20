/*
 * test_fork_choice.c — v7.1 deterministic fork-choice rule tests.
 *
 * Tests:
 *   1. A has quorum (4 of 5), B has 3 — A wins.
 *   2. A has 3 sigs, B has 2 — A wins (sig count).
 *   3. A and B both have 3 sigs but different hash — lower hash wins.
 *   4. Same hash — equal (return 0).
 */

#include "../include/mxd_fork_choice.h"
#include "../include/mxd_blockchain.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Build a minimal block with just the fields fork-choice cares about. */
static void make_block(mxd_block_t *blk, const uint8_t hash_byte_0, uint32_t validation_count,
                       uint32_t rapid_membership_count) {
    memset(blk, 0, sizeof(*blk));
    blk->version = 7;
    blk->height = 1;
    blk->validation_count = validation_count;
    blk->rapid_membership_count = rapid_membership_count;
    /* Distinct hash by setting the first byte. */
    for (int i = 0; i < 64; i++) blk->block_hash[i] = (uint8_t)(hash_byte_0 + i);
}

static void test_quorum_first(void) {
    TEST_START("rule 1: quorum first (A 4-of-5, B 3-of-5 → A wins)");
    mxd_block_t a, b;
    make_block(&a, 0x10, 4, 5);  /* 4 sigs of 5 = at quorum */
    make_block(&b, 0x20, 3, 5);  /* 3 sigs of 5 = below quorum */
    int cmp = mxd_compare_forks(&a, &b);
    printf("  cmp(a,b) = %d (expected <0, A wins)\n", cmp);
    TEST_ASSERT(cmp < 0, "A wins on quorum");

    int cmp2 = mxd_compare_forks(&b, &a);
    printf("  cmp(b,a) = %d (expected >0, A still wins)\n", cmp2);
    TEST_ASSERT(cmp2 > 0, "symmetry: B loses to A");
    TEST_END("rule 1: quorum first");
}

static void test_sig_count(void) {
    TEST_START("rule 2: sig count (A=3, B=2, neither at quorum → A wins)");
    mxd_block_t a, b;
    make_block(&a, 0x10, 3, 5);  /* 3 sigs, below 4-of-5 quorum */
    make_block(&b, 0x20, 2, 5);
    int cmp = mxd_compare_forks(&a, &b);
    printf("  cmp(a,b) = %d (expected <0, A wins on count)\n", cmp);
    TEST_ASSERT(cmp < 0, "A wins on sig count");
    TEST_END("rule 2: sig count");
}

static void test_hash_tiebreak(void) {
    TEST_START("rule 3: hash tiebreak (lower hash wins)");
    mxd_block_t a, b;
    make_block(&a, 0x10, 3, 5);   /* both below quorum */
    make_block(&b, 0x20, 3, 5);   /* tied on sigs */
    int cmp = mxd_compare_forks(&a, &b);
    printf("  cmp(a,b) = %d (expected <0, A's hash 0x10 < B's 0x20)\n", cmp);
    TEST_ASSERT(cmp < 0, "lower hash wins");

    /* Reverse — B has lower hash now. */
    make_block(&a, 0x80, 3, 5);
    make_block(&b, 0x40, 3, 5);
    cmp = mxd_compare_forks(&a, &b);
    printf("  cmp(a,b) = %d (expected >0, B's hash 0x40 < A's 0x80)\n", cmp);
    TEST_ASSERT(cmp > 0, "lower hash wins (other direction)");
    TEST_END("rule 3: hash tiebreak");
}

static void test_same_block(void) {
    TEST_START("rule 4: same hash → return 0");
    mxd_block_t a, b;
    make_block(&a, 0x10, 3, 5);
    make_block(&b, 0x10, 3, 5);   /* identical hash */
    int cmp = mxd_compare_forks(&a, &b);
    printf("  cmp(a,b) = %d (expected 0)\n", cmp);
    TEST_ASSERT(cmp == 0, "same hash returns 0");
    TEST_END("rule 4: same hash");
}

static void test_quorum_threshold(void) {
    TEST_START("quorum threshold formula");
    printf("  quorum_threshold values: 3=%u 4=%u 5=%u 6=%u 7=%u\n",
           mxd_quorum_threshold(3), mxd_quorum_threshold(4),
           mxd_quorum_threshold(5), mxd_quorum_threshold(6),
           mxd_quorum_threshold(7));
    TEST_ASSERT(mxd_quorum_threshold(5) == 4, "5 validators → 4 sigs quorum (per v7.1 dispatch)");
    TEST_END("quorum threshold formula");
}

int main(void) {
    test_quorum_threshold();
    test_quorum_first();
    test_sig_count();
    test_hash_tiebreak();
    test_same_block();
    printf("\nAll fork-choice tests passed.\n");
    return 0;
}
