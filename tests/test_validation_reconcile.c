/*
 * test_validation_reconcile.c — validation-chain reconciliation (catch-up of
 * validator signatures from peers) must converge without turning into a
 * permanent request/reject loop.
 *
 * Background (mainnet 2026-10/11): blocks produced while a validator in the
 * signing order was offline (identity rotation, rolling restart) never collect
 * a quorum on ANY node — the sequential chain cannot skip a position. The
 * reconciliation pass re-requested their chains from every peer every ~30 s
 * and rejected every answer (the same short chain, or a divergent one from a
 * competing proposal that shares the block hash), forever.
 *
 * Covered here:
 *   1. mxd_validation_chain_extends_local — prefix compatibility of a peer chain.
 *   2. mxd_reconcile_select_blocks — only below-quorum blocks inside the
 *      lookback window are selected, newest first, each (height, hash) with
 *      exponential backoff capped at MXD_RECONCILE_MAX_BACKOFF_MS; the state is
 *      dropped once the block reaches quorum and by mxd_reconcile_reset_state.
 */

#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain_sync.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DB_PATH "test_validation_reconcile_db"

static void remove_stale_db(void) {
    if (system("rm -rf " DB_PATH) != 0) {
        printf("warning: could not remove stale test database\n");
    }
}

/* Attach `n` dummy signatures (validator 0xA0+i, 64-byte signature 0x50+i). */
static void attach_sigs(mxd_block_t *b, uint32_t n) {
    free(b->validation_chain);
    b->validation_chain = NULL;
    b->validation_capacity = 0;
    b->validation_count = 0;
    if (n == 0) return;
    b->validation_chain = calloc(n, sizeof(mxd_validator_signature_t));
    TEST_ASSERT(b->validation_chain != NULL, "alloc validation chain");
    b->validation_capacity = n;
    b->validation_count = n;
    for (uint32_t i = 0; i < n; i++) {
        mxd_validator_signature_t *s = &b->validation_chain[i];
        memset(s->validator_id, 0xA0 + i, 32);
        s->timestamp = 1000000ULL + i;
        s->algo_id = 1;
        s->signature_length = 64;
        memset(s->signature, 0x50 + i, 64);
        s->chain_position = i;
    }
}

/* Copy a block's chain into a standalone array (a "peer chain"). */
static mxd_validator_signature_t *copy_chain(const mxd_block_t *b, uint32_t *count) {
    *count = b->validation_count;
    mxd_validator_signature_t *out = calloc(b->validation_count > 0 ? b->validation_count : 1,
                                            sizeof(mxd_validator_signature_t));
    TEST_ASSERT(out != NULL, "alloc peer chain");
    if (b->validation_count > 0) {
        memcpy(out, b->validation_chain, b->validation_count * sizeof(mxd_validator_signature_t));
    }
    return out;
}

/* ---------------------------------------------------------------------------
 * 1. Peer-chain prefix compatibility
 * ------------------------------------------------------------------------- */

static void test_extends_local(void) {
    TEST_START("extends_local: prefix-compatible peer chains vs divergent ones");

    mxd_block_t local;
    memset(&local, 0, sizeof(local));
    local.height = 47;
    attach_sigs(&local, 2);

    /* Peer chain with three positions whose first two equal ours. */
    mxd_block_t longer;
    memset(&longer, 0, sizeof(longer));
    attach_sigs(&longer, 3);
    uint32_t n = 0;
    mxd_validator_signature_t *peer = copy_chain(&longer, &n);
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 1, "same prefix + one more position extends ours");
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, 2) == 1, "identical chain is compatible");
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, 1) == 1, "shorter prefix is compatible (nothing to add)");
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, 0) == 1, "empty peer chain is compatible");

    /* Different proposer at position 0 (competing proposal, same block hash). */
    memset(peer[0].validator_id, 0xEE, 32);
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 0, "different validator at position 0 diverges");
    free(peer);

    /* Same validators, different signature bytes at position 1. */
    peer = copy_chain(&longer, &n);
    peer[1].signature[10] ^= 0xFF;
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 0, "different signature bytes diverge");
    free(peer);

    /* Same validators and bytes, but mislabelled positions. */
    peer = copy_chain(&longer, &n);
    peer[2].chain_position = 7;
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 0, "non-sequential chain_position beyond our prefix diverges");
    peer[2].chain_position = 2;
    peer[0].chain_position = 1;
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 0, "non-sequential chain_position inside our prefix diverges");
    free(peer);

    /* Signature length mismatch at a shared position. */
    peer = copy_chain(&longer, &n);
    peer[0].signature_length = 32;
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, peer, n) == 0, "signature length mismatch diverges");
    free(peer);

    /* Bad input. */
    TEST_ASSERT(mxd_validation_chain_extends_local(NULL, longer.validation_chain, n) == -1, "NULL local is an error");
    TEST_ASSERT(mxd_validation_chain_extends_local(&local, NULL, 3) == -1, "NULL sigs with count > 0 is an error");

    /* Local block with no signatures accepts any well-formed chain. */
    mxd_block_t empty;
    memset(&empty, 0, sizeof(empty));
    TEST_ASSERT(mxd_validation_chain_extends_local(&empty, longer.validation_chain, n) == 1, "empty local chain is extended by any sequential chain");

    mxd_free_block(&local);
    mxd_free_block(&longer);
    TEST_END("extends_local");
}

/* ---------------------------------------------------------------------------
 * 2. Selection with backoff (DB-backed)
 * ------------------------------------------------------------------------- */

#define CHAIN_LEN 12   /* heights 0..11, current_height (count) = 12 */
#define QUORUM    4

static uint32_t sigs_for_height(uint32_t h) {
    if (h == 1) return 0;   /* below quorum but outside a 10-block window */
    if (h == 3) return 1;   /* below quorum, inside the window */
    if (h == 7) return 1;   /* below quorum, inside the window */
    return QUORUM;          /* at quorum */
}

static int build_chain(void) {
    uint8_t prev[64] = {0};
    for (uint32_t h = 0; h < CHAIN_LEN; h++) {
        mxd_block_t b;
        memset(&b, 0, sizeof(b));
        if (mxd_init_block(&b, prev) != 0) return -1;
        b.version = 8;
        b.height = h;
        b.timestamp = 1000000ULL + h;
        b.nonce = h;
        if (mxd_calculate_block_hash(&b, b.block_hash) != 0) { mxd_free_block(&b); return -1; }
        attach_sigs(&b, sigs_for_height(h));
        if (mxd_store_block(&b) != 0) { mxd_free_block(&b); return -1; }
        memcpy(prev, b.block_hash, 64);
        mxd_free_block(&b);
    }
    return 0;
}

static uint32_t select_at(uint64_t now_ms, uint32_t lookback, uint32_t max,
                          uint32_t *heights, uint8_t (*hashes)[64]) {
    return mxd_reconcile_select_blocks(lookback, QUORUM, now_ms, heights, hashes, max);
}

static void test_select_window_and_order(void) {
    TEST_START("select: below-quorum blocks inside the window, newest first; attempts recorded");
    mxd_reconcile_reset_state();

    uint32_t heights[8];
    uint8_t hashes[8][64];
    uint64_t t0 = 1000000000ULL;

    uint32_t n = select_at(t0, 10, 8, heights, hashes);
    printf("  first pass selected %u block(s): %u %u\n", n, n > 0 ? heights[0] : 0, n > 1 ? heights[1] : 0);
    TEST_ASSERT(n == 2, "two blocks below quorum inside the 10-block window");
    TEST_ASSERT(heights[0] == 7 && heights[1] == 3, "newest first: 7 then 3 (height 1 is outside the window)");

    mxd_block_t b7;
    memset(&b7, 0, sizeof(b7));
    TEST_ASSERT(mxd_retrieve_block_by_height(7, &b7) == 0, "read block 7");
    TEST_ASSERT(memcmp(hashes[0], b7.block_hash, 64) == 0, "hash of the selected block is returned");
    mxd_free_block(&b7);

    /* A pass right after selection must not re-request: backoff is pending. */
    TEST_ASSERT(select_at(t0 + 1000, 10, 8, heights, hashes) == 0, "no re-request 1 s later");
    TEST_ASSERT(select_at(t0 + MXD_RECONCILE_BASE_BACKOFF_MS - 1, 10, 8, heights, hashes) == 0, "no re-request just before the base backoff");

    /* A window of one height (the stored tip has quorum) selects nothing. */
    mxd_reconcile_reset_state();
    TEST_ASSERT(select_at(t0, 1, 8, heights, hashes) == 0, "lookback 1 covers only the (missing) count height");
    TEST_ASSERT(select_at(t0, 2, 8, heights, hashes) == 0, "lookback 2 covers the tip, which is at quorum");

    /* `max` caps the pass and only returned blocks are charged an attempt. */
    mxd_reconcile_reset_state();
    TEST_ASSERT(select_at(t0, 10, 1, heights, hashes) == 1 && heights[0] == 7, "max=1 returns only the newest");
    TEST_ASSERT(select_at(t0, 10, 8, heights, hashes) == 1 && heights[0] == 3, "the block not returned before is still due");
    TEST_ASSERT(select_at(t0, 10, 8, heights, hashes) == 0, "both are now backed off");

    TEST_END("select: window and order");
}

static void test_select_backoff_schedule(void) {
    TEST_START("select: exponential backoff per block, capped at MXD_RECONCILE_MAX_BACKOFF_MS");
    mxd_reconcile_reset_state();

    uint32_t heights[8];
    uint8_t hashes[8][64];
    uint64_t t = 2000000000ULL;

    TEST_ASSERT(select_at(t, 10, 8, heights, hashes) == 2, "attempt 1 immediate");

    uint64_t gap = MXD_RECONCILE_BASE_BACKOFF_MS;
    for (int attempt = 2; attempt <= 10; attempt++) {
        TEST_ASSERT(select_at(t + gap - 1, 10, 8, heights, hashes) == 0, "nothing due just before the backoff elapses");
        t += gap;
        uint32_t n = select_at(t, 10, 8, heights, hashes);
        printf("  attempt %d after %llu s: selected %u\n", attempt, (unsigned long long)(gap / 1000), n);
        TEST_ASSERT(n == 2, "both blocks due again once the backoff elapses");
        gap *= 2;
        if (gap > MXD_RECONCILE_MAX_BACKOFF_MS) gap = MXD_RECONCILE_MAX_BACKOFF_MS;
    }
    TEST_ASSERT(gap == MXD_RECONCILE_MAX_BACKOFF_MS, "schedule reached the hourly cap");

    /* Still retried at the cap — convergence remains eventual. */
    TEST_ASSERT(select_at(t + MXD_RECONCILE_MAX_BACKOFF_MS - 1, 10, 8, heights, hashes) == 0, "capped: nothing before an hour");
    TEST_ASSERT(select_at(t + MXD_RECONCILE_MAX_BACKOFF_MS, 10, 8, heights, hashes) == 2, "capped: retried after an hour");

    TEST_END("select: backoff schedule");
}

static void test_select_quorum_and_reset(void) {
    TEST_START("select: reaching quorum drops the block; reset forgets the backoff");
    mxd_reconcile_reset_state();

    uint32_t heights[8];
    uint8_t hashes[8][64];
    uint64_t t = 3000000000ULL;

    TEST_ASSERT(select_at(t, 10, 8, heights, hashes) == 2, "both selected once");

    /* Block 7 catches up to quorum (same hash → idempotent re-store). */
    mxd_block_t b7;
    memset(&b7, 0, sizeof(b7));
    TEST_ASSERT(mxd_retrieve_block_by_height(7, &b7) == 0, "read block 7");
    attach_sigs(&b7, QUORUM);
    TEST_ASSERT(mxd_store_block(&b7) == 0, "re-store block 7 with a quorum of signatures");
    mxd_free_block(&b7);

    t += MXD_RECONCILE_MAX_BACKOFF_MS;   /* far enough for any backoff to elapse */
    uint32_t n = select_at(t, 10, 8, heights, hashes);
    printf("  after block 7 reached quorum: selected %u (height %u)\n", n, n ? heights[0] : 0);
    TEST_ASSERT(n == 1 && heights[0] == 3, "only block 3 remains below quorum");

    /* Reset forgets the backoff: block 3 is due again immediately. */
    TEST_ASSERT(select_at(t + 1, 10, 8, heights, hashes) == 0, "block 3 backed off after its request");
    mxd_reconcile_reset_state();
    TEST_ASSERT(select_at(t + 2, 10, 8, heights, hashes) == 1 && heights[0] == 3, "reset: block 3 requested again at once");

    TEST_END("select: quorum and reset");
}

int main(void) {
    printf("=== Validation-chain reconciliation tests ===\n");

    test_extends_local();

    remove_stale_db();
    if (mxd_init_blockchain_db(DB_PATH) != 0) {
        printf("FATAL: could not init blockchain DB\n");
        return 1;
    }
    if (build_chain() != 0) {
        printf("FATAL: could not build the test chain\n");
        mxd_close_blockchain_db();
        return 1;
    }

    test_select_window_and_order();
    test_select_backoff_schedule();
    test_select_quorum_and_reset();

    mxd_close_blockchain_db();
    remove_stale_db();
    printf("\nAll validation-chain reconciliation tests passed.\n");
    return 0;
}
