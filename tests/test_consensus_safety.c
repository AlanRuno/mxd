/*
 * test_consensus_safety.c — fault-injection tests for the two safe-by-construction
 * consensus fixes that a live BFT mesh structurally cannot exercise:
 *
 *   RISK-1 (equivocation guard): the per-height vote book (mxd_votebook_claim).
 *     A validator must never sign two different blocks at the same height. On a
 *     healthy 6-of-quorum-4 mesh you cannot manufacture a competing CERTIFIED
 *     block to provoke a second vote (4+4 > 6 — the BFT safety property), so the
 *     refusal path is unobservable in production. Here we drive it directly.
 *
 *   RISK-2 (deep-fork recovery): the rollback primitive (mxd_rollback_to_height)
 *     that truncates a losing minority fork to the common ancestor so normal sync
 *     can re-fill the certified winning chain — the escape hatch from the
 *     >MXD_MAX_REORG_DEPTH permanent wedge.
 *
 * These exercise the NOVEL code added for the two fixes. The surrounding reorg
 * glue (mxd_compare_forks, mxd_verify_validation_chain_crypto, common-ancestor
 * search) is covered by test_fork_choice / test_validation_chain and by the live
 * 095b2e92 deploy validation (06-23). See
 * DESIGN_consensus_safe_by_construction_2026-06-22.md.
 */

#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mxd_rsc.h"
#include "mxd_protocol_version.h"
#include "mxd_validator_management.h"
#include "mxd_domain_tags.h"
#include "mxd_crypto.h"
#include "mxd_address.h"

#define DB_PATH "test_consensus_safety_db"

/* The two DB paths must not survive from a previous run: re-storing the deterministic
 * chain over the refilled one is (correctly) rejected by mxd_store_block, and the test
 * would then abort in build_and_store_chain(). ctest always starts from a fresh build
 * tree; this keeps manual re-runs deterministic as well. */
static void remove_stale_dbs(void) {
    if (system("rm -rf " DB_PATH " " DB_PATH "_rb") != 0) {
        printf("warning: could not remove stale test databases\n");
    }
}

static void fill_hash(uint8_t hash[64], uint8_t seed) {
    for (int i = 0; i < 64; i++) hash[i] = (uint8_t)(seed + i);
}

/* ---------------------------------------------------------------------------
 * RISK-1: per-height vote book (mxd_votebook_claim)
 * ------------------------------------------------------------------------- */

static void test_votebook_first_and_idempotent(void) {
    TEST_START("RISK-1: first vote claimed, re-claim of same hash idempotent");
    uint8_t a[64]; fill_hash(a, 0x10);

    int r1 = mxd_votebook_claim(500, a);
    printf("  claim(500, A) = %d (expect 0)\n", r1);
    TEST_ASSERT(r1 == 0, "first vote at a height succeeds");

    int r2 = mxd_votebook_claim(500, a);
    printf("  claim(500, A) again = %d (expect 0, idempotent)\n", r2);
    TEST_ASSERT(r2 == 0, "re-claiming the SAME block at the same height is idempotent");
    TEST_END("RISK-1: first vote + idempotent");
}

static void test_votebook_refuses_equivocation(void) {
    TEST_START("RISK-1: refuses a SECOND DIFFERENT block at the same height");
    uint8_t a[64], b[64];
    fill_hash(a, 0x20);
    fill_hash(b, 0x21);   /* different block hash, same height */

    int r1 = mxd_votebook_claim(600, a);
    TEST_ASSERT(r1 == 0, "claim block A at h=600 succeeds");

    int r2 = mxd_votebook_claim(600, b);
    printf("  claim(600, B) = %d (expect 1 — equivocation refused)\n", r2);
    TEST_ASSERT(r2 == 1, "claiming a DIFFERENT block at h=600 is refused (equivocation)");

    /* The original vote is unchanged and still claimable idempotently. */
    int r3 = mxd_votebook_claim(600, a);
    TEST_ASSERT(r3 == 0, "original vote A still stands after the refused B");
    TEST_END("RISK-1: refuses equivocation");
}

static void test_votebook_heights_independent(void) {
    TEST_START("RISK-1: votes at different heights are independent");
    uint8_t a[64], b[64];
    fill_hash(a, 0x30);
    fill_hash(b, 0x31);
    TEST_ASSERT(mxd_votebook_claim(700, a) == 0, "vote A at h=700");
    TEST_ASSERT(mxd_votebook_claim(701, b) == 0, "a DIFFERENT block at h=701 is fine");
    TEST_END("RISK-1: heights independent");
}

static void test_votebook_persists_across_reopen(void) {
    TEST_START("RISK-1: vote book SURVIVES restart (reorg/restart guarantee)");
    uint8_t a[64], b[64];
    fill_hash(a, 0x40);
    fill_hash(b, 0x41);

    TEST_ASSERT(mxd_votebook_claim(800, a) == 0, "vote A at h=800 before restart");

    /* Simulate a process restart: close and reopen the DB. */
    mxd_close_blockchain_db();
    TEST_ASSERT(mxd_init_blockchain_db(DB_PATH) == 0, "reopen DB (simulated restart)");

    int after = mxd_votebook_claim(800, b);
    printf("  after reopen, claim(800, B) = %d (expect 1 — vote persisted)\n", after);
    TEST_ASSERT(after == 1, "a DIFFERENT block at h=800 is STILL refused after restart");

    TEST_ASSERT(mxd_votebook_claim(800, a) == 0, "the persisted vote A is still ours after restart");
    TEST_END("RISK-1: persists across restart");
}

/* ---------------------------------------------------------------------------
 * RISK-2: rollback-to-ancestor primitive (mxd_rollback_to_height)
 * ------------------------------------------------------------------------- */

/* Build and store a minimal contiguous chain of `n` blocks (heights 0..n-1),
 * each linked by prev_block_hash. Returns 0 on success. */
static int build_and_store_chain(uint32_t n) {
    uint8_t prev[64] = {0};
    for (uint32_t h = 0; h < n; h++) {
        mxd_block_t b;
        memset(&b, 0, sizeof(b));
        if (mxd_init_block(&b, prev) != 0) return -1;
        b.version = 8;
        b.height = h;
        b.timestamp = 1000000ULL + h;
        b.nonce = h;
        if (mxd_calculate_block_hash(&b, b.block_hash) != 0) { mxd_free_block(&b); return -1; }
        if (mxd_store_block(&b) != 0) { mxd_free_block(&b); return -1; }
        memcpy(prev, b.block_hash, 64);
        mxd_free_block(&b);
    }
    return 0;
}

static void test_rollback_truncates_chain(void) {
    TEST_START("RISK-2: rollback_to_height truncates the chain to the target");

    /* Fresh DB for a clean height space. */
    mxd_close_blockchain_db();
    TEST_ASSERT(mxd_init_blockchain_db(DB_PATH "_rb") == 0, "fresh DB for rollback test");

    const uint32_t N = 18;           /* heights 0..17, tip = 17 */
    const uint32_t TARGET = 5;       /* roll back to 5 → demote 12 blocks (> MXD_MAX_REORG_DEPTH=10) */
    TEST_ASSERT(build_and_store_chain(N) == 0, "store a contiguous 18-block chain");

    uint32_t h_before = 0;
    TEST_ASSERT(mxd_get_blockchain_height(&h_before) == 0, "read height before rollback");
    printf("  current_height before = %u (expect %u)\n", h_before, N);
    TEST_ASSERT(h_before == N, "tip is at height N before rollback");
    TEST_ASSERT(mxd_block_exists_at_height(12) == 1, "height 12 present before rollback");

    /* The operation under test — a deep truncate (12 > the 10-block reorg cap). */
    int rc = mxd_rollback_to_height(TARGET);
    printf("  mxd_rollback_to_height(%u) = %d\n", TARGET, rc);
    TEST_ASSERT(rc == 0, "rollback succeeds");

    uint32_t h_after = 0;
    TEST_ASSERT(mxd_get_blockchain_height(&h_after) == 0, "read height after rollback");
    printf("  current_height after = %u (expect %u)\n", h_after, TARGET + 1);
    TEST_ASSERT(h_after == TARGET + 1, "current_height rolled back to target+1");

    /* Heights above the target are emptied (their height keys deleted) so normal
     * forward sync can re-fill them — this is what escapes the permanent wedge. */
    TEST_ASSERT(mxd_block_exists_at_height(TARGET) == 1, "ancestor (target) height retained");
    TEST_ASSERT(mxd_block_exists_at_height(TARGET + 1) == 0, "height target+1 emptied");
    TEST_ASSERT(mxd_block_exists_at_height(12) == 0, "deep height 12 emptied");
    TEST_ASSERT(mxd_block_exists_at_height(N - 1) == 0, "former tip emptied");
    TEST_END("RISK-2: rollback truncates chain");
}

static void test_rollback_then_refill(void) {
    TEST_START("RISK-2: after rollback, the emptied heights re-fill (sim. sync)");

    /* The chain is currently truncated to height 5 (current_height=6) from the
     * previous test. Re-storing the same blocks forward must succeed — this is
     * the 'normal sync re-fills the certified chain' step. */
    uint32_t h = 0;
    TEST_ASSERT(mxd_get_blockchain_height(&h) == 0, "read height");
    TEST_ASSERT(h == 6, "chain is truncated to height 5 (current_height=6)");

    /* Rebuild blocks 5..9 forward from the retained ancestor at height 5. */
    mxd_block_t anc;
    memset(&anc, 0, sizeof(anc));
    TEST_ASSERT(mxd_retrieve_block_by_height(5, &anc) == 0, "retrieve retained ancestor at h=5");
    uint8_t prev[64];
    memcpy(prev, anc.block_hash, 64);
    mxd_free_block(&anc);

    for (uint32_t height = 6; height <= 9; height++) {
        mxd_block_t b;
        memset(&b, 0, sizeof(b));
        TEST_ASSERT(mxd_init_block(&b, prev) == 0, "init refill block");
        b.version = 8;
        b.height = height;
        b.timestamp = 2000000ULL + height;   /* different content than the demoted ones */
        b.nonce = height + 1000;
        TEST_ASSERT(mxd_calculate_block_hash(&b, b.block_hash) == 0, "hash refill block");
        TEST_ASSERT(mxd_store_block(&b) == 0, "store refill block forward");
        memcpy(prev, b.block_hash, 64);
        mxd_free_block(&b);
    }

    uint32_t h2 = 0;
    TEST_ASSERT(mxd_get_blockchain_height(&h2) == 0, "read height after refill");
    printf("  current_height after refill = %u (expect 10)\n", h2);
    TEST_ASSERT(h2 == 10, "chain advanced past the rollback point via fresh forward stores");
    TEST_ASSERT(mxd_block_exists_at_height(9) == 1, "refilled height 9 present");
    TEST_END("RISK-2: rollback then refill");
}


/* v9: the committed score array built for block H drops validators evicted
 * on-chain. prev (v9, h=100) carries scores [A,B,C], evicts B and C, and has
 * JOINs for C (re-join, same block → eviction wins) and D (new). Expected
 * scores for h=101: {A, D}. Steady-state path (prev already v9): no DB scan. */
static void test_v9_scores_drop_evicted(void) {
    mxd_network_type_t saved = mxd_get_network_type();
    mxd_set_network_type(MXD_NETWORK_DEVNET);   /* v9 from genesis on devnet */

    uint8_t A[32], B[32], C[32], D[32];
    memset(A, 0xA1, 32); memset(B, 0xB2, 32); memset(C, 0xC3, 32); memset(D, 0xD4, 32);

    mxd_block_t prev;
    memset(&prev, 0, sizeof(prev));
    prev.version = MXD_PROTOCOL_VERSION_9;
    prev.height = 100;
    prev.validator_scores = calloc(3, sizeof(mxd_validator_score_entry_t));
    prev.validator_scores_count = 3;
    memcpy(prev.validator_scores[0].validator_address, A, 32); prev.validator_scores[0].blocks_since_joined = 7;
    memcpy(prev.validator_scores[1].validator_address, B, 32);
    memcpy(prev.validator_scores[2].validator_address, C, 32);
    prev.rapid_eviction_entries = calloc(2, sizeof(mxd_rapid_eviction_entry_t));
    prev.rapid_eviction_count = 2;
    memcpy(prev.rapid_eviction_entries[0].target_addr, B, 32);
    memcpy(prev.rapid_eviction_entries[1].target_addr, C, 32);
    prev.rapid_membership_entries = calloc(2, sizeof(mxd_rapid_membership_entry_t));
    prev.rapid_membership_count = 2;
    memcpy(prev.rapid_membership_entries[0].node_address, C, 32);
    memcpy(prev.rapid_membership_entries[1].node_address, D, 32);

    mxd_rapid_table_t table;
    memset(&table, 0, sizeof(table));

    mxd_validator_score_entry_t *out = NULL;
    uint32_t n = 0;
    TEST_ASSERT(mxd_compute_block_validator_scores(&prev, &table, &out, &n) == 0, "v9 compute succeeds");
    TEST_ASSERT(n == 2, "v9: evicted B and C dropped, D added -> 2 entries");
    int hasA = 0, hasB = 0, hasC = 0, hasD = 0;
    uint32_t a_bsj = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (memcmp(out[i].validator_address, A, 32) == 0) { hasA = 1; a_bsj = out[i].blocks_since_joined; }
        if (memcmp(out[i].validator_address, B, 32) == 0) hasB = 1;
        if (memcmp(out[i].validator_address, C, 32) == 0) hasC = 1;
        if (memcmp(out[i].validator_address, D, 32) == 0) hasD = 1;
    }
    TEST_ASSERT(hasA && hasD && !hasB && !hasC, "v9: {A, D} kept, {B, C} gone (same-block eviction wins over JOIN)");
    TEST_ASSERT(a_bsj == 8, "v9: deltas still applied to kept entries");

    /* pre-v9 behaviour unchanged: with prev.version 8 on a network where h=101 is v8, nothing is dropped */
    mxd_set_network_type(MXD_NETWORK_MAINNET);   /* mainnet v9 activates at h=30; h=101 is v9 too, so use testnet */
    mxd_set_network_type(MXD_NETWORK_TESTNET);   /* testnet v9 activates at h=37970 -> h=101 is v8 */
    prev.version = MXD_PROTOCOL_VERSION_8;
    free(out); out = NULL; n = 0;
    TEST_ASSERT(mxd_compute_block_validator_scores(&prev, &table, &out, &n) == 0, "v8 compute succeeds");
    TEST_ASSERT(n == 4, "v8 (pre-v9) keeps evicted entries: A,B,C + D = 4");

    free(out);
    free(prev.validator_scores);
    free(prev.rapid_eviction_entries);
    free(prev.rapid_membership_entries);
    mxd_set_network_type(saved);
    printf("  v9 committed-score eviction filter OK\n");
}


/* v10: validator JOIN admission is Dilithium5-only from the activation height.
 * (a) the gate itself; (b) a v10 block carrying an Ed25519 JOIN entry is rejected
 * before any signature check; (c) a v10 block carrying a properly signed
 * Dilithium5 JOIN entry is accepted. */
static void test_v10_join_requires_dilithium5(void) {
    mxd_network_type_t saved = mxd_get_network_type();
    mxd_set_network_type(MXD_NETWORK_MAINNET);   /* mainnet: v10 at h=52 */

    TEST_ASSERT(mxd_join_algo_allowed_at(MXD_SIGALG_ED25519, 0, MXD_NETWORK_MAINNET) == 1, "v10: genesis exempt");
    TEST_ASSERT(mxd_join_algo_allowed_at(MXD_SIGALG_ED25519, 51, MXD_NETWORK_MAINNET) == 1, "v10: Ed25519 still admitted before activation");
    TEST_ASSERT(mxd_join_algo_allowed_at(MXD_SIGALG_ED25519, 52, MXD_NETWORK_MAINNET) == 0, "v10: Ed25519 refused at activation");
    TEST_ASSERT(mxd_join_algo_allowed_at(MXD_SIGALG_DILITHIUM5, 52, MXD_NETWORK_MAINNET) == 1, "v10: Dilithium5 admitted");
    TEST_ASSERT(mxd_join_algo_allowed_at(MXD_SIGALG_ED25519, 1, MXD_NETWORK_DEVNET) == 0, "v10: devnet from genesis (h>0)");

    /* (b) Ed25519 JOIN entry in a v10 block -> rejected */
    mxd_block_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.version = MXD_PROTOCOL_VERSION_10;
    blk.height = 100;
    blk.rapid_membership_entries = calloc(1, sizeof(mxd_rapid_membership_entry_t));
    blk.rapid_membership_count = 1;
    mxd_rapid_membership_entry_t *e = &blk.rapid_membership_entries[0];
    e->algo_id = MXD_SIGALG_ED25519;
    e->public_key_length = 32;
    e->signature_length = 64;
    memset(e->public_key, 0x11, 32);
    memset(e->node_address, 0x22, 32);
    TEST_ASSERT(mxd_verify_block_validator_entries(&blk) != 0, "v10: block with Ed25519 JOIN entry rejected");

    /* (c) properly signed Dilithium5 JOIN entry in a v10 block -> accepted */
    static uint8_t pub[MXD_PUBKEY_MAX_LEN];
    static uint8_t priv[MXD_PRIVKEY_MAX_LEN];
    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, pub, priv) == 0, "v10: D5 keygen");
    memset(e, 0, sizeof(*e));
    e->algo_id = MXD_SIGALG_DILITHIUM5;
    e->public_key_length = (uint16_t)mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    memcpy(e->public_key, pub, e->public_key_length);
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, pub, e->public_key_length, e->node_address) == 0, "v10: derive addr32");
    e->timestamp = 1791000000000ULL;
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x00;                     /* op_type = JOIN */
    memcpy(sign_data + off, e->node_address, 32); off += 32;
    for (int i = 7; i >= 0; i--) { sign_data[off + i] = (uint8_t)(e->timestamp >> (8 * (7 - i))); }
    off += 8;
    size_t sig_len = sizeof(e->signature);
    TEST_ASSERT(mxd_sig_sign(MXD_SIGALG_DILITHIUM5, e->signature, &sig_len, sign_data, sizeof(sign_data), priv) == 0, "v10: D5 sign JOIN");
    e->signature_length = (uint16_t)sig_len;
    TEST_ASSERT(mxd_verify_block_validator_entries(&blk) == 0, "v10: block with signed Dilithium5 JOIN entry accepted");

    /* same D5 entry is also fine before activation; an Ed25519 one is fine before activation only */
    blk.height = 40;
    TEST_ASSERT(mxd_verify_block_validator_entries(&blk) == 0, "pre-v10: D5 entry accepted");

    free(blk.rapid_membership_entries);
    memset(priv, 0, sizeof(priv));
    mxd_set_network_type(saved);
    printf("  v10 Dilithium5-only JOIN admission OK\n");
}

int main(void) {
    printf("=== Consensus safe-by-construction fault-injection tests ===\n");
    remove_stale_dbs();

    if (mxd_init_blockchain_db(DB_PATH) != 0) {
        printf("FATAL: could not init blockchain DB\n");
        return 1;
    }

    /* RISK-1 — equivocation vote book */
    test_votebook_first_and_idempotent();
    test_votebook_refuses_equivocation();
    test_votebook_heights_independent();
    test_votebook_persists_across_reopen();

    /* RISK-2 — deep-fork rollback */
    test_rollback_truncates_chain();
    test_rollback_then_refill();

    mxd_close_blockchain_db();

    test_v9_scores_drop_evicted();
    test_v10_join_requires_dilithium5();
    printf("\nAll consensus-safety fault-injection tests passed.\n");
    return 0;
}
