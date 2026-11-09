/*
 * test_consensus_v11.c — protocol v11 and the height-index continuity fixes.
 *
 *   A. The block hash binds proposer_id from v11 (two proposals with the same
 *      content from different proposers no longer share a hash).
 *   B. Deterministic signer skip in the validation chain: the next canonical
 *      signer may sign at once; a validator of rank j may take the next
 *      position only with a timestamp >= previous + j * MXD_SIGN_SKIP_MS.
 *      Checked on the per-signature admission path and on whole-chain
 *      verification.
 *   C. Parent continuity on append: a block that extends a losing sibling
 *      promotes it (depth-1 reorg) instead of leaving an orphan under the
 *      height key; mxd_repair_height_index fixes an already-inconsistent DB.
 */

#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_protocol_version.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_domain_tags.h"
#include "../include/mxd_endian.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DB_PATH "test_consensus_v11_db"
#define NV 5

typedef struct {
    uint8_t pub[MXD_PUBKEY_MAX_LEN];
    uint8_t priv[MXD_PRIVKEY_MAX_LEN];
    uint8_t addr[32];
} validator_t;

static validator_t V[NV];

static void remove_stale_db(void) {
    if (system("rm -rf " DB_PATH " " DB_PATH "_c " DB_PATH "_r") != 0) {
        printf("warning: could not remove stale test databases\n");
    }
}

static void make_validators(void) {
    mxd_test_clear_validator_pubkeys();
    for (int i = 0; i < NV; i++) {
        TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, V[i].pub, V[i].priv) == 0, "keygen");
        TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, V[i].pub, mxd_sig_pubkey_len(MXD_SIGALG_ED25519), V[i].addr) == 0, "derive address");
        TEST_ASSERT(mxd_test_register_validator_pubkey(V[i].addr, V[i].pub, mxd_sig_pubkey_len(MXD_SIGALG_ED25519)) == 0, "register pubkey");
    }
}

/* Sign the v7 canonical consensus message for the next chain position. */
static void sign_next(const mxd_block_t *b, const validator_t *v, uint64_t ts, uint8_t *sig, size_t *sig_len) {
    uint8_t chain_hash[64];
    mxd_compute_chain_hash(b, b->validation_count, chain_hash);
    uint8_t msg[MXD_DOMAIN_TAG_CONS_LEN + 64 + 64 + 8];
    size_t o = 0;
    memcpy(msg + o, MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN); o += MXD_DOMAIN_TAG_CONS_LEN;
    memcpy(msg + o, b->block_hash, 64); o += 64;
    memcpy(msg + o, chain_hash, 64); o += 64;
    uint64_t ts_be = mxd_htonll(ts);
    memcpy(msg + o, &ts_be, 8);
    *sig_len = MXD_SIGNATURE_MAX;
    TEST_ASSERT(mxd_sig_sign(MXD_SIGALG_ED25519, sig, sig_len, msg, sizeof(msg), v->priv) == 0, "sign");
}

/* Admission through the verifier path used for gossiped signatures. */
static int try_add(mxd_block_t *b, const validator_t *v, uint64_t ts) {
    uint8_t sig[MXD_SIGNATURE_MAX];
    size_t sig_len = 0;
    sign_next(b, v, ts, sig, &sig_len);
    return mxd_add_validator_signature_to_block(b, v->addr, ts, MXD_SIGALG_ED25519, sig, (uint16_t)sig_len, b->validation_count);
}

/* Append without any admission check (what a signer does with its own signature). */
static void add_unchecked(mxd_block_t *b, const validator_t *v, uint64_t ts) {
    uint8_t sig[MXD_SIGNATURE_MAX];
    size_t sig_len = 0;
    sign_next(b, v, ts, sig, &sig_len);
    TEST_ASSERT(mxd_add_validator_signature(b, v->addr, ts, MXD_SIGALG_ED25519, sig, (uint16_t)sig_len) == 0, "add unchecked");
}

static void init_block(mxd_block_t *b, const uint8_t prev[64], uint32_t height, uint32_t version, const uint8_t proposer[32], uint64_t nonce) {
    memset(b, 0, sizeof(*b));
    TEST_ASSERT(mxd_init_block(b, prev) == 0, "init block");
    b->validation_capacity = 10;
    b->validation_chain = calloc(b->validation_capacity, sizeof(mxd_validator_signature_t));
    TEST_ASSERT(b->validation_chain != NULL, "alloc validation chain");
    b->version = version;
    b->height = height;
    b->timestamp = 1700000000ULL + height;
    b->nonce = nonce;
    if (proposer) memcpy(b->proposer_id, proposer, 32);
    TEST_ASSERT(mxd_calculate_block_hash(b, b->block_hash) == 0, "hash block");
}

/* ------------------------------------------------------------------------- */
static void test_hash_binds_proposer(void) {
    TEST_START("A: block hash binds proposer_id from v11");
    uint8_t prev[64]; memset(prev, 0x11, 64);
    mxd_block_t a, b;
    init_block(&a, prev, 60, MXD_PROTOCOL_VERSION_11, V[0].addr, 7);
    init_block(&b, prev, 60, MXD_PROTOCOL_VERSION_11, V[1].addr, 7);
    TEST_ASSERT(memcmp(a.block_hash, b.block_hash, 64) != 0, "v11: different proposers -> different hashes");
    mxd_block_t c, d;
    init_block(&c, prev, 60, MXD_PROTOCOL_VERSION_10, V[0].addr, 7);
    init_block(&d, prev, 60, MXD_PROTOCOL_VERSION_10, V[1].addr, 7);
    TEST_ASSERT(memcmp(c.block_hash, d.block_hash, 64) == 0, "v10: the proposer was not part of the hash (historical behaviour kept)");
    mxd_block_t e;
    init_block(&e, prev, 60, MXD_PROTOCOL_VERSION_11, V[0].addr, 7);
    TEST_ASSERT(memcmp(a.block_hash, e.block_hash, 64) == 0, "v11: same content and proposer -> same hash (deterministic)");
    mxd_free_block(&a); mxd_free_block(&b); mxd_free_block(&c); mxd_free_block(&d); mxd_free_block(&e);
    TEST_END("A");
}

/* ------------------------------------------------------------------------- */
/* Store a v11 block at height 9 carrying committed scores for the 5
 * validators (distinct stakes -> deterministic order), so the committed
 * signer order of height 10 can be derived from the DB. Returns its hash. */
static void store_parent_with_scores(uint8_t out_hash[64]) {
    uint8_t prev[64]; memset(prev, 0x22, 64);
    mxd_block_t p;
    init_block(&p, prev, 9, MXD_PROTOCOL_VERSION_11, V[0].addr, 1);
    p.validator_scores = calloc(NV, sizeof(mxd_validator_score_entry_t));
    p.validator_scores_count = NV;
    p.validator_scores_capacity = NV;
    for (int i = 0; i < NV; i++) {
        memcpy(p.validator_scores[i].validator_address, V[i].addr, 32);
        p.validator_scores[i].stake_amount = 1000 + 100 * (uint64_t)i;
        p.validator_scores[i].blocks_since_joined = 1;
    }
    TEST_ASSERT(mxd_calculate_validator_scores_root(&p, p.validator_scores_root) == 0, "scores root");
    TEST_ASSERT(mxd_calculate_block_hash(&p, p.block_hash) == 0, "parent hash");
    TEST_ASSERT(mxd_store_block(&p) == 0, "store parent at h=9");
    memcpy(out_hash, p.block_hash, 64);
    mxd_free_block(&p);
}

static void test_skip_rule(void) {
    TEST_START("B: deterministic signer skip (per-signature admission and whole-chain verification)");
    uint8_t parent_hash[64];
    store_parent_with_scores(parent_hash);

    /* Canonical order for height 10 with V[0] proposing: positions 1..4. */
    const validator_t *at[NV] = {0};
    at[0] = &V[0];
    for (int i = 1; i < NV; i++) {
        int pos = mxd_get_my_signing_position(NULL, V[0].addr, V[i].addr, 10);
        TEST_ASSERT(pos >= 1 && pos <= 4 && at[pos] == NULL, "every non-proposer has a distinct canonical position");
        at[pos] = &V[i];
    }
    printf("  canonical positions resolved for h=10\n");

    mxd_block_t b;
    init_block(&b, parent_hash, 10, MXD_PROTOCOL_VERSION_11, V[0].addr, 3);
    const uint64_t t0 = 1700000000000ULL;
    add_unchecked(&b, at[0], t0);                       /* proposer, position 0 */

    /* Ranks before anyone else signs. */
    TEST_ASSERT(mxd_signing_rank(&b, at[1]->addr) == 0, "position-1 validator has rank 0");
    TEST_ASSERT(mxd_signing_rank(&b, at[2]->addr) == 1, "position-2 validator has rank 1");
    TEST_ASSERT(mxd_signing_rank(&b, at[4]->addr) == 3, "position-4 validator has rank 3");
    TEST_ASSERT(mxd_signing_rank(&b, at[0]->addr) == -1, "the proposer has no rank");
    uint8_t stranger[32]; memset(stranger, 0xEE, 32);
    TEST_ASSERT(mxd_signing_rank(&b, stranger) == -1, "a non-validator has no rank");
    TEST_ASSERT(mxd_signing_not_before_ms(&b, 1) == t0 + MXD_SIGN_SKIP_MS, "rank 1 may sign 10 s after the previous signature");
    TEST_ASSERT(mxd_signing_not_before_ms(&b, 3) == t0 + 3 * MXD_SIGN_SKIP_MS, "rank 3 may sign 30 s after");

    /* Position-1 validator is offline: the rank-1 validator tries too early, then in time. */
    TEST_ASSERT(try_add(&b, at[2], t0 + 5000) != 0, "rank-1 signer rejected 5 s after the previous signature");
    TEST_ASSERT(b.validation_count == 1, "nothing appended");
    TEST_ASSERT(try_add(&b, at[2], t0 + MXD_SIGN_SKIP_MS) == 0, "rank-1 signer admitted at 10 s");
    TEST_ASSERT(b.validation_count == 2 && memcmp(b.validation_chain[1].validator_id, at[2]->addr, 32) == 0, "it occupies chain position 1");

    /* The passed-over validator moves behind every validator that was not passed over:
     * it is rank 2 now and cannot jump back in; the next canonical validator is rank 0. */
    TEST_ASSERT(mxd_signing_rank(&b, at[1]->addr) == 2, "a validator passed over moves to the end of the order (rank 2)");
    TEST_ASSERT(mxd_signing_rank(&b, at[3]->addr) == 0, "the next canonical validator is rank 0");
    TEST_ASSERT(try_add(&b, at[1], t0 + MXD_SIGN_SKIP_MS + 10) != 0, "the passed-over validator cannot take position 2 at once");
    TEST_ASSERT(try_add(&b, at[3], t0 + MXD_SIGN_SKIP_MS + 10) == 0, "the rank-0 validator signs at chain position 2 immediately");
    TEST_ASSERT(b.validation_count == 3, "three signatures");

    /* Position-4 validator offline too: the passed-over validator (rank 1 now) needs 10 s after the last signature. */
    uint64_t t_prev = b.validation_chain[2].timestamp;
    TEST_ASSERT(mxd_signing_rank(&b, at[4]->addr) == 0 && mxd_signing_rank(&b, at[1]->addr) == 1, "remaining order is [position-4, passed-over]");
    TEST_ASSERT(try_add(&b, at[1], t_prev + 9999) != 0, "rank-1 signer rejected 1 ms early");
    TEST_ASSERT(try_add(&b, at[1], t_prev + MXD_SIGN_SKIP_MS) == 0, "rank-1 signer admitted at exactly 10 s");
    TEST_ASSERT(b.validation_count == 4, "quorum of 4 reached with one validator still missing");

    /* Duplicate and proposer re-sign are refused. */
    TEST_ASSERT(try_add(&b, at[2], t_prev + 2 * MXD_SIGN_SKIP_MS) != 0, "a validator cannot sign twice");
    TEST_ASSERT(try_add(&b, at[0], t_prev + 2 * MXD_SIGN_SKIP_MS) != 0, "the proposer cannot sign again");

    /* Last one closes the chain; whole-chain verification accepts it. */
    TEST_ASSERT(try_add(&b, at[4], t_prev + MXD_SIGN_SKIP_MS + 1) == 0, "last validator (rank 0) signs");
    TEST_ASSERT(b.validation_count == 5, "five signatures");
    TEST_ASSERT(mxd_verify_validation_chain_crypto(&b) == 0, "whole-chain verification accepts the skipped chain");
    mxd_free_block(&b);

    /* Whole-chain verification rejects a chain where a rank-1 signer jumped early. */
    mxd_block_t bad;
    init_block(&bad, parent_hash, 10, MXD_PROTOCOL_VERSION_11, V[0].addr, 3);
    add_unchecked(&bad, at[0], t0);
    add_unchecked(&bad, at[2], t0 + 1);                 /* valid signature, but rank 1 at +1 ms */
    TEST_ASSERT(mxd_verify_validation_chain_crypto(&bad) != 0, "early rank-1 signature fails whole-chain verification");
    mxd_free_block(&bad);

    /* Whole-chain verification rejects a position-0 signer that is not the proposer. */
    mxd_block_t bad0;
    init_block(&bad0, parent_hash, 10, MXD_PROTOCOL_VERSION_11, V[0].addr, 3);
    add_unchecked(&bad0, at[1], t0);
    TEST_ASSERT(mxd_verify_validation_chain_crypto(&bad0) != 0, "position 0 must be the proposer");
    mxd_free_block(&bad0);

    /* Pre-v11 chains keep the historical semantics on whole-chain verification (no order rule). */
    mxd_block_t old;
    init_block(&old, parent_hash, 10, MXD_PROTOCOL_VERSION_10, V[0].addr, 3);
    add_unchecked(&old, at[0], t0);
    add_unchecked(&old, at[2], t0 + 1);
    TEST_ASSERT(mxd_verify_validation_chain_crypto(&old) == 0, "v10 chain: order not enforced on the whole-chain path (unchanged)");
    mxd_free_block(&old);

    TEST_END("B");
}

/* ------------------------------------------------------------------------- */
/* Two sibling candidates at `height`, each carrying one real proposer
 * signature (fork-choice only admits candidates whose chain verifies).
 * They tie on signatures, so the lower hash wins. */
static void build_sibling_pair(mxd_block_t *lo, mxd_block_t *hi, const uint8_t prev[64], uint32_t height) {
    mxd_block_t x, y;
    init_block(&x, prev, height, 8, V[0].addr, 100);
    init_block(&y, prev, height, 8, V[0].addr, 200);
    add_unchecked(&x, &V[0], 1700000000000ULL + height);
    add_unchecked(&y, &V[0], 1700000000000ULL + height);
    if (memcmp(x.block_hash, y.block_hash, 64) < 0) { *lo = x; *hi = y; } else { *lo = y; *hi = x; }
}

static void store_chain(uint32_t n, uint8_t out_tip[64]) {
    uint8_t prev[64] = {0};
    for (uint32_t h = 0; h < n; h++) {
        mxd_block_t b;
        init_block(&b, prev, h, 8, NULL, h);
        TEST_ASSERT(mxd_store_block(&b) == 0, "store chain block");
        memcpy(prev, b.block_hash, 64);
        mxd_free_block(&b);
    }
    memcpy(out_tip, prev, 64);
}

static void test_continuity_promotes_sibling(void) {
    TEST_START("C1: a block extending a losing sibling promotes it (depth-1 reorg)");
    mxd_close_blockchain_db();
    TEST_ASSERT(mxd_init_blockchain_db(DB_PATH "_c") == 0, "fresh DB");

    uint8_t tip2[64];
    store_chain(3, tip2);                                  /* heights 0..2 */
    mxd_block_t lo, hi;
    build_sibling_pair(&lo, &hi, tip2, 3);
    TEST_ASSERT(mxd_store_block(&lo) == 0, "store the sibling with the lower hash first (it wins the tie)");
    TEST_ASSERT(mxd_store_block(&hi) == 0, "the higher-hash sibling loses and is kept under its hash key only");
    mxd_block_t at3;
    memset(&at3, 0, sizeof(at3));
    TEST_ASSERT(mxd_retrieve_block_by_height(3, &at3) == 0 && memcmp(at3.block_hash, lo.block_hash, 64) == 0, "height 3 holds the winner");
    mxd_free_block(&at3);

    /* Validators extend the loser: the child promotes it. */
    mxd_block_t child;
    init_block(&child, hi.block_hash, 4, 8, NULL, 4);
    TEST_ASSERT(mxd_store_block(&child) == 0, "child of the losing sibling is stored");
    memset(&at3, 0, sizeof(at3));
    TEST_ASSERT(mxd_retrieve_block_by_height(3, &at3) == 0 && memcmp(at3.block_hash, hi.block_hash, 64) == 0, "height 3 now holds the extended sibling");
    mxd_free_block(&at3);
    mxd_block_t at4;
    memset(&at4, 0, sizeof(at4));
    TEST_ASSERT(mxd_retrieve_block_by_height(4, &at4) == 0 && memcmp(at4.prev_block_hash, hi.block_hash, 64) == 0, "height 4 links to it");
    mxd_free_block(&at4);
    uint32_t h = 0;
    TEST_ASSERT(mxd_get_blockchain_height(&h) == 0 && h == 5, "current_height advanced to 5");
    TEST_ASSERT(mxd_repair_height_index() == 0, "index is consistent: nothing to repair");

    /* A block whose parent is unknown is refused. */
    uint8_t ghost[64]; memset(ghost, 0x77, 64);
    mxd_block_t orphan_child;
    init_block(&orphan_child, ghost, 5, 8, NULL, 5);
    TEST_ASSERT(mxd_store_block(&orphan_child) != 0, "block with an unknown parent is not appended");
    TEST_ASSERT(mxd_get_blockchain_height(&h) == 0 && h == 5, "height unchanged");

    mxd_free_block(&lo); mxd_free_block(&hi); mxd_free_block(&child); mxd_free_block(&orphan_child);
    TEST_END("C1");
}

static void test_repair_height_index(void) {
    TEST_START("C2: mxd_repair_height_index re-points an orphaned height at the tip's ancestor");
    mxd_close_blockchain_db();
    TEST_ASSERT(mxd_init_blockchain_db(DB_PATH "_r") == 0, "fresh DB");

    uint8_t tip2[64];
    store_chain(3, tip2);
    mxd_block_t lo, hi;
    build_sibling_pair(&lo, &hi, tip2, 3);
    TEST_ASSERT(mxd_store_block(&lo) == 0, "winner at height 3");
    TEST_ASSERT(mxd_store_block(&hi) == 0, "loser under hash only");

    /* Legacy state: a child of the loser appended without the continuity check. */
    mxd_block_t child;
    init_block(&child, hi.block_hash, 4, 8, NULL, 4);
    TEST_ASSERT(mxd_test_store_block_unconditional(&child) == 0, "legacy append of the loser's child");
    mxd_block_t at3;
    memset(&at3, 0, sizeof(at3));
    TEST_ASSERT(mxd_retrieve_block_by_height(3, &at3) == 0 && memcmp(at3.block_hash, lo.block_hash, 64) == 0, "height 3 still holds the orphan (inconsistent)");
    mxd_free_block(&at3);

    int fixed = mxd_repair_height_index();
    printf("  repaired heights: %d\n", fixed);
    TEST_ASSERT(fixed == 1, "exactly one height rewritten");
    memset(&at3, 0, sizeof(at3));
    TEST_ASSERT(mxd_retrieve_block_by_height(3, &at3) == 0 && memcmp(at3.block_hash, hi.block_hash, 64) == 0, "height 3 now holds the tip's ancestor");
    mxd_free_block(&at3);
    mxd_block_t orphan;
    memset(&orphan, 0, sizeof(orphan));
    TEST_ASSERT(mxd_retrieve_block_by_hash(lo.block_hash, &orphan) == 0, "the orphan is still reachable by hash");
    mxd_free_block(&orphan);
    TEST_ASSERT(mxd_repair_height_index() == 0, "second pass finds nothing");

    mxd_free_block(&lo); mxd_free_block(&hi); mxd_free_block(&child);
    TEST_END("C2");
}

/* ------------------------------------------------------------------------- */
static void test_convergence(void) {
    TEST_START("D: convergence on competing signatures for one position");
    uint8_t parent_hash[64];
    store_parent_with_scores(parent_hash);
    const validator_t *at[NV] = {0};
    at[0] = &V[0];
    for (int i = 1; i < NV; i++) at[mxd_get_my_signing_position(NULL, V[0].addr, V[i].addr, 10)] = &V[i];

    /* Local chain: proposer, position-1 validator, then the position-3 validator took
     * chain position 2 as rank 1 (position-2's signature was late), position-4 followed. */
    mxd_block_t b;
    init_block(&b, parent_hash, 10, MXD_PROTOCOL_VERSION_11, V[0].addr, 3);
    const uint64_t t0 = 1700000000000ULL;
    add_unchecked(&b, at[0], t0);
    add_unchecked(&b, at[1], t0 + 100);
    TEST_ASSERT(try_add(&b, at[3], t0 + 100 + MXD_SIGN_SKIP_MS) == 0, "rank-1 signer took position 2 after 10 s");
    TEST_ASSERT(try_add(&b, at[4], t0 + 100 + MXD_SIGN_SKIP_MS + 1) == 0, "position-4 validator (rank 0 now) signed position 3");
    TEST_ASSERT(b.validation_count == 4, "local chain has 4 signatures");

    /* The late rank-0 signature for position 2 arrives: it outranks our signer there. */
    mxd_block_t prefix = b; prefix.validation_count = 2;
    uint8_t sig[MXD_SIGNATURE_MAX]; size_t sig_len = 0;
    sign_next(&prefix, at[2], t0 + 200, sig, &sig_len);
    TEST_ASSERT(mxd_add_validator_signature_to_block(&b, at[2]->addr, t0 + 200, MXD_SIGALG_ED25519, sig, (uint16_t)sig_len, 2) == 0,
                "rank-0 signature replaces the rank-1 signer at position 2");
    TEST_ASSERT(b.validation_count == 3 && memcmp(b.validation_chain[2].validator_id, at[2]->addr, 32) == 0,
                "chain is now [proposer, pos-1, pos-2]; what was built on the replaced signer was dropped");
    TEST_ASSERT(mxd_verify_validation_chain_crypto(&b) == 0, "the converged chain verifies");

    /* The replaced rank-1 signature offered again for position 2 is ignored. */
    prefix = b; prefix.validation_count = 2;
    sign_next(&prefix, at[3], t0 + 100 + MXD_SIGN_SKIP_MS, sig, &sig_len);
    TEST_ASSERT(mxd_add_validator_signature_to_block(&b, at[3]->addr, t0 + 100 + MXD_SIGN_SKIP_MS, MXD_SIGALG_ED25519, sig, (uint16_t)sig_len, 2) != 0,
                "a higher-ranked competing signature does not replace a lower-ranked one");
    TEST_ASSERT(b.validation_count == 3 && memcmp(b.validation_chain[2].validator_id, at[2]->addr, 32) == 0, "chain unchanged");

    /* A competing signature for an occupied position that is not admissible on the prefix is ignored. */
    prefix = b; prefix.validation_count = 1;
    sign_next(&prefix, at[4], t0 + 101, sig, &sig_len);
    TEST_ASSERT(mxd_add_validator_signature_to_block(&b, at[4]->addr, t0 + 101, MXD_SIGALG_ED25519, sig, (uint16_t)sig_len, 1) != 0,
                "an early higher-ranked signature for an occupied position is ignored");
    TEST_ASSERT(b.validation_count == 3, "chain still has 3 signatures");

    /* The displaced validators sign again on the converged chain. */
    TEST_ASSERT(try_add(&b, at[3], t0 + 300) == 0, "position-3 validator (rank 0) signs position 3");
    TEST_ASSERT(try_add(&b, at[4], t0 + 301) == 0, "position-4 validator signs position 4");
    TEST_ASSERT(b.validation_count == 5 && mxd_verify_validation_chain_crypto(&b) == 0, "five signatures, chain verifies");
    mxd_free_block(&b);
    TEST_END("D");
}

int main(void) {
    printf("=== Protocol v11 and height-index continuity tests ===\n");
    remove_stale_db();
    mxd_network_type_t saved = mxd_get_network_type();
    mxd_set_network_type(MXD_NETWORK_DEVNET);   /* v11 from genesis */

    make_validators();
    test_hash_binds_proposer();

    TEST_ASSERT(mxd_init_blockchain_db(DB_PATH) == 0, "init DB");
    test_skip_rule();
    test_convergence();
    test_continuity_promotes_sibling();
    test_repair_height_index();
    mxd_close_blockchain_db();

    mxd_test_clear_validator_pubkeys();
    mxd_set_network_type(saved);
    remove_stale_db();
    printf("\nAll protocol v11 tests passed.\n");
    return 0;
}
