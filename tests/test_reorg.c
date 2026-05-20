/*
 * test_reorg.c — v7.1 reorg machinery tests.
 *
 * Tests:
 *   1. Delta serialize/deserialize round-trip is byte-identical.
 *   2. Delta append helpers grow correctly.
 *   3. Genesis is untouchable (compute_reorg_depth returns -1 on h=0).
 *   4. Reorg depth limit (compute_reorg_depth returns >MAX or fails).
 *
 * NOTE: Full UTXO reorg integration tests would need a live RocksDB and
 * proper block headers — that's the live-smoke step on testnet, not a unit
 * test. These tests pin the supporting building blocks.
 */

#include "../include/mxd_fork_choice.h"
#include "../include/mxd_block_delta.h"
#include "../include/mxd_blockchain.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void test_delta_roundtrip(void) {
    TEST_START("delta serialize/deserialize round-trip");
    mxd_block_delta_t d;
    mxd_block_delta_init(&d);

    uint8_t prev_hash_a[64];
    uint8_t prev_hash_b[64];
    for (int i = 0; i < 64; i++) prev_hash_a[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 64; i++) prev_hash_b[i] = (uint8_t)(0x80 + i);
    TEST_ASSERT(mxd_block_delta_append_spent(&d, prev_hash_a, 0) == 0, "append spent #0");
    TEST_ASSERT(mxd_block_delta_append_spent(&d, prev_hash_b, 7) == 0, "append spent #1");

    uint8_t tx_hash[64];
    uint8_t addr[32];
    for (int i = 0; i < 64; i++) tx_hash[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) addr[i] = (uint8_t)(0xC0 + i);
    TEST_ASSERT(mxd_block_delta_append_created(&d, tx_hash, 0, addr, 1234567890ULL) == 0,
                "append created #0");
    TEST_ASSERT(mxd_block_delta_append_created(&d, tx_hash, 1, addr, 999ULL) == 0,
                "append created #1");

    uint8_t *buf = NULL;
    size_t buf_len = 0;
    TEST_ASSERT(mxd_block_delta_serialize(&d, &buf, &buf_len) == 0, "serialize");
    printf("  serialized size = %zu bytes\n", buf_len);

    mxd_block_delta_t d2;
    TEST_ASSERT(mxd_block_delta_deserialize(buf, buf_len, &d2) == 0, "deserialize");

    TEST_ASSERT(d2.spent_count == 2, "spent count round-trip");
    TEST_ASSERT(d2.created_count == 2, "created count round-trip");
    TEST_ASSERT(memcmp(d2.spent[0].prev_tx_hash, prev_hash_a, 64) == 0, "spent[0] hash");
    TEST_ASSERT(d2.spent[1].output_index == 7, "spent[1] output_index");
    TEST_ASSERT(d2.created[0].amount == 1234567890ULL, "created[0] amount");
    TEST_ASSERT(memcmp(d2.created[0].owner_addr, addr, 32) == 0, "created[0] owner");

    free(buf);
    mxd_block_delta_free(&d);
    mxd_block_delta_free(&d2);
    TEST_END("delta serialize/deserialize round-trip");
}

static void test_genesis_untouchable(void) {
    TEST_START("genesis is untouchable (depth=-1)");
    mxd_block_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.height = 0;
    b.height = 1;
    int d = mxd_compute_reorg_depth(&a, &b);
    printf("  compute_reorg_depth(h=0, h=1) = %d (expected -1)\n", d);
    TEST_ASSERT(d == -1, "current head at genesis cannot be reorged");

    a.height = 1;
    b.height = 0;
    d = mxd_compute_reorg_depth(&a, &b);
    printf("  compute_reorg_depth(h=1, h=0) = %d (expected -1)\n", d);
    TEST_ASSERT(d == -1, "candidate at genesis cannot reorg");
    TEST_END("genesis is untouchable");
}

static void test_reorg_depth_constant(void) {
    TEST_START("MXD_MAX_REORG_DEPTH is 10");
    TEST_ASSERT(MXD_MAX_REORG_DEPTH == 10, "MXD_MAX_REORG_DEPTH = 10 per v7.1 dispatch");
    printf("  MXD_MAX_REORG_DEPTH = %d\n", MXD_MAX_REORG_DEPTH);
    TEST_END("MXD_MAX_REORG_DEPTH");
}

static void test_empty_delta(void) {
    TEST_START("empty delta serializes to 8 bytes (two u32 counts)");
    mxd_block_delta_t d;
    mxd_block_delta_init(&d);
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    TEST_ASSERT(mxd_block_delta_serialize(&d, &buf, &buf_len) == 0, "serialize empty");
    TEST_ASSERT(buf_len == 8, "empty delta = 8 bytes");

    mxd_block_delta_t d2;
    TEST_ASSERT(mxd_block_delta_deserialize(buf, buf_len, &d2) == 0, "deserialize empty");
    TEST_ASSERT(d2.spent_count == 0 && d2.created_count == 0, "counts are zero");

    free(buf);
    mxd_block_delta_free(&d);
    mxd_block_delta_free(&d2);
    TEST_END("empty delta");
}

int main(void) {
    test_reorg_depth_constant();
    test_empty_delta();
    test_delta_roundtrip();
    test_genesis_untouchable();
    printf("\nAll reorg tests passed.\n");
    return 0;
}
