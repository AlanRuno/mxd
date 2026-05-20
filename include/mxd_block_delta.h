#ifndef MXD_BLOCK_DELTA_H
#define MXD_BLOCK_DELTA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Per-block UTXO delta record (v7.1).
 *
 * Captures what a block changed in the UTXO set so a reorg-rollback can
 * reverse it: re-create spent UTXOs, delete created UTXOs.
 *
 * Stored in RocksDB under key "delta:{block_hash}" written atomically with
 * the block-store. Read on reorg-rollback.
 *
 * Wire format (big-endian):
 *   u32  spent_count
 *   for i in [0, spent_count):
 *     u8[64]  prev_tx_hash
 *     u32     output_index
 *   u32  created_count
 *   for i in [0, created_count):
 *     u8[64]  tx_hash
 *     u32     output_index
 *     u8[32]  owner_addr
 *     u64     amount
 *
 * created entries carry enough information to re-add the UTXO to the DB
 * verbatim on rollback (we only need to delete it on rollback, but the
 * fuller record is also useful for diagnostics).
 *
 * The serialization is intentionally simple — no cosigner_keys, no
 * required_signatures field. v2 transactions are always 1-of-1 spends in
 * the current consensus path; multi-sig output applications would need to
 * extend this format.
 */

typedef struct {
    uint8_t  prev_tx_hash[64];
    uint32_t output_index;
} mxd_delta_spent_t;

typedef struct {
    uint8_t  tx_hash[64];
    uint32_t output_index;
    uint8_t  owner_addr[32];
    uint64_t amount;
} mxd_delta_created_t;

typedef struct {
    uint32_t              spent_count;
    mxd_delta_spent_t    *spent;
    uint32_t              created_count;
    mxd_delta_created_t  *created;
} mxd_block_delta_t;

int mxd_block_delta_init(mxd_block_delta_t *d);
int mxd_block_delta_append_spent(mxd_block_delta_t *d, const uint8_t prev_tx_hash[64], uint32_t output_index);
int mxd_block_delta_append_created(mxd_block_delta_t *d, const uint8_t tx_hash[64], uint32_t output_index,
                                   const uint8_t owner_addr[32], uint64_t amount);

int mxd_block_delta_serialize(const mxd_block_delta_t *d, uint8_t **out, size_t *out_len);
int mxd_block_delta_deserialize(const uint8_t *buf, size_t buf_len, mxd_block_delta_t *out);
void mxd_block_delta_free(mxd_block_delta_t *d);

/*
 * Reverse the UTXO state changes recorded in d. Re-creates spent UTXOs (when
 * possible — we only have keys, so we re-create from the original UTXO data
 * still in DB if present) and deletes created UTXOs.
 *
 * NOTE: spent UTXOs are not deleted from the DB — they're flagged is_spent=1.
 * Reversing therefore means flipping is_spent back to 0.
 */
int mxd_reverse_utxo_delta(const mxd_block_delta_t *d);

/*
 * Apply the UTXO state changes recorded in d (forward direction). Only used
 * during reorg-promote when re-applying a stored delta from disk.
 */
int mxd_apply_utxo_delta(const mxd_block_delta_t *d);

/* RocksDB persistence. Uses the blockchain DB handle. */
int mxd_store_block_delta(const uint8_t block_hash[64], const mxd_block_delta_t *d);
int mxd_load_block_delta(const uint8_t block_hash[64], mxd_block_delta_t *out);
int mxd_delete_block_delta(const uint8_t block_hash[64]);

/* Key-construction primitive. Exposed so mxd_store_block can fold the
 * delta write into its own RocksDB WriteBatch for atomicity (F8-1).
 * Key layout: "delta:" + block_hash[64] = 70 bytes. */
#define MXD_BLOCK_DELTA_KEY_LEN 70
void mxd_block_delta_make_key(const uint8_t block_hash[64],
                               uint8_t out_key[MXD_BLOCK_DELTA_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCK_DELTA_H
