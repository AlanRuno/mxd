/*
 * mxd_block_delta.c — per-block UTXO delta record for v7.1 reorg.
 *
 * Layout (big-endian, no padding):
 *   u32 spent_count
 *     for each spent: u8[64] tx_hash | u32 output_index
 *   u32 created_count
 *     for each created: u8[64] tx_hash | u32 output_index | u8[32] owner_addr | u64 amount
 */

#include "../../include/mxd_block_delta.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_rocksdb_globals.h"
#include "../../include/mxd_endian.h"
#include "../../include/mxd_logging.h"

#include <rocksdb/c.h>
#include <stdlib.h>
#include <string.h>

#define DELTA_KEY_PREFIX "delta:"
#define DELTA_KEY_PREFIX_LEN 6

int mxd_block_delta_init(mxd_block_delta_t *d) {
    if (!d) return -1;
    memset(d, 0, sizeof(*d));
    return 0;
}

int mxd_block_delta_append_spent(mxd_block_delta_t *d, const uint8_t prev_tx_hash[64], uint32_t output_index) {
    if (!d || !prev_tx_hash) return -1;
    mxd_delta_spent_t *grow = realloc(d->spent, (d->spent_count + 1) * sizeof(*d->spent));
    if (!grow) return -1;
    d->spent = grow;
    memcpy(d->spent[d->spent_count].prev_tx_hash, prev_tx_hash, 64);
    d->spent[d->spent_count].output_index = output_index;
    d->spent_count++;
    return 0;
}

int mxd_block_delta_append_created(mxd_block_delta_t *d, const uint8_t tx_hash[64], uint32_t output_index,
                                   const uint8_t owner_addr[32], uint64_t amount) {
    if (!d || !tx_hash || !owner_addr) return -1;
    mxd_delta_created_t *grow = realloc(d->created, (d->created_count + 1) * sizeof(*d->created));
    if (!grow) return -1;
    d->created = grow;
    memcpy(d->created[d->created_count].tx_hash, tx_hash, 64);
    d->created[d->created_count].output_index = output_index;
    memcpy(d->created[d->created_count].owner_addr, owner_addr, 32);
    d->created[d->created_count].amount = amount;
    d->created_count++;
    return 0;
}

int mxd_block_delta_serialize(const mxd_block_delta_t *d, uint8_t **out, size_t *out_len) {
    if (!d || !out || !out_len) return -1;
    size_t spent_sz = (size_t)d->spent_count * (64 + 4);
    size_t created_sz = (size_t)d->created_count * (64 + 4 + 32 + 8);
    size_t total = 4 + spent_sz + 4 + created_sz;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    uint8_t *p = buf;

    uint32_t sc_be = htonl(d->spent_count);
    memcpy(p, &sc_be, 4); p += 4;
    for (uint32_t i = 0; i < d->spent_count; i++) {
        memcpy(p, d->spent[i].prev_tx_hash, 64); p += 64;
        uint32_t oi_be = htonl(d->spent[i].output_index);
        memcpy(p, &oi_be, 4); p += 4;
    }

    uint32_t cc_be = htonl(d->created_count);
    memcpy(p, &cc_be, 4); p += 4;
    for (uint32_t i = 0; i < d->created_count; i++) {
        memcpy(p, d->created[i].tx_hash, 64); p += 64;
        uint32_t oi_be = htonl(d->created[i].output_index);
        memcpy(p, &oi_be, 4); p += 4;
        memcpy(p, d->created[i].owner_addr, 32); p += 32;
        uint64_t amt_be = mxd_htonll(d->created[i].amount);
        memcpy(p, &amt_be, 8); p += 8;
    }

    *out = buf;
    *out_len = total;
    return 0;
}

int mxd_block_delta_deserialize(const uint8_t *buf, size_t buf_len, mxd_block_delta_t *out) {
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf;
    const uint8_t *end = buf + buf_len;
    if (p + 4 > end) return -1;
    uint32_t sc_be;
    memcpy(&sc_be, p, 4); p += 4;
    uint32_t spent_count = ntohl(sc_be);
    if ((size_t)spent_count * (64 + 4) > (size_t)(end - p)) return -1;
    if (spent_count > 0) {
        out->spent = calloc(spent_count, sizeof(*out->spent));
        if (!out->spent) return -1;
        for (uint32_t i = 0; i < spent_count; i++) {
            memcpy(out->spent[i].prev_tx_hash, p, 64); p += 64;
            uint32_t oi_be;
            memcpy(&oi_be, p, 4); p += 4;
            out->spent[i].output_index = ntohl(oi_be);
        }
        out->spent_count = spent_count;
    }
    if (p + 4 > end) {
        mxd_block_delta_free(out);
        return -1;
    }
    uint32_t cc_be;
    memcpy(&cc_be, p, 4); p += 4;
    uint32_t created_count = ntohl(cc_be);
    if ((size_t)created_count * (64 + 4 + 32 + 8) > (size_t)(end - p)) {
        mxd_block_delta_free(out);
        return -1;
    }
    if (created_count > 0) {
        out->created = calloc(created_count, sizeof(*out->created));
        if (!out->created) {
            mxd_block_delta_free(out);
            return -1;
        }
        for (uint32_t i = 0; i < created_count; i++) {
            memcpy(out->created[i].tx_hash, p, 64); p += 64;
            uint32_t oi_be;
            memcpy(&oi_be, p, 4); p += 4;
            out->created[i].output_index = ntohl(oi_be);
            memcpy(out->created[i].owner_addr, p, 32); p += 32;
            uint64_t amt_be;
            memcpy(&amt_be, p, 8); p += 8;
            out->created[i].amount = mxd_ntohll(amt_be);
        }
        out->created_count = created_count;
    }
    return 0;
}

void mxd_block_delta_free(mxd_block_delta_t *d) {
    if (!d) return;
    free(d->spent);
    free(d->created);
    d->spent = NULL;
    d->created = NULL;
    d->spent_count = 0;
    d->created_count = 0;
}

/*
 * Reverse the recorded UTXO state changes:
 *   - For each spent UTXO: flip is_spent back to 0 by re-adding the UTXO
 *     record (the underlying record was kept around with is_spent=1; we just
 *     overwrite it with is_spent=0).
 *   - For each created UTXO: delete it from the DB.
 */
int mxd_reverse_utxo_delta(const mxd_block_delta_t *d) {
    if (!d) return -1;

    /* Re-spendify the spent UTXOs (set is_spent=0). */
    for (uint32_t i = 0; i < d->spent_count; i++) {
        mxd_utxo_t utxo;
        memset(&utxo, 0, sizeof(utxo));
        if (mxd_find_utxo(d->spent[i].prev_tx_hash, d->spent[i].output_index, &utxo) != 0) {
            MXD_LOG_WARN("delta", "reverse: could not find spent UTXO output_index=%u", d->spent[i].output_index);
            continue;
        }
        utxo.is_spent = 0;
        if (mxd_add_utxo(&utxo) != 0) {
            MXD_LOG_ERROR("delta", "reverse: failed to re-add UTXO output_index=%u", d->spent[i].output_index);
            mxd_free_utxo(&utxo);
            return -1;
        }
        mxd_free_utxo(&utxo);
    }

    /* Delete the created UTXOs (they shouldn't exist on the new canonical fork). */
    for (uint32_t i = 0; i < d->created_count; i++) {
        if (mxd_remove_utxo(d->created[i].tx_hash, d->created[i].output_index) != 0) {
            MXD_LOG_WARN("delta", "reverse: failed to remove created UTXO output_index=%u", d->created[i].output_index);
            /* Continue anyway — best effort. */
        }
    }

    return 0;
}

int mxd_apply_utxo_delta(const mxd_block_delta_t *d) {
    if (!d) return -1;

    /* Mark spent inputs spent. */
    for (uint32_t i = 0; i < d->spent_count; i++) {
        if (mxd_mark_utxo_spent(d->spent[i].prev_tx_hash, d->spent[i].output_index) != 0) {
            MXD_LOG_WARN("delta", "apply: failed to mark spent output_index=%u (already spent or missing)",
                         d->spent[i].output_index);
        }
    }

    /* Re-create the outputs. */
    for (uint32_t i = 0; i < d->created_count; i++) {
        mxd_utxo_t utxo;
        memset(&utxo, 0, sizeof(utxo));
        memcpy(utxo.tx_hash, d->created[i].tx_hash, 64);
        utxo.output_index = d->created[i].output_index;
        memcpy(utxo.owner_key, d->created[i].owner_addr, 32);
        utxo.amount = d->created[i].amount;
        utxo.required_signatures = 1;
        utxo.cosigner_keys = NULL;
        utxo.cosigner_count = 0;
        utxo.is_spent = 0;
        if (mxd_add_utxo(&utxo) != 0) {
            MXD_LOG_ERROR("delta", "apply: failed to add UTXO output_index=%u", d->created[i].output_index);
            return -1;
        }
    }
    return 0;
}

static void make_delta_key(const uint8_t block_hash[64], uint8_t key[DELTA_KEY_PREFIX_LEN + 64]) {
    memcpy(key, DELTA_KEY_PREFIX, DELTA_KEY_PREFIX_LEN);
    memcpy(key + DELTA_KEY_PREFIX_LEN, block_hash, 64);
}

/* Public wrapper (F8-1): mxd_store_block uses this to fold the delta key
 * into its WriteBatch instead of issuing a separate rocksdb_put. */
void mxd_block_delta_make_key(const uint8_t block_hash[64],
                               uint8_t out_key[MXD_BLOCK_DELTA_KEY_LEN]) {
    make_delta_key(block_hash, out_key);
}

int mxd_store_block_delta(const uint8_t block_hash[64], const mxd_block_delta_t *d) {
    if (!block_hash || !d || !mxd_get_rocksdb_db()) return -1;
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    if (mxd_block_delta_serialize(d, &buf, &buf_len) != 0) return -1;
    uint8_t key[DELTA_KEY_PREFIX_LEN + 64];
    make_delta_key(block_hash, key);
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                (char *)key, sizeof(key), (char *)buf, buf_len, &err);
    free(buf);
    if (err) {
        MXD_LOG_ERROR("delta", "Failed to store block delta: %s", err);
        free(err);
        return -1;
    }
    return 0;
}

int mxd_load_block_delta(const uint8_t block_hash[64], mxd_block_delta_t *out) {
    if (!block_hash || !out || !mxd_get_rocksdb_db()) return -1;
    uint8_t key[DELTA_KEY_PREFIX_LEN + 64];
    make_delta_key(block_hash, key);
    char *err = NULL;
    size_t value_len = 0;
    char *value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                              (char *)key, sizeof(key), &value_len, &err);
    if (err) {
        free(err);
        return -1;
    }
    if (!value) return -1;
    int rc = mxd_block_delta_deserialize((const uint8_t *)value, value_len, out);
    free(value);
    return rc;
}

int mxd_delete_block_delta(const uint8_t block_hash[64]) {
    if (!block_hash || !mxd_get_rocksdb_db()) return -1;
    uint8_t key[DELTA_KEY_PREFIX_LEN + 64];
    make_delta_key(block_hash, key);
    char *err = NULL;
    rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                   (char *)key, sizeof(key), &err);
    if (err) {
        MXD_LOG_ERROR("delta", "Failed to delete block delta: %s", err);
        free(err);
        return -1;
    }
    return 0;
}
