#include "mxd_logging.h"

#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_endian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rocksdb/c.h>

#include "../include/mxd_rocksdb_globals.h"
#include <pthread.h>
#include "../include/mxd_error.h"

static rocksdb_options_t *options = NULL;
static rocksdb_cache_t *block_cache = NULL;
static rocksdb_block_based_table_options_t *table_options = NULL;
static char *db_path_global = NULL;

static size_t utxo_count = 0;
static size_t pruned_count = 0;
static mxd_amount_t total_value = 0;

static pthread_mutex_t db_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int utxo_db_initialized = 0;

#define LRU_CACHE_SIZE 5000
static mxd_utxo_t *lru_cache = NULL;
static size_t lru_cache_count = 0;
static uint64_t *lru_access_counter = NULL;
static uint64_t current_access_count = 0;

// BLOCKER FIX: Serialize UTXO with proper endian conversion
static int serialize_utxo(const mxd_utxo_t *utxo, uint8_t **data, size_t *data_len) {
    if (!utxo || !data || !data_len) {
        return -1;
    }

    // Calculate size with field-by-field serialization
    size_t size = 64 + 4 + 32 + 8 + 4 + 4 + 1; // tx_hash + output_index + owner_key(addr32) + amount + required_signatures + cosigner_count + is_spent
    if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
        size += utxo->cosigner_count * 32;
    }

    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    uint8_t *ptr = *data;
    
    // Serialize with big-endian byte order for cross-platform compatibility
    memcpy(ptr, utxo->tx_hash, 64); ptr += 64;
    
    uint32_t output_index_be = htonl(utxo->output_index);
    memcpy(ptr, &output_index_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    memcpy(ptr, utxo->owner_key, 32); ptr += 32;
    
    uint64_t amount_be = mxd_htonll(utxo->amount);
    memcpy(ptr, &amount_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    
    uint32_t required_sigs_be = htonl(utxo->required_signatures);
    memcpy(ptr, &required_sigs_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    uint32_t cosigner_count_be = htonl(utxo->cosigner_count);
    memcpy(ptr, &cosigner_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    
    memcpy(ptr, &utxo->is_spent, 1); ptr += 1;
    
    if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
        memcpy(ptr, utxo->cosigner_keys, utxo->cosigner_count * 32);
        ptr += utxo->cosigner_count * 32;
    }

    *data_len = size;
    return 0;
}

// BLOCKER FIX: Deserialize UTXO with proper endian conversion
static int deserialize_utxo(const uint8_t *data, size_t data_len, mxd_utxo_t *utxo) {
    size_t min_size = 64 + 4 + 32 + 8 + 4 + 4 + 1;
    if (!data || !utxo || data_len < min_size) {
        return -1;
    }

    const uint8_t *ptr = data;
    
    // Deserialize with big-endian byte order conversion
    memcpy(utxo->tx_hash, ptr, 64); ptr += 64;
    
    uint32_t output_index_be;
    memcpy(&output_index_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    utxo->output_index = ntohl(output_index_be);
    
    memcpy(utxo->owner_key, ptr, 32); ptr += 32;
    
    uint64_t amount_be;
    memcpy(&amount_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    utxo->amount = mxd_ntohll(amount_be);
    
    uint32_t required_sigs_be;
    memcpy(&required_sigs_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    utxo->required_signatures = ntohl(required_sigs_be);
    
    uint32_t cosigner_count_be;
    memcpy(&cosigner_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    utxo->cosigner_count = ntohl(cosigner_count_be);
    
    memcpy(&utxo->is_spent, ptr, 1); ptr += 1;
    
    utxo->cosigner_keys = NULL;
    
    if (utxo->cosigner_count > 0) {
        // Cap cosigner count to prevent integer overflow (20 * count)
        if (utxo->cosigner_count > 1000) {
            return -1;
        }
        size_t cosigner_size = utxo->cosigner_count * 32;
        if (data_len < min_size + cosigner_size) {
            return -1;
        }
        utxo->cosigner_keys = malloc(cosigner_size);
        if (!utxo->cosigner_keys) {
            return -1;
        }
        memcpy(utxo->cosigner_keys, ptr, cosigner_size);
    }

    return 0;
}

static void create_utxo_key(const uint8_t tx_hash[64], uint32_t output_index, uint8_t *key, size_t *key_len) {
    memcpy(key, "utxo:", 5);
    memcpy(key + 5, tx_hash, 64);
    memcpy(key + 5 + 64, &output_index, sizeof(uint32_t));
    *key_len = 5 + 64 + sizeof(uint32_t);
}

static void create_pubkey_hash_key(const uint8_t pubkey_hash[32], uint8_t *key, size_t *key_len) {
    memcpy(key, "pubkey:", 7);
    memcpy(key + 7, pubkey_hash, 32);
    *key_len = 7 + 32;
}

// Initialize LRU cache
static int init_lru_cache() {
    if (lru_cache) {
        for (size_t i = 0; i < lru_cache_count; i++) {
            free(lru_cache[i].cosigner_keys);
        }
        free(lru_cache);
        free(lru_access_counter);
    }
    
    // Allocate memory for cache
    lru_cache = calloc(LRU_CACHE_SIZE, sizeof(mxd_utxo_t));
    if (!lru_cache) {
        return -1;
    }
    
    lru_access_counter = calloc(LRU_CACHE_SIZE, sizeof(uint64_t));
    if (!lru_access_counter) {
        free(lru_cache);
        lru_cache = NULL;
        return -1;
    }
    
    lru_cache_count = 0;
    current_access_count = 0;
    
    return 0;
}

static void add_to_lru_cache(const mxd_utxo_t *utxo) {
    if (!utxo || !lru_cache) return;
    
    // Check if UTXO is already in cache - update it if found
    for (size_t i = 0; i < lru_cache_count; i++) {
        if (memcmp(lru_cache[i].tx_hash, utxo->tx_hash, 64) == 0 &&
            lru_cache[i].output_index == utxo->output_index) {
            free(lru_cache[i].cosigner_keys);
            lru_cache[i].cosigner_keys = NULL;
            memcpy(&lru_cache[i], utxo, sizeof(mxd_utxo_t));
            if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
                lru_cache[i].cosigner_keys = malloc(utxo->cosigner_count * 32);
                if (lru_cache[i].cosigner_keys) {
                    memcpy(lru_cache[i].cosigner_keys, utxo->cosigner_keys, utxo->cosigner_count * 32);
                }
            }
            lru_access_counter[i] = ++current_access_count;
            return;
        }
    }
    
    if (lru_cache_count == LRU_CACHE_SIZE) {
        size_t lru_index = 0;
        uint64_t min_access_count = lru_access_counter[0];
        
        for (size_t i = 1; i < LRU_CACHE_SIZE; i++) {
            if (lru_access_counter[i] < min_access_count) {
                min_access_count = lru_access_counter[i];
                lru_index = i;
            }
        }
        
        free(lru_cache[lru_index].cosigner_keys);
        lru_cache[lru_index].cosigner_keys = NULL;
        
        memcpy(&lru_cache[lru_index], utxo, sizeof(mxd_utxo_t));
        
        if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
            lru_cache[lru_index].cosigner_keys = malloc(utxo->cosigner_count * 32);
            if (lru_cache[lru_index].cosigner_keys) {
                memcpy(lru_cache[lru_index].cosigner_keys, utxo->cosigner_keys, utxo->cosigner_count * 32);
            }
        }
        
        lru_access_counter[lru_index] = ++current_access_count;
    } else {
        free(lru_cache[lru_cache_count].cosigner_keys);
        lru_cache[lru_cache_count].cosigner_keys = NULL;
        
        memcpy(&lru_cache[lru_cache_count], utxo, sizeof(mxd_utxo_t));
        
        if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
            lru_cache[lru_cache_count].cosigner_keys = malloc(utxo->cosigner_count * 32);
            if (lru_cache[lru_cache_count].cosigner_keys) {
                memcpy(lru_cache[lru_cache_count].cosigner_keys, utxo->cosigner_keys, utxo->cosigner_count * 32);
            }
        }
        
        lru_access_counter[lru_cache_count] = ++current_access_count;
        lru_cache_count++;
    }
}

static int find_in_lru_cache(const uint8_t tx_hash[64], uint32_t output_index, mxd_utxo_t *utxo) {
    if (!tx_hash || !utxo || !lru_cache) return -1;
    
    for (size_t i = 0; i < lru_cache_count; i++) {
        if (memcmp(lru_cache[i].tx_hash, tx_hash, 64) == 0 &&
            lru_cache[i].output_index == output_index) {
            // Copy UTXO data
            memcpy(utxo, &lru_cache[i], sizeof(mxd_utxo_t));
            
            if (lru_cache[i].cosigner_count > 0 && lru_cache[i].cosigner_keys) {
                utxo->cosigner_keys = malloc(lru_cache[i].cosigner_count * 32);
                if (!utxo->cosigner_keys) {
                    return -1;
                }
                memcpy(utxo->cosigner_keys, lru_cache[i].cosigner_keys, lru_cache[i].cosigner_count * 32);
            } else {
                utxo->cosigner_keys = NULL;
            }
            
            lru_access_counter[i] = ++current_access_count;
            return 0;
        }
    }
    
    return -1; // Not found in cache
}

// Initialize UTXO database with persistent storage
int mxd_init_utxo_db(const char *db_path) {
    if (!db_path) return -1;
    
    pthread_mutex_lock(&db_init_mutex);
    if (utxo_db_initialized) {
        pthread_mutex_unlock(&db_init_mutex);
        return 0;
    }
    
    if (mxd_get_rocksdb_db() != NULL) {
        mxd_close_utxo_db();
    }
    
    if (db_path_global) free(db_path_global);
    db_path_global = strdup(db_path);
    
    // Create RocksDB options
    options = rocksdb_options_create();
    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    
    rocksdb_options_set_create_if_missing(options, 1);
    rocksdb_options_set_compression(options, rocksdb_lz4_compression);
    
    size_t write_buffer_size = 16 * 1024 * 1024; // 16MB (reduced from 64MB)
    int max_write_buffer_number = 2; // 2 (reduced from 3)
    size_t block_cache_size = 32 * 1024 * 1024; // 32MB (reduced from 128MB)
    
    rocksdb_options_set_write_buffer_size(options, write_buffer_size);
    rocksdb_options_set_max_write_buffer_number(options, max_write_buffer_number);
    rocksdb_options_set_target_file_size_base(options, 16 * 1024 * 1024); // 16MB (reduced from 32MB)
    
    rocksdb_options_set_paranoid_checks(options, 1);
    rocksdb_options_set_skip_stats_update_on_db_open(options, 1);
    rocksdb_options_set_max_open_files(options, -1); // Keep all SST files open to prevent fd reuse races during compaction
    rocksdb_options_set_max_background_jobs(options, 2); // Allow concurrent flush + compaction
    rocksdb_options_set_stats_dump_period_sec(options, 0); // Disable periodic stats dump to prevent background thread issues
    
    MXD_LOG_INFO("utxo", "RocksDB UTXO settings: write_buffer=%zu MB, max_buffers=%d, block_cache=%zu MB, total_est=%zu MB",
                 write_buffer_size / (1024*1024), max_write_buffer_number, block_cache_size / (1024*1024),
                 (write_buffer_size * max_write_buffer_number + block_cache_size) / (1024*1024));
    
    block_cache = rocksdb_cache_create_lru(block_cache_size);
    table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(table_options, block_cache);
    rocksdb_options_set_block_based_table_factory(options, table_options);
    
    rocksdb_readoptions_set_verify_checksums(readoptions, 1);
    
    rocksdb_writeoptions_set_sync(writeoptions, 0); // WAL provides crash safety; fsync per-write causes backpressure during sync
    
    // Open database (removed destructive rocksdb_destroy_db and LOCK removal)
    char *err = NULL;
    rocksdb_t *db = rocksdb_open(options, db_path, &err);
    
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to open UTXO database: %s", err);
        free(err);
        
        rocksdb_options_set_error_if_exists(options, 0);
        rocksdb_options_set_create_if_missing(options, 1);
        
        err = NULL;
        db = rocksdb_open(options, db_path, &err);
        if (err) {
            MXD_LOG_ERROR("utxo", "Second attempt to open UTXO database failed: %s", err);
            free(err);
            pthread_mutex_unlock(&db_init_mutex);
            return -1;
        }
    }
    
    mxd_set_rocksdb_db(db);
    mxd_set_rocksdb_readoptions(readoptions);
    mxd_set_rocksdb_writeoptions(writeoptions);
    
    // Initialize LRU cache
    if (init_lru_cache() != 0) {
        rocksdb_close(mxd_get_rocksdb_db());
        mxd_set_rocksdb_db(NULL);
        pthread_mutex_unlock(&db_init_mutex);
        return -1;
    }
    
    // Initialize statistics
    utxo_count = 0;
    pruned_count = 0;
    total_value = 0;
    
    // Load persisted UTXO statistics on startup with version checking
    // Version 1 format: [version:uint32_t][utxo_count:size_t][pruned_count:size_t][total_value:mxd_amount_t]
    // Legacy format (v0): [utxo_count:size_t][pruned_count:size_t][total_value:mxd_amount_t]
    uint8_t stats_key[] = "utxo_stats";
    char *value = NULL;
    size_t value_len = 0;
    err = NULL;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), 
                       (char *)stats_key, sizeof(stats_key) - 1, &value_len, &err);
    
    size_t expected_v1_len = sizeof(uint32_t) + sizeof(size_t) * 2 + sizeof(mxd_amount_t);
    size_t expected_v0_len = sizeof(size_t) * 2 + sizeof(mxd_amount_t);
    
    if (value && value_len == expected_v1_len) {
        // Version 1 format with version field
        uint32_t version;
        memcpy(&version, value, sizeof(uint32_t));
        if (version == 1) {
            memcpy(&utxo_count, value + sizeof(uint32_t), sizeof(size_t));
            memcpy(&pruned_count, value + sizeof(uint32_t) + sizeof(size_t), sizeof(size_t));
            memcpy(&total_value, value + sizeof(uint32_t) + sizeof(size_t) * 2, sizeof(mxd_amount_t));
            MXD_LOG_DEBUG("utxo", "Loaded UTXO stats v1: count=%zu, pruned=%zu, value=%lu",
                          utxo_count, pruned_count, (unsigned long)total_value);
        } else {
            MXD_LOG_WARN("utxo", "Unknown UTXO stats version %u, ignoring persisted stats", version);
        }
        free(value);
    } else if (value && value_len == expected_v0_len) {
        // Legacy format without version field - migrate on next save
        memcpy(&utxo_count, value, sizeof(size_t));
        memcpy(&pruned_count, value + sizeof(size_t), sizeof(size_t));
        memcpy(&total_value, value + sizeof(size_t) * 2, sizeof(mxd_amount_t));
        MXD_LOG_INFO("utxo", "Migrating UTXO stats from legacy format to v1");
        free(value);
    } else if (err) {
        free(err);
    } else if (value) {
        MXD_LOG_WARN("utxo", "Invalid UTXO stats size %zu, ignoring persisted stats", value_len);
        free(value);
    }
    
    utxo_db_initialized = 1;
    pthread_mutex_unlock(&db_init_mutex);
    return 0;
}

int mxd_reset_utxo_db(const char *db_path) {
    if (!db_path) return -1;
    
    pthread_mutex_lock(&db_init_mutex);
    
    if (mxd_get_rocksdb_db() != NULL) {
        mxd_close_utxo_db();
    }
    
    rocksdb_options_t *reset_options = rocksdb_options_create();
    char *err = NULL;
    rocksdb_destroy_db(reset_options, db_path, &err);
    rocksdb_options_destroy(reset_options);
    
    if (err != NULL) {
        MXD_LOG_ERROR("utxo", "Failed to destroy UTXO database: %s", err);
        free(err);
        pthread_mutex_unlock(&db_init_mutex);
        return -1;
    }
    
    utxo_db_initialized = 0;
    pthread_mutex_unlock(&db_init_mutex);
    return 0;
}

int mxd_add_utxo(const mxd_utxo_t *utxo) {
    if (!utxo || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // Create key for UTXO lookup
    uint8_t key[5 + 64 + sizeof(uint32_t)];
    size_t key_len;
    create_utxo_key(utxo->tx_hash, utxo->output_index, key, &key_len);
    
    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_utxo(utxo, &data, &data_len) != 0) {
        return -1;
    }
    
    // Create secondary index key
    uint8_t pubkey_key[7 + 32 + 64 + sizeof(uint32_t)];
    size_t pubkey_key_len;
    create_pubkey_hash_key(utxo->owner_key, pubkey_key, &pubkey_key_len);
    memcpy(pubkey_key + pubkey_key_len, utxo->tx_hash, 64);
    memcpy(pubkey_key + pubkey_key_len + 64, &utxo->output_index, sizeof(uint32_t));
    pubkey_key_len += 64 + sizeof(uint32_t);
    
    // Use WriteBatch for atomic UTXO + index write
    rocksdb_writebatch_t *batch = rocksdb_writebatch_create();
    rocksdb_writebatch_put(batch, (char *)key, key_len, (char *)data, data_len);
    rocksdb_writebatch_put(batch, (char *)pubkey_key, pubkey_key_len, "", 0);
    
    char *err = NULL;
    rocksdb_write(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), batch, &err);
    rocksdb_writebatch_destroy(batch);
    
    if (err) {
        int ret = mxd_is_io_error(err) ? MXD_ERR_IO : MXD_ERR_GENERIC;
        MXD_LOG_ERROR("utxo", "Failed to store UTXO: %s", err);
        free(err);
        free(data);
        return ret;
    }
    
    // Add to LRU cache
    add_to_lru_cache(utxo);
    
    // Update statistics
    utxo_count++;
    total_value += utxo->amount;
    
    free(data);
    return 0;
}

int mxd_remove_utxo(const uint8_t tx_hash[64], uint32_t output_index) {
    if (!tx_hash || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return -1; // UTXO not found
    }
    
    // Create key for UTXO lookup
    uint8_t key[5 + 64 + sizeof(uint32_t)];
    size_t key_len;
    create_utxo_key(tx_hash, output_index, key, &key_len);
    
    char *err = NULL;
    rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)key, key_len, &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to remove UTXO: %s", err);
        free(err);
        mxd_free_utxo(&utxo);
        return -1;
    }
    
    uint8_t pubkey_key[7 + 32 + 64 + sizeof(uint32_t)];
    size_t pubkey_key_len;
    create_pubkey_hash_key(utxo.owner_key, pubkey_key, &pubkey_key_len);
    memcpy(pubkey_key + pubkey_key_len, tx_hash, 64);
    memcpy(pubkey_key + pubkey_key_len + 64, &output_index, sizeof(uint32_t));
    pubkey_key_len += 64 + sizeof(uint32_t);
    
    rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)pubkey_key, pubkey_key_len, &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to remove pubkey hash index: %s", err);
        free(err);
        mxd_free_utxo(&utxo);
        return -1;
    }
    
    // Remove from LRU cache
    if (lru_cache) {
        for (size_t i = 0; i < lru_cache_count; i++) {
            if (memcmp(lru_cache[i].tx_hash, tx_hash, 64) == 0 &&
                lru_cache[i].output_index == output_index) {
                // Free cosigner keys if present
                free(lru_cache[i].cosigner_keys);
                lru_cache[i].cosigner_keys = NULL;
                
                if (i < lru_cache_count - 1) {
                    memcpy(&lru_cache[i], &lru_cache[lru_cache_count - 1], sizeof(mxd_utxo_t));
                    lru_access_counter[i] = lru_access_counter[lru_cache_count - 1];
                    
                    lru_cache[lru_cache_count - 1].cosigner_keys = NULL;
                }
                
                lru_cache_count--;
                break;
            }
        }
    }
    
    // Update statistics
    utxo_count--;
    total_value -= utxo.amount;
    
    mxd_free_utxo(&utxo);
    return 0;
}

int mxd_find_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                  mxd_utxo_t *utxo) {
    if (!tx_hash || !utxo || !mxd_get_rocksdb_db()) {
        return -1;
    }

    // Always read from RocksDB (authoritative source of truth).
    // The LRU cache has no thread safety and caused stale is_spent values
    // to be served during concurrent block processing + HTTP queries.
    // RocksDB has its own block cache, so performance impact is negligible.

    // Create key for UTXO lookup
    uint8_t key[5 + 64 + sizeof(uint32_t)];
    size_t key_len;
    create_utxo_key(tx_hash, output_index, key, &key_len);

    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to retrieve UTXO: %s", err);
        free(err);
        return -1;
    }

    if (!value) {
        return -1; // UTXO not found
    }

    int result = deserialize_utxo((uint8_t *)value, value_len, utxo);

    free(value);
    return result;
}

mxd_amount_t mxd_get_balance(const uint8_t address[32]) {
    if (!address || !mxd_get_rocksdb_db()) {
        return 0;
    }
    
    mxd_utxo_t *utxos = NULL;
    size_t utxo_count_local = 0;
    if (mxd_get_utxos_by_pubkey_hash(address, &utxos, &utxo_count_local) != 0) {
        return 0;
    }
    
    mxd_amount_t balance = 0;
    for (size_t i = 0; i < utxo_count_local; i++) {
        if (!utxos[i].is_spent) {
            balance += utxos[i].amount;
        }
    }
    
    for (size_t i = 0; i < utxo_count_local; i++) {
        mxd_free_utxo(&utxos[i]);
    }
    free(utxos);
    
    return balance;
}

int mxd_verify_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                    const uint8_t address[32]) {
    if (!tx_hash || !address || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return -1;
    }
    
    if (utxo.is_spent) {
        mxd_free_utxo(&utxo);
        return -1;
    }
    
    if (memcmp(utxo.owner_key, address, 32) == 0) {
        mxd_free_utxo(&utxo);
        return 0;
    }

    for (uint32_t j = 0; j < utxo.cosigner_count; j++) {
        if (memcmp(utxo.cosigner_keys + (j * 32), address, 32) == 0) {
            mxd_free_utxo(&utxo);
            return 0;
        }
    }
    
    mxd_free_utxo(&utxo);
    return -1;
}

int mxd_create_multisig_utxo(mxd_utxo_t *utxo, const uint8_t *cosigner_keys,
                             uint32_t cosigner_count,
                             uint32_t required_signatures) {
    if (!utxo || !cosigner_keys || cosigner_count == 0 ||
        required_signatures == 0 || required_signatures > cosigner_count) {
        return -1;
    }
    
    utxo->cosigner_keys = malloc(cosigner_count * 32);
    if (!utxo->cosigner_keys) {
        return -1;
    }

    memcpy(utxo->cosigner_keys, cosigner_keys, cosigner_count * 32);
    utxo->cosigner_count = cosigner_count;
    utxo->required_signatures = required_signatures;
    utxo->is_spent = 0;
    
    return 0;
}

// Free UTXO resources
void mxd_free_utxo(mxd_utxo_t *utxo) {
    if (utxo) {
        free(utxo->cosigner_keys);
        utxo->cosigner_keys = NULL;
        memset(utxo, 0, sizeof(mxd_utxo_t));
    }
}

int mxd_save_utxo_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    return mxd_flush_utxo_db();
}

int mxd_load_utxo_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // RocksDB automatically loads data, just need to update statistics
    return mxd_get_utxo_stats(&utxo_count, &pruned_count, &total_value);
}

int mxd_close_utxo_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_close(mxd_get_rocksdb_db());
    mxd_set_rocksdb_db(NULL);
    
    if (table_options) {
        rocksdb_block_based_options_destroy(table_options);
        table_options = NULL;
    }
    
    if (block_cache) {
        rocksdb_cache_destroy(block_cache);
        block_cache = NULL;
    }
    
    rocksdb_options_destroy(options);
    rocksdb_readoptions_destroy(mxd_get_rocksdb_readoptions());
    rocksdb_writeoptions_destroy(mxd_get_rocksdb_writeoptions());
    options = NULL;
    mxd_set_rocksdb_readoptions(NULL);
    mxd_set_rocksdb_writeoptions(NULL);
    
    free(db_path_global);
    db_path_global = NULL;
    
    if (lru_cache) {
        for (size_t i = 0; i < lru_cache_count; i++) {
            free(lru_cache[i].cosigner_keys);
        }
        free(lru_cache);
        free(lru_access_counter);
        lru_cache = NULL;
        lru_access_counter = NULL;
        lru_cache_count = 0;
    }
    
    return 0;
}

int mxd_verify_utxo_funds(const uint8_t tx_hash[64], uint32_t output_index, mxd_amount_t amount) {
    if (!tx_hash || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return -1; // UTXO not found
    }
    
    // Check if UTXO is spent
    if (utxo.is_spent) {
        mxd_free_utxo(&utxo);
        return -1; // UTXO is already spent
    }
    
    // Check if UTXO has sufficient funds
    int result = (utxo.amount >= amount) ? 0 : -1;
    
    mxd_free_utxo(&utxo);
    return result;
}

int mxd_get_utxos_by_pubkey_hash(const uint8_t pubkey_hash[32], mxd_utxo_t **utxos, size_t *utxo_count) {
    if (!pubkey_hash || !utxos || !utxo_count || !mxd_get_rocksdb_db()) {
        return -1;
    }

    // Create prefix key for pubkey hash index
    uint8_t prefix_key[7 + 32];
    size_t prefix_key_len;
    create_pubkey_hash_key(pubkey_hash, prefix_key, &prefix_key_len);
    
    // Create iterator
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t count = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        // Check if key starts with our prefix
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        count++;
        rocksdb_iter_next(iter);
    }
    
    // Allocate memory for UTXOs
    *utxos = NULL;
    *utxo_count = 0;
    if (count == 0) {
        rocksdb_iter_destroy(iter);
        return 0; // No UTXOs found
    }
    
    *utxos = malloc(count * sizeof(mxd_utxo_t));
    if (!*utxos) {
        rocksdb_iter_destroy(iter);
        return -1;
    }
    memset(*utxos, 0, count * sizeof(mxd_utxo_t));
    
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t index = 0;
    while (rocksdb_iter_valid(iter) && index < count) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        // Check if key starts with our prefix
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        uint8_t tx_hash[64];
        uint32_t output_index;
        memcpy(tx_hash, key + prefix_key_len, 64);
        memcpy(&output_index, key + prefix_key_len + 64, sizeof(uint32_t));
        
        if (mxd_find_utxo(tx_hash, output_index, &(*utxos)[index]) == 0) {
            index++;
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    *utxo_count = index;
    
    return 0;
}

int mxd_prune_spent_utxos(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // Create iterator
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek_to_first(iter);
    
    size_t pruned = 0;
    
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        // Check if key starts with "utxo:"
        if (key_len > 5 && memcmp(key, "utxo:", 5) == 0) {
            size_t value_len;
            const char *value = rocksdb_iter_value(iter, &value_len);
            
            mxd_utxo_t utxo;
            memset(&utxo, 0, sizeof(mxd_utxo_t));
            if (deserialize_utxo((uint8_t *)value, value_len, &utxo) == 0) {
                // Check if UTXO is spent
                if (utxo.is_spent) {
                    uint8_t tx_hash[64];
                    uint32_t output_index;
                    memcpy(tx_hash, key + 5, 64);
                    memcpy(&output_index, key + 5 + 64, sizeof(uint32_t));
                    
                    mxd_remove_utxo(tx_hash, output_index);
                    pruned++;
                }
                
                mxd_free_utxo(&utxo);
            }
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    pruned_count += pruned;
    
    return 0;
}

int mxd_get_utxo_count(size_t *count) {
    if (!count || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    *count = utxo_count;
    return 0;
}

// Get UTXO database statistics
int mxd_get_utxo_stats(size_t *total_count, size_t *pruned_count_out, mxd_amount_t *total_value_out) {
    if (!total_count || !pruned_count_out || !total_value_out || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // Reset statistics
    size_t count = 0;
    size_t pruned = 0;
    mxd_amount_t value = 0;
    
    // Create iterator
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek_to_first(iter);
    
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        // Check if key starts with "utxo:"
        if (key_len > 5 && memcmp(key, "utxo:", 5) == 0) {
            size_t value_len;
            const char *value_str = rocksdb_iter_value(iter, &value_len);
            
            mxd_utxo_t utxo;
            memset(&utxo, 0, sizeof(mxd_utxo_t));
            if (deserialize_utxo((uint8_t *)value_str, value_len, &utxo) == 0) {
                count++;
                if (!utxo.is_spent) {
                    value += utxo.amount;
                } else {
                    pruned++;
                }
                
                mxd_free_utxo(&utxo);
            }
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    
    *total_count = count;
    *pruned_count_out = pruned;
    *total_value_out = value;
    
    // Update global statistics
    utxo_count = count;
    pruned_count = pruned;
    total_value = value;
    
    // Persist UTXO statistics to database for restart recovery with versioned format
    // Version 1 format: [version:uint32_t][utxo_count:size_t][pruned_count:size_t][total_value:mxd_amount_t]
    uint8_t stats_key[] = "utxo_stats";
    uint32_t stats_version = 1;
    uint8_t stats_data[sizeof(uint32_t) + sizeof(size_t) * 2 + sizeof(mxd_amount_t)];
    memcpy(stats_data, &stats_version, sizeof(uint32_t));
    memcpy(stats_data + sizeof(uint32_t), &utxo_count, sizeof(size_t));
    memcpy(stats_data + sizeof(uint32_t) + sizeof(size_t), &pruned_count, sizeof(size_t));
    memcpy(stats_data + sizeof(uint32_t) + sizeof(size_t) * 2, &total_value, sizeof(mxd_amount_t));
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
               (char *)stats_key, sizeof(stats_key) - 1,
               (char *)stats_data, sizeof(stats_data), &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to persist UTXO statistics: %s", err);
        free(err);
    }
    
    return 0;
}

int mxd_mark_utxo_spent(const uint8_t tx_hash[64], uint32_t output_index) {
    if (!tx_hash || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return MXD_ERR_GENERIC; // UTXO not found
    }
    
    // Reject if already spent (prevents double-spend inflation)
    if (utxo.is_spent) {
        mxd_free_utxo(&utxo);
        return MXD_ERR_GENERIC; // Already spent - double-spend attempt
    }
    
    utxo.is_spent = 1;
    
    // Update UTXO in database - propagates MXD_ERR_IO on write failure
    int result = mxd_add_utxo(&utxo);
    
    mxd_free_utxo(&utxo);
    return result;
}

// Add a UTXO write to a batch (does not commit)
int mxd_add_utxo_to_batch(rocksdb_writebatch_t *batch, const mxd_utxo_t *utxo) {
    if (!batch || !utxo) return -1;

    uint8_t key[5 + 64 + sizeof(uint32_t)];
    size_t key_len;
    create_utxo_key(utxo->tx_hash, utxo->output_index, key, &key_len);

    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_utxo(utxo, &data, &data_len) != 0) return -1;

    uint8_t pubkey_key[7 + 32 + 64 + sizeof(uint32_t)];
    size_t pubkey_key_len;
    create_pubkey_hash_key(utxo->owner_key, pubkey_key, &pubkey_key_len);
    memcpy(pubkey_key + pubkey_key_len, utxo->tx_hash, 64);
    memcpy(pubkey_key + pubkey_key_len + 64, &utxo->output_index, sizeof(uint32_t));
    pubkey_key_len += 64 + sizeof(uint32_t);

    rocksdb_writebatch_put(batch, (char *)key, key_len, (char *)data, data_len);
    rocksdb_writebatch_put(batch, (char *)pubkey_key, pubkey_key_len, "", 0);

    free(data);
    return 0;
}

// Mark a UTXO spent in a batch (does not commit)
int mxd_mark_utxo_spent_to_batch(rocksdb_writebatch_t *batch,
                                  const uint8_t tx_hash[64], uint32_t output_index) {
    if (!batch || !tx_hash) return -1;

    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return MXD_ERR_GENERIC;
    }
    if (utxo.is_spent) {
        mxd_free_utxo(&utxo);
        return MXD_ERR_GENERIC;
    }

    utxo.is_spent = 1;
    int result = mxd_add_utxo_to_batch(batch, &utxo);
    mxd_free_utxo(&utxo);
    return result;
}

// Atomically commit a UTXO batch
int mxd_utxo_commit_batch(rocksdb_writebatch_t *batch) {
    if (!batch || !mxd_get_rocksdb_db()) return -1;

    char *err = NULL;
    rocksdb_write(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), batch, &err);
    if (err) {
        int ret = mxd_is_io_error(err) ? MXD_ERR_IO : MXD_ERR_GENERIC;
        MXD_LOG_ERROR("utxo", "Failed to commit UTXO batch: %s", err);
        free(err);
        return ret;
    }
    return 0;
}

int mxd_flush_utxo_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    char *err = NULL;
    rocksdb_flushoptions_t *flushoptions = rocksdb_flushoptions_create();
    rocksdb_flushoptions_set_wait(flushoptions, 1);
    
    rocksdb_flush(mxd_get_rocksdb_db(), flushoptions, &err);
    rocksdb_flushoptions_destroy(flushoptions);
    
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to flush UTXO database: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_compact_utxo_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    char *err = NULL;
    rocksdb_compact_range(mxd_get_rocksdb_db(), NULL, 0, NULL, 0);
    
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to compact UTXO database: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}
