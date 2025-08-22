#include "mxd_logging.h"

#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rocksdb/c.h>

#include "../include/mxd_rocksdb_globals.h"

static rocksdb_options_t *options = NULL;
static char *db_path_global = NULL;

static size_t utxo_count = 0;
static size_t pruned_count = 0;
static double total_value = 0.0;

#define LRU_CACHE_SIZE 5000
static mxd_utxo_t *lru_cache = NULL;
static size_t lru_cache_count = 0;
static uint64_t *lru_access_counter = NULL;
static uint64_t current_access_count = 0;

static int serialize_utxo(const mxd_utxo_t *utxo, uint8_t **data, size_t *data_len) {
    if (!utxo || !data || !data_len) {
        return -1;
    }

    size_t size = sizeof(mxd_utxo_t);
    if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
        size += utxo->cosigner_count * 256;
    }

    // Allocate memory
    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    // Copy UTXO structure
    memcpy(*data, utxo, sizeof(mxd_utxo_t));
    
    // Copy cosigner keys if present
    if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
        memcpy(*data + sizeof(mxd_utxo_t), utxo->cosigner_keys, utxo->cosigner_count * 256);
    }

    *data_len = size;
    return 0;
}

static int deserialize_utxo(const uint8_t *data, size_t data_len, mxd_utxo_t *utxo) {
    if (!data || !utxo || data_len < sizeof(mxd_utxo_t)) {
        return -1;
    }

    // Copy UTXO structure
    memcpy(utxo, data, sizeof(mxd_utxo_t));
    
    utxo->cosigner_keys = NULL;
    
    // Copy cosigner keys if present
    if (utxo->cosigner_count > 0 && data_len > sizeof(mxd_utxo_t)) {
        utxo->cosigner_keys = malloc(utxo->cosigner_count * 256);
        if (!utxo->cosigner_keys) {
            return -1;
        }
        memcpy(utxo->cosigner_keys, data + sizeof(mxd_utxo_t), utxo->cosigner_count * 256);
    }

    return 0;
}

static void create_utxo_key(const uint8_t tx_hash[64], uint32_t output_index, uint8_t *key, size_t *key_len) {
    memcpy(key, "utxo:", 5);
    memcpy(key + 5, tx_hash, 64);
    memcpy(key + 5 + 64, &output_index, sizeof(uint32_t));
    *key_len = 5 + 64 + sizeof(uint32_t);
}

static void create_pubkey_hash_key(const uint8_t pubkey_hash[20], uint8_t *key, size_t *key_len) {
    memcpy(key, "pubkey:", 7);
    memcpy(key + 7, pubkey_hash, 20);
    *key_len = 7 + 20;
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
    
    // Check if UTXO is already in cache
    for (size_t i = 0; i < lru_cache_count; i++) {
        if (memcmp(lru_cache[i].tx_hash, utxo->tx_hash, 64) == 0 &&
            lru_cache[i].output_index == utxo->output_index) {
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
        
        // Copy cosigner keys if present
        if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
            lru_cache[lru_index].cosigner_keys = malloc(utxo->cosigner_count * 256);
            if (lru_cache[lru_index].cosigner_keys) {
                memcpy(lru_cache[lru_index].cosigner_keys, utxo->cosigner_keys, utxo->cosigner_count * 256);
            }
        }
        
        lru_access_counter[lru_index] = ++current_access_count;
    } else {
        free(lru_cache[lru_cache_count].cosigner_keys);
        lru_cache[lru_cache_count].cosigner_keys = NULL;
        
        memcpy(&lru_cache[lru_cache_count], utxo, sizeof(mxd_utxo_t));
        
        // Copy cosigner keys if present
        if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
            lru_cache[lru_cache_count].cosigner_keys = malloc(utxo->cosigner_count * 256);
            if (lru_cache[lru_cache_count].cosigner_keys) {
                memcpy(lru_cache[lru_cache_count].cosigner_keys, utxo->cosigner_keys, utxo->cosigner_count * 256);
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
            
            // Copy cosigner keys if present
            if (lru_cache[i].cosigner_count > 0 && lru_cache[i].cosigner_keys) {
                utxo->cosigner_keys = malloc(lru_cache[i].cosigner_count * 256);
                if (!utxo->cosigner_keys) {
                    return -1;
                }
                memcpy(utxo->cosigner_keys, lru_cache[i].cosigner_keys, lru_cache[i].cosigner_count * 256);
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
    
    rocksdb_options_set_write_buffer_size(options, 64 * 1024 * 1024); // 64MB
    rocksdb_options_set_max_write_buffer_number(options, 3);
    rocksdb_options_set_target_file_size_base(options, 32 * 1024 * 1024); // 32MB
    
    rocksdb_options_set_paranoid_checks(options, 1);
    rocksdb_options_set_recycle_log_file_num(options, 1);
    rocksdb_options_set_skip_stats_update_on_db_open(options, 1);
    
    rocksdb_cache_t *cache = rocksdb_cache_create_lru(128 * 1024 * 1024); // 128MB
    rocksdb_block_based_table_options_t *table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(table_options, cache);
    rocksdb_options_set_block_based_table_factory(options, table_options);
    
    rocksdb_readoptions_set_verify_checksums(readoptions, 1);
    
    rocksdb_writeoptions_set_sync(writeoptions, 1);
    
    char *err = NULL;
    rocksdb_destroy_db(options, db_path, &err);
    if (err != NULL) {
        free(err);
        err = NULL;
    }
    
    char lock_path[1024];
    snprintf(lock_path, sizeof(lock_path), "%s/LOCK", db_path);
    remove(lock_path);
    
    // Open database
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
        return -1;
    }
    
    // Initialize statistics
    utxo_count = 0;
    pruned_count = 0;
    total_value = 0.0;
    
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
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)key, key_len, (char *)data, data_len, &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to store UTXO: %s", err);
        free(err);
        free(data);
        return -1;
    }
    
    // Create secondary index by pubkey hash
    uint8_t pubkey_key[7 + 20 + 64 + sizeof(uint32_t)];
    size_t pubkey_key_len;
    create_pubkey_hash_key(utxo->pubkey_hash, pubkey_key, &pubkey_key_len);
    memcpy(pubkey_key + pubkey_key_len, utxo->tx_hash, 64);
    memcpy(pubkey_key + pubkey_key_len + 64, &utxo->output_index, sizeof(uint32_t));
    pubkey_key_len += 64 + sizeof(uint32_t);
    
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)pubkey_key, pubkey_key_len, "", 0, &err);
    if (err) {
        MXD_LOG_ERROR("utxo", "Failed to store pubkey hash index: %s", err);
        free(err);
        free(data);
        return -1;
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
    
    uint8_t pubkey_key[7 + 20 + 64 + sizeof(uint32_t)];
    size_t pubkey_key_len;
    create_pubkey_hash_key(utxo.pubkey_hash, pubkey_key, &pubkey_key_len);
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
    
    if (find_in_lru_cache(tx_hash, output_index, utxo) == 0) {
        return 0;
    }
    
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
    
    // Add to LRU cache
    if (result == 0) {
        add_to_lru_cache(utxo);
    }
    
    free(value);
    return result;
}

double mxd_get_balance(const uint8_t public_key[256]) {
    if (!public_key || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t pubkey_hash[20];
    if (mxd_hash160(public_key, 256, pubkey_hash) != 0) {
        return -1;
    }
    
    mxd_utxo_t *utxos = NULL;
    size_t utxo_count_local = 0;
    if (mxd_get_utxos_by_pubkey_hash(pubkey_hash, &utxos, &utxo_count_local) != 0) {
        return 0.0; // No UTXOs found
    }
    
    double balance = 0.0;
    for (size_t i = 0; i < utxo_count_local; i++) {
        if (!utxos[i].is_spent) {
            balance += utxos[i].amount;
        }
    }
    
    // Free UTXOs
    for (size_t i = 0; i < utxo_count_local; i++) {
        mxd_free_utxo(&utxos[i]);
    }
    free(utxos);
    
    return balance;
}

int mxd_verify_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                    const uint8_t public_key[256]) {
    if (!tx_hash || !public_key || !mxd_get_rocksdb_db()) {
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
    
    if (memcmp(utxo.owner_key, public_key, 256) == 0) {
        mxd_free_utxo(&utxo);
        return 0; // UTXO is spendable
    }
    
    // Check if public key is a cosigner
    for (uint32_t j = 0; j < utxo.cosigner_count; j++) {
        if (memcmp(utxo.cosigner_keys + (j * 256), public_key, 256) == 0) {
            mxd_free_utxo(&utxo);
            return 0; // UTXO is spendable by cosigner
        }
    }
    
    mxd_free_utxo(&utxo);
    return -1; // Not authorized
}

// Create multi-signature UTXO
int mxd_create_multisig_utxo(mxd_utxo_t *utxo, const uint8_t *cosigner_keys,
                             uint32_t cosigner_count,
                             uint32_t required_signatures) {
    if (!utxo || !cosigner_keys || cosigner_count == 0 ||
        required_signatures == 0 || required_signatures > cosigner_count) {
        return -1;
    }
    
    // Allocate space for cosigner keys
    utxo->cosigner_keys = malloc(cosigner_count * 256);
    if (!utxo->cosigner_keys) {
        return -1;
    }
    
    // Copy cosigner keys
    memcpy(utxo->cosigner_keys, cosigner_keys, cosigner_count * 256);
    utxo->cosigner_count = cosigner_count;
    utxo->required_signatures = required_signatures;
    
    if (mxd_hash160(utxo->owner_key, 256, utxo->pubkey_hash) != 0) {
        free(utxo->cosigner_keys);
        utxo->cosigner_keys = NULL;
        return -1;
    }
    
    // Initialize as unspent
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

int mxd_verify_utxo_funds(const uint8_t tx_hash[64], uint32_t output_index, double amount) {
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

int mxd_get_utxos_by_pubkey_hash(const uint8_t pubkey_hash[20], mxd_utxo_t **utxos, size_t *utxo_count) {
    if (!pubkey_hash || !utxos || !utxo_count || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // Create prefix key for pubkey hash index
    uint8_t prefix_key[7 + 20];
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
int mxd_get_utxo_stats(size_t *total_count, size_t *pruned_count_out, double *total_value_out) {
    if (!total_count || !pruned_count_out || !total_value_out || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    // Reset statistics
    size_t count = 0;
    size_t pruned = 0;
    double value = 0.0;
    
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
    
    return 0;
}

int mxd_mark_utxo_spent(const uint8_t tx_hash[64], uint32_t output_index) {
    if (!tx_hash || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    mxd_utxo_t utxo;
    memset(&utxo, 0, sizeof(mxd_utxo_t));
    if (mxd_find_utxo(tx_hash, output_index, &utxo) != 0) {
        return -1; // UTXO not found
    }
    
    // Check if already spent
    if (utxo.is_spent) {
        mxd_free_utxo(&utxo);
        return 0; // Already spent
    }
    
    utxo.is_spent = 1;
    
    // Update UTXO in database
    int result = mxd_add_utxo(&utxo);
    
    mxd_free_utxo(&utxo);
    return result;
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
