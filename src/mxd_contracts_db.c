#include "mxd_logging.h"

#include "../include/mxd_contracts_db.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_crypto.h"
#include <rocksdb/c.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>

// SECURITY FIX (MEDIUM #13): Global mutex for thread-safe database operations
static pthread_mutex_t contracts_db_mutex = PTHREAD_MUTEX_INITIALIZER;

static rocksdb_t *contracts_db = NULL;
static rocksdb_options_t *contracts_db_options = NULL;
static char *contracts_db_path = NULL;

// Key prefixes for different data types
#define CONTRACT_META_PREFIX  "CM:"  // Contract metadata
#define CONTRACT_STATE_PREFIX "CS:"  // Contract state
#define CONTRACT_CALL_PREFIX  "CC:"  // Contract calls
#define CONTRACT_LIST_KEY     "CL:"  // List of all contract hashes

// Initialize contracts database
int mxd_contracts_db_init(const char *db_path) {
    if (contracts_db) {
        MXD_LOG_WARN("contracts_db", "Database already initialized");
        return 0;
    }

    if (!db_path) {
        MXD_LOG_ERROR("contracts_db", "Invalid database path");
        return -1;
    }

    // Allocate path
    contracts_db_path = strdup(db_path);
    if (!contracts_db_path) {
        MXD_LOG_ERROR("contracts_db", "Failed to allocate database path");
        return -1;
    }

    // Create options
    contracts_db_options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(contracts_db_options, 1);
    rocksdb_options_increase_parallelism(contracts_db_options, 4);
    rocksdb_options_optimize_level_style_compaction(contracts_db_options, 0);
    rocksdb_options_set_max_open_files(contracts_db_options, 1000);

    // Open database
    char *err = NULL;
    contracts_db = rocksdb_open(contracts_db_options, contracts_db_path, &err);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to open database: %s", err);
        free(err);
        free(contracts_db_path);
        contracts_db_path = NULL;
        rocksdb_options_destroy(contracts_db_options);
        contracts_db_options = NULL;
        return -1;
    }

    MXD_LOG_INFO("contracts_db", "Contracts database initialized at %s", contracts_db_path);
    return 0;
}

// Close contracts database
void mxd_contracts_db_close(void) {
    if (contracts_db) {
        rocksdb_close(contracts_db);
        contracts_db = NULL;
    }

    if (contracts_db_options) {
        rocksdb_options_destroy(contracts_db_options);
        contracts_db_options = NULL;
    }

    if (contracts_db_path) {
        free(contracts_db_path);
        contracts_db_path = NULL;
    }

    MXD_LOG_INFO("contracts_db", "Contracts database closed");
}

// Serialize contract metadata
static int serialize_contract_metadata(const mxd_contract_metadata_t *contract,
                                        uint8_t **data, size_t *data_len) {
    if (!contract || !data || !data_len) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #15): Validate bytecode_size fits in uint32_t
    if (contract->bytecode_size > UINT32_MAX) {
        MXD_LOG_ERROR("contracts_db", "Bytecode size %zu exceeds uint32_t max (%u)",
                      contract->bytecode_size, UINT32_MAX);
        return -1;
    }

    // Calculate size
    size_t size = 64 +                          // contract_hash
                  sizeof(uint32_t) +             // bytecode_size
                  contract->bytecode_size +      // bytecode
                  sizeof(uint64_t) +             // deployed_at
                  sizeof(uint64_t) +             // deployed_timestamp
                  20 +                           // deployer
                  sizeof(uint64_t) +             // total_gas_used
                  sizeof(uint32_t);              // call_count

    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    uint8_t *ptr = *data;

    // Serialize with endian conversion
    memcpy(ptr, contract->contract_hash, 64); ptr += 64;

    uint32_t bytecode_size_be = htonl((uint32_t)contract->bytecode_size);
    memcpy(ptr, &bytecode_size_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, contract->bytecode, contract->bytecode_size); ptr += contract->bytecode_size;

    uint64_t deployed_at_be = mxd_htonll(contract->deployed_at);
    memcpy(ptr, &deployed_at_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    uint64_t deployed_timestamp_be = mxd_htonll(contract->deployed_timestamp);
    memcpy(ptr, &deployed_timestamp_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    memcpy(ptr, contract->deployer, 20); ptr += 20;

    uint64_t total_gas_be = mxd_htonll(contract->total_gas_used);
    memcpy(ptr, &total_gas_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    uint32_t call_count_be = htonl(contract->call_count);
    memcpy(ptr, &call_count_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);

    *data_len = size;
    return 0;
}

// Deserialize contract metadata
static int deserialize_contract_metadata(const uint8_t *data, size_t data_len,
                                          mxd_contract_metadata_t *contract) {
    if (!data || !contract) {
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;

    if (ptr + 64 > end) return -1;
    memcpy(contract->contract_hash, ptr, 64); ptr += 64;

    if (ptr + sizeof(uint32_t) > end) return -1;
    uint32_t bytecode_size_be;
    memcpy(&bytecode_size_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    contract->bytecode_size = ntohl(bytecode_size_be);

    if (ptr + contract->bytecode_size > end) return -1;
    contract->bytecode = malloc(contract->bytecode_size);
    if (!contract->bytecode) return -1;
    memcpy(contract->bytecode, ptr, contract->bytecode_size); ptr += contract->bytecode_size;

    if (ptr + sizeof(uint64_t) > end) {
        free(contract->bytecode);
        return -1;
    }
    uint64_t deployed_at_be;
    memcpy(&deployed_at_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    contract->deployed_at = mxd_ntohll(deployed_at_be);

    if (ptr + sizeof(uint64_t) > end) {
        free(contract->bytecode);
        return -1;
    }
    uint64_t deployed_timestamp_be;
    memcpy(&deployed_timestamp_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    contract->deployed_timestamp = mxd_ntohll(deployed_timestamp_be);

    if (ptr + 20 > end) {
        free(contract->bytecode);
        return -1;
    }
    memcpy(contract->deployer, ptr, 20); ptr += 20;

    if (ptr + sizeof(uint64_t) > end) {
        free(contract->bytecode);
        return -1;
    }
    uint64_t total_gas_be;
    memcpy(&total_gas_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    contract->total_gas_used = mxd_ntohll(total_gas_be);

    if (ptr + sizeof(uint32_t) > end) {
        free(contract->bytecode);
        return -1;
    }
    uint32_t call_count_be;
    memcpy(&call_count_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    contract->call_count = ntohl(call_count_be);

    return 0;
}

// Store deployed contract
int mxd_contracts_db_store_contract(const mxd_contract_metadata_t *contract) {
    if (!contracts_db || !contract) {
        MXD_LOG_ERROR("contracts_db", "Database not initialized or invalid contract");
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    // Serialize contract
    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_contract_metadata(contract, &data, &data_len) != 0) {
        MXD_LOG_ERROR("contracts_db", "Failed to serialize contract");
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    // Build key: "CM:" + contract_hash_hex
    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", contract->contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_META_PREFIX, hash_hex);

    // Write to database
    rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(contracts_db, writeoptions, key, strlen(key),
                (const char*)data, data_len, &err);

    free(data);
    rocksdb_writeoptions_destroy(writeoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to store contract: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);

    MXD_LOG_INFO("contracts_db", "Stored contract %s", hash_hex);
    return 0;
}

// Load contract by hash
int mxd_contracts_db_load_contract(const uint8_t contract_hash[64],
                                    mxd_contract_metadata_t *contract) {
    if (!contracts_db || !contract_hash || !contract) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    // Build key
    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_META_PREFIX, hash_hex);

    // Read from database
    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    char *err = NULL;
    size_t data_len = 0;

    char *data = rocksdb_get(contracts_db, readoptions, key, strlen(key),
                             &data_len, &err);

    rocksdb_readoptions_destroy(readoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to load contract: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    if (!data) {
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1; // Contract not found
    }

    // Deserialize
    int result = deserialize_contract_metadata((uint8_t*)data, data_len, contract);
    free(data);

    if (result != 0) {
        pthread_mutex_unlock(&contracts_db_mutex);
        return result;
    }

    // SECURITY FIX (MEDIUM #20): Validate contract hash matches loaded bytecode
    uint8_t computed_hash[64];
    if (mxd_sha512(contract->bytecode, contract->bytecode_size, computed_hash) != 0) {
        MXD_LOG_ERROR("contracts_db", "Failed to compute SHA-512 hash for validation");
        free(contract->bytecode);
        contract->bytecode = NULL;
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    // Verify hash matches
    if (memcmp(computed_hash, contract_hash, 64) != 0) {
        MXD_LOG_ERROR("contracts_db", "Contract hash mismatch! Database may be corrupted");
        MXD_LOG_ERROR("contracts_db", "Expected hash: %s", hash_hex);

        char computed_hex[129] = {0};
        for (int i = 0; i < 64; i++) {
            snprintf(computed_hex + i*2, 3, "%02x", computed_hash[i]);
        }
        MXD_LOG_ERROR("contracts_db", "Computed hash: %s", computed_hex);

        free(contract->bytecode);
        contract->bytecode = NULL;
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);

    return 0;
}

// Check if contract exists
int mxd_contracts_db_exists(const uint8_t contract_hash[64]) {
    if (!contracts_db || !contract_hash) {
        return 0;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_META_PREFIX, hash_hex);

    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    char *err = NULL;
    size_t data_len = 0;

    char *data = rocksdb_get(contracts_db, readoptions, key, strlen(key),
                             &data_len, &err);

    rocksdb_readoptions_destroy(readoptions);

    if (err) {
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return 0;
    }

    if (data) {
        free(data);
        pthread_mutex_unlock(&contracts_db_mutex);
        return 1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);
    return 0;
}

// Get all contracts
int mxd_contracts_db_get_all_contracts(mxd_contract_metadata_t **contracts,
                                        uint32_t *count) {
    if (!contracts_db || !contracts || !count) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    *contracts = NULL;
    *count = 0;

    // Create iterator
    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    rocksdb_iterator_t *iter = rocksdb_create_iterator(contracts_db, readoptions);

    // Count contracts first
    uint32_t contract_count = 0;
    rocksdb_iter_seek(iter, CONTRACT_META_PREFIX, strlen(CONTRACT_META_PREFIX));

    while (rocksdb_iter_valid(iter)) {
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);

        if (key_len < strlen(CONTRACT_META_PREFIX) ||
            memcmp(key, CONTRACT_META_PREFIX, strlen(CONTRACT_META_PREFIX)) != 0) {
            break;
        }

        contract_count++;
        rocksdb_iter_next(iter);
    }

    if (contract_count == 0) {
        rocksdb_iter_destroy(iter);
        rocksdb_readoptions_destroy(readoptions);
        pthread_mutex_unlock(&contracts_db_mutex);
        return 0;
    }

    // Allocate array
    *contracts = calloc(contract_count, sizeof(mxd_contract_metadata_t));
    if (!*contracts) {
        rocksdb_iter_destroy(iter);
        rocksdb_readoptions_destroy(readoptions);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    // Load contracts
    uint32_t loaded = 0;
    rocksdb_iter_seek(iter, CONTRACT_META_PREFIX, strlen(CONTRACT_META_PREFIX));

    while (rocksdb_iter_valid(iter) && loaded < contract_count) {
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);

        if (key_len < strlen(CONTRACT_META_PREFIX) ||
            memcmp(key, CONTRACT_META_PREFIX, strlen(CONTRACT_META_PREFIX)) != 0) {
            break;
        }

        size_t value_len = 0;
        const char *value = rocksdb_iter_value(iter, &value_len);

        if (deserialize_contract_metadata((uint8_t*)value, value_len,
                                           &(*contracts)[loaded]) == 0) {
            loaded++;
        }

        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    rocksdb_readoptions_destroy(readoptions);

    pthread_mutex_unlock(&contracts_db_mutex);

    *count = loaded;
    return 0;
}

// Store contract state
int mxd_contracts_db_store_state(const mxd_contract_storage_t *state) {
    if (!contracts_db || !state) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    // Build key
    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", state->contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_STATE_PREFIX, hash_hex);

    // Serialize state (simplified - just store the storage data)
    // In production, you'd include state_root and last_modified
    rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(contracts_db, writeoptions, key, strlen(key),
                (const char*)state->storage_data, state->storage_size, &err);

    rocksdb_writeoptions_destroy(writeoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to store state: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);
    return 0;
}

// Delete contract
int mxd_contracts_db_delete_contract(const uint8_t contract_hash[64]) {
    if (!contracts_db || !contract_hash) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_META_PREFIX, hash_hex);

    rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_delete(contracts_db, writeoptions, key, strlen(key), &err);

    rocksdb_writeoptions_destroy(writeoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to delete contract: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);
    return 0;
}

// Serialize contract call record
static int serialize_contract_call(const mxd_contract_call_t *call,
                                    uint8_t **data, size_t *data_len) {
    if (!call || !data || !data_len) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #15): Validate sizes fit in uint32_t
    if (call->params_size > UINT32_MAX) {
        MXD_LOG_ERROR("contracts_db", "Params size %zu exceeds uint32_t max", call->params_size);
        return -1;
    }
    if (call->result_size > UINT32_MAX) {
        MXD_LOG_ERROR("contracts_db", "Result size %zu exceeds uint32_t max", call->result_size);
        return -1;
    }

    // Calculate size
    size_t size = 64 +                     // tx_hash
                  64 +                     // contract_hash
                  256 +                    // function_name
                  sizeof(uint32_t) +       // params_size
                  call->params_size +      // params
                  sizeof(uint32_t) +       // result_size
                  call->result_size +      // result
                  sizeof(uint64_t) +       // gas_used
                  sizeof(uint64_t) +       // timestamp
                  sizeof(uint32_t);        // success

    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    uint8_t *ptr = *data;

    // Serialize
    memcpy(ptr, call->tx_hash, 64); ptr += 64;
    memcpy(ptr, call->contract_hash, 64); ptr += 64;
    memcpy(ptr, call->function_name, 256); ptr += 256;

    uint32_t params_size_be = htonl((uint32_t)call->params_size);
    memcpy(ptr, &params_size_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    if (call->params && call->params_size > 0) {
        memcpy(ptr, call->params, call->params_size); ptr += call->params_size;
    }

    uint32_t result_size_be = htonl((uint32_t)call->result_size);
    memcpy(ptr, &result_size_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    if (call->result && call->result_size > 0) {
        memcpy(ptr, call->result, call->result_size); ptr += call->result_size;
    }

    uint64_t gas_used_be = mxd_htonll(call->gas_used);
    memcpy(ptr, &gas_used_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    uint64_t timestamp_be = mxd_htonll(call->timestamp);
    memcpy(ptr, &timestamp_be, sizeof(uint64_t)); ptr += sizeof(uint64_t);

    uint32_t success_be = htonl(call->success);
    memcpy(ptr, &success_be, sizeof(uint32_t)); ptr += sizeof(uint32_t);

    *data_len = size;
    return 0;
}

// Store contract call record
int mxd_contracts_db_store_call(const mxd_contract_call_t *call) {
    if (!contracts_db || !call) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    // Serialize call record
    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_contract_call(call, &data, &data_len) != 0) {
        MXD_LOG_ERROR("contracts_db", "Failed to serialize call record");
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    // Build key: "CC:" + tx_hash_hex
    char key[256];
    char tx_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_hex + i*2, 3, "%02x", call->tx_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_CALL_PREFIX, tx_hash_hex);

    // Write to database
    rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(contracts_db, writeoptions, key, strlen(key),
                (const char*)data, data_len, &err);

    free(data);
    rocksdb_writeoptions_destroy(writeoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to store call record: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&contracts_db_mutex);

    MXD_LOG_INFO("contracts_db", "Stored call record for tx %s", tx_hash_hex);
    return 0;
}

// Deserialize contract call record
static int deserialize_contract_call(const uint8_t *data, size_t data_len,
                                      mxd_contract_call_t *call) {
    if (!data || !call) {
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;

    if (ptr + 64 > end) return -1;
    memcpy(call->tx_hash, ptr, 64); ptr += 64;

    if (ptr + 64 > end) return -1;
    memcpy(call->contract_hash, ptr, 64); ptr += 64;

    if (ptr + 256 > end) return -1;
    memcpy(call->function_name, ptr, 256); ptr += 256;

    if (ptr + sizeof(uint32_t) > end) return -1;
    uint32_t params_size_be;
    memcpy(&params_size_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    call->params_size = ntohl(params_size_be);

    if (call->params_size > 0) {
        if (ptr + call->params_size > end) return -1;
        call->params = malloc(call->params_size);
        if (!call->params) return -1;
        memcpy(call->params, ptr, call->params_size); ptr += call->params_size;
    } else {
        call->params = NULL;
    }

    if (ptr + sizeof(uint32_t) > end) {
        free(call->params);
        return -1;
    }
    uint32_t result_size_be;
    memcpy(&result_size_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    call->result_size = ntohl(result_size_be);

    if (call->result_size > 0) {
        if (ptr + call->result_size > end) {
            free(call->params);
            return -1;
        }
        call->result = malloc(call->result_size);
        if (!call->result) {
            free(call->params);
            return -1;
        }
        memcpy(call->result, ptr, call->result_size); ptr += call->result_size;
    } else {
        call->result = NULL;
    }

    if (ptr + sizeof(uint64_t) > end) {
        free(call->params);
        free(call->result);
        return -1;
    }
    uint64_t gas_used_be;
    memcpy(&gas_used_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    call->gas_used = mxd_ntohll(gas_used_be);

    if (ptr + sizeof(uint64_t) > end) {
        free(call->params);
        free(call->result);
        return -1;
    }
    uint64_t timestamp_be;
    memcpy(&timestamp_be, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    call->timestamp = mxd_ntohll(timestamp_be);

    if (ptr + sizeof(uint32_t) > end) {
        free(call->params);
        free(call->result);
        return -1;
    }
    uint32_t success_be;
    memcpy(&success_be, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    call->success = ntohl(success_be);

    return 0;
}

// Get contract call history
int mxd_contracts_db_get_call_history(const uint8_t contract_hash[64],
                                       mxd_contract_call_t **calls,
                                       uint32_t *count) {
    if (!contracts_db || !contract_hash || !calls || !count) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    *calls = NULL;
    *count = 0;

    // Create iterator
    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    rocksdb_iterator_t *iter = rocksdb_create_iterator(contracts_db, readoptions);

    // Count matching calls first
    uint32_t call_count = 0;
    rocksdb_iter_seek(iter, CONTRACT_CALL_PREFIX, strlen(CONTRACT_CALL_PREFIX));

    while (rocksdb_iter_valid(iter)) {
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);

        if (key_len < strlen(CONTRACT_CALL_PREFIX) ||
            memcmp(key, CONTRACT_CALL_PREFIX, strlen(CONTRACT_CALL_PREFIX)) != 0) {
            break;
        }

        size_t value_len = 0;
        const char *value = rocksdb_iter_value(iter, &value_len);

        // Check if this call is for the specified contract
        // Contract hash is at offset 64 (after tx_hash)
        if (value_len >= 128 && memcmp((uint8_t*)value + 64, contract_hash, 64) == 0) {
            call_count++;
        }

        rocksdb_iter_next(iter);
    }

    if (call_count == 0) {
        rocksdb_iter_destroy(iter);
        rocksdb_readoptions_destroy(readoptions);
        pthread_mutex_unlock(&contracts_db_mutex);
        return 0;
    }

    // Allocate array
    *calls = calloc(call_count, sizeof(mxd_contract_call_t));
    if (!*calls) {
        rocksdb_iter_destroy(iter);
        rocksdb_readoptions_destroy(readoptions);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    // Load matching calls
    uint32_t loaded = 0;
    rocksdb_iter_seek(iter, CONTRACT_CALL_PREFIX, strlen(CONTRACT_CALL_PREFIX));

    while (rocksdb_iter_valid(iter) && loaded < call_count) {
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);

        if (key_len < strlen(CONTRACT_CALL_PREFIX) ||
            memcmp(key, CONTRACT_CALL_PREFIX, strlen(CONTRACT_CALL_PREFIX)) != 0) {
            break;
        }

        size_t value_len = 0;
        const char *value = rocksdb_iter_value(iter, &value_len);

        // Check if this call is for the specified contract
        if (value_len >= 128 && memcmp((uint8_t*)value + 64, contract_hash, 64) == 0) {
            if (deserialize_contract_call((uint8_t*)value, value_len, &(*calls)[loaded]) == 0) {
                loaded++;
            }
        }

        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    rocksdb_readoptions_destroy(readoptions);

    pthread_mutex_unlock(&contracts_db_mutex);

    *count = loaded;
    return 0;
}

// Load contract state
int mxd_contracts_db_load_state(const uint8_t contract_hash[64],
                                 mxd_contract_storage_t *state) {
    if (!contracts_db || !contract_hash || !state) {
        return -1;
    }

    // SECURITY FIX (MEDIUM #13): Acquire mutex for thread safety
    pthread_mutex_lock(&contracts_db_mutex);

    // Build key
    char key[256];
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", contract_hash[i]);
    }
    snprintf(key, sizeof(key), "%s%s", CONTRACT_STATE_PREFIX, hash_hex);

    // Read from database
    rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
    char *err = NULL;
    size_t data_len = 0;

    char *data = rocksdb_get(contracts_db, readoptions, key, strlen(key),
                             &data_len, &err);

    rocksdb_readoptions_destroy(readoptions);

    if (err) {
        MXD_LOG_ERROR("contracts_db", "Failed to load state: %s", err);
        free(err);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    if (!data) {
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1; // State not found
    }

    // For now, store the raw data
    // In production, should deserialize state_root and last_modified
    memcpy(state->contract_hash, contract_hash, 64);
    state->storage_size = data_len;
    state->storage_data = malloc(data_len);

    if (!state->storage_data) {
        free(data);
        pthread_mutex_unlock(&contracts_db_mutex);
        return -1;
    }

    memcpy(state->storage_data, data, data_len);
    free(data);

    // TODO: Deserialize state_root and last_modified from stored data
    memset(state->state_root, 0, 64);
    state->last_modified = 0;

    pthread_mutex_unlock(&contracts_db_mutex);

    MXD_LOG_INFO("contracts_db", "Loaded state for contract %s", hash_hex);
    return 0;
}
