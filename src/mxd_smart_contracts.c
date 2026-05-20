#include "mxd_logging.h"

#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "../include/mxd_gas_metering.h"
#include "../include/mxd_merkle_trie.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_wasm_validator.h"
#include "../include/mxd_contracts_db.h"
#include "../include/mxd_blockchain_db.h"
#include "metrics/mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <wasm3/wasm3.h>

// SECURITY FIX: Removed global shared WASM runtime
// Each contract now has its own isolated runtime in mxd_contract_state_t

static inline int contracts_disabled(void) {
  const mxd_config_t* config = mxd_get_config();
  return (!config || !config->contracts.enabled);
}

// Initialize smart contracts module
// SECURITY FIX: Only initializes database, not shared runtime
int mxd_init_contracts(void) {
  if (contracts_disabled()) {
    MXD_LOG_INFO("contracts", "Smart contracts are disabled (skipping initialization)");
    return 0;  // FIX: Disabled is a valid state, not an error
  }

  // Initialize contracts database
  const mxd_config_t* config = mxd_get_config();
  if (config && config->data_dir) {
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/contracts.db", config->data_dir);
    if (mxd_contracts_db_init(db_path) != 0) {
      MXD_LOG_ERROR("contracts", "Failed to initialize contracts database");
      return -1;
    }
  }

  MXD_LOG_INFO("contracts", "Smart contracts module initialized (per-contract runtimes)");
  return 0;
}

// Deploy contract
// SECURITY FIX: Creates isolated runtime per contract
int mxd_deploy_contract(const uint8_t *code, size_t code_size,
                        const uint8_t deployer[20],
                        mxd_contract_state_t *state) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }

  // SECURITY FIX: Validate code_size > 0
  if (!code || !state || !deployer || code_size == 0 || code_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  // Validate WASM bytecode for determinism
  mxd_wasm_validation_result_t validation_result;
  int validation_code = mxd_validate_wasm_determinism(code, code_size, &validation_result);

  if (validation_code != MXD_WASM_VALID) {
    MXD_LOG_ERROR("contracts", "Contract validation failed: %s",
                  validation_result.error_message);
    return -1;
  }

  MXD_LOG_INFO("contracts", "Contract passed determinism validation");

  // Calculate contract hash
  mxd_sha512(code, code_size, state->contract_hash);

  // Initialize state
  memset(state->state_hash, 0, sizeof(state->state_hash));
  state->gas_used = 0;
  state->gas_limit = MXD_MAX_GAS;
  state->storage = NULL;
  state->storage_size = 0;
  state->storage_trie = mxd_trie_create();  // Create merkle trie for production storage
  state->reentrancy_lock = 0;
  state->call_depth = 0;

  // SECURITY FIX: Store bytecode for proper gas calculation
  state->bytecode = malloc(code_size);
  if (!state->bytecode) {
    MXD_LOG_ERROR("contracts", "Failed to allocate bytecode storage");
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }
  memcpy(state->bytecode, code, code_size);
  state->bytecode_size = code_size;

  // SECURITY FIX: Create per-contract WASM environment (not shared)
  IM3Environment env = m3_NewEnvironment();
  if (!env) {
    MXD_LOG_ERROR("contracts", "Failed to create WASM environment");
    free(state->bytecode);
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }
  state->env = env;

  // SECURITY FIX: Create per-contract WASM runtime (isolated, 64KB memory)
  IM3Runtime runtime = m3_NewRuntime(env, 64 * 1024, NULL);
  if (!runtime) {
    MXD_LOG_ERROR("contracts", "Failed to create WASM runtime");
    m3_FreeEnvironment(env);
    free(state->bytecode);
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }
  state->runtime = runtime;

  // Parse WASM module
  IM3Module module = NULL;
  M3Result result = m3_ParseModule(env, &module, code, code_size);
  if (!module || result) {
    MXD_LOG_ERROR("contracts", "Parse error: %s", result);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    free(state->bytecode);
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }

  // Load module into runtime
  result = m3_LoadModule(runtime, module);
  if (result) {
    MXD_LOG_ERROR("contracts", "Load error: %s", result);
    m3_FreeModule(module);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    free(state->bytecode);
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }

  // Store module in state for later use
  state->module = module;

  // SECURITY FIX: Create mutex for thread safety
  pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
  if (!mutex) {
    MXD_LOG_ERROR("contracts", "Failed to allocate mutex");
    m3_FreeModule(module);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    free(state->bytecode);
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
    }
    return -1;
  }
  pthread_mutex_init(mutex, NULL);
  state->mutex = mutex;

  // Persist contract to database
  mxd_contract_metadata_t metadata;
  memcpy(metadata.contract_hash, state->contract_hash, 64);
  metadata.bytecode = malloc(code_size);
  if (metadata.bytecode) {
    memcpy(metadata.bytecode, code, code_size);
    metadata.bytecode_size = code_size;

    // Get current blockchain height
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) == 0) {
      metadata.deployed_at = current_height;
    } else {
      metadata.deployed_at = 0;  // Fallback to 0 if height unavailable
    }

    metadata.deployed_timestamp = (uint64_t)time(NULL);
    memcpy(metadata.deployer, deployer, 20);  // Store deployer address
    metadata.total_gas_used = 0;
    metadata.call_count = 0;

    if (mxd_contracts_db_store_contract(&metadata) != 0) {
      MXD_LOG_WARN("contracts", "Failed to persist contract to database");
      // Don't fail deployment if DB storage fails
    } else {
      MXD_LOG_INFO("contracts", "Contract persisted to database");
    }

    free(metadata.bytecode);
  }

  return 0;
}

// Calculate estimated gas cost based on execution
// This is a simplified approach until WASM3 metering is fully integrated
static uint64_t estimate_gas_cost(size_t bytecode_size, size_t input_size) {
  // Base cost for execution
  uint64_t base_cost = 1000;

  // Cost per byte of bytecode (simplified)
  uint64_t bytecode_cost = bytecode_size / 10;

  // Cost per byte of input
  uint64_t input_cost = input_size * 2;

  return base_cost + bytecode_cost + input_cost;
}

// Execute contract
// SECURITY FIX: Removed const, proper thread safety
int mxd_execute_contract(mxd_contract_state_t *state,
                         const uint8_t *input, size_t input_size,
                         mxd_execution_result_t *result) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }

  if (!state || !input || !result || input_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  // SECURITY FIX: Acquire mutex for thread safety
  pthread_mutex_t *mutex = (pthread_mutex_t *)state->mutex;
  if (mutex) {
    pthread_mutex_lock(mutex);
  }

  // SECURITY FIX: Thread-safe reentrancy check (under mutex)
  if (state->reentrancy_lock) {
    MXD_LOG_ERROR("contracts", "Reentrancy detected");
    if (mutex) {
      pthread_mutex_unlock(mutex);
    }
    return -1;
  }

  // Check call depth (max 256)
  if (state->call_depth > 256) {
    MXD_LOG_ERROR("contracts", "Call stack overflow (depth > 256)");
    if (mutex) {
      pthread_mutex_unlock(mutex);
    }
    return -1;
  }

  // Set reentrancy lock (now safe - we have mutex)
  state->reentrancy_lock = 1;
  state->call_depth++;

  memset(result, 0, sizeof(mxd_execution_result_t));

  mxd_config_t* config = mxd_get_config();
  int timeout_seconds = 5;
  if (config && config->contracts.timeout_seconds > 0) {
    timeout_seconds = config->contracts.timeout_seconds;
  }

  time_t start_time = time(NULL);

  // SECURITY FIX: Use per-contract runtime, not shared global
  IM3Runtime runtime = (IM3Runtime)state->runtime;
  if (!runtime) {
    MXD_LOG_ERROR("contracts", "Contract runtime not initialized");
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  IM3Function func;
  M3Result res = m3_FindFunction(&func, runtime, "main");
  if (res) {
    MXD_LOG_ERROR("contracts", "Find function error: %s", res);
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  // Validate input size before accessing as uint32_t to prevent out-of-bounds read
  // This is a memory safety fix - callers must provide at least 4 bytes of input
  if (input_size < sizeof(uint32_t)) {
    MXD_LOG_ERROR("contracts", "Input size too small: %zu bytes (minimum: %zu)",
                  input_size, sizeof(uint32_t));
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  // SECURITY FIX: Pass stored bytecode to gas calculation, not runtime pointer
  uint64_t gas_used = 0;
  if (state->bytecode && state->bytecode_size > 0) {
    gas_used = mxd_calculate_gas_from_bytecode(state->bytecode, state->bytecode_size);
  }

  // SECURITY FIX: Never allow zero gas for real contracts
  if (gas_used == 0) {
    // Minimum gas cost to prevent infinite loops
    gas_used = 1000 + (state->bytecode_size / 10) + (input_size * 2);
  }

  // Check if gas limit would be exceeded before execution
  if (gas_used > state->gas_limit) {
    MXD_LOG_ERROR("contracts", "Gas limit exceeded before execution: %lu > %lu",
                  (unsigned long)gas_used, (unsigned long)state->gas_limit);
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  // Check cumulative gas usage
  if (state->gas_used + gas_used > state->gas_limit) {
    MXD_LOG_ERROR("contracts", "Cumulative gas limit exceeded: %lu + %lu > %lu",
                  (unsigned long)state->gas_used, (unsigned long)gas_used,
                  (unsigned long)state->gas_limit);
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  // Safe access after size validation - copy to avoid alignment issues
  uint32_t input_val;
  memcpy(&input_val, input, sizeof(uint32_t));
  res = m3_CallV(func, input_val);

  time_t end_time = time(NULL);

  // Update gas used (already calculated earlier)
  state->gas_used += gas_used;

  // Check timeout
  if (difftime(end_time, start_time) > timeout_seconds) {
    MXD_LOG_ERROR("contracts", "Contract execution timeout exceeded (%d seconds)", timeout_seconds);
    result->gas_used = gas_used;
    result->success = 0;
    mxd_metrics_increment("contract_timeouts_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  if (res) {
    MXD_LOG_ERROR("contracts", "Call error: %s", res);
    result->gas_used = gas_used;
    result->success = 0;
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  uint32_t ret = 0;
  res = m3_GetResultsV(func, &ret);
  if (res) {
    MXD_LOG_ERROR("contracts", "Get results error: %s", res);
    result->gas_used = gas_used;
    result->success = 0;
    mxd_metrics_increment("contract_execution_errors_total");
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }

  if (sizeof(ret) > sizeof(result->return_data)) {
    // Release locks on error
    state->call_depth--;
    state->reentrancy_lock = 0;
    if (mutex) pthread_mutex_unlock(mutex);
    return -1;
  }
  memcpy(result->return_data, &ret, sizeof(ret));
  result->return_size = sizeof(ret);
  result->success = 1;
  result->gas_used = gas_used;

  // Gas tracking already updated above
  // state->gas_used now reflects actual gas consumed

  // Release reentrancy lock and mutex
  state->call_depth--;
  state->reentrancy_lock = 0;
  if (mutex) pthread_mutex_unlock(mutex);

  mxd_metrics_increment("contract_executions_total");

  return 0;
}

// Validate contract state transition
int mxd_validate_state_transition(const mxd_contract_state_t *old_state,
                                  const mxd_contract_state_t *new_state) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!old_state || !new_state) {
    return -1;
  }

  // Validate contract hash hasn't changed
  if (memcmp(old_state->contract_hash, new_state->contract_hash, 64) != 0) {
    return -1;
  }

  // Validate gas usage
  if (new_state->gas_used > new_state->gas_limit) {
    return -1;
  }

  // Validate state hash only if storage exists
  if (new_state->storage && new_state->storage_size > 0) {
    uint8_t computed_hash[64];
    mxd_sha512(new_state->storage, new_state->storage_size, computed_hash);
    if (memcmp(computed_hash, new_state->state_hash, 64) != 0) {
      return -1;
    }
  } else if (old_state->storage && old_state->storage_size > 0) {
    // If new state has no storage but old state did, that's invalid
    return -1;
  }

  return 0;
}

// Calculate contract gas cost
uint64_t mxd_calculate_gas(const uint8_t *code, size_t code_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return 0;
  }
  
  if (!code) {
    return 0;
  }

  // Use proper gas metering with WASM bytecode analysis
  uint64_t gas_cost = mxd_calculate_gas_from_bytecode(code, code_size);
  
  MXD_LOG_DEBUG("contracts", "Calculated gas cost: %lu for contract size: %zu bytes", 
                gas_cost, code_size);
  
  return gas_cost;
}

// Get contract storage
int mxd_get_contract_storage(const mxd_contract_state_t *state,
                             const uint8_t *key, size_t key_size,
                             uint8_t *value, size_t *value_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!state || !key || !value || !value_size) {
    return -1;
  }

  // Use merkle patricia trie for production storage (O(log n) lookup with cryptographic verification)
  if (state->storage_trie) {
    mxd_merkle_trie_t *trie = (mxd_merkle_trie_t *)state->storage_trie;
    return mxd_trie_get(trie, key, key_size, value, value_size);
  }

  // Fallback to legacy linear storage for backward compatibility
  if (!state->storage) {
    return -1;
  }

  size_t offset = 0;
  while (offset < state->storage_size) {
    uint64_t stored_key_size_be;
    memcpy(&stored_key_size_be, state->storage + offset, sizeof(uint64_t));
    size_t stored_key_size = (size_t)mxd_ntohll(stored_key_size_be);
    offset += sizeof(uint64_t);

    if (stored_key_size == key_size &&
        memcmp(state->storage + offset, key, key_size) == 0) {
      offset += stored_key_size;
      uint64_t stored_value_size_be;
      memcpy(&stored_value_size_be, state->storage + offset, sizeof(uint64_t));
      size_t stored_value_size = (size_t)mxd_ntohll(stored_value_size_be);
      offset += sizeof(uint64_t);

      if (stored_value_size > *value_size) {
        return -1;
      }

      memcpy(value, state->storage + offset, stored_value_size);
      *value_size = stored_value_size;
      return 0;
    }

    offset += stored_key_size;
    uint64_t stored_value_size_be;
    memcpy(&stored_value_size_be, state->storage + offset, sizeof(uint64_t));
    size_t stored_value_size = (size_t)mxd_ntohll(stored_value_size_be);
    offset += sizeof(uint64_t) + stored_value_size;
  }

  return -1;
}

// Set contract storage
int mxd_set_contract_storage(mxd_contract_state_t *state, const uint8_t *key,
                             size_t key_size, const uint8_t *value,
                             size_t value_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }

  if (!state || !key || !value) {
    return -1;
  }

  // Use merkle patricia trie for production storage (O(log n) insert with cryptographic verification)
  // Create trie if it doesn't exist yet
  if (!state->storage_trie) {
    state->storage_trie = mxd_trie_create();
    if (!state->storage_trie) {
      MXD_LOG_ERROR("contracts", "Failed to create storage trie");
      return -1;
    }
  }

  mxd_merkle_trie_t *trie = (mxd_merkle_trie_t *)state->storage_trie;
  int result = mxd_trie_set(trie, key, key_size, value, value_size);
  if (result == 0) {
    // Update state hash with merkle root
    mxd_trie_get_root_hash(trie, state->state_hash);

    // SECURITY FIX (MEDIUM #19): Persist state changes to database
    // Serialize trie to storage_data
    size_t serialized_size = 0;

    // First get the size needed
    if (mxd_trie_serialize(trie, NULL, &serialized_size) != 0 || serialized_size == 0) {
      MXD_LOG_WARN("contracts", "Failed to get serialized trie size, skipping persistence");
      return 0; // Don't fail the storage operation
    }

    uint8_t *serialized_data = malloc(serialized_size);
    if (!serialized_data) {
      MXD_LOG_WARN("contracts", "Failed to allocate memory for trie serialization");
      return 0; // Don't fail the storage operation
    }

    if (mxd_trie_serialize(trie, serialized_data, &serialized_size) != 0) {
      MXD_LOG_WARN("contracts", "Failed to serialize trie, skipping persistence");
      free(serialized_data);
      return 0; // Don't fail the storage operation
    }

    // Persist to database
    mxd_contract_storage_t storage = {
      .storage_data = serialized_data,
      .storage_size = serialized_size,
      .last_modified = time(NULL)
    };
    memcpy(storage.contract_hash, state->contract_hash, 64);
    memcpy(storage.state_root, state->state_hash, 64);

    int db_result = mxd_contracts_db_store_state(&storage);
    free(serialized_data);

    if (db_result != 0) {
      MXD_LOG_WARN("contracts", "Failed to persist state to database");
      // Don't fail the operation - in-memory state is still updated
    }
  }
  return result;
}

// Free contract state resources
// SECURITY FIX: Properly free all resources including runtime, env, mutex
void mxd_free_contract_state(mxd_contract_state_t *state) {
  if (state) {
    // Free mutex
    if (state->mutex) {
      pthread_mutex_t *mutex = (pthread_mutex_t *)state->mutex;
      pthread_mutex_destroy(mutex);
      free(mutex);
      state->mutex = NULL;
    }

    // Free bytecode
    if (state->bytecode) {
      free(state->bytecode);
      state->bytecode = NULL;
    }

    // Free storage
    if (state->storage) {
      free(state->storage);
      state->storage = NULL;
    }

    // Free storage trie
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
      state->storage_trie = NULL;
    }

    // SECURITY FIX: Free per-contract WASM runtime
    if (state->runtime) {
      m3_FreeRuntime((IM3Runtime)state->runtime);
      state->runtime = NULL;
    }

    // SECURITY FIX: Free per-contract WASM environment
    if (state->env) {
      m3_FreeEnvironment((IM3Environment)state->env);
      state->env = NULL;
    }

    // Note: module is freed when runtime is freed
    memset(state, 0, sizeof(mxd_contract_state_t));
  }
}
