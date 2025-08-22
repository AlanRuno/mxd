#include "mxd_logging.h"

#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <wasm3/wasm3.h>

// WASM runtime state
static struct {
  IM3Environment env;
  IM3Runtime runtime;
} wasm_state = {0};

// Initialize smart contracts module
int mxd_init_contracts(void) {
  // Free existing environment if any
  if (wasm_state.env) {
    if (wasm_state.runtime) {
      m3_FreeRuntime(wasm_state.runtime);
      wasm_state.runtime = NULL;
    }
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
  }

  // Free existing runtime if any
  if (wasm_state.runtime) {
    m3_FreeRuntime(wasm_state.runtime);
    wasm_state.runtime = NULL;
  }

  // Free existing environment if any
  if (wasm_state.env) {
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
  }

  // Initialize new WASM environment
  wasm_state.env = m3_NewEnvironment();
  if (!wasm_state.env) {
    return -1;
  }

  // Create new runtime with 64KB memory
  wasm_state.runtime = m3_NewRuntime(wasm_state.env, 64 * 1024, NULL);
  if (!wasm_state.runtime) {
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
    return -1;
  }
  return 0;
}

// Deploy contract
int mxd_deploy_contract(const uint8_t *code, size_t code_size,
                        mxd_contract_state_t *state) {
  if (!code || !state || code_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  // Calculate contract hash
  mxd_sha512(code, code_size, state->contract_hash);

  // Initialize state
  memset(state->state_hash, 0, sizeof(state->state_hash));
  state->gas_used = 0;
  state->gas_limit = MXD_MAX_GAS;
  state->storage = NULL;
  state->storage_size = 0;

  // Calculate contract hash
  mxd_sha512(code, code_size, state->contract_hash);

  // Ensure runtime is initialized
  if (!wasm_state.env || !wasm_state.runtime) {
    if (mxd_init_contracts() != 0) {
      return -1;
    }
  }

  // Parse WASM module
  IM3Module module = NULL;
  M3Result result = m3_ParseModule(wasm_state.env, &module, code, code_size);
  if (!module || result) {
    MXD_LOG_ERROR("contracts", "Parse error: %s", result);
    return -1;
  }

  // Load module into runtime
  result = m3_LoadModule(wasm_state.runtime, module);
  if (result) {
    MXD_LOG_ERROR("contracts", "Load error: %s", result);
    m3_FreeModule(module);
    return -1;
  }

  // Store module in state for later use
  state->module = module;

  return 0;
}

// Execute contract
int mxd_execute_contract(const mxd_contract_state_t *state,
                         const uint8_t *input, size_t input_size,
                         mxd_execution_result_t *result) {
  if (!state || !input || !result || input_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  // Initialize result
  memset(result, 0, sizeof(mxd_execution_result_t));

  // Find main function
  IM3Function func;
  M3Result res = m3_FindFunction(&func, wasm_state.runtime, "main");
  if (res) {
    MXD_LOG_ERROR("contracts", "Find function error: %s", res);
    return -1;
  }

  // Calculate initial gas cost (base cost + input size)
  uint64_t gas_used = 100 + input_size; // Base cost of 100 gas units

  // Call function with input value
  uint32_t input_val = *(const uint32_t *)input;
  res = m3_CallV(func, input_val);
  if (res) {
    MXD_LOG_ERROR("contracts", "Call error: %s", res);
    return -1;
  }

  // Get return value
  uint32_t ret = 0;
  res = m3_GetResultsV(func, &ret);
  if (res) {
    MXD_LOG_ERROR("contracts", "Get results error: %s", res);
    return -1;
  }

  // Add gas cost for computation (simplified model)
  gas_used += 10; // Cost per operation

  // Copy return value to result
  if (sizeof(ret) > sizeof(result->return_data)) {
    return -1;
  }
  memcpy(result->return_data, &ret, sizeof(ret));
  result->return_size = sizeof(ret);
  result->success = 1;
  result->gas_used = gas_used;

  return 0;
}

// Validate contract state transition
int mxd_validate_state_transition(const mxd_contract_state_t *old_state,
                                  const mxd_contract_state_t *new_state) {
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
  if (!code) {
    return 0;
  }

  // Simple gas calculation based on code size
  // TODO: Implement proper gas metering
  return code_size * 10;
}

// Get contract storage
int mxd_get_contract_storage(const mxd_contract_state_t *state,
                             const uint8_t *key, size_t key_size,
                             uint8_t *value, size_t *value_size) {
  if (!state || !key || !value || !value_size || !state->storage) {
    return -1;
  }

  // Simple key-value storage implementation
  // TODO: Implement proper storage with merkle trees
  size_t offset = 0;
  while (offset < state->storage_size) {
    size_t stored_key_size = *(size_t *)(state->storage + offset);
    offset += sizeof(size_t);

    if (stored_key_size == key_size &&
        memcmp(state->storage + offset, key, key_size) == 0) {
      offset += stored_key_size;
      size_t stored_value_size = *(size_t *)(state->storage + offset);
      offset += sizeof(size_t);

      if (stored_value_size > *value_size) {
        return -1;
      }

      memcpy(value, state->storage + offset, stored_value_size);
      *value_size = stored_value_size;
      return 0;
    }

    offset += key_size;
    size_t stored_value_size = *(size_t *)(state->storage + offset);
    offset += sizeof(size_t) + stored_value_size;
  }

  return -1;
}

// Set contract storage
int mxd_set_contract_storage(mxd_contract_state_t *state, const uint8_t *key,
                             size_t key_size, const uint8_t *value,
                             size_t value_size) {
  if (!state || !key || !value) {
    return -1;
  }

  // Calculate new storage size
  size_t entry_size = sizeof(size_t) + key_size + sizeof(size_t) + value_size;
  size_t new_size = state->storage_size + entry_size;

  // Reallocate storage
  uint8_t *new_storage = realloc(state->storage, new_size);
  if (!new_storage) {
    return -1;
  }

  // Add new entry
  size_t offset = state->storage_size;
  *(size_t *)(new_storage + offset) = key_size;
  offset += sizeof(size_t);
  memcpy(new_storage + offset, key, key_size);
  offset += key_size;
  *(size_t *)(new_storage + offset) = value_size;
  offset += sizeof(size_t);
  memcpy(new_storage + offset, value, value_size);

  // Update state
  state->storage = new_storage;
  state->storage_size = new_size;

  // Update state hash
  mxd_sha512(state->storage, state->storage_size, state->state_hash);

  return 0;
}

// Free contract state resources
void mxd_free_contract_state(mxd_contract_state_t *state) {
  if (state) {
    if (state->storage) {
      free(state->storage);
      state->storage = NULL;
    }
    // Note: module is managed by the runtime and shared between states
    memset(state, 0, sizeof(mxd_contract_state_t));
  }
}
