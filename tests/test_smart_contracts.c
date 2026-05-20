#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_config.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Test WebAssembly code (minimal module)
#include "wasm_binary.h"

static mxd_config_t test_config = {0};
static int config_initialized = 0;

static void enable_contracts_for_testing(void) {
  if (!config_initialized) {
    mxd_set_default_config(&test_config);
    test_config.contracts.enabled = 1;
    mxd_set_global_config(&test_config);
    config_initialized = 1;
  }
}

// Test input/output values
#define TEST_INPUT_VALUE 5
#define EXPECTED_OUTPUT_VALUE 47 // 5 + 42 (from WebAssembly code)

static void test_contract_initialization(void) {
  TEST_START("Contract Initialization");
  enable_contracts_for_testing();
  TEST_ASSERT(mxd_init_contracts() == 0, "Contract system initialization successful");
  TEST_END("Contract Initialization");
}

static void test_contract_deployment(void) {
  mxd_contract_state_t state;
  memset(&state, 0, sizeof(state));

  TEST_START("Contract Deployment");
  enable_contracts_for_testing();
  
  // Initialize contracts module
  TEST_ASSERT(mxd_init_contracts() == 0, "Contract system initialization successful");

  // Deploy contract
  TEST_VALUE("Contract size", "%zu", sizeof(test_wasm));
  TEST_ASSERT(mxd_deploy_contract(test_wasm, sizeof(test_wasm), &state) == 0, "Contract deployment successful");

  // Verify contract hash
  TEST_ARRAY("Contract hash", state.contract_hash, 64);
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (state.contract_hash[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(!is_zero, "Contract hash is not empty");

  mxd_free_contract_state(&state);
  TEST_END("Contract Deployment");
}

static void test_contract_execution(void) {
  mxd_contract_state_t state;
  mxd_execution_result_t result;
  uint32_t input = TEST_INPUT_VALUE;

  TEST_START("Contract Execution");
  enable_contracts_for_testing();
  TEST_VALUE("Input value", "%u", input);
  
  // Deploy and execute contract
  TEST_ASSERT(mxd_deploy_contract(test_wasm, test_wasm_len, &state) == 0, "Contract deployment successful");
  TEST_ASSERT(mxd_execute_contract(&state, (uint8_t *)&input, sizeof(input),
                              &result) == 0, "Contract execution successful");

  // Verify result
  TEST_ASSERT(result.success, "Execution completed successfully");
  TEST_VALUE("Gas used", "%lu", result.gas_used);
  TEST_VALUE("Return value", "%u", *(uint32_t *)result.return_data);
  TEST_ASSERT(*(uint32_t *)result.return_data == EXPECTED_OUTPUT_VALUE, "Return value matches expected");

  mxd_free_contract_state(&state);
  TEST_END("Contract Execution");
}

static void test_contract_storage(void) {
  mxd_contract_state_t state;
  uint8_t key[4] = {1, 2, 3, 4};
  uint8_t value[4] = {5, 6, 7, 8};
  uint8_t retrieved[4];
  size_t value_size = sizeof(retrieved);

  TEST_START("Contract Storage");
  enable_contracts_for_testing();
  
  // Deploy contract
  TEST_ASSERT(mxd_deploy_contract(test_wasm, sizeof(test_wasm), &state) == 0, "Contract deployment successful");

  // Set storage
  TEST_ARRAY("Storage key", key, sizeof(key));
  TEST_ARRAY("Storage value", value, sizeof(value));
  TEST_ASSERT(mxd_set_contract_storage(&state, key, sizeof(key), value,
                                  sizeof(value)) == 0, "Storage set successful");

  // Get storage
  TEST_ASSERT(mxd_get_contract_storage(&state, key, sizeof(key), retrieved,
                                  &value_size) == 0, "Storage retrieval successful");
  TEST_ASSERT(value_size == sizeof(value), "Retrieved value size matches original");
  TEST_ARRAY("Retrieved value", retrieved, value_size);
  TEST_ASSERT(memcmp(value, retrieved, value_size) == 0, "Retrieved value matches original");

  mxd_free_contract_state(&state);
  TEST_END("Contract Storage");
}

static void test_state_transition(void) {
  mxd_contract_state_t old_state = {0}, new_state = {0};
  uint8_t key[4] = {1, 2, 3, 4};
  uint8_t value[4] = {5, 6, 7, 8};

  TEST_START("State Transition");
  enable_contracts_for_testing();
  
  // Deploy contract
  TEST_ASSERT(mxd_deploy_contract(test_wasm, test_wasm_len, &old_state) == 0, "Initial contract deployment successful");

  // Create new state - copy hash and module, but create fresh storage
  TEST_VALUE("Creating new state", "%s", "deep copy with shared module");
  memcpy(new_state.contract_hash, old_state.contract_hash, 64);
  memcpy(new_state.state_hash, old_state.state_hash, 64);
  new_state.gas_used = old_state.gas_used;
  new_state.gas_limit = old_state.gas_limit;
  new_state.storage = NULL;
  new_state.storage_size = 0;
  new_state.storage_trie = NULL;  // Will be created by mxd_set_contract_storage if needed
  new_state.module = old_state.module; // Share the module between states

  // Modify state
  TEST_ARRAY("Storage key", key, sizeof(key));
  TEST_ARRAY("Storage value", value, sizeof(value));
  TEST_ASSERT(mxd_set_contract_storage(&new_state, key, sizeof(key), value,
                                  sizeof(value)) == 0, "New state storage modification successful");

  // Validate transition
  TEST_ASSERT(mxd_validate_state_transition(&old_state, &new_state) == 0, "State transition validation successful");

  mxd_free_contract_state(&old_state);
  mxd_free_contract_state(&new_state);
  TEST_END("State Transition");
}

static void test_gas_calculation(void) {
  TEST_START("Gas Calculation");
  enable_contracts_for_testing();
  
  uint64_t gas = mxd_calculate_gas(test_wasm, sizeof(test_wasm));
  TEST_VALUE("Contract size", "%zu", sizeof(test_wasm));
  TEST_VALUE("Calculated gas", "%lu", gas);
  
  TEST_ASSERT(gas > 0, "Gas cost is positive");
  TEST_ASSERT(gas <= MXD_MAX_GAS, "Gas cost is within limits");
  
  TEST_END("Gas Calculation");
}

static void test_contracts_disabled_by_default(void) {
  mxd_config_t disabled_config = {0};
  mxd_contract_state_t state = {0};
  mxd_execution_result_t result = {0};
  uint8_t key[4] = {1, 2, 3, 4};
  uint8_t value[4] = {5, 6, 7, 8};
  size_t value_size = sizeof(value);
  uint32_t input = TEST_INPUT_VALUE;
  
  TEST_START("Contracts Disabled By Default");
  
  mxd_set_default_config(&disabled_config);
  mxd_set_global_config(&disabled_config);
  
  TEST_ASSERT(mxd_init_contracts() == -1, "mxd_init_contracts returns -1 when disabled");
  TEST_ASSERT(mxd_deploy_contract(test_wasm, sizeof(test_wasm), &state) == -1, "mxd_deploy_contract returns -1 when disabled");
  TEST_ASSERT(mxd_execute_contract(&state, (uint8_t *)&input, sizeof(input), &result) == -1, "mxd_execute_contract returns -1 when disabled");
  TEST_ASSERT(mxd_validate_state_transition(&state, &state) == -1, "mxd_validate_state_transition returns -1 when disabled");
  TEST_ASSERT(mxd_calculate_gas(test_wasm, sizeof(test_wasm)) == 0, "mxd_calculate_gas returns 0 when disabled");
  TEST_ASSERT(mxd_get_contract_storage(&state, key, sizeof(key), value, &value_size) == -1, "mxd_get_contract_storage returns -1 when disabled");
  TEST_ASSERT(mxd_set_contract_storage(&state, key, sizeof(key), value, sizeof(value)) == -1, "mxd_set_contract_storage returns -1 when disabled");
  
  TEST_END("Contracts Disabled By Default");
}

int main(void) {
  TEST_START("Smart Contracts Tests");

  test_contracts_disabled_by_default();
  test_contract_initialization();
  test_contract_deployment();
  test_contract_execution();
  test_contract_storage();
  test_state_transition();
  test_gas_calculation();

  TEST_END("Smart Contracts Tests");
  return 0;
}
