#ifndef MXD_SMART_CONTRACTS_H
#define MXD_SMART_CONTRACTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Maximum contract size
#define MXD_MAX_CONTRACT_SIZE 1048576 // 1MB

// Maximum gas per transaction
#define MXD_MAX_GAS 1000000

// Contract state
typedef struct {
  uint8_t contract_hash[64]; // SHA-512 hash of contract code
  uint8_t state_hash[64];    // SHA-512 hash of contract state (merkle root)
  uint64_t gas_used;         // Gas used by contract
  uint64_t gas_limit;        // Gas limit for contract
  uint8_t *storage;          // Legacy linear storage (for backward compatibility)
  size_t storage_size;       // Legacy storage size
  void *storage_trie;        // Merkle patricia trie for production storage
  void *module;              // WebAssembly module handle
  void *runtime;             // SECURITY FIX: Per-contract WASM runtime (not shared)
  void *env;                 // SECURITY FIX: Per-contract WASM environment
  uint8_t reentrancy_lock;   // Prevent recursive calls
  uint32_t call_depth;       // Track call stack depth (max 256)
  void *mutex;               // SECURITY FIX: Thread safety mutex
  uint8_t *bytecode;         // SECURITY FIX: Store bytecode for gas calculation
  size_t bytecode_size;      // Bytecode size
} mxd_contract_state_t;

// Contract execution result
typedef struct {
  int success;              // Execution success flag
  uint64_t gas_used;        // Gas used during execution
  uint8_t return_data[256]; // Return data
  size_t return_size;       // Return data size
} mxd_execution_result_t;

// Initialize smart contracts module
int mxd_init_contracts(void);

// Deploy contract
int mxd_deploy_contract(const uint8_t *code, size_t code_size,
                        const uint8_t deployer[20],
                        mxd_contract_state_t *state);

// Execute contract
// SECURITY FIX: Removed const to allow safe reentrancy lock modification
int mxd_execute_contract(mxd_contract_state_t *state,
                         const uint8_t *input, size_t input_size,
                         mxd_execution_result_t *result);

// Validate contract state transition
int mxd_validate_state_transition(const mxd_contract_state_t *old_state,
                                  const mxd_contract_state_t *new_state);

// Calculate contract gas cost
uint64_t mxd_calculate_gas(const uint8_t *code, size_t code_size);

// Get contract storage
int mxd_get_contract_storage(const mxd_contract_state_t *state,
                             const uint8_t *key, size_t key_size,
                             uint8_t *value, size_t *value_size);

// Set contract storage
int mxd_set_contract_storage(mxd_contract_state_t *state, const uint8_t *key,
                             size_t key_size, const uint8_t *value,
                             size_t value_size);

// Free contract state resources
void mxd_free_contract_state(mxd_contract_state_t *state);

#ifdef __cplusplus
}
#endif

#endif // MXD_SMART_CONTRACTS_H
