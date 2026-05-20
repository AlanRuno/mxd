#ifndef MXD_CONTRACTS_DB_H
#define MXD_CONTRACTS_DB_H

#include <stdint.h>
#include <stddef.h>

// Contract metadata structure
typedef struct {
    uint8_t contract_hash[64];
    uint8_t *bytecode;
    size_t bytecode_size;
    uint64_t deployed_at;        // Block height
    uint64_t deployed_timestamp; // Unix timestamp
    uint8_t deployer[20];        // Address that deployed the contract
    uint64_t total_gas_used;     // Cumulative gas used by this contract
    uint32_t call_count;         // Number of times contract has been called
} mxd_contract_metadata_t;

// Contract call record
typedef struct {
    uint8_t tx_hash[64];
    uint8_t contract_hash[64];
    char function_name[256];
    uint8_t *params;
    size_t params_size;
    uint8_t *result;
    size_t result_size;
    uint64_t gas_used;
    uint64_t timestamp;
    uint32_t success;
} mxd_contract_call_t;

// Contract state storage (database representation)
typedef struct {
    uint8_t contract_hash[64];
    uint8_t state_root[64];
    uint8_t *storage_data;
    size_t storage_size;
    uint64_t last_modified;
} mxd_contract_storage_t;

// Initialize contracts database
int mxd_contracts_db_init(const char *db_path);

// Close contracts database
void mxd_contracts_db_close(void);

// Store deployed contract
int mxd_contracts_db_store_contract(const mxd_contract_metadata_t *contract);

// Load contract by hash
int mxd_contracts_db_load_contract(const uint8_t contract_hash[64],
                                    mxd_contract_metadata_t *contract);

// Get all contracts (returns array, caller must free)
int mxd_contracts_db_get_all_contracts(mxd_contract_metadata_t **contracts,
                                        uint32_t *count);

// Store contract call record
int mxd_contracts_db_store_call(const mxd_contract_call_t *call);

// Get contract call history
int mxd_contracts_db_get_call_history(const uint8_t contract_hash[64],
                                       mxd_contract_call_t **calls,
                                       uint32_t *count);

// Store contract state
int mxd_contracts_db_store_state(const mxd_contract_storage_t *state);

// Load contract state
int mxd_contracts_db_load_state(const uint8_t contract_hash[64],
                                 mxd_contract_storage_t *state);

// Delete contract (for testing/cleanup)
int mxd_contracts_db_delete_contract(const uint8_t contract_hash[64]);

// Check if contract exists
int mxd_contracts_db_exists(const uint8_t contract_hash[64]);

#endif // MXD_CONTRACTS_DB_H
