# 🔗 MXD Library Integration Guide

## Library Setup

### Static Linking
```cmake
# CMakeLists.txt
find_package(MXD REQUIRED)
target_link_libraries(your_project PRIVATE mxd)
```

### Dynamic Linking
```cmake
# CMakeLists.txt
find_package(MXD REQUIRED)
target_link_libraries(your_project PRIVATE mxd_shared)
```

Note:
- mxd_dilithium_* APIs are stable.
- Default builds use Ed25519; when built with -DMXD_PQC_DILITHIUM=ON they use Crystals Dilithium (both implementations available).
## Basic Usage Examples

### Cryptographic Operations
```c
#include <mxd_crypto.h>

void crypto_example() {
    // Generate keypair
    uint8_t public_key[256];
    uint8_t private_key[128];
    mxd_dilithium_keygen(public_key, private_key);

    // Sign message
    const char *message = "Hello, MXD!";
    uint8_t signature[256];
    size_t signature_length;
    mxd_dilithium_sign(signature, &signature_length, 
                       (uint8_t*)message, strlen(message), 
                       private_key);
}
```

### Address Management
```c
#include <mxd_address.h>

void address_example() {
    // Generate passphrase
    char passphrase[256];
    mxd_generate_passphrase(passphrase, sizeof(passphrase));

    // Generate address
    char address[42];
    uint8_t public_key[256];
    mxd_generate_address(public_key, address, sizeof(address));
}
```

### Transaction Creation with UTXO Verification
```c
#include <mxd_transaction.h>
#include <mxd_utxo.h>

void transaction_example() {
    // Initialize UTXO database with RocksDB
    mxd_init_utxo_db("./utxo.db");
    
    // Create transaction
    mxd_transaction_t tx;
    mxd_create_transaction(&tx);

    // Add input/output
    uint8_t prev_hash[64] = {0};
    uint8_t recipient[256] = {0};
    mxd_add_tx_input(&tx, prev_hash, 0, public_key);
    mxd_add_tx_output(&tx, recipient, 1.0);

    // Sign and validate with UTXO verification
    mxd_sign_tx_input(&tx, 0, private_key);
    
    // Verify transaction against UTXO database
    if (mxd_validate_transaction(&tx) == 0) {
        // Apply transaction to UTXO database
        mxd_apply_transaction_to_utxo(&tx);
    }
    
    // Close UTXO database when done
    mxd_close_utxo_db();
}
```

### Validation Chain Protocol
```c
#include <mxd_blockchain.h>
#include <mxd_rsc.h>

void validation_chain_example() {
    // Initialize blockchain with RocksDB
    mxd_init_blockchain_db("./blockchain.db");
    
    // Create a new block with validation chain
    mxd_block_t block;
    mxd_create_block(&block);
    
    // Add validator signatures to validation chain
    uint8_t validator_id[20] = {0};
    uint8_t signature[256] = {0};
    uint64_t timestamp = mxd_get_current_time_ms();
    
    // Add first validator signature
    mxd_add_validator_signature(&block, validator_id, timestamp, signature);
    
    // Verify validation chain
    if (mxd_verify_validation_chain(&block) == 0) {
        // Calculate cumulative latency score for fork resolution
        double score = mxd_calculate_latency_score(&block);
        
        // Add block to blockchain
        mxd_add_block_to_chain(&block);
    }
    
    // Close blockchain database when done
    mxd_close_blockchain_db();
}
```

### Smart Contract Deployment
```c
#include <mxd_smart_contracts.h>

void contract_example() {
    // Initialize contracts
    mxd_init_contracts();

    // Deploy contract
    mxd_contract_state_t state;
    mxd_deploy_contract(wasm_code, wasm_size, &state);

    // Execute contract
    uint8_t input[4] = {1, 0, 0, 0};
    mxd_execution_result_t result;
    mxd_execute_contract(&state, input, sizeof(input), &result);
}
```

## Best Practices

### Memory Management
- Always free resources using provided cleanup functions
- Use stack allocation for small buffers
- Check return values for error conditions

### Thread Safety
- Use thread-safe functions for concurrent operations
- Implement proper synchronization when sharing resources
- Follow the documented thread safety guidelines

### Error Handling
```c
// Example error handling pattern
int result = mxd_function();
if (result != 0) {
    // Handle error
    return result;
}
```

### Security Considerations
- Keep private keys secure
- Validate all inputs
- Use secure random number generation
- Follow cryptographic best practices

## Performance Optimization

### Memory Pool Configuration
```c
// Configure memory pool size based on requirements
#define MXD_MAX_MEMPOOL_SIZE 10000
```

### Smart Contract Gas Limits
```c
// Set appropriate gas limits
#define MXD_MAX_GAS 1000000
```

### Network Settings
```c
// Configure P2P network parameters
#define MXD_MAX_PEERS 1000
#define MXD_MAX_MESSAGE_SIZE 1048576
```
