#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_gas_metering.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Simple WASM module with infinite loop
// (module
//   (func $infinite_loop (result i32)
//     (local $i i32)
//     (loop $continue
//       local.get $i
//       i32.const 1
//       i32.add
//       local.set $i
//       br $continue
//     )
//     local.get $i
//   )
//   (export "main" (func $infinite_loop))
// )
static const uint8_t infinite_loop_wasm[] = {
    0x00, 0x61, 0x73, 0x6D, // Magic number
    0x01, 0x00, 0x00, 0x00, // Version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // Type section
    0x03, 0x02, 0x01, 0x00, // Function section
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00, // Export section
    0x0A, 0x10, 0x01, 0x0E, 0x01, 0x01, 0x7F, // Code section start
    0x03, 0x40, // loop
    0x20, 0x00, // local.get 0
    0x41, 0x01, // i32.const 1
    0x6A,       // i32.add
    0x21, 0x00, // local.set 0
    0x0C, 0x00, // br 0 (infinite loop)
    0x0B,       // end loop
    0x20, 0x00, // local.get 0
    0x0B        // end function
};

// Simple WASM module that returns input (for reentrancy test)
// (module
//   (func $echo (param i32) (result i32)
//     local.get 0
//   )
//   (export "main" (func $echo))
// )
static const uint8_t echo_wasm[] = {
    0x00, 0x61, 0x73, 0x6D, // Magic number
    0x01, 0x00, 0x00, 0x00, // Version
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F, // Type section
    0x03, 0x02, 0x01, 0x00, // Function section
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00, // Export section
    0x0A, 0x06, 0x01, 0x04, 0x00, 0x20, 0x00, 0x0B // Code section
};

void test_gas_metering_enforcement() {
    printf("\n=== Test: Gas Metering Enforcement ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    // Deploy contract with low gas limit
    int result = mxd_deploy_contract(echo_wasm, sizeof(echo_wasm), &state);
    assert(result == 0);

    state.gas_limit = 100; // Very low gas limit

    // Execute contract
    uint32_t input = 42;
    mxd_execution_result_t exec_result;

    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);

    // Should succeed if gas used is within limit
    printf("Gas used: %lu, Gas limit: %lu\n",
           (unsigned long)exec_result.gas_used,
           (unsigned long)state.gas_limit);

    // Verify gas tracking
    assert(state.gas_used <= state.gas_limit);

    printf("✓ Gas metering enforcement test passed\n");

    mxd_free_contract_state(&state);
}

void test_cumulative_gas_tracking() {
    printf("\n=== Test: Cumulative Gas Tracking ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    int result = mxd_deploy_contract(echo_wasm, sizeof(echo_wasm), &state);
    assert(result == 0);

    state.gas_limit = 500;

    uint32_t input = 42;
    mxd_execution_result_t exec_result;

    // Execute contract multiple times
    uint64_t total_gas = 0;
    for (int i = 0; i < 3; i++) {
        result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);

        if (result == 0) {
            total_gas += exec_result.gas_used;
            printf("Execution %d: gas_used=%lu, cumulative=%lu\n",
                   i + 1,
                   (unsigned long)exec_result.gas_used,
                   (unsigned long)state.gas_used);
        } else {
            printf("Execution %d: Failed (cumulative gas limit exceeded)\n", i + 1);
            break;
        }
    }

    // Verify cumulative tracking
    assert(state.gas_used == total_gas);
    assert(state.gas_used <= state.gas_limit);

    printf("✓ Cumulative gas tracking test passed\n");

    mxd_free_contract_state(&state);
}

void test_reentrancy_protection() {
    printf("\n=== Test: Reentrancy Protection ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    int result = mxd_deploy_contract(echo_wasm, sizeof(echo_wasm), &state);
    assert(result == 0);

    // Manually set reentrancy lock to simulate recursive call
    state.reentrancy_lock = 1;

    uint32_t input = 42;
    mxd_execution_result_t exec_result;

    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);

    // Should fail due to reentrancy
    assert(result != 0);
    printf("✓ Reentrancy protection test passed (execution blocked as expected)\n");

    // Reset lock and verify execution works
    state.reentrancy_lock = 0;
    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);
    assert(result == 0);
    printf("✓ Execution succeeds after reentrancy lock released\n");

    mxd_free_contract_state(&state);
}

void test_call_depth_limit() {
    printf("\n=== Test: Call Depth Limit ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    int result = mxd_deploy_contract(echo_wasm, sizeof(echo_wasm), &state);
    assert(result == 0);

    // Set call depth to max
    state.call_depth = 256;

    uint32_t input = 42;
    mxd_execution_result_t exec_result;

    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);

    // Should fail due to call depth exceeded
    assert(result != 0);
    printf("✓ Call depth limit test passed (execution blocked at depth 256)\n");

    // Reset depth and verify execution works
    state.call_depth = 0;
    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);
    assert(result == 0);
    printf("✓ Execution succeeds with normal call depth\n");

    mxd_free_contract_state(&state);
}

void test_gas_calculation_accuracy() {
    printf("\n=== Test: Gas Calculation Accuracy ===\n");

    // Test individual opcode costs
    assert(mxd_get_opcode_gas_cost(0x20) == 1);   // local.get (BASE)
    assert(mxd_get_opcode_gas_cost(0x6A) == 2);   // i32.add (ARITHMETIC)
    assert(mxd_get_opcode_gas_cost(0x6D) == 10);  // i32.div_s (DIVISION)
    assert(mxd_get_opcode_gas_cost(0x28) == 3);   // i32.load (MEMORY_LOAD)
    assert(mxd_get_opcode_gas_cost(0x10) == 10);  // call (CALL)
    assert(mxd_get_opcode_gas_cost(0x40) == 1000); // memory.grow (MEMORY_GROW)

    printf("✓ Gas calculation accuracy test passed\n");
}

int main() {
    printf("Starting Gas Metering Enforcement Tests\n");
    printf("========================================\n");

    // Initialize smart contracts
    if (mxd_init_contracts() != 0) {
        printf("WARNING: Smart contracts may be disabled in config\n");
        printf("Some tests may be skipped\n");
    }

    test_gas_calculation_accuracy();
    test_gas_metering_enforcement();
    test_cumulative_gas_tracking();
    test_reentrancy_protection();
    test_call_depth_limit();

    printf("\n========================================\n");
    printf("All gas metering enforcement tests passed!\n");

    return 0;
}
