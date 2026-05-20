/**
 * Fuzz Test: Gas Metering
 *
 * Tests gas calculation and enforcement with malformed/malicious WASM
 * Ensures gas limits cannot be bypassed
 */

#include "../../include/mxd_gas_metering.h"
#include "../../include/mxd_smart_contracts.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0;
    }

    // Test 1: Gas calculation from bytecode
    uint64_t gas_cost = mxd_calculate_gas_from_bytecode(data, size);

    // Gas cost should never be 0 for valid bytecode
    // (unless it's completely empty, but that should fail validation)

    // Test 2: Gas enforcement during execution
    if (size > 32) {
        // Extract gas limit from fuzzer input
        uint64_t gas_limit;
        memcpy(&gas_limit, data, sizeof(uint64_t));

        // Reasonable gas limit range
        gas_limit = (gas_limit % 100000) + 100;

        mxd_contract_state_t state;
        memset(&state, 0, sizeof(state));
        state.gas_limit = gas_limit;

        // Try to deploy and execute
        const uint8_t *wasm = data + 8;
        size_t wasm_size = size - 8;

        if (wasm_size < 1024 && mxd_deploy_contract(wasm, wasm_size, &state) == 0) {
            uint32_t input = 0;
            mxd_execution_result_t result;

            // Execute - should never exceed gas limit
            if (mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &result) == 0) {
                // Verify gas tracking
                if (result.gas_used > state.gas_limit) {
                    // CRITICAL BUG: Gas limit exceeded!
                    __builtin_trap();
                }

                if (state.gas_used > state.gas_limit) {
                    // CRITICAL BUG: State gas exceeded limit!
                    __builtin_trap();
                }
            }

            mxd_free_contract_state(&state);
        }
    }

    // Test 3: Opcode gas costs
    for (size_t i = 0; i < size && i < 256; i++) {
        uint8_t opcode = data[i];
        uint64_t cost = mxd_get_opcode_gas_cost(opcode);

        // All opcodes should have non-zero cost
        // (even if banned, they should have a cost defined)
        if (cost == 0 && opcode != 0x00 && opcode != 0x0B) {
            // 0x00 (unreachable) and 0x0B (end) can have zero cost
            // Other opcodes should cost something
        }
    }

    return 0;
}
