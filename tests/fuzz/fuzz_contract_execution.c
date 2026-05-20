/**
 * Fuzz Test: Contract Execution
 *
 * Uses libFuzzer to test contract execution with random inputs
 * Finds crashes, hangs, memory leaks, and undefined behavior
 *
 * Compile with:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 \
 *         fuzz_contract_execution.c \
 *         ../../src/*.c ../../src/blockchain/*.c \
 *         -I../../include -I../../wasm3/source \
 *         -lsqlite3 -lcrypto -lssl -lm -lpthread \
 *         -o fuzz_contract_execution
 *
 * Run:
 *   ./fuzz_contract_execution corpus/ -max_len=1048576 -timeout=10
 */

#include "../../include/mxd_smart_contracts.h"
#include "../../include/mxd_wasm_validator.h"
#include "../../include/mxd_logging.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Minimal valid WASM module template
static const uint8_t WASM_TEMPLATE[] = {
    0x00, 0x61, 0x73, 0x6D, // Magic
    0x01, 0x00, 0x00, 0x00, // Version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // Type section
    0x03, 0x02, 0x01, 0x00, // Function section
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00, // Export "main"
    0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0B // Code: i32.const 0
};

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Skip empty inputs
    if (size < 8) {
        return 0;
    }

    // Initialize contracts (once)
    static int initialized = 0;
    if (!initialized) {
        mxd_init_contracts();
        initialized = 1;
    }

    // Split input: first part is WASM, rest is execution input
    size_t wasm_size = size / 2;
    size_t input_size = size - wasm_size;
    const uint8_t *wasm = data;
    const uint8_t *input = data + wasm_size;

    // Limit sizes to prevent timeouts
    if (wasm_size > 65536) {
        wasm_size = 65536;
    }
    if (input_size > 1024) {
        input_size = 1024;
    }

    // Test 1: WASM validation
    mxd_wasm_validation_result_t validation_result;
    int validation_code = mxd_validate_wasm_determinism(wasm, wasm_size, &validation_result);

    // If validation passes, try to deploy and execute
    if (validation_code == MXD_WASM_VALID) {
        mxd_contract_state_t state;
        memset(&state, 0, sizeof(state));

        // Try to deploy
        int deploy_result = mxd_deploy_contract(wasm, wasm_size, &state);

        if (deploy_result == 0) {
            // Try to execute with fuzzer-provided input
            mxd_execution_result_t exec_result;

            // Limit gas to prevent infinite loops
            state.gas_limit = 10000;

            // Execute (may fail, that's ok)
            mxd_execute_contract(&state, input, input_size, &exec_result);

            // Clean up
            mxd_free_contract_state(&state);
        }
    }

    // Test 2: Validation edge cases
    // Try validation with various corrupted inputs
    if (size > sizeof(WASM_TEMPLATE)) {
        uint8_t modified_wasm[sizeof(WASM_TEMPLATE)];
        memcpy(modified_wasm, WASM_TEMPLATE, sizeof(WASM_TEMPLATE));

        // Corrupt random byte
        if (size > 0) {
            size_t corrupt_offset = data[0] % sizeof(WASM_TEMPLATE);
            modified_wasm[corrupt_offset] ^= data[size - 1];
        }

        mxd_validate_wasm_determinism(modified_wasm, sizeof(modified_wasm), &validation_result);
    }

    return 0;
}
