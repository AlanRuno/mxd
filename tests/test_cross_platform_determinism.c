#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_wasm_validator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/**
 * Cross-Platform Determinism Test Suite
 *
 * These tests MUST produce identical results on:
 * - Linux x64 (GCC, Clang)
 * - Linux ARM64 (GCC, Clang)
 * - macOS ARM64 (M1/M2) (Clang)
 * - Windows x64 (MSVC, MinGW)
 *
 * Any difference in results indicates a determinism bug!
 */

// Test contract: Simple arithmetic
static const uint8_t test_arithmetic_wasm[] = {
    0x00, 0x61, 0x73, 0x6D, // Magic
    0x01, 0x00, 0x00, 0x00, // Version
    // Type section: () -> i32
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
    // Function section
    0x03, 0x02, 0x01, 0x00,
    // Export section
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00,
    // Code section: i32.const 2147483647; i32.const 1; i32.add
    0x0A, 0x0C, 0x01, 0x0A, 0x00,
    0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, // i32.const 2147483647
    0x41, 0x01,                          // i32.const 1
    0x6A,                                // i32.add
    0x0B                                 // end
};

// Test contract: Division operations
static const uint8_t test_division_wasm[] = {
    0x00, 0x61, 0x73, 0x6D,
    0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00,
    // Code: i32.const -10; i32.const 3; i32.div_s
    0x0A, 0x0A, 0x01, 0x08, 0x00,
    0x41, 0x76,        // i32.const -10 (LEB128)
    0x41, 0x03,        // i32.const 3
    0x6D,              // i32.div_s
    0x0B
};

// Test contract with banned f32 instruction (should fail validation)
static const uint8_t test_banned_f32_wasm[] = {
    0x00, 0x61, 0x73, 0x6D,
    0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7D, // Result type: f32
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00,
    // Code: f32.const 1.5; f32.const 2.0; f32.add
    0x0A, 0x11, 0x01, 0x0F, 0x00,
    0x43, 0x00, 0x00, 0xC0, 0x3F, // f32.const 1.5
    0x43, 0x00, 0x00, 0x00, 0x40, // f32.const 2.0
    0x92,                          // f32.add (BANNED)
    0x0B
};

// Test contract with memory.grow (should fail validation)
static const uint8_t test_banned_memory_grow_wasm[] = {
    0x00, 0x61, 0x73, 0x6D,
    0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
    0x03, 0x02, 0x01, 0x00,
    0x05, 0x03, 0x01, 0x00, 0x01, // Memory section: 1 page
    0x07, 0x08, 0x01, 0x04, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00,
    // Code: i32.const 1; memory.grow
    0x0A, 0x07, 0x01, 0x05, 0x00,
    0x41, 0x01,  // i32.const 1
    0x40, 0x00,  // memory.grow (BANNED)
    0x0B
};

// Expected results for each platform (SHA-512 hash of execution result)
// These MUST match across all platforms
typedef struct {
    const char *test_name;
    const uint8_t *wasm;
    size_t wasm_size;
    uint32_t expected_result;
    uint8_t expected_hash[64];
} determinism_test_case_t;

void print_platform_info() {
    printf("\n=== Platform Information ===\n");

#if defined(_WIN32) || defined(_WIN64)
    printf("OS: Windows\n");
#elif defined(__APPLE__)
    printf("OS: macOS\n");
#elif defined(__linux__)
    printf("OS: Linux\n");
#else
    printf("OS: Unknown\n");
#endif

#if defined(__x86_64__) || defined(_M_X64)
    printf("Architecture: x86_64\n");
#elif defined(__aarch64__) || defined(_M_ARM64)
    printf("Architecture: ARM64\n");
#elif defined(__i386__) || defined(_M_IX86)
    printf("Architecture: x86\n");
#else
    printf("Architecture: Unknown\n");
#endif

#if defined(__GNUC__)
    printf("Compiler: GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__clang__)
    printf("Compiler: Clang %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(_MSC_VER)
    printf("Compiler: MSVC %d\n", _MSC_VER);
#else
    printf("Compiler: Unknown\n");
#endif

    printf("sizeof(int): %zu bytes\n", sizeof(int));
    printf("sizeof(long): %zu bytes\n", sizeof(long));
    printf("sizeof(long long): %zu bytes\n", sizeof(long long));
    printf("sizeof(void*): %zu bytes\n", sizeof(void*));
    printf("Endianness: %s\n",
           *(uint16_t*)"\x01\x02" == 0x0201 ? "Little-endian" : "Big-endian");
}

void test_wasm_validation() {
    printf("\n=== Test: WASM Validation ===\n");

    // Test 1: Valid contract should pass
    mxd_wasm_validation_result_t result;
    int code = mxd_validate_wasm_determinism(test_arithmetic_wasm,
                                              sizeof(test_arithmetic_wasm),
                                              &result);
    printf("Arithmetic contract validation: %s\n",
           code == MXD_WASM_VALID ? "PASS" : "FAIL");
    assert(code == MXD_WASM_VALID);

    // Test 2: F32 contract should fail
    code = mxd_validate_wasm_determinism(test_banned_f32_wasm,
                                         sizeof(test_banned_f32_wasm),
                                         &result);
    printf("F32 contract validation: %s (expected FAIL)\n",
           code == MXD_WASM_VALID ? "PASS" : "FAIL");
    printf("  Error: %s\n", result.error_message);
    assert(code == MXD_WASM_NON_DETERMINISTIC);

    // Test 3: memory.grow contract should fail
    code = mxd_validate_wasm_determinism(test_banned_memory_grow_wasm,
                                         sizeof(test_banned_memory_grow_wasm),
                                         &result);
    printf("Memory.grow contract validation: %s (expected FAIL)\n",
           code == MXD_WASM_VALID ? "PASS" : "FAIL");
    printf("  Error: %s\n", result.error_message);
    assert(code == MXD_WASM_NON_DETERMINISTIC);

    printf("✓ WASM validation tests passed\n");
}

void test_banned_instructions() {
    printf("\n=== Test: Banned Instructions List ===\n");

    size_t count = 0;
    const mxd_banned_instruction_t *banned = mxd_get_banned_instructions(&count);

    printf("Total banned instructions: %zu\n", count);
    printf("Sample banned instructions:\n");

    int samples = count < 10 ? count : 10;
    for (int i = 0; i < samples; i++) {
        printf("  0x%02X %-20s - %s\n",
               banned[i].opcode,
               banned[i].name,
               banned[i].reason);
    }

    // Verify specific banned opcodes
    assert(mxd_is_opcode_banned(0x43) != NULL); // f32.const
    assert(mxd_is_opcode_banned(0x44) != NULL); // f64.const
    assert(mxd_is_opcode_banned(0x40) != NULL); // memory.grow
    assert(mxd_is_opcode_banned(0x92) != NULL); // f32.add

    // Verify allowed opcodes
    assert(mxd_is_opcode_banned(0x41) == NULL); // i32.const (allowed)
    assert(mxd_is_opcode_banned(0x6A) == NULL); // i32.add (allowed)
    assert(mxd_is_opcode_banned(0x6D) == NULL); // i32.div_s (allowed)

    printf("✓ Banned instructions test passed\n");
}

void test_integer_overflow() {
    printf("\n=== Test: Integer Overflow Determinism ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    int result = mxd_deploy_contract(test_arithmetic_wasm,
                                      sizeof(test_arithmetic_wasm),
                                      &state);
    assert(result == 0);

    uint32_t input = 0;
    mxd_execution_result_t exec_result;

    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);
    assert(result == 0);

    // Extract result (i32.max + 1 should wrap to i32.min)
    uint32_t output;
    memcpy(&output, exec_result.return_data, sizeof(output));

    printf("i32.max + 1 = %d (0x%08X)\n", (int32_t)output, output);
    printf("Expected: -2147483648 (0x80000000)\n");

    // This MUST be -2147483648 (0x80000000) on all platforms
    assert((int32_t)output == -2147483648);
    assert(output == 0x80000000);

    printf("✓ Integer overflow is deterministic\n");

    mxd_free_contract_state(&state);
}

void test_division_determinism() {
    printf("\n=== Test: Division Determinism ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    int result = mxd_deploy_contract(test_division_wasm,
                                      sizeof(test_division_wasm),
                                      &state);
    assert(result == 0);

    uint32_t input = 0;
    mxd_execution_result_t exec_result;

    result = mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);
    assert(result == 0);

    // Extract result (-10 / 3 = -3 signed)
    int32_t output;
    memcpy(&output, exec_result.return_data, sizeof(output));

    printf("-10 / 3 (signed) = %d\n", output);
    printf("Expected: -3\n");

    // This MUST be -3 on all platforms
    assert(output == -3);

    printf("✓ Signed division is deterministic\n");

    mxd_free_contract_state(&state);
}

void test_result_hashing() {
    printf("\n=== Test: Execution Result Hashing ===\n");

    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    mxd_deploy_contract(test_arithmetic_wasm,
                       sizeof(test_arithmetic_wasm),
                       &state);

    uint32_t input = 0;
    mxd_execution_result_t exec_result;

    mxd_execute_contract(&state, (uint8_t*)&input, sizeof(input), &exec_result);

    // Hash the execution result
    uint8_t result_hash[64];
    mxd_sha512(exec_result.return_data, exec_result.return_size, result_hash);

    printf("Execution result hash (first 16 bytes):\n  ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", result_hash[i]);
    }
    printf("\n");

    printf("\nIMPORTANT: Record this hash and compare across platforms!\n");
    printf("All platforms MUST produce the identical hash.\n");

    // Print full hash for verification
    printf("\nFull SHA-512 hash for verification:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", result_hash[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }

    mxd_free_contract_state(&state);

    printf("✓ Result hashing test passed\n");
}

int main() {
    printf("Cross-Platform Determinism Test Suite\n");
    printf("======================================\n");

    print_platform_info();

    // Initialize contracts
    if (mxd_init_contracts() != 0) {
        printf("WARNING: Smart contracts may be disabled\n");
    }

    test_wasm_validation();
    test_banned_instructions();
    test_integer_overflow();
    test_division_determinism();
    test_result_hashing();

    printf("\n======================================\n");
    printf("All determinism tests passed!\n");
    printf("\n");
    printf("Next Steps:\n");
    printf("1. Run this test on all target platforms:\n");
    printf("   - Linux x64 (GCC, Clang)\n");
    printf("   - Linux ARM64 (GCC, Clang)\n");
    printf("   - macOS ARM64 (Clang)\n");
    printf("   - Windows x64 (MSVC, MinGW)\n");
    printf("2. Compare the result hashes\n");
    printf("3. Any difference indicates a determinism bug\n");
    printf("4. Document platform-specific behavior (if any)\n");

    return 0;
}
