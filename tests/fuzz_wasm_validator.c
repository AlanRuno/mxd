/**
 * WASM Validator Fuzzer
 *
 * Fuzzes the WASM validator to find crashes, hangs, or memory issues
 *
 * Compile with AFL:
 *   afl-gcc -o fuzz_wasm_validator fuzz_wasm_validator.c \
 *       ../src/mxd_wasm_validator.c ../src/mxd_logging.c \
 *       -I../include
 *
 * Compile with libFuzzer:
 *   clang -g -O1 -fsanitize=fuzzer,address \
 *       -o fuzz_wasm_validator fuzz_wasm_validator.c \
 *       ../src/mxd_wasm_validator.c ../src/mxd_logging.c \
 *       -I../include
 *
 * Run with AFL:
 *   mkdir -p fuzz_input fuzz_output
 *   echo -ne '\x00\x61\x73\x6D\x01\x00\x00\x00' > fuzz_input/valid.wasm
 *   afl-fuzz -i fuzz_input -o fuzz_output ./fuzz_wasm_validator
 *
 * Run with libFuzzer:
 *   ./fuzz_wasm_validator corpus/ -max_len=1048576 -timeout=60
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "../include/mxd_wasm_validator.h"

#ifdef __AFL_COMPILER
// AFL fuzzing target
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    uint8_t buffer[1048576]; // 1MB max
    size_t size = fread(buffer, 1, sizeof(buffer), stdin);

    if (size > 0) {
        mxd_wasm_validation_result_t result;
        mxd_validate_wasm_determinism(buffer, size, &result);
    }

    return 0;
}
#else
// libFuzzer target
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1048576) { // 0 bytes or > 1MB
        return 0;
    }

    mxd_wasm_validation_result_t result;
    mxd_validate_wasm_determinism(data, size, &result);

    return 0;
}
#endif
