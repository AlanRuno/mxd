#ifndef MXD_WASM_VALIDATOR_H
#define MXD_WASM_VALIDATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * WASM Determinism Validator
 *
 * Validates WASM bytecode to ensure deterministic execution across platforms.
 * Rejects contracts with non-deterministic instructions or behaviors.
 */

// Validation result codes
#define MXD_WASM_VALID 0
#define MXD_WASM_INVALID_MAGIC -1
#define MXD_WASM_INVALID_VERSION -2
#define MXD_WASM_NON_DETERMINISTIC -3
#define MXD_WASM_FLOATING_POINT -4
#define MXD_WASM_MEMORY_GROW -5
#define MXD_WASM_TOO_LARGE -6
#define MXD_WASM_INVALID_IMPORT -7

/**
 * Validation result structure
 */
typedef struct {
    int result_code;
    char error_message[256];
    uint32_t error_offset;      // Byte offset where error occurred
    uint8_t banned_opcode;      // Opcode that caused rejection
    const char *banned_instruction; // Human-readable instruction name
} mxd_wasm_validation_result_t;

/**
 * Banned instruction information
 */
typedef struct {
    uint8_t opcode;
    const char *name;
    const char *reason;
} mxd_banned_instruction_t;

/**
 * Validate WASM bytecode for determinism
 *
 * Checks that the WASM module:
 * - Contains no floating-point operations (f32/f64)
 * - Contains no memory.grow instructions
 * - Contains no non-deterministic imports
 * - Has valid WASM magic number and version
 * - Is within size limits
 *
 * @param bytecode WASM bytecode to validate
 * @param size Size of bytecode in bytes
 * @param result Validation result (output)
 * @return 0 if valid, negative error code if invalid
 */
int mxd_validate_wasm_determinism(const uint8_t *bytecode, size_t size,
                                   mxd_wasm_validation_result_t *result);

/**
 * Check if an opcode is banned for determinism
 *
 * @param opcode WASM opcode to check
 * @return Pointer to banned instruction info, or NULL if allowed
 */
const mxd_banned_instruction_t *mxd_is_opcode_banned(uint8_t opcode);

/**
 * Get list of all banned instructions
 *
 * @param count Output parameter for number of banned instructions
 * @return Array of banned instruction info
 */
const mxd_banned_instruction_t *mxd_get_banned_instructions(size_t *count);

/**
 * Validate WASM imports for determinism
 *
 * Ensures all imports are from allowed modules/functions
 *
 * @param module_name Import module name
 * @param field_name Import field name
 * @return 1 if allowed, 0 if banned
 */
int mxd_is_import_allowed(const char *module_name, const char *field_name);

#ifdef __cplusplus
}
#endif

#endif // MXD_WASM_VALIDATOR_H
