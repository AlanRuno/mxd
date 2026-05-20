#ifndef MXD_GAS_METERING_H
#define MXD_GAS_METERING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Gas context for runtime metering
typedef struct {
    uint64_t gas_remaining;
    uint64_t gas_limit;
    int out_of_gas;
} mxd_gas_context_t;

/**
 * Calculate gas cost by analyzing WASM bytecode
 *
 * This function parses the WASM binary format and calculates gas costs
 * based on instruction types and counts. Different instruction categories
 * have different gas costs based on their computational complexity:
 *
 * - Basic operations (local.get, drop): 1 gas
 * - Arithmetic operations (add, sub, mul): 2 gas
 * - Division operations: 10 gas
 * - Memory operations: 3 gas
 * - Control flow (br, if): 5 gas
 * - Function calls: 10 gas
 * - Memory grow: 1000 gas
 *
 * @param code Pointer to WASM bytecode
 * @param code_size Size of bytecode in bytes
 * @return Total gas cost for executing the contract
 */
uint64_t mxd_calculate_gas_from_bytecode(const uint8_t *code, size_t code_size);

/**
 * Get gas cost for a specific WASM opcode
 *
 * @param opcode WASM opcode byte
 * @return Gas cost for the instruction
 */
uint64_t mxd_get_opcode_gas_cost(uint8_t opcode);

#ifdef __cplusplus
}
#endif

#endif // MXD_GAS_METERING_H
