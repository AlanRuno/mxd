#include "../include/mxd_gas_metering.h"
#include "../include/mxd_logging.h"
#include <string.h>

// Gas costs for different WASM instruction categories
// Based on computational complexity and resource usage
#define GAS_COST_BASE           1    // Basic operations (local.get, drop, etc.)
#define GAS_COST_ARITHMETIC     2    // Arithmetic operations (add, sub, mul, etc.)
#define GAS_COST_COMPARISON     2    // Comparison operations (eq, ne, lt, etc.)
#define GAS_COST_BITWISE        2    // Bitwise operations (and, or, xor, etc.)
#define GAS_COST_SHIFT          2    // Shift operations (shl, shr, etc.)
#define GAS_COST_DIVISION       10   // Division operations (div, rem)
#define GAS_COST_MEMORY_LOAD    3    // Memory load operations
#define GAS_COST_MEMORY_STORE   3    // Memory store operations
#define GAS_COST_CONTROL_FLOW   5    // Control flow (br, br_if, br_table)
#define GAS_COST_CALL           10   // Function calls
#define GAS_COST_CALL_INDIRECT  15   // Indirect function calls
#define GAS_COST_CONVERSION     3    // Type conversion operations
#define GAS_COST_MEMORY_SIZE    2    // Memory size query
#define GAS_COST_MEMORY_GROW    1000 // Memory grow (expensive operation)

// WASM opcode categories for gas calculation
typedef enum {
    WASM_OP_CONTROL = 0x00,
    WASM_OP_PARAMETRIC = 0x1A,
    WASM_OP_VARIABLE = 0x20,
    WASM_OP_MEMORY = 0x28,
    WASM_OP_NUMERIC_I32 = 0x41,
    WASM_OP_NUMERIC_I64 = 0x42,
    WASM_OP_NUMERIC_F32 = 0x43,
    WASM_OP_NUMERIC_F64 = 0x44,
} wasm_opcode_category_t;

// Get gas cost for a specific WASM opcode (now public for runtime use)
uint64_t mxd_get_opcode_gas_cost(uint8_t opcode) {
    // Control flow instructions (0x00-0x11)
    if (opcode >= 0x00 && opcode <= 0x11) {
        if (opcode == 0x10) return GAS_COST_CALL;           // call
        if (opcode == 0x11) return GAS_COST_CALL_INDIRECT;  // call_indirect
        return GAS_COST_CONTROL_FLOW;                       // block, loop, if, br, etc.
    }
    
    // Parametric instructions (0x1A-0x1B)
    if (opcode >= 0x1A && opcode <= 0x1B) {
        return GAS_COST_BASE;  // drop, select
    }
    
    // Variable instructions (0x20-0x24)
    if (opcode >= 0x20 && opcode <= 0x24) {
        return GAS_COST_BASE;  // local.get, local.set, global.get, global.set
    }
    
    // Memory instructions (0x28-0x40)
    if (opcode >= 0x28 && opcode <= 0x3E) {
        return GAS_COST_MEMORY_LOAD;  // i32.load, i64.load, f32.load, f64.load, etc.
    }
    if (opcode >= 0x36 && opcode <= 0x3E) {
        return GAS_COST_MEMORY_STORE;  // i32.store, i64.store, f32.store, f64.store, etc.
    }
    if (opcode == 0x3F) return GAS_COST_MEMORY_SIZE;  // memory.size
    if (opcode == 0x40) return GAS_COST_MEMORY_GROW;  // memory.grow
    
    // Numeric instructions (0x41-0xC4)
    if (opcode >= 0x41 && opcode <= 0xC4) {
        // Constants
        if (opcode >= 0x41 && opcode <= 0x44) {
            return GAS_COST_BASE;  // i32.const, i64.const, f32.const, f64.const
        }
        
        // Comparison operations
        if ((opcode >= 0x45 && opcode <= 0x50) ||  // i32 comparisons
            (opcode >= 0x51 && opcode <= 0x5A) ||  // i64 comparisons
            (opcode >= 0x5B && opcode <= 0x60) ||  // f32 comparisons
            (opcode >= 0x61 && opcode <= 0x66)) {  // f64 comparisons
            return GAS_COST_COMPARISON;
        }
        
        // Arithmetic operations
        if ((opcode >= 0x67 && opcode <= 0x78) ||  // i32 arithmetic
            (opcode >= 0x79 && opcode <= 0x8A) ||  // i64 arithmetic
            (opcode >= 0x8B && opcode <= 0x98) ||  // f32 arithmetic
            (opcode >= 0x99 && opcode <= 0xA6)) {  // f64 arithmetic
            // Division and remainder are more expensive
            if (opcode == 0x6D || opcode == 0x6E || opcode == 0x6F ||  // i32 div/rem
                opcode == 0x7F || opcode == 0x80 || opcode == 0x81 ||  // i64 div/rem
                opcode == 0x95 || opcode == 0xA3) {                    // f32/f64 div
                return GAS_COST_DIVISION;
            }
            return GAS_COST_ARITHMETIC;
        }
        
        // Bitwise operations
        if ((opcode >= 0x71 && opcode <= 0x78) ||  // i32 bitwise
            (opcode >= 0x83 && opcode <= 0x8A)) {  // i64 bitwise
            return GAS_COST_BITWISE;
        }
        
        // Conversion operations
        if (opcode >= 0xA7 && opcode <= 0xC4) {
            return GAS_COST_CONVERSION;
        }
    }
    
    // Default cost for unknown opcodes
    return GAS_COST_BASE;
}

// Parse LEB128 unsigned integer and advance pointer
static uint64_t parse_leb128_u(const uint8_t **ptr, const uint8_t *end) {
    uint64_t result = 0;
    int shift = 0;
    
    while (*ptr < end) {
        uint8_t byte = **ptr;
        (*ptr)++;
        
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        
        if ((byte & 0x80) == 0) {
            break;
        }
        
        shift += 7;
        if (shift >= 64) {
            // Overflow protection
            break;
        }
    }
    
    return result;
}

// Parse LEB128 signed integer and advance pointer
static int64_t parse_leb128_s(const uint8_t **ptr, const uint8_t *end) {
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;  // Initialize to avoid uninitialized variable warning
    
    while (*ptr < end) {
        byte = **ptr;
        (*ptr)++;
        
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
        
        if ((byte & 0x80) == 0) {
            break;
        }
        
        if (shift >= 64) {
            // Overflow protection
            break;
        }
    }
    
    // Sign extend if needed
    if (shift < 64 && (byte & 0x40)) {
        result |= -(1ULL << shift);
    }
    
    return result;
}

// Calculate gas cost by analyzing WASM bytecode
uint64_t mxd_calculate_gas_from_bytecode(const uint8_t *code, size_t code_size) {
    if (!code || code_size == 0) {
        return 0;
    }
    
    uint64_t total_gas = 0;
    const uint8_t *ptr = code;
    const uint8_t *end = code + code_size;
    
    // WASM binary format: magic number (4 bytes) + version (4 bytes)
    if (code_size < 8) {
        MXD_LOG_WARN("gas", "WASM bytecode too small: %zu bytes", code_size);
        return code_size * 10;  // Fallback to simple calculation
    }
    
    // Verify magic number (0x00 0x61 0x73 0x6D = "\0asm")
    if (ptr[0] != 0x00 || ptr[1] != 0x61 || ptr[2] != 0x73 || ptr[3] != 0x6D) {
        MXD_LOG_WARN("gas", "Invalid WASM magic number");
        return code_size * 10;  // Fallback to simple calculation
    }
    
    ptr += 8;  // Skip magic + version
    
    // Parse WASM sections
    while (ptr < end) {
        if (ptr + 1 > end) break;
        
        uint8_t section_id = *ptr++;
        
        if (ptr >= end) break;
        uint64_t section_size = parse_leb128_u(&ptr, end);
        
        const uint8_t *section_end = ptr + section_size;
        if (section_end > end) {
            section_end = end;
        }
        
        // Section 10 is the Code section containing function bodies
        if (section_id == 10) {
            // Parse function count
            if (ptr >= section_end) break;
            uint64_t function_count = parse_leb128_u(&ptr, section_end);
            
            // Parse each function body
            for (uint64_t i = 0; i < function_count && ptr < section_end; i++) {
                // Parse function body size
                uint64_t body_size = parse_leb128_u(&ptr, section_end);
                const uint8_t *body_end = ptr + body_size;
                if (body_end > section_end) {
                    body_end = section_end;
                }
                
                // Parse local declarations
                uint64_t local_count = parse_leb128_u(&ptr, body_end);
                for (uint64_t j = 0; j < local_count && ptr < body_end; j++) {
                    parse_leb128_u(&ptr, body_end);  // count
                    if (ptr < body_end) ptr++;       // type
                }
                
                // Parse instructions in function body
                while (ptr < body_end) {
                    uint8_t opcode = *ptr++;
                    total_gas += mxd_get_opcode_gas_cost(opcode);
                    
                    // Skip immediate operands based on opcode
                    if (opcode == 0x0C || opcode == 0x0D) {  // br, br_if
                        parse_leb128_u(&ptr, body_end);
                    } else if (opcode == 0x0E) {  // br_table
                        uint64_t target_count = parse_leb128_u(&ptr, body_end);
                        for (uint64_t k = 0; k <= target_count && ptr < body_end; k++) {
                            parse_leb128_u(&ptr, body_end);
                        }
                    } else if (opcode == 0x10 || opcode == 0x11) {  // call, call_indirect
                        parse_leb128_u(&ptr, body_end);
                        if (opcode == 0x11 && ptr < body_end) {
                            ptr++;  // table index
                        }
                    } else if (opcode >= 0x20 && opcode <= 0x24) {  // variable access
                        parse_leb128_u(&ptr, body_end);
                    } else if (opcode >= 0x28 && opcode <= 0x40) {  // memory operations
                        parse_leb128_u(&ptr, body_end);  // align
                        parse_leb128_u(&ptr, body_end);  // offset
                    } else if (opcode == 0x41) {  // i32.const
                        parse_leb128_s(&ptr, body_end);
                    } else if (opcode == 0x42) {  // i64.const
                        parse_leb128_s(&ptr, body_end);
                    } else if (opcode == 0x43) {  // f32.const
                        ptr += 4;
                    } else if (opcode == 0x44) {  // f64.const
                        ptr += 8;
                    }
                    
                    // Safety check
                    if (ptr > body_end) {
                        ptr = body_end;
                        break;
                    }
                }
            }
        }
        
        ptr = section_end;
    }
    
    // Add base gas cost for deployment
    total_gas += code_size;
    
    MXD_LOG_DEBUG("gas", "Calculated gas from bytecode: %lu (code size: %zu bytes)", 
                  total_gas, code_size);
    
    return total_gas;
}
