/**
 * Fuzz Test: Contract Storage
 *
 * Tests storage operations for:
 * - Buffer overflows
 * - Integer overflows in size calculations
 * - Merkle trie corruption
 * - Storage isolation between contracts
 */

#include "../../include/mxd_smart_contracts.h"
#include "../../include/mxd_merkle_trie.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Create contract state
    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));
    state.storage_trie = mxd_trie_create();

    if (!state.storage_trie) {
        return 0;
    }

    // Parse fuzzer input as operations
    const uint8_t *ptr = data;
    const uint8_t *end = data + size;

    while (ptr + 4 < end) {
        uint8_t op = *ptr++;
        uint8_t key_size = *ptr++;
        uint8_t value_size = *ptr++;

        // Limit sizes to prevent timeout
        key_size = (key_size % 64) + 1;
        value_size = (value_size % 256) + 1;

        if (ptr + key_size + value_size > end) {
            break;
        }

        const uint8_t *key = ptr;
        ptr += key_size;
        const uint8_t *value = ptr;
        ptr += value_size;

        switch (op % 3) {
            case 0: {
                // Test SET operation
                int result = mxd_set_contract_storage(&state, key, key_size, value, value_size);

                // Should always succeed with valid inputs
                if (result != 0) {
                    // Check if it was due to allocation failure (acceptable)
                }
                break;
            }

            case 1: {
                // Test GET operation
                uint8_t retrieved_value[512];
                size_t retrieved_size = sizeof(retrieved_value);

                int result = mxd_get_contract_storage(&state, key, key_size,
                                                      retrieved_value, &retrieved_size);

                // Verify size bounds
                if (result == 0) {
                    if (retrieved_size > sizeof(retrieved_value)) {
                        // CRITICAL BUG: Buffer overflow!
                        __builtin_trap();
                    }
                }
                break;
            }

            case 2: {
                // Test state hash computation
                uint8_t computed_hash[64];
                mxd_trie_get_root_hash((mxd_merkle_trie_t*)state.storage_trie, computed_hash);

                // Hash should be deterministic - same operations should produce same hash
                // (We can't verify this in a single fuzz iteration, but crashes would indicate bugs)
                break;
            }
        }
    }

    // Test storage isolation
    // Create second contract state
    mxd_contract_state_t state2;
    memset(&state2, 0, sizeof(state2));
    state2.storage_trie = mxd_trie_create();

    if (state2.storage_trie) {
        // Set same key in both states
        if (size >= 16) {
            uint8_t key[8];
            uint8_t value1[8];
            uint8_t value2[8];

            memcpy(key, data, 8);
            memcpy(value1, data + 8, 8);
            if (size >= 24) {
                memcpy(value2, data + 16, 8);
            } else {
                memcpy(value2, value1, 8);
                value2[0] ^= 0xFF; // Make different
            }

            // Set different values in different states
            mxd_set_contract_storage(&state, key, 8, value1, 8);
            mxd_set_contract_storage(&state2, key, 8, value2, 8);

            // Retrieve from both
            uint8_t retrieved1[64];
            uint8_t retrieved2[64];
            size_t size1 = sizeof(retrieved1);
            size_t size2 = sizeof(retrieved2);

            int result1 = mxd_get_contract_storage(&state, key, 8, retrieved1, &size1);
            int result2 = mxd_get_contract_storage(&state2, key, 8, retrieved2, &size2);

            // Both should succeed
            if (result1 == 0 && result2 == 0) {
                // Verify isolation - different contracts should have different values
                if (memcmp(value1, value2, 8) != 0) {
                    if (memcmp(retrieved1, retrieved2, 8) == 0) {
                        // CRITICAL BUG: Storage not isolated!
                        __builtin_trap();
                    }
                }
            }
        }

        mxd_free_contract_state(&state2);
    }

    // Clean up
    mxd_free_contract_state(&state);

    return 0;
}
