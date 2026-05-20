#include "../../include/mxd_validator_management.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_address.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_endian.h"
#include "../../include/mxd_p2p.h"
#include "../../include/mxd_domain_tags.h"
#include <string.h>
#include <stdlib.h>

static mxd_validator_request_pool_t g_request_pool = {0};
static mxd_validator_liveness_t *g_liveness_tracker = NULL;
static size_t g_liveness_count = 0;
static size_t g_liveness_capacity = 0;
static pthread_mutex_t g_liveness_mutex = PTHREAD_MUTEX_INITIALIZER;

int mxd_init_validator_request_pool(void) {
    g_request_pool.join_capacity = 10;
    g_request_pool.join_requests = calloc(10, sizeof(mxd_validator_join_request_t));
    if (!g_request_pool.join_requests) {
        return -1;
    }
    g_request_pool.join_count = 0;

    g_request_pool.exit_capacity = 10;
    g_request_pool.exit_requests = calloc(10, sizeof(mxd_validator_exit_request_t));
    if (!g_request_pool.exit_requests) {
        free(g_request_pool.join_requests);
        return -1;
    }
    g_request_pool.exit_count = 0;

    pthread_mutex_init(&g_request_pool.mutex, NULL);
    return 0;
}

int mxd_submit_validator_join_request(const uint8_t *node_address,
                                      const uint8_t *public_key,
                                      uint16_t public_key_length,
                                      uint8_t algo_id,
                                      const uint8_t *private_key) {
    if (!node_address || !public_key || !private_key) {
        return -1;
    }

    // Validate algorithm ID (SECURITY: Issue #5)
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_ERROR("validator", "Invalid algorithm ID: %u", algo_id);
        return -1;
    }

    // Validate public key length matches algorithm
    size_t expected_key_len = mxd_sig_pubkey_len(algo_id);
    if (public_key_length != expected_key_len) {
        MXD_LOG_ERROR("validator", "Public key length %u doesn't match algorithm %u (expected %zu)",
                      public_key_length, algo_id, expected_key_len);
        return -1;
    }

    // Validate public key length doesn't exceed buffer (SECURITY: Issue #2)
    if (public_key_length > 2592) {
        MXD_LOG_ERROR("validator", "Public key length %u exceeds maximum buffer size 2592",
                      public_key_length);
        return -1;
    }

    pthread_mutex_lock(&g_request_pool.mutex);

    // Check for duplicates (v6: addr32)
    for (size_t i = 0; i < g_request_pool.join_count; i++) {
        if (memcmp(g_request_pool.join_requests[i].node_address, node_address, 32) == 0) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            return 0; // Already submitted
        }
    }

    // Expand array if needed
    if (g_request_pool.join_count >= g_request_pool.join_capacity) {
        size_t new_cap = g_request_pool.join_capacity * 2;

        // Check for integer overflow (SECURITY: Issue #4)
        if (new_cap > SIZE_MAX / sizeof(mxd_validator_join_request_t)) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            MXD_LOG_ERROR("validator", "Request pool size would cause integer overflow");
            return -1;
        }

        // Check for maximum pool size (SECURITY: Issue #7 - DoS prevention)
        #define MXD_MAX_REQUEST_POOL_SIZE 1000
        if (new_cap > MXD_MAX_REQUEST_POOL_SIZE) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            MXD_LOG_WARN("validator", "Request pool full (%zu requests), rejecting new request",
                         g_request_pool.join_count);
            return -1;
        }

        mxd_validator_join_request_t *new_requests = realloc(g_request_pool.join_requests,
                                               new_cap * sizeof(mxd_validator_join_request_t));
        if (!new_requests) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            return -1;
        }
        g_request_pool.join_requests = new_requests;
        g_request_pool.join_capacity = new_cap;
    }

    // Create request (v6: addr32)
    mxd_validator_join_request_t *req = &g_request_pool.join_requests[g_request_pool.join_count];
    memcpy(req->node_address, node_address, 32);
    req->algo_id = algo_id;
    memcpy(req->public_key, public_key, public_key_length);
    req->public_key_length = public_key_length;
    req->stake_amount = mxd_get_balance(node_address);
    req->timestamp = mxd_now_ms();

    // v7 cascade (L6-4): signing payload now prefixes MXD-VAL-V1 (11) and a
    // 1-byte op_type (0x00 = JOIN) to the addr32(32) || timestamp_be(8)
    // payload. op_type explicitly defends against cross-replay between join
    // and exit signatures.
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x00; /* op_type = JOIN */
    memcpy(sign_data + off, node_address, 32); off += 32;
    uint64_t ts_be = mxd_htonll(req->timestamp);
    memcpy(sign_data + off, &ts_be, 8); off += 8;

    size_t sig_len = sizeof(req->signature);
    if (mxd_sig_sign(algo_id, req->signature, &sig_len, sign_data, sizeof(sign_data),
                     private_key) != 0) {
        pthread_mutex_unlock(&g_request_pool.mutex);
        return -1;
    }
    req->signature_length = sig_len;

    g_request_pool.join_count++;
    pthread_mutex_unlock(&g_request_pool.mutex);

    MXD_LOG_INFO("validator", "Submitted join request for validator %02x%02x...%02x%02x (stake: %llu)",
                 node_address[0], node_address[1], node_address[30], node_address[31],
                 (unsigned long long)req->stake_amount);

    // TODO: Broadcast to network via mxd_broadcast_validator_join_request(req);

    return 0;
}

int mxd_submit_validator_exit_request(const uint8_t *node_address,
                                      const uint8_t *private_key,
                                      uint8_t algo_id) {
    if (!node_address || !private_key) {
        return -1;
    }

    pthread_mutex_lock(&g_request_pool.mutex);

    // Check for duplicates (v6: addr32)
    for (size_t i = 0; i < g_request_pool.exit_count; i++) {
        if (memcmp(g_request_pool.exit_requests[i].node_address, node_address, 32) == 0) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            return 0; // Already submitted
        }
    }

    // Expand array if needed
    if (g_request_pool.exit_count >= g_request_pool.exit_capacity) {
        size_t new_cap = g_request_pool.exit_capacity * 2;

        // SECURITY: Issue #13 - Check for multiplication overflow
        if (new_cap > SIZE_MAX / sizeof(mxd_validator_exit_request_t)) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            MXD_LOG_ERROR("validator", "Exit request pool allocation would overflow");
            return -1;
        }

        // SECURITY: Issue #13 - Enforce maximum capacity (same as join requests)
        if (new_cap > MXD_MAX_REQUEST_POOL_SIZE) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            MXD_LOG_WARN("validator", "Exit request pool full (%zu requests)",
                         g_request_pool.exit_count);
            return -1;
        }

        mxd_validator_exit_request_t *new_requests = realloc(g_request_pool.exit_requests,
                                               new_cap * sizeof(mxd_validator_exit_request_t));
        if (!new_requests) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            return -1;
        }
        g_request_pool.exit_requests = new_requests;
        g_request_pool.exit_capacity = new_cap;
    }

    // Create exit request (v6: addr32)
    mxd_validator_exit_request_t *req = &g_request_pool.exit_requests[g_request_pool.exit_count];
    memcpy(req->node_address, node_address, 32);
    req->timestamp = mxd_now_ms();
    req->exit_height = 0; // Will be set by proposer

    // v7 cascade (L6-4): signing payload now prefixes MXD-VAL-V1 (11) and a
    // 1-byte op_type (0x01 = EXIT) to the addr32(32) || timestamp_be(8)
    // payload. op_type explicitly defends against cross-replay between join
    // and exit signatures.
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x01; /* op_type = EXIT */
    memcpy(sign_data + off, node_address, 32); off += 32;
    uint64_t ts_be = mxd_htonll(req->timestamp);
    memcpy(sign_data + off, &ts_be, 8); off += 8;

    size_t sig_len = sizeof(req->signature);
    if (mxd_sig_sign(algo_id, req->signature, &sig_len, sign_data, sizeof(sign_data),
                     private_key) != 0) {
        pthread_mutex_unlock(&g_request_pool.mutex);
        return -1;
    }
    req->signature_length = sig_len;

    g_request_pool.exit_count++;
    pthread_mutex_unlock(&g_request_pool.mutex);

    MXD_LOG_INFO("validator", "Submitted exit request for validator %02x%02x...%02x%02x",
                 node_address[0], node_address[1], node_address[30], node_address[31]);

    return 0;
}

int mxd_validate_join_request(const mxd_validator_join_request_t *request,
                              mxd_amount_t total_supply) {
    if (!request) {
        return -1;
    }

    // 1. Validate timestamp to prevent replay attacks (SECURITY: Issue #6)
    uint64_t current_time = mxd_now_ms();
    uint64_t max_future_ms = 60000;  // Max 1 minute in future
    uint64_t max_age_ms = 300000;    // Max 5 minutes old

    if (request->timestamp > current_time + max_future_ms) {
        MXD_LOG_WARN("validator", "Join request rejected: timestamp %llu ms in future",
                     request->timestamp - current_time);
        return -1;
    }

    // SECURITY: Issue #11 - Check timestamp age only if in the past (prevent underflow)
    if (request->timestamp <= current_time) {
        if (current_time - request->timestamp > max_age_ms) {
            MXD_LOG_WARN("validator", "Join request rejected: timestamp too old (%llu ms)",
                         current_time - request->timestamp);
            return -1;
        }
    }
    // If timestamp > current_time, it's in the future but within tolerance (valid)

    // 2. Verify stake meets 0.10% requirement
    if (request->stake_amount < total_supply / 1000) {
        MXD_LOG_WARN("validator", "Join request rejected: insufficient stake (%llu < %llu)",
                     (unsigned long long)request->stake_amount,
                     (unsigned long long)(total_supply / 1000));
        return -1;
    }

    // 3. Verify balance matches declared stake
    mxd_amount_t actual_balance = mxd_get_balance(request->node_address);
    if (actual_balance < request->stake_amount) {
        MXD_LOG_WARN("validator", "Join request rejected: declared stake exceeds actual balance");
        return -1;
    }

    // 4. Verify signature — v7 (L6-4): MXD-VAL-V1 || op_type(JOIN=0x00) || addr32 || ts_be
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 8];
    size_t voff = 0;
    memcpy(sign_data + voff, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); voff += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[voff++] = 0x00; /* op_type = JOIN */
    memcpy(sign_data + voff, request->node_address, 32); voff += 32;
    uint64_t ts_be = mxd_htonll(request->timestamp);
    memcpy(sign_data + voff, &ts_be, 8); voff += 8;

    if (mxd_sig_verify(request->algo_id, request->signature, request->signature_length,
                       sign_data, sizeof(sign_data), request->public_key) != 0) {
        MXD_LOG_WARN("validator", "Join request rejected: invalid signature");
        return -1;
    }

    // 5. Verify address matches public key (v6: addr32 — full 32-byte compare)
    uint8_t derived_addr[MXD_ADDR32_LEN];
    mxd_derive_address(request->algo_id, request->public_key, request->public_key_length,
                       derived_addr);
    if (memcmp(derived_addr, request->node_address, 32) != 0) {
        MXD_LOG_WARN("validator", "Join request rejected: address/pubkey mismatch");
        return -1;
    }

    return 0;
}

// SECURITY: Issue #3 - Return deep copy to prevent TOCTOU vulnerability
// Caller must free the returned array with free()
int mxd_get_pending_join_requests(mxd_validator_join_request_t **requests, size_t *count) {
    if (!requests || !count) {
        return -1;
    }

    pthread_mutex_lock(&g_request_pool.mutex);

    *count = g_request_pool.join_count;

    // If no requests, return NULL
    if (*count == 0) {
        *requests = NULL;
        pthread_mutex_unlock(&g_request_pool.mutex);
        return 0;
    }

    // Allocate memory for copy
    *requests = malloc(*count * sizeof(mxd_validator_join_request_t));
    if (!*requests) {
        pthread_mutex_unlock(&g_request_pool.mutex);
        MXD_LOG_ERROR("validator", "Failed to allocate memory for request copy");
        return -1;
    }

    // Deep copy all requests
    memcpy(*requests, g_request_pool.join_requests,
           *count * sizeof(mxd_validator_join_request_t));

    pthread_mutex_unlock(&g_request_pool.mutex);
    return 0;
}

int mxd_clear_processed_requests(const mxd_block_t *block) {
    if (!block) {
        return -1;
    }

    pthread_mutex_lock(&g_request_pool.mutex);

    // Remove join requests that were processed (added to block membership)
    size_t new_count = 0;
    for (size_t i = 0; i < g_request_pool.join_count; i++) {
        int found = 0;
        if (block->rapid_membership_entries) {
            for (uint32_t j = 0; j < block->rapid_membership_count; j++) {
                if (memcmp(g_request_pool.join_requests[i].node_address,
                          block->rapid_membership_entries[j].node_address, 32) == 0) {   // v6: addr32
                    found = 1;
                    break;
                }
            }
        }

        if (!found) {
            // Keep this request
            if (new_count != i) {
                memcpy(&g_request_pool.join_requests[new_count],
                       &g_request_pool.join_requests[i],
                       sizeof(mxd_validator_join_request_t));
            }
            new_count++;
        }
    }
    g_request_pool.join_count = new_count;

    pthread_mutex_unlock(&g_request_pool.mutex);
    return 0;
}

// Liveness tracking implementation
int mxd_track_validator_liveness(mxd_rapid_table_t *table, uint32_t height,
                                 const uint8_t *actual_proposer) {
    if (!table || !actual_proposer || table->count == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_liveness_mutex);

    // Determine expected proposer for this height
    uint32_t expected_index = height % table->count;
    uint8_t *expected_addr = table->nodes[expected_index]->node_address;

    // Find or create liveness entry for expected proposer (v6: addr32)
    mxd_validator_liveness_t *entry = NULL;
    for (size_t i = 0; i < g_liveness_count; i++) {
        if (memcmp(g_liveness_tracker[i].node_address, expected_addr, 32) == 0) {
            entry = &g_liveness_tracker[i];
            break;
        }
    }

    if (!entry) {
        // Create new entry
        if (g_liveness_count >= g_liveness_capacity) {
            size_t new_cap = g_liveness_capacity == 0 ? 10 : g_liveness_capacity * 2;

            // SECURITY: Issue #12 - Check for doubling overflow
            if (g_liveness_capacity > 0 && new_cap / 2 != g_liveness_capacity) {
                pthread_mutex_unlock(&g_liveness_mutex);
                MXD_LOG_ERROR("validator", "Liveness capacity doubling would overflow");
                return -1;
            }

            // SECURITY: Issue #12 - Check for multiplication overflow
            if (new_cap > SIZE_MAX / sizeof(mxd_validator_liveness_t)) {
                pthread_mutex_unlock(&g_liveness_mutex);
                MXD_LOG_ERROR("validator", "Liveness allocation size would overflow");
                return -1;
            }

            // SECURITY: Issue #12 - Enforce maximum capacity (DoS prevention)
            #define MXD_MAX_LIVENESS_TRACKER_SIZE 10000
            if (new_cap > MXD_MAX_LIVENESS_TRACKER_SIZE) {
                pthread_mutex_unlock(&g_liveness_mutex);
                MXD_LOG_ERROR("validator", "Liveness tracker at maximum capacity %d",
                             MXD_MAX_LIVENESS_TRACKER_SIZE);
                return -1;
            }

            mxd_validator_liveness_t *new_tracker = realloc(g_liveness_tracker,
                                        new_cap * sizeof(mxd_validator_liveness_t));
            if (!new_tracker) {
                pthread_mutex_unlock(&g_liveness_mutex);
                return -1;
            }
            g_liveness_tracker = new_tracker;
            g_liveness_capacity = new_cap;
        }
        entry = &g_liveness_tracker[g_liveness_count++];
        memcpy(entry->node_address, expected_addr, 32);   // v6: addr32
        entry->last_active_height = 0;
        entry->consecutive_misses = 0;
        entry->marked_for_removal = 0;
    }

    // Check if expected proposer actually proposed (v6: addr32)
    if (memcmp(expected_addr, actual_proposer, 32) == 0) {
        // Proposer was active
        entry->last_active_height = height;
        entry->consecutive_misses = 0;
    } else {
        // Proposer missed their slot
        entry->consecutive_misses++;

        if (entry->consecutive_misses >= MXD_MAX_CONSECUTIVE_MISSES) {
            entry->marked_for_removal = 1;
            MXD_LOG_WARN("validator", "Validator %02x%02x...%02x%02x marked for removal (missed %u consecutive proposals)",
                        expected_addr[0], expected_addr[1], expected_addr[30], expected_addr[31],
                        entry->consecutive_misses);
        }
    }

    pthread_mutex_unlock(&g_liveness_mutex);
    return 0;
}

int mxd_get_validators_to_remove(mxd_rapid_table_t *table, uint32_t current_height,
                                 uint8_t **addresses, size_t *count) {
    if (!addresses || !count) {
        return -1;
    }

    pthread_mutex_lock(&g_liveness_mutex);

    // Count marked validators
    size_t marked_count = 0;
    for (size_t i = 0; i < g_liveness_count; i++) {
        if (g_liveness_tracker[i].marked_for_removal) {
            marked_count++;
        }
    }

    if (marked_count == 0) {
        *addresses = NULL;
        *count = 0;
        pthread_mutex_unlock(&g_liveness_mutex);
        return 0;
    }

    // Collect addresses (v6: 32 bytes per address)
    uint8_t *result = malloc(marked_count * 32);
    if (!result) {
        pthread_mutex_unlock(&g_liveness_mutex);
        return -1;
    }

    size_t result_idx = 0;
    for (size_t i = 0; i < g_liveness_count; i++) {
        if (g_liveness_tracker[i].marked_for_removal) {
            memcpy(result + (result_idx * 32), g_liveness_tracker[i].node_address, 32);
            result_idx++;
        }
    }

    *addresses = result;
    *count = marked_count;

    pthread_mutex_unlock(&g_liveness_mutex);
    return 0;
}
