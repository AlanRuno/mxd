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

/* v8+: EVICT request pool, parallel to g_request_pool.join_requests.
 * Definition lifted to the top of the file so mxd_clear_processed_requests
 * (which clears EVICT entries alongside JOINs after block-apply) can see it.
 * The init helper `evict_pool_ensure_init` and the management functions
 * stay in their original place lower in the file. */
static struct {
    mxd_validator_evict_request_t *requests;
    size_t count;
    size_t capacity;
    pthread_mutex_t mutex;
} g_evict_pool = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };

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
        /* mxd_init_validator_request_pool() has no caller, so on a fresh
         * process the pool starts at {NULL, 0, 0}. The "* 2" grow path then
         * produces a 0-byte realloc — the subsequent memcpy into
         * &join_requests[0] writes 32 bytes into a 0-byte allocation and
         * corrupts the heap, surfacing as a SIGSEGV inside the next
         * malloc/free in mxd_broadcast_validator_join_request. Seed the
         * capacity here so the first JOIN ever submitted on a node works. */
        size_t new_cap = g_request_pool.join_capacity == 0
                             ? 10
                             : g_request_pool.join_capacity * 2;

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

    /* Broadcast to all connected peers via epidemic gossip. The serializer
     * + receive handler in this file (added with the broadcast wire-up,
     * mxd_p2p.h: MXD_MSG_VALIDATOR_JOIN_REQUEST) handles dedup and
     * re-broadcast on the receiver side. */
    if (mxd_broadcast_validator_join_request(req) != 0) {
        /* Don't fail the local submit if broadcast fails — the request is
         * still in our pool and a proposer running on this same node will
         * include it. Other peers just won't see it until they connect or
         * we retry. */
        MXD_LOG_WARN("validator", "JOIN broadcast failed (request still in local pool)");
    }
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
        size_t new_cap = g_request_pool.exit_capacity == 0
                             ? 10
                             : g_request_pool.exit_capacity * 2;

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

    /* v8+: also clear EVICT pool entries whose target appears in this
     * block's rapid_eviction_entries. Without this, the per-(evictor,target)
     * dedup in mxd_submit_validator_evict_with_pubkey keeps the stale entry
     * forever, and the FIRST EVICT cycle for a given target succeeds but
     * the SECOND (after the target rejoins and gets drained again) is
     * silently no-op'd. Discovered during the 2026-05-21 smoke battery —
     * test 3 (re-EVICT) didn't fire because the founders' pools still held
     * stale entries from the original h=63 EVICT cycle. */
    if (block->version >= 8 && block->rapid_eviction_count > 0 &&
        block->rapid_eviction_entries) {
        pthread_mutex_lock(&g_evict_pool.mutex);
        size_t new_evict_count = 0;
        for (size_t i = 0; i < g_evict_pool.count; i++) {
            int found = 0;
            for (uint32_t j = 0; j < block->rapid_eviction_count; j++) {
                if (memcmp(g_evict_pool.requests[i].target_addr,
                           block->rapid_eviction_entries[j].target_addr, 32) == 0) {
                    /* Match by target only — the proposer block has at most
                     * one entry per target (dedup-by-target rule §4.5.2), but
                     * the pool may have N entries (one per evictor signing
                     * the same target). All N pool entries get cleared so a
                     * future rejoin+redrain cycle can populate fresh
                     * (evictor,target) pairs without being blocked by the
                     * old fingerprints. */
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (new_evict_count != i) {
                    memcpy(&g_evict_pool.requests[new_evict_count],
                           &g_evict_pool.requests[i],
                           sizeof(mxd_validator_evict_request_t));
                }
                new_evict_count++;
            }
        }
        g_evict_pool.count = new_evict_count;
        pthread_mutex_unlock(&g_evict_pool.mutex);
    }

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

/* ======================================================================
 * Validator JOIN / EVICT — P2P broadcast, receive, serialization, evict pool.
 *
 * Added to wire up the previously-unimplemented broadcast (see TODO removed
 * from line ~145 above) and to introduce the EVICT mechanism (op_type 0x02
 * in the MXD-VAL-V1 domain). See include/mxd_validator_management.h for the
 * wire format documentation.
 * ====================================================================== */

#include "../../include/mxd_blockchain_db.h"
#include "../../include/mxd_blockchain_sync.h"

/* ---------- gossip dedup seen-set (bounded LRU) ---------- */

#define MXD_VAL_SEEN_CAPACITY 256
static uint64_t g_val_seen[MXD_VAL_SEEN_CAPACITY] = {0};
static size_t g_val_seen_idx = 0;
static pthread_mutex_t g_val_seen_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t val_seen_fingerprint(uint8_t msg_type, const uint8_t addr[32], uint64_t timestamp) {
    uint64_t fp = ((uint64_t)msg_type) << 56;
    for (size_t i = 0; i < 32; i++) {
        fp ^= ((uint64_t)addr[i]) << ((i * 7) % 56);
    }
    fp ^= timestamp;
    return fp;
}

/* Returns 1 if this fingerprint was already in the seen-set (caller drops),
 * 0 if it was freshly inserted (caller proceeds). */
static int val_seen_check_and_insert(uint8_t msg_type, const uint8_t addr[32], uint64_t timestamp) {
    uint64_t fp = val_seen_fingerprint(msg_type, addr, timestamp);
    pthread_mutex_lock(&g_val_seen_mutex);
    for (size_t i = 0; i < MXD_VAL_SEEN_CAPACITY; i++) {
        if (g_val_seen[i] == fp) {
            pthread_mutex_unlock(&g_val_seen_mutex);
            return 1;
        }
    }
    g_val_seen[g_val_seen_idx] = fp;
    g_val_seen_idx = (g_val_seen_idx + 1) % MXD_VAL_SEEN_CAPACITY;
    pthread_mutex_unlock(&g_val_seen_mutex);
    return 0;
}

/* ---------- EVICT request pool helpers (storage moved to top of file) ---------- */

static int evict_pool_ensure_init(void) {
    pthread_mutex_lock(&g_evict_pool.mutex);
    if (g_evict_pool.requests == NULL) {
        g_evict_pool.capacity = 10;
        g_evict_pool.requests = calloc(g_evict_pool.capacity, sizeof(mxd_validator_evict_request_t));
        if (!g_evict_pool.requests) {
            g_evict_pool.capacity = 0;
            pthread_mutex_unlock(&g_evict_pool.mutex);
            return -1;
        }
        g_evict_pool.count = 0;
    }
    pthread_mutex_unlock(&g_evict_pool.mutex);
    return 0;
}

/* Read total_supply from the latest finalized block. Returns -1 if no
 * blocks exist yet (genesis hasn't landed).
 *
 * IMPORTANT: mxd_get_blockchain_height returns the "next-to-write" height
 * (== count of existing blocks). The latest *committed* block sits at
 * height - 1. Reading at `height` directly hits a block that doesn't exist
 * yet and returns -1 — which surfaces as "JOIN msg dropped: no total_supply
 * yet" on every receive handler invocation. The auto-join thread in main.c
 * already uses the -1 offset; mirror that here. */
static int get_latest_total_supply(mxd_amount_t *out_supply) {
    if (!out_supply) return -1;
    uint32_t height = 0;
    if (mxd_get_blockchain_height(&height) != 0) return -1;
    if (height == 0) return -1; /* genesis not yet landed */
    mxd_block_t block = {0};
    if (mxd_retrieve_block_by_height(height - 1, &block) != 0) return -1;
    *out_supply = block.total_supply;
    mxd_free_block(&block);
    return 0;
}

/* ---------- JOIN serialize / deserialize ---------- */

int mxd_serialize_join_request(const mxd_validator_join_request_t *req,
                               uint8_t **out_buf, size_t *out_len) {
    if (!req || !out_buf || !out_len) return -1;
    if (req->public_key_length > sizeof(req->public_key) ||
        req->signature_length > sizeof(req->signature)) return -1;

    size_t len = 1u + 32u + 2u + req->public_key_length + 8u + 8u + 2u + req->signature_length;
    uint8_t *buf = malloc(len);
    if (!buf) return -1;

    uint8_t *p = buf;
    *p++ = req->algo_id;
    memcpy(p, req->node_address, 32); p += 32;
    uint16_t pkl_be = htons(req->public_key_length);
    memcpy(p, &pkl_be, 2); p += 2;
    memcpy(p, req->public_key, req->public_key_length); p += req->public_key_length;
    uint64_t stake_be = mxd_htonll(req->stake_amount);
    memcpy(p, &stake_be, 8); p += 8;
    uint64_t ts_be = mxd_htonll(req->timestamp);
    memcpy(p, &ts_be, 8); p += 8;
    uint16_t sl_be = htons(req->signature_length);
    memcpy(p, &sl_be, 2); p += 2;
    memcpy(p, req->signature, req->signature_length);

    *out_buf = buf;
    *out_len = len;
    return 0;
}

int mxd_deserialize_join_request(const uint8_t *buf, size_t buf_len,
                                  mxd_validator_join_request_t *req) {
    if (!buf || !req) return -1;
    if (buf_len < 1u + 32u + 2u + 8u + 8u + 2u) return -1;

    memset(req, 0, sizeof(*req));
    const uint8_t *p = buf;
    const uint8_t *end = buf + buf_len;

    req->algo_id = *p++;
    if (end - p < 32) return -1;
    memcpy(req->node_address, p, 32); p += 32;
    if (end - p < 2) return -1;
    uint16_t pkl; memcpy(&pkl, p, 2); p += 2;
    req->public_key_length = ntohs(pkl);
    if (req->public_key_length > sizeof(req->public_key)) return -1;
    if ((size_t)(end - p) < (size_t)req->public_key_length) return -1;
    memcpy(req->public_key, p, req->public_key_length); p += req->public_key_length;
    if (end - p < 8) return -1;
    uint64_t stake; memcpy(&stake, p, 8); p += 8;
    req->stake_amount = mxd_ntohll(stake);
    if (end - p < 8) return -1;
    uint64_t ts; memcpy(&ts, p, 8); p += 8;
    req->timestamp = mxd_ntohll(ts);
    if (end - p < 2) return -1;
    uint16_t sl; memcpy(&sl, p, 2); p += 2;
    req->signature_length = ntohs(sl);
    if (req->signature_length > sizeof(req->signature)) return -1;
    if ((size_t)(end - p) < (size_t)req->signature_length) return -1;
    memcpy(req->signature, p, req->signature_length);
    return 0;
}

/* ---------- EVICT serialize / deserialize ---------- */

int mxd_serialize_evict_request(const mxd_validator_evict_request_t *req,
                                uint8_t **out_buf, size_t *out_len) {
    if (!req || !out_buf || !out_len) return -1;
    if (req->evictor_public_key_length > sizeof(req->evictor_public_key) ||
        req->signature_length > sizeof(req->signature)) return -1;

    size_t len = 32u + 32u + 1u + 2u + req->evictor_public_key_length
                + 8u + 2u + req->signature_length;
    uint8_t *buf = malloc(len);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, req->target_addr, 32); p += 32;
    memcpy(p, req->evictor_addr, 32); p += 32;
    *p++ = req->evictor_algo_id;
    uint16_t pkl_be = htons(req->evictor_public_key_length);
    memcpy(p, &pkl_be, 2); p += 2;
    memcpy(p, req->evictor_public_key, req->evictor_public_key_length); p += req->evictor_public_key_length;
    uint64_t ts_be = mxd_htonll(req->timestamp);
    memcpy(p, &ts_be, 8); p += 8;
    uint16_t sl_be = htons(req->signature_length);
    memcpy(p, &sl_be, 2); p += 2;
    memcpy(p, req->signature, req->signature_length);

    *out_buf = buf;
    *out_len = len;
    return 0;
}

int mxd_deserialize_evict_request(const uint8_t *buf, size_t buf_len,
                                   mxd_validator_evict_request_t *req) {
    if (!buf || !req) return -1;
    if (buf_len < 32u + 32u + 1u + 2u + 8u + 2u) return -1;

    memset(req, 0, sizeof(*req));
    const uint8_t *p = buf;
    const uint8_t *end = buf + buf_len;

    memcpy(req->target_addr, p, 32); p += 32;
    memcpy(req->evictor_addr, p, 32); p += 32;
    req->evictor_algo_id = *p++;
    uint16_t pkl; memcpy(&pkl, p, 2); p += 2;
    req->evictor_public_key_length = ntohs(pkl);
    if (req->evictor_public_key_length > sizeof(req->evictor_public_key)) return -1;
    if ((size_t)(end - p) < (size_t)req->evictor_public_key_length) return -1;
    memcpy(req->evictor_public_key, p, req->evictor_public_key_length);
    p += req->evictor_public_key_length;
    if (end - p < 8) return -1;
    uint64_t ts; memcpy(&ts, p, 8); p += 8;
    req->timestamp = mxd_ntohll(ts);
    if (end - p < 2) return -1;
    uint16_t sl; memcpy(&sl, p, 2); p += 2;
    req->signature_length = ntohs(sl);
    if (req->signature_length > sizeof(req->signature)) return -1;
    if ((size_t)(end - p) < (size_t)req->signature_length) return -1;
    memcpy(req->signature, p, req->signature_length);
    return 0;
}

/* ---------- Broadcast helpers ---------- */

int mxd_broadcast_validator_join_request(const mxd_validator_join_request_t *req) {
    if (!req) return -1;
    uint8_t *buf = NULL;
    size_t len = 0;
    if (mxd_serialize_join_request(req, &buf, &len) != 0) {
        MXD_LOG_ERROR("validator", "JOIN serialize failed for broadcast");
        return -1;
    }
    val_seen_check_and_insert(MXD_MSG_VALIDATOR_JOIN_REQUEST, req->node_address, req->timestamp);
    int rc = mxd_broadcast_message(MXD_MSG_VALIDATOR_JOIN_REQUEST, buf, len);
    free(buf);
    if (rc == 0) {
        MXD_LOG_INFO("validator", "Broadcasted JOIN %02x%02x...%02x%02x (%zu bytes)",
                     req->node_address[0], req->node_address[1],
                     req->node_address[30], req->node_address[31], len);
    }
    return rc;
}

int mxd_broadcast_validator_evict_request(const mxd_validator_evict_request_t *req) {
    if (!req) return -1;
    uint8_t *buf = NULL;
    size_t len = 0;
    if (mxd_serialize_evict_request(req, &buf, &len) != 0) {
        MXD_LOG_ERROR("validator", "EVICT serialize failed for broadcast");
        return -1;
    }
    val_seen_check_and_insert(MXD_MSG_VALIDATOR_EVICT_REQUEST, req->target_addr, req->timestamp);
    int rc = mxd_broadcast_message(MXD_MSG_VALIDATOR_EVICT_REQUEST, buf, len);
    free(buf);
    if (rc == 0) {
        MXD_LOG_INFO("validator", "Broadcasted EVICT target=%02x%02x...%02x%02x (%zu bytes)",
                     req->target_addr[0], req->target_addr[1],
                     req->target_addr[30], req->target_addr[31], len);
    }
    return rc;
}

/* ---------- EVICT submit / validate / pool drain ---------- */

int mxd_submit_validator_evict_request(const uint8_t *target_addr,
                                       const uint8_t *self_addr,
                                       const uint8_t *self_private_key,
                                       uint8_t self_algo_id) {
    if (!target_addr || !self_addr || !self_private_key) return -1;
    if (self_algo_id != MXD_SIGALG_ED25519 && self_algo_id != MXD_SIGALG_DILITHIUM5) return -1;
    if (memcmp(target_addr, self_addr, 32) == 0) {
        MXD_LOG_WARN("validator", "EVICT submit refused: self-eviction not allowed");
        return -1;
    }
    if (evict_pool_ensure_init() != 0) return -1;

    /* Build the request — we need the local node's pubkey too. Derive the
     * evictor pubkey from the private key via the standard sign-then-extract
     * pattern is overkill; the caller in production should pass it via a
     * surrounding API. For now we expose this helper to callers who already
     * have the pubkey loaded (node startup path), so we leave the pubkey
     * fields zero and require the auto-trigger to populate them via the
     * higher-level wrapper below. */
    /* (helper retained for callers that fill the struct directly) */
    (void)target_addr; (void)self_private_key;
    MXD_LOG_ERROR("validator", "Direct mxd_submit_validator_evict_request without pubkey is not supported; use mxd_submit_validator_evict_with_pubkey instead");
    return -1;
}

/* Full EVICT submission: builds + signs + broadcasts. */
int mxd_submit_validator_evict_with_pubkey(const uint8_t *target_addr,
                                           const uint8_t *self_addr,
                                           uint8_t self_algo_id,
                                           const uint8_t *self_public_key,
                                           uint16_t self_public_key_length,
                                           const uint8_t *self_private_key) {
    if (!target_addr || !self_addr || !self_public_key || !self_private_key) return -1;
    if (self_algo_id != MXD_SIGALG_ED25519 && self_algo_id != MXD_SIGALG_DILITHIUM5) return -1;
    /* v8 design point (6): self-EVICT is allowed as a graceful-exit path. */
    if (self_public_key_length > 2592) return -1;
    if (evict_pool_ensure_init() != 0) return -1;

    mxd_validator_evict_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.target_addr, target_addr, 32);
    memcpy(req.evictor_addr, self_addr, 32);
    req.evictor_algo_id = self_algo_id;
    memcpy(req.evictor_public_key, self_public_key, self_public_key_length);
    req.evictor_public_key_length = self_public_key_length;
    req.timestamp = mxd_now_ms();

    /* 84-byte signed payload: domain || op_type=0x02 || target || evictor || ts_be */
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x02; /* EVICT */
    memcpy(sign_data + off, target_addr, 32); off += 32;
    memcpy(sign_data + off, self_addr, 32); off += 32;
    uint64_t ts_be = mxd_htonll(req.timestamp);
    memcpy(sign_data + off, &ts_be, 8); off += 8;

    size_t sig_len = sizeof(req.signature);
    if (mxd_sig_sign(self_algo_id, req.signature, &sig_len, sign_data, sizeof(sign_data),
                     self_private_key) != 0) {
        MXD_LOG_ERROR("validator", "EVICT sign failed");
        return -1;
    }
    req.signature_length = (uint16_t)sig_len;

    /* Dedup against pool. */
    pthread_mutex_lock(&g_evict_pool.mutex);
    for (size_t i = 0; i < g_evict_pool.count; i++) {
        if (memcmp(g_evict_pool.requests[i].target_addr, target_addr, 32) == 0 &&
            memcmp(g_evict_pool.requests[i].evictor_addr, self_addr, 32) == 0) {
            pthread_mutex_unlock(&g_evict_pool.mutex);
            return 0; /* already pending */
        }
    }
    if (g_evict_pool.count >= g_evict_pool.capacity) {
        size_t nc = g_evict_pool.capacity * 2;
        if (nc > 1000) { pthread_mutex_unlock(&g_evict_pool.mutex); return -1; }
        mxd_validator_evict_request_t *nr = realloc(g_evict_pool.requests, nc * sizeof(*nr));
        if (!nr) { pthread_mutex_unlock(&g_evict_pool.mutex); return -1; }
        g_evict_pool.requests = nr;
        g_evict_pool.capacity = nc;
    }
    memcpy(&g_evict_pool.requests[g_evict_pool.count], &req, sizeof(req));
    g_evict_pool.count++;
    pthread_mutex_unlock(&g_evict_pool.mutex);

    MXD_LOG_INFO("validator", "Submitted EVICT target=%02x%02x...%02x%02x",
                 target_addr[0], target_addr[1], target_addr[30], target_addr[31]);

    return mxd_broadcast_validator_evict_request(&req);
}

int mxd_validate_evict_request(const mxd_validator_evict_request_t *request,
                               const mxd_rapid_table_t *active_set,
                               mxd_amount_t total_supply) {
    if (!request || !active_set) return -1;
    /* v8 design point (6): self-EVICT IS allowed — gives a validator a clean
     * graceful-exit path now that op_type=0x01 EXIT is deprecated. The other
     * checks (target in set, balance below threshold, grace period) still
     * apply, so an above-threshold validator can't self-EVICT either. */

    /* Timestamp window (mirror of JOIN). */
    uint64_t now = mxd_now_ms();
    if (request->timestamp > now + 60000ULL) return -1;
    if (request->timestamp <= now && (now - request->timestamp) > 300000ULL) return -1;

    /* Both evictor and target must be in the active set. */
    int evictor_in = 0, target_in = 0;
    mxd_node_stake_t *target_node = NULL;
    for (size_t i = 0; i < active_set->count; i++) {
        if (!active_set->nodes[i]) continue;
        if (memcmp(active_set->nodes[i]->node_address, request->evictor_addr, 32) == 0) evictor_in = 1;
        if (memcmp(active_set->nodes[i]->node_address, request->target_addr, 32) == 0) {
            target_in = 1;
            target_node = active_set->nodes[i];
        }
    }
    if (!evictor_in) { MXD_LOG_WARN("validator", "EVICT rejected: evictor not in active set"); return -1; }
    if (!target_in)  { MXD_LOG_WARN("validator", "EVICT rejected: target not in active set");  return -1; }

    /* v8 design point (4): 5-minute grace period for freshly-added
     * validators. Protects a JOINer whose balance is fluctuating just below
     * threshold during the first few blocks. added_at_block_time_ms == 0
     * means "genesis or pre-v8" — no grace needed. Self-EVICT bypasses the
     * grace period; an operator can always leave immediately. */
    if (target_node && target_node->added_at_block_time_ms > 0 &&
        memcmp(request->evictor_addr, request->target_addr, 32) != 0) {
        uint64_t age_ms = (now > target_node->added_at_block_time_ms) ? (now - target_node->added_at_block_time_ms) : 0;
        if (age_ms < 300000ULL) {
            MXD_LOG_WARN("validator", "EVICT rejected: target within 5-min grace period (age=%llu ms)",
                         (unsigned long long)age_ms);
            return -1;
        }
    }

    /* Wire-supplied pubkey must derive to the declared evictor_addr32. */
    uint8_t derived[MXD_ADDR32_LEN];
    if (mxd_derive_address(request->evictor_algo_id, request->evictor_public_key,
                           request->evictor_public_key_length, derived) != 0) {
        MXD_LOG_WARN("validator", "EVICT rejected: pubkey address derivation failed");
        return -1;
    }
    if (memcmp(derived, request->evictor_addr, 32) != 0) {
        MXD_LOG_WARN("validator", "EVICT rejected: evictor pubkey does not derive to claimed addr");
        return -1;
    }

    /* Target's current on-chain balance must be below threshold. */
    mxd_amount_t target_balance = mxd_get_balance(request->target_addr);
    mxd_amount_t threshold = total_supply / 1000ULL;
    if (target_balance >= threshold) {
        MXD_LOG_WARN("validator", "EVICT rejected: target balance %llu >= threshold %llu",
                     (unsigned long long)target_balance, (unsigned long long)threshold);
        return -1;
    }

    /* Verify signature over the 84-byte canonical payload. */
    uint8_t sign_data[MXD_DOMAIN_TAG_VAL_LEN + 1 + 32 + 32 + 8];
    size_t off = 0;
    memcpy(sign_data + off, MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN); off += MXD_DOMAIN_TAG_VAL_LEN;
    sign_data[off++] = 0x02;
    memcpy(sign_data + off, request->target_addr, 32); off += 32;
    memcpy(sign_data + off, request->evictor_addr, 32); off += 32;
    uint64_t ts_be = mxd_htonll(request->timestamp);
    memcpy(sign_data + off, &ts_be, 8); off += 8;

    if (mxd_sig_verify(request->evictor_algo_id,
                       request->signature, request->signature_length,
                       sign_data, sizeof(sign_data),
                       request->evictor_public_key) != 0) {
        MXD_LOG_WARN("validator", "EVICT rejected: signature verify failed");
        return -1;
    }
    return 0;
}

int mxd_get_pending_evict_requests(mxd_validator_evict_request_t **requests, size_t *count) {
    if (!requests || !count) return -1;
    if (evict_pool_ensure_init() != 0) return -1;
    pthread_mutex_lock(&g_evict_pool.mutex);
    *count = g_evict_pool.count;
    if (*count == 0) {
        *requests = NULL;
        pthread_mutex_unlock(&g_evict_pool.mutex);
        return 0;
    }
    *requests = malloc(*count * sizeof(**requests));
    if (!*requests) {
        pthread_mutex_unlock(&g_evict_pool.mutex);
        return -1;
    }
    memcpy(*requests, g_evict_pool.requests, *count * sizeof(**requests));
    pthread_mutex_unlock(&g_evict_pool.mutex);
    return 0;
}

/* ---------- Receive handlers (called from mxd_p2p.c dispatch) ---------- */

int mxd_handle_validator_join_message(const uint8_t *payload, size_t payload_len) {
    mxd_validator_join_request_t req;
    if (mxd_deserialize_join_request(payload, payload_len, &req) != 0) {
        MXD_LOG_WARN("validator", "Malformed JOIN msg (%zu bytes)", payload_len);
        return -1;
    }
    if (val_seen_check_and_insert(MXD_MSG_VALIDATOR_JOIN_REQUEST,
                                   req.node_address, req.timestamp)) {
        return 0;
    }
    mxd_amount_t supply = 0;
    if (get_latest_total_supply(&supply) != 0 || supply == 0) {
        MXD_LOG_WARN("validator", "JOIN msg dropped: no total_supply yet");
        return -1;
    }
    if (mxd_validate_join_request(&req, supply) != 0) return -1;

    /* Append to local join pool (dedup on addr32). */
    pthread_mutex_lock(&g_request_pool.mutex);
    for (size_t i = 0; i < g_request_pool.join_count; i++) {
        if (memcmp(g_request_pool.join_requests[i].node_address, req.node_address, 32) == 0) {
            pthread_mutex_unlock(&g_request_pool.mutex);
            return 0;
        }
    }
    if (g_request_pool.join_count >= g_request_pool.join_capacity) {
        /* Same bootstrap-from-0 fix as in mxd_submit_validator_join_request:
         * the pool is statically zeroed on process start, so the first grow
         * must seed a positive capacity instead of doubling 0. */
        size_t nc = g_request_pool.join_capacity == 0
                        ? 10
                        : g_request_pool.join_capacity * 2;
        if (nc > 1000) { pthread_mutex_unlock(&g_request_pool.mutex); return -1; }
        mxd_validator_join_request_t *nr = realloc(g_request_pool.join_requests, nc * sizeof(*nr));
        if (!nr) { pthread_mutex_unlock(&g_request_pool.mutex); return -1; }
        g_request_pool.join_requests = nr;
        g_request_pool.join_capacity = nc;
    }
    memcpy(&g_request_pool.join_requests[g_request_pool.join_count], &req, sizeof(req));
    g_request_pool.join_count++;
    pthread_mutex_unlock(&g_request_pool.mutex);

    MXD_LOG_INFO("validator", "Accepted gossip JOIN %02x%02x...%02x%02x",
                 req.node_address[0], req.node_address[1],
                 req.node_address[30], req.node_address[31]);

    /* Epidemic re-broadcast. */
    uint8_t *rb_buf = NULL; size_t rb_len = 0;
    if (mxd_serialize_join_request(&req, &rb_buf, &rb_len) == 0) {
        mxd_broadcast_message(MXD_MSG_VALIDATOR_JOIN_REQUEST, rb_buf, rb_len);
        free(rb_buf);
    }
    return 0;
}

int mxd_handle_validator_evict_message(const uint8_t *payload, size_t payload_len) {
    mxd_validator_evict_request_t req;
    if (mxd_deserialize_evict_request(payload, payload_len, &req) != 0) {
        MXD_LOG_WARN("validator", "Malformed EVICT msg (%zu bytes)", payload_len);
        return -1;
    }
    if (val_seen_check_and_insert(MXD_MSG_VALIDATOR_EVICT_REQUEST,
                                   req.target_addr, req.timestamp)) {
        return 0;
    }
    mxd_amount_t supply = 0;
    if (get_latest_total_supply(&supply) != 0 || supply == 0) return -1;
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (!table) return -1;

    if (mxd_validate_evict_request(&req, table, supply) != 0) return -1;

    if (evict_pool_ensure_init() != 0) return -1;
    pthread_mutex_lock(&g_evict_pool.mutex);
    for (size_t i = 0; i < g_evict_pool.count; i++) {
        if (memcmp(g_evict_pool.requests[i].target_addr, req.target_addr, 32) == 0 &&
            memcmp(g_evict_pool.requests[i].evictor_addr, req.evictor_addr, 32) == 0) {
            pthread_mutex_unlock(&g_evict_pool.mutex);
            return 0;
        }
    }
    if (g_evict_pool.count >= g_evict_pool.capacity) {
        size_t nc = g_evict_pool.capacity * 2;
        if (nc > 1000) { pthread_mutex_unlock(&g_evict_pool.mutex); return -1; }
        mxd_validator_evict_request_t *nr = realloc(g_evict_pool.requests, nc * sizeof(*nr));
        if (!nr) { pthread_mutex_unlock(&g_evict_pool.mutex); return -1; }
        g_evict_pool.requests = nr;
        g_evict_pool.capacity = nc;
    }
    memcpy(&g_evict_pool.requests[g_evict_pool.count], &req, sizeof(req));
    g_evict_pool.count++;
    pthread_mutex_unlock(&g_evict_pool.mutex);

    MXD_LOG_INFO("validator", "Accepted gossip EVICT target=%02x%02x...%02x%02x",
                 req.target_addr[0], req.target_addr[1],
                 req.target_addr[30], req.target_addr[31]);

    uint8_t *rb_buf = NULL; size_t rb_len = 0;
    if (mxd_serialize_evict_request(&req, &rb_buf, &rb_len) == 0) {
        mxd_broadcast_message(MXD_MSG_VALIDATOR_EVICT_REQUEST, rb_buf, rb_len);
        free(rb_buf);
    }
    return 0;
}
