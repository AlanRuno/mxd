#include "../include/mxd_block_proposer.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_transaction.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

// Helper function to serialize a transaction for block storage
// Returns allocated buffer that must be freed by caller, or NULL on error
static uint8_t* serialize_transaction_for_block(const mxd_transaction_t* tx, size_t* out_len) {
    if (!tx || !out_len) return NULL;
    
    // Calculate total size needed
    size_t size = 0;
    size += 4;  // version (u32)
    size += 4;  // chain_id (u32) — NEW per MXD-04 §3.1
    size += 4;  // input_count (u32)
    size += 4;  // output_count (u32)
    size += 8;  // voluntary_tip (u64)
    size += 8;  // timestamp (u64)
    // is_coinbase NOT serialized; recovered as (input_count == 0)
    size += 64; // tx_hash

    // Calculate input sizes
    for (uint32_t i = 0; i < tx->input_count; i++) {
        size += 64;  // prev_tx_hash
        size += 4;   // output_index (u32)
        size += 1;   // algo_id (u8)
        size += 2;   // public_key_length (u16)
        size += tx->inputs[i].public_key_length;
        size += 2;   // signature_length (u16)
        size += tx->inputs[i].signature_length;
    }

    // Calculate output sizes (addr32)
    for (uint32_t i = 0; i < tx->output_count; i++) {
        size += 32;  // recipient_addr (addr32)
        size += 8;   // amount (u64)
    }
    
    uint8_t* buffer = malloc(size);
    if (!buffer) return NULL;
    
    uint8_t* ptr = buffer;
    
    // Serialize header fields (MXD-04 v1.1.x wire format)
    mxd_write_u32_be(&ptr, tx->version);
    mxd_write_u32_be(&ptr, tx->chain_id);   // NEW: chain_id per MXD-04 §3.1
    mxd_write_u32_be(&ptr, tx->input_count);
    mxd_write_u32_be(&ptr, tx->output_count);
    mxd_write_u64_be(&ptr, tx->voluntary_tip);
    mxd_write_u64_be(&ptr, tx->timestamp);
    // is_coinbase NOT serialized; recovered as (input_count == 0) on deserialize
    mxd_write_bytes(&ptr, tx->tx_hash, 64);
    
    // Serialize inputs (including signatures for block storage)
    for (uint32_t i = 0; i < tx->input_count; i++) {
        mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
        mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
        mxd_write_u8(&ptr, tx->inputs[i].algo_id);
        mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
        mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
        mxd_write_u16_be(&ptr, tx->inputs[i].signature_length);
        if (tx->inputs[i].signature_length > 0 && tx->inputs[i].signature) {
            mxd_write_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
        }
    }
    
    // Serialize outputs (addr32)
    for (uint32_t i = 0; i < tx->output_count; i++) {
        mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 32);
        mxd_write_u64_be(&ptr, tx->outputs[i].amount);
    }
    
    *out_len = size;
    return buffer;
}

static mxd_block_proposer_t proposer_state = {0};

static uint64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

int mxd_init_block_proposer(const uint8_t proposer_id[32]) {
    if (!proposer_id) {
        return -1;
    }

    memset(&proposer_state, 0, sizeof(mxd_block_proposer_t));
    memcpy(proposer_state.proposer_id, proposer_id, 32);   // v6: addr32
    proposer_state.current_block = NULL;
    proposer_state.is_proposing = 0;
    
    MXD_LOG_INFO("proposer", "Block proposer initialized");
    return 0;
}

int mxd_start_block_proposal(const uint8_t prev_hash[64], uint32_t height) {
    if (!prev_hash) {
        return -1;
    }
    
    if (proposer_state.is_proposing) {
        MXD_LOG_WARN("proposer", "Stopping existing block proposal before starting new one");
        mxd_stop_block_proposal();
    }
    
    proposer_state.current_block = malloc(sizeof(mxd_block_t));
    if (!proposer_state.current_block) {
        MXD_LOG_ERROR("proposer", "Failed to allocate memory for new block");
        return -1;
    }
    
    if (mxd_init_block_with_validation(proposer_state.current_block, prev_hash, 
                                       proposer_state.proposer_id, height) != 0) {
        MXD_LOG_ERROR("proposer", "Failed to initialize block");
        free(proposer_state.current_block);
        proposer_state.current_block = NULL;
        return -1;
    }
    
    proposer_state.block_start_time = get_current_time_ms();
    proposer_state.is_proposing = 1;
    
    MXD_LOG_INFO("proposer", "Started block proposal at height %u (timeout: %d ms)", 
                 height, MXD_BLOCK_CLOSE_TIMEOUT_MS);
    return 0;
}

int mxd_add_transaction_to_block(const mxd_transaction_t* tx) {
    if (!tx || !proposer_state.is_proposing || !proposer_state.current_block) {
        return -1;
    }
    
    if (proposer_state.current_block->transaction_set_frozen) {
        MXD_LOG_WARN("proposer", "Cannot add transaction to frozen block");
        return -1;
    }
    
    // Serialize the transaction for block storage
    size_t tx_data_len = 0;
    uint8_t* tx_data = serialize_transaction_for_block(tx, &tx_data_len);
    if (!tx_data) {
        MXD_LOG_ERROR("proposer", "Failed to serialize transaction for block");
        return -1;
    }
    
    // Add the serialized transaction to the block
    int result = mxd_add_transaction(proposer_state.current_block, tx_data, tx_data_len);
    free(tx_data);
    
    if (result != 0) {
        MXD_LOG_ERROR("proposer", "Failed to add transaction to block");
        return -1;
    }
    
    MXD_LOG_DEBUG("proposer", "Transaction added to block");
    return 0;
}

// Add v3 transaction (bridge mint/burn) to current block being proposed
int mxd_add_transaction_v3_to_block(const mxd_transaction_v3_t* tx) {
    if (!tx || !proposer_state.is_proposing || !proposer_state.current_block) {
        return -1;
    }

    if (proposer_state.current_block->transaction_set_frozen) {
        MXD_LOG_WARN("proposer", "Cannot add v3 transaction to frozen block");
        return -1;
    }

    // Serialize v3 transaction for block storage
    size_t tx_data_len = 0;
    uint8_t* tx_data = mxd_serialize_transaction_v3_for_block(tx, &tx_data_len);
    if (!tx_data) {
        MXD_LOG_ERROR("proposer", "Failed to serialize v3 transaction for block");
        return -1;
    }

    // Add the serialized transaction to the block
    int result = mxd_add_transaction(proposer_state.current_block, tx_data, tx_data_len);
    free(tx_data);

    if (result != 0) {
        MXD_LOG_ERROR("proposer", "Failed to add v3 transaction to block");
        return -1;
    }

    MXD_LOG_INFO("proposer", "V3 bridge transaction added to block (type=%d)", tx->type);
    return 0;
}

int mxd_should_close_block(void) {
    if (!proposer_state.is_proposing || !proposer_state.current_block) {
        return 0;
    }

    // Block should close if:
    // 1. Already frozen (ready for validation)
    // 2. Has transactions and timeout reached
    // 3. Has membership entries and timeout reached
    if (proposer_state.current_block->transaction_set_frozen) {
        return 0;  // Already closed
    }

    uint64_t current_time = get_current_time_ms();
    uint64_t elapsed = current_time - proposer_state.block_start_time;

    // Log block status periodically (every 5 seconds)
    static uint64_t last_status_log = 0;
    if (current_time - last_status_log >= 5000) {
        MXD_LOG_INFO("proposer", "Block status: height=%u, tx_count=%u, membership_count=%u, elapsed=%llu ms",
                     proposer_state.current_block->height,
                     proposer_state.current_block->transaction_count,
                     proposer_state.current_block->rapid_membership_count,
                     (unsigned long long)elapsed);
        last_status_log = current_time;
    }

    // Check if block is empty (no transactions and no membership changes)
    int is_empty = (proposer_state.current_block->transaction_count == 0 &&
                    proposer_state.current_block->rapid_membership_count == 0);

    // Both empty and non-empty blocks close after 5 seconds.
    // Fast block closure is critical: the previous 30s empty block timeout collided
    // with the proposer timeout, causing fallback proposers and chain forks.
    uint64_t timeout = MXD_BLOCK_CLOSE_TIMEOUT_MS;

    if (elapsed >= timeout) {
        if (is_empty) {
            MXD_LOG_INFO("proposer", "Empty block timeout reached (%llu ms elapsed), closing to keep chain alive",
                         (unsigned long long)elapsed);
        } else {
            MXD_LOG_INFO("proposer", "Block timeout reached (%llu ms elapsed, %u txs, %u membership), closing block",
                         (unsigned long long)elapsed,
                         proposer_state.current_block->transaction_count,
                         proposer_state.current_block->rapid_membership_count);
        }
        return 1;
    }

    return 0;
}

int mxd_close_block(void) {
    if (!proposer_state.is_proposing || !proposer_state.current_block) {
        MXD_LOG_WARN("proposer", "No active block to close");
        return -1;
    }
    
    if (proposer_state.current_block->transaction_set_frozen) {
        MXD_LOG_DEBUG("proposer", "Block already frozen");
        return 0;
    }
    
    if (mxd_freeze_transaction_set(proposer_state.current_block) != 0) {
        MXD_LOG_ERROR("proposer", "Failed to freeze transaction set");
        return -1;
    }
    
    uint64_t elapsed = get_current_time_ms() - proposer_state.block_start_time;
    MXD_LOG_INFO("proposer", "Block closed and transaction set frozen after %llu ms",
                 (unsigned long long)elapsed);
    
    return 0;
}

mxd_block_t* mxd_get_current_block(void) {
    if (!proposer_state.is_proposing) {
        return NULL;
    }
    return proposer_state.current_block;
}

int mxd_stop_block_proposal(void) {
    if (!proposer_state.is_proposing) {
        return 0;
    }
    
    if (proposer_state.current_block) {
        if (proposer_state.current_block->validation_chain) {
            free(proposer_state.current_block->validation_chain);
        }

        if (proposer_state.current_block->rapid_membership_entries) {
            free(proposer_state.current_block->rapid_membership_entries);
        }

        /* v8+: also free rapid_eviction_entries to avoid a per-proposal leak
         * when EVICT entries land in a proposed block. */
        if (proposer_state.current_block->rapid_eviction_entries) {
            free(proposer_state.current_block->rapid_eviction_entries);
        }

        if (proposer_state.current_block->validator_scores) {
            free(proposer_state.current_block->validator_scores);
        }

        free(proposer_state.current_block);
        proposer_state.current_block = NULL;
    }
    
    proposer_state.is_proposing = 0;
    MXD_LOG_INFO("proposer", "Block proposal stopped");
    
    return 0;
}

void mxd_cleanup_block_proposer(void) {
    mxd_stop_block_proposal();
    memset(&proposer_state, 0, sizeof(mxd_block_proposer_t));
    MXD_LOG_INFO("proposer", "Block proposer cleaned up");
}

// Timeout tracking implementation
static mxd_height_timeout_t g_height_timeout = {0};
static pthread_mutex_t g_timeout_mutex = PTHREAD_MUTEX_INITIALIZER;

// Note: get_current_time_ms() is already defined earlier in this file (line 82)

int mxd_start_height_timeout(uint32_t height, const uint8_t *expected_proposer) {
    if (!expected_proposer) {
        return -1;
    }

    pthread_mutex_lock(&g_timeout_mutex);

    if (g_height_timeout.height == height) {
        // Already tracking this height
        pthread_mutex_unlock(&g_timeout_mutex);
        return 0;
    }

    g_height_timeout.height = height;
    g_height_timeout.wait_start_time = get_current_time_ms();
    g_height_timeout.retry_count = 0;
    memcpy(g_height_timeout.expected_proposer, expected_proposer, 32);   // v6: addr32

    pthread_mutex_unlock(&g_timeout_mutex);
    return 0;
}

int mxd_check_timeout_expired(void) {
    pthread_mutex_lock(&g_timeout_mutex);

    uint64_t now = get_current_time_ms();

    // SECURITY: Issue #14 - Check if clock went backward (prevent underflow)
    if (now < g_height_timeout.wait_start_time) {
        // Clock adjustment detected - reset timer
        MXD_LOG_WARN("proposer", "Clock adjustment detected (time went backward), resetting timeout timer");
        g_height_timeout.wait_start_time = now;
        pthread_mutex_unlock(&g_timeout_mutex);
        return 0;  // Not expired, timer reset
    }

    uint64_t elapsed = now - g_height_timeout.wait_start_time;
    int expired = (elapsed >= MXD_PROPOSER_TIMEOUT_MS);

    pthread_mutex_unlock(&g_timeout_mutex);
    return expired;
}

int mxd_increment_retry_count(void) {
    pthread_mutex_lock(&g_timeout_mutex);
    g_height_timeout.retry_count++;
    // Liveness: when all fallbacks are exhausted, cycle back to primary (retry 0)
    // so the chain doesn't freeze if every validator had a transient failure.
    // Without this reset, retry_count stays at MXD_MAX_FALLBACK_RETRIES forever
    // and no one proposes (caller's guard excludes retry >= MAX).
    if (g_height_timeout.retry_count > MXD_MAX_FALLBACK_RETRIES) {
        MXD_LOG_WARN("proposer",
                     "Exhausted %u fallbacks for height %u, cycling back to primary",
                     MXD_MAX_FALLBACK_RETRIES, g_height_timeout.height);
        g_height_timeout.retry_count = 0;
    }
    g_height_timeout.wait_start_time = get_current_time_ms(); // Reset timer for next fallback
    uint32_t count = g_height_timeout.retry_count;
    pthread_mutex_unlock(&g_timeout_mutex);
    return count;
}

// Thread-safe accessor: Get both height and retry count atomically
int mxd_get_timeout_state(uint32_t *height, uint32_t *retry_count) {
    if (!height || !retry_count) {
        return -1;
    }

    pthread_mutex_lock(&g_timeout_mutex);
    *height = g_height_timeout.height;
    *retry_count = g_height_timeout.retry_count;
    pthread_mutex_unlock(&g_timeout_mutex);
    return 0;
}

// Thread-safe accessor: Get retry count only
uint32_t mxd_get_timeout_retry_count(void) {
    pthread_mutex_lock(&g_timeout_mutex);
    uint32_t count = g_height_timeout.retry_count;
    pthread_mutex_unlock(&g_timeout_mutex);
    return count;
}

// Thread-safe accessor: Get height only
uint32_t mxd_get_timeout_height(void) {
    pthread_mutex_lock(&g_timeout_mutex);
    uint32_t height = g_height_timeout.height;
    pthread_mutex_unlock(&g_timeout_mutex);
    return height;
}
