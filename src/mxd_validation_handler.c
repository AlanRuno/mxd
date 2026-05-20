#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_serialize.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

// Mutex to prevent race condition when multiple signature handlers
// concurrently load, modify, and store the same block
static pthread_mutex_t validation_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

// Pending signature buffer for out-of-order delivery.
// When position N+1's signature arrives before position N's has been stored,
// we buffer it and process it after the preceding signature is added.
typedef struct {
    uint8_t block_hash[64];
    uint8_t validator_id[32];   // v6: addr32 validator identity
    uint8_t algo_id;
    uint8_t signature[MXD_SIGNATURE_MAX];
    uint16_t sig_len;
    uint32_t chain_position;
    uint64_t timestamp;
    time_t buffered_at;
    int used;
} pending_sig_entry_t;

#define MAX_PENDING_SIGS 32
#define PENDING_SIG_EXPIRY_SEC 15

static pending_sig_entry_t pending_sig_buffer[MAX_PENDING_SIGS];

// Buffer a signature for later processing. Caller must hold validation_sig_mutex.
static void buffer_pending_sig(const uint8_t *block_hash, const uint8_t *validator_id,
                               uint8_t algo_id, const uint8_t *signature, uint16_t sig_len,
                               uint32_t chain_position, uint64_t timestamp) {
    time_t now = time(NULL);

    // Check for duplicate before buffering
    for (int i = 0; i < MAX_PENDING_SIGS; i++) {
        if (pending_sig_buffer[i].used &&
            memcmp(pending_sig_buffer[i].block_hash, block_hash, 64) == 0 &&
            pending_sig_buffer[i].chain_position == chain_position &&
            memcmp(pending_sig_buffer[i].validator_id, validator_id, 32) == 0) {
            return;  // Already buffered
        }
    }

    // Find an empty or expired slot
    for (int i = 0; i < MAX_PENDING_SIGS; i++) {
        if (!pending_sig_buffer[i].used ||
            (now - pending_sig_buffer[i].buffered_at > PENDING_SIG_EXPIRY_SEC)) {
            pending_sig_buffer[i].used = 1;
            pending_sig_buffer[i].buffered_at = now;
            memcpy(pending_sig_buffer[i].block_hash, block_hash, 64);
            memcpy(pending_sig_buffer[i].validator_id, validator_id, 32);
            pending_sig_buffer[i].algo_id = algo_id;
            memcpy(pending_sig_buffer[i].signature, signature, sig_len);
            pending_sig_buffer[i].sig_len = sig_len;
            pending_sig_buffer[i].chain_position = chain_position;
            pending_sig_buffer[i].timestamp = timestamp;
            MXD_LOG_INFO("validation", "Buffered out-of-order sig at pos %u", chain_position);
            return;
        }
    }
    MXD_LOG_WARN("validation", "Pending signature buffer full, dropping sig at pos %u", chain_position);
}

// Process buffered signatures for a block after a new signature was added.
// Caller must hold validation_sig_mutex.
static void drain_pending_sigs(const uint8_t *block_hash) {
    time_t now = time(NULL);
    int progress = 1;

    while (progress) {
        progress = 0;

        // Find the buffered sig with the lowest chain_position for this block
        int best_idx = -1;
        uint32_t best_pos = UINT32_MAX;

        for (int i = 0; i < MAX_PENDING_SIGS; i++) {
            if (!pending_sig_buffer[i].used) continue;
            if (now - pending_sig_buffer[i].buffered_at > PENDING_SIG_EXPIRY_SEC) {
                pending_sig_buffer[i].used = 0;
                continue;
            }
            if (memcmp(pending_sig_buffer[i].block_hash, block_hash, 64) != 0) continue;
            if (pending_sig_buffer[i].chain_position < best_pos) {
                best_pos = pending_sig_buffer[i].chain_position;
                best_idx = i;
            }
        }

        if (best_idx < 0) break;

        // Retrieve current block state
        mxd_block_t block;
        memset(&block, 0, sizeof(block));
        if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) break;

        if (best_pos < block.validation_count) {
            // Already past this position, remove stale entry
            pending_sig_buffer[best_idx].used = 0;
            mxd_free_block(&block);
            progress = 1;
            continue;
        }

        if (best_pos > block.validation_count) {
            // Still waiting for preceding signatures
            mxd_free_block(&block);
            break;
        }

        // best_pos == validation_count: this is the next expected position
        pending_sig_entry_t *entry = &pending_sig_buffer[best_idx];
        if (mxd_verify_and_add_validation_signature(&block, entry->validator_id,
                                                    entry->algo_id, entry->signature,
                                                    entry->sig_len, entry->timestamp,
                                                    /* skip_drift_check */ 0) == 0) {
            if (mxd_store_block(&block) == 0) {
                MXD_LOG_INFO("validation", "Added buffered sig to block %u at pos %u (now has %u sigs)",
                             block.height, best_pos, block.validation_count);

                if (mxd_check_block_relay_status(block_hash) == 1) {
                    MXD_LOG_INFO("validation", "Block now has enough signatures for relay");
                }

                // Chain reaction: check if it's now our turn to sign
                mxd_block_t fresh_block;
                memset(&fresh_block, 0, sizeof(fresh_block));
                if (mxd_retrieve_block_by_hash(block_hash, &fresh_block) == 0) {
                    mxd_sign_and_broadcast_block(&fresh_block);
                    mxd_free_block(&fresh_block);
                }
                progress = 1;
            }
        }
        entry->used = 0;
        mxd_free_block(&block);
    }
}

// BLOCKER FIX: Implement actual processing of validation messages instead of just logging

// Forward declaration for block response callback
extern void mxd_handle_blocks_response(const uint8_t *data, size_t data_len, uint32_t block_index);

// Helper to serialize validation chain for response
static int serialize_validation_chain(const mxd_block_t *block, uint8_t **out_data, size_t *out_len) {
    if (!block || !out_data || !out_len) return -1;
    if (block->validation_count == 0 || !block->validation_chain) {
        *out_data = NULL;
        *out_len = 0;
        return 0;
    }
    
    // Calculate size: block_hash(64) + count(4) + signatures
    size_t size = 64 + 4;
    for (uint32_t i = 0; i < block->validation_count; i++) {
        // validator_id(32) + timestamp(8) + algo_id(1) + sig_len(2) + signature + chain_pos(4) — v6 addr32
        size += 32 + 8 + 1 + 2 + block->validation_chain[i].signature_length + 4;
    }

    uint8_t *data = malloc(size);
    if (!data) return -1;

    uint8_t *ptr = data;
    memcpy(ptr, block->block_hash, 64);
    ptr += 64;

    uint32_t count_net = htonl(block->validation_count);
    memcpy(ptr, &count_net, 4);
    ptr += 4;

    for (uint32_t i = 0; i < block->validation_count; i++) {
        const mxd_validator_signature_t *sig = &block->validation_chain[i];
        memcpy(ptr, sig->validator_id, 32);
        ptr += 32;
        uint64_t ts_net = mxd_htonll(sig->timestamp);
        memcpy(ptr, &ts_net, 8);
        ptr += 8;
        *ptr++ = sig->algo_id;
        uint16_t sig_len_net = htons(sig->signature_length);
        memcpy(ptr, &sig_len_net, 2);
        ptr += 2;
        memcpy(ptr, sig->signature, sig->signature_length);
        ptr += sig->signature_length;
        uint32_t pos_net = htonl(sig->chain_position);
        memcpy(ptr, &pos_net, 4);
        ptr += 4;
    }
    
    *out_data = data;
    *out_len = size;
    return 0;
}

// Helper to deserialize validation chain from network message
static int deserialize_validation_chain(const uint8_t *data, size_t data_len,
                                       uint8_t block_hash[64],
                                       mxd_validator_signature_t **out_sigs,
                                       uint32_t *out_count) {
    if (!data || data_len < 68 || !block_hash || !out_sigs || !out_count) return -1;
    
    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;
    
    memcpy(block_hash, ptr, 64);
    ptr += 64;
    
    uint32_t count_net;
    memcpy(&count_net, ptr, 4);
    ptr += 4;
    uint32_t count = ntohl(count_net);
    
    if (count == 0 || count > 1000) {
        *out_sigs = NULL;
        *out_count = 0;
        return 0;
    }
    
    mxd_validator_signature_t *sigs = calloc(count, sizeof(mxd_validator_signature_t));
    if (!sigs) return -1;
    
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 32 + 8 + 1 + 2 > end) {
            free(sigs);
            return -1;
        }

        memcpy(sigs[i].validator_id, ptr, 32);   // v6: addr32
        ptr += 32;
        uint64_t ts_net;
        memcpy(&ts_net, ptr, 8);
        ptr += 8;
        sigs[i].timestamp = mxd_ntohll(ts_net);
        sigs[i].algo_id = *ptr++;
        uint16_t sig_len_net;
        memcpy(&sig_len_net, ptr, 2);
        ptr += 2;
        sigs[i].signature_length = ntohs(sig_len_net);
        
        if (sigs[i].signature_length > MXD_SIGNATURE_MAX || ptr + sigs[i].signature_length + 4 > end) {
            free(sigs);
            return -1;
        }
        
        memcpy(sigs[i].signature, ptr, sigs[i].signature_length);
        ptr += sigs[i].signature_length;
        uint32_t pos_net;
        memcpy(&pos_net, ptr, 4);
        ptr += 4;
        sigs[i].chain_position = ntohl(pos_net);
    }
    
    *out_sigs = sigs;
    *out_count = count;
    return 0;
}

void mxd_validation_message_handler(const char *address, uint16_t port,
                                      mxd_message_type_t type,
                                      const void *payload,
                                      size_t payload_length) {
    MXD_LOG_DEBUG("validation", "Validation handler invoked: type=%d len=%zu from %s:%u", 
                 type, payload_length, address, port);
    
    switch (type) {
        case MXD_MSG_VALIDATION_SIGNATURE: {
            // v6 wire format: block_hash(64) + algo_id(1) + validator_id(32) + sig_len(2) + ...
            if (payload_length < 64 + 1 + 32 + 2) {
                MXD_LOG_WARN("validation", "Invalid VALIDATION_SIGNATURE message size: %zu", payload_length);
                return;
            }

            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;

            const uint8_t *block_hash = data + offset;
            offset += 64;

            uint8_t algo_id = data[offset];
            offset += 1;

            const uint8_t *validator_id = data + offset;
            offset += 32;
            
            uint16_t sig_len_net;
            memcpy(&sig_len_net, data + offset, 2);
            uint16_t sig_len = ntohs(sig_len_net);
            offset += 2;
            
            if (offset + sig_len + 4 + 8 > payload_length) {
                MXD_LOG_WARN("validation", "Invalid VALIDATION_SIGNATURE signature length: %u", sig_len);
                return;
            }
            
            const uint8_t *signature = data + offset;
            offset += sig_len;
            
            uint32_t chain_pos_net;
            memcpy(&chain_pos_net, data + offset, 4);
            uint32_t chain_position = ntohl(chain_pos_net);
            offset += 4;
            
            uint64_t timestamp_net;
            memcpy(&timestamp_net, data + offset, 8);
            uint64_t timestamp = mxd_ntohll(timestamp_net);
            offset += 8;

            // Detect new chain format: 64 extra bytes for chain_hash at end
            int has_chain_hash = (offset + 64 <= payload_length);
            if (has_chain_hash) {
                char ch_hex[17] = {0};
                for (int j = 0; j < 8; j++) snprintf(ch_hex + j*2, 3, "%02x", data[offset + j]);
                MXD_LOG_DEBUG("validation", "Processing chained signature: algo_id=%u, sig_len=%u, chain_pos=%u, chain_hash=%s...",
                              algo_id, sig_len, chain_position, ch_hex);
            } else {
                MXD_LOG_DEBUG("validation", "Processing validation signature: algo_id=%u, sig_len=%u, chain_pos=%u",
                              algo_id, sig_len, chain_position);
            }

            int sig_added = 0;

            pthread_mutex_lock(&validation_sig_mutex);

            mxd_block_t block;
            memset(&block, 0, sizeof(block));
            if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
                // Block not stored yet - buffer the signature for later
                buffer_pending_sig(block_hash, validator_id, algo_id,
                                   signature, sig_len, chain_position, timestamp);
                pthread_mutex_unlock(&validation_sig_mutex);
                break;
            }

            // If the signature is for a future position, buffer it and request missing chain
            if (chain_position > block.validation_count) {
                MXD_LOG_INFO("validation", "Buffering out-of-order sig: pos %u but block %u has %u sigs",
                             chain_position, block.height, block.validation_count);
                buffer_pending_sig(block_hash, validator_id, algo_id,
                                   signature, sig_len, chain_position, timestamp);
                mxd_free_block(&block);
                pthread_mutex_unlock(&validation_sig_mutex);

                // Request the full validation chain from the sender to fill gaps
                mxd_send_message(address, port, MXD_MSG_GET_VALIDATION_CHAIN,
                                 block_hash, 64);
                MXD_LOG_DEBUG("validation", "Requested validation chain from %s:%u for missing sigs",
                              address, port);
                break;
            }

            // Verify and add the signature to the block
            if (mxd_verify_and_add_validation_signature(&block, validator_id, algo_id,
                                                        signature, sig_len, timestamp,
                                                        /* skip_drift_check */ 0) == 0) {
                if (mxd_store_block(&block) == 0) {
                    sig_added = 1;
                    MXD_LOG_INFO("validation", "Added chained signature to block %u at pos %u (now has %u sigs)",
                                 block.height, chain_position, block.validation_count);

                    if (mxd_check_block_relay_status(block_hash) == 1) {
                        MXD_LOG_INFO("validation", "Block now has enough signatures for relay");
                    }

                    // Drain any buffered signatures that can now be added
                    drain_pending_sigs(block_hash);

                    // Chain reaction: check if it's now our turn to sign
                    mxd_block_t fresh_block;
                    memset(&fresh_block, 0, sizeof(fresh_block));
                    if (mxd_retrieve_block_by_hash(block_hash, &fresh_block) == 0) {
                        mxd_sign_and_broadcast_block(&fresh_block);
                        mxd_free_block(&fresh_block);
                    }
                } else {
                    MXD_LOG_ERROR("validation", "Failed to store block with new signature");
                }
            } else {
                MXD_LOG_DEBUG("validation", "Duplicate or invalid signature at pos %u", chain_position);
            }

            mxd_free_block(&block);
            pthread_mutex_unlock(&validation_sig_mutex);

            // Gossip relay: re-broadcast new signatures to all peers.
            // This ensures every validator receives every signature even with
            // partial P2P connectivity (where original broadcasts miss some nodes).
            // Deduplication at the receiver prevents infinite relay loops.
            if (sig_added) {
                mxd_peer_t relay_peers[MXD_MAX_PEERS];
                size_t relay_peer_count = MXD_MAX_PEERS;
                if (mxd_get_peers(relay_peers, &relay_peer_count) == 0 && relay_peer_count > 0) {
                    int relayed = 0;
                    for (size_t ri = 0; ri < relay_peer_count; ri++) {
                        if (mxd_send_message(relay_peers[ri].address, relay_peers[ri].port,
                                            MXD_MSG_VALIDATION_SIGNATURE, payload, payload_length) == 0) {
                            relayed++;
                        }
                    }
                    MXD_LOG_INFO("validation", "Relayed pos %u sig to %d/%zu peers",
                                 chain_position, relayed, relay_peer_count);
                }
            }
            break;
        }
        
        case MXD_MSG_VALIDATION_CHAIN: {
            MXD_LOG_INFO("validation", "Processing validation chain message: len=%zu", payload_length);
            
            // BLOCKER FIX: Deserialize and process the validation chain
            uint8_t block_hash[64];
            mxd_validator_signature_t *signatures = NULL;
            uint32_t sig_count = 0;
            
            if (deserialize_validation_chain(payload, payload_length, block_hash, &signatures, &sig_count) == 0) {
                if (sig_count > 0 && signatures) {
                    if (mxd_process_incoming_validation_chain(block_hash, signatures, sig_count) == 0) {
                        MXD_LOG_INFO("validation", "Successfully processed validation chain with %u signatures", sig_count);

                        // Drain buffered sigs and trigger chain reaction
                        pthread_mutex_lock(&validation_sig_mutex);
                        drain_pending_sigs(block_hash);
                        pthread_mutex_unlock(&validation_sig_mutex);

                        mxd_block_t chain_block;
                        memset(&chain_block, 0, sizeof(chain_block));
                        if (mxd_retrieve_block_by_hash(block_hash, &chain_block) == 0) {
                            mxd_sign_and_broadcast_block(&chain_block);
                            mxd_free_block(&chain_block);
                        }
                    } else {
                        MXD_LOG_WARN("validation", "Failed to process validation chain");
                    }
                    free(signatures);
                }
            } else {
                MXD_LOG_WARN("validation", "Failed to deserialize validation chain");
            }
            break;
        }
        
        case MXD_MSG_BLOCKS: {
            MXD_LOG_INFO("validation", "Processing block message: len=%zu", payload_length);
            
            // BLOCKER FIX: Process received block data
            if (payload_length < 4) {
                MXD_LOG_WARN("validation", "Block message too short");
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;

            // Check if this is a height response (4 bytes: current_height)
            if (payload_length == 4) {
                // This is a height info response - route to sync module
                extern void mxd_handle_peer_height_response(const uint8_t *data, size_t data_len);
                const uint8_t *ptr = data;
                uint32_t current_height = mxd_read_u32_be(&ptr);
                MXD_LOG_INFO("validation", "Received height response: %u", current_height);
                mxd_handle_peer_height_response(data, payload_length);
                return;
            }
            
            // Otherwise, this is actual block data - pass to block response handler
            // Block index is typically 0 for single block responses
            mxd_handle_blocks_response(data, payload_length, 0);
            break;
        }
        
        case MXD_MSG_GET_BLOCKS: {
            MXD_LOG_INFO("validation", "Processing GET_BLOCKS request: len=%zu", payload_length);
            
            // BLOCKER FIX: Respond to block requests
            if (payload_length < 8) {
                MXD_LOG_WARN("validation", "GET_BLOCKS message too short");
                return;
            }
            
            const uint8_t *ptr = (const uint8_t *)payload;
            uint32_t start_height = mxd_read_u32_be(&ptr);
            uint32_t end_height = mxd_read_u32_be(&ptr);
            
            // If both are 0, this is a height info request
            if (start_height == 0 && end_height == 0) {
                uint32_t current_height = 0;
                mxd_get_blockchain_height(&current_height);

                // Send height response - height must be in first 4 bytes for sync code to read it
                uint8_t response[4];
                uint8_t *rp = response;
                mxd_write_u32_be(&rp, current_height);  // current_height (first 4 bytes)

                mxd_send_message(address, port, MXD_MSG_BLOCKS, response, sizeof(response));
                MXD_LOG_INFO("validation", "Sent height response: %u", current_height);
                return;
            }
            
            // Otherwise, send requested blocks with full serialization
            for (uint32_t h = start_height; h <= end_height && h - start_height < 100; h++) {
                mxd_block_t block;
                memset(&block, 0, sizeof(block));
                if (mxd_retrieve_block_by_height(h, &block) == 0) {
                    // Serialize full block for network transmission
                    uint8_t *block_data = NULL;
                    size_t block_data_len = 0;

                    if (mxd_serialize_block_for_network(&block, &block_data, &block_data_len) == 0 && block_data) {
                        mxd_send_message(address, port, MXD_MSG_BLOCKS, block_data, block_data_len);
                        MXD_LOG_INFO("validation", "Sent block at height %u (size=%zu bytes)", h, block_data_len);
                        free(block_data);
                    } else {
                        MXD_LOG_ERROR("validation", "Failed to serialize block at height %u", h);
                    }
                    mxd_free_block(&block);
                }
            }
            break;
        }
        
        case MXD_MSG_GET_VALIDATION_CHAIN: {
            if (payload_length < 64) {
                MXD_LOG_WARN("validation", "Invalid GET_VALIDATION_CHAIN message size: %zu", payload_length);
                return;
            }
            
            const uint8_t *block_hash = (const uint8_t *)payload;
            MXD_LOG_INFO("validation", "Processing request for validation chain");
            
            // BLOCKER FIX: Actually send the validation chain
            mxd_block_t block;
            memset(&block, 0, sizeof(block));
            if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
                MXD_LOG_WARN("validation", "Block not found for validation chain request");
                return;
            }
            
            uint8_t *chain_data = NULL;
            size_t chain_len = 0;
            if (serialize_validation_chain(&block, &chain_data, &chain_len) == 0 && chain_data) {
                mxd_send_message(address, port, MXD_MSG_VALIDATION_CHAIN, chain_data, chain_len);
                MXD_LOG_INFO("validation", "Sent validation chain with %u signatures", block.validation_count);
                free(chain_data);
            }
            
            mxd_free_block(&block);
            break;
        }
        
        case MXD_MSG_BLOCK_VALIDATION: {
            MXD_LOG_INFO("validation", "Processing BLOCK_VALIDATION message: len=%zu", payload_length);
            // Block validation requests are handled similarly to validation signatures
            // but may include additional validation context
            break;
        }
        
        default:
            MXD_LOG_WARN("validation", "Unhandled validation message type: %d", type);
            break;
    }
}

// Public API: drain pending validation signatures for a block.
// Call this after storing a new block to process any signatures
// that arrived before the block itself.
void mxd_drain_pending_validation_sigs(const uint8_t *block_hash) {
    if (!block_hash) return;
    pthread_mutex_lock(&validation_sig_mutex);
    drain_pending_sigs(block_hash);
    pthread_mutex_unlock(&validation_sig_mutex);
}
