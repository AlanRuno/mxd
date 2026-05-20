#include "mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "mxd_blockchain.h"
#include "mxd_crypto.h"
#include "mxd_p2p.h"
#include "mxd_rsc.h"
#include "mxd_endian.h"

int mxd_should_relay_block(const mxd_block_t *block, int just_signed) {
    if (!block) return 0;
    if (just_signed) return 1;
    if (mxd_verify_validation_chain(block) != 0) return 0;
    return mxd_block_has_min_relay_signatures(block);
}

#define MXD_MIN_RELAY_SIGNATURES 3

#define MXD_MAX_TIMESTAMP_DRIFT 60

static uint32_t min_relay_signatures = MXD_MIN_RELAY_SIGNATURES;

// Persistent rapid table status storage (peers come from DHT which doesn't
// track rapid table membership, so we maintain it separately)
typedef struct {
    char address[256];
    uint16_t port;
    uint8_t in_rapid_table;
    uint32_t rapid_table_position;
    int valid;
} rapid_table_entry_t;

static rapid_table_entry_t rapid_table_status[MXD_MAX_PEERS];
static size_t rapid_table_status_count = 0;
static pthread_mutex_t rapid_table_mutex = PTHREAD_MUTEX_INITIALIZER;

int mxd_broadcast_to_rapid_table(mxd_message_type_t type, const void *payload,
                                size_t payload_length) {
    if (!payload || payload_length == 0) {
        return -1;
    }
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_rapid_table_peers(peers, &peer_count) != 0 || peer_count == 0) {
        return -1;
    }
    
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            mxd_send_message(peers[i].address, peers[i].port, type, payload, payload_length);
        }
    }
    
    return 0;
}

int mxd_broadcast_block_with_validation(const void *block_data, size_t block_length,
                                       const void *validation_chain, size_t validation_length) {
    if (!block_data || block_length == 0) {
        return -1;
    }
    
    mxd_broadcast_to_rapid_table(MXD_MSG_BLOCKS, block_data, block_length);
    
    if (validation_chain && validation_length > 0) {
        mxd_broadcast_to_rapid_table(MXD_MSG_VALIDATION_CHAIN, validation_chain, validation_length);
    }
    
    return 0;
}

int mxd_relay_block_by_validation_count(const void *block_data, size_t block_length,
                                       uint32_t signature_count) {
    if (!block_data || block_length == 0) {
        return -1;
    }
    
    if (signature_count < min_relay_signatures) {
        return 0; // Not an error, just not relaying yet
    }
    
    return mxd_broadcast_message(MXD_MSG_BLOCKS, block_data, block_length);
}

int mxd_send_validation_signature(const char *address, uint16_t port,
                                 const uint8_t *block_hash, uint8_t algo_id,
                                 const uint8_t *validator_id, const uint8_t *signature,
                                 uint16_t signature_length, uint32_t chain_position) {
    if (!address || !block_hash || !validator_id || !signature) {
        return -1;
    }
    if (signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    // v6: validator_id widened to 32 bytes (addr32)
    size_t msg_len = 64 + 1 + 32 + sizeof(uint16_t) + signature_length + sizeof(uint32_t) + sizeof(uint64_t);
    uint8_t *validation_msg = malloc(msg_len);
    if (!validation_msg) {
        return -1;
    }

    uint8_t *ptr = validation_msg;

    memcpy(ptr, block_hash, 64);
    ptr += 64;

    *ptr = algo_id;
    ptr += 1;

    memcpy(ptr, validator_id, 32);
    ptr += 32;
    
    uint16_t sig_len_net = htons(signature_length);
    memcpy(ptr, &sig_len_net, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    
    memcpy(ptr, signature, signature_length);
    ptr += signature_length;
    
    uint32_t chain_pos_net = htonl(chain_position);
    memcpy(ptr, &chain_pos_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    uint64_t timestamp = time(NULL);
    uint64_t timestamp_net = mxd_htonll(timestamp);
    memcpy(ptr, &timestamp_net, sizeof(uint64_t));
    
    int result = mxd_send_message(address, port, MXD_MSG_VALIDATION_SIGNATURE, 
                                  validation_msg, msg_len);
    free(validation_msg);
    return result;
}

int mxd_request_validation_chain(const char *address, uint16_t port,
                                const uint8_t *block_hash) {
    if (!address || !block_hash) {
        return -1;
    }
    
    return mxd_send_message(address, port, MXD_MSG_GET_VALIDATION_CHAIN, 
                           block_hash, 64);
}

int mxd_update_peer_rapid_table_status(const char *address, uint16_t port,
                                      uint8_t in_rapid_table, uint32_t position) {
    if (!address) {
        return -1;
    }

    // Verify peer exists
    mxd_peer_t peer;
    if (mxd_get_peer(address, port, &peer) != 0) {
        return -1;
    }

    // Update or insert into rapid table status store
    pthread_mutex_lock(&rapid_table_mutex);
    int free_slot = -1;
    for (size_t i = 0; i < rapid_table_status_count; i++) {
        if (rapid_table_status[i].valid &&
            strcmp(rapid_table_status[i].address, address) == 0 &&
            rapid_table_status[i].port == port) {
            rapid_table_status[i].in_rapid_table = in_rapid_table;
            rapid_table_status[i].rapid_table_position = position;
            pthread_mutex_unlock(&rapid_table_mutex);
            MXD_LOG_INFO("validation", "Updated peer %s:%d Rapid Table status: in_table=%d, position=%u",
                   address, port, in_rapid_table, position);
            return 0;
        }
        if (!rapid_table_status[i].valid && free_slot < 0) {
            free_slot = (int)i;
        }
    }

    // Insert new entry
    size_t slot;
    if (free_slot >= 0) {
        slot = (size_t)free_slot;
    } else if (rapid_table_status_count < MXD_MAX_PEERS) {
        slot = rapid_table_status_count++;
    } else {
        pthread_mutex_unlock(&rapid_table_mutex);
        MXD_LOG_WARN("validation", "Rapid table status store full, cannot track %s:%d", address, port);
        return -1;
    }

    strncpy(rapid_table_status[slot].address, address, sizeof(rapid_table_status[slot].address) - 1);
    rapid_table_status[slot].address[sizeof(rapid_table_status[slot].address) - 1] = '\0';
    rapid_table_status[slot].port = port;
    rapid_table_status[slot].in_rapid_table = in_rapid_table;
    rapid_table_status[slot].rapid_table_position = position;
    rapid_table_status[slot].valid = 1;
    pthread_mutex_unlock(&rapid_table_mutex);

    MXD_LOG_INFO("validation", "Updated peer %s:%d Rapid Table status: in_table=%d, position=%u",
           address, port, in_rapid_table, position);

    return 0;
}

int mxd_get_rapid_table_peers(mxd_peer_t *peers, size_t *peer_count) {
    if (!peers || !peer_count || *peer_count == 0) {
        return -1;
    }

    mxd_peer_t all_peers[MXD_MAX_PEERS];
    size_t all_peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(all_peers, &all_peer_count) != 0) {
        return -1;
    }

    // Enrich peers with rapid table status from our persistent store
    pthread_mutex_lock(&rapid_table_mutex);
    for (size_t i = 0; i < all_peer_count; i++) {
        for (size_t j = 0; j < rapid_table_status_count; j++) {
            if (rapid_table_status[j].valid &&
                strcmp(rapid_table_status[j].address, all_peers[i].address) == 0 &&
                rapid_table_status[j].port == all_peers[i].port) {
                all_peers[i].in_rapid_table = rapid_table_status[j].in_rapid_table;
                all_peers[i].rapid_table_position = rapid_table_status[j].rapid_table_position;
                break;
            }
        }
    }
    pthread_mutex_unlock(&rapid_table_mutex);

    size_t rapid_peer_count = 0;
    for (size_t i = 0; i < all_peer_count && rapid_peer_count < *peer_count; i++) {
        if (all_peers[i].in_rapid_table) {
            memcpy(&peers[rapid_peer_count], &all_peers[i], sizeof(mxd_peer_t));
            rapid_peer_count++;
        }
    }

    *peer_count = rapid_peer_count;
    return 0;
}

int mxd_verify_signature_timestamp(uint64_t signature_timestamp) {
    uint64_t current_time = time(NULL);
    uint64_t drift = (signature_timestamp > current_time) ? 
                     (signature_timestamp - current_time) : 
                     (current_time - signature_timestamp);
    
    return (drift <= MXD_MAX_TIMESTAMP_DRIFT) ? 0 : -1;
}

int mxd_set_min_relay_signatures(uint32_t threshold) {
    if (threshold < 1) {
        return -1;
    }
    
    min_relay_signatures = threshold;
    return 0;
}

uint32_t mxd_get_min_relay_signatures(void) {
    return min_relay_signatures;
}
