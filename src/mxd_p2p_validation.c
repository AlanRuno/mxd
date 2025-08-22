#include "mxd_logging.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mxd_blockchain.h"
#include "mxd_crypto.h"
#include "mxd_p2p.h"
#include "mxd_rsc.h"

int mxd_should_relay_block(const mxd_block_t *block, int just_signed) {
    if (!block) return 0;
    if (just_signed) return 1;
    if (mxd_verify_validation_chain(block) != 0) return 0;
    return mxd_block_has_min_relay_signatures(block);
}

#define MXD_MIN_RELAY_SIGNATURES 3

#define MXD_MAX_TIMESTAMP_DRIFT 60

static uint32_t min_relay_signatures = MXD_MIN_RELAY_SIGNATURES;

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
                                 const uint8_t *block_hash, const uint8_t *signature,
                                 uint16_t signature_length, uint32_t chain_position) {
    if (!address || !block_hash || !signature) {
        return -1;
    }
    if (signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    struct {
        uint8_t block_hash[64];
        uint16_t signature_length;
        uint8_t signature[MXD_SIGNATURE_MAX];
        uint32_t chain_position;
        uint64_t timestamp;
    } validation_msg;
    
    memcpy(validation_msg.block_hash, block_hash, 64);
    validation_msg.signature_length = signature_length;
    memcpy(validation_msg.signature, signature, signature_length);
    validation_msg.chain_position = chain_position;
    validation_msg.timestamp = time(NULL);

    size_t msg_len = sizeof(validation_msg.block_hash)
                   + sizeof(validation_msg.signature_length)
                   + signature_length
                   + sizeof(validation_msg.chain_position)
                   + sizeof(validation_msg.timestamp);
    
    return mxd_send_message(address, port, MXD_MSG_VALIDATION_SIGNATURE, 
                           &validation_msg, msg_len);
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
    
    mxd_peer_t peer;
    if (mxd_get_peer(address, port, &peer) != 0) {
        return -1;
    }
    
    peer.in_rapid_table = in_rapid_table;
    peer.rapid_table_position = position;
    
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
