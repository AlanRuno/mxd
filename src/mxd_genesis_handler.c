#include "../include/mxd_rsc.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_endian.h"
#include <string.h>
#include <stdlib.h>

void mxd_genesis_message_handler(const char *address, uint16_t port,
                                  mxd_message_type_t type,
                                  const void *payload,
                                  size_t payload_length) {
    MXD_LOG_INFO("genesis", "Genesis handler invoked: type=%d len=%zu from %s:%u", 
                 type, payload_length, address, port);
    switch (type) {
        case MXD_MSG_GENESIS_ANNOUNCE: {
            // v6 wire format: algo_id(1) + node_address(32) + pubkey_len(2) + ... + sig_len(2)
            if (payload_length < 1 + 32 + 2 + 8 + 2) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_ANNOUNCE message size: %zu (min: %zu)",
                             payload_length, (size_t)(1 + 32 + 2 + 8 + 2));
                return;
            }

            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;

            uint8_t algo_id = data[offset];
            offset += 1;

            if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
                MXD_LOG_WARN("genesis", "Invalid algorithm ID: %u", algo_id);
                return;
            }

            const uint8_t *node_address = data + offset;
            offset += 32;   // v6: addr32
            
            uint16_t pubkey_len_net;
            memcpy(&pubkey_len_net, data + offset, 2);
            uint16_t pubkey_len = ntohs(pubkey_len_net);
            offset += 2;
            
            size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
            if (pubkey_len != expected_pubkey_len) {
                MXD_LOG_WARN("genesis", "Invalid pubkey length %u for algo %u (expected %zu)", 
                             pubkey_len, algo_id, expected_pubkey_len);
                return;
            }
            
            if (payload_length < offset + pubkey_len + 8 + 2) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_ANNOUNCE message size for algo %u", algo_id);
                return;
            }
            
            const uint8_t *public_key = data + offset;
            offset += pubkey_len;
            
            uint64_t timestamp_net;
            memcpy(&timestamp_net, data + offset, 8);
            uint64_t timestamp = mxd_ntohll(timestamp_net);
            offset += 8;
            
            uint16_t sig_len_net;
            memcpy(&sig_len_net, data + offset, 2);
            uint16_t sig_len = ntohs(sig_len_net);
            offset += 2;
            
            if (offset + sig_len > payload_length) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_ANNOUNCE signature length: %u (remaining: %zu)", 
                             sig_len, payload_length - offset);
                return;
            }
            
            const uint8_t *signature = data + offset;
            
            MXD_LOG_INFO("genesis", "Parsed genesis announce: algo=%u, pubkey_len=%u, timestamp=%lu, sig_len=%u",
                         algo_id, pubkey_len, timestamp, sig_len);
            
            mxd_handle_genesis_announce(algo_id, node_address, public_key, pubkey_len, timestamp, signature, sig_len);
            break;
        }
        
        case MXD_MSG_GENESIS_SIGN_REQUEST: {
            // v6 wire format: target_address(32) + membership_digest(64) + proposer_id(32) + height(4) + member_count(1) + ...
            if (payload_length < 32 + 64 + 32 + 4 + 1) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_REQUEST message size: %zu (min: %zu)",
                             payload_length, (size_t)(32 + 64 + 32 + 4 + 1));
                return;
            }

            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;

            const uint8_t *target_address = data + offset;
            offset += 32;
            const uint8_t *membership_digest = data + offset;
            offset += 64;
            const uint8_t *proposer_id = data + offset;
            offset += 32;
            uint32_t height;
            memcpy(&height, data + offset, 4);
            offset += 4;

            uint8_t member_count = data[offset];
            offset += 1;

            if (member_count == 0 || member_count > 10) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_REQUEST member count: %u", member_count);
                return;
            }

            mxd_genesis_member_t *members = calloc(member_count, sizeof(mxd_genesis_member_t));
            if (!members) {
                MXD_LOG_ERROR("genesis", "Failed to allocate memory for genesis members");
                return;
            }

            for (uint8_t i = 0; i < member_count; i++) {
                if (offset + 32 + 1 + 2 > payload_length) {
                    MXD_LOG_WARN("genesis", "GENESIS_SIGN_REQUEST truncated at member %u", i);
                    free(members);
                    return;
                }

                memcpy(members[i].node_address, data + offset, 32);
                offset += 32;
                
                members[i].algo_id = data[offset];
                offset += 1;
                
                uint16_t pubkey_len_net;
                memcpy(&pubkey_len_net, data + offset, 2);
                uint16_t pubkey_len = ntohs(pubkey_len_net);
                offset += 2;
                
                size_t expected_pubkey_len = mxd_sig_pubkey_len(members[i].algo_id);
                if (pubkey_len != expected_pubkey_len) {
                    MXD_LOG_WARN("genesis", "Invalid pubkey length %u for member %u algo %u (expected %zu)", 
                                 pubkey_len, i, members[i].algo_id, expected_pubkey_len);
                    free(members);
                    return;
                }
                
                if (offset + pubkey_len > payload_length) {
                    MXD_LOG_WARN("genesis", "GENESIS_SIGN_REQUEST truncated at member %u pubkey", i);
                    free(members);
                    return;
                }
                
                memcpy(members[i].public_key, data + offset, pubkey_len);
                offset += pubkey_len;
            }
            
            MXD_LOG_INFO("genesis", "Parsed genesis sign request with %u members", member_count);
            
            mxd_handle_genesis_sign_request(target_address, membership_digest, proposer_id, height, members, member_count);
            free(members);
            break;
        }
        
        case MXD_MSG_GENESIS_SIGN_RESPONSE: {
            // v6 response format: signer_address(32) + proposer_id(32) + membership_digest(64) + sig_len(2) + signature
            if (payload_length < 32 + 32 + 64 + 2) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_RESPONSE message size");
                return;
            }

            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;

            const uint8_t *signer_address = data + offset;
            offset += 32;
            const uint8_t *proposer_id = data + offset;
            offset += 32;
            const uint8_t *membership_digest = data + offset;
            offset += 64;
            uint16_t sig_len;
            memcpy(&sig_len, data + offset, 2);
            sig_len = ntohs(sig_len);
            offset += 2;
            
            if (offset + sig_len > payload_length) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_RESPONSE signature length");
                return;
            }
            
            const uint8_t *signature = data + offset;
            
            mxd_handle_genesis_sign_response(signer_address, proposer_id, membership_digest, signature, sig_len);
            break;
        }
        
        case MXD_MSG_GENESIS_SYNC: {
            // v6 message format: [node_address(32)] [member_count(4)] [member_list_hash(64)] [timestamp(8)]
            if (payload_length < 32 + 4 + 64 + 8) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SYNC message size: %zu (expected: %zu)",
                             payload_length, (size_t)(32 + 4 + 64 + 8));
                return;
            }

            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;

            const uint8_t *node_address = data + offset;
            offset += 32;
            
            uint32_t member_count_net;
            memcpy(&member_count_net, data + offset, 4);
            uint32_t member_count = ntohl(member_count_net);
            offset += 4;
            
            const uint8_t *member_list_hash = data + offset;
            offset += 64;
            
            uint64_t timestamp_net;
            memcpy(&timestamp_net, data + offset, 8);
            uint64_t timestamp = mxd_ntohll(timestamp_net);
            
            MXD_LOG_INFO("genesis", "Received genesis sync: member_count=%u", member_count);
            
            mxd_handle_genesis_sync(node_address, member_count, member_list_hash, timestamp);
            break;
        }
        
        default:
            break;
    }
}
