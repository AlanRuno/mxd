#ifndef MXD_VALIDATOR_MANAGEMENT_H
#define MXD_VALIDATOR_MANAGEMENT_H

#include "mxd_blockchain.h"
#include "mxd_rsc.h"
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

// Validator join request
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint8_t algo_id;                    // Signature algorithm
    uint8_t public_key[2592];           // Public key (max Dilithium5 size)
    uint16_t public_key_length;
    mxd_amount_t stake_amount;          // Declared stake
    uint64_t timestamp;                 // Request timestamp
    uint8_t signature[4627];            // Signature over request (FIPS 204 ML-DSA-87, was 4595)
    uint16_t signature_length;
} mxd_validator_join_request_t;

// Validator exit request
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint32_t exit_height;               // Height when exit takes effect
    uint64_t timestamp;
    uint8_t signature[4595];            // Signature over exit
    uint16_t signature_length;
} mxd_validator_exit_request_t;

// Validator EVICT request (op_type 0x02 in MXD-VAL-V1 domain).
// Submitted by an *active* validator (the "evictor") to remove another active
// validator (the "target") whose on-chain balance has fallen below the
// 0.10 %-of-total_supply stake threshold enforced for JOIN.
//
// SIGNED BYTES (84): domain_tag(11) || op_type=0x02(1) || target_addr32(32) ||
//                    evictor_addr32(32) || timestamp_be(8)
//
// The evictor's algo_id + public_key are carried on the wire (not in the
// signed bytes) for self-contained verifiability — receivers don't need any
// external pubkey-resolution state to validate. The addr32 binding is still
// enforced by recomputing addr32 = mxd_derive_address(algo_id, pubkey) and
// comparing to evictor_addr32 before signature verification.
typedef struct {
    uint8_t target_addr[32];            // The validator being evicted
    uint8_t evictor_addr[32];           // The active validator initiating the eviction
    uint8_t evictor_algo_id;            // Wire-only: not signed
    uint8_t evictor_public_key[2592];   // Wire-only: not signed (max Dilithium5)
    uint16_t evictor_public_key_length;
    uint64_t timestamp;
    uint8_t signature[4627];            // Evictor's signature (FIPS 204 ML-DSA-87 max)
    uint16_t signature_length;
} mxd_validator_evict_request_t;

// Pending requests pool
typedef struct {
    mxd_validator_join_request_t *join_requests;
    size_t join_count;
    size_t join_capacity;

    mxd_validator_exit_request_t *exit_requests;
    size_t exit_count;
    size_t exit_capacity;

    pthread_mutex_t mutex;
} mxd_validator_request_pool_t;

// Track validator liveness
typedef struct {
    uint8_t node_address[32];           // v6: addr32 (was [20])
    uint32_t last_active_height;        // Last height this validator was seen
    uint32_t consecutive_misses;        // Consecutive missed proposals
    uint8_t marked_for_removal;         // Flag for removal
} mxd_validator_liveness_t;

#define MXD_MAX_CONSECUTIVE_MISSES 10    // Remove after 10 missed proposals

// API functions
int mxd_init_validator_request_pool(void);
int mxd_submit_validator_join_request(const uint8_t *node_address,
                                      const uint8_t *public_key,
                                      uint16_t public_key_length,
                                      uint8_t algo_id,
                                      const uint8_t *private_key);
int mxd_submit_validator_exit_request(const uint8_t *node_address,
                                      const uint8_t *private_key,
                                      uint8_t algo_id);
int mxd_get_pending_join_requests(mxd_validator_join_request_t **requests,
                                   size_t *count);
int mxd_validate_join_request(const mxd_validator_join_request_t *request,
                              mxd_amount_t total_supply);
int mxd_clear_processed_requests(const mxd_block_t *block);
int mxd_track_validator_liveness(mxd_rapid_table_t *table, uint32_t height,
                                 const uint8_t *actual_proposer);
int mxd_get_validators_to_remove(mxd_rapid_table_t *table, uint32_t current_height,
                                 uint8_t **addresses, size_t *count);

// ===== P2P broadcast and receive for JOIN / EVICT requests =====
//
// Serialization helpers — wire format is network byte order, length-prefixed
// for variable-size fields. The serialized buffer is allocated by the
// serializer; caller must free() it.
//
// JOIN wire layout (variable length, min 149 bytes Ed25519, max ~7300 bytes Dilithium5):
//   algo_id              u8
//   node_address         u8[32]
//   public_key_length    u16 BE
//   public_key           u8[public_key_length]
//   stake_amount         u64 BE
//   timestamp            u64 BE
//   signature_length     u16 BE
//   signature            u8[signature_length]
//
// EVICT wire layout (variable):
//   target_addr          u8[32]
//   evictor_addr         u8[32]
//   evictor_algo_id      u8
//   evictor_pubkey_len   u16 BE
//   evictor_pubkey       u8[evictor_pubkey_len]
//   timestamp            u64 BE
//   signature_length     u16 BE
//   signature            u8[signature_length]
// NOTE: signed bytes remain the 84-byte payload defined on the struct
// docstring; the evictor pubkey is wire-transport only.
int mxd_serialize_join_request(const mxd_validator_join_request_t *req,
                               uint8_t **out_buf, size_t *out_len);
int mxd_deserialize_join_request(const uint8_t *buf, size_t buf_len,
                                  mxd_validator_join_request_t *req);
int mxd_serialize_evict_request(const mxd_validator_evict_request_t *req,
                                uint8_t **out_buf, size_t *out_len);
int mxd_deserialize_evict_request(const uint8_t *buf, size_t buf_len,
                                   mxd_validator_evict_request_t *req);

// Broadcast helpers. These wrap mxd_broadcast_message() with the appropriate
// MXD_MSG_VALIDATOR_{JOIN,EVICT}_REQUEST type and the serialized payload.
// Both are idempotent at the wire layer (receivers dedup by addr32 +
// timestamp via the seen-set in mxd_p2p.c) so callers may invoke repeatedly
// without ill effect.
int mxd_broadcast_validator_join_request(const mxd_validator_join_request_t *req);
int mxd_broadcast_validator_evict_request(const mxd_validator_evict_request_t *req);

// Receive-side handlers — called by the P2P dispatch when a message of the
// corresponding type arrives. Each handler: (1) deserializes, (2) checks
// the seen-set to drop duplicates, (3) validates the request, (4) appends
// to the local request pool, (5) re-broadcasts to peers as epidemic gossip.
int mxd_handle_validator_join_message(const uint8_t *payload, size_t payload_len);
int mxd_handle_validator_evict_message(const uint8_t *payload, size_t payload_len);

// Submit + broadcast an EVICT request from the locally-running validator.
// The local node MUST be in the active validator set (otherwise the EVICT
// would not be accepted by other nodes). Signs with the local node key.
// Use the _with_pubkey variant for production code paths — the simpler
// variant returns -1 because it cannot reconstruct the public key from the
// private key without an algorithm-specific derivation routine.
int mxd_submit_validator_evict_request(const uint8_t *target_addr,
                                       const uint8_t *self_addr,
                                       const uint8_t *self_private_key,
                                       uint8_t self_algo_id);

int mxd_submit_validator_evict_with_pubkey(const uint8_t *target_addr,
                                            const uint8_t *self_addr,
                                            uint8_t self_algo_id,
                                            const uint8_t *self_public_key,
                                            uint16_t self_public_key_length,
                                            const uint8_t *self_private_key);

// Validate an EVICT request: signer (evictor) is in active set, target is
// in active set, target's on-chain balance is below 0.10 % of total_supply,
// signature verifies, timestamp is within the same window used for JOIN,
// derived addr32 from pubkey matches evictor_addr32.
int mxd_validate_evict_request(const mxd_validator_evict_request_t *request,
                               const mxd_rapid_table_t *active_set,
                               mxd_amount_t total_supply);

// Drain pending EVICT requests for inclusion in a block (deep copy, caller
// frees with free()). Mirrors mxd_get_pending_join_requests.
int mxd_get_pending_evict_requests(mxd_validator_evict_request_t **requests,
                                   size_t *count);

#endif // MXD_VALIDATOR_MANAGEMENT_H
