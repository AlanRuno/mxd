#ifndef MXD_TRANSACTION_H
#define MXD_TRANSACTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_types.h"

// Transaction types
typedef enum {
    MXD_TX_TYPE_REGULAR = 0,
    MXD_TX_TYPE_COINBASE = 1,
    MXD_TX_TYPE_CONTRACT_DEPLOY = 2,
    MXD_TX_TYPE_CONTRACT_CALL = 3,
    MXD_TX_TYPE_BRIDGE_MINT = 4,                // Bridge minting (BNB → MXD)
    MXD_TX_TYPE_BRIDGE_BURN = 5,                // Bridge burning (MXD → BNB)
    MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE = 6,     // Admin: authorize a bridge contract hash
    MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE = 7,        // Admin: revoke a bridge contract hash
    MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET = 8     // Admin: set the oracle pubkey list used for bridge mint verification
} mxd_tx_type_t;

// Minimum number of oracle signatures required to authorize an admin tx.
// 3-of-5 oracles must sign the canonical admin message — same signing body
// as bridge mint attestations. Matches authority scope to function scope:
// bridge-related governance (contract authorization, oracle set rotation)
// is controlled by the oracle committee, not the validator set. Byzantine
// fault tolerance holds with 3 sigs even if 2 oracles are offline/adversarial.
#define MXD_ADMIN_MIN_ORACLE_SIGS 3
#define MXD_ADMIN_MAX_ORACLE_SIGS 5

// Maximum number of oracle pubkeys in an UPDATE_ORACLE_SET payload.
#define MXD_MAX_ADMIN_ORACLE_PUBKEYS 16

// Maximum number of oracle signatures per bridge transaction (for N-of-M consensus)
#define MXD_MAX_BRIDGE_ORACLE_SIGS 10

// Single oracle attestation entry
typedef struct {
    uint8_t algo_id;               // MXD_SIGALG_ED25519(1) or MXD_SIGALG_DILITHIUM5(2)
    uint16_t pubkey_length;        // 32 for Ed25519, 2592 for Dilithium5
    uint8_t *pubkey;               // Dynamically allocated oracle public key
    uint16_t sig_length;           // 64 for Ed25519, 4627 for ML-DSA-87 (FIPS 204)
    uint8_t *signature;            // Dynamically allocated oracle signature
} mxd_oracle_attestation_t;

// Bridge transaction payload
typedef struct {
    uint8_t bridge_contract[64];      // Bridge contract hash
    uint8_t source_chain_id[32];      // BNB Chain ID (56 mainnet, 97 testnet)
    uint8_t source_tx_hash[32];       // BNB transaction hash
    uint64_t source_block_number;     // BNB block number
    uint8_t recipient_addr[32];       // MXD recipient address (addr32 per MXD-01 v1.1.x §4)
    mxd_amount_t amount;              // Amount to mint/burn
    uint8_t mxd_chain_id[32];        // MXD chain identifier (prevents cross-chain replay on reset)

    // Oracle attestations — one or more oracle signatures for N-of-M consensus.
    // Every node verifies ALL signatures during block validation.
    // Blocks with insufficient valid signatures are rejected.
    uint32_t oracle_count;            // Number of oracle attestations (>= min_required)
    mxd_oracle_attestation_t oracles[MXD_MAX_BRIDGE_ORACLE_SIGS];

    // Legacy single-oracle fields (kept for backward compat with in-flight v3 txs)
    uint8_t oracle_algo_id;
    uint16_t oracle_pubkey_length;
    uint8_t *oracle_pubkey;
    uint16_t oracle_sig_length;
    uint8_t *oracle_signature;
} mxd_bridge_payload_t;

// Single oracle public-key entry for UPDATE_ORACLE_SET admin payload.
// Used to store the authorized oracle pubkey list on-chain so it's
// recoverable after a node data wipe.
typedef struct {
    uint8_t algo_id;                  // MXD_SIGALG_ED25519(1) or MXD_SIGALG_DILITHIUM5(2)
    uint16_t pubkey_length;           // 32 for Ed25519, 2592 for Dilithium5
    uint8_t *pubkey;                  // Oracle public key (dynamically allocated)
} mxd_oracle_pubkey_entry_t;

// Admin transaction payload. Carries a governance operation plus 3-of-5
// oracle Dilithium5 signatures over the canonical admin message:
//   SHA-512( version(u32 BE) || type(u32 BE) || nonce(u64 BE) || op_data )
// where op_data is:
//   AUTHORIZE_BRIDGE / REVOKE_BRIDGE: bridge_contract (64 bytes)
//   UPDATE_ORACLE_SET: oracle_count(u32 BE) then
//                      per oracle: algo_id(u8) || pubkey_len(u16 BE) || pubkey
//                      then oracle_set_threshold(u32 BE)
// NONCE semantics: scoped per oracle pubkey — once a (oracle, nonce) pair
// has signed an admin tx included in a block, that pair cannot sign
// another. This prevents replay while still allowing parallel admin ops
// from different subsets of oracles.
typedef struct {
    uint64_t nonce;                                        // Replay protection
    mxd_tx_type_t op_type;                                 // Which admin op

    // AUTHORIZE_BRIDGE / REVOKE_BRIDGE payload:
    uint8_t bridge_contract[64];                           // Contract hash (64 bytes)

    // UPDATE_ORACLE_SET payload:
    uint32_t oracle_set_count;                             // Number of oracle pubkeys
    mxd_oracle_pubkey_entry_t *oracle_set;                 // Array, length = oracle_set_count
    uint32_t oracle_set_threshold;                         // K of N required for bridge mints
                                                           // (1 <= threshold <= oracle_set_count)

    // Oracle signatures over the canonical admin message. Must have at
    // least MXD_ADMIN_MIN_ORACLE_SIGS (3) entries; at most
    // MXD_ADMIN_MAX_ORACLE_SIGS (5). Each signer's pubkey must be in the
    // currently authorized oracle set (on-chain admin:oracle_set if set,
    // else config.http.bridge_oracle_pubkeys).
    uint32_t sig_count;
    mxd_oracle_attestation_t sigs[MXD_ADMIN_MAX_ORACLE_SIGS];
} mxd_admin_payload_t;

// Initialize transaction validation system
int mxd_init_transaction_validation(void);

// Reset transaction validation state
void mxd_reset_transaction_validation(void);

// Maximum number of inputs/outputs per transaction
#define MXD_MAX_TX_INPUTS 256
#define MXD_MAX_TX_OUTPUTS 256

// Transaction input structure (v2 - algo-aware)
typedef struct {
  uint8_t prev_tx_hash[64];     // Previous transaction hash (SHA-512)
  uint32_t output_index;        // Index of the output in previous transaction
  uint8_t algo_id;              // Algorithm ID (Ed25519=1, Dilithium5=2)
  uint16_t public_key_length;   // Length of public key
  uint8_t *public_key;          // Signer's public key (variable length)
  uint16_t signature_length;    // Length of signature
  uint8_t *signature;           // Signature (variable length)
  mxd_amount_t amount;          // Amount from the UTXO (cached for validation, in base units)
} mxd_tx_input_t;

// Transaction output structure (v2 - uses addr32 per MXD-01 v1.1.x §4)
typedef struct {
  uint8_t recipient_addr[32];   // Recipient's address (SHA-512[0..31] of algo_id || pubkey)
  mxd_amount_t amount;          // Amount to transfer (in base units)
} mxd_tx_output_t;

// Transaction structure (v2)
typedef struct {
  uint32_t version;             // Transaction version (= 2)
  uint32_t chain_id;            // Chain identifier per MXD-04 §3.1; e.g. MXD_CHAIN_ID_MAINNET
  uint32_t input_count;         // Number of inputs
  uint32_t output_count;        // Number of outputs
  mxd_amount_t voluntary_tip;   // Optional tip for node operators (in base units)
  uint64_t timestamp;           // Transaction timestamp (NTP synchronized, Unix seconds)
  mxd_tx_input_t *inputs;       // Array of inputs (variable-length keys/sigs)
  mxd_tx_output_t *outputs;     // Array of outputs (addr32 format)
  uint8_t tx_hash[64];          // Transaction hash (SHA-512)
  uint8_t is_coinbase;          // NOT serialized in canonical bytes; broadcast bytes only
} mxd_transaction_t;

// Extended transaction structure (v3 - bridge support)
typedef struct {
  uint32_t version;           // Transaction version (v3 for bridge support)
  mxd_tx_type_t type;         // Transaction type
  uint32_t input_count;       // Number of inputs
  uint32_t output_count;      // Number of outputs
  mxd_amount_t voluntary_tip; // Optional tip for node operators (in base units)
  uint64_t timestamp;         // Transaction timestamp (NTP synchronized, Unix seconds)
  mxd_tx_input_t *inputs;     // Array of inputs (variable-length keys/sigs)
  mxd_tx_output_t *outputs;   // Array of outputs (address20 format)

  // Type-specific payload (only one is active based on 'type' field)
  union {
    mxd_bridge_payload_t *bridge;  // For BRIDGE_MINT and BRIDGE_BURN
    mxd_admin_payload_t *admin;    // For ADMIN_* types (bridge auth + oracle set)
    // Future: add contract_deploy_t, contract_call_t
  } payload;

  uint8_t tx_hash[64];        // Transaction hash (SHA-512)
} mxd_transaction_v3_t;

// Create a new transaction
int mxd_create_transaction(mxd_transaction_t *tx);

// Add input to transaction (v2 - algo-aware)
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, uint8_t algo_id, 
                     const uint8_t *public_key, size_t pubkey_len);

// Add output to transaction (v2 - uses addr32 per MXD-01 v1.1.x §4)
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_addr[32],
                      mxd_amount_t amount);

// Sign transaction input (v2 - algo-aware)
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      uint8_t algo_id, const uint8_t *private_key);

// Verify transaction input signature
int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index);

// Calculate transaction hash
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]);

// Validate entire transaction
int mxd_validate_transaction(const mxd_transaction_t *tx);

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx);

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, mxd_amount_t *amount);

// Apply transaction to UTXO database (create outputs, mark inputs as spent)
int mxd_apply_transaction_to_utxo(const mxd_transaction_t *tx);

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]);

// Mark transaction inputs as spent in UTXO database
int mxd_mark_tx_inputs_spent(const mxd_transaction_t *tx);

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, mxd_amount_t tip_amount);

// Get voluntary tip amount
mxd_amount_t mxd_get_voluntary_tip(const mxd_transaction_t *tx);

// Peek voluntary tip from serialized transaction bytes (lightweight extraction)
int mxd_peek_voluntary_tip_from_bytes(const uint8_t *data, size_t length, mxd_amount_t *tip_out);

// Create a coinbase transaction (for block rewards, v2 - uses addr32)
int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_addr[32],
                                   mxd_amount_t reward_amount);

// Deep copy transaction (including pointer fields)
int mxd_tx_deep_copy(mxd_transaction_t *dst, const mxd_transaction_t *src);

// Serialize transaction to bytes (for P2P broadcast)
uint8_t* mxd_serialize_transaction(const mxd_transaction_t *tx, size_t *out_len);

// Deserialize transaction from bytes
int mxd_deserialize_transaction(const uint8_t *data, size_t data_len, mxd_transaction_t *tx);

// Free transaction resources
void mxd_free_transaction(mxd_transaction_t *tx);

// ========== Bridge Transaction Functions (v3) ==========

// Create a bridge mint transaction (BNB → MXD)
int mxd_create_bridge_mint_tx(mxd_transaction_v3_t *tx,
                               const mxd_bridge_payload_t *payload);

// Create a bridge burn transaction (MXD → BNB)
int mxd_create_bridge_burn_tx(mxd_transaction_v3_t *tx,
                               const uint8_t sender_addr[20],
                               mxd_amount_t burn_amount,
                               const uint8_t bridge_contract[64],
                               uint32_t dest_chain_id,
                               const uint8_t dest_recipient[20]);

// Validate bridge mint transaction (full check — used by HTTP submission path).
// Runs all checks including bridge_auth registry, daily rate limit, and oracle sigs.
int mxd_validate_bridge_mint_tx(const mxd_transaction_v3_t *tx);

// Validate bridge burn transaction (full check — used by HTTP submission path).
int mxd_validate_bridge_burn_tx(const mxd_transaction_v3_t *tx);

// Consensus-only variants: used by the block-apply path during sync/replay.
// They skip stateful policy checks (bridge_auth registry, daily rate limit,
// replay-table lookup) that depend on node-local state not carried in block
// data. Structure + oracle signature (the crypto security gate) are kept, so
// a block that reached consensus stays verifiable even if a node lost its
// admin/ratelimit state. Existing HTTP submission path still uses the full
// validators above so new live submissions get the full policy gating.
int mxd_validate_bridge_mint_tx_consensus_only(const mxd_transaction_v3_t *tx);
int mxd_validate_bridge_burn_tx_consensus_only(const mxd_transaction_v3_t *tx);

// ================= Admin transaction helpers =================
//
// Serialize the admin payload into a canonical byte buffer used as the signing
// message. Does NOT include validator signatures — the signature field is what
// validators produce over these bytes. Caller owns *out_bytes (free with free).
// Returns 0 on success, -1 on error.
int mxd_serialize_admin_payload_for_signing(const mxd_admin_payload_t *admin,
                                             uint32_t tx_version,
                                             uint8_t **out_bytes,
                                             size_t *out_len);

// Serialize a full admin transaction (payload + all signatures) for wire.
// Returns 0 on success, -1 on error. Caller owns *out_bytes.
int mxd_serialize_admin_tx(const mxd_transaction_v3_t *tx,
                            uint8_t **out_bytes, size_t *out_len);

// Deserialize admin tx wire bytes into tx_v3. Allocates tx->payload.admin
// and its inner arrays. Caller must free via mxd_free_transaction_v3.
int mxd_deserialize_admin_tx(const uint8_t *data, size_t data_len,
                              mxd_transaction_v3_t *tx);

// Validate an admin transaction: structure + 3-of-5 oracle signatures
// against the currently authorized oracle set (on-chain admin:oracle_set
// or config fallback) + nonce not previously used by any signer. Used at
// HTTP submission time. Returns 0 valid, -1 invalid.
int mxd_validate_admin_tx(const mxd_transaction_v3_t *tx);

// Consensus-only admin validator used by the block-apply path. Skips the
// nonce-reuse check (idempotent apply via RocksDB UPSERT handles
// re-processing) but still enforces structure + 3-of-5 oracle signature
// quorum.
int mxd_validate_admin_tx_consensus_only(const mxd_transaction_v3_t *tx);

// Apply an admin transaction to chain state (write bridge_auth or oracle
// set keys to RocksDB, mark nonces as used). Returns 0 on success.
int mxd_apply_admin_tx(const mxd_transaction_v3_t *tx);

// Free memory held by an admin payload (does not free the payload struct itself).
void mxd_free_admin_payload(mxd_admin_payload_t *admin);

// Load the on-chain oracle pubkey set (written by UPDATE_ORACLE_SET admin
// txs). Populates *out_set (array of entries), *out_count, and
// *out_threshold (K-of-N required for bridge mint attestation). Caller must
// free each entry's pubkey and then the array. Returns -1 if no on-chain set
// is present (caller should fall back to config-based pubkeys + config
// threshold). out_threshold may be NULL if caller doesn't need it.
int mxd_load_onchain_oracle_set(mxd_oracle_pubkey_entry_t **out_set,
                                 uint32_t *out_count,
                                 uint32_t *out_threshold);

// Queue an admin transaction for inclusion in a future block. Uses the
// same pending queue as bridge mints; block proposer dequeues and includes
// them alongside other v3 txs.
int mxd_queue_admin_tx(const mxd_transaction_v3_t *tx);

// Check if bridge transaction already processed (replay protection)
int mxd_is_bridge_tx_processed(const uint8_t source_tx_hash[32]);

// Mark bridge transaction as processed
int mxd_mark_bridge_tx_processed(const mxd_bridge_payload_t *payload,
                                  const uint8_t mxd_tx_hash[64],
                                  uint32_t block_index);

// Verify bridge contract is authorized
int mxd_is_bridge_contract_authorized(const uint8_t contract_hash[64]);

// Calculate v3 transaction hash
int mxd_calculate_tx_hash_v3(const mxd_transaction_v3_t *tx, uint8_t hash[64]);

// Validate v3 transaction
int mxd_validate_transaction_v3(const mxd_transaction_v3_t *tx);

// Free v3 transaction resources
void mxd_free_transaction_v3(mxd_transaction_v3_t *tx);

// Verify oracle signature(s) embedded in bridge payload (called by all nodes during block sync)
// Supports both legacy single-oracle and new multi-oracle N-of-M consensus.
int mxd_verify_bridge_oracle_signature(const mxd_bridge_payload_t *payload);

// Check bridge mint rate limits (daily cap + per-tx max)
int mxd_check_bridge_mint_limits(mxd_amount_t amount);

// Record a bridge mint for daily rate tracking
void mxd_record_bridge_mint(mxd_amount_t amount);

// Get MXD chain ID for signed message (derived from genesis block hash)
int mxd_get_chain_id(uint8_t chain_id[32]);

// Serialize v3 transaction for block storage
uint8_t* mxd_serialize_transaction_v3_for_block(const mxd_transaction_v3_t *tx, size_t *out_len);

// Deserialize v3 transaction from block storage format
int mxd_deserialize_transaction_v3_from_block(const uint8_t *data, size_t data_len,
                                               mxd_transaction_v3_t *tx);

// Add v3 transaction to current block being proposed
int mxd_add_transaction_v3_to_block(const mxd_transaction_v3_t *tx);

// Apply v3 transaction to UTXO database
int mxd_apply_transaction_v3_to_utxo(const mxd_transaction_v3_t *tx);

// Deep copy bridge payload (including dynamic oracle credential allocations)
int mxd_bridge_payload_deep_copy(mxd_bridge_payload_t *dst, const mxd_bridge_payload_t *src);

// Free bridge payload dynamic fields (oracle_pubkey, oracle_signature)
void mxd_free_bridge_payload(mxd_bridge_payload_t *payload);

// ========== Bridge Pending Queue ==========

// Maximum pending bridge transactions awaiting block inclusion
#define MXD_MAX_PENDING_BRIDGE_TXS 256

// Queue a validated bridge mint for inclusion in the next block
int mxd_queue_bridge_mint(const mxd_transaction_v3_t *tx);

// Dequeue up to max_count pending bridge mints (caller must free via mxd_free_transaction_v3)
int mxd_dequeue_bridge_mints(mxd_transaction_v3_t *out, size_t max_count, size_t *out_count);

// Get number of pending bridge mints
size_t mxd_pending_bridge_count(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_TRANSACTION_H
