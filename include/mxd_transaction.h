#ifndef MXD_TRANSACTION_H
#define MXD_TRANSACTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_utxo.h"

// Initialize transaction validation system
int mxd_init_transaction_validation(void);

// Reset transaction validation state
void mxd_reset_transaction_validation(void);

// Maximum number of inputs/outputs per transaction
#define MXD_MAX_TX_INPUTS 256
#define MXD_MAX_TX_OUTPUTS 256

// Transaction input structure
typedef struct {
  uint8_t prev_tx_hash[64]; // Previous transaction hash (SHA-512)
  uint32_t output_index;    // Index of the output in previous transaction
  uint8_t signature[256];   // Dilithium5 signature
  uint8_t public_key[256];  // Signer's public key
  double amount;            // Amount from the UTXO (cached for validation)
} mxd_tx_input_t;

// Transaction output structure
typedef struct {
  uint8_t recipient_key[256]; // Recipient's public key
  double amount;              // Amount to transfer
  uint8_t pubkey_hash[20];    // Hash of recipient's public key (for indexing)
} mxd_tx_output_t;

// Transaction structure
typedef struct {
  uint32_t version;         // Transaction version
  uint32_t input_count;     // Number of inputs
  uint32_t output_count;    // Number of outputs
  double voluntary_tip;     // Optional tip for node operators
  uint64_t timestamp;       // Transaction timestamp (NTP synchronized)
  mxd_tx_input_t *inputs;   // Array of inputs
  mxd_tx_output_t *outputs; // Array of outputs
  uint8_t tx_hash[64];      // Transaction hash (SHA-512)
  uint8_t is_coinbase;      // Flag indicating if this is a coinbase transaction
} mxd_transaction_t;

// Create a new transaction
int mxd_create_transaction(mxd_transaction_t *tx);

// Add input to transaction
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, const uint8_t public_key[256]);

// Add output to transaction
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_key[256],
                      double amount);

// Sign transaction input
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      const uint8_t private_key[128]);

// Verify transaction input signature
int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index);

// Calculate transaction hash
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]);

// Validate entire transaction
int mxd_validate_transaction(const mxd_transaction_t *tx);

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx);

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, double *amount);

// Calculate public key hash for indexing
int mxd_calculate_pubkey_hash(const uint8_t public_key[256], uint8_t pubkey_hash[20]);

// Apply transaction to UTXO database (create outputs, mark inputs as spent)
int mxd_apply_transaction_to_utxo(const mxd_transaction_t *tx);

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]);

// Mark transaction inputs as spent in UTXO database
int mxd_mark_tx_inputs_spent(const mxd_transaction_t *tx);

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, double tip_amount);

// Get voluntary tip amount
double mxd_get_voluntary_tip(const mxd_transaction_t *tx);

// Create a coinbase transaction (for block rewards)
int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_key[256],
                                   double reward_amount);

// Free transaction resources
void mxd_free_transaction(mxd_transaction_t *tx);

#ifdef __cplusplus
}
#endif

#endif // MXD_TRANSACTION_H
