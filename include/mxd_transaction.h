#ifndef MXD_TRANSACTION_H
#define MXD_TRANSACTION_H

#ifdef __cplusplus
extern "C" {
#endif

// Initialize transaction validation system
int mxd_init_transaction_validation(void);

// Reset transaction validation state
void mxd_reset_transaction_validation(void);

#include <stddef.h>
#include <stdint.h>

// Maximum number of inputs/outputs per transaction
#define MXD_MAX_TX_INPUTS 256
#define MXD_MAX_TX_OUTPUTS 256

// Transaction input structure
typedef struct {
  uint8_t prev_tx_hash[64]; // Previous transaction hash (SHA-512)
  uint32_t output_index;    // Index of the output in previous transaction
  uint8_t signature[256];   // Dilithium5 signature
  uint8_t public_key[256];  // Signer's public key
} mxd_tx_input_t;

// Transaction output structure
typedef struct {
  uint8_t recipient_key[256]; // Recipient's public key
  double amount;              // Amount to transfer
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

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, double tip_amount);

// Get voluntary tip amount
double mxd_get_voluntary_tip(const mxd_transaction_t *tx);

// Free transaction resources
void mxd_free_transaction(mxd_transaction_t *tx);

#ifdef __cplusplus
}
#endif

#endif // MXD_TRANSACTION_H
