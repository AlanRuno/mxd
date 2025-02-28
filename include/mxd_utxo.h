#ifndef MXD_UTXO_H
#define MXD_UTXO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_transaction.h"
#include <stdint.h>

// UTXO entry structure
typedef struct {
  uint8_t tx_hash[64];          // Transaction hash
  uint32_t output_index;        // Output index in transaction
  uint8_t owner_key[256];       // Owner's public key
  double amount;                // Amount of coins
  uint32_t required_signatures; // Number of required signatures (multi-sig)
  uint8_t *cosigner_keys;       // Array of cosigner public keys
  uint32_t cosigner_count;      // Number of cosigners
} mxd_utxo_t;

// Initialize UTXO database
int mxd_init_utxo_db(void);

// Add UTXO to database
int mxd_add_utxo(const mxd_utxo_t *utxo);

// Remove UTXO from database
int mxd_remove_utxo(const uint8_t tx_hash[64], uint32_t output_index);

// Find UTXO by transaction hash and output index
int mxd_find_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                  mxd_utxo_t *utxo);

// Get total balance for a public key
double mxd_get_balance(const uint8_t public_key[256]);

// Verify UTXO exists and is spendable
int mxd_verify_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                    const uint8_t public_key[256]);

// Create multi-signature UTXO
int mxd_create_multisig_utxo(mxd_utxo_t *utxo, const uint8_t *cosigner_keys,
                             uint32_t cosigner_count,
                             uint32_t required_signatures);

// Free UTXO resources
void mxd_free_utxo(mxd_utxo_t *utxo);

#ifdef __cplusplus
}
#endif

#endif // MXD_UTXO_H
