#ifndef MXD_UTXO_H
#define MXD_UTXO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_transaction.h"
#include <stdint.h>
#include <rocksdb/c.h>

// UTXO entry structure
typedef struct {
  uint8_t tx_hash[64];          // Transaction hash
  uint32_t output_index;        // Output index in transaction
  uint8_t owner_key[256];       // Owner's public key
  double amount;                // Amount of coins
  uint32_t required_signatures; // Number of required signatures (multi-sig)
  uint8_t *cosigner_keys;       // Array of cosigner public keys
  uint32_t cosigner_count;      // Number of cosigners
  uint8_t pubkey_hash[20];      // Hash of owner's public key for indexing
  uint8_t is_spent;             // Flag indicating if UTXO is spent
} mxd_utxo_t;

// Initialize UTXO database with persistent storage
int mxd_init_utxo_db(const char *db_path);

// Add UTXO to database
int mxd_add_utxo(const mxd_utxo_t *utxo);

// Remove UTXO from database
int mxd_remove_utxo(const uint8_t tx_hash[64], uint32_t output_index);

// Find UTXO by transaction hash and output index
int mxd_find_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                  mxd_utxo_t *utxo);

// Get UTXO by transaction hash and output index (wrapper for mxd_find_utxo)
int mxd_get_utxo(const uint8_t tx_hash[64], uint32_t output_index,
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

// Save UTXO database to disk
int mxd_save_utxo_db(void);

// Load UTXO database from disk
int mxd_load_utxo_db(void);

// Close UTXO database connection
int mxd_close_utxo_db(void);

// Verify UTXO exists and has sufficient funds
int mxd_verify_utxo_funds(const uint8_t tx_hash[64], uint32_t output_index, double amount);

// Get UTXOs by public key hash (for address balance queries)
int mxd_get_utxos_by_pubkey_hash(const uint8_t pubkey_hash[20], mxd_utxo_t **utxos, size_t *utxo_count);

// Prune spent UTXOs from database
int mxd_prune_spent_utxos(void);

// Get total UTXO count
int mxd_get_utxo_count(size_t *count);

// Get UTXO database statistics
int mxd_get_utxo_stats(size_t *total_count, size_t *pruned_count, double *total_value);

// Mark UTXO as spent
int mxd_mark_utxo_spent(const uint8_t tx_hash[64], uint32_t output_index);

// Flush UTXO database to disk (for checkpointing)
int mxd_flush_utxo_db(void);

// Compact UTXO database (optimize storage)
int mxd_compact_utxo_db(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_UTXO_H
