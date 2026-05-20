#ifndef MXD_UTXO_H
#define MXD_UTXO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_transaction.h"
#include "mxd_types.h"
#include <stdint.h>
#include <rocksdb/c.h>

// UTXO entry structure (v2 - uses addr32 per MXD-01 v1.1.x §4)
typedef struct {
  uint8_t tx_hash[64];          // Transaction hash
  uint32_t output_index;        // Output index in transaction
  uint8_t owner_key[32];        // Owner's address (SHA-512[0..31] of algo_id || pubkey)
  mxd_amount_t amount;          // Amount of coins in base units
  uint32_t required_signatures; // Number of required signatures (multi-sig)
  uint8_t *cosigner_keys;       // Array of cosigner addresses (32 bytes each)
  uint32_t cosigner_count;      // Number of cosigners
  uint8_t is_spent;             // Flag indicating if UTXO is spent
} mxd_utxo_t;

// Initialize UTXO database with persistent storage
int mxd_init_utxo_db(const char *db_path);

// Reset UTXO database (for tests only - destroys all data)
int mxd_reset_utxo_db(const char *db_path);

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

// Get total balance for an address (addr32 per MXD-01 v1.1.x §4)
mxd_amount_t mxd_get_balance(const uint8_t address[32]);

// Verify UTXO exists and is spendable (addr32 per MXD-01 v1.1.x §4)
int mxd_verify_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                    const uint8_t address[32]);

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
int mxd_verify_utxo_funds(const uint8_t tx_hash[64], uint32_t output_index, mxd_amount_t amount);

// Get UTXOs by public key hash (addr32 for address balance queries)
int mxd_get_utxos_by_pubkey_hash(const uint8_t pubkey_hash[32], mxd_utxo_t **utxos, size_t *utxo_count);

// Prune spent UTXOs from database
int mxd_prune_spent_utxos(void);

// Get total UTXO count
int mxd_get_utxo_count(size_t *count);

// Get UTXO database statistics
int mxd_get_utxo_stats(size_t *total_count, size_t *pruned_count, mxd_amount_t *total_value);

// Mark UTXO as spent
int mxd_mark_utxo_spent(const uint8_t tx_hash[64], uint32_t output_index);

// Batch variants: serialize operations into a WriteBatch without committing.
// Call mxd_utxo_commit_batch() to atomically commit all operations.
int mxd_mark_utxo_spent_to_batch(rocksdb_writebatch_t *batch,
                                  const uint8_t tx_hash[64], uint32_t output_index);
int mxd_add_utxo_to_batch(rocksdb_writebatch_t *batch, const mxd_utxo_t *utxo);
int mxd_utxo_commit_batch(rocksdb_writebatch_t *batch);

// Flush UTXO database to disk (for checkpointing)
int mxd_flush_utxo_db(void);

// Compact UTXO database (optimize storage)
int mxd_compact_utxo_db(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_UTXO_H
