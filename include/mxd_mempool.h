#ifndef MXD_MEMPOOL_H
#define MXD_MEMPOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_transaction.h"
#include <stdint.h>

// Maximum number of transactions in mempool
#define MXD_MAX_MEMPOOL_SIZE 10000

// Transaction priority levels
typedef enum {
  MXD_PRIORITY_LOW = 0,
  MXD_PRIORITY_MEDIUM = 1,
  MXD_PRIORITY_HIGH = 2
} mxd_tx_priority_t;

// Mempool transaction entry
typedef struct {
  mxd_transaction_t tx;       // Transaction data
  double fee;                 // Transaction fee
  mxd_tx_priority_t priority; // Transaction priority
  uint64_t timestamp;         // Entry timestamp
} mxd_mempool_entry_t;

// Initialize mempool
int mxd_init_mempool(void);

// Add transaction to mempool
int mxd_add_to_mempool(const mxd_transaction_t *tx, mxd_tx_priority_t priority);

// Remove transaction from mempool
int mxd_remove_from_mempool(const uint8_t tx_hash[64]);

// Get transaction from mempool
int mxd_get_from_mempool(const uint8_t tx_hash[64], mxd_transaction_t *tx);

// Get highest priority transactions
int mxd_get_priority_transactions(mxd_transaction_t *txs, size_t *tx_count,
                                  mxd_tx_priority_t min_priority);

// Clean expired transactions
int mxd_clean_mempool(uint64_t max_age);

// Get current mempool size
size_t mxd_get_mempool_size(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_MEMPOOL_H
