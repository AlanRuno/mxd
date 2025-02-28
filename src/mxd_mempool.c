#include "../include/mxd_mempool.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Mempool storage
static mxd_mempool_entry_t *mempool = NULL;
static size_t mempool_size = 0;

// Initialize mempool
int mxd_init_mempool(void) {
  if (mempool) {
    // Clean up existing entries
    for (size_t i = 0; i < mempool_size; i++) {
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);
    }
    free(mempool);
  }
  mempool = malloc(MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  if (!mempool) {
    return -1;
  }
  memset(mempool, 0, MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  mempool_size = 0;
  return 0;
}

// Compare function for transaction sorting
static int compare_tx_entries(const void *a, const void *b) {
  const mxd_mempool_entry_t *entry_a = (const mxd_mempool_entry_t *)a;
  const mxd_mempool_entry_t *entry_b = (const mxd_mempool_entry_t *)b;

  // First compare by priority
  if (entry_a->priority != entry_b->priority) {
    return entry_b->priority - entry_a->priority;
  }

  // Then by fee (higher fee first)
  if (entry_a->fee > entry_b->fee)
    return -1;
  if (entry_a->fee < entry_b->fee)
    return 1;

  // Finally by timestamp (older first)
  if (entry_a->timestamp < entry_b->timestamp)
    return -1;
  if (entry_a->timestamp > entry_b->timestamp)
    return 1;

  return 0;
}

// Add transaction to mempool
int mxd_add_to_mempool(const mxd_transaction_t *tx,
                       mxd_tx_priority_t priority) {
  if (!tx || !mempool || priority < MXD_PRIORITY_LOW ||
      priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  // Check if mempool is full
  if (mempool_size >= MXD_MAX_MEMPOOL_SIZE) {
    return -1;
  }

  // Calculate transaction hash
  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  // Check if transaction already exists
  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t existing_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, existing_hash) == 0 &&
        memcmp(existing_hash, tx_hash, 64) == 0) {
      return -1;
    }
  }

  // Initialize new entry
  memset(&mempool[mempool_size], 0, sizeof(mxd_mempool_entry_t));

  // Copy basic transaction fields
  memcpy(&mempool[mempool_size].tx, tx, sizeof(mxd_transaction_t));
  mempool[mempool_size].tx.inputs = NULL;
  mempool[mempool_size].tx.outputs = NULL;

  // Copy inputs if present
  if (tx->inputs && tx->input_count > 0) {
    mempool[mempool_size].tx.inputs =
        malloc(tx->input_count * sizeof(mxd_tx_input_t));
    if (!mempool[mempool_size].tx.inputs) {
      return -1;
    }
    memcpy(mempool[mempool_size].tx.inputs, tx->inputs,
           tx->input_count * sizeof(mxd_tx_input_t));
  }

  // Copy outputs if present
  if (tx->outputs && tx->output_count > 0) {
    mempool[mempool_size].tx.outputs =
        malloc(tx->output_count * sizeof(mxd_tx_output_t));
    if (!mempool[mempool_size].tx.outputs) {
      free(mempool[mempool_size].tx.inputs);
      return -1;
    }
    memcpy(mempool[mempool_size].tx.outputs, tx->outputs,
           tx->output_count * sizeof(mxd_tx_output_t));
  }

  mempool[mempool_size].priority = priority;
  mempool[mempool_size].timestamp = time(NULL);
  mempool[mempool_size].fee = mxd_get_voluntary_tip(tx);

  mempool_size++;

  // Sort mempool by priority and fee
  qsort(mempool, mempool_size, sizeof(mxd_mempool_entry_t), compare_tx_entries);

  return 0;
}

// Remove transaction from mempool
int mxd_remove_from_mempool(const uint8_t tx_hash[64]) {
  if (!tx_hash || !mempool) {
    return -1;
  }

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      // Free transaction resources
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);

      // Remove by shifting remaining entries
      if (i < mempool_size - 1) {
        memmove(&mempool[i], &mempool[i + 1],
                (mempool_size - i - 1) * sizeof(mxd_mempool_entry_t));
      }
      mempool_size--;
      return 0;
    }
  }

  return -1; // Transaction not found
}

// Get transaction from mempool
int mxd_get_from_mempool(const uint8_t tx_hash[64], mxd_transaction_t *tx) {
  if (!tx_hash || !tx || !mempool) {
    return -1;
  }

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      // Copy basic fields
      memcpy(tx, &mempool[i].tx, sizeof(mxd_transaction_t));
      tx->inputs = NULL;
      tx->outputs = NULL;

      // Copy inputs if present
      if (mempool[i].tx.inputs && tx->input_count > 0) {
        tx->inputs = malloc(tx->input_count * sizeof(mxd_tx_input_t));
        if (!tx->inputs) {
          return -1;
        }
        memcpy(tx->inputs, mempool[i].tx.inputs,
               tx->input_count * sizeof(mxd_tx_input_t));
      }

      // Copy outputs if present
      if (mempool[i].tx.outputs && tx->output_count > 0) {
        tx->outputs = malloc(tx->output_count * sizeof(mxd_tx_output_t));
        if (!tx->outputs) {
          free(tx->inputs);
          return -1;
        }
        memcpy(tx->outputs, mempool[i].tx.outputs,
               tx->output_count * sizeof(mxd_tx_output_t));
      }

      return 0;
    }
  }

  return -1; // Transaction not found
}

// Get highest priority transactions
int mxd_get_priority_transactions(mxd_transaction_t *txs, size_t *tx_count,
                                  mxd_tx_priority_t min_priority) {
  if (!txs || !tx_count || !mempool || *tx_count == 0 ||
      min_priority < MXD_PRIORITY_LOW || min_priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  size_t count = 0;
  for (size_t i = 0; i < mempool_size && count < *tx_count; i++) {
    if (mempool[i].priority >= min_priority) {
      // Copy basic fields
      memcpy(&txs[count], &mempool[i].tx, sizeof(mxd_transaction_t));
      txs[count].inputs = NULL;
      txs[count].outputs = NULL;

      // Copy inputs if present
      if (mempool[i].tx.inputs && txs[count].input_count > 0) {
        txs[count].inputs =
            malloc(txs[count].input_count * sizeof(mxd_tx_input_t));
        if (!txs[count].inputs) {
          // Clean up previous transactions
          for (size_t j = 0; j < count; j++) {
            free(txs[j].inputs);
            free(txs[j].outputs);
          }
          return -1;
        }
        memcpy(txs[count].inputs, mempool[i].tx.inputs,
               txs[count].input_count * sizeof(mxd_tx_input_t));
      }

      // Copy outputs if present
      if (mempool[i].tx.outputs && txs[count].output_count > 0) {
        txs[count].outputs =
            malloc(txs[count].output_count * sizeof(mxd_tx_output_t));
        if (!txs[count].outputs) {
          free(txs[count].inputs);
          // Clean up previous transactions
          for (size_t j = 0; j < count; j++) {
            free(txs[j].inputs);
            free(txs[j].outputs);
          }
          return -1;
        }
        memcpy(txs[count].outputs, mempool[i].tx.outputs,
               txs[count].output_count * sizeof(mxd_tx_output_t));
      }

      count++;
    }
  }

  *tx_count = count;
  return 0;
}

// Clean expired transactions
int mxd_clean_mempool(uint64_t max_age) {
  if (!mempool) {
    return -1;
  }

  uint64_t current_time = time(NULL);
  size_t write_index = 0;

  for (size_t i = 0; i < mempool_size; i++) {
    if (current_time - mempool[i].timestamp <= max_age) {
      if (i != write_index) {
        // Free destination transaction resources
        free(mempool[write_index].tx.inputs);
        free(mempool[write_index].tx.outputs);

        // Copy entry
        memcpy(&mempool[write_index], &mempool[i], sizeof(mxd_mempool_entry_t));

        // Clear source pointers to prevent double free
        mempool[i].tx.inputs = NULL;
        mempool[i].tx.outputs = NULL;
      }
      write_index++;
    } else {
      // Free expired transaction resources
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);
      mempool[i].tx.inputs = NULL;
      mempool[i].tx.outputs = NULL;
    }
  }

  mempool_size = write_index;
  return 0;
}

// Get current mempool size
size_t mxd_get_mempool_size(void) { return mempool_size; }
