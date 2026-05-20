#include "../include/mxd_mempool.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "metrics/mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef struct {
  char peer_id[64];
  size_t tx_count;
  size_t total_size;
  time_t last_tx_time;
  size_t tx_in_last_second;
  time_t rate_window_start;
} mxd_peer_quota_t;

static mxd_mempool_entry_t *mempool = NULL;
static size_t mempool_size = 0;
static pthread_mutex_t mempool_mutex = PTHREAD_MUTEX_INITIALIZER;
static mxd_peer_quota_t *peer_quotas = NULL;
static size_t peer_quota_count = 0;
static size_t peer_quota_capacity = 0;
static pthread_mutex_t peer_quota_mutex = PTHREAD_MUTEX_INITIALIZER;

static mxd_peer_quota_t* get_or_create_peer_quota_locked(const char* peer_id) {
  if (!peer_id) {
    return NULL;
  }
  
  for (size_t i = 0; i < peer_quota_count; i++) {
    if (strcmp(peer_quotas[i].peer_id, peer_id) == 0) {
      return &peer_quotas[i];
    }
  }
  
  if (peer_quota_count >= peer_quota_capacity) {
    size_t new_capacity = peer_quota_capacity == 0 ? 16 : peer_quota_capacity * 2;
    mxd_peer_quota_t* new_quotas = realloc(peer_quotas, new_capacity * sizeof(mxd_peer_quota_t));
    if (!new_quotas) {
      return NULL;
    }
    peer_quotas = new_quotas;
    peer_quota_capacity = new_capacity;
  }
  
  mxd_peer_quota_t* quota = &peer_quotas[peer_quota_count++];
  memset(quota, 0, sizeof(mxd_peer_quota_t));
  strncpy(quota->peer_id, peer_id, sizeof(quota->peer_id) - 1);
  quota->rate_window_start = time(NULL);
  return quota;
}

static int check_and_reserve_peer_quota(const char* peer_id, size_t tx_size) {
  pthread_mutex_lock(&peer_quota_mutex);
  
  mxd_peer_quota_t* quota = get_or_create_peer_quota_locked(peer_id);
  if (!quota) {
    pthread_mutex_unlock(&peer_quota_mutex);
    return -1;
  }
  
  time_t now = time(NULL);
  
  if (now - quota->rate_window_start >= 1) {
    quota->tx_in_last_second = 0;
    quota->rate_window_start = now;
  }
  
  mxd_config_t* config = mxd_get_config();
  uint32_t max_rate = config ? config->mempool.max_tx_per_sec_per_peer : 10;
  uint32_t max_count = config ? config->mempool.max_tx_per_peer : 100;
  uint64_t max_size = config ? config->mempool.max_bytes_per_peer : (10 * 1024 * 1024);
  
  if (quota->tx_in_last_second >= max_rate) {
    mxd_metrics_increment("mempool_peer_rate_limited_total");
    pthread_mutex_unlock(&peer_quota_mutex);
    return -1;
  }
  
  if (quota->tx_count >= max_count) {
    mxd_metrics_increment("mempool_peer_quota_exceeded_total");
    pthread_mutex_unlock(&peer_quota_mutex);
    return -1;
  }
  
  if (quota->total_size + tx_size > max_size) {
    mxd_metrics_increment("mempool_peer_size_exceeded_total");
    pthread_mutex_unlock(&peer_quota_mutex);
    return -1;
  }
  
  quota->tx_count++;
  quota->total_size += tx_size;
  quota->last_tx_time = time(NULL);
  quota->tx_in_last_second++;
  
  pthread_mutex_unlock(&peer_quota_mutex);
  return 0;
}

static void release_peer_quota(const char* peer_id, size_t tx_size) {
  pthread_mutex_lock(&peer_quota_mutex);
  
  mxd_peer_quota_t* quota = get_or_create_peer_quota_locked(peer_id);
  if (!quota) {
    pthread_mutex_unlock(&peer_quota_mutex);
    return;
  }
  
  if (quota->tx_count > 0) quota->tx_count--;
  if (quota->total_size >= tx_size) quota->total_size -= tx_size;
  if (quota->tx_in_last_second > 0) quota->tx_in_last_second--;
  
  pthread_mutex_unlock(&peer_quota_mutex);
}

int mxd_init_mempool(void) {
  // Lock order: peer_quota_mutex THEN mempool_mutex
  // (consistent with mxd_add_to_mempool_with_peer which locks quota first)
  pthread_mutex_lock(&peer_quota_mutex);
  pthread_mutex_lock(&mempool_mutex);

  if (mempool) {
    for (size_t i = 0; i < mempool_size; i++) {
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);
    }
    free(mempool);
    mempool = NULL;
    mempool_size = 0;
  }

  if (peer_quotas) {
    free(peer_quotas);
  }
  peer_quotas = NULL;
  peer_quota_count = 0;
  peer_quota_capacity = 0;

  mempool = malloc(MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  if (!mempool) {
    pthread_mutex_unlock(&mempool_mutex);
    pthread_mutex_unlock(&peer_quota_mutex);
    return -1;
  }
  memset(mempool, 0, MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  mempool_size = 0;

  pthread_mutex_unlock(&mempool_mutex);
  pthread_mutex_unlock(&peer_quota_mutex);
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

static size_t calculate_tx_size(const mxd_transaction_t *tx) {
  if (!tx) {
    return 0;
  }
  
  size_t size = sizeof(mxd_transaction_t);
  size += tx->input_count * sizeof(mxd_tx_input_t);
  size += tx->output_count * sizeof(mxd_tx_output_t);
  return size;
}

static int evict_lowest_priority_tx(void) {
  if (mempool_size == 0) {
    return -1;
  }
  
  size_t lowest_idx = mempool_size - 1;
  
  free(mempool[lowest_idx].tx.inputs);
  free(mempool[lowest_idx].tx.outputs);
  
  mempool_size--;
  mxd_metrics_increment("mempool_evictions_total");
  
  return 0;
}

int mxd_add_to_mempool_with_peer(const mxd_transaction_t *tx,
                                  mxd_tx_priority_t priority,
                                  const char *peer_id) {
  if (!tx || !mempool || priority < MXD_PRIORITY_LOW ||
      priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  // SECURITY: Reject coinbase transactions from external sources.
  // Coinbase txs must only be created internally by the block proposer.
  if (tx->is_coinbase) {
    return -1;
  }

  size_t tx_size = calculate_tx_size(tx);
  
  if (peer_id && check_and_reserve_peer_quota(peer_id, tx_size) != 0) {
    return -1;
  }

  pthread_mutex_lock(&mempool_mutex);

  if (mempool_size >= MXD_MAX_MEMPOOL_SIZE) {
    if (evict_lowest_priority_tx() != 0) {
      pthread_mutex_unlock(&mempool_mutex);
      if (peer_id) release_peer_quota(peer_id, tx_size);
      return -1;
    }
  }

  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    pthread_mutex_unlock(&mempool_mutex);
    if (peer_id) release_peer_quota(peer_id, tx_size);
    return -1;
  }

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t existing_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, existing_hash) == 0 &&
        memcmp(existing_hash, tx_hash, 64) == 0) {
      pthread_mutex_unlock(&mempool_mutex);
      if (peer_id) release_peer_quota(peer_id, tx_size);
      return -1;
    }
  }

  memset(&mempool[mempool_size], 0, sizeof(mxd_mempool_entry_t));

  if (mxd_tx_deep_copy(&mempool[mempool_size].tx, tx) != 0) {
    pthread_mutex_unlock(&mempool_mutex);
    if (peer_id) release_peer_quota(peer_id, tx_size);
    return -1;
  }

  mempool[mempool_size].priority = priority;
  mempool[mempool_size].timestamp = time(NULL);
  mempool[mempool_size].fee = mxd_get_voluntary_tip(tx);

  mempool_size++;

  qsort(mempool, mempool_size, sizeof(mxd_mempool_entry_t), compare_tx_entries);

  pthread_mutex_unlock(&mempool_mutex);

  mxd_metrics_increment("mempool_transactions_added_total");

  return 0;
}

int mxd_add_to_mempool(const mxd_transaction_t *tx, mxd_tx_priority_t priority) {
  return mxd_add_to_mempool_with_peer(tx, priority, NULL);
}

int mxd_remove_from_mempool(const uint8_t tx_hash[64]) {
  if (!tx_hash || !mempool) {
    return -1;
  }

  pthread_mutex_lock(&mempool_mutex);

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);

      if (i < mempool_size - 1) {
        memmove(&mempool[i], &mempool[i + 1],
                (mempool_size - i - 1) * sizeof(mxd_mempool_entry_t));
      }
      mempool_size--;
      pthread_mutex_unlock(&mempool_mutex);
      return 0;
    }
  }

  pthread_mutex_unlock(&mempool_mutex);
  return -1;
}

int mxd_get_from_mempool(const uint8_t tx_hash[64], mxd_transaction_t *tx) {
  if (!tx_hash || !tx || !mempool) {
    return -1;
  }

  pthread_mutex_lock(&mempool_mutex);

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      if (mxd_tx_deep_copy(tx, &mempool[i].tx) != 0) {
        pthread_mutex_unlock(&mempool_mutex);
        return -1;
      }
      pthread_mutex_unlock(&mempool_mutex);
      return 0;
    }
  }

  pthread_mutex_unlock(&mempool_mutex);
  return -1;
}

int mxd_get_priority_transactions(mxd_transaction_t *txs, size_t *tx_count,
                                  mxd_tx_priority_t min_priority) {
  if (!txs || !tx_count || !mempool || *tx_count == 0 ||
      min_priority < MXD_PRIORITY_LOW || min_priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  pthread_mutex_lock(&mempool_mutex);

  size_t count = 0;
  for (size_t i = 0; i < mempool_size && count < *tx_count; i++) {
    if (mempool[i].priority >= min_priority) {
      if (mxd_tx_deep_copy(&txs[count], &mempool[i].tx) != 0) {
        for (size_t j = 0; j < count; j++) {
          mxd_free_transaction(&txs[j]);
        }
        pthread_mutex_unlock(&mempool_mutex);
        return -1;
      }
      count++;
    }
  }

  pthread_mutex_unlock(&mempool_mutex);

  *tx_count = count;
  return 0;
}

int mxd_clean_mempool(uint64_t max_age) {
  if (!mempool) {
    return -1;
  }

  pthread_mutex_lock(&mempool_mutex);

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
  pthread_mutex_unlock(&mempool_mutex);
  return 0;
}

size_t mxd_get_mempool_size(void) {
  pthread_mutex_lock(&mempool_mutex);
  size_t size = mempool_size;
  pthread_mutex_unlock(&mempool_mutex);
  return size;
}
