#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Internal UTXO database
static mxd_utxo_t *utxo_db = NULL;
static size_t utxo_count = 0;
static size_t utxo_capacity = 0;

// Initialize UTXO database
int mxd_init_utxo_db(void) {
  utxo_capacity = 1000; // Initial capacity
  utxo_db = malloc(utxo_capacity * sizeof(mxd_utxo_t));
  if (!utxo_db) {
    return -1;
  }
  utxo_count = 0;
  return 0;
}

// Add UTXO to database
int mxd_add_utxo(const mxd_utxo_t *utxo) {
  if (!utxo || !utxo_db) {
    return -1;
  }

  // Check if UTXO already exists
  for (size_t i = 0; i < utxo_count; i++) {
    if (memcmp(utxo_db[i].tx_hash, utxo->tx_hash, 64) == 0 &&
        utxo_db[i].output_index == utxo->output_index) {
      return -1;
    }
  }

  // Resize database if needed
  if (utxo_count >= utxo_capacity) {
    size_t new_capacity = utxo_capacity * 2;
    mxd_utxo_t *new_db = realloc(utxo_db, new_capacity * sizeof(mxd_utxo_t));
    if (!new_db) {
      return -1;
    }
    utxo_db = new_db;
    utxo_capacity = new_capacity;
  }

  // Copy UTXO data
  memcpy(&utxo_db[utxo_count], utxo, sizeof(mxd_utxo_t));

  // Allocate and copy cosigner keys if present
  if (utxo->cosigner_count > 0 && utxo->cosigner_keys) {
    utxo_db[utxo_count].cosigner_keys = malloc(utxo->cosigner_count * 256);
    if (!utxo_db[utxo_count].cosigner_keys) {
      return -1;
    }
    memcpy(utxo_db[utxo_count].cosigner_keys, utxo->cosigner_keys,
           utxo->cosigner_count * 256);
  }

  utxo_count++;
  return 0;
}

// Remove UTXO from database
int mxd_remove_utxo(const uint8_t tx_hash[64], uint32_t output_index) {
  if (!tx_hash || !utxo_db) {
    return -1;
  }

  // Find UTXO
  for (size_t i = 0; i < utxo_count; i++) {
    if (memcmp(utxo_db[i].tx_hash, tx_hash, 64) == 0 &&
        utxo_db[i].output_index == output_index) {
      // Free cosigner keys if present
      free(utxo_db[i].cosigner_keys);

      // Remove by shifting remaining entries
      if (i < utxo_count - 1) {
        memmove(&utxo_db[i], &utxo_db[i + 1],
                (utxo_count - i - 1) * sizeof(mxd_utxo_t));
      }
      utxo_count--;
      return 0;
    }
  }

  return -1; // UTXO not found
}

// Find UTXO by transaction hash and output index
int mxd_find_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                  mxd_utxo_t *utxo) {
  if (!tx_hash || !utxo || !utxo_db) {
    return -1;
  }

  for (size_t i = 0; i < utxo_count; i++) {
    if (memcmp(utxo_db[i].tx_hash, tx_hash, 64) == 0 &&
        utxo_db[i].output_index == output_index) {
      memcpy(utxo, &utxo_db[i], sizeof(mxd_utxo_t));

      // Copy cosigner keys if present
      if (utxo_db[i].cosigner_count > 0 && utxo_db[i].cosigner_keys) {
        utxo->cosigner_keys = malloc(utxo_db[i].cosigner_count * 256);
        if (!utxo->cosigner_keys) {
          return -1;
        }
        memcpy(utxo->cosigner_keys, utxo_db[i].cosigner_keys,
               utxo_db[i].cosigner_count * 256);
      }

      return 0;
    }
  }

  return -1; // UTXO not found
}

// Get total balance for a public key
double mxd_get_balance(const uint8_t public_key[256]) {
  if (!public_key || !utxo_db) {
    return -1;
  }

  double balance = 0;
  for (size_t i = 0; i < utxo_count; i++) {
    if (memcmp(utxo_db[i].owner_key, public_key, 256) == 0) {
      balance += utxo_db[i].amount;
    }
  }

  return balance;
}

// Verify UTXO exists and is spendable
int mxd_verify_utxo(const uint8_t tx_hash[64], uint32_t output_index,
                    const uint8_t public_key[256]) {
  if (!tx_hash || !public_key || !utxo_db) {
    return -1;
  }

  for (size_t i = 0; i < utxo_count; i++) {
    if (memcmp(utxo_db[i].tx_hash, tx_hash, 64) == 0 &&
        utxo_db[i].output_index == output_index) {
      // Check owner key
      if (memcmp(utxo_db[i].owner_key, public_key, 256) == 0) {
        return 0; // UTXO is spendable
      }

      // Check if public key is a cosigner
      for (uint32_t j = 0; j < utxo_db[i].cosigner_count; j++) {
        if (memcmp(utxo_db[i].cosigner_keys + (j * 256), public_key, 256) ==
            0) {
          return 0; // UTXO is spendable by cosigner
        }
      }
      return -1; // Not authorized
    }
  }

  return -1; // UTXO not found
}

// Create multi-signature UTXO
int mxd_create_multisig_utxo(mxd_utxo_t *utxo, const uint8_t *cosigner_keys,
                             uint32_t cosigner_count,
                             uint32_t required_signatures) {
  if (!utxo || !cosigner_keys || cosigner_count == 0 ||
      required_signatures == 0 || required_signatures > cosigner_count) {
    return -1;
  }

  // Allocate space for cosigner keys
  utxo->cosigner_keys = malloc(cosigner_count * 256);
  if (!utxo->cosigner_keys) {
    return -1;
  }

  // Copy cosigner keys
  memcpy(utxo->cosigner_keys, cosigner_keys, cosigner_count * 256);
  utxo->cosigner_count = cosigner_count;
  utxo->required_signatures = required_signatures;

  return 0;
}

// Free UTXO resources
void mxd_free_utxo(mxd_utxo_t *utxo) {
  if (utxo) {
    free(utxo->cosigner_keys);
    memset(utxo, 0, sizeof(mxd_utxo_t));
  }
}
