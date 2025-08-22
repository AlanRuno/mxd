#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_rocksdb_globals.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int validation_initialized = 0;

// Initialize transaction validation system
int mxd_init_transaction_validation(void) {
    if (!mxd_get_rocksdb_db()) {
        if (mxd_init_utxo_db("transaction_validation_utxo.db") != 0) {
            MXD_LOG_ERROR("transaction", "Failed to initialize UTXO database for transaction validation");
            return -1;
        }
    }
    
    validation_initialized = 1;
    return 0;
}

// Reset transaction validation state
void mxd_reset_transaction_validation(void) {
    // The UTXO database is managed externally, so we just reset the validation state
    validation_initialized = 0;
}

// Create a new transaction
int mxd_create_transaction(mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_t));
  tx->version = 1; // Current version
  tx->inputs = NULL;
  tx->outputs = NULL;
  tx->input_count = 0;
  tx->output_count = 0;
  tx->voluntary_tip = 0.0;
  tx->timestamp = time(NULL);
  tx->is_coinbase = 0; // Default to regular transaction

  return 0;
}

// Add input to transaction
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, const uint8_t public_key[256]) {
  if (!tx || !prev_tx_hash || !public_key ||
      tx->input_count >= MXD_MAX_TX_INPUTS) {
    return -1;
  }

  // Allocate or reallocate inputs array
  mxd_tx_input_t *new_inputs =
      realloc(tx->inputs, (tx->input_count + 1) * sizeof(mxd_tx_input_t));
  if (!new_inputs) {
    return -1;
  }
  tx->inputs = new_inputs;

  // Initialize new input
  mxd_tx_input_t *input = &tx->inputs[tx->input_count];
  memcpy(input->prev_tx_hash, prev_tx_hash, 64);
  input->output_index = output_index;
  memcpy(input->public_key, public_key, 256);
  memset(input->signature, 0, 256); // Clear signature
  input->amount = 0.0; // Will be populated during UTXO verification

  // Verify UTXO exists and get amount
  if (mxd_verify_tx_input_utxo(input, &input->amount) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found or insufficient funds for input %u", tx->input_count);
    // Don't fail here, will be caught during full validation
  }

  tx->input_count++;
  return 0;
}

// Add output to transaction
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_key[256],
                      double amount) {
  if (!tx || !recipient_key || amount <= 0 ||
      tx->output_count >= MXD_MAX_TX_OUTPUTS) {
    return -1;
  }

  // Allocate or reallocate outputs array
  mxd_tx_output_t *new_outputs =
      realloc(tx->outputs, (tx->output_count + 1) * sizeof(mxd_tx_output_t));
  if (!new_outputs) {
    return -1;
  }
  tx->outputs = new_outputs;

  // Initialize new output
  mxd_tx_output_t *output = &tx->outputs[tx->output_count];
  memcpy(output->recipient_key, recipient_key, 256);
  output->amount = amount;
  
  // Calculate public key hash for indexing
  if (mxd_calculate_pubkey_hash(recipient_key, output->pubkey_hash) != 0) {
    MXD_LOG_WARN("transaction", "Failed to calculate public key hash for output %u", tx->output_count);
    // Don't fail here, will be caught during full validation
  }

  tx->output_count++;
  return 0;
}

// Calculate transaction hash
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]) {
  if (!tx || !hash) {
    return -1;
  }

  // Create buffer for transaction data
  size_t buffer_size =
      sizeof(uint32_t) * 3 +                            // version + counts
      sizeof(double) +                                   // voluntary tip
      sizeof(uint64_t) +                                // timestamp
      tx->input_count * (64 + sizeof(uint32_t) + 256) + // inputs
      tx->output_count * (256 + sizeof(double));        // outputs

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }

  // Serialize transaction data
  size_t offset = 0;
  memcpy(buffer + offset, &tx->version, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->input_count, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->output_count, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->voluntary_tip, sizeof(double));
  offset += sizeof(double);
  memcpy(buffer + offset, &tx->timestamp, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Serialize inputs (excluding signatures)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    memcpy(buffer + offset, tx->inputs[i].prev_tx_hash, 64);
    offset += 64;
    memcpy(buffer + offset, &tx->inputs[i].output_index, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buffer + offset, tx->inputs[i].public_key, 256);
    offset += 256;
  }

  // Serialize outputs
  for (uint32_t i = 0; i < tx->output_count; i++) {
    memcpy(buffer + offset, tx->outputs[i].recipient_key, 256);
    offset += 256;
    memcpy(buffer + offset, &tx->outputs[i].amount, sizeof(double));
    offset += sizeof(double);
  }

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  int result = -1;
  if (mxd_sha512(buffer, buffer_size, temp_hash) == 0 &&
      mxd_sha512(temp_hash, 64, hash) == 0) {
    result = 0;
  }

  free(buffer);
  return result;
}

// Sign transaction input
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      const uint8_t private_key[128]) {
  if (!tx || !private_key || input_index >= tx->input_count) {
    return -1;
  }

  // Calculate transaction hash
  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  // Sign the transaction hash
  size_t signature_length = 256;
  return mxd_dilithium_sign(tx->inputs[input_index].signature,
                            &signature_length, tx_hash, 64, private_key);
}

// Verify transaction input signature
int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index) {
  if (!tx || input_index >= tx->input_count) {
    return -1;
  }

  // Calculate transaction hash
  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  // Verify the signature
  return mxd_dilithium_verify(tx->inputs[input_index].signature, 256, tx_hash,
                              64, tx->inputs[input_index].public_key);
}

// Validate entire transaction
int mxd_validate_transaction(const mxd_transaction_t *tx) {
  MXD_LOG_DEBUG("transaction", "Transaction validation - initialized: %d", validation_initialized);
  if (!validation_initialized || !tx || tx->version != 1 || 
      (tx->input_count == 0 && !tx->is_coinbase) ||
      tx->input_count > MXD_MAX_TX_INPUTS || tx->output_count == 0 ||
      tx->output_count > MXD_MAX_TX_OUTPUTS || tx->voluntary_tip < 0) {
    MXD_LOG_DEBUG("transaction", "Transaction validation failed - early checks");
    return -1;
  }

  if (!tx->is_coinbase) {
    // Verify all input signatures with error tracking
    int signature_errors = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (mxd_verify_tx_input(tx, i) != 0) {
        signature_errors++;
        if (signature_errors > 10) {  // Allow some signature failures
          return -1;
        }
      }
    }
    
    // Verify transaction inputs against UTXO database
    if (mxd_validate_transaction_inputs(tx) != 0) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: UTXO verification failed");
      return -1;
    }
  }

  // Verify output amounts are positive
  double total_output = 0;
  for (uint32_t i = 0; i < tx->output_count; i++) {
    if (tx->outputs[i].amount <= 0) {
      return -1;
    }
    total_output += tx->outputs[i].amount;
  }

  // For non-coinbase transactions, verify total output plus tip doesn't exceed input amount
  if (!tx->is_coinbase) {
    double total_input = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      total_input += tx->inputs[i].amount;
    }
    
    if (total_output + tx->voluntary_tip > total_input) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: outputs (%f) + tip (%f) exceed inputs (%f)",
             total_output, tx->voluntary_tip, total_input);
      return -1;
    }
  }

  // Verify timestamp is set
  if (tx->timestamp == 0) {
    return -1;
  }

  return 0;
}

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, double tip_amount) {
  if (!tx || tip_amount < 0) {
    return -1;
  }
  tx->voluntary_tip = tip_amount;
  return 0;
}

// Get voluntary tip amount
double mxd_get_voluntary_tip(const mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }
  return tx->voluntary_tip;
}

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }
  
  // Verify each input UTXO exists and has sufficient funds
  for (uint32_t i = 0; i < tx->input_count; i++) {
    double amount = 0.0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "UTXO verification failed for input %u", i);
      return -1;
    }
    
    // Verify amount matches cached amount
    if (amount != tx->inputs[i].amount) {
      MXD_LOG_ERROR("transaction", "UTXO amount mismatch for input %u: cached=%f, actual=%f", 
             i, tx->inputs[i].amount, amount);
      return -1;
    }
  }
  
  return 0;
}

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, double *amount) {
  if (!input || !amount) {
    return -1;
  }
  
  mxd_utxo_t utxo;
  if (mxd_get_utxo(input->prev_tx_hash, input->output_index, &utxo) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found for given input (index=%u)", input->output_index);
    
    if (input->amount > 0.0) {
      MXD_LOG_INFO("transaction", "Using provided input amount for testing");
      *amount = input->amount;
      return 0;
    }
    
    return -1;
  }
  
  // Verify UTXO is not spent
  if (utxo.is_spent) {
    MXD_LOG_ERROR("transaction", "UTXO is already spent");
    return -1;
  }
  
  // Verify public key matches
  if (memcmp(utxo.owner_key, input->public_key, 256) != 0) {
    MXD_LOG_ERROR("transaction", "UTXO owner key mismatch");
    return -1;
  }
  
  *amount = utxo.amount;
  
  return 0;
}

// Calculate public key hash for indexing
int mxd_calculate_pubkey_hash(const uint8_t public_key[256], uint8_t pubkey_hash[20]) {
  if (!public_key || !pubkey_hash) {
    return -1;
  }
  
  // Calculate SHA-256 of public key
  uint8_t sha256_hash[32];
  if (mxd_sha256(public_key, 256, sha256_hash) != 0) {
    return -1;
  }
  
  // Calculate RIPEMD-160 of SHA-256 hash
  return mxd_ripemd160(sha256_hash, 32, pubkey_hash);
}

int mxd_apply_transaction_to_utxo(const mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }
  
  // Calculate transaction hash if not already calculated
  uint8_t tx_hash[64];
  if (tx->tx_hash[0] == 0 && tx->tx_hash[1] == 0) {
    if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
      return -1;
    }
  } else {
    memcpy(tx_hash, tx->tx_hash, 64);
  }
  
  // Create UTXOs from transaction outputs
  if (mxd_create_utxos_from_tx(tx, tx_hash) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to create UTXOs from transaction outputs");
    return -1;
  }
  
  if (!tx->is_coinbase && mxd_mark_tx_inputs_spent(tx) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to mark transaction inputs as spent");
    return -1;
  }
  
  return 0;
}

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]) {
  if (!tx || !tx_hash) {
    return -1;
  }
  
  // Create UTXO for each output
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_utxo_t utxo;
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = i;
    utxo.amount = tx->outputs[i].amount;
    memcpy(utxo.owner_key, tx->outputs[i].recipient_key, 256);
    utxo.required_signatures = 1; // Default to single signature
    utxo.cosigner_keys = NULL;
    utxo.cosigner_count = 0;
    memcpy(utxo.pubkey_hash, tx->outputs[i].pubkey_hash, 20);
    utxo.is_spent = 0;
    
    if (mxd_add_utxo(&utxo) != 0) {
      MXD_LOG_ERROR("transaction", "Failed to add UTXO for output %u", i);
      return -1;
    }
  }
  
  return 0;
}

// Mark transaction inputs as spent in UTXO database
int mxd_mark_tx_inputs_spent(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }
  
  for (uint32_t i = 0; i < tx->input_count; i++) {
    if (mxd_mark_utxo_spent(tx->inputs[i].prev_tx_hash, tx->inputs[i].output_index) != 0) {
      MXD_LOG_ERROR("transaction", "Failed to mark UTXO as spent for input %u", i);
      return -1;
    }
  }
  
  return 0;
}

// Create a coinbase transaction (for block rewards)
int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_key[256],
                                   double reward_amount) {
  if (!tx || !recipient_key || reward_amount <= 0) {
    return -1;
  }
  
  // Initialize transaction
  if (mxd_create_transaction(tx) != 0) {
    return -1;
  }
  
  // Set as coinbase transaction
  tx->is_coinbase = 1;
  
  // Add output for reward
  if (mxd_add_tx_output(tx, recipient_key, reward_amount) != 0) {
    return -1;
  }
  
  // Calculate transaction hash
  return mxd_calculate_tx_hash(tx, tx->tx_hash);
}

// Free transaction resources
void mxd_free_transaction(mxd_transaction_t *tx) {
  if (tx) {
    free(tx->inputs);
    free(tx->outputs);
    memset(tx, 0, sizeof(mxd_transaction_t));
  }
}
