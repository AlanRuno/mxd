#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_domain_tags.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_config.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_chain.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include "../include/mxd_error.h"

static int validation_initialized = 0;

// Initialize transaction validation system
int mxd_init_transaction_validation(void) {
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("transaction", "UTXO database not initialized - must be initialized before transaction validation");
        return -1;
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
  tx->version = 2;
  tx->chain_id = mxd_get_configured_chain_id();
  tx->inputs = NULL;
  tx->outputs = NULL;
  tx->input_count = 0;
  tx->output_count = 0;
  tx->voluntary_tip = 0;
  tx->timestamp = (uint64_t)time(NULL);
  tx->is_coinbase = 0;

  return 0;
}

// Add input to transaction (v2 - algo-aware)
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, uint8_t algo_id,
                     const uint8_t *public_key, size_t pubkey_len) {
  if (!tx || !prev_tx_hash || !public_key ||
      tx->input_count >= MXD_MAX_TX_INPUTS) {
    return -1;
  }

  mxd_tx_input_t *new_inputs =
      realloc(tx->inputs, (tx->input_count + 1) * sizeof(mxd_tx_input_t));
  if (!new_inputs) {
    return -1;
  }
  tx->inputs = new_inputs;

  mxd_tx_input_t *input = &tx->inputs[tx->input_count];
  memset(input, 0, sizeof(mxd_tx_input_t));
  memcpy(input->prev_tx_hash, prev_tx_hash, 64);
  input->output_index = output_index;
  input->algo_id = algo_id;
  input->public_key_length = (uint16_t)pubkey_len;
  
  input->public_key = malloc(pubkey_len);
  if (!input->public_key) {
    return -1;
  }
  memcpy(input->public_key, public_key, pubkey_len);
  
  input->signature = NULL;
  input->signature_length = 0;
  input->amount = 0.0;

  if (mxd_verify_tx_input_utxo(input, &input->amount) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found or insufficient funds for input %u", tx->input_count);
  }

  tx->input_count++;
  return 0;
}

// Add output to transaction (v2 - uses addr32 per MXD-01 v1.1.x §4)
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_addr[32],
                      mxd_amount_t amount) {
  if (!tx || !recipient_addr || amount == 0 ||
      tx->output_count >= MXD_MAX_TX_OUTPUTS) {
    return -1;
  }

  mxd_tx_output_t *new_outputs =
      realloc(tx->outputs, (tx->output_count + 1) * sizeof(mxd_tx_output_t));
  if (!new_outputs) {
    return -1;
  }
  tx->outputs = new_outputs;

  mxd_tx_output_t *output = &tx->outputs[tx->output_count];
  memcpy(output->recipient_addr, recipient_addr, 32);
  output->amount = amount;

  tx->output_count++;
  return 0;
}

// Calculate transaction hash (MXD-04 v1.1.x §7 — MXD-TX-V1 sighash)
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]) {
  if (!tx || !hash) return -1;

  static const char domain_tag[] = "MXD-TX-V1\0";  // 10 bytes incl. NUL
  static const size_t domain_tag_len = 10;

  // Compute canonical buffer size: domain_tag + header + inputs (no sigs) + outputs (addr32)
  size_t buffer_size = domain_tag_len
      + 4   // version
      + 4   // chain_id  (NEW per MXD-04 §3.1)
      + 4   // input_count
      + 4   // output_count
      + 8   // voluntary_tip
      + 8;  // timestamp

  for (uint32_t i = 0; i < tx->input_count; i++) {
    buffer_size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length;
  }
  buffer_size += tx->output_count * (32 + 8);  // 32-byte recipient per MXD-01 v1.1.x §4

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) return -1;
  uint8_t *ptr = buffer;

  memcpy(ptr, domain_tag, domain_tag_len);
  ptr += domain_tag_len;

  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, tx->chain_id);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);

  // Serialize inputs (signatures excluded from sighash)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
  }

  // Serialize outputs with 32-byte recipient addresses
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 32);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  // Double SHA-512 over (domain_tag || canonical_bytes)
  uint8_t temp[64];
  int rc = -1;
  if (mxd_sha512(buffer, buffer_size, temp) == 0 &&
      mxd_sha512(temp, 64, hash) == 0) {
    rc = 0;
  }
  free(buffer);
  return rc;
}

// Sign transaction input
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      uint8_t algo_id, const uint8_t *private_key) {
  if (!tx || !private_key || input_index >= tx->input_count) {
    return -1;
  }

  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  mxd_tx_input_t *input = &tx->inputs[input_index];
  size_t sig_len = mxd_sig_signature_len(algo_id);
  
  if (input->signature) {
    free(input->signature);
  }
  input->signature = malloc(sig_len);
  if (!input->signature) {
    return -1;
  }

  size_t actual_sig_len = sig_len;
  if (mxd_sig_sign(algo_id, input->signature, &actual_sig_len, tx_hash, 64, private_key) != 0) {
    free(input->signature);
    input->signature = NULL;
    return -1;
  }
  
  input->signature_length = (uint16_t)actual_sig_len;
  return 0;
}

int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index) {
  if (!tx || input_index >= tx->input_count) {
    return -1;
  }

  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  const mxd_tx_input_t *input = &tx->inputs[input_index];
  if (!input->signature || input->signature_length == 0) {
    return -1;
  }

  return mxd_sig_verify(input->algo_id, input->signature, input->signature_length,
                        tx_hash, 64, input->public_key);
}

int mxd_validate_transaction(const mxd_transaction_t *tx) {
  MXD_LOG_DEBUG("transaction", "Transaction validation - initialized: %d", validation_initialized);
  if (!validation_initialized || !tx || tx->version != 2 ||
      (tx->input_count == 0 && !tx->is_coinbase) ||
      tx->input_count > MXD_MAX_TX_INPUTS || tx->output_count == 0 ||
      tx->output_count > MXD_MAX_TX_OUTPUTS) {
    MXD_LOG_DEBUG("transaction", "Transaction validation failed - early checks");
    return -1;
  }

  // Per MXD-04 §11: reject transactions whose chain_id doesn't match this node
  if (tx->chain_id != mxd_get_configured_chain_id()) {
    MXD_LOG_ERROR("transaction", "chain_id mismatch: got 0x%08x, expected 0x%08x",
                  tx->chain_id, mxd_get_configured_chain_id());
    return -1;
  }

  if (!tx->is_coinbase) {
    // SECURITY: Check for duplicate inputs (same UTXO referenced twice)
    // This prevents a double-spend attack where the same UTXO's amount
    // is counted multiple times, allowing money creation from nothing.
    for (uint32_t i = 0; i < tx->input_count; i++) {
      for (uint32_t j = i + 1; j < tx->input_count; j++) {
        if (memcmp(tx->inputs[i].prev_tx_hash, tx->inputs[j].prev_tx_hash, 64) == 0 &&
            tx->inputs[i].output_index == tx->inputs[j].output_index) {
          MXD_LOG_ERROR("transaction", "Duplicate input detected: inputs %u and %u reference the same UTXO", i, j);
          return -1;
        }
      }
    }

    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (mxd_verify_tx_input(tx, i) != 0) {
        MXD_LOG_ERROR("transaction", "Invalid signature on input %u", i);
        return -1;
      }
    }

    // Verify transaction inputs against UTXO database
    if (mxd_validate_transaction_inputs(tx) != 0) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: UTXO verification failed");
      return -1;
    }
  }

  // Verify output amounts are positive and calculate total using integer arithmetic
  // to ensure consensus-critical calculations are deterministic across platforms
  mxd_amount_t total_output = 0;
  for (uint32_t i = 0; i < tx->output_count; i++) {
    if (tx->outputs[i].amount == 0) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output %u has zero amount", i);
      return -1;
    }
    // Check for overflow before adding
    if (total_output > UINT64_MAX - tx->outputs[i].amount) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output sum overflow");
      return -1;
    }
    total_output += tx->outputs[i].amount;
  }

  // For non-coinbase transactions, verify total output plus tip doesn't exceed input amount
  if (!tx->is_coinbase) {
    mxd_amount_t total_input = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      // Check for overflow before adding
      if (total_input > UINT64_MAX - tx->inputs[i].amount) {
        MXD_LOG_ERROR("transaction", "Transaction validation failed: input sum overflow");
        return -1;
      }
      total_input += tx->inputs[i].amount;
    }
    
    // Check for overflow when adding tip to outputs
    if (total_output > UINT64_MAX - tx->voluntary_tip) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output + tip overflow");
      return -1;
    }
    
    if (total_output + tx->voluntary_tip > total_input) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: outputs (%lu) + tip (%lu) exceed inputs (%lu)",
             (unsigned long)total_output, (unsigned long)tx->voluntary_tip, (unsigned long)total_input);
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
int mxd_set_voluntary_tip(mxd_transaction_t *tx, mxd_amount_t tip_amount) {
  if (!tx) {
    return -1;
  }
  tx->voluntary_tip = tip_amount;
  return 0;
}

// Get voluntary tip amount
mxd_amount_t mxd_get_voluntary_tip(const mxd_transaction_t *tx) {
  if (!tx) {
    return 0;
  }
  return tx->voluntary_tip;
}

int mxd_peek_voluntary_tip_from_bytes(const uint8_t *data, size_t length, mxd_amount_t *tip_out) {
  if (!data || !tip_out) {
    return -1;
  }

  // New wire format: version(4) + chain_id(4) + input_count(4) + output_count(4) + tip(8) + ...
  const size_t header_min = sizeof(uint32_t) * 4 + sizeof(uint64_t);

  if (length < header_min) {
    return -1;
  }

  // Serialization uses big-endian (mxd_write_u32_be / mxd_write_u64_be),
  // so deserialization must also convert from big-endian.
  const uint8_t *ptr = data;
  uint32_t version = mxd_read_u32_be(&ptr);

  if (version != 2) {
    return -1;
  }

  // Skip chain_id, input_count, output_count (3 x u32)
  ptr += sizeof(uint32_t) * 3;

  *tip_out = mxd_read_u64_be(&ptr);

  return 0;
}

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }

  // Verify each input UTXO exists and populate the cached amount from the
  // authoritative on-chain value. The wire format doesn't carry input
  // amounts (mxd_serialize_transaction doesn't write them), so after
  // deserialization tx->inputs[i].amount is 0 until this function fills it.
  // For callers that do pre-populate (e.g. during block reprocessing), we
  // verify consistency with the on-chain UTXO.
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_amount_t amount = 0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "UTXO verification failed for input %u", i);
      return -1;
    }

    if (tx->inputs[i].amount == 0) {
      // Fresh from wire — populate from UTXO lookup (authoritative).
      // Cast away const on the inner field: the outer tx is const but the
      // `inputs` pointer points to mutable mxd_tx_input_t memory.
      ((mxd_tx_input_t *)&tx->inputs[i])->amount = amount;
    } else if (tx->inputs[i].amount != amount) {
      // Caller pre-populated with a wrong value — tamper attempt or bug.
      MXD_LOG_ERROR("transaction", "UTXO amount mismatch for input %u: cached=%lu, actual=%lu",
             i, tx->inputs[i].amount, amount);
      return -1;
    }
  }

  return 0;
}

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, mxd_amount_t *amount) {
  if (!input || !amount) {
    return -1;
  }
  
  mxd_utxo_t utxo;
  if (mxd_get_utxo(input->prev_tx_hash, input->output_index, &utxo) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found for given input (index=%u)", input->output_index);
    return -1;
  }
  
  // Verify UTXO is not spent
  if (utxo.is_spent) {
    MXD_LOG_ERROR("transaction", "UTXO is already spent");
    return -1;
  }
  
  uint8_t input_addr[MXD_ADDR32_LEN];
  if (mxd_derive_address(input->algo_id, input->public_key, input->public_key_length, input_addr) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to derive address from input public key");
    return -1;
  }
  if (memcmp(utxo.owner_key, input_addr, 32) != 0) {
    MXD_LOG_ERROR("transaction", "UTXO owner address mismatch");
    return -1;
  }
  
  *amount = utxo.amount;
  
  return 0;
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

  // SECURITY: Use a single WriteBatch for all input-spent marks and output-UTXO
  // creates. This ensures atomicity: if the process crashes mid-way, either all
  // changes are applied or none are, preventing fund loss from partially applied
  // transactions (inputs spent but outputs not created).
  rocksdb_writebatch_t *batch = rocksdb_writebatch_create();
  if (!batch) {
    return -1;
  }

  // Mark inputs as spent FIRST (validates they exist and are unspent)
  if (!tx->is_coinbase) {
    for (uint32_t i = 0; i < tx->input_count; i++) {
      int ret = mxd_mark_utxo_spent_to_batch(batch, tx->inputs[i].prev_tx_hash, tx->inputs[i].output_index);
      if (ret != 0) {
        MXD_LOG_ERROR("transaction", "Failed to mark UTXO as spent for input %u", i);
        rocksdb_writebatch_destroy(batch);
        return (ret == MXD_ERR_IO) ? MXD_ERR_IO : MXD_ERR_GENERIC;
      }
    }
  }

  // Add output UTXOs to the same batch
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_utxo_t utxo;
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = i;
    utxo.amount = tx->outputs[i].amount;
    memcpy(utxo.owner_key, tx->outputs[i].recipient_addr, 32);
    utxo.required_signatures = 1;
    utxo.cosigner_keys = NULL;
    utxo.cosigner_count = 0;
    utxo.is_spent = 0;

    if (mxd_add_utxo_to_batch(batch, &utxo) != 0) {
      MXD_LOG_ERROR("transaction", "Failed to add UTXO for output %u to batch", i);
      rocksdb_writebatch_destroy(batch);
      return MXD_ERR_GENERIC;
    }
  }

  // Atomically commit all changes
  int ret = mxd_utxo_commit_batch(batch);
  rocksdb_writebatch_destroy(batch);
  if (ret != 0) {
    MXD_LOG_ERROR("transaction", "Failed to commit UTXO batch");
    return ret;
  }

  return 0;
}

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]) {
  if (!tx || !tx_hash) {
    return -1;
  }
  
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_utxo_t utxo;
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = i;
    utxo.amount = tx->outputs[i].amount;
    memcpy(utxo.owner_key, tx->outputs[i].recipient_addr, 32);
    utxo.required_signatures = 1;
    utxo.cosigner_keys = NULL;
    utxo.cosigner_count = 0;
    utxo.is_spent = 0;
    
    int ret = mxd_add_utxo(&utxo);
    if (ret == MXD_ERR_IO) return MXD_ERR_IO;  // IO error - halt
    if (ret != 0) {
      MXD_LOG_ERROR("transaction", "Failed to add UTXO for output %u", i);
      return MXD_ERR_GENERIC;
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
    int ret = mxd_mark_utxo_spent(tx->inputs[i].prev_tx_hash, tx->inputs[i].output_index);
    if (ret == MXD_ERR_IO) return MXD_ERR_IO;  // IO error - halt
    if (ret != 0) {
      MXD_LOG_ERROR("transaction", "Failed to mark UTXO as spent for input %u", i);
      return MXD_ERR_GENERIC;  // not found/spent - skip tx
    }
  }
  
  return 0;
}

// Serialize transaction to bytes for P2P broadcast (MXD-04 v1.1.x wire format)
// Format: version(u32) | chain_id(u32) | input_count(u32) | output_count(u32) |
//         voluntary_tip(u64) | timestamp(u64) | tx_hash(64) |
//         inputs... | outputs(addr32 + amount)...
// is_coinbase is NOT on the wire; recovered as (input_count == 0).
// tx_hash is a non-authoritative pre-parse dedup hint (MXD-04 §10.1).
// Callers MUST call mxd_calculate_tx_hash before this function so the field is populated.
uint8_t* mxd_serialize_transaction(const mxd_transaction_t *tx, size_t *out_len) {
  if (!tx || !out_len) return NULL;

  // Calculate total size: version + chain_id + input_count + output_count + tip + timestamp + tx_hash
  size_t size = 4 + 4 + 4 + 4 + 8 + 8 + 64;

  for (uint32_t i = 0; i < tx->input_count; i++) {
    size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length + 2 + tx->inputs[i].signature_length;
  }

  for (uint32_t i = 0; i < tx->output_count; i++) {
    size += 32 + 8;  // addr32 + amount
  }

  uint8_t *buffer = malloc(size);
  if (!buffer) return NULL;

  uint8_t *ptr = buffer;
  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, tx->chain_id);         // chain_id per MXD-04 §3.1
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);
  // is_coinbase NOT written — recovered as (input_count == 0) on deserialize
  mxd_write_bytes(&ptr, tx->tx_hash, 64);  // pre-parse dedup hint per MXD-04 §10.1

  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
    mxd_write_u16_be(&ptr, tx->inputs[i].signature_length);
    if (tx->inputs[i].signature_length > 0 && tx->inputs[i].signature) {
      mxd_write_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
    }
  }

  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 32);  // addr32
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  *out_len = size;
  return buffer;
}

int mxd_deserialize_transaction(const uint8_t *data, size_t data_len, mxd_transaction_t *tx) {
  // Minimum header: version(4) + chain_id(4) + input_count(4) + output_count(4)
  //                 + tip(8) + timestamp(8) + tx_hash(64) = 96 bytes
  // tx_hash is a non-authoritative pre-parse dedup hint (MXD-04 §10.1).
  // Receivers MUST recompute sighash from canonical bytes and compare to tx_hash.
  if (!data || !tx || data_len < 96) return -1;

  const uint8_t *ptr = data;
  const uint8_t *end = data + data_len;

  memset(tx, 0, sizeof(mxd_transaction_t));

  tx->version = mxd_read_u32_be(&ptr);
  tx->chain_id = mxd_read_u32_be(&ptr);      // chain_id per MXD-04 §3.1
  tx->input_count = mxd_read_u32_be(&ptr);
  tx->output_count = mxd_read_u32_be(&ptr);
  tx->voluntary_tip = mxd_read_u64_be(&ptr);
  tx->timestamp = mxd_read_u64_be(&ptr);
  // is_coinbase NOT on wire; recover from input_count
  mxd_read_bytes(&ptr, tx->tx_hash, 64);  // pre-parse dedup hint per MXD-04 §10.1
  tx->is_coinbase = (tx->input_count == 0) ? 1 : 0;

  if (tx->input_count > 256 || tx->output_count > 256) {
    return -1;
  }

  // Deserialize inputs
  if (tx->input_count > 0) {
    tx->inputs = calloc(tx->input_count, sizeof(mxd_tx_input_t));
    if (!tx->inputs) return -1;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (ptr + 64 + 4 + 1 + 2 > end) { mxd_free_transaction(tx); return -1; }
      mxd_read_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
      tx->inputs[i].output_index = mxd_read_u32_be(&ptr);
      tx->inputs[i].algo_id = mxd_read_u8(&ptr);
      tx->inputs[i].public_key_length = mxd_read_u16_be(&ptr);
      if (ptr + tx->inputs[i].public_key_length + 2 > end) { mxd_free_transaction(tx); return -1; }
      tx->inputs[i].public_key = malloc(tx->inputs[i].public_key_length);
      if (!tx->inputs[i].public_key) { mxd_free_transaction(tx); return -1; }
      mxd_read_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
      tx->inputs[i].signature_length = mxd_read_u16_be(&ptr);
      if (tx->inputs[i].signature_length > 0) {
        if (ptr + tx->inputs[i].signature_length > end) { mxd_free_transaction(tx); return -1; }
        tx->inputs[i].signature = malloc(tx->inputs[i].signature_length);
        if (!tx->inputs[i].signature) { mxd_free_transaction(tx); return -1; }
        mxd_read_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
      }
    }
  }

  // Deserialize outputs (addr32 per MXD-01 v1.1.x §4)
  if (tx->output_count > 0) {
    tx->outputs = calloc(tx->output_count, sizeof(mxd_tx_output_t));
    if (!tx->outputs) { mxd_free_transaction(tx); return -1; }
    for (uint32_t i = 0; i < tx->output_count; i++) {
      if (ptr + 32 + 8 > end) { mxd_free_transaction(tx); return -1; }
      mxd_read_bytes(&ptr, tx->outputs[i].recipient_addr, 32);
      tx->outputs[i].amount = mxd_read_u64_be(&ptr);
    }
  }

  return 0;
}

int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_addr[32],
                                   mxd_amount_t reward_amount) {
  if (!tx || !recipient_addr || reward_amount == 0) {
    return -1;
  }
  
  if (mxd_create_transaction(tx) != 0) {
    return -1;
  }
  
  tx->is_coinbase = 1;
  
  if (mxd_add_tx_output(tx, recipient_addr, reward_amount) != 0) {
    return -1;
  }
  
  return mxd_calculate_tx_hash(tx, tx->tx_hash);
}

int mxd_tx_deep_copy(mxd_transaction_t *dst, const mxd_transaction_t *src) {
  if (!dst || !src) return -1;
  
  memcpy(dst, src, sizeof(mxd_transaction_t));
  dst->inputs = NULL;
  dst->outputs = NULL;
  
  if (src->inputs && src->input_count > 0) {
    dst->inputs = malloc(src->input_count * sizeof(mxd_tx_input_t));
    if (!dst->inputs) return -1;
    
    for (uint32_t i = 0; i < src->input_count; i++) {
      memcpy(&dst->inputs[i], &src->inputs[i], sizeof(mxd_tx_input_t));
      dst->inputs[i].public_key = NULL;
      dst->inputs[i].signature = NULL;
      
      if (src->inputs[i].public_key && src->inputs[i].public_key_length > 0) {
        dst->inputs[i].public_key = malloc(src->inputs[i].public_key_length);
        if (!dst->inputs[i].public_key) {
          mxd_free_transaction(dst);
          return -1;
        }
        memcpy(dst->inputs[i].public_key, src->inputs[i].public_key, 
               src->inputs[i].public_key_length);
      }
      
      if (src->inputs[i].signature && src->inputs[i].signature_length > 0) {
        dst->inputs[i].signature = malloc(src->inputs[i].signature_length);
        if (!dst->inputs[i].signature) {
          mxd_free_transaction(dst);
          return -1;
        }
        memcpy(dst->inputs[i].signature, src->inputs[i].signature,
               src->inputs[i].signature_length);
      }
    }
  }
  
  if (src->outputs && src->output_count > 0) {
    dst->outputs = malloc(src->output_count * sizeof(mxd_tx_output_t));
    if (!dst->outputs) {
      mxd_free_transaction(dst);
      return -1;
    }
    memcpy(dst->outputs, src->outputs, 
           src->output_count * sizeof(mxd_tx_output_t));
  }
  
  return 0;
}

void mxd_free_transaction(mxd_transaction_t *tx) {
  if (tx) {
    if (tx->inputs) {
      for (uint32_t i = 0; i < tx->input_count; i++) {
        if (tx->inputs[i].public_key) {
          free(tx->inputs[i].public_key);
        }
        if (tx->inputs[i].signature) {
          free(tx->inputs[i].signature);
        }
      }
      free(tx->inputs);
    }
    if (tx->outputs) {
      free(tx->outputs);
    }
    memset(tx, 0, sizeof(mxd_transaction_t));
  }
}

// ========== Bridge Transaction Functions (v3) ==========

// Free dynamically allocated fields in bridge payload
void mxd_free_bridge_payload(mxd_bridge_payload_t *payload) {
  if (!payload) return;
  // Free legacy single-oracle fields
  if (payload->oracle_pubkey) {
    free(payload->oracle_pubkey);
    payload->oracle_pubkey = NULL;
  }
  if (payload->oracle_signature) {
    free(payload->oracle_signature);
    payload->oracle_signature = NULL;
  }
  // Free multi-oracle attestation fields
  for (uint32_t i = 0; i < payload->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
    if (payload->oracles[i].pubkey) {
      free(payload->oracles[i].pubkey);
      payload->oracles[i].pubkey = NULL;
    }
    if (payload->oracles[i].signature) {
      free(payload->oracles[i].signature);
      payload->oracles[i].signature = NULL;
    }
  }
}

// Deep copy bridge payload including dynamic oracle credential allocations
int mxd_bridge_payload_deep_copy(mxd_bridge_payload_t *dst, const mxd_bridge_payload_t *src) {
  if (!dst || !src) return -1;

  // Copy fixed fields
  memcpy(dst->bridge_contract, src->bridge_contract, 64);
  memcpy(dst->source_chain_id, src->source_chain_id, 32);
  memcpy(dst->source_tx_hash, src->source_tx_hash, 32);
  dst->source_block_number = src->source_block_number;
  memcpy(dst->recipient_addr, src->recipient_addr, MXD_ADDR32_LEN);
  dst->amount = src->amount;
  memcpy(dst->mxd_chain_id, src->mxd_chain_id, 32);

  // Deep copy multi-oracle attestations
  dst->oracle_count = src->oracle_count;
  for (uint32_t i = 0; i < src->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
    dst->oracles[i].algo_id = src->oracles[i].algo_id;
    dst->oracles[i].pubkey_length = src->oracles[i].pubkey_length;
    dst->oracles[i].sig_length = src->oracles[i].sig_length;
    dst->oracles[i].pubkey = NULL;
    dst->oracles[i].signature = NULL;

    if (src->oracles[i].pubkey && src->oracles[i].pubkey_length > 0) {
      dst->oracles[i].pubkey = malloc(src->oracles[i].pubkey_length);
      if (!dst->oracles[i].pubkey) goto deep_copy_fail;
      memcpy(dst->oracles[i].pubkey, src->oracles[i].pubkey, src->oracles[i].pubkey_length);
    }
    if (src->oracles[i].signature && src->oracles[i].sig_length > 0) {
      dst->oracles[i].signature = malloc(src->oracles[i].sig_length);
      if (!dst->oracles[i].signature) goto deep_copy_fail;
      memcpy(dst->oracles[i].signature, src->oracles[i].signature, src->oracles[i].sig_length);
    }
  }

  // Deep copy legacy single-oracle fields (backward compat)
  dst->oracle_algo_id = src->oracle_algo_id;
  dst->oracle_pubkey_length = src->oracle_pubkey_length;
  dst->oracle_sig_length = src->oracle_sig_length;
  dst->oracle_pubkey = NULL;
  dst->oracle_signature = NULL;

  if (src->oracle_pubkey && src->oracle_pubkey_length > 0) {
    dst->oracle_pubkey = malloc(src->oracle_pubkey_length);
    if (!dst->oracle_pubkey) goto deep_copy_fail;
    memcpy(dst->oracle_pubkey, src->oracle_pubkey, src->oracle_pubkey_length);
  }
  if (src->oracle_signature && src->oracle_sig_length > 0) {
    dst->oracle_signature = malloc(src->oracle_sig_length);
    if (!dst->oracle_signature) goto deep_copy_fail;
    memcpy(dst->oracle_signature, src->oracle_signature, src->oracle_sig_length);
  }

  return 0;

deep_copy_fail:
  // Clean up all allocated fields on failure
  for (uint32_t i = 0; i < dst->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
    free(dst->oracles[i].pubkey);
    dst->oracles[i].pubkey = NULL;
    free(dst->oracles[i].signature);
    dst->oracles[i].signature = NULL;
  }
  free(dst->oracle_pubkey);
  dst->oracle_pubkey = NULL;
  free(dst->oracle_signature);
  dst->oracle_signature = NULL;
  return -1;
}

// Verify oracle signature(s) embedded in bridge payload.
// This is the CRITICAL security function — called by every node during block
// validation to verify that authorized oracle(s) attested to the bridge event.
// Supports both multi-oracle N-of-M consensus and legacy single-oracle format.
// Helper to free on-chain oracle set (local to this file).
static void free_onchain_oracle_set(mxd_oracle_pubkey_entry_t *set, uint32_t count) {
  if (!set) return;
  for (uint32_t i = 0; i < count; i++) {
    if (set[i].pubkey) free(set[i].pubkey);
  }
  free(set);
}

int mxd_verify_bridge_oracle_signature(const mxd_bridge_payload_t *payload) {
  if (!payload) {
    MXD_LOG_ERROR("transaction", "Bridge oracle verification: NULL payload");
    return -1;
  }

  mxd_config_t *cfg = mxd_get_config();

  int result = -1;

  // Load the authorized oracle pubkey set. Prefer on-chain (written by
  // UPDATE_ORACLE_SET admin tx, survives data-dir wipes) and fall back to
  // the config-based list if no on-chain set exists yet. This is the
  // bootstrap compatibility path: until an UPDATE_ORACLE_SET admin tx
  // lands, nodes use their config oracle list as before.
  //
  // K-of-N threshold lookup follows the same precedence: on-chain
  // (admin:oracle_set), then config (bridge_min_oracle_signatures). Both
  // sources must agree across all validators or block validation diverges,
  // so config defaults should be kept identical on every node.
  mxd_oracle_pubkey_entry_t *onchain_oracles = NULL;
  uint32_t onchain_oracle_count = 0;
  uint32_t onchain_threshold = 0;
  (void)mxd_load_onchain_oracle_set(&onchain_oracles, &onchain_oracle_count,
                                     &onchain_threshold);
  // (non-fatal if not found — we'll just check config)

  uint32_t min_required;
  if (onchain_oracles && onchain_oracle_count > 0 && onchain_threshold > 0) {
    min_required = onchain_threshold;
  } else {
    min_required = (cfg) ? cfg->http.bridge_min_oracle_signatures : 1;
    if (min_required == 0) min_required = 1;
  }

  // Reconstruct the v7 canonical 220-byte signed message (MXD-API-01 §6).
  // Layout:
  //   "MXD-BRG-V1\0" (11) || algo_id(1) ||
  //   bridge_contract(64) || source_chain_id(32, BE u32 in first 4 bytes) ||
  //   source_tx_hash(32) || source_block_number(8 BE) ||
  //   recipient_addr(32) || amount(8 BE) || mxd_chain_id(32)
  //
  // The 208-byte tail is invariant across oracles in the multi-oracle loop;
  // only the algo_id byte varies per signature. Build the tail once here,
  // then prepend tag + per-oracle algo_id inside the loop.
  uint8_t sign_msg_tail[208];
  memcpy(sign_msg_tail, payload->bridge_contract, 64);
  memcpy(sign_msg_tail + 64, payload->source_chain_id, 32);
  memcpy(sign_msg_tail + 96, payload->source_tx_hash, 32);
  // v7: block_number and amount in BIG-ENDIAN per MXD-04 §3 / MXD-API-01 §6.
  uint64_t block_num_be = mxd_htonll(payload->source_block_number);
  memcpy(sign_msg_tail + 128, &block_num_be, 8);
  memcpy(sign_msg_tail + 136, payload->recipient_addr, MXD_ADDR32_LEN);
  uint64_t amount_be = mxd_htonll(payload->amount);
  memcpy(sign_msg_tail + 168, &amount_be, 8);
  memcpy(sign_msg_tail + 176, payload->mxd_chain_id, 32);

  // Multi-oracle path: verify N-of-M oracle attestations
  if (payload->oracle_count > 0) {
    if (payload->oracle_count > MXD_MAX_BRIDGE_ORACLE_SIGS) {
      MXD_LOG_ERROR("transaction", "Bridge oracle: count %u exceeds max %u",
                     payload->oracle_count, MXD_MAX_BRIDGE_ORACLE_SIGS);
      goto cleanup;
    }

    uint32_t valid_sigs = 0;

    for (uint32_t i = 0; i < payload->oracle_count; i++) {
      const mxd_oracle_attestation_t *oracle = &payload->oracles[i];

      // Validate credential fields
      if (!oracle->pubkey || oracle->pubkey_length == 0 ||
          !oracle->signature || oracle->sig_length == 0) {
        MXD_LOG_WARN("transaction", "Bridge oracle[%u]: missing credentials, skipping", i);
        continue;
      }

      // Duplicate-signer check. A duplicate is malicious intent — anyone
      // packing the same operator pubkey twice is trying to inflate the sig
      // count to reach quorum with fewer actual signers. Hard-fail the whole
      // submission rather than silently dropping the duplicate, so the source
      // gets a 400 and we don't get a partially-validated mint.
      int is_duplicate = 0;
      for (uint32_t j = 0; j < i; j++) {
        const mxd_oracle_attestation_t *prev = &payload->oracles[j];
        if (prev->pubkey_length == oracle->pubkey_length &&
            prev->algo_id == oracle->algo_id &&
            memcmp(prev->pubkey, oracle->pubkey, oracle->pubkey_length) == 0) {
          is_duplicate = 1;
          break;
        }
      }
      if (is_duplicate) {
        MXD_LOG_ERROR("transaction", "Bridge oracle[%u]: duplicate signer pubkey", i);
        goto cleanup;
      }

      // Validate algo_id and key length
      if (oracle->algo_id == MXD_SIGALG_ED25519) {
        if (oracle->pubkey_length != 32) {
          MXD_LOG_WARN("transaction", "Bridge oracle[%u]: Ed25519 pubkey must be 32 bytes, got %u", i, oracle->pubkey_length);
          continue;
        }
      } else if (oracle->algo_id == MXD_SIGALG_DILITHIUM5) {
        if (oracle->pubkey_length != 2592) {
          MXD_LOG_WARN("transaction", "Bridge oracle[%u]: Dilithium5 pubkey must be 2592 bytes, got %u", i, oracle->pubkey_length);
          continue;
        }
      } else {
        MXD_LOG_WARN("transaction", "Bridge oracle[%u]: unsupported algo_id %u", i, oracle->algo_id);
        continue;
      }

      // Check oracle is in the authorized set. On-chain UPDATE_ORACLE_SET
      // takes precedence if populated; otherwise fall back to config.
      int oracle_authorized = 0;
      if (onchain_oracles && onchain_oracle_count > 0) {
        for (uint32_t j = 0; j < onchain_oracle_count; j++) {
          if (onchain_oracles[j].pubkey_length == oracle->pubkey_length &&
              onchain_oracles[j].algo_id == oracle->algo_id &&
              memcmp(onchain_oracles[j].pubkey, oracle->pubkey,
                     oracle->pubkey_length) == 0) {
            oracle_authorized = 1;
            break;
          }
        }
      } else if (cfg && cfg->http.bridge_oracle_count > 0) {
        for (uint32_t j = 0; j < cfg->http.bridge_oracle_count; j++) {
          if (cfg->http.bridge_oracle_pubkey_lengths[j] == oracle->pubkey_length &&
              cfg->http.bridge_oracle_algo_ids[j] == oracle->algo_id &&
              memcmp(cfg->http.bridge_oracle_pubkeys[j], oracle->pubkey,
                     oracle->pubkey_length) == 0) {
            oracle_authorized = 1;
            break;
          }
        }
      }

      if (!oracle_authorized) {
        MXD_LOG_WARN("transaction", "Bridge oracle[%u]: pubkey not in allowlist", i);
        continue;
      }

      // Build the per-oracle 220-byte v7 canonical: tag(11) || algo_id(1) || tail(208).
      uint8_t sign_msg[MXD_DOMAIN_TAG_BRG_LEN + 1 + 208];
      size_t smo = 0;
      memcpy(sign_msg + smo, MXD_DOMAIN_TAG_BRG, MXD_DOMAIN_TAG_BRG_LEN);
      smo += MXD_DOMAIN_TAG_BRG_LEN;
      sign_msg[smo++] = oracle->algo_id;
      memcpy(sign_msg + smo, sign_msg_tail, 208);
      smo += 208;
      /* smo == sizeof(sign_msg) == 220 */

      // Verify cryptographic signature
      if (mxd_sig_verify(oracle->algo_id, oracle->signature,
                         (size_t)oracle->sig_length,
                         sign_msg, sizeof(sign_msg), oracle->pubkey) != 0) {
        MXD_LOG_WARN("transaction", "Bridge oracle[%u]: signature verification FAILED", i);
        continue;
      }

      valid_sigs++;
      MXD_LOG_INFO("transaction", "Bridge oracle[%u] signature verified (algo=%u, pubkey=%02x%02x...)",
                   i, oracle->algo_id, oracle->pubkey[0], oracle->pubkey[1]);
    }

    if (valid_sigs < min_required) {
      MXD_LOG_ERROR("transaction", "Bridge oracle: only %u of %u required signatures valid",
                     valid_sigs, min_required);
      goto cleanup;
    }

    MXD_LOG_INFO("transaction", "Bridge oracle N-of-M consensus passed: %u/%u valid (min %u)",
                 valid_sigs, payload->oracle_count, min_required);
    result = 0;
    goto cleanup;
  }

  // No oracles[] array present. The legacy single-oracle path was removed
  // (q.1 hard cutover). Pre-q.1 submissions that only set the singular
  // oracle_pubkey/oracle_signature fields are rejected here — that matches
  // the HTTP handler's 400 on the same shape, and keeps block validation
  // strict on sync.
  MXD_LOG_ERROR("transaction", "Bridge oracle verification: payload->oracles[] empty "
                "(legacy single-oracle path is disabled — submitter must send oracles array)");

cleanup:
  free_onchain_oracle_set(onchain_oracles, onchain_oracle_count);
  return result;
}

// Create a bridge mint transaction (BNB → MXD)
int mxd_create_bridge_mint_tx(mxd_transaction_v3_t *tx,
                               const mxd_bridge_payload_t *payload) {
  if (!tx || !payload) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_v3_t));
  tx->version = 3;
  tx->type = MXD_TX_TYPE_BRIDGE_MINT;
  tx->input_count = 0;  // Bridge mints have no inputs
  tx->output_count = 0;
  tx->voluntary_tip = 0;
  tx->timestamp = time(NULL);
  tx->inputs = NULL;
  tx->outputs = NULL;

  // Deep copy bridge payload (includes oracle credential allocations)
  tx->payload.bridge = malloc(sizeof(mxd_bridge_payload_t));
  if (!tx->payload.bridge) {
    return -1;
  }
  memset(tx->payload.bridge, 0, sizeof(mxd_bridge_payload_t));
  if (mxd_bridge_payload_deep_copy(tx->payload.bridge, payload) != 0) {
    free(tx->payload.bridge);
    tx->payload.bridge = NULL;
    return -1;
  }

  // Create output for minted MXD
  tx->outputs = malloc(sizeof(mxd_tx_output_t));
  if (!tx->outputs) {
    free(tx->payload.bridge);
    tx->payload.bridge = NULL;
    return -1;
  }

  memcpy(tx->outputs[0].recipient_addr, payload->recipient_addr, MXD_ADDR32_LEN);
  tx->outputs[0].amount = payload->amount;
  tx->output_count = 1;

  return 0;
}

// Create a bridge burn transaction (MXD → BNB)
int mxd_create_bridge_burn_tx(mxd_transaction_v3_t *tx,
                               const uint8_t sender_addr[20],
                               mxd_amount_t burn_amount,
                               const uint8_t bridge_contract[64],
                               uint32_t dest_chain_id,
                               const uint8_t dest_recipient[20]) {
  if (!tx || !sender_addr || !bridge_contract || !dest_recipient || burn_amount == 0) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_v3_t));
  tx->version = 3;
  tx->type = MXD_TX_TYPE_BRIDGE_BURN;
  tx->input_count = 0;  // Will be set when inputs are added
  tx->output_count = 0;
  tx->voluntary_tip = 0;
  tx->timestamp = time(NULL);
  tx->inputs = NULL;
  tx->outputs = NULL;

  // Allocate bridge payload
  tx->payload.bridge = malloc(sizeof(mxd_bridge_payload_t));
  if (!tx->payload.bridge) {
    return -1;
  }

  // Initialize bridge payload
  memset(tx->payload.bridge, 0, sizeof(mxd_bridge_payload_t));
  memcpy(tx->payload.bridge->bridge_contract, bridge_contract, 64);
  // Store dest_chain_id in source_chain_id field (repurposed for burn).
  // v7: stored as BE u32 in first 4 bytes per MXD-API-01 §6.
  uint32_t dest_chain_id_be = htonl(dest_chain_id);
  memcpy(tx->payload.bridge->source_chain_id, &dest_chain_id_be, sizeof(uint32_t));
  // BURN recipient is a BNB BSC address (20 bytes); pad to 32-byte addr32 frame
  // by zeroing remainder. dest_recipient is the user's destination on BNB.
  memset(tx->payload.bridge->recipient_addr, 0, MXD_ADDR32_LEN);
  memcpy(tx->payload.bridge->recipient_addr, dest_recipient, 20);
  tx->payload.bridge->amount = burn_amount;
  // Burns are user-initiated — no oracle attestation needed
  tx->payload.bridge->oracle_pubkey = NULL;
  tx->payload.bridge->oracle_signature = NULL;

  // Create burn output (to zero address)
  tx->outputs = malloc(sizeof(mxd_tx_output_t));
  if (!tx->outputs) {
    free(tx->payload.bridge);
    tx->payload.bridge = NULL;
    return -1;
  }

  // Burn address (all zeros)
  memset(tx->outputs[0].recipient_addr, 0, 32);
  tx->outputs[0].amount = burn_amount;
  tx->output_count = 1;

  return 0;
}

// Validate bridge mint transaction
int mxd_validate_bridge_mint_tx(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_MINT) {
    MXD_LOG_ERROR("transaction", "Invalid bridge mint transaction: wrong version or type");
    return -1;
  }

  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge mint transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // 1. Verify bridge contract is authorized
  if (!mxd_is_bridge_contract_authorized(bridge->bridge_contract)) {
    MXD_LOG_ERROR("transaction", "Bridge contract not authorized");
    return -1;
  }

  // 2. Verify source chain is supported (BNB mainnet 56 or testnet 97).
  // v7: source_chain_id stored as BE u32; decode with ntohl.
  uint32_t chain_id_be;
  memcpy(&chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
  uint32_t chain_id = ntohl(chain_id_be);
  if (chain_id != 56 && chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported source chain ID: %u", chain_id);
    return -1;
  }

  // 3. Verify source transaction hasn't been processed before (replay protection)
  if (mxd_is_bridge_tx_processed(bridge->source_tx_hash)) {
    MXD_LOG_ERROR("transaction", "Bridge transaction already processed (replay attack)");
    return -1;
  }

  // 4. Verify amount is positive
  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint amount must be positive");
    return -1;
  }

  // 4a. Verify amount does not exceed per-transaction maximum
  mxd_config_t *cfg = mxd_get_config();
  if (cfg && cfg->http.bridge_max_mint_per_tx > 0 &&
      bridge->amount > cfg->http.bridge_max_mint_per_tx) {
    MXD_LOG_ERROR("transaction", "Bridge mint amount %lu exceeds per-tx max %lu",
                  (unsigned long)bridge->amount, (unsigned long)cfg->http.bridge_max_mint_per_tx);
    return -1;
  }

  // 4b. Verify daily rate limit not exceeded
  if (mxd_check_bridge_mint_limits(bridge->amount) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint rejected: daily rate limit exceeded");
    return -1;
  }

  // 5. Verify recipient address is valid (not zero)
  uint8_t zero_addr[MXD_ADDR32_LEN] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, MXD_ADDR32_LEN) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint recipient cannot be zero address");
    return -1;
  }

  // 6. CRITICAL: Verify oracle signature over the bridge payload.
  //    This is the core security check — every node independently verifies
  //    that an authorized oracle cryptographically attested to this bridge event.
  //    Without this, a malicious block proposer could mint arbitrary coins.
  if (mxd_verify_bridge_oracle_signature(bridge) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint REJECTED: oracle signature verification failed");
    return -1;
  }

  // 7. Verify transaction has exactly one output matching the payload
  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have exactly one output");
    return -1;
  }

  if (memcmp(tx->outputs[0].recipient_addr, bridge->recipient_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("transaction", "Output recipient mismatch");
    return -1;
  }

  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }

  // 8. Verify no inputs (mint creates new coins)
  if (tx->input_count != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have zero inputs");
    return -1;
  }

  return 0;
}

// Validate bridge burn transaction
int mxd_validate_bridge_burn_tx(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_BURN) {
    MXD_LOG_ERROR("transaction", "Invalid bridge burn transaction: wrong version or type");
    return -1;
  }

  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge burn transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // 1. Verify bridge contract is authorized
  if (!mxd_is_bridge_contract_authorized(bridge->bridge_contract)) {
    MXD_LOG_ERROR("transaction", "Bridge contract not authorized");
    return -1;
  }

  // 2. Verify destination chain is supported.
  // v7: dest_chain_id stored as BE u32; decode with ntohl.
  uint32_t dest_chain_id_be;
  memcpy(&dest_chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
  uint32_t dest_chain_id = ntohl(dest_chain_id_be);
  if (dest_chain_id != 56 && dest_chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported destination chain ID: %u", dest_chain_id);
    return -1;
  }

  // 3. Verify amount is positive
  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn amount must be positive");
    return -1;
  }

  // 4. Verify recipient address is valid (not zero)
  // (BNB address is the lower 20 bytes; upper 12 are zero-padded — addr32 frame)
  uint8_t zero_addr[MXD_ADDR32_LEN] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, MXD_ADDR32_LEN) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn recipient cannot be zero address");
    return -1;
  }

  // 5. Verify transaction has exactly one output to burn address
  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have exactly one output");
    return -1;
  }

  if (memcmp(tx->outputs[0].recipient_addr, zero_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn output must be to zero address");
    return -1;
  }

  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }

  // 6. Verify inputs exist and are valid
  if (tx->input_count == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have inputs");
    return -1;
  }

  // 7. Validate inputs against UTXO database
  mxd_amount_t total_input = 0;
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_amount_t amount = 0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "Invalid UTXO for burn input %u", i);
      return -1;
    }

    // Check for overflow
    if (total_input > UINT64_MAX - amount) {
      MXD_LOG_ERROR("transaction", "Input sum overflow in bridge burn");
      return -1;
    }
    total_input += amount;
  }

  // 8. Verify total input >= burn amount + fee (with overflow check)
  if (bridge->amount > UINT64_MAX - tx->voluntary_tip) {
    MXD_LOG_ERROR("transaction", "Bridge burn required amount overflow");
    return -1;
  }
  mxd_amount_t required = bridge->amount + tx->voluntary_tip;
  if (total_input < required) {
    MXD_LOG_ERROR("transaction", "Insufficient input for bridge burn: have %lu, need %lu",
                  (unsigned long)total_input, (unsigned long)required);
    return -1;
  }

  return 0;
}

// Consensus-only bridge mint validation.
//
// Used by the block-apply path (during sync / replay) where admin/policy
// state like the bridge_auth registry and daily rate-limit counter may not
// be populated on a recovering node. Keeps the security-critical checks
// (structure + oracle signature + output consistency) and drops policy
// gates that are appropriate only at submission time. A block that reached
// consensus was already checked against full policy at creation time; the
// oracle signature is the cryptographic proof that an authorized oracle
// set attested to the mint, independent of any per-node config.
int mxd_validate_bridge_mint_tx_consensus_only(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_MINT) {
    MXD_LOG_ERROR("transaction", "Invalid bridge mint transaction: wrong version or type");
    return -1;
  }
  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge mint transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // Source chain is supported (BNB mainnet 56 or testnet 97).
  // v7: source_chain_id stored as BE u32; decode with ntohl.
  uint32_t chain_id_be;
  memcpy(&chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
  uint32_t chain_id = ntohl(chain_id_be);
  if (chain_id != 56 && chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported source chain ID: %u", chain_id);
    return -1;
  }

  // Amount is positive
  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint amount must be positive");
    return -1;
  }

  // Recipient is non-zero
  uint8_t zero_addr[MXD_ADDR32_LEN] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, MXD_ADDR32_LEN) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint recipient cannot be zero address");
    return -1;
  }

  // CRITICAL: oracle signature. This is the security gate — N-of-M authorized
  // oracles attested to this mint. Stateless crypto, works regardless of
  // the node's admin/ratelimit state.
  if (mxd_verify_bridge_oracle_signature(bridge) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint REJECTED: oracle signature verification failed");
    return -1;
  }

  // A1: consensus-level replay protection. The bridge_tx:<source_tx_hash>
  // RocksDB index is populated by mxd_mark_bridge_tx_processed inside
  // mxd_apply_block_transactions immediately after this validator returns
  // success on each tx. So during in-order replay/apply, a duplicate is
  // caught here whether it spans two blocks (the prior block's mark is in
  // RocksDB) or sits intra-block (the prior tx in the same block was just
  // marked before this validator runs for the current tx). Combined with
  // the queue dedup in mxd_queue_bridge_mint (fix-b) and the oracle-side
  // row-lock in bnb-monitor.js (A3), this closes the bug-class
  // structurally: even a malicious proposer cannot include a duplicate.
  if (mxd_is_bridge_tx_processed(bridge->source_tx_hash)) {
    MXD_LOG_ERROR("transaction",
                  "Bridge mint REJECTED: source_tx_hash already processed (replay)");
    return -1;
  }

  // Output structure: exactly one output matching the payload
  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have exactly one output");
    return -1;
  }
  if (memcmp(tx->outputs[0].recipient_addr, bridge->recipient_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("transaction", "Output recipient mismatch");
    return -1;
  }
  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }
  if (tx->input_count != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have zero inputs");
    return -1;
  }

  return 0;
}

// Consensus-only bridge burn validation (see _consensus_only rationale above).
// Bridge burns are user-initiated (they spend real UTXOs) rather than
// oracle-attested, so there is no oracle signature to check. All checks
// retained here are either pure structure or UTXO validation, which is
// always safe to run during sync because UTXO state is rebuilt from the
// chain deterministically.
int mxd_validate_bridge_burn_tx_consensus_only(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_BURN) {
    MXD_LOG_ERROR("transaction", "Invalid bridge burn transaction: wrong version or type");
    return -1;
  }
  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge burn transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // v7: dest_chain_id stored as BE u32; decode with ntohl.
  uint32_t dest_chain_id_be;
  memcpy(&dest_chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
  uint32_t dest_chain_id = ntohl(dest_chain_id_be);
  if (dest_chain_id != 56 && dest_chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported destination chain ID: %u", dest_chain_id);
    return -1;
  }

  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn amount must be positive");
    return -1;
  }

  uint8_t zero_addr[MXD_ADDR32_LEN] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, MXD_ADDR32_LEN) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn recipient cannot be zero address");
    return -1;
  }

  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have exactly one output");
    return -1;
  }
  if (memcmp(tx->outputs[0].recipient_addr, zero_addr, MXD_ADDR32_LEN) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn output must be to zero address");
    return -1;
  }
  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }
  if (tx->input_count == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have inputs");
    return -1;
  }

  mxd_amount_t total_input = 0;
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_amount_t amount = 0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "Invalid UTXO for burn input %u", i);
      return -1;
    }
    if (total_input > UINT64_MAX - amount) {
      MXD_LOG_ERROR("transaction", "Input sum overflow in bridge burn");
      return -1;
    }
    total_input += amount;
  }

  if (bridge->amount > UINT64_MAX - tx->voluntary_tip) {
    MXD_LOG_ERROR("transaction", "Bridge burn required amount overflow");
    return -1;
  }
  mxd_amount_t required = bridge->amount + tx->voluntary_tip;
  if (total_input < required) {
    MXD_LOG_ERROR("transaction", "Insufficient input for bridge burn: have %lu, need %lu",
                  (unsigned long)total_input, (unsigned long)required);
    return -1;
  }

  return 0;
}

// Check if bridge transaction already processed (replay protection)
int mxd_is_bridge_tx_processed(const uint8_t source_tx_hash[32]) {
  if (!source_tx_hash) {
    return 0;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return 0;
  }

  // Create key: "bridge_tx:" + source_tx_hash
  uint8_t key[42];
  memcpy(key, "bridge_tx:", 10);
  memcpy(key + 10, source_tx_hash, 32);

  rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
  char *err = NULL;
  size_t val_len;

  char *value = rocksdb_get(db, readopts, (const char *)key, 42, &val_len, &err);

  rocksdb_readoptions_destroy(readopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Database error checking bridge tx: %s", err);
    free(err);
    return 0;
  }

  if (value) {
    free(value);
    return 1;  // Already processed
  }

  return 0;  // Not processed
}

// Mark bridge transaction as processed
int mxd_mark_bridge_tx_processed(const mxd_bridge_payload_t *payload,
                                  const uint8_t mxd_tx_hash[64],
                                  uint32_t block_index) {
  if (!payload || !mxd_tx_hash) {
    return -1;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return -1;
  }

  // Create key: "bridge_tx:" + source_tx_hash
  uint8_t key[42];
  memcpy(key, "bridge_tx:", 10);
  memcpy(key + 10, payload->source_tx_hash, 32);

  // Create value: mxd_tx_hash (64 bytes) + block_index (4 bytes)
  uint8_t value[68];
  memcpy(value, mxd_tx_hash, 64);
  memcpy(value + 64, &block_index, 4);

  rocksdb_writeoptions_t *writeopts = rocksdb_writeoptions_create();
  char *err = NULL;

  rocksdb_put(db, writeopts, (const char *)key, 42, (const char *)value, 68, &err);

  rocksdb_writeoptions_destroy(writeopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Failed to mark bridge tx as processed: %s", err);
    free(err);
    return -1;
  }

  MXD_LOG_INFO("transaction", "Marked bridge transaction as processed at block %u", block_index);
  return 0;
}

// Verify bridge contract is authorized
int mxd_is_bridge_contract_authorized(const uint8_t contract_hash[64]) {
  if (!contract_hash) {
    return 0;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return 0;
  }

  // Create key: "bridge_auth:" + contract_hash
  uint8_t key[76];
  memcpy(key, "bridge_auth:", 12);
  memcpy(key + 12, contract_hash, 64);

  rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
  char *err = NULL;
  size_t val_len;

  char *value = rocksdb_get(db, readopts, (const char *)key, 76, &val_len, &err);

  rocksdb_readoptions_destroy(readopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Database error checking bridge auth: %s", err);
    free(err);
    return 0;
  }

  if (value) {
    // Check if not revoked (value should be "1" for authorized, "0" for revoked)
    int authorized = (val_len > 0 && value[0] == '1');
    free(value);
    return authorized;
  }

  return 0;  // Not authorized
}

// ========== Bridge Rate Limiting ==========

// In-memory daily mint tracking (reset at UTC midnight boundary)
static uint64_t bridge_daily_minted = 0;
static uint64_t bridge_daily_reset_time = 0;  // Unix timestamp of current day start
static pthread_mutex_t bridge_rate_mutex = PTHREAD_MUTEX_INITIALIZER;

// Get the start of the current UTC day
static uint64_t get_utc_day_start(void) {
  time_t now = time(NULL);
  return (uint64_t)(now - (now % 86400));
}

// Check bridge mint rate limits (daily cap)
// Returns 0 if within limits, -1 if limit would be exceeded
int mxd_check_bridge_mint_limits(mxd_amount_t amount) {
  mxd_config_t *cfg = mxd_get_config();
  if (!cfg || cfg->http.bridge_daily_mint_cap == 0) {
    return 0;  // No daily cap configured
  }

  pthread_mutex_lock(&bridge_rate_mutex);

  uint64_t day_start = get_utc_day_start();
  if (day_start != bridge_daily_reset_time) {
    // New day — reset counter
    bridge_daily_minted = 0;
    bridge_daily_reset_time = day_start;
  }

  // Check if adding this amount would exceed the daily cap
  if (bridge_daily_minted > UINT64_MAX - amount ||
      bridge_daily_minted + amount > cfg->http.bridge_daily_mint_cap) {
    pthread_mutex_unlock(&bridge_rate_mutex);
    MXD_LOG_ERROR("transaction", "Bridge daily mint limit: minted=%lu + new=%lu > cap=%lu",
                  (unsigned long)bridge_daily_minted, (unsigned long)amount,
                  (unsigned long)cfg->http.bridge_daily_mint_cap);
    return -1;
  }

  pthread_mutex_unlock(&bridge_rate_mutex);
  return 0;
}

// Record a bridge mint for daily rate tracking
void mxd_record_bridge_mint(mxd_amount_t amount) {
  pthread_mutex_lock(&bridge_rate_mutex);

  uint64_t day_start = get_utc_day_start();
  if (day_start != bridge_daily_reset_time) {
    bridge_daily_minted = 0;
    bridge_daily_reset_time = day_start;
  }

  bridge_daily_minted += amount;
  MXD_LOG_INFO("transaction", "Bridge daily mint recorded: +%lu (total today: %lu)",
               (unsigned long)amount, (unsigned long)bridge_daily_minted);

  pthread_mutex_unlock(&bridge_rate_mutex);
}

// Get MXD chain ID for signed message (SHA-512(genesis_block_hash) truncated to 32 bytes)
// This prevents cross-chain replay attacks when the chain is reset.
// v7 cascade (M6-1): switched from SHA-256 to SHA-512 truncation to align with
// MXD's SHA-512 hash family — chain_id is still 32 bytes wide, but is now the
// first 32 bytes of SHA-512(genesis_block_hash).
int mxd_get_chain_id(uint8_t chain_id[32]) {
  if (!chain_id) return -1;

  // Get genesis block (height 0) hash
  mxd_block_t genesis;
  memset(&genesis, 0, sizeof(genesis));

  if (mxd_get_block_by_height(0, &genesis) != 0) {
    MXD_LOG_WARN("transaction", "Cannot retrieve genesis block for chain ID, using zero");
    memset(chain_id, 0, 32);
    return 0;
  }

  // Chain ID = SHA-512(genesis_block_hash)[0..31]
  uint8_t full[64];
  int ret = mxd_sha512(genesis.block_hash, 64, full);
  if (ret != 0) return ret;
  memcpy(chain_id, full, 32);
  return 0;
}

// Calculate v3 transaction hash
int mxd_calculate_tx_hash_v3(const mxd_transaction_v3_t *tx, uint8_t hash[64]) {
  if (!tx || !hash) {
    return -1;
  }

  // Calculate buffer size
  size_t buffer_size =
      4 +                                               // version (u32)
      4 +                                               // type (u32)
      4 +                                               // input_count (u32)
      4 +                                               // output_count (u32)
      8 +                                               // voluntary_tip (u64)
      8;                                                // timestamp (u64)

  // Add input sizes
  for (uint32_t i = 0; i < tx->input_count; i++) {
    buffer_size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length;
  }

  // Add output sizes (v6: addr32 widened, recipient_addr now 32 bytes)
  buffer_size += tx->output_count * (32 + 8);

  // Add bridge payload size if applicable
  if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
    if (!tx->payload.bridge) {
      return -1;
    }
    mxd_bridge_payload_t *bp = tx->payload.bridge;
    // Fixed fields: bridge_contract(64) + source_chain_id(32) + source_tx_hash(32) +
    //               source_block_number(8) + recipient_addr(32) + amount(8) + mxd_chain_id(32) — v6
    buffer_size += 64 + 32 + 32 + 8 + 32 + 8 + 32;
    // Multi-oracle attestations: oracle_count(4) + per oracle (algo_id(1) + pubkey_len(2) + pubkey + sig_len(2) + sig)
    buffer_size += 4;
    for (uint32_t i = 0; i < bp->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
      buffer_size += 1 + 2 + bp->oracles[i].pubkey_length + 2 + bp->oracles[i].sig_length;
    }
    // Legacy oracle fields
    buffer_size += 1 + 2 + bp->oracle_pubkey_length + 2 + bp->oracle_sig_length;
  } else if (tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
             tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
             tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    if (!tx->payload.admin) return -1;
    mxd_admin_payload_t *a = tx->payload.admin;
    buffer_size += 8; // nonce
    if (a->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
        a->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
      buffer_size += 64;
    } else {
      buffer_size += 4; // oracle_count
      for (uint32_t i = 0; i < a->oracle_set_count; i++) {
        buffer_size += 1 + 2 + a->oracle_set[i].pubkey_length;
      }
      buffer_size += 4; // oracle_set_threshold (q.1 wire format — tx hash must commit to it)
    }
    buffer_size += 4; // sig_count
    for (uint32_t i = 0; i < a->sig_count; i++) {
      buffer_size += 1 + 2 + a->sigs[i].pubkey_length + 2 + a->sigs[i].sig_length;
    }
  }

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }

  // Serialize transaction data
  uint8_t *ptr = buffer;

  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, (uint32_t)tx->type);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);

  // Serialize inputs
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
  }

  // Serialize outputs (v6: addr32)
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, MXD_ADDR32_LEN);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  // Serialize bridge payload (including oracle attestations — commits to the proof)
  if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
    mxd_bridge_payload_t *bridge = tx->payload.bridge;
    mxd_write_bytes(&ptr, bridge->bridge_contract, 64);
    mxd_write_bytes(&ptr, bridge->source_chain_id, 32);
    mxd_write_bytes(&ptr, bridge->source_tx_hash, 32);
    mxd_write_u64_be(&ptr, bridge->source_block_number);
    mxd_write_bytes(&ptr, bridge->recipient_addr, MXD_ADDR32_LEN);
    mxd_write_u64_be(&ptr, bridge->amount);
    mxd_write_bytes(&ptr, bridge->mxd_chain_id, 32);
    // Multi-oracle attestations
    mxd_write_u32_be(&ptr, bridge->oracle_count);
    for (uint32_t i = 0; i < bridge->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
      // Validate consistency: non-zero length MUST have non-NULL data (prevents hash malleability)
      if (bridge->oracles[i].pubkey_length > 0 && bridge->oracles[i].pubkey == NULL) {
        free(buffer);
        return -1;  // Invalid: non-zero length but NULL data
      }
      if (bridge->oracles[i].sig_length > 0 && bridge->oracles[i].signature == NULL) {
        free(buffer);
        return -1;  // Invalid: non-zero length but NULL data
      }
      mxd_write_u8(&ptr, bridge->oracles[i].algo_id);
      mxd_write_u16_be(&ptr, bridge->oracles[i].pubkey_length);
      if (bridge->oracles[i].pubkey && bridge->oracles[i].pubkey_length > 0) {
        mxd_write_bytes(&ptr, bridge->oracles[i].pubkey, bridge->oracles[i].pubkey_length);
      }
      mxd_write_u16_be(&ptr, bridge->oracles[i].sig_length);
      if (bridge->oracles[i].signature && bridge->oracles[i].sig_length > 0) {
        mxd_write_bytes(&ptr, bridge->oracles[i].signature, bridge->oracles[i].sig_length);
      }
    }
    // Legacy oracle fields (for backward compat in hash)
    mxd_write_u8(&ptr, bridge->oracle_algo_id);
    mxd_write_u16_be(&ptr, bridge->oracle_pubkey_length);
    if (bridge->oracle_pubkey && bridge->oracle_pubkey_length > 0) {
      mxd_write_bytes(&ptr, bridge->oracle_pubkey, bridge->oracle_pubkey_length);
    }
    mxd_write_u16_be(&ptr, bridge->oracle_sig_length);
    if (bridge->oracle_signature && bridge->oracle_sig_length > 0) {
      mxd_write_bytes(&ptr, bridge->oracle_signature, bridge->oracle_sig_length);
    }
  } else if ((tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) &&
             tx->payload.admin) {
    mxd_admin_payload_t *a = tx->payload.admin;
    mxd_write_u64_be(&ptr, a->nonce);
    if (a->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
        a->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
      mxd_write_bytes(&ptr, a->bridge_contract, 64);
    } else {
      mxd_write_u32_be(&ptr, a->oracle_set_count);
      for (uint32_t i = 0; i < a->oracle_set_count; i++) {
        mxd_write_u8(&ptr, a->oracle_set[i].algo_id);
        mxd_write_u16_be(&ptr, a->oracle_set[i].pubkey_length);
        mxd_write_bytes(&ptr, a->oracle_set[i].pubkey,
                        a->oracle_set[i].pubkey_length);
      }
      mxd_write_u32_be(&ptr, a->oracle_set_threshold);
    }
    mxd_write_u32_be(&ptr, a->sig_count);
    for (uint32_t i = 0; i < a->sig_count; i++) {
      mxd_write_u8(&ptr, a->sigs[i].algo_id);
      mxd_write_u16_be(&ptr, a->sigs[i].pubkey_length);
      mxd_write_bytes(&ptr, a->sigs[i].pubkey, a->sigs[i].pubkey_length);
      mxd_write_u16_be(&ptr, a->sigs[i].sig_length);
      mxd_write_bytes(&ptr, a->sigs[i].signature, a->sigs[i].sig_length);
    }
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

// Validate v3 transaction
int mxd_validate_transaction_v3(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3) {
    return -1;
  }

  // Dispatch to type-specific validation
  switch (tx->type) {
    case MXD_TX_TYPE_BRIDGE_MINT:
      return mxd_validate_bridge_mint_tx(tx);

    case MXD_TX_TYPE_BRIDGE_BURN:
      return mxd_validate_bridge_burn_tx(tx);

    case MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE:
    case MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE:
    case MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET:
      return mxd_validate_admin_tx(tx);

    case MXD_TX_TYPE_REGULAR:
    case MXD_TX_TYPE_COINBASE:
      // Regular/coinbase transactions use v2 validation logic
      // (would need to convert to v2 structure or adapt validation)
      MXD_LOG_ERROR("transaction", "Regular/coinbase should use v2 transactions");
      return -1;

    case MXD_TX_TYPE_CONTRACT_DEPLOY:
    case MXD_TX_TYPE_CONTRACT_CALL:
      MXD_LOG_ERROR("transaction", "Contract transactions not yet implemented");
      return -1;

    default:
      MXD_LOG_ERROR("transaction", "Unknown transaction type: %d", tx->type);
      return -1;
  }
}

// ============================================================
// Admin transactions (bridge authorization + oracle set rotation)
// ============================================================
//
// Admin txs move formerly-RocksDB-only state (bridge_auth:*) and
// formerly-config-only state (oracle pubkey list) onto the chain.
// Each admin tx carries 3-of-5 oracle Dilithium5 signatures over the
// canonical admin message. Oracles are the bridge-specific governance
// body (same signing committee that attests to bridge mints); using
// the oracle set here matches the authority scope to the function
// scope. Sync replay reconstructs the admin state automatically, so a
// node that loses its data dir can recover without operator
// intervention.

void mxd_free_admin_payload(mxd_admin_payload_t *admin) {
  if (!admin) return;
  if (admin->oracle_set) {
    uint32_t oracle_cap = admin->oracle_set_count;
    if (oracle_cap > MXD_MAX_ADMIN_ORACLE_PUBKEYS) oracle_cap = MXD_MAX_ADMIN_ORACLE_PUBKEYS;
    for (uint32_t i = 0; i < oracle_cap; i++) {
      if (admin->oracle_set[i].pubkey) free(admin->oracle_set[i].pubkey);
    }
    free(admin->oracle_set);
  }
  // sigs[] is a fixed-size array — never walk past it even if sig_count is garbage
  // (e.g. a deserialize that failed bounds-check before zeroing the field).
  uint32_t sig_cap = admin->sig_count;
  if (sig_cap > MXD_ADMIN_MAX_ORACLE_SIGS) sig_cap = MXD_ADMIN_MAX_ORACLE_SIGS;
  for (uint32_t i = 0; i < sig_cap; i++) {
    if (admin->sigs[i].pubkey) free(admin->sigs[i].pubkey);
    if (admin->sigs[i].signature) free(admin->sigs[i].signature);
  }
  memset(admin, 0, sizeof(*admin));
}

// Build the canonical signing message. Every oracle signs the hash of
// these bytes — NOT the bytes themselves (sigs are over SHA-512 output
// in mxd_verify_bridge_oracle_signature too).
int mxd_serialize_admin_payload_for_signing(const mxd_admin_payload_t *admin,
                                             uint32_t tx_version,
                                             uint8_t **out_bytes,
                                             size_t *out_len) {
  if (!admin || !out_bytes || !out_len) return -1;

  // Compute size
  size_t size = 4 /* version */ + 4 /* type */ + 8 /* nonce */;
  if (admin->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
      admin->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
    size += 64;  // bridge_contract
  } else if (admin->op_type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    size += 4;   // oracle_count
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      size += 1 + 2 + admin->oracle_set[i].pubkey_length;
    }
    size += 4;   // oracle_set_threshold (K-of-N), appended after entries
  } else {
    return -1;
  }

  uint8_t *buf = malloc(size);
  if (!buf) return -1;
  uint8_t *p = buf;

  mxd_write_u32_be(&p, tx_version);
  mxd_write_u32_be(&p, (uint32_t)admin->op_type);
  mxd_write_u64_be(&p, admin->nonce);

  if (admin->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
      admin->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
    mxd_write_bytes(&p, admin->bridge_contract, 64);
  } else {
    mxd_write_u32_be(&p, admin->oracle_set_count);
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      mxd_write_u8(&p, admin->oracle_set[i].algo_id);
      mxd_write_u16_be(&p, admin->oracle_set[i].pubkey_length);
      mxd_write_bytes(&p, admin->oracle_set[i].pubkey,
                      admin->oracle_set[i].pubkey_length);
    }
    mxd_write_u32_be(&p, admin->oracle_set_threshold);
  }

  *out_bytes = buf;
  *out_len = size;
  return 0;
}

// Serialize a full admin tx to wire format:
//   version(u32 BE) | type(u32 BE) | input_count=0 | output_count=0 |
//   voluntary_tip=0 | timestamp(u64 BE) | tx_hash(64) |
//   -- admin payload: --
//   nonce(u64 BE) | op_data |
//   sig_count(u32 BE) |
//   per sig: algo_id(u8) | pubkey_len(u16 BE) | pubkey | sig_len(u16 BE) | sig
int mxd_serialize_admin_tx(const mxd_transaction_v3_t *tx,
                            uint8_t **out_bytes, size_t *out_len) {
  if (!tx || !out_bytes || !out_len) return -1;
  if (!tx->payload.admin) return -1;
  const mxd_admin_payload_t *admin = tx->payload.admin;

  // Size the body (payload + sigs)
  size_t body_size;
  {
    uint8_t *tmp = NULL; size_t sl = 0;
    if (mxd_serialize_admin_payload_for_signing(admin, tx->version, &tmp, &sl) != 0) return -1;
    // We reuse the signing-message op_data length. Header of signing msg is
    // version(4)+type(4)+nonce(8)=16 bytes; inside the wire we drop the
    // version/type (they're in the tx header) but keep nonce + op_data.
    // So body payload size = (sl - 8 /* version+type removed */) -- actually
    // wait: signing msg = version+type+nonce+op_data. Wire payload =
    // nonce+op_data (8 + (sl - 16)). Let's just compute directly.
    body_size = 8 /* nonce */ + (sl - 16);
    free(tmp);
  }

  // Add sig section
  body_size += 4; // sig_count
  for (uint32_t i = 0; i < admin->sig_count; i++) {
    body_size += 1 + 2 + admin->sigs[i].pubkey_length +
                 2 + admin->sigs[i].sig_length;
  }

  // Header: version(4) + type(4) + input_count(4) + output_count(4) +
  //         voluntary_tip(8) + timestamp(8) + tx_hash(64) = 96 bytes
  size_t header_size = 4 + 4 + 4 + 4 + 8 + 8 + 64;
  size_t total = header_size + body_size;
  uint8_t *buf = malloc(total);
  if (!buf) return -1;
  uint8_t *p = buf;

  // Header
  mxd_write_u32_be(&p, tx->version);
  mxd_write_u32_be(&p, (uint32_t)tx->type);
  mxd_write_u32_be(&p, 0); // input_count
  mxd_write_u32_be(&p, 0); // output_count
  mxd_write_u64_be(&p, tx->voluntary_tip);
  mxd_write_u64_be(&p, tx->timestamp);
  mxd_write_bytes(&p, tx->tx_hash, 64);

  // Admin body: nonce + op_data
  mxd_write_u64_be(&p, admin->nonce);
  if (admin->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
      admin->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
    mxd_write_bytes(&p, admin->bridge_contract, 64);
  } else if (admin->op_type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    mxd_write_u32_be(&p, admin->oracle_set_count);
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      mxd_write_u8(&p, admin->oracle_set[i].algo_id);
      mxd_write_u16_be(&p, admin->oracle_set[i].pubkey_length);
      mxd_write_bytes(&p, admin->oracle_set[i].pubkey,
                      admin->oracle_set[i].pubkey_length);
    }
    mxd_write_u32_be(&p, admin->oracle_set_threshold);
  } else {
    free(buf);
    return -1;
  }

  // Signatures
  mxd_write_u32_be(&p, admin->sig_count);
  for (uint32_t i = 0; i < admin->sig_count; i++) {
    mxd_write_u8(&p, admin->sigs[i].algo_id);
    mxd_write_u16_be(&p, admin->sigs[i].pubkey_length);
    mxd_write_bytes(&p, admin->sigs[i].pubkey, admin->sigs[i].pubkey_length);
    mxd_write_u16_be(&p, admin->sigs[i].sig_length);
    mxd_write_bytes(&p, admin->sigs[i].signature, admin->sigs[i].sig_length);
  }

  *out_bytes = buf;
  *out_len = total;
  return 0;
}

int mxd_deserialize_admin_tx(const uint8_t *data, size_t data_len,
                              mxd_transaction_v3_t *tx) {
  if (!data || !tx) return -1;
  if (data_len < 96 + 8 /* minimum: header + nonce */) return -1;

  memset(tx, 0, sizeof(*tx));
  const uint8_t *p = data;
  const uint8_t *end = data + data_len;

  tx->version = mxd_read_u32_be(&p);
  tx->type = (mxd_tx_type_t)mxd_read_u32_be(&p);
  tx->input_count = mxd_read_u32_be(&p);
  tx->output_count = mxd_read_u32_be(&p);
  tx->voluntary_tip = mxd_read_u64_be(&p);
  tx->timestamp = mxd_read_u64_be(&p);
  mxd_read_bytes(&p, tx->tx_hash, 64);

  if (tx->version != 3) return -1;
  if (tx->type != MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE &&
      tx->type != MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE &&
      tx->type != MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    return -1;
  }
  if (tx->input_count != 0 || tx->output_count != 0) return -1;

  mxd_admin_payload_t *admin = calloc(1, sizeof(*admin));
  if (!admin) return -1;
  tx->payload.admin = admin;
  admin->op_type = tx->type;

  if (p + 8 > end) goto fail;
  admin->nonce = mxd_read_u64_be(&p);

  if (admin->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
      admin->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
    if (p + 64 > end) goto fail;
    mxd_read_bytes(&p, admin->bridge_contract, 64);
  } else {
    // UPDATE_ORACLE_SET
    if (p + 4 > end) goto fail;
    admin->oracle_set_count = mxd_read_u32_be(&p);
    if (admin->oracle_set_count == 0 ||
        admin->oracle_set_count > MXD_MAX_ADMIN_ORACLE_PUBKEYS) goto fail;
    admin->oracle_set = calloc(admin->oracle_set_count,
                                sizeof(mxd_oracle_pubkey_entry_t));
    if (!admin->oracle_set) goto fail;
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      if (p + 3 > end) goto fail;
      admin->oracle_set[i].algo_id = mxd_read_u8(&p);
      admin->oracle_set[i].pubkey_length = mxd_read_u16_be(&p);
      if (admin->oracle_set[i].pubkey_length == 0 ||
          admin->oracle_set[i].pubkey_length > 4096) goto fail;
      if (p + admin->oracle_set[i].pubkey_length > end) goto fail;
      admin->oracle_set[i].pubkey = malloc(admin->oracle_set[i].pubkey_length);
      if (!admin->oracle_set[i].pubkey) goto fail;
      mxd_read_bytes(&p, admin->oracle_set[i].pubkey,
                     admin->oracle_set[i].pubkey_length);
    }
    // K-of-N threshold appended after the oracle entries. Range check
    // (1..oracle_set_count) happens in mxd_validate_admin_tx so a malformed
    // payload can't dodge the check by short-reading.
    if (p + 4 > end) goto fail;
    admin->oracle_set_threshold = mxd_read_u32_be(&p);
  }

  // Signatures
  if (p + 4 > end) goto fail;
  admin->sig_count = mxd_read_u32_be(&p);
  if (admin->sig_count < MXD_ADMIN_MIN_ORACLE_SIGS ||
      admin->sig_count > MXD_ADMIN_MAX_ORACLE_SIGS) goto fail;

  for (uint32_t i = 0; i < admin->sig_count; i++) {
    if (p + 3 > end) goto fail;
    admin->sigs[i].algo_id = mxd_read_u8(&p);
    admin->sigs[i].pubkey_length = mxd_read_u16_be(&p);
    if (admin->sigs[i].pubkey_length == 0 ||
        admin->sigs[i].pubkey_length > 4096) goto fail;
    if (p + admin->sigs[i].pubkey_length + 2 > end) goto fail;
    admin->sigs[i].pubkey = malloc(admin->sigs[i].pubkey_length);
    if (!admin->sigs[i].pubkey) goto fail;
    mxd_read_bytes(&p, admin->sigs[i].pubkey, admin->sigs[i].pubkey_length);
    admin->sigs[i].sig_length = mxd_read_u16_be(&p);
    if (admin->sigs[i].sig_length == 0 ||
        admin->sigs[i].sig_length > 8192) goto fail;
    if (p + admin->sigs[i].sig_length > end) goto fail;
    admin->sigs[i].signature = malloc(admin->sigs[i].sig_length);
    if (!admin->sigs[i].signature) goto fail;
    mxd_read_bytes(&p, admin->sigs[i].signature, admin->sigs[i].sig_length);
  }

  return 0;

fail:
  mxd_free_transaction_v3(tx);
  return -1;
}

// Internal: validate admin structure + 3-of-5 oracle signature quorum.
// Does NOT check nonce reuse (caller decides whether to enforce that).
// Verifies each sig against the currently authorized oracle set: on-chain
// admin:oracle_set if populated (written by a prior UPDATE_ORACLE_SET),
// falling back to config.http.bridge_oracle_pubkeys. This mirrors the
// lookup used in mxd_verify_bridge_oracle_signature for bridge mints.
static int admin_tx_check_structure_and_sigs(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3) return -1;
  if (tx->type != MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE &&
      tx->type != MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE &&
      tx->type != MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) return -1;
  if (tx->input_count != 0 || tx->output_count != 0) return -1;
  if (!tx->payload.admin) return -1;

  const mxd_admin_payload_t *admin = tx->payload.admin;
  if (admin->op_type != tx->type) return -1;

  // For UPDATE_ORACLE_SET, the threshold must be in [1, oracle_set_count].
  // A zero threshold would disable the bridge entirely; a > N threshold
  // would be unsatisfiable. Either is a sign of a malformed admin payload.
  if (admin->op_type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    if (admin->oracle_set_threshold == 0 ||
        admin->oracle_set_threshold > admin->oracle_set_count) {
      MXD_LOG_ERROR("admin", "UPDATE_ORACLE_SET: invalid threshold %u (must be 1..%u)",
                    admin->oracle_set_threshold, admin->oracle_set_count);
      return -1;
    }
  }

  // Build signing message
  uint8_t *sign_msg = NULL;
  size_t sign_len = 0;
  if (mxd_serialize_admin_payload_for_signing(admin, tx->version,
                                                &sign_msg, &sign_len) != 0) {
    MXD_LOG_ERROR("admin", "Failed to build admin signing message");
    return -1;
  }

  // Oracles sign the SHA-512 of the canonical message (same pattern as
  // bridge mint attestation).
  uint8_t msg_hash[64];
  if (mxd_sha512(sign_msg, sign_len, msg_hash) != 0) {
    free(sign_msg);
    MXD_LOG_ERROR("admin", "Failed to hash admin signing message");
    return -1;
  }
  free(sign_msg);

  // Load the authorized oracle pubkey set. Prefer on-chain, fall back to
  // config. Free via free_onchain_oracle_set on all exits. Admin tx quorum
  // (3-of-5 from MXD_ADMIN_MIN_ORACLE_SIGS) is independent of the bridge-mint
  // K-of-N threshold, so we don't read out_threshold here.
  mxd_oracle_pubkey_entry_t *onchain_oracles = NULL;
  uint32_t onchain_oracle_count = 0;
  (void)mxd_load_onchain_oracle_set(&onchain_oracles, &onchain_oracle_count, NULL);
  mxd_config_t *cfg = mxd_get_config();

  int result = -1;
  uint32_t valid_sigs = 0;

  for (uint32_t i = 0; i < admin->sig_count; i++) {
    // Dedupe: each oracle pubkey must appear at most once.
    int duplicate = 0;
    for (uint32_t j = 0; j < i; j++) {
      if (admin->sigs[i].pubkey_length == admin->sigs[j].pubkey_length &&
          memcmp(admin->sigs[i].pubkey, admin->sigs[j].pubkey,
                 admin->sigs[i].pubkey_length) == 0) {
        MXD_LOG_ERROR("admin", "Duplicate oracle pubkey in admin sigs");
        duplicate = 1;
        break;
      }
    }
    if (duplicate) goto done;

    // Confirm this pubkey is in the currently authorized oracle set.
    int authorized = 0;
    if (onchain_oracles && onchain_oracle_count > 0) {
      for (uint32_t o = 0; o < onchain_oracle_count; o++) {
        if (onchain_oracles[o].pubkey_length == admin->sigs[i].pubkey_length &&
            onchain_oracles[o].algo_id == admin->sigs[i].algo_id &&
            memcmp(onchain_oracles[o].pubkey, admin->sigs[i].pubkey,
                   admin->sigs[i].pubkey_length) == 0) {
          authorized = 1;
          break;
        }
      }
    } else if (cfg && cfg->http.bridge_oracle_count > 0) {
      for (uint32_t o = 0; o < cfg->http.bridge_oracle_count; o++) {
        if (cfg->http.bridge_oracle_pubkey_lengths[o] == admin->sigs[i].pubkey_length &&
            cfg->http.bridge_oracle_algo_ids[o] == admin->sigs[i].algo_id &&
            memcmp(cfg->http.bridge_oracle_pubkeys[o], admin->sigs[i].pubkey,
                   admin->sigs[i].pubkey_length) == 0) {
          authorized = 1;
          break;
        }
      }
    }
    if (!authorized) {
      MXD_LOG_WARN("admin", "Admin sig #%u pubkey is not in authorized oracle set", i);
      continue;
    }

    // Verify the Dilithium5 signature.
    if (mxd_sig_verify(admin->sigs[i].algo_id,
                       admin->sigs[i].signature, admin->sigs[i].sig_length,
                       msg_hash, 64,
                       admin->sigs[i].pubkey) != 0) {
      MXD_LOG_WARN("admin", "Admin sig #%u verification failed", i);
      continue;
    }

    valid_sigs++;
  }

  if (valid_sigs < MXD_ADMIN_MIN_ORACLE_SIGS) {
    MXD_LOG_ERROR("admin", "Admin tx has %u valid oracle sigs, need %u",
                  valid_sigs, MXD_ADMIN_MIN_ORACLE_SIGS);
    goto done;
  }

  result = 0;

done:
  free_onchain_oracle_set(onchain_oracles, onchain_oracle_count);
  return result;
}

// Full admin validation (HTTP submission): structure + quorum + nonce-fresh.
int mxd_validate_admin_tx(const mxd_transaction_v3_t *tx) {
  if (admin_tx_check_structure_and_sigs(tx) != 0) return -1;
  const mxd_admin_payload_t *admin = tx->payload.admin;

  // Replay: each (signer_pubkey, nonce) pair can only authorize one admin
  // tx. Key: "admin_nonce:" + sha256(pubkey) + nonce(u64 BE).
  rocksdb_t *db = mxd_get_rocksdb_db();
  if (db) {
    for (uint32_t i = 0; i < admin->sig_count; i++) {
      uint8_t pk_hash[32];
      if (mxd_sha256(admin->sigs[i].pubkey, admin->sigs[i].pubkey_length,
                     pk_hash) != 0) return -1;
      uint8_t key[12 + 32 + 8];
      memcpy(key, "admin_nonce:", 12);
      memcpy(key + 12, pk_hash, 32);
      uint64_t nonce_be = mxd_htonll(admin->nonce);
      memcpy(key + 44, &nonce_be, 8);
      rocksdb_readoptions_t *ro = rocksdb_readoptions_create();
      char *err = NULL;
      size_t vl = 0;
      char *val = rocksdb_get(db, ro, (const char *)key, 52, &vl, &err);
      rocksdb_readoptions_destroy(ro);
      if (err) { free(err); }
      if (val) {
        free(val);
        MXD_LOG_ERROR("admin", "Admin tx nonce %lu already used by signer %u",
                      (unsigned long)admin->nonce, i);
        return -1;
      }
    }
  }

  return 0;
}

// Consensus-only admin validation (block apply / sync): structure + quorum.
// Skips nonce-reuse check — re-apply during sync is idempotent because the
// underlying RocksDB writes are UPSERTs.
int mxd_validate_admin_tx_consensus_only(const mxd_transaction_v3_t *tx) {
  return admin_tx_check_structure_and_sigs(tx);
}

int mxd_apply_admin_tx(const mxd_transaction_v3_t *tx) {
  if (!tx || !tx->payload.admin) return -1;
  const mxd_admin_payload_t *admin = tx->payload.admin;
  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) return -1;
  rocksdb_writeoptions_t *wo = mxd_get_rocksdb_writeoptions();
  char *err = NULL;

  // Apply the operation
  if (admin->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE) {
    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, admin->bridge_contract, 64);
    rocksdb_put(db, wo, (const char *)key, 76, "1", 1, &err);
    if (err) { MXD_LOG_ERROR("admin", "bridge_auth write: %s", err); free(err); return -1; }
    MXD_LOG_INFO("admin", "Bridge contract AUTHORIZED via admin tx (nonce=%lu)",
                 (unsigned long)admin->nonce);

  } else if (admin->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, admin->bridge_contract, 64);
    rocksdb_delete(db, wo, (const char *)key, 76, &err);
    if (err) { MXD_LOG_ERROR("admin", "bridge_auth revoke: %s", err); free(err); return -1; }
    MXD_LOG_INFO("admin", "Bridge contract REVOKED via admin tx (nonce=%lu)",
                 (unsigned long)admin->nonce);

  } else if (admin->op_type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    // Serialize the oracle list into the same canonical on-wire format
    // so mxd_load_onchain_oracle_set can re-read it. K-of-N threshold (u32 BE)
    // is appended after the entries.
    size_t size = 4; // oracle_count
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      size += 1 + 2 + admin->oracle_set[i].pubkey_length;
    }
    size += 4; // threshold
    uint8_t *val = malloc(size);
    if (!val) return -1;
    uint8_t *p = val;
    mxd_write_u32_be(&p, admin->oracle_set_count);
    for (uint32_t i = 0; i < admin->oracle_set_count; i++) {
      mxd_write_u8(&p, admin->oracle_set[i].algo_id);
      mxd_write_u16_be(&p, admin->oracle_set[i].pubkey_length);
      mxd_write_bytes(&p, admin->oracle_set[i].pubkey,
                      admin->oracle_set[i].pubkey_length);
    }
    mxd_write_u32_be(&p, admin->oracle_set_threshold);
    rocksdb_put(db, wo, "admin:oracle_set", 16, (const char *)val, size, &err);
    free(val);
    if (err) { MXD_LOG_ERROR("admin", "oracle_set write: %s", err); free(err); return -1; }
    MXD_LOG_INFO("admin", "Oracle set UPDATED via admin tx (count=%u, threshold=%u, nonce=%lu)",
                 admin->oracle_set_count, admin->oracle_set_threshold,
                 (unsigned long)admin->nonce);
  } else {
    return -1;
  }

  // Mark each signer's nonce as used.
  for (uint32_t i = 0; i < admin->sig_count; i++) {
    uint8_t pk_hash[32];
    if (mxd_sha256(admin->sigs[i].pubkey, admin->sigs[i].pubkey_length,
                   pk_hash) != 0) continue;
    uint8_t key[52];
    memcpy(key, "admin_nonce:", 12);
    memcpy(key + 12, pk_hash, 32);
    uint64_t nonce_be = mxd_htonll(admin->nonce);
    memcpy(key + 44, &nonce_be, 8);
    rocksdb_put(db, wo, (const char *)key, 52, "1", 1, &err);
    if (err) {
      MXD_LOG_ERROR("admin", "nonce mark: %s", err);
      free(err);
      err = NULL;
    }
  }

  return 0;
}

// Load the on-chain oracle pubkey list and K-of-N threshold. Returns -1 if
// not set — caller should fall back to the config list + config threshold.
// out_threshold may be NULL if caller doesn't need the threshold.
int mxd_load_onchain_oracle_set(mxd_oracle_pubkey_entry_t **out_set,
                                 uint32_t *out_count,
                                 uint32_t *out_threshold) {
  if (!out_set || !out_count) return -1;
  *out_set = NULL; *out_count = 0;
  if (out_threshold) *out_threshold = 0;

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) return -1;
  rocksdb_readoptions_t *ro = rocksdb_readoptions_create();
  char *err = NULL;
  size_t vl = 0;
  char *val = rocksdb_get(db, ro, "admin:oracle_set", 16, &vl, &err);
  rocksdb_readoptions_destroy(ro);
  if (err) { free(err); return -1; }
  if (!val) return -1;
  if (vl < 4) { free(val); return -1; }

  const uint8_t *p = (const uint8_t *)val;
  const uint8_t *end = p + vl;
  uint32_t count = mxd_read_u32_be(&p);
  if (count == 0 || count > MXD_MAX_ADMIN_ORACLE_PUBKEYS) { free(val); return -1; }

  mxd_oracle_pubkey_entry_t *set = calloc(count, sizeof(*set));
  if (!set) { free(val); return -1; }

  for (uint32_t i = 0; i < count; i++) {
    if (p + 3 > end) goto bad;
    set[i].algo_id = mxd_read_u8(&p);
    set[i].pubkey_length = mxd_read_u16_be(&p);
    if (set[i].pubkey_length == 0 || set[i].pubkey_length > 4096) goto bad;
    if (p + set[i].pubkey_length > end) goto bad;
    set[i].pubkey = malloc(set[i].pubkey_length);
    if (!set[i].pubkey) goto bad;
    memcpy(set[i].pubkey, p, set[i].pubkey_length);
    p += set[i].pubkey_length;
  }

  // K-of-N threshold (u32 BE) appended after the entries. Required by current
  // format; missing/short value means stored state is pre-q.1 and must be
  // refreshed via a new UPDATE_ORACLE_SET admin tx.
  if (p + 4 > end) goto bad;
  uint32_t threshold = mxd_read_u32_be(&p);
  if (threshold == 0 || threshold > count) goto bad;

  free(val);
  *out_set = set;
  *out_count = count;
  if (out_threshold) *out_threshold = threshold;
  return 0;

bad:
  for (uint32_t i = 0; i < count; i++) {
    if (set[i].pubkey) free(set[i].pubkey);
  }
  free(set);
  free(val);
  return -1;
}

// Free v3 transaction resources
void mxd_free_transaction_v3(mxd_transaction_v3_t *tx) {
  if (tx) {
    if (tx->inputs) {
      for (uint32_t i = 0; i < tx->input_count; i++) {
        if (tx->inputs[i].public_key) {
          free(tx->inputs[i].public_key);
        }
        if (tx->inputs[i].signature) {
          free(tx->inputs[i].signature);
        }
      }
      free(tx->inputs);
    }
    if (tx->outputs) {
      free(tx->outputs);
    }
    if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
      if (tx->payload.bridge) {
        mxd_free_bridge_payload(tx->payload.bridge);
        free(tx->payload.bridge);
      }
    } else if (tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
               tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
               tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
      if (tx->payload.admin) {
        mxd_free_admin_payload(tx->payload.admin);
        free(tx->payload.admin);
      }
    }
    memset(tx, 0, sizeof(mxd_transaction_v3_t));
  }
}

// Serialize v3 transaction for block storage.
// Wire format (v6: addr32 widened):
//   version(4) | type(4) | input_count(4) | output_count(4) |
//   voluntary_tip(8) | timestamp(8) | tx_hash(64) |
//   [inputs: prev_tx_hash(64) | output_index(4) | algo_id(1) | pubkey_len(2) |
//            pubkey(var) | sig_len(2) | sig(var)] |
//   [outputs: recipient_addr(32) | amount(8)] |
//   -- if bridge type: --
//   bridge_contract(64) | source_chain_id(32) | source_tx_hash(32) |
//   source_block_number(8) | recipient_addr(32) | amount(8) |
//   oracle_algo_id(1) | oracle_pubkey_len(2) | oracle_pubkey(var) |
//   oracle_sig_len(2) | oracle_sig(var)
uint8_t* mxd_serialize_transaction_v3_for_block(const mxd_transaction_v3_t *tx, size_t *out_len) {
  if (!tx || !out_len) return NULL;

  // Calculate total size
  size_t size = 4 + 4 + 4 + 4 + 8 + 8 + 64;  // header + tx_hash

  for (uint32_t i = 0; i < tx->input_count; i++) {
    size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length + 2 + tx->inputs[i].signature_length;
  }

  size += tx->output_count * (MXD_ADDR32_LEN + 8);

  if ((tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) &&
      tx->payload.bridge) {
    mxd_bridge_payload_t *b = tx->payload.bridge;
    // Fixed bridge fields + mxd_chain_id (v6: recipient_addr widened to 32)
    size += 64 + 32 + 32 + 8 + MXD_ADDR32_LEN + 8 + 32;
    // Multi-oracle attestations: oracle_count(4)
    size += 4;
    for (uint32_t i = 0; i < b->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
      size += 1 + 2 + b->oracles[i].pubkey_length + 2 + b->oracles[i].sig_length;
    }
    // Legacy oracle attestation
    size += 1 + 2 + b->oracle_pubkey_length + 2 + b->oracle_sig_length;
  } else if ((tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) &&
             tx->payload.admin) {
    mxd_admin_payload_t *a = tx->payload.admin;
    size += 8; // nonce
    if (a->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
        a->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
      size += 64;
    } else {
      size += 4; // oracle_count
      for (uint32_t i = 0; i < a->oracle_set_count; i++) {
        size += 1 + 2 + a->oracle_set[i].pubkey_length;
      }
      size += 4; // oracle_set_threshold (q.1 wire format — matches deserializer)
    }
    size += 4; // sig_count
    for (uint32_t i = 0; i < a->sig_count; i++) {
      size += 1 + 2 + a->sigs[i].pubkey_length + 2 + a->sigs[i].sig_length;
    }
  }

  uint8_t *buffer = malloc(size);
  if (!buffer) return NULL;
  uint8_t *ptr = buffer;

  // Header
  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, (uint32_t)tx->type);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);
  mxd_write_bytes(&ptr, tx->tx_hash, 64);

  // Inputs
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
    mxd_write_u16_be(&ptr, tx->inputs[i].signature_length);
    if (tx->inputs[i].signature_length > 0 && tx->inputs[i].signature) {
      mxd_write_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
    }
  }

  // Outputs (v6: addr32)
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, MXD_ADDR32_LEN);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  // Bridge payload
  if ((tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) &&
      tx->payload.bridge) {
    mxd_bridge_payload_t *b = tx->payload.bridge;
    mxd_write_bytes(&ptr, b->bridge_contract, 64);
    mxd_write_bytes(&ptr, b->source_chain_id, 32);
    mxd_write_bytes(&ptr, b->source_tx_hash, 32);
    mxd_write_u64_be(&ptr, b->source_block_number);
    mxd_write_bytes(&ptr, b->recipient_addr, MXD_ADDR32_LEN);
    mxd_write_u64_be(&ptr, b->amount);
    mxd_write_bytes(&ptr, b->mxd_chain_id, 32);
    // Multi-oracle attestations
    mxd_write_u32_be(&ptr, b->oracle_count);
    for (uint32_t i = 0; i < b->oracle_count && i < MXD_MAX_BRIDGE_ORACLE_SIGS; i++) {
      mxd_write_u8(&ptr, b->oracles[i].algo_id);
      mxd_write_u16_be(&ptr, b->oracles[i].pubkey_length);
      if (b->oracles[i].pubkey && b->oracles[i].pubkey_length > 0) {
        mxd_write_bytes(&ptr, b->oracles[i].pubkey, b->oracles[i].pubkey_length);
      }
      mxd_write_u16_be(&ptr, b->oracles[i].sig_length);
      if (b->oracles[i].signature && b->oracles[i].sig_length > 0) {
        mxd_write_bytes(&ptr, b->oracles[i].signature, b->oracles[i].sig_length);
      }
    }
    // Legacy oracle fields
    mxd_write_u8(&ptr, b->oracle_algo_id);
    mxd_write_u16_be(&ptr, b->oracle_pubkey_length);
    if (b->oracle_pubkey && b->oracle_pubkey_length > 0) {
      mxd_write_bytes(&ptr, b->oracle_pubkey, b->oracle_pubkey_length);
    }
    mxd_write_u16_be(&ptr, b->oracle_sig_length);
    if (b->oracle_signature && b->oracle_sig_length > 0) {
      mxd_write_bytes(&ptr, b->oracle_signature, b->oracle_sig_length);
    }
  } else if ((tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
              tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) &&
             tx->payload.admin) {
    mxd_admin_payload_t *a = tx->payload.admin;
    mxd_write_u64_be(&ptr, a->nonce);
    if (a->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
        a->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
      mxd_write_bytes(&ptr, a->bridge_contract, 64);
    } else {
      mxd_write_u32_be(&ptr, a->oracle_set_count);
      for (uint32_t i = 0; i < a->oracle_set_count; i++) {
        mxd_write_u8(&ptr, a->oracle_set[i].algo_id);
        mxd_write_u16_be(&ptr, a->oracle_set[i].pubkey_length);
        mxd_write_bytes(&ptr, a->oracle_set[i].pubkey,
                        a->oracle_set[i].pubkey_length);
      }
      mxd_write_u32_be(&ptr, a->oracle_set_threshold);
    }
    mxd_write_u32_be(&ptr, a->sig_count);
    for (uint32_t i = 0; i < a->sig_count; i++) {
      mxd_write_u8(&ptr, a->sigs[i].algo_id);
      mxd_write_u16_be(&ptr, a->sigs[i].pubkey_length);
      mxd_write_bytes(&ptr, a->sigs[i].pubkey, a->sigs[i].pubkey_length);
      mxd_write_u16_be(&ptr, a->sigs[i].sig_length);
      mxd_write_bytes(&ptr, a->sigs[i].signature, a->sigs[i].sig_length);
    }
  }

  *out_len = (size_t)(ptr - buffer);
  return buffer;
}

// Deserialize v3 transaction from block storage format.
// Returns 0 on success, -1 on error. Caller must free via mxd_free_transaction_v3().
int mxd_deserialize_transaction_v3_from_block(const uint8_t *data, size_t data_len,
                                               mxd_transaction_v3_t *tx) {
  if (!data || !tx || data_len < 4 + 4 + 4 + 4 + 8 + 8 + 64) return -1;

  memset(tx, 0, sizeof(mxd_transaction_v3_t));

  const uint8_t *ptr = data;
  const uint8_t *end = data + data_len;

  // Header
  tx->version = mxd_read_u32_be(&ptr);
  if (tx->version != 3) return -1;

  tx->type = (mxd_tx_type_t)mxd_read_u32_be(&ptr);
  tx->input_count = mxd_read_u32_be(&ptr);
  tx->output_count = mxd_read_u32_be(&ptr);
  tx->voluntary_tip = mxd_read_u64_be(&ptr);
  tx->timestamp = mxd_read_u64_be(&ptr);
  mxd_read_bytes(&ptr, tx->tx_hash, 64);

  // Bounds check counts
  if (tx->input_count > MXD_MAX_TX_INPUTS || tx->output_count > MXD_MAX_TX_OUTPUTS) {
    MXD_LOG_ERROR("transaction", "v3 deser: excessive input/output count");
    return -1;
  }

  // Deserialize inputs
  if (tx->input_count > 0) {
    tx->inputs = calloc(tx->input_count, sizeof(mxd_tx_input_t));
    if (!tx->inputs) goto fail;

    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (ptr + 64 + 4 + 1 + 2 > end) goto fail;
      mxd_read_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
      tx->inputs[i].output_index = mxd_read_u32_be(&ptr);
      tx->inputs[i].algo_id = mxd_read_u8(&ptr);
      tx->inputs[i].public_key_length = mxd_read_u16_be(&ptr);

      if (tx->inputs[i].public_key_length > MXD_PUBKEY_MAX_LEN || ptr + tx->inputs[i].public_key_length + 2 > end)
        goto fail;

      tx->inputs[i].public_key = malloc(tx->inputs[i].public_key_length);
      if (!tx->inputs[i].public_key) goto fail;
      mxd_read_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);

      tx->inputs[i].signature_length = mxd_read_u16_be(&ptr);
      if (tx->inputs[i].signature_length > 0) {
        if (ptr + tx->inputs[i].signature_length > end) goto fail;
        tx->inputs[i].signature = malloc(tx->inputs[i].signature_length);
        if (!tx->inputs[i].signature) goto fail;
        mxd_read_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
      }
    }
  }

  // Deserialize outputs
  if (tx->output_count > 0) {
    tx->outputs = calloc(tx->output_count, sizeof(mxd_tx_output_t));
    if (!tx->outputs) goto fail;

    for (uint32_t i = 0; i < tx->output_count; i++) {
      if (ptr + MXD_ADDR32_LEN + 8 > end) goto fail;
      mxd_read_bytes(&ptr, tx->outputs[i].recipient_addr, MXD_ADDR32_LEN);
      tx->outputs[i].amount = mxd_read_u64_be(&ptr);
    }
  }

  // Deserialize bridge payload
  if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
    // Minimum: fixed fields(64+32+32+8+32+8+32) + oracle_count(4) + legacy oracle(1+2+2) — v6 addr32
    if (ptr + 64 + 32 + 32 + 8 + MXD_ADDR32_LEN + 8 + 32 + 4 > end) goto fail;

    tx->payload.bridge = calloc(1, sizeof(mxd_bridge_payload_t));
    if (!tx->payload.bridge) goto fail;

    mxd_bridge_payload_t *b = tx->payload.bridge;
    mxd_read_bytes(&ptr, b->bridge_contract, 64);
    mxd_read_bytes(&ptr, b->source_chain_id, 32);
    mxd_read_bytes(&ptr, b->source_tx_hash, 32);
    b->source_block_number = mxd_read_u64_be(&ptr);
    mxd_read_bytes(&ptr, b->recipient_addr, MXD_ADDR32_LEN);
    b->amount = mxd_read_u64_be(&ptr);
    mxd_read_bytes(&ptr, b->mxd_chain_id, 32);

    // Multi-oracle attestations
    b->oracle_count = mxd_read_u32_be(&ptr);
    if (b->oracle_count > MXD_MAX_BRIDGE_ORACLE_SIGS) {
      MXD_LOG_ERROR("transaction", "v3 deser: oracle_count %u exceeds max", b->oracle_count);
      goto fail;
    }

    for (uint32_t i = 0; i < b->oracle_count; i++) {
      if (ptr + 1 + 2 > end) goto fail;
      b->oracles[i].algo_id = mxd_read_u8(&ptr);
      b->oracles[i].pubkey_length = mxd_read_u16_be(&ptr);

      if (b->oracles[i].pubkey_length > MXD_PUBKEY_MAX_LEN || ptr + b->oracles[i].pubkey_length + 2 > end)
        goto fail;

      b->oracles[i].pubkey = malloc(b->oracles[i].pubkey_length);
      if (!b->oracles[i].pubkey) goto fail;
      mxd_read_bytes(&ptr, b->oracles[i].pubkey, b->oracles[i].pubkey_length);

      b->oracles[i].sig_length = mxd_read_u16_be(&ptr);
      if (b->oracles[i].sig_length == 0 || b->oracles[i].sig_length > MXD_SIG_MAX_LEN ||
          ptr + b->oracles[i].sig_length > end) goto fail;

      b->oracles[i].signature = malloc(b->oracles[i].sig_length);
      if (!b->oracles[i].signature) goto fail;
      mxd_read_bytes(&ptr, b->oracles[i].signature, b->oracles[i].sig_length);
    }

    // Legacy oracle attestation
    if (ptr + 1 + 2 > end) goto fail;
    b->oracle_algo_id = mxd_read_u8(&ptr);
    b->oracle_pubkey_length = mxd_read_u16_be(&ptr);

    if (b->oracle_pubkey_length > 0) {
      // Validate oracle pubkey length against algorithm
      if ((b->oracle_algo_id == MXD_SIGALG_ED25519 && b->oracle_pubkey_length != 32) ||
          (b->oracle_algo_id == MXD_SIGALG_DILITHIUM5 && b->oracle_pubkey_length != 2592) ||
          (b->oracle_algo_id != MXD_SIGALG_ED25519 && b->oracle_algo_id != MXD_SIGALG_DILITHIUM5)) {
        MXD_LOG_ERROR("transaction", "v3 deser: invalid legacy oracle algo/pubkey: algo=%u len=%u",
                       b->oracle_algo_id, b->oracle_pubkey_length);
        goto fail;
      }

      if (ptr + b->oracle_pubkey_length + 2 > end) goto fail;
      b->oracle_pubkey = malloc(b->oracle_pubkey_length);
      if (!b->oracle_pubkey) goto fail;
      mxd_read_bytes(&ptr, b->oracle_pubkey, b->oracle_pubkey_length);

      b->oracle_sig_length = mxd_read_u16_be(&ptr);
      if (b->oracle_sig_length == 0 || ptr + b->oracle_sig_length > end) goto fail;
      b->oracle_signature = malloc(b->oracle_sig_length);
      if (!b->oracle_signature) goto fail;
      mxd_read_bytes(&ptr, b->oracle_signature, b->oracle_sig_length);
    } else {
      // No legacy oracle — read past sig_length field
      if (ptr + 2 > end) goto fail;
      b->oracle_sig_length = mxd_read_u16_be(&ptr);
    }
  } else if (tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
             tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
             tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    // Admin payload: nonce + op-specific body + sig_count + sigs
    if (ptr + 8 > end) goto fail;
    tx->payload.admin = calloc(1, sizeof(mxd_admin_payload_t));
    if (!tx->payload.admin) goto fail;
    mxd_admin_payload_t *a = tx->payload.admin;
    a->op_type = tx->type;
    a->nonce = mxd_read_u64_be(&ptr);

    if (a->op_type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
        a->op_type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE) {
      if (ptr + 64 > end) goto fail;
      mxd_read_bytes(&ptr, a->bridge_contract, 64);
    } else {
      if (ptr + 4 > end) goto fail;
      a->oracle_set_count = mxd_read_u32_be(&ptr);
      if (a->oracle_set_count == 0 ||
          a->oracle_set_count > MXD_MAX_ADMIN_ORACLE_PUBKEYS) goto fail;
      a->oracle_set = calloc(a->oracle_set_count, sizeof(mxd_oracle_pubkey_entry_t));
      if (!a->oracle_set) goto fail;
      for (uint32_t i = 0; i < a->oracle_set_count; i++) {
        if (ptr + 3 > end) goto fail;
        a->oracle_set[i].algo_id = mxd_read_u8(&ptr);
        a->oracle_set[i].pubkey_length = mxd_read_u16_be(&ptr);
        if (a->oracle_set[i].pubkey_length == 0 ||
            a->oracle_set[i].pubkey_length > 4096) goto fail;
        if (ptr + a->oracle_set[i].pubkey_length > end) goto fail;
        a->oracle_set[i].pubkey = malloc(a->oracle_set[i].pubkey_length);
        if (!a->oracle_set[i].pubkey) goto fail;
        mxd_read_bytes(&ptr, a->oracle_set[i].pubkey, a->oracle_set[i].pubkey_length);
      }
      // K-of-N threshold appended after the oracle entries (q.1 wire format).
      // Range check happens in mxd_validate_admin_tx → admin_tx_check_structure_and_sigs.
      if (ptr + 4 > end) goto fail;
      a->oracle_set_threshold = mxd_read_u32_be(&ptr);
    }

    // Validator signatures
    if (ptr + 4 > end) goto fail;
    a->sig_count = mxd_read_u32_be(&ptr);
    if (a->sig_count < MXD_ADMIN_MIN_ORACLE_SIGS ||
        a->sig_count > MXD_ADMIN_MAX_ORACLE_SIGS) goto fail;
    for (uint32_t i = 0; i < a->sig_count; i++) {
      if (ptr + 3 > end) goto fail;
      a->sigs[i].algo_id = mxd_read_u8(&ptr);
      a->sigs[i].pubkey_length = mxd_read_u16_be(&ptr);
      if (a->sigs[i].pubkey_length == 0 ||
          a->sigs[i].pubkey_length > 4096) goto fail;
      if (ptr + a->sigs[i].pubkey_length + 2 > end) goto fail;
      a->sigs[i].pubkey = malloc(a->sigs[i].pubkey_length);
      if (!a->sigs[i].pubkey) goto fail;
      mxd_read_bytes(&ptr, a->sigs[i].pubkey, a->sigs[i].pubkey_length);
      a->sigs[i].sig_length = mxd_read_u16_be(&ptr);
      if (a->sigs[i].sig_length == 0 ||
          a->sigs[i].sig_length > 8192) goto fail;
      if (ptr + a->sigs[i].sig_length > end) goto fail;
      a->sigs[i].signature = malloc(a->sigs[i].sig_length);
      if (!a->sigs[i].signature) goto fail;
      mxd_read_bytes(&ptr, a->sigs[i].signature, a->sigs[i].sig_length);
    }
  }

  return 0;

fail:
  mxd_free_transaction_v3(tx);
  return -1;
}

// Apply v3 transaction to UTXO database.
// Adapts v3 transaction to v2 format for UTXO application (reuses tested code path).
int mxd_apply_transaction_v3_to_utxo(const mxd_transaction_v3_t *tx_v3) {
  if (!tx_v3) return -1;

  // Create a minimal v2 wrapper for UTXO application
  mxd_transaction_t wrapper;
  memset(&wrapper, 0, sizeof(wrapper));
  wrapper.version = 2;
  // Bridge mints create new coins (like coinbase), bridge burns consume inputs
  wrapper.is_coinbase = (tx_v3->type == MXD_TX_TYPE_BRIDGE_MINT) ? 1 : 0;
  wrapper.output_count = tx_v3->output_count;
  wrapper.outputs = tx_v3->outputs;    // Shared pointer, do NOT free
  wrapper.input_count = tx_v3->input_count;
  wrapper.inputs = tx_v3->inputs;      // Shared pointer, do NOT free
  wrapper.voluntary_tip = tx_v3->voluntary_tip;
  wrapper.timestamp = tx_v3->timestamp;
  memcpy(wrapper.tx_hash, tx_v3->tx_hash, 64);

  int ret = mxd_apply_transaction_to_utxo(&wrapper);

  // Zero out shared pointers to prevent double-free
  wrapper.outputs = NULL;
  wrapper.inputs = NULL;

  return ret;
}

// ========== Bridge Pending Queue ==========

static mxd_transaction_v3_t pending_bridge_txs[MXD_MAX_PENDING_BRIDGE_TXS];
static size_t pending_bridge_count = 0;
static pthread_mutex_t pending_bridge_mutex = PTHREAD_MUTEX_INITIALIZER;

// Deep-copy a v3 transaction into dst. Handles bridge and admin payloads.
static int bridge_tx_deep_copy(mxd_transaction_v3_t *dst, const mxd_transaction_v3_t *src) {
  memcpy(dst, src, sizeof(mxd_transaction_v3_t));
  dst->inputs = NULL;
  dst->outputs = NULL;
  dst->payload.bridge = NULL;  // same storage as admin

  if (src->output_count > 0 && src->outputs) {
    dst->outputs = malloc(sizeof(mxd_tx_output_t) * src->output_count);
    if (!dst->outputs) return -1;
    memcpy(dst->outputs, src->outputs, sizeof(mxd_tx_output_t) * src->output_count);
  }

  if (src->type == MXD_TX_TYPE_BRIDGE_MINT || src->type == MXD_TX_TYPE_BRIDGE_BURN) {
    if (src->payload.bridge) {
      dst->payload.bridge = malloc(sizeof(mxd_bridge_payload_t));
      if (!dst->payload.bridge) goto fail;
      memset(dst->payload.bridge, 0, sizeof(mxd_bridge_payload_t));
      if (mxd_bridge_payload_deep_copy(dst->payload.bridge, src->payload.bridge) != 0) {
        free(dst->payload.bridge);
        dst->payload.bridge = NULL;
        goto fail;
      }
    }
  } else if (src->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
             src->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
             src->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
    if (src->payload.admin) {
      mxd_admin_payload_t *a_src = src->payload.admin;
      mxd_admin_payload_t *a_dst = calloc(1, sizeof(mxd_admin_payload_t));
      if (!a_dst) goto fail;
      dst->payload.admin = a_dst;
      a_dst->nonce = a_src->nonce;
      a_dst->op_type = a_src->op_type;
      a_dst->oracle_set_threshold = a_src->oracle_set_threshold;
      memcpy(a_dst->bridge_contract, a_src->bridge_contract, 64);
      if (a_src->oracle_set_count > 0 && a_src->oracle_set) {
        a_dst->oracle_set_count = a_src->oracle_set_count;
        a_dst->oracle_set = calloc(a_src->oracle_set_count, sizeof(mxd_oracle_pubkey_entry_t));
        if (!a_dst->oracle_set) goto fail;
        for (uint32_t i = 0; i < a_src->oracle_set_count; i++) {
          a_dst->oracle_set[i].algo_id = a_src->oracle_set[i].algo_id;
          a_dst->oracle_set[i].pubkey_length = a_src->oracle_set[i].pubkey_length;
          if (a_src->oracle_set[i].pubkey_length > 0) {
            a_dst->oracle_set[i].pubkey = malloc(a_src->oracle_set[i].pubkey_length);
            if (!a_dst->oracle_set[i].pubkey) goto fail;
            memcpy(a_dst->oracle_set[i].pubkey, a_src->oracle_set[i].pubkey,
                   a_src->oracle_set[i].pubkey_length);
          }
        }
      }
      a_dst->sig_count = a_src->sig_count;
      for (uint32_t i = 0; i < a_src->sig_count; i++) {
        a_dst->sigs[i].algo_id = a_src->sigs[i].algo_id;
        a_dst->sigs[i].pubkey_length = a_src->sigs[i].pubkey_length;
        a_dst->sigs[i].sig_length = a_src->sigs[i].sig_length;
        if (a_src->sigs[i].pubkey_length > 0) {
          a_dst->sigs[i].pubkey = malloc(a_src->sigs[i].pubkey_length);
          if (!a_dst->sigs[i].pubkey) goto fail;
          memcpy(a_dst->sigs[i].pubkey, a_src->sigs[i].pubkey,
                 a_src->sigs[i].pubkey_length);
        }
        if (a_src->sigs[i].sig_length > 0) {
          a_dst->sigs[i].signature = malloc(a_src->sigs[i].sig_length);
          if (!a_dst->sigs[i].signature) goto fail;
          memcpy(a_dst->sigs[i].signature, a_src->sigs[i].signature,
                 a_src->sigs[i].sig_length);
        }
      }
    }
  }

  return 0;

fail:
  mxd_free_transaction_v3(dst);
  return -1;
}

int mxd_queue_bridge_mint(const mxd_transaction_v3_t *tx) {
  if (!tx) return -1;

  pthread_mutex_lock(&pending_bridge_mutex);

  // Dedup so the same tx submitted to multiple validators in parallel doesn't
  // get included by each one in successive proposed blocks. Admin txs key on
  // (op_type, nonce) — nonce is the operator-coordinated value and any tx with
  // the same nonce is the same governance action. Bridge mints have no nonce
  // concept, so they key on tx_hash (which already commits to source chain id,
  // source tx hash, recipient, amount, and oracle attestations).
  int is_admin = (tx->type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ||
                  tx->type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ||
                  tx->type == MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET);
  for (size_t i = 0; i < pending_bridge_count; i++) {
    const mxd_transaction_v3_t *q = &pending_bridge_txs[i];
    if (is_admin && q->payload.admin && tx->payload.admin &&
        q->type == tx->type &&
        q->payload.admin->nonce == tx->payload.admin->nonce) {
      pthread_mutex_unlock(&pending_bridge_mutex);
      MXD_LOG_INFO("transaction",
                   "Admin tx with same (type=%d, nonce=%lu) already queued — dropping duplicate",
                   tx->type, (unsigned long)tx->payload.admin->nonce);
      return 0;  // not an error — caller's intent already represented in queue
    }
    if (!is_admin && memcmp(q->tx_hash, tx->tx_hash, 64) == 0) {
      pthread_mutex_unlock(&pending_bridge_mutex);
      MXD_LOG_INFO("transaction",
                   "Bridge tx with same tx_hash already queued — dropping duplicate");
      return 0;
    }
    // Mainnet 2026-05-19: oracle retry path with different quorum subsets
    // produced distinct tx_hash values for the SAME BSC source_tx_hash,
    // bypassing the dedup above and causing a +1 MXD double-mint at h=3
    // (deposit 0x7a97d59a re-minted from h=2). The chain-side replay guard
    // (bridge_tx:<source_tx_hash> in RocksDB) only fires after a block is
    // applied — within the pre-block window where both submissions sit on
    // the queue together, only this in-queue check can catch them.
    if (!is_admin && tx->payload.bridge && q->payload.bridge &&
        q->type == MXD_TX_TYPE_BRIDGE_MINT &&
        memcmp(q->payload.bridge->source_tx_hash,
               tx->payload.bridge->source_tx_hash, 32) == 0) {
      pthread_mutex_unlock(&pending_bridge_mutex);
      MXD_LOG_INFO("transaction",
                   "Bridge tx with same source_tx_hash already queued — "
                   "dropping retry-with-different-quorum duplicate");
      return 0;
    }
  }

  if (pending_bridge_count >= MXD_MAX_PENDING_BRIDGE_TXS) {
    pthread_mutex_unlock(&pending_bridge_mutex);
    MXD_LOG_WARN("transaction", "Bridge pending queue full (%zu)", pending_bridge_count);
    return -1;
  }

  if (bridge_tx_deep_copy(&pending_bridge_txs[pending_bridge_count], tx) != 0) {
    pthread_mutex_unlock(&pending_bridge_mutex);
    return -1;
  }
  pending_bridge_count++;

  pthread_mutex_unlock(&pending_bridge_mutex);
  MXD_LOG_INFO("transaction", "V3 tx queued (pending: %zu)", pending_bridge_count);
  return 0;
}

// Admin txs share the same pending queue and proposer inclusion path as
// bridge mints. Keep a distinct public symbol for clarity.
int mxd_queue_admin_tx(const mxd_transaction_v3_t *tx) {
  return mxd_queue_bridge_mint(tx);
}

int mxd_dequeue_bridge_mints(mxd_transaction_v3_t *out, size_t max_count, size_t *out_count) {
  if (!out || !out_count) return -1;

  pthread_mutex_lock(&pending_bridge_mutex);

  size_t count = pending_bridge_count < max_count ? pending_bridge_count : max_count;

  // Deep copy each entry to avoid sharing heap pointers (use-after-free)
  for (size_t i = 0; i < count; i++) {
    if (bridge_tx_deep_copy(&out[i], &pending_bridge_txs[i]) != 0) {
      // Clean up already-copied entries on failure
      for (size_t j = 0; j < i; j++) {
        mxd_free_transaction_v3(&out[j]);
      }
      pthread_mutex_unlock(&pending_bridge_mutex);
      *out_count = 0;
      return -1;
    }
  }

  // Free originals before shifting
  for (size_t i = 0; i < count; i++) {
    mxd_free_transaction_v3(&pending_bridge_txs[i]);
  }

  // Shift remaining entries forward
  if (count < pending_bridge_count) {
    memmove(pending_bridge_txs, pending_bridge_txs + count,
            sizeof(mxd_transaction_v3_t) * (pending_bridge_count - count));
  }
  // Zero shifted-out slots to prevent stale pointer use
  memset(&pending_bridge_txs[pending_bridge_count - count], 0,
         sizeof(mxd_transaction_v3_t) * count);
  pending_bridge_count -= count;
  *out_count = count;

  pthread_mutex_unlock(&pending_bridge_mutex);
  return 0;
}

size_t mxd_pending_bridge_count(void) {
  pthread_mutex_lock(&pending_bridge_mutex);
  size_t count = pending_bridge_count;
  pthread_mutex_unlock(&pending_bridge_mutex);
  return count;
}
