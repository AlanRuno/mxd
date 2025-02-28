#include "../../include/mxd_data_quantization.h"
#include "../../include/mxd_crypto.h"
#include <stdlib.h>
#include <string.h>

// Initialize proof system
int mxd_init_quantization(void) {
  // Initialize cryptographic primitives
  return 0;
}

// Generate Dilithium proof
static int generate_dilithium_proof(const uint8_t *data, size_t data_size,
                                    mxd_proof_t *proof) {
  if (!data || !proof || data_size == 0) {
    return -1;
  }

  // Generate commitment
  mxd_sha512(data, data_size, proof->commitment);

  // Generate Dilithium signature (simplified)
  memcpy(proof->proof_data, data, data_size);
  proof->proof_size = data_size;
  proof->type = MXD_PROOF_TYPE_DILITHIUM;

  return 0;
}

// Generate Merkle proof
static int generate_merkle_proof(const uint8_t *data, size_t data_size,
                                 mxd_proof_t *proof) {
  if (!data || !proof || data_size == 0) {
    return -1;
  }

  // Generate Merkle tree root as commitment
  mxd_sha512(data, data_size, proof->commitment);

  // Generate Merkle proof (simplified)
  memcpy(proof->proof_data, data, data_size);
  proof->proof_size = data_size;
  proof->type = MXD_PROOF_TYPE_MERKLE;

  return 0;
}

// Generate zk-STARK proof
static int generate_zk_stark_proof(const uint8_t *data, size_t data_size,
                                   mxd_proof_t *proof) {
  if (!data || !proof || data_size == 0) {
    return -1;
  }

  // Generate commitment using SHA-512
  mxd_sha512(data, data_size, proof->commitment);

  // Generate zk-STARK proof (simplified)
  memcpy(proof->proof_data, data, data_size);
  proof->proof_size = data_size;
  proof->type = MXD_PROOF_TYPE_ZK_STARK;

  return 0;
}

// Generate proof for data
int mxd_generate_proof(const uint8_t *data, size_t data_size,
                       mxd_proof_type_t type, mxd_proof_t *proof) {
  if (!data || !proof || data_size == 0 || data_size > MXD_MAX_PROOF_SIZE) {
    return -1;
  }

  // Generate proof based on type
  switch (type) {
  case MXD_PROOF_TYPE_DILITHIUM:
    return generate_dilithium_proof(data, data_size, proof);
  case MXD_PROOF_TYPE_MERKLE:
    return generate_merkle_proof(data, data_size, proof);
  case MXD_PROOF_TYPE_ZK_STARK:
    return generate_zk_stark_proof(data, data_size, proof);
  default:
    return -1;
  }
}

// Verify proof
int mxd_verify_proof(const mxd_proof_t *proof, const uint8_t *public_inputs,
                     size_t inputs_size) {
  if (!proof || !public_inputs || inputs_size == 0) {
    return -1;
  }

  // Verify based on proof type
  uint8_t computed_commitment[64];
  switch (proof->type) {
  case MXD_PROOF_TYPE_DILITHIUM:
    // Verify Dilithium signature (simplified)
    mxd_sha512(proof->proof_data, proof->proof_size, computed_commitment);
    break;
  case MXD_PROOF_TYPE_MERKLE:
    // Verify Merkle proof (simplified)
    mxd_sha512(proof->proof_data, proof->proof_size, computed_commitment);
    break;
  case MXD_PROOF_TYPE_ZK_STARK:
    // Verify zk-STARK proof (simplified)
    mxd_sha512(proof->proof_data, proof->proof_size, computed_commitment);
    break;
  default:
    return -1;
  }

  // Compare computed commitment with stored commitment
  return memcmp(computed_commitment, proof->commitment, 64) == 0 ? 0 : -1;
}

// Aggregate multiple proofs
int mxd_aggregate_proofs(const mxd_proof_t *proofs, size_t proof_count,
                         mxd_proof_aggregate_t *aggregate) {
  if (!proofs || !aggregate || proof_count == 0) {
    return -1;
  }

  // Allocate memory for proofs
  aggregate->proofs = calloc(proof_count, sizeof(mxd_proof_t));
  if (!aggregate->proofs) {
    return -1;
  }

  // Copy proofs
  memcpy(aggregate->proofs, proofs, proof_count * sizeof(mxd_proof_t));
  aggregate->count = proof_count;

  // Calculate aggregate hash
  size_t total_size = 0;
  for (size_t i = 0; i < proof_count; i++) {
    total_size += proofs[i].proof_size;
  }

  uint8_t *combined = malloc(total_size);
  if (!combined) {
    free(aggregate->proofs);
    return -1;
  }

  size_t offset = 0;
  for (size_t i = 0; i < proof_count; i++) {
    memcpy(combined + offset, proofs[i].proof_data, proofs[i].proof_size);
    offset += proofs[i].proof_size;
  }

  mxd_sha512(combined, total_size, aggregate->aggregate_hash);
  free(combined);

  return 0;
}

// Verify aggregated proofs
int mxd_verify_aggregate(const mxd_proof_aggregate_t *aggregate) {
  if (!aggregate || !aggregate->proofs || aggregate->count == 0) {
    return -1;
  }

  // Verify each proof
  for (size_t i = 0; i < aggregate->count; i++) {
    if (mxd_verify_proof(&aggregate->proofs[i],
                         aggregate->proofs[i].public_inputs,
                         sizeof(aggregate->proofs[i].public_inputs)) != 0) {
      return -1;
    }
  }

  // Verify aggregate hash
  uint8_t computed_hash[64];
  size_t total_size = 0;
  for (size_t i = 0; i < aggregate->count; i++) {
    total_size += aggregate->proofs[i].proof_size;
  }

  uint8_t *combined = malloc(total_size);
  if (!combined) {
    return -1;
  }

  size_t offset = 0;
  for (size_t i = 0; i < aggregate->count; i++) {
    memcpy(combined + offset, aggregate->proofs[i].proof_data,
           aggregate->proofs[i].proof_size);
    offset += aggregate->proofs[i].proof_size;
  }

  mxd_sha512(combined, total_size, computed_hash);
  free(combined);

  return memcmp(computed_hash, aggregate->aggregate_hash, 64) == 0 ? 0 : -1;
}

// Free proof resources
void mxd_free_proof(mxd_proof_t *proof) {
  if (proof) {
    memset(proof, 0, sizeof(mxd_proof_t));
  }
}

void mxd_free_aggregate(mxd_proof_aggregate_t *aggregate) {
  if (aggregate) {
    if (aggregate->proofs) {
      free(aggregate->proofs);
    }
    memset(aggregate, 0, sizeof(mxd_proof_aggregate_t));
  }
}
