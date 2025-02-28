#ifndef MXD_DATA_QUANTIZATION_H
#define MXD_DATA_QUANTIZATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Maximum proof size
#define MXD_MAX_PROOF_SIZE 4096

// Proof types
typedef enum {
  MXD_PROOF_TYPE_DILITHIUM, // Post-quantum signature
  MXD_PROOF_TYPE_MERKLE,    // Merkle proof
  MXD_PROOF_TYPE_ZK_STARK   // Zero-knowledge STARK proof
} mxd_proof_type_t;

// Proof structure
typedef struct {
  uint8_t proof_data[MXD_MAX_PROOF_SIZE]; // Proof data
  size_t proof_size;                      // Size of proof data
  mxd_proof_type_t type;                  // Type of proof
  uint8_t public_inputs[64];              // Public inputs for verification
  uint8_t commitment[64];                 // Commitment to private data
} mxd_proof_t;

// Proof aggregation structure
typedef struct {
  mxd_proof_t *proofs;        // Array of proofs
  size_t count;               // Number of proofs
  uint8_t aggregate_hash[64]; // Aggregate hash of all proofs
} mxd_proof_aggregate_t;

// Initialize proof system
int mxd_init_quantization(void);

// Generate proof for data
int mxd_generate_proof(const uint8_t *data, size_t data_size,
                       mxd_proof_type_t type, mxd_proof_t *proof);

// Verify proof
int mxd_verify_proof(const mxd_proof_t *proof, const uint8_t *public_inputs,
                     size_t inputs_size);

// Aggregate multiple proofs
int mxd_aggregate_proofs(const mxd_proof_t *proofs, size_t proof_count,
                         mxd_proof_aggregate_t *aggregate);

// Verify aggregated proofs
int mxd_verify_aggregate(const mxd_proof_aggregate_t *aggregate);

// Free proof resources
void mxd_free_proof(mxd_proof_t *proof);
void mxd_free_aggregate(mxd_proof_aggregate_t *aggregate);

#ifdef __cplusplus
}
#endif

#endif // MXD_DATA_QUANTIZATION_H
