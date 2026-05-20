#include "../include/mxd_data_quantization.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_proof_initialization(void) {
  TEST_START("Proof Initialization");
  TEST_ASSERT(mxd_init_quantization() == 0, "Quantization system initialization successful");
  TEST_END("Proof Initialization");
}

static void test_dilithium_proof(void) {
  uint8_t data[64] = "Test data for Dilithium proof";
  mxd_proof_t proof;

  TEST_START("Dilithium Proof");
  TEST_VALUE("Input data", "%s", (char *)data);
  
  // Generate proof
  TEST_ASSERT(mxd_generate_proof(data, strlen((char *)data),
                            MXD_PROOF_TYPE_DILITHIUM, &proof) == 0, "Proof generation successful");
  TEST_ASSERT(proof.type == MXD_PROOF_TYPE_DILITHIUM, "Proof type is Dilithium");
  TEST_ASSERT(proof.proof_size > 0, "Proof size is non-zero");
  TEST_VALUE("Proof size", "%zu", proof.proof_size);
  TEST_ARRAY("Proof data", proof.proof_data, proof.proof_size);

  // Verify proof
  TEST_ASSERT(mxd_verify_proof(&proof, data, strlen((char *)data)) == 0, "Proof verification successful");

  mxd_free_proof(&proof);
  TEST_END("Dilithium Proof");
}

static void test_merkle_proof(void) {
  uint8_t data[64] = "Test data for Merkle proof";
  mxd_proof_t proof;

  TEST_START("Merkle Proof");
  TEST_VALUE("Input data", "%s", (char *)data);
  
  // Generate proof
  TEST_ASSERT(mxd_generate_proof(data, strlen((char *)data), MXD_PROOF_TYPE_MERKLE,
                            &proof) == 0, "Proof generation successful");
  TEST_ASSERT(proof.type == MXD_PROOF_TYPE_MERKLE, "Proof type is Merkle");
  TEST_ASSERT(proof.proof_size > 0, "Proof size is non-zero");
  TEST_VALUE("Proof size", "%zu", proof.proof_size);
  TEST_ARRAY("Proof data", proof.proof_data, proof.proof_size);

  // Verify proof
  TEST_ASSERT(mxd_verify_proof(&proof, data, strlen((char *)data)) == 0, "Proof verification successful");

  mxd_free_proof(&proof);
  TEST_END("Merkle Proof");
}

static void test_zk_stark_proof(void) {
  uint8_t data[64] = "Test data for zk-STARK proof";
  mxd_proof_t proof;

  // Generate proof
  assert(mxd_generate_proof(data, strlen((char *)data), MXD_PROOF_TYPE_ZK_STARK,
                            &proof) == 0);
  assert(proof.type == MXD_PROOF_TYPE_ZK_STARK);
  assert(proof.proof_size > 0);

  // Verify proof
  assert(mxd_verify_proof(&proof, data, strlen((char *)data)) == 0);

  mxd_free_proof(&proof);
  printf("zk-STARK proof test passed\n");
}

static void test_proof_aggregation(void) {
  uint8_t data1[64] = "Test data 1";
  uint8_t data2[64] = "Test data 2";
  mxd_proof_t proofs[2];
  mxd_proof_aggregate_t aggregate;

  // Generate proofs
  assert(mxd_generate_proof(data1, strlen((char *)data1),
                            MXD_PROOF_TYPE_DILITHIUM, &proofs[0]) == 0);
  assert(mxd_generate_proof(data2, strlen((char *)data2), MXD_PROOF_TYPE_MERKLE,
                            &proofs[1]) == 0);

  // Aggregate proofs
  assert(mxd_aggregate_proofs(proofs, 2, &aggregate) == 0);
  assert(aggregate.count == 2);

  // Verify aggregate
  assert(mxd_verify_aggregate(&aggregate) == 0);

  mxd_free_proof(&proofs[0]);
  mxd_free_proof(&proofs[1]);
  mxd_free_aggregate(&aggregate);
  printf("Proof aggregation test passed\n");
}

int main(void) {
  printf("Starting data quantization tests...\n");

  test_proof_initialization();
  test_dilithium_proof();
  test_merkle_proof();
  test_zk_stark_proof();
  test_proof_aggregation();

  printf("All data quantization tests passed\n");
  return 0;
}
