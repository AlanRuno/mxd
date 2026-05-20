#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_rsc.h"

static int test_count = 0;
static int test_passed = 0;

#define TEST_START(name) \
    do { \
        test_count++; \
        printf("Test %d: %s ... ", test_count, name); \
        fflush(stdout); \
    } while(0)

#define TEST_END() \
    do { \
        test_passed++; \
        printf("PASSED\n"); \
    } while(0)

void test_mixed_keygen_and_verify(void) {
    TEST_START("Mixed algorithm keygen and signature verification");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    const char* test_message = "Test message for mixed algorithm verification";
    size_t msg_len = strlen(test_message);
    
    uint8_t ed25519_sig[MXD_SIG_MAX_LEN];
    size_t ed25519_sig_len = 0;
    assert(mxd_sig_sign(MXD_SIGALG_ED25519, ed25519_sig, &ed25519_sig_len,
                        (const uint8_t*)test_message, msg_len, ed25519_privkey) == 0);
    assert(ed25519_sig_len == 64);
    
    uint8_t dilithium5_sig[MXD_SIG_MAX_LEN];
    size_t dilithium5_sig_len = 0;
    assert(mxd_sig_sign(MXD_SIGALG_DILITHIUM5, dilithium5_sig, &dilithium5_sig_len,
                        (const uint8_t*)test_message, msg_len, dilithium5_privkey) == 0);
    assert(dilithium5_sig_len == 4627);  /* FIPS 204 ML-DSA-87 (was 4595 Round-3) */
    
    assert(mxd_sig_verify(MXD_SIGALG_ED25519, ed25519_sig, ed25519_sig_len,
                          (const uint8_t*)test_message, msg_len, ed25519_pubkey) == 0);
    assert(mxd_sig_verify(MXD_SIGALG_DILITHIUM5, dilithium5_sig, dilithium5_sig_len,
                          (const uint8_t*)test_message, msg_len, dilithium5_pubkey) == 0);
    
    assert(mxd_sig_verify(MXD_SIGALG_ED25519, dilithium5_sig, dilithium5_sig_len,
                          (const uint8_t*)test_message, msg_len, ed25519_pubkey) != 0);
    assert(mxd_sig_verify(MXD_SIGALG_DILITHIUM5, ed25519_sig, ed25519_sig_len,
                          (const uint8_t*)test_message, msg_len, dilithium5_pubkey) != 0);
    
    TEST_END();
}

void test_mixed_address_generation(void) {
    TEST_START("Mixed algorithm address generation with collision prevention");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    char ed25519_address[64];
    char dilithium5_address[64];
    
    size_t ed25519_pubkey_len = mxd_sig_pubkey_len(MXD_SIGALG_ED25519);
    size_t dilithium5_pubkey_len = mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    
    // Task 3.3: use canonical mxd_address_to_string (37-byte payload, mainnet)
    assert(mxd_address_to_string(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_pubkey_len,
                                  /*mainnet*/1, ed25519_address, sizeof(ed25519_address)) == 0);
    assert(mxd_address_to_string(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_pubkey_len,
                                  /*mainnet*/1, dilithium5_address, sizeof(dilithium5_address)) == 0);

    assert(strcmp(ed25519_address, dilithium5_address) != 0);

    uint8_t parsed_algo_id;
    uint8_t parsed_addr32[MXD_ADDR32_LEN];  // Task 3.3: widened to 32 bytes
    uint8_t expected_addr32[MXD_ADDR32_LEN];

    assert(mxd_parse_address(ed25519_address, &parsed_algo_id, parsed_addr32) == 0);
    assert(parsed_algo_id == MXD_SIGALG_ED25519);
    assert(mxd_derive_address(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_pubkey_len, expected_addr32) == 0);
    assert(memcmp(parsed_addr32, expected_addr32, MXD_ADDR32_LEN) == 0);

    assert(mxd_parse_address(dilithium5_address, &parsed_algo_id, parsed_addr32) == 0);
    assert(parsed_algo_id == MXD_SIGALG_DILITHIUM5);
    assert(mxd_derive_address(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_pubkey_len, expected_addr32) == 0);
    assert(memcmp(parsed_addr32, expected_addr32, MXD_ADDR32_LEN) == 0);
    
    TEST_END();
}

void test_mixed_transaction_inputs(void) {
    TEST_START("Transaction with mixed algorithm inputs");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    mxd_tx_input_t ed25519_input;
    memset(&ed25519_input, 0, sizeof(ed25519_input));
    ed25519_input.algo_id = MXD_SIGALG_ED25519;
    ed25519_input.public_key_length = mxd_sig_pubkey_len(MXD_SIGALG_ED25519);
    ed25519_input.public_key = malloc(ed25519_input.public_key_length);
    memcpy(ed25519_input.public_key, ed25519_pubkey, ed25519_input.public_key_length);
    ed25519_input.signature_length = mxd_sig_signature_len(MXD_SIGALG_ED25519);
    ed25519_input.signature = malloc(ed25519_input.signature_length);
    
    mxd_tx_input_t dilithium5_input;
    memset(&dilithium5_input, 0, sizeof(dilithium5_input));
    dilithium5_input.algo_id = MXD_SIGALG_DILITHIUM5;
    dilithium5_input.public_key_length = mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    dilithium5_input.public_key = malloc(dilithium5_input.public_key_length);
    memcpy(dilithium5_input.public_key, dilithium5_pubkey, dilithium5_input.public_key_length);
    dilithium5_input.signature_length = mxd_sig_signature_len(MXD_SIGALG_DILITHIUM5);
    dilithium5_input.signature = malloc(dilithium5_input.signature_length);
    
    assert(ed25519_input.public_key_length == 32);
    assert(ed25519_input.signature_length == 64);
    assert(dilithium5_input.public_key_length == 2592);
    assert(dilithium5_input.signature_length == 4627);  /* FIPS 204 ML-DSA-87 (was 4595 Round-3) */
    
    free(ed25519_input.public_key);
    free(ed25519_input.signature);
    free(dilithium5_input.public_key);
    free(dilithium5_input.signature);
    
    TEST_END();
}

void test_mixed_validator_signatures(void) {
    TEST_START("Validator signatures with mixed algorithms");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    uint8_t ed25519_addr[MXD_ADDR32_LEN];
    uint8_t dilithium5_addr[MXD_ADDR32_LEN];
    assert(mxd_derive_address(MXD_SIGALG_ED25519, ed25519_pubkey, 32, ed25519_addr) == 0);
    assert(mxd_derive_address(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, 2592, dilithium5_addr) == 0);

    mxd_validator_signature_t ed25519_sig;
    memset(&ed25519_sig, 0, sizeof(ed25519_sig));
    memcpy(ed25519_sig.validator_id, ed25519_addr, 20);  // legacy 20-byte field
    ed25519_sig.algo_id = MXD_SIGALG_ED25519;
    ed25519_sig.signature_length = 64;
    ed25519_sig.timestamp = 1234567890;
    ed25519_sig.chain_position = 0;
    
    mxd_validator_signature_t dilithium5_sig;
    memset(&dilithium5_sig, 0, sizeof(dilithium5_sig));
    memcpy(dilithium5_sig.validator_id, dilithium5_addr, 20);  // legacy 20-byte field
    dilithium5_sig.algo_id = MXD_SIGALG_DILITHIUM5;
    dilithium5_sig.signature_length = 4627;  /* FIPS 204 ML-DSA-87 (was 4595 Round-3) */
    dilithium5_sig.timestamp = 1234567891;
    dilithium5_sig.chain_position = 1;
    
    assert(memcmp(ed25519_sig.validator_id, dilithium5_sig.validator_id, 20) != 0);
    assert(ed25519_sig.algo_id != dilithium5_sig.algo_id);
    assert(ed25519_sig.signature_length != dilithium5_sig.signature_length);
    
    TEST_END();
}

void test_mixed_genesis_members(void) {
    TEST_START("Genesis coordination with mixed algorithm members");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    uint8_t ed25519_addr[MXD_ADDR32_LEN];
    uint8_t dilithium5_addr[MXD_ADDR32_LEN];
    assert(mxd_derive_address(MXD_SIGALG_ED25519, ed25519_pubkey, 32, ed25519_addr) == 0);
    assert(mxd_derive_address(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, 2592, dilithium5_addr) == 0);

    mxd_genesis_member_t ed25519_member;
    memset(&ed25519_member, 0, sizeof(ed25519_member));
    memcpy(ed25519_member.node_address, ed25519_addr, 20);  // legacy 20-byte field
    ed25519_member.algo_id = MXD_SIGALG_ED25519;
    memcpy(ed25519_member.public_key, ed25519_pubkey, 32);
    ed25519_member.timestamp = 1234567890;
    ed25519_member.signature_length = 64;
    
    mxd_genesis_member_t dilithium5_member;
    memset(&dilithium5_member, 0, sizeof(dilithium5_member));
    memcpy(dilithium5_member.node_address, dilithium5_addr, 20);  // legacy 20-byte field
    dilithium5_member.algo_id = MXD_SIGALG_DILITHIUM5;
    memcpy(dilithium5_member.public_key, dilithium5_pubkey, 2592);
    dilithium5_member.timestamp = 1234567891;
    dilithium5_member.signature_length = 4627;  /* FIPS 204 ML-DSA-87 (was 4595 Round-3) */
    
    assert(memcmp(ed25519_member.node_address, dilithium5_member.node_address, 20) != 0);
    assert(ed25519_member.algo_id != dilithium5_member.algo_id);
    assert(ed25519_member.signature_length != dilithium5_member.signature_length);
    
    TEST_END();
}

void test_algorithm_length_helpers(void) {
    TEST_START("Algorithm length helper functions");
    
    assert(mxd_sig_pubkey_len(MXD_SIGALG_ED25519) == 32);
    assert(mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5) == 2592);
    
    assert(mxd_sig_privkey_len(MXD_SIGALG_ED25519) == 64);
    assert(mxd_sig_privkey_len(MXD_SIGALG_DILITHIUM5) == 4896);  /* FIPS 204 ML-DSA-87 */

    assert(mxd_sig_signature_len(MXD_SIGALG_ED25519) == 64);
    assert(mxd_sig_signature_len(MXD_SIGALG_DILITHIUM5) == 4627);  /* FIPS 204 ML-DSA-87 */
    
    assert(strcmp(mxd_sig_alg_name(MXD_SIGALG_ED25519), "Ed25519") == 0);
    assert(strcmp(mxd_sig_alg_name(MXD_SIGALG_DILITHIUM5), "Dilithium5") == 0);
    assert(strcmp(mxd_sig_alg_name(99), "Unknown") == 0);
    
    TEST_END();
}

void test_cross_algorithm_verification_failure(void) {
    TEST_START("Cross-algorithm signature verification should fail");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    
    assert(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0);
    assert(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0);
    
    const char* test_message = "Test message";
    size_t msg_len = strlen(test_message);
    
    uint8_t ed25519_sig[MXD_SIG_MAX_LEN];
    size_t ed25519_sig_len = 0;
    assert(mxd_sig_sign(MXD_SIGALG_ED25519, ed25519_sig, &ed25519_sig_len,
                        (const uint8_t*)test_message, msg_len, ed25519_privkey) == 0);
    
    assert(mxd_sig_verify(MXD_SIGALG_DILITHIUM5, ed25519_sig, ed25519_sig_len,
                          (const uint8_t*)test_message, msg_len, dilithium5_pubkey) != 0);
    
    uint8_t dilithium5_sig[MXD_SIG_MAX_LEN];
    size_t dilithium5_sig_len = 0;
    assert(mxd_sig_sign(MXD_SIGALG_DILITHIUM5, dilithium5_sig, &dilithium5_sig_len,
                        (const uint8_t*)test_message, msg_len, dilithium5_privkey) == 0);
    
    assert(mxd_sig_verify(MXD_SIGALG_ED25519, dilithium5_sig, dilithium5_sig_len,
                          (const uint8_t*)test_message, msg_len, ed25519_pubkey) != 0);
    
    TEST_END();
}

int main(void) {
    printf("=== Mixed Algorithm Integration Tests ===\n\n");
    
    test_mixed_keygen_and_verify();
    test_mixed_address_generation();
    test_mixed_transaction_inputs();
    test_mixed_validator_signatures();
    test_mixed_genesis_members();
    test_algorithm_length_helpers();
    test_cross_algorithm_verification_failure();
    
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_count - test_passed);
    
    if (test_passed == test_count) {
        printf("\nAll tests PASSED!\n");
        return 0;
    } else {
        printf("\nSome tests FAILED!\n");
        return 1;
    }
}
