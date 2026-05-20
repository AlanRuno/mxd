#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_rsc.h"
#include "test_utils.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void test_dilithium5_address_generation(void) {
    TEST_START("Dilithium5 Address Generation");
    
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint8_t secret_key[MXD_PRIVKEY_MAX_LEN];
    
    int result = mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, public_key, secret_key);
    TEST_ASSERT(result == 0, "Dilithium5 key generation successful");
    
    uint8_t address[MXD_ADDR32_LEN];
    result = mxd_derive_address(MXD_SIGALG_DILITHIUM5, public_key,
                                mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5), address);
    TEST_ASSERT(result == 0, "Address derivation successful");
    TEST_ARRAY("Dilithium5 Address", address, MXD_ADDR32_LEN);
    
    char address_str[128];
    result = mxd_address_to_string(MXD_SIGALG_DILITHIUM5, public_key,
                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5),
                                   /*mainnet*/1, address_str, sizeof(address_str));
    TEST_ASSERT(result == 0, "Address string conversion successful");
    TEST_VALUE("Address string length", "%zu", strlen(address_str));
    
    TEST_ASSERT(strlen(address_str) > 0, "Address string is not empty");
    
    TEST_END("Dilithium5 Address Generation");
}

static void test_dilithium5_transaction_signing(void) {
    TEST_START("Dilithium5 Transaction Signing");
    
    uint8_t sender_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t sender_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t sender_addr[MXD_ADDR32_LEN];

    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, sender_pubkey, sender_privkey) == 0,
                "Sender key generation successful");
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, sender_pubkey,
                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5), sender_addr) == 0,
                "Sender address derivation successful");
    
    uint8_t recipient_addr[MXD_ADDR32_LEN];
    memset(recipient_addr, 0xAB, MXD_ADDR32_LEN);

    mxd_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.input_count = 1;
    tx.output_count = 1;

    tx.inputs = malloc(sizeof(mxd_tx_input_t));
    tx.outputs = malloc(sizeof(mxd_tx_output_t));

    memset(tx.inputs[0].prev_tx_hash, 0x12, 64);
    tx.inputs[0].output_index = 0;
    tx.inputs[0].algo_id = MXD_SIGALG_DILITHIUM5;
    tx.inputs[0].public_key_length = mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    tx.inputs[0].public_key = malloc(tx.inputs[0].public_key_length);
    memcpy(tx.inputs[0].public_key, sender_pubkey, tx.inputs[0].public_key_length);
    tx.inputs[0].signature_length = 0;
    tx.inputs[0].signature = NULL;
    tx.inputs[0].amount = 100.0;

    memcpy(tx.outputs[0].recipient_addr, recipient_addr, MXD_ADDR32_LEN);
    tx.outputs[0].amount = 95.0;
    
    int result = mxd_sign_tx_input(&tx, 0, MXD_SIGALG_DILITHIUM5, sender_privkey);
    TEST_ASSERT(result == 0, "Transaction signing successful");
    TEST_ASSERT(tx.inputs[0].signature_length > 0, "Signature length set");
    TEST_ASSERT(tx.inputs[0].signature != NULL, "Signature allocated");
    TEST_VALUE("Signature length", "%u", tx.inputs[0].signature_length);
    
    result = mxd_verify_tx_input(&tx, 0);
    TEST_ASSERT(result == 0, "Transaction signature verification successful");
    
    mxd_free_transaction(&tx);
    
    TEST_END("Dilithium5 Transaction Signing");
}

static void test_dilithium5_p2p_handshake(void) {
    TEST_START("Dilithium5 P2P Handshake");
    
    uint8_t node_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t node_privkey[MXD_PRIVKEY_MAX_LEN];
    
    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, node_pubkey, node_privkey) == 0,
                "Node key generation successful");
    
    size_t pubkey_len = mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    TEST_VALUE("Dilithium5 public key length", "%zu", pubkey_len);
    TEST_ASSERT(pubkey_len == 2592, "Public key length is 2592 bytes");
    
    const char *message = "P2P handshake test";
    uint8_t signature[MXD_SIG_MAX_LEN];
    size_t sig_len;
    
    int result = mxd_sig_sign(MXD_SIGALG_DILITHIUM5, signature, &sig_len,
                              (const uint8_t *)message, strlen(message), node_privkey);
    TEST_ASSERT(result == 0, "Message signing successful");
    TEST_VALUE("Signature length", "%zu", sig_len);
    
    result = mxd_sig_verify(MXD_SIGALG_DILITHIUM5, signature, sig_len,
                           (const uint8_t *)message, strlen(message), node_pubkey);
    TEST_ASSERT(result == 0, "Signature verification successful");
    
    TEST_END("Dilithium5 P2P Handshake");
}

static void test_dilithium5_block_validation_signature(void) {
    TEST_START("Dilithium5 Block Validation Signature");
    
    uint8_t validator_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t validator_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t validator_addr[MXD_ADDR32_LEN];

    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, validator_pubkey, validator_privkey) == 0,
                "Validator key generation successful");
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, validator_pubkey,
                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5), validator_addr) == 0,
                "Validator address derivation successful");
    
    TEST_ASSERT(mxd_test_register_validator_pubkey(validator_addr, validator_pubkey,
                                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5)) == 0,
                "Validator public key registration successful");
    
    uint8_t retrieved_algo_id;
    TEST_ASSERT(mxd_get_validator_algo_id(validator_addr, &retrieved_algo_id) == 0,
                "Algorithm ID retrieval successful");
    TEST_ASSERT(retrieved_algo_id == MXD_SIGALG_DILITHIUM5, "Algorithm ID matches");
    
    uint8_t block_hash[64];
    memset(block_hash, 0x22, 64);
    
    uint8_t signature[MXD_SIG_MAX_LEN];
    size_t sig_len;
    uint64_t timestamp = time(NULL);
    
    uint8_t sign_data[128];
    memcpy(sign_data, block_hash, 64);
    memcpy(sign_data + 64, validator_addr, 20);
    memcpy(sign_data + 84, &timestamp, sizeof(uint64_t));
    
    int result = mxd_sig_sign(MXD_SIGALG_DILITHIUM5, signature, &sig_len,
                              sign_data, 92, validator_privkey);
    TEST_ASSERT(result == 0, "Block validation signature creation successful");
    TEST_VALUE("Validation signature length", "%zu", sig_len);
    TEST_ASSERT(sig_len == 4627, "ML-DSA-87 (FIPS 204) signature length is 4627 bytes");
    
    result = mxd_sig_verify(MXD_SIGALG_DILITHIUM5, signature, sig_len,
                           sign_data, 92, validator_pubkey);
    TEST_ASSERT(result == 0, "Block validation signature verification successful");
    
    TEST_END("Dilithium5 Block Validation Signature");
}

static void test_dilithium5_genesis_coordination(void) {
    TEST_START("Dilithium5 Genesis Coordination");
    
    uint8_t genesis_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t genesis_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t genesis_addr[MXD_ADDR32_LEN];

    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, genesis_pubkey, genesis_privkey) == 0,
                "Genesis key generation successful");
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, genesis_pubkey,
                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5), genesis_addr) == 0,
                "Genesis address derivation successful");

    mxd_genesis_member_t member;
    memset(&member, 0, sizeof(member));
    memcpy(member.node_address, genesis_addr, 20);  // legacy 20-byte field (Task 5 widens)
    member.algo_id = MXD_SIGALG_DILITHIUM5;
    size_t pubkey_len = mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5);
    memcpy(member.public_key, genesis_pubkey, pubkey_len);
    member.timestamp = time(NULL);
    
    uint8_t announce_hash[64];
    memset(announce_hash, 0x33, 64);
    
    uint8_t signature[MXD_SIG_MAX_LEN];
    size_t sig_len;
    int result = mxd_sig_sign(MXD_SIGALG_DILITHIUM5, signature, &sig_len,
                              announce_hash, 64, genesis_privkey);
    TEST_ASSERT(result == 0, "Genesis announce signing successful");
    TEST_VALUE("Genesis signature length", "%zu", sig_len);
    
    result = mxd_sig_verify(MXD_SIGALG_DILITHIUM5, signature, sig_len,
                           announce_hash, 64, genesis_pubkey);
    TEST_ASSERT(result == 0, "Genesis signature verification successful");
    
    TEST_END("Dilithium5 Genesis Coordination");
}

static void test_mixed_ed25519_dilithium5_network(void) {
    TEST_START("Mixed Ed25519/Dilithium5 Network");
    
    uint8_t ed25519_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t ed25519_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t ed25519_addr[MXD_ADDR32_LEN];

    uint8_t dilithium5_pubkey[MXD_PUBKEY_MAX_LEN];
    uint8_t dilithium5_privkey[MXD_PRIVKEY_MAX_LEN];
    uint8_t dilithium5_addr[MXD_ADDR32_LEN];

    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey) == 0,
                "Ed25519 key generation successful");
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, ed25519_pubkey,
                                   mxd_sig_pubkey_len(MXD_SIGALG_ED25519), ed25519_addr) == 0,
                "Ed25519 address derivation successful");

    TEST_ASSERT(mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey) == 0,
                "Dilithium5 key generation successful");
    TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey,
                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5), dilithium5_addr) == 0,
                "Dilithium5 address derivation successful");

    TEST_ASSERT(memcmp(ed25519_addr, dilithium5_addr, MXD_ADDR32_LEN) != 0,
                "Addresses are different (no collision)");
    
    TEST_ASSERT(mxd_test_register_validator_pubkey(ed25519_addr, ed25519_pubkey,
                                                   mxd_sig_pubkey_len(MXD_SIGALG_ED25519)) == 0,
                "Ed25519 validator registration successful");
    TEST_ASSERT(mxd_test_register_validator_pubkey(dilithium5_addr, dilithium5_pubkey,
                                                   mxd_sig_pubkey_len(MXD_SIGALG_DILITHIUM5)) == 0,
                "Dilithium5 validator registration successful");
    
    uint8_t retrieved_algo_id;
    TEST_ASSERT(mxd_get_validator_algo_id(ed25519_addr, &retrieved_algo_id) == 0,
                "Ed25519 algo_id retrieval successful");
    TEST_ASSERT(retrieved_algo_id == MXD_SIGALG_ED25519, "Ed25519 algo_id correct");
    
    TEST_ASSERT(mxd_get_validator_algo_id(dilithium5_addr, &retrieved_algo_id) == 0,
                "Dilithium5 algo_id retrieval successful");
    TEST_ASSERT(retrieved_algo_id == MXD_SIGALG_DILITHIUM5, "Dilithium5 algo_id correct");
    
    const char *test_message = "Mixed network test message";
    uint8_t ed25519_sig[MXD_SIG_MAX_LEN];
    uint8_t dilithium5_sig[MXD_SIG_MAX_LEN];
    size_t ed25519_sig_len, dilithium5_sig_len;
    
    TEST_ASSERT(mxd_sig_sign(MXD_SIGALG_ED25519, ed25519_sig, &ed25519_sig_len,
                            (const uint8_t *)test_message, strlen(test_message), ed25519_privkey) == 0,
                "Ed25519 signature creation successful");
    TEST_VALUE("Ed25519 signature length", "%zu", ed25519_sig_len);
    
    TEST_ASSERT(mxd_sig_sign(MXD_SIGALG_DILITHIUM5, dilithium5_sig, &dilithium5_sig_len,
                            (const uint8_t *)test_message, strlen(test_message), dilithium5_privkey) == 0,
                "Dilithium5 signature creation successful");
    TEST_VALUE("Dilithium5 signature length", "%zu", dilithium5_sig_len);
    
    TEST_ASSERT(mxd_sig_verify(MXD_SIGALG_ED25519, ed25519_sig, ed25519_sig_len,
                              (const uint8_t *)test_message, strlen(test_message), ed25519_pubkey) == 0,
                "Ed25519 signature verification successful");
    
    TEST_ASSERT(mxd_sig_verify(MXD_SIGALG_DILITHIUM5, dilithium5_sig, dilithium5_sig_len,
                              (const uint8_t *)test_message, strlen(test_message), dilithium5_pubkey) == 0,
                "Dilithium5 signature verification successful");
    
    mxd_test_clear_validator_pubkeys();
    
    TEST_END("Mixed Ed25519/Dilithium5 Network");
}

int main(void) {
    TEST_START("Comprehensive Dilithium5 Tests");
    
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    test_dilithium5_address_generation();
    test_dilithium5_transaction_signing();
    test_dilithium5_p2p_handshake();
    test_dilithium5_block_validation_signature();
    test_dilithium5_genesis_coordination();
    test_mixed_ed25519_dilithium5_network();
    
    TEST_END("Comprehensive Dilithium5 Tests");
    return 0;
}
