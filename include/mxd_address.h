#ifndef MXD_ADDRESS_H
#define MXD_ADDRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_crypto.h"

// MXD address layer per MXD-01 v1.1.x.
//
// Address string format:
//   "mx" + Base58Check( version_byte || addr32 || checksum4 )    37 bytes payload
//   addr32 = SHA-512(algo_id || pubkey)[0..31]
//   checksum4 = SHA-512(SHA-512(version_byte || addr32))[0..3]

#define MXD_ADDR32_LEN    32
#define MXD_PAYLOAD_LEN   37    // 1 (version) + 32 (addr32) + 4 (checksum)
#define MXD_ADDR_STR_MAX  64    // generous; actual range is 50–53 chars + "mx" prefix + NUL

// Version byte registry per MXD-01 §5.
#define MXD_VBYTE_MAINNET_ED25519     0x32
#define MXD_VBYTE_MAINNET_DILITHIUM5  0x33
#define MXD_VBYTE_MAINNET_COMPOSITE   0x34   // reserved (MXD-PQ-03)
#define MXD_VBYTE_TESTNET_ED25519     0x3A
#define MXD_VBYTE_TESTNET_DILITHIUM5  0x3B
#define MXD_VBYTE_TESTNET_COMPOSITE   0x3C   // reserved (MXD-PQ-03)

// Generate a fresh BIP-39 mnemonic. Thin wrapper over mxd_bip39_generate.
//   num_words: 12 or 24
int mxd_generate_passphrase_n(int num_words, char *out, size_t out_len);

// Derive addr32 = SHA-512(algo_id || pubkey)[0..31].
//   pubkey_len: must equal mxd_sig_pubkey_len(algo_id) (32 for Ed25519, 2592 for Dilithium5)
int mxd_derive_address(uint8_t algo_id,
                        const uint8_t *pubkey, size_t pubkey_len,
                        uint8_t out_addr32[MXD_ADDR32_LEN]);

// Encode an MXD address string given (algo_id, pubkey).
// Selects the version byte from algo_id and `network` (1 = mainnet, 0 = testnet).
//   out:     buffer for NUL-terminated address string
//   out_len: capacity (>= MXD_ADDR_STR_MAX recommended)
int mxd_address_to_string(uint8_t algo_id, const uint8_t *pubkey, size_t pubkey_len,
                           int mainnet, char *out, size_t out_len);

// Validate an address string (prefix, length, base58, checksum, version-byte registry).
// Returns 0 if valid, -1 if not.
int mxd_validate_address(const char *address);

// Parse an address string into (algo_id, addr32). algo_id is derived from the
// version byte per MXD-01 §9. Returns 0 on success, -1 on any failure.
// Composite version bytes (0x34/0x3C) parse successfully and set algo_id=0x03;
// callers are responsible for refusing to sign for or construct outputs to
// algo_id=0x03 addresses (mxd_address_to_string and mxd_sign_tx_input enforce
// this already).
int mxd_parse_address(const char *address, uint8_t *out_algo_id,
                       uint8_t out_addr32[MXD_ADDR32_LEN]);

// -------------------------------------------------------------------------
// Compatibility shims — DEPRECATED. Phase 8.3 will delete these.
// -------------------------------------------------------------------------

// Shim for callers expecting a 20-byte addr output (returns first 20 bytes of
// addr32). Migrate to mxd_parse_address() with MXD_ADDR32_LEN output.
int mxd_parse_address_legacy_addr20(const char *address, uint8_t *out_algo_id,
                                    uint8_t out_addr20[20]);

// Legacy: generate 12-word passphrase (calls mxd_generate_passphrase_n(12,...))
__attribute__((deprecated("Use mxd_generate_passphrase_n(12, ...) instead")))
int mxd_generate_passphrase(char *output, size_t max_length);


#ifdef __cplusplus
}
#endif

#endif  // MXD_ADDRESS_H
