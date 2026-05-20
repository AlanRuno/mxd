#ifndef MXD_BIP39_H
#define MXD_BIP39_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// BIP-39 mnemonic and seed derivation per MXD-02 §3, §4.
//
// English wordlist only in this version (MXD-02 §3.1: English MUST). Other
// BIP-39 wordlists are out of scope for the C reference implementation.

#define MXD_BIP39_SEED_LEN  64    // PBKDF2 output, MXD-02 §4
#define MXD_BIP39_PBKDF2_ITERS 2048

// Generate a fresh mnemonic with the requested entropy size.
//   entropy_bits: 128 (12 words) MUST be supported; 256 (24 words) MAY.
//                 Only 128 and 256 are accepted.
//   out:          buffer to receive NUL-terminated UTF-8 mnemonic
//   out_len:      capacity of out (240 bytes is enough for 24 words)
// Returns 0 on success, -1 on error.
int mxd_bip39_generate(int entropy_bits, char *out, size_t out_len);

// Validate a mnemonic per BIP-39 (wordlist + checksum). NFKD-normalize the
// input first if it may have come from a non-canonical source.
// Returns 0 if valid, -1 if invalid.
int mxd_bip39_validate(const char *mnemonic);

// Derive the 64-byte BIP-39 seed.
//   mnemonic: NFKD-normalized UTF-8 (caller's responsibility)
//   passphrase: NFKD-normalized UTF-8; may be empty string ""
//   out_seed: receives 64 bytes
// Implements: PBKDF2(NFKD(mnemonic), "mnemonic"||NFKD(passphrase), 2048,
//                    HMAC-SHA-512, 64 bytes) per BIP-39 / MXD-02 §4.
// Returns 0 on success, -1 on error.
int mxd_bip39_seed(const char *mnemonic, const char *passphrase,
                   uint8_t out_seed[MXD_BIP39_SEED_LEN]);

#ifdef __cplusplus
}
#endif

#endif  // MXD_BIP39_H
