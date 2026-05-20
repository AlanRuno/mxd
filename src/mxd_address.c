#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_logging.h"
#include "base58.h"
#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// MXD-01 v1.1.x §4: addr32 = SHA-512(algo_id || pubkey)[0..31]
// ---------------------------------------------------------------------------
int mxd_derive_address(uint8_t algo_id, const uint8_t *pubkey, size_t pubkey_len,
                        uint8_t out_addr32[MXD_ADDR32_LEN]) {
  if (!pubkey || !out_addr32) return -1;
  size_t expected = mxd_sig_pubkey_len(algo_id);
  if (expected == 0 || pubkey_len != expected) {
    MXD_LOG_ERROR("address", "invalid pubkey length %zu for algo %u (expected %zu)",
                  pubkey_len, algo_id, expected);
    return -1;
  }

  // Build (algo_id || pubkey) on the heap to handle Dilithium5's 2592-byte key.
  uint8_t *buf = (uint8_t *)malloc(1 + pubkey_len);
  if (!buf) return -1;
  buf[0] = algo_id;
  memcpy(buf + 1, pubkey, pubkey_len);

  uint8_t full[64];
  int rc = mxd_sha512(buf, 1 + pubkey_len, full);
  free(buf);
  if (rc != 0) return -1;

  memcpy(out_addr32, full, MXD_ADDR32_LEN);
  return 0;
}

// Full BIP-39 English wordlist (2048 words) for 128-bit entropy with 12 words
// Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
#include "bip39_wordlist.h"

int mxd_generate_passphrase_n(int num_words, char *output, size_t max_length) {
  if (!output || !num_words) return -1;
  // 24 words need ~240 chars max
  if (num_words == 24 && max_length < 240) return -1;
  if (num_words == 12 && max_length < 120) return -1;

  size_t offset = 0;
  const size_t wordlist_size = sizeof(BIP39_WORDS) / sizeof(BIP39_WORDS[0]);

  for (int i = 0; i < num_words; i++) {
    uint32_t index = randombytes_uniform((uint32_t)wordlist_size);
    const char *word = BIP39_WORDS[index];
    size_t word_len = strlen(word);

    if (offset + word_len + 2 > max_length) {
      output[0] = '\0';
      return -1;
    }

    if (i > 0) {
      output[offset++] = ' ';
    }

    memcpy(output + offset, word, word_len);
    offset += word_len;
  }
  output[offset] = '\0';

  return 0;
}

int mxd_generate_passphrase(char *output, size_t max_length) {
  return mxd_generate_passphrase_n(12, output, max_length);
}


// ---------------------------------------------------------------------------
// MXD-01 v1.1.x §5: canonical address string — "mx" + Base58(37-byte payload)
// payload = version_byte(1) || addr32(32) || checksum4(4)
// checksum4 = SHA-512(SHA-512(version_byte || addr32))[0..3]
// "mx" prefix is OUTSIDE Base58Check.
// ---------------------------------------------------------------------------
int mxd_address_to_string(uint8_t algo_id, const uint8_t *pubkey, size_t pubkey_len,
                           int mainnet, char *out, size_t out_len) {
  if (!pubkey || !out || out_len < 64) return -1;

  uint8_t version;
  switch (algo_id) {
    case MXD_SIGALG_ED25519:    version = mainnet ? 0x32 : 0x3A; break;
    case MXD_SIGALG_DILITHIUM5: version = mainnet ? 0x33 : 0x3B; break;
    default: return -1;  // 0x03 (composite) is reserved; MXD-PQ-03 not active
  }

  uint8_t addr32[32];
  if (mxd_derive_address(algo_id, pubkey, pubkey_len, addr32) != 0) return -1;

  uint8_t payload[37];
  payload[0] = version;
  memcpy(payload + 1, addr32, 32);

  // checksum4 = SHA-512(SHA-512(version || addr32))[0..3]
  uint8_t h1[64], h2[64];
  if (mxd_sha512(payload, 33, h1) != 0) return -1;
  if (mxd_sha512(h1, 64, h2) != 0) return -1;
  memcpy(payload + 33, h2, 4);

  // "mx" prefix is OUTSIDE Base58Check.
  out[0] = 'm';
  out[1] = 'x';
  return base58_encode(payload, 37, out + 2, out_len - 2);
}

// ---------------------------------------------------------------------------
// mxd_validate_address — wraps mxd_parse_address, discards outputs.
// ---------------------------------------------------------------------------
int mxd_validate_address(const char *address) {
  uint8_t algo;
  uint8_t addr32[32];
  return mxd_parse_address(address, &algo, addr32);
}

// ---------------------------------------------------------------------------
// mxd_parse_address — strips "mx", base58-decodes 37 bytes, verifies checksum,
// maps version byte to algo_id. Rejects composite (0x34/0x3C) per MXD-01 §3 N2.
// ---------------------------------------------------------------------------
int mxd_parse_address(const char *address, uint8_t *out_algo_id,
                       uint8_t out_addr32[MXD_ADDR32_LEN]) {
  if (!address || !out_algo_id || !out_addr32) return -1;
  if (address[0] != 'm' || address[1] != 'x') return -1;

  uint8_t payload[37];
  size_t payload_len = sizeof(payload);
  if (base58_decode(address + 2, payload, &payload_len) != 0 || payload_len != 37) {
    return -1;
  }

  uint8_t version = payload[0];
  // Verify checksum.
  uint8_t h1[64], h2[64];
  if (mxd_sha512(payload, 33, h1) != 0) return -1;
  if (mxd_sha512(h1, 64, h2) != 0) return -1;
  if (memcmp(payload + 33, h2, 4) != 0) return -1;

  // Map version byte → algo_id per MXD-01 §9.
  // Composite (0x34/0x3C) parses successfully to algo_id=0x03; the prohibition
  // on signing and output-construction lives in mxd_address_to_string and
  // mxd_sign_tx_input (both correctly refuse algo_id=0x03 already).
  switch (version) {
    case 0x32: case 0x3A: *out_algo_id = MXD_SIGALG_ED25519;    break;
    case 0x33: case 0x3B: *out_algo_id = MXD_SIGALG_DILITHIUM5; break;
    case 0x34: case 0x3C: *out_algo_id = 0x03;                  break; // MXD-PQ-03 reserved, algo_id=0x03
    default:              return -1;
  }

  memcpy(out_addr32, payload + 1, 32);
  return 0;
}


// ---------------------------------------------------------------------------
// mxd_parse_address_legacy_addr20 — LEGACY SHIM
//
// Callers that still expect a 20-byte address output (e.g. mxd_monitoring.c).
// Returns first 20 bytes of addr32.  Callers MUST migrate to mxd_parse_address().
//
// Scheduled removal: 2026-06-01 (~1 month from audit date 2026-04-28).
// After that date, uncomment the #error below to catch any surviving callers
// at compile time, then delete this shim and its declaration in mxd_address.h.
//
// Tracking: Phase 8.3 was supposed to remove this but shipped without doing so.
//           Use this compile gate instead of relying on a phase label.
//
// #if defined(__DATE__)
// #error "mxd_parse_address_legacy_addr20 has outlived its removal date (2026-06-01). Migrate mxd_monitoring.c to mxd_parse_address() and delete this shim."
// #endif
// ---------------------------------------------------------------------------
int mxd_parse_address_legacy_addr20(const char *address, uint8_t *out_algo_id,
                                    uint8_t out_addr20[20]) {
  if (!out_addr20) return -1;
  uint8_t addr32[MXD_ADDR32_LEN];
  if (mxd_parse_address(address, out_algo_id, addr32) != 0) return -1;
  memcpy(out_addr20, addr32, 20);
  return 0;
}


