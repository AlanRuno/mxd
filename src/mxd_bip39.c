#include "../include/mxd_bip39.h"
#include "../include/mxd_crypto.h"
#include "bip39_wordlist.h"
#include <openssl/evp.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BIP39_WORDLIST_SIZE 2048

int mxd_bip39_generate(int entropy_bits, char *out, size_t out_len) {
    if (!out) return -1;
    if (entropy_bits != 128 && entropy_bits != 256) return -1;

    size_t entropy_bytes = (size_t)entropy_bits / 8;
    uint8_t entropy[32];
    randombytes_buf(entropy, entropy_bytes);

    /* Compute checksum: first (entropy_bits / 32) bits of SHA-256(entropy) */
    uint8_t cs_hash[32];
    if (mxd_sha256(entropy, entropy_bytes, cs_hash) != 0) {
        sodium_memzero(entropy, sizeof(entropy));
        return -1;
    }
    int cs_bits = entropy_bits / 32;  /* 4 (12 words) or 8 (24 words) */

    /* Total bits = entropy_bits + checksum_bits; word_count = total / 11 */
    int total_bits = entropy_bits + cs_bits;
    int word_count = total_bits / 11;  /* 12 or 24 */

    /* Pack bits into 11-bit indices and write words */
    size_t offset = 0;
    for (int w = 0; w < word_count; w++) {
        uint32_t idx = 0;
        for (int b = 0; b < 11; b++) {
            int bit_pos = w * 11 + b;
            uint8_t bit;
            if (bit_pos < entropy_bits) {
                bit = (entropy[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1;
            } else {
                int cs_bit_pos = bit_pos - entropy_bits;
                bit = (cs_hash[cs_bit_pos / 8] >> (7 - (cs_bit_pos % 8))) & 1;
            }
            idx = (idx << 1) | bit;
        }
        const char *word = BIP39_WORDS[idx];
        size_t wlen = strlen(word);
        if (offset + wlen + 2 > out_len) {
            sodium_memzero(entropy, sizeof(entropy));
            out[0] = '\0';
            return -1;
        }
        if (w > 0) out[offset++] = ' ';
        memcpy(out + offset, word, wlen);
        offset += wlen;
    }
    out[offset] = '\0';

    sodium_memzero(entropy, sizeof(entropy));
    return 0;
}

/* Look up a word in BIP39_WORDS via linear scan (2048 words; cheap).
 * Returns index in [0, 2047] or -1 if not found. */
static int bip39_word_index(const char *word, size_t len) {
    for (int i = 0; i < BIP39_WORDLIST_SIZE; i++) {
        const char *w = BIP39_WORDS[i];
        if (strlen(w) == len && memcmp(w, word, len) == 0) return i;
    }
    return -1;
}

int mxd_bip39_validate(const char *mnemonic) {
    if (!mnemonic) return -1;

    /* Tokenize into up to 24 words; reject anything unexpected. */
    uint16_t indices[24];
    int word_count = 0;
    const char *p = mnemonic;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t)(p - start);
        if (word_count >= 24) return -1;
        int idx = bip39_word_index(start, len);
        if (idx < 0) return -1;
        indices[word_count++] = (uint16_t)idx;
    }

    if (word_count != 12 && word_count != 24) return -1;

    /* Reconstruct entropy + checksum bit-stream. */
    int total_bits = word_count * 11;
    int entropy_bits = total_bits * 32 / 33;  /* 128 or 256 */
    int cs_bits = total_bits - entropy_bits;
    size_t entropy_bytes = (size_t)entropy_bits / 8;

    uint8_t buf[33] = {0};  /* entropy_bytes + ceil(cs_bits/8) <= 33 */
    for (int w = 0; w < word_count; w++) {
        uint32_t idx = indices[w];
        for (int b = 0; b < 11; b++) {
            int bit = (idx >> (10 - b)) & 1;
            int bit_pos = w * 11 + b;
            buf[bit_pos / 8] |= (uint8_t)(bit << (7 - (bit_pos % 8)));
        }
    }

    /* Verify checksum. */
    uint8_t cs_hash[32];
    if (mxd_sha256(buf, entropy_bytes, cs_hash) != 0) return -1;

    for (int b = 0; b < cs_bits; b++) {
        int reconstructed = (buf[(entropy_bits + b) / 8] >> (7 - ((entropy_bits + b) % 8))) & 1;
        int expected = (cs_hash[b / 8] >> (7 - (b % 8))) & 1;
        if (reconstructed != expected) return -1;
    }
    return 0;
}

int mxd_bip39_seed(const char *mnemonic, const char *passphrase,
                   uint8_t out_seed[MXD_BIP39_SEED_LEN]) {
    if (!mnemonic || !out_seed) return -1;
    if (!passphrase) passphrase = "";

    /* Salt = "mnemonic" || passphrase (UTF-8 bytes; caller must NFKD-normalize). */
    static const char *prefix = "mnemonic";
    size_t prefix_len = strlen(prefix);
    size_t pp_len = strlen(passphrase);
    size_t salt_len = prefix_len + pp_len;

    uint8_t *salt = (uint8_t *)malloc(salt_len);
    if (!salt) return -1;
    memcpy(salt, prefix, prefix_len);
    memcpy(salt + prefix_len, passphrase, pp_len);

    int rc = PKCS5_PBKDF2_HMAC(
        mnemonic, (int)strlen(mnemonic),
        salt, (int)salt_len,
        MXD_BIP39_PBKDF2_ITERS,
        EVP_sha512(),
        MXD_BIP39_SEED_LEN, out_seed);

    sodium_memzero(salt, salt_len);
    free(salt);
    return rc == 1 ? 0 : -1;
}
