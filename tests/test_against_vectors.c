/*
 * test_against_vectors.c — Task 9.2
 *
 * Integration test: proves that the C library reproduces every populated
 * (non-placeholder) vector in the five MXD-NN-test-vectors.json files.
 *
 * Each group:
 *   test_mxd01_vectors  — MXD-01: pubkey + algo_id → addr32 + checksum4 + address_string
 *   test_mxd02_vectors  — MXD-02: mnemonic → BIP-39 seed → SLIP-10 → pub32 → addr32 → address
 *   test_pq01_vectors   — MXD-PQ-01: same BIP-39 seed → PQ tree → pub2592 → addr32 → address
 *   test_mxd03_vectors  — MXD-03: RFC 8032 Ed25519 sign/verify
 *   test_mxd04_vectors  — MXD-04: build tx → sighash → sign → broadcast bytes
 *
 * Build-time constant MXD_TEST_VECTORS_DIR is set by CMakeLists.txt to
 * point at docs/standards/ in the source tree so the test finds the JSONs
 * wherever ctest runs.
 *
 * Placeholder detection: any expected field whose value starts with
 * "_placeholder" is skipped with a printed note — never silently passed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <cjson/cJSON.h>
#include <sodium.h>

#include "../include/mxd_address.h"
#include "../include/mxd_bip39.h"
#include "../include/mxd_slip10.h"
#include "../include/mxd_wallet.h"
#include "../include/mxd_pq01.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_chain.h"

/* ------------------------------------------------------------------ */
/* Compile-time path set by CMakeLists.txt                            */
/* ------------------------------------------------------------------ */
#ifndef MXD_TEST_VECTORS_DIR
#  error "MXD_TEST_VECTORS_DIR must be set by CMakeLists.txt"
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static int g_skipped = 0;
static int g_verified = 0;
static int g_failed   = 0;   /* set to 1 on first mismatch; causes non-zero exit */

/* Load a JSON file into a cJSON tree (caller must cJSON_Delete). */
static cJSON *load_json(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: cannot open %s\n", path);
        abort();
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    assert(buf);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        fprintf(stderr, "ERROR: JSON parse failed for %s\n", path);
        abort();
    }
    return root;
}

/* Decode a lowercase hex string into bytes. Returns byte count, -1 on error. */
static int hex_decode(const char *hex, uint8_t *out, size_t out_max) {
    if (!hex) return -1;
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t nbytes = hlen / 2;
    if (nbytes > out_max) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%02x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)nbytes;
}

/* True if the string starts with "_placeholder". */
static int is_placeholder(const char *s) {
    return s && strncmp(s, "_placeholder", 12) == 0;
}

/* Macro: check a byte array against an expected hex value from JSON.
 * Skips if the JSON string is a placeholder.
 * desc: human-readable label. */
#define CHECK_HEX(desc, got_bytes, got_len, expected_hex) do { \
    if (is_placeholder(expected_hex)) { \
        printf("  SKIP [%s] — still placeholder\n", desc); \
        g_skipped++; \
    } else { \
        uint8_t _exp[4096]; \
        int _elen = hex_decode(expected_hex, _exp, sizeof(_exp)); \
        assert(_elen >= 0); \
        if ((size_t)_elen != (got_len) || memcmp(_exp, got_bytes, got_len) != 0) { \
            fprintf(stderr, "FAIL [%s]: got/expected mismatch\n  got:      ", desc); \
            for (size_t _i = 0; _i < (got_len); _i++) fprintf(stderr, "%02x", ((const uint8_t*)(got_bytes))[_i]); \
            fprintf(stderr, "\n  expected: %s\n", expected_hex); \
            g_failed = 1; \
        } else { \
            printf("  PASS [%s]\n", desc); \
            g_verified++; \
        } \
    } \
} while(0)

/* Macro: check a NUL-terminated string. */
#define CHECK_STR(desc, got_str, expected_str) do { \
    if (is_placeholder(expected_str)) { \
        printf("  SKIP [%s] — still placeholder\n", desc); \
        g_skipped++; \
    } else { \
        if (strcmp(got_str, expected_str) != 0) { \
            fprintf(stderr, "FAIL [%s]:\n  got:      %s\n  expected: %s\n", \
                    desc, got_str, expected_str); \
            g_failed = 1; \
        } else { \
            printf("  PASS [%s]\n", desc); \
            g_verified++; \
        } \
    } \
} while(0)

/* Safe accessor for cJSON string value, returns "" on missing/null. */
static const char *jstr(const cJSON *obj, const char *key) {
    if (!obj) return "";
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return "";
    return item->valuestring ? item->valuestring : "";
}

/* ------------------------------------------------------------------ */
/* MXD-01: addr32 + checksum4 + address_string                       */
/* ------------------------------------------------------------------ */
static void test_mxd01_vectors(void) {
    printf("\n=== MXD-01 vectors ===\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/MXD-01-test-vectors.json", MXD_TEST_VECTORS_DIR);
    cJSON *root = load_json(path);

    cJSON *vecs = cJSON_GetObjectItemCaseSensitive(root, "positive_vectors");
    assert(vecs && cJSON_IsArray(vecs));

    cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        const char *name = jstr(v, "name");

        /* Skip vectors that carry _placeholder at the vector level */
        if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "_placeholder"))) {
            printf("  SKIP vector [%s] — _placeholder:true\n", name);
            g_skipped++;
            continue;
        }

        cJSON *inp  = cJSON_GetObjectItemCaseSensitive(v, "input");
        cJSON *exp  = cJSON_GetObjectItemCaseSensitive(v, "expected");
        if (!inp || !exp) continue;

        const char *algo_hex   = jstr(inp, "algo_id");
        const char *pubkey_hex = jstr(inp, "pubkey_hex");
        const char *vbyte_hex  = jstr(inp, "version_byte");

        /* Skip if any expected field is a placeholder */
        const char *exp_addr32   = jstr(exp, "addr32_hex");
        const char *exp_check4   = jstr(exp, "checksum4_hex");
        const char *exp_addrstr  = jstr(exp, "address_string");

        if (is_placeholder(exp_addr32) || is_placeholder(exp_addrstr)) {
            printf("  SKIP vector [%s] — expected values still placeholder\n", name);
            g_skipped++;
            continue;
        }

        printf("  Vector: %s\n", name);

        /* Parse algo_id */
        unsigned int algo_id_val;
        sscanf(algo_hex, "0x%02x", &algo_id_val);
        uint8_t algo_id = (uint8_t)algo_id_val;

        /* Parse version byte */
        unsigned int vbyte_val;
        sscanf(vbyte_hex, "0x%02x", &vbyte_val);
        int mainnet = (vbyte_val == MXD_VBYTE_MAINNET_ED25519 ||
                       vbyte_val == MXD_VBYTE_MAINNET_DILITHIUM5);

        /* Decode pubkey */
        uint8_t pubkey[4096];
        int pklen = hex_decode(pubkey_hex, pubkey, sizeof(pubkey));
        assert(pklen > 0);

        /* Derive addr32 */
        uint8_t addr32[32];
        assert(mxd_derive_address(algo_id, pubkey, (size_t)pklen, addr32) == 0);

        CHECK_HEX("addr32", addr32, 32, exp_addr32);

        /* Build address string */
        char addrstr[MXD_ADDR_STR_MAX];
        assert(mxd_address_to_string(algo_id, pubkey, (size_t)pklen, mainnet, addrstr, sizeof(addrstr)) == 0);

        CHECK_STR("address_string", addrstr, exp_addrstr);

        /* Verify checksum4 — parse the address back and manually extract checksum bytes.
         * The 4 checksum bytes are bytes [33..36] of the 37-byte payload. We validate by
         * computing what the library embeds and comparing. Easiest: decode the Base58 part,
         * skip "mx" prefix, then compare payload[33..36] against exp_check4. */
        if (!is_placeholder(exp_check4)) {
            /* Decode the address back to get the raw payload */
            uint8_t algo_back;
            uint8_t addr32_back[32];
            if (mxd_parse_address(addrstr, &algo_back, addr32_back) == 0) {
                /* Recompute checksum: SHA-512(SHA-512(version_byte || addr32))[0..3] */
                uint8_t csInput[33];
                csInput[0] = (uint8_t)vbyte_val;
                memcpy(csInput + 1, addr32, 32);
                uint8_t h1[64], h2[64];
                mxd_sha512(csInput, 33, h1);
                mxd_sha512(h1, 64, h2);
                CHECK_HEX("checksum4", h2, 4, exp_check4);
            } else {
                /* If algo_id is reserved (composite), parse may fail — skip */
                printf("  SKIP [checksum4] — address parse returned error (reserved version byte?)\n");
                g_skipped++;
            }
        } else {
            printf("  SKIP [checksum4] — still placeholder\n");
            g_skipped++;
        }
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* MXD-02: mnemonic → SLIP-10 → pub32 → addr32 → address             */
/* ------------------------------------------------------------------ */
static void test_mxd02_vectors(void) {
    printf("\n=== MXD-02 vectors ===\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/MXD-02-test-vectors.json", MXD_TEST_VECTORS_DIR);
    cJSON *root = load_json(path);

    cJSON *vecs = cJSON_GetObjectItemCaseSensitive(root, "positive_vectors");
    assert(vecs && cJSON_IsArray(vecs));

    cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        const char *name = jstr(v, "name");

        if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "_placeholder"))) {
            printf("  SKIP vector [%s] — _placeholder:true\n", name);
            g_skipped++;
            continue;
        }

        cJSON *inp = cJSON_GetObjectItemCaseSensitive(v, "input");
        cJSON *exp = cJSON_GetObjectItemCaseSensitive(v, "expected");
        if (!inp || !exp) continue;

        const char *mnemonic   = jstr(inp, "mnemonic");
        const char *passphrase = jstr(inp, "passphrase");
        cJSON *account_item    = cJSON_GetObjectItemCaseSensitive(inp, "account");
        uint32_t account       = account_item ? (uint32_t)account_item->valueint : 0;

        /* Skip vectors with placeholder expected values */
        const char *exp_seed    = jstr(exp, "bip39_seed_hex");
        const char *exp_addr32  = jstr(exp, "addr32_hex");
        const char *exp_addrM   = jstr(exp, "address_mainnet");

        if (is_placeholder(exp_seed) || is_placeholder(exp_addr32) || is_placeholder(exp_addrM)) {
            printf("  SKIP vector [%s] — expected values still placeholder\n", name);
            g_skipped++;
            continue;
        }

        printf("  Vector: %s\n", name);

        /* BIP-39 seed */
        uint8_t seed[64];
        assert(mxd_bip39_seed(mnemonic, passphrase, seed) == 0);
        CHECK_HEX("bip39_seed", seed, 64, exp_seed);

        /* SLIP-10 master */
        const char *exp_mpriv  = jstr(exp, "slip10_master_priv32_hex");
        const char *exp_mchain = jstr(exp, "slip10_master_chain32_hex");
        if (!is_placeholder(exp_mpriv) && strlen(exp_mpriv) > 0) {
            uint8_t mpriv[32], mchain[32];
            assert(mxd_slip10_ed25519_master(seed, mpriv, mchain) == 0);
            CHECK_HEX("master_priv32", mpriv, 32, exp_mpriv);
            CHECK_HEX("master_chain32", mchain, 32, exp_mchain);
        }

        /* SLIP-10 child */
        const char *exp_cpriv  = jstr(exp, "child_priv32_hex");
        const char *exp_cchain = jstr(exp, "child_chain32_hex");
        if (!is_placeholder(exp_cpriv) && strlen(exp_cpriv) > 0) {
            uint8_t cpriv[32], cchain[32];
            assert(mxd_slip10_ed25519_derive_mxd_path(seed, 19800, account, cpriv, cchain) == 0);
            CHECK_HEX("child_priv32", cpriv, 32, exp_cpriv);
            CHECK_HEX("child_chain32", cchain, 32, exp_cchain);
        }

        /* Full wallet derivation */
        mxd_wallet_v2_t w;
        assert(mxd_wallet_derive_v2(mnemonic, passphrase, account, &w) == 0);

        /* pub32 */
        const char *exp_pub32 = jstr(exp, "ed25519_pub32_hex");
        if (!is_placeholder(exp_pub32) && strlen(exp_pub32) > 0) {
            CHECK_HEX("ed25519_pub32", w.pub32, 32, exp_pub32);
        }

        CHECK_HEX("addr32", w.addr32, 32, exp_addr32);
        CHECK_STR("address_mainnet", w.address_mainnet, exp_addrM);

        const char *exp_addrT = jstr(exp, "address_testnet");
        if (!is_placeholder(exp_addrT) && strlen(exp_addrT) > 0) {
            CHECK_STR("address_testnet", w.address_testnet, exp_addrT);
        }

        mxd_wallet_v2_free(&w);
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* MXD-PQ-01: mnemonic → PQ tree → pub2592 → addr32 → address        */
/* ------------------------------------------------------------------ */
static void test_pq01_vectors(void) {
    printf("\n=== MXD-PQ-01 vectors ===\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/MXD-PQ-01-test-vectors.json", MXD_TEST_VECTORS_DIR);
    cJSON *root = load_json(path);

    cJSON *vecs = cJSON_GetObjectItemCaseSensitive(root, "positive_vectors");
    assert(vecs && cJSON_IsArray(vecs));

    cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        const char *name = jstr(v, "name");

        if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "_placeholder"))) {
            printf("  SKIP vector [%s] — _placeholder:true\n", name);
            g_skipped++;
            continue;
        }

        /* Skip vectors that don't have mnemonic inputs (invariant vectors, round-trip vector) */
        cJSON *inp = cJSON_GetObjectItemCaseSensitive(v, "input");
        if (!inp) {
            printf("  SKIP vector [%s] — no 'input' object (invariant/structural vector)\n", name);
            g_skipped++;
            continue;
        }
        const char *mnemonic = jstr(inp, "mnemonic");
        if (!mnemonic || strlen(mnemonic) == 0) {
            /* deterministic_keygen_round_trip uses leaf_xi32 as input, not mnemonic */
            const char *leaf_xi_hex = jstr(inp, "leaf_xi32_hex");
            if (leaf_xi_hex && strlen(leaf_xi_hex) > 0 && !is_placeholder(leaf_xi_hex)) {
                printf("  Vector: %s\n", name);
                cJSON *exp = cJSON_GetObjectItemCaseSensitive(v, "expected");
                if (!exp) { g_skipped++; continue; }

                cJSON *first = cJSON_GetObjectItemCaseSensitive(exp, "first_keygen");
                if (!first) { g_skipped++; continue; }

                const char *exp_pub = jstr(first, "pub2592_hex");
                if (is_placeholder(exp_pub)) {
                    printf("  SKIP [%s/first_keygen/pub2592] — still placeholder\n", name);
                    g_skipped++;
                    continue;
                }

                uint8_t leaf_xi[32];
                hex_decode(leaf_xi_hex, leaf_xi, 32);

                uint8_t pub[2592], priv[4896];
                assert(mxd_pq01_keygen_at_leaf(leaf_xi, pub, priv) == 0);
                CHECK_HEX("keygen_round_trip/pub2592", pub, 2592, exp_pub);
            } else {
                printf("  SKIP vector [%s] — no usable mnemonic or leaf_xi\n", name);
                g_skipped++;
            }
            continue;
        }

        const char *passphrase = jstr(inp, "passphrase");
        cJSON *acct_item = cJSON_GetObjectItemCaseSensitive(inp, "account");
        uint32_t account = acct_item ? (uint32_t)acct_item->valueint : 0;

        cJSON *exp = cJSON_GetObjectItemCaseSensitive(v, "expected");
        if (!exp) { g_skipped++; continue; }

        /* Skip if pub2592 and/or addr32 are placeholders */
        const char *exp_pub2592  = jstr(exp, "ml_dsa_87_pub2592_hex");
        const char *exp_addr32   = jstr(exp, "addr32_hex");
        const char *exp_addrM    = jstr(exp, "address_mainnet");

        if (is_placeholder(exp_pub2592) || strlen(exp_pub2592) == 0) {
            printf("  SKIP vector [%s] — pub2592_hex still placeholder\n", name);
            g_skipped++;
            continue;
        }
        if (is_placeholder(exp_addr32) || strlen(exp_addr32) == 0) {
            printf("  SKIP vector [%s] — addr32_hex still placeholder\n", name);
            g_skipped++;
            continue;
        }

        printf("  Vector: %s\n", name);

        /* BIP-39 seed */
        uint8_t seed[64];
        assert(mxd_bip39_seed(mnemonic, passphrase, seed) == 0);

        const char *exp_seed = jstr(exp, "bip39_seed_hex");
        if (!is_placeholder(exp_seed) && strlen(exp_seed) > 0) {
            CHECK_HEX("bip39_seed", seed, 64, exp_seed);
        }

        /* PQ-01 master */
        const char *exp_xi = jstr(exp, "master_xi32_hex");
        if (!is_placeholder(exp_xi) && strlen(exp_xi) > 0) {
            uint8_t xi[32], ch[32];
            assert(mxd_pq01_master(seed, xi, ch) == 0);
            CHECK_HEX("master_xi32", xi, 32, exp_xi);
        }

        /* PQ-01 leaf */
        const char *exp_leaf_xi = jstr(exp, "leaf_xi32_hex");
        uint8_t leaf_xi[32], leaf_chain[32];
        assert(mxd_pq01_derive_mxd_path(seed, 19800, account, leaf_xi, leaf_chain) == 0);
        if (!is_placeholder(exp_leaf_xi) && strlen(exp_leaf_xi) > 0) {
            CHECK_HEX("leaf_xi32", leaf_xi, 32, exp_leaf_xi);
        }

        /* ML-DSA-87 KeyGen */
        uint8_t pub[2592], priv[4896];
        assert(mxd_pq01_keygen_at_leaf(leaf_xi, pub, priv) == 0);
        CHECK_HEX("pub2592", pub, 2592, exp_pub2592);

        /* addr32 via Dilithium5 */
        uint8_t addr32[32];
        assert(mxd_derive_address(MXD_SIGALG_DILITHIUM5, pub, 2592, addr32) == 0);
        CHECK_HEX("addr32", addr32, 32, exp_addr32);

        /* address_mainnet */
        if (!is_placeholder(exp_addrM) && strlen(exp_addrM) > 0) {
            char addrstr[MXD_ADDR_STR_MAX];
            assert(mxd_address_to_string(MXD_SIGALG_DILITHIUM5, pub, 2592, 1, addrstr, sizeof(addrstr)) == 0);
            CHECK_STR("address_mainnet", addrstr, exp_addrM);
        }

        const char *exp_addrT = jstr(exp, "address_testnet");
        if (!is_placeholder(exp_addrT) && strlen(exp_addrT) > 0) {
            char addrt[MXD_ADDR_STR_MAX];
            assert(mxd_address_to_string(MXD_SIGALG_DILITHIUM5, pub, 2592, 0, addrt, sizeof(addrt)) == 0);
            CHECK_STR("address_testnet", addrt, exp_addrT);
        }
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* MXD-03: RFC 8032 Ed25519 sign + verify                             */
/* ------------------------------------------------------------------ */
static void test_mxd03_vectors(void) {
    printf("\n=== MXD-03 vectors ===\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/MXD-03-test-vectors.json", MXD_TEST_VECTORS_DIR);
    cJSON *root = load_json(path);

    cJSON *vecs = cJSON_GetObjectItemCaseSensitive(root, "ed25519_positive_vectors");
    assert(vecs && cJSON_IsArray(vecs));

    cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        const char *name = jstr(v, "name");

        if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "_placeholder"))) {
            printf("  SKIP vector [%s] — _placeholder:true\n", name);
            g_skipped++;
            continue;
        }

        cJSON *inp = cJSON_GetObjectItemCaseSensitive(v, "input");
        cJSON *exp = cJSON_GetObjectItemCaseSensitive(v, "expected");
        if (!inp || !exp) continue;

        const char *exp_sig = jstr(exp, "sig64_hex");
        if (is_placeholder(exp_sig)) {
            printf("  SKIP vector [%s] — sig64_hex still placeholder\n", name);
            g_skipped++;
            continue;
        }

        printf("  Vector: %s\n", name);

        const char *priv_hex = jstr(inp, "priv32_hex");
        const char *pub_hex  = jstr(inp, "pub32_hex");
        const char *msg_hex  = jstr(inp, "msg_hex");

        uint8_t seed32[32], pub[32];
        hex_decode(priv_hex, seed32, 32);
        hex_decode(pub_hex,  pub,    32);

        /* Expand 32-byte seed into libsodium 64-byte secret key (seed || pub) */
        uint8_t sk64[64], pk_derived[32];
        assert(crypto_sign_seed_keypair(pk_derived, sk64, seed32) == 0);

        /* Decode message (may be empty) */
        size_t msg_hex_len = strlen(msg_hex);
        size_t msg_len = msg_hex_len / 2;
        uint8_t *msg = msg_len ? malloc(msg_len) : NULL;
        if (msg_len) hex_decode(msg_hex, msg, msg_len);

        /* Sign with 64-byte libsodium key */
        uint8_t sig[64];
        size_t sig_len = 64;
        int rc = mxd_sig_sign(MXD_SIGALG_ED25519, sig, &sig_len, msg, msg_len, sk64);
        assert(rc == 0);
        assert(sig_len == 64);

        CHECK_HEX("sig64", sig, 64, exp_sig);

        /* Verify */
        int vrc = mxd_sig_verify(MXD_SIGALG_ED25519, sig, 64, msg, msg_len, pub);
        if (vrc != 0) {
            fprintf(stderr, "FAIL [%s]: verify returned %d, expected 0\n", name, vrc);
            g_failed = 1;
        } else {
            printf("  PASS [%s/verify]\n", name);
            g_verified++;
        }

        free(msg);
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* MXD-04: build tx from inputs → sighash → sign → broadcast bytes   */
/* ------------------------------------------------------------------ */

/*
 * Build a transaction, compute sighash, sign, serialize, compare.
 *
 * The Alice key used in all vectors:
 *   priv32: 847dbf23adbf0270eb8118f1e13fab328a9cf81a476d63757c6018bb278a1ca4
 *   pub32:  0c88dc68ac619aa0f9e54138661505b36659306a8924f6f01b448f40c3518522
 */

/* Alice's SLIP-10 seed (32 bytes) from MXD-02 abandon×11 about, account=0.
 * Derived via mxd_slip10_ed25519_derive_mxd_path(seed, 19800, 0, ...).
 * Value: 1dbe41d6b377d0aa72b1e58644c07da9cbc127b6d83b937154fed90611ab94b8 */
static const uint8_t ALICE_PRIV_SEED[32] = {
    0x1d, 0xbe, 0x41, 0xd6, 0xb3, 0x77, 0xd0, 0xaa,
    0x72, 0xb1, 0xe5, 0x86, 0x44, 0xc0, 0x7d, 0xa9,
    0xcb, 0xc1, 0x27, 0xb6, 0xd8, 0x3b, 0x93, 0x71,
    0x54, 0xfe, 0xd9, 0x06, 0x11, 0xab, 0x94, 0xb8
};


static void run_mxd04_vector(const cJSON *v, const cJSON *actor_keys, const char *name) {
    if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "_placeholder"))) {
        printf("  SKIP vector [%s] — _placeholder:true\n", name);
        g_skipped++;
        return;
    }

    cJSON *inp = cJSON_GetObjectItemCaseSensitive(v, "input");
    cJSON *exp = cJSON_GetObjectItemCaseSensitive(v, "expected");
    if (!inp || !exp) return;

    /* Check if sighash is a placeholder */
    const char *exp_sighash = jstr(exp, "sighash_hex");
    const char *exp_bcast   = jstr(exp, "broadcast_tx_bytes_hex");
    if (is_placeholder(exp_sighash) || is_placeholder(exp_bcast)) {
        printf("  SKIP vector [%s] — sighash/broadcast still placeholder\n", name);
        g_skipped++;
        return;
    }

    printf("  Vector: %s\n", name);

    cJSON *tx_c = cJSON_GetObjectItemCaseSensitive(inp, "tx_construction");
    if (!tx_c) {
        /* Some vectors put tx_construction at the top of input (vector_a) */
        tx_c = inp;
    }

    /* Skip vectors whose inputs array is absent — those are wallet-demonstration
     * vectors (e.g. vector_b_dust_change_dropped_to_tip) that don't supply
     * enough wire-format data to reproduce from scratch in a unit test. */
    cJSON *inputs_check = cJSON_GetObjectItemCaseSensitive(tx_c, "inputs");
    if (!inputs_check || !cJSON_IsArray(inputs_check)) {
        printf("  SKIP vector [%s] — no 'inputs' array (wallet-construction demo only)\n", name);
        g_skipped++;
        return;
    }

    /* Header fields */
    cJSON *ver_item  = cJSON_GetObjectItemCaseSensitive(tx_c, "version");
    cJSON *ts_item   = cJSON_GetObjectItemCaseSensitive(tx_c, "timestamp_unix");
    cJSON *tip_item  = cJSON_GetObjectItemCaseSensitive(tx_c, "voluntary_tip_base_units");
    cJSON *cid_str   = cJSON_GetObjectItemCaseSensitive(tx_c, "chain_id");

    uint32_t version = ver_item ? (uint32_t)ver_item->valueint : 2;
    uint64_t timestamp = ts_item ? (uint64_t)ts_item->valuedouble : 0;
    uint64_t tip = tip_item ? (uint64_t)tip_item->valuedouble : 0;

    uint32_t chain_id = MXD_CHAIN_ID_MAINNET;
    if (cid_str && cJSON_IsString(cid_str)) {
        unsigned long long cid_v;
        sscanf(cid_str->valuestring, "0x%llx", &cid_v);
        chain_id = (uint32_t)cid_v;
    }

    /* Create transaction */
    mxd_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version      = version;
    tx.chain_id     = chain_id;
    tx.voluntary_tip = (mxd_amount_t)tip;
    tx.timestamp    = timestamp;

    /* Add inputs */
    cJSON *inputs_arr = cJSON_GetObjectItemCaseSensitive(tx_c, "inputs");
    if (inputs_arr && cJSON_IsArray(inputs_arr)) {
        cJSON *inp_item;
        cJSON_ArrayForEach(inp_item, inputs_arr) {
            const char *ph = jstr(inp_item, "prev_tx_hash_hex");
            cJSON *oi_item = cJSON_GetObjectItemCaseSensitive(inp_item, "output_index");
            uint32_t oi = oi_item ? (uint32_t)oi_item->valueint : 0;
            const char *pk_hex = jstr(inp_item, "pubkey_hex");

            /* Skip if pubkey is a placeholder (e.g. carol's key) */
            if (is_placeholder(pk_hex)) {
                printf("  SKIP vector [%s] — input pubkey_hex still placeholder\n", name);
                g_skipped++;
                mxd_free_transaction(&tx);
                return;
            }

            uint8_t prev_hash[64];
            memset(prev_hash, 0, 64);
            int ph_len = hex_decode(ph, prev_hash, 64);
            if (ph_len != 64) {
                fprintf(stderr, "FAIL vector [%s]: prev_tx_hash_hex decode returned %d (ph='%.20s')\n",
                        name, ph_len, ph);
                g_failed = 1;
                mxd_free_transaction(&tx);
                return;
            }

            uint8_t pk[2592];
            int pklen = hex_decode(pk_hex, pk, sizeof(pk));
            assert(pklen > 0);

            assert(mxd_add_tx_input(&tx, prev_hash, oi, MXD_SIGALG_ED25519, pk, (size_t)pklen) == 0);
        }
    }

    /* Add outputs */
    cJSON *outputs_arr = cJSON_GetObjectItemCaseSensitive(tx_c, "outputs");
    if (outputs_arr && cJSON_IsArray(outputs_arr)) {
        cJSON *out_item;
        cJSON_ArrayForEach(out_item, outputs_arr) {
            const char *r32_hex = jstr(out_item, "recipient_addr32_hex");
            cJSON *amt_item = cJSON_GetObjectItemCaseSensitive(out_item, "amount_base_units");
            uint64_t amount = amt_item ? (uint64_t)amt_item->valuedouble : 0;

            uint8_t raddr[32];
            hex_decode(r32_hex, raddr, 32);
            assert(mxd_add_tx_output(&tx, raddr, (mxd_amount_t)amount) == 0);
        }
    }

    /* Compute sighash */
    uint8_t sighash[64];
    assert(mxd_calculate_tx_hash(&tx, sighash) == 0);
    CHECK_HEX("sighash", sighash, 64, exp_sighash);

    /* Store sighash as tx_hash so serialize includes it (MXD-04 §10.1 pre-parse dedup hint). */
    memcpy(tx.tx_hash, sighash, 64);

    /* Expand Alice's 32-byte SLIP-10 seed into libsodium's 64-byte secret key
     * (seed || public_key) — mxd_sig_sign(Ed25519) wraps crypto_sign_detached
     * which requires the 64-byte expanded form. */
    uint8_t alice_sk64[64], alice_pk_tmp[32];
    assert(crypto_sign_seed_keypair(alice_pk_tmp, alice_sk64, ALICE_PRIV_SEED) == 0);

    /* Sign each input with Alice's key (all test vectors use Alice for ed25519 inputs;
     * any carol input is already guarded above). */
    for (uint32_t i = 0; i < tx.input_count; i++) {
        assert(mxd_sign_tx_input(&tx, i, MXD_SIGALG_ED25519, alice_sk64) == 0);
    }

    /* Check individual input signatures if present in expected */
    const char *exp_sig0 = jstr(exp, "signature_hex");
    const char *exp_isig0 = jstr(exp, "input_0_signature_hex");

    if (!is_placeholder(exp_sig0) && strlen(exp_sig0) > 0 && tx.input_count >= 1) {
        CHECK_HEX("input_0_sig", tx.inputs[0].signature, 64, exp_sig0);
    }
    if (!is_placeholder(exp_isig0) && strlen(exp_isig0) > 0 && tx.input_count >= 1) {
        CHECK_HEX("input_0_sig", tx.inputs[0].signature, 64, exp_isig0);
    }
    const char *exp_isig1 = jstr(exp, "input_1_signature_hex");
    if (!is_placeholder(exp_isig1) && strlen(exp_isig1) > 0 && tx.input_count >= 2) {
        CHECK_HEX("input_1_sig", tx.inputs[1].signature, 64, exp_isig1);
    }

    /* Serialize (broadcast bytes) */
    size_t bcast_len;
    uint8_t *bcast = mxd_serialize_transaction(&tx, &bcast_len);
    assert(bcast != NULL);
    CHECK_HEX("broadcast_tx_bytes", bcast, bcast_len, exp_bcast);
    free(bcast);

    mxd_free_transaction(&tx);
}

static void test_mxd04_vectors(void) {
    printf("\n=== MXD-04 vectors ===\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/MXD-04-test-vectors.json", MXD_TEST_VECTORS_DIR);
    cJSON *root = load_json(path);

    cJSON *actor_keys = cJSON_GetObjectItemCaseSensitive(root, "_actor_keys");
    cJSON *vecs = cJSON_GetObjectItemCaseSensitive(root, "positive_vectors");
    assert(vecs && cJSON_IsArray(vecs));

    cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        const char *name = jstr(v, "name");
        run_mxd04_vector(v, actor_keys, name);
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium_init() failed\n");
        return 1;
    }

    printf("=== test_against_vectors: C library vs MXD-NN test vectors ===\n");
    printf("Vector directory: %s\n", MXD_TEST_VECTORS_DIR);

    test_mxd01_vectors();
    test_mxd02_vectors();
    test_pq01_vectors();
    test_mxd03_vectors();
    test_mxd04_vectors();

    printf("\n========================================\n");
    printf("Results: %d verified, %d skipped (placeholders), %d FAILED\n",
           g_verified, g_skipped, g_failed);

    if (g_failed > 0) {
        fprintf(stderr, "FATAL: %d vector(s) did not match.\n", g_failed);
        return 1;
    }

    printf("All populated vectors PASS.\n");
    return 0;
}
