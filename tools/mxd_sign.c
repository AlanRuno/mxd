/*
 * mxd_sign.c (FIPS 204 ML-DSA-87 variant) — Dilithium5 signing tool for MXD bridge oracle.
 *
 * Migrated 2026-05-14 from liboqs OQS_SIG_alg_dilithium_5 (Round-3) to
 * libmxd.so's mxd_sig_{keygen,sign,verify} which routes through pq-crystals
 * FIPS 204 ML-DSA-87. The Round-3 binary produced 4595-byte signatures with
 * 4864-byte private keys; FIPS 204 produces 4627-byte signatures with
 * 4896-byte private keys. The two schemes are not signature-compatible,
 * so the entire toolchain must match.
 *
 * Commands:
 *   mxd_sign keygen --out <keyfile>
 *   mxd_sign sign   --key <keyfile>       (reads hex message from stdin)
 *   mxd_sign pubkey --key <keyfile>
 *
 * Keyfile format (binary, unchanged from Round-3 layout — only sizes differ):
 *   algo_id       (1 byte)   - always 0x02 for Dilithium5
 *   pubkey_len    (2 bytes)  - big-endian (= 2592 for Dilithium5)
 *   privkey_len   (2 bytes)  - big-endian (= 4896 for FIPS 204 Dilithium5)
 *   pubkey        (pubkey_len bytes)
 *   privkey       (privkey_len bytes)
 *
 * Build (after building libmxd.so via the top-level CMake):
 *   gcc -O2 -o mxd_sign mxd_sign.c \
 *       -I../include \
 *       -L../build/lib -lmxd \
 *       -Wl,-rpath,../build/lib
 * Or install libmxd.so to /usr/local/lib and link with -lmxd directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mxd_crypto.h"  /* mxd_sig_keygen / mxd_sig_sign — FIPS 204 */

#define MXD_SIGALG_DILITHIUM5  2

/* FIPS 204 ML-DSA-87 sizes (was Round-3: 4864 SK, 4595 sig). */
#define DILITHIUM5_PUBKEY_LEN   2592
#define DILITHIUM5_PRIVKEY_LEN  4896
#define DILITHIUM5_SIG_MAX_LEN  4627

/* ---------- helpers ---------- */

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t max_len, size_t *out_len) {
    size_t slen = strlen(hex);
    while (slen > 0 && (hex[slen - 1] == '\n' || hex[slen - 1] == '\r' ||
                         hex[slen - 1] == ' '  || hex[slen - 1] == '\t')) {
        slen--;
    }
    if (slen % 2 != 0) return -1;
    size_t byte_len = slen / 2;
    if (byte_len > max_len) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%2x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    *out_len = byte_len;
    return 0;
}

static void put_be16(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v & 0xFF);
}

static uint16_t get_be16(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
}

/* ---------- keyfile I/O ---------- */

static int write_keyfile(const char *path, uint8_t algo_id,
                         const uint8_t *pubkey, size_t pubkey_len,
                         const uint8_t *privkey, size_t privkey_len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s' for writing\n", path);
        return -1;
    }
    uint8_t header[5];
    header[0] = algo_id;
    put_be16(header + 1, (uint16_t)pubkey_len);
    put_be16(header + 3, (uint16_t)privkey_len);
    if (fwrite(header, 1, 5, f) != 5 ||
        fwrite(pubkey, 1, pubkey_len, f) != pubkey_len ||
        fwrite(privkey, 1, privkey_len, f) != privkey_len) {
        fprintf(stderr, "error: write failed\n");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int read_keyfile(const char *path, uint8_t *algo_id,
                        uint8_t *pubkey, size_t *pubkey_len,
                        uint8_t *privkey, size_t *privkey_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }
    uint8_t header[5];
    if (fread(header, 1, 5, f) != 5) {
        fprintf(stderr, "error: keyfile too short\n");
        fclose(f);
        return -1;
    }
    *algo_id = header[0];
    *pubkey_len = get_be16(header + 1);
    *privkey_len = get_be16(header + 3);

    /* Use MXD_*_MAX_LEN from mxd_crypto.h — same FIPS 204 sizes. */
    if (*pubkey_len > MXD_PUBKEY_MAX_LEN || *privkey_len > MXD_PRIVKEY_MAX_LEN) {
        fprintf(stderr, "error: invalid key lengths in keyfile "
                "(pubkey=%zu max=%u, privkey=%zu max=%u)\n",
                *pubkey_len, MXD_PUBKEY_MAX_LEN,
                *privkey_len, MXD_PRIVKEY_MAX_LEN);
        fclose(f);
        return -1;
    }
    if (fread(pubkey, 1, *pubkey_len, f) != *pubkey_len ||
        fread(privkey, 1, *privkey_len, f) != *privkey_len) {
        fprintf(stderr, "error: keyfile truncated\n");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* ---------- commands ---------- */

static int cmd_keygen(const char *outpath) {
    uint8_t pubkey[DILITHIUM5_PUBKEY_LEN];
    uint8_t privkey[DILITHIUM5_PRIVKEY_LEN];

    /* FIPS 204 ML-DSA-87 keygen via libmxd. */
    if (mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, pubkey, privkey) != 0) {
        fprintf(stderr, "error: keygen failed\n");
        return 1;
    }

    if (write_keyfile(outpath, MXD_SIGALG_DILITHIUM5,
                      pubkey, DILITHIUM5_PUBKEY_LEN,
                      privkey, DILITHIUM5_PRIVKEY_LEN) != 0) {
        return 1;
    }

    /* Print public key hex to stderr (informational). */
    char *hex = malloc(DILITHIUM5_PUBKEY_LEN * 2 + 1);
    if (!hex) return 1;
    hex_encode(pubkey, DILITHIUM5_PUBKEY_LEN, hex);
    fprintf(stderr, "pubkey: %s\n", hex);
    free(hex);

    return 0;
}

static int cmd_sign(const char *keypath) {
    uint8_t algo_id;
    uint8_t pubkey[DILITHIUM5_PUBKEY_LEN];
    uint8_t privkey[DILITHIUM5_PRIVKEY_LEN];
    size_t pubkey_len, privkey_len;

    if (read_keyfile(keypath, &algo_id, pubkey, &pubkey_len, privkey, &privkey_len) != 0) {
        return 1;
    }
    if (algo_id != MXD_SIGALG_DILITHIUM5) {
        fprintf(stderr, "error: keyfile is not Dilithium5 (algo_id=%u)\n", algo_id);
        return 1;
    }
    if (privkey_len != DILITHIUM5_PRIVKEY_LEN) {
        fprintf(stderr, "error: keyfile has Round-3 privkey size (%zu); "
                "expected FIPS 204 size (%d). Regenerate with this binary.\n",
                privkey_len, DILITHIUM5_PRIVKEY_LEN);
        return 1;
    }

    char hex_buf[65536];
    if (!fgets(hex_buf, sizeof(hex_buf), stdin)) {
        fprintf(stderr, "error: no input on stdin\n");
        return 1;
    }

    uint8_t msg[32768];
    size_t msg_len = 0;
    if (hex_decode(hex_buf, msg, sizeof(msg), &msg_len) != 0) {
        fprintf(stderr, "error: invalid hex input\n");
        return 1;
    }

    uint8_t signature[DILITHIUM5_SIG_MAX_LEN];
    size_t sig_len = 0;
    if (mxd_sig_sign(MXD_SIGALG_DILITHIUM5, signature, &sig_len,
                     msg, msg_len, privkey) != 0) {
        fprintf(stderr, "error: signing failed\n");
        return 1;
    }

    char *sig_hex = malloc(sig_len * 2 + 1);
    if (!sig_hex) return 1;
    hex_encode(signature, sig_len, sig_hex);
    printf("%s\n", sig_hex);
    free(sig_hex);

    memset(privkey, 0, sizeof(privkey));
    return 0;
}

static int cmd_pubkey(const char *keypath) {
    uint8_t algo_id;
    uint8_t pubkey[DILITHIUM5_PUBKEY_LEN];
    uint8_t privkey[DILITHIUM5_PRIVKEY_LEN];
    size_t pubkey_len, privkey_len;

    if (read_keyfile(keypath, &algo_id, pubkey, &pubkey_len, privkey, &privkey_len) != 0) {
        return 1;
    }
    memset(privkey, 0, sizeof(privkey));

    char *hex = malloc(pubkey_len * 2 + 1);
    if (!hex) return 1;
    hex_encode(pubkey, pubkey_len, hex);
    printf("%s\n", hex);
    free(hex);

    return 0;
}

/* ---------- usage / main ---------- */

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  mxd_sign keygen --out <keyfile>\n"
        "  mxd_sign sign   --key <keyfile>   (hex message on stdin)\n"
        "  mxd_sign pubkey --key <keyfile>\n"
        "(FIPS 204 ML-DSA-87 build — incompatible with Round-3 keys/sigs)\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0) {
        const char *outpath = NULL;
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--out") == 0) {
                outpath = argv[i + 1];
                break;
            }
        }
        if (!outpath) {
            fprintf(stderr, "error: keygen requires --out <keyfile>\n");
            return 1;
        }
        return cmd_keygen(outpath);

    } else if (strcmp(cmd, "sign") == 0) {
        const char *keypath = NULL;
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--key") == 0) {
                keypath = argv[i + 1];
                break;
            }
        }
        if (!keypath) {
            fprintf(stderr, "error: sign requires --key <keyfile>\n");
            return 1;
        }
        return cmd_sign(keypath);

    } else if (strcmp(cmd, "pubkey") == 0) {
        const char *keypath = NULL;
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--key") == 0) {
                keypath = argv[i + 1];
                break;
            }
        }
        if (!keypath) {
            fprintf(stderr, "error: pubkey requires --key <keyfile>\n");
            return 1;
        }
        return cmd_pubkey(keypath);

    } else {
        fprintf(stderr, "error: unknown command '%s'\n", cmd);
        usage();
        return 1;
    }
}
