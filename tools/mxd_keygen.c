/*
 * mxd_keygen — generate a node identity keypair file (data/node_keys.v2) offline.
 *
 * Uses the exact same key generation as the node (mxd_sig_keygen: libsodium
 * Ed25519 or pq-crystals ML-DSA-87 / FIPS 204) and writes the MXDK v2 layout
 * read by load_or_generate_node_keypair() in src/mxd_dht.c:
 *
 *   "MXDK"(4) | version=2(1) | algo_id(1) | pubkey_len BE(2) | privkey_len BE(2) | pubkey | privkey
 *
 *   Ed25519    : 10 + 32   + 64   =  106 bytes
 *   Dilithium5 : 10 + 2592 + 4896 = 7498 bytes
 *
 * Prints the algorithm, public key, addr32 and the "mx…" address so the
 * operator can fund the new identity before installing the file. NEVER prints
 * the private key. Refuses to overwrite an existing output file.
 *
 * Usage:
 *   mxd_keygen [--algo dilithium5|ed25519] [--out FILE] [--testnet]
 *
 * Defaults: --algo dilithium5, --out node_keys.v2, mainnet address encoding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"

#define KEYFILE_VERSION 2

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [--algo dilithium5|ed25519] [--out FILE] [--testnet]\n"
            "  --algo     signature algorithm for the new identity (default: dilithium5)\n"
            "  --out      output keyfile path (default: node_keys.v2); never overwritten\n"
            "  --testnet  print the address with the testnet version byte\n",
            argv0);
}

int main(int argc, char **argv) {
    uint8_t algo_id = MXD_SIGALG_DILITHIUM5;
    const char *out_path = "node_keys.v2";
    int mainnet = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
            const char *a = argv[++i];
            if (strcmp(a, "dilithium5") == 0) {
                algo_id = MXD_SIGALG_DILITHIUM5;
            } else if (strcmp(a, "ed25519") == 0) {
                algo_id = MXD_SIGALG_ED25519;
            } else {
                fprintf(stderr, "Unknown algorithm: %s\n", a);
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--testnet") == 0) {
            mainnet = 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    size_t pub_len = mxd_sig_pubkey_len(algo_id);
    size_t priv_len = mxd_sig_privkey_len(algo_id);
    if (pub_len == 0 || priv_len == 0) {
        fprintf(stderr, "Unsupported algo_id %u\n", algo_id);
        return 1;
    }

    static uint8_t pub[MXD_PUBKEY_MAX_LEN];
    static uint8_t priv[MXD_PRIVKEY_MAX_LEN];
    if (mxd_sig_keygen(algo_id, pub, priv) != 0) {
        fprintf(stderr, "Key generation failed for %s\n", mxd_sig_alg_name(algo_id));
        return 1;
    }

    uint8_t addr32[32];
    if (mxd_derive_address(algo_id, pub, pub_len, addr32) != 0) {
        wipe(priv, sizeof(priv));
        fprintf(stderr, "Address derivation failed\n");
        return 1;
    }
    char addr_str[128] = {0};
    if (mxd_address_to_string(algo_id, pub, pub_len, mainnet, addr_str, sizeof(addr_str)) != 0) {
        wipe(priv, sizeof(priv));
        fprintf(stderr, "Address encoding failed\n");
        return 1;
    }

    /* O_EXCL: never clobber an existing identity. 0600: owner-only. */
    int fd = open(out_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        wipe(priv, sizeof(priv));
        fprintf(stderr, "Cannot create %s: %s\n", out_path, strerror(errno));
        return 1;
    }

    uint8_t header[10];
    memcpy(header, "MXDK", 4);
    header[4] = KEYFILE_VERSION;
    header[5] = algo_id;
    uint16_t pub_be = htons((uint16_t)pub_len);
    uint16_t priv_be = htons((uint16_t)priv_len);
    memcpy(header + 6, &pub_be, 2);
    memcpy(header + 8, &priv_be, 2);

    int rc = 0;
    if (write_all(fd, header, sizeof(header)) != 0 ||
        write_all(fd, pub, pub_len) != 0 ||
        write_all(fd, priv, priv_len) != 0 ||
        fsync(fd) != 0) {
        fprintf(stderr, "Write failed: %s\n", strerror(errno));
        rc = 1;
    }
    close(fd);
    wipe(priv, sizeof(priv));
    if (rc != 0) {
        unlink(out_path);
        return rc;
    }

    size_t total = sizeof(header) + pub_len + priv_len;
    printf("Algorithm:   %s (algo_id=%u)\n", mxd_sig_alg_name(algo_id), algo_id);
    printf("Public key:  ");
    print_hex(pub, pub_len);
    printf("\n");
    printf("addr32:      ");
    print_hex(addr32, 32);
    printf("\n");
    printf("Address:     %s (%s)\n", addr_str, mainnet ? "mainnet" : "testnet");
    printf("Keyfile:     %s (%zu bytes)\n", out_path, total);
    printf("\n");
    printf("Install as <data_dir>/node_keys.v2 on the node (or upload to Secret Manager).\n");
    printf("Fund the address above with at least 0.1%% of total supply before starting the\n");
    printf("node so the automatic validator JOIN is accepted. Keep this file private.\n");
    return 0;
}
