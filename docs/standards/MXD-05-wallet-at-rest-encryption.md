# MXD-05: Wallet-at-rest Encryption

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.0 |
| **Created** | 2026-05-06 |
| **Updated** | 2026-05-06 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-02, MXD-PQ-01 |

## 1. Abstract

This document defines the local at-rest encryption format for an MXD wallet's private material — the BIP-39 mnemonic and the derived raw private key — when persisted to browser `localStorage`, a desktop application's profile directory, or any other non-volatile store under user control. It does **not** govern transmission of private material across a network (which MUST NOT happen) nor the layout of seed phrases on paper.

Two formats coexist on disk: a legacy v2 format (PBKDF2-HMAC-SHA-256) that all earlier MXD wallets produced, and a v3 format (Argon2id) introduced in this spec. Wallets MUST be able to decrypt both and MUST lazily re-encrypt v2 blobs as v3 on every successful unlock (§6).

## 2. Terminology

| Term | Meaning |
|---|---|
| `wallet blob` | The JSON object persisted to storage. Contains the AES-GCM ciphertext, the KDF parameters, and the public-key material needed to identify the wallet without unlocking it. |
| `password` | The user-supplied UTF-8 string used to derive the AES key. Length and entropy policies are out of scope. |
| `KDF` | Key derivation function. PBKDF2-HMAC-SHA-256 in v2 blobs, Argon2id in v3 blobs. |
| `lazy migration` | The process of decrypting a v2 blob, re-encrypting it as v3 with the same password, and writing it back. Performed transparently to the user. |
| `addr32` | The 32-byte address per MXD-01. Stored in cleartext alongside the blob so the wallet can identify itself before unlock. |

## 3. Wallet blob shape

A wallet blob is a JSON object with the following fields. Field order is not significant; whitespace is not significant.

| Field | Type | v2 | v3 | Notes |
|---|---|---|---|---|
| `version` | integer | `2` | `3` | Determines KDF dispatch. |
| `encrypted` | boolean | `true` | `true` | Sentinel; always true in this format. |
| `algoId` | integer | `1` or `2` | `1` or `2` | MXD-01 §3 algo_id of the keypair. |
| `publicKey` | hex string | required | required | Raw public-key bytes (32 for Ed25519, 2592 for Dilithium5). Stored cleartext. |
| `address` | string | required | required | The display-form `"mx…"` Base58Check address (MXD-01 §9). Stored cleartext. |
| `encryptedData` | hex string | required | required | AES-256-GCM ciphertext of the inner JSON (§4). The 16-byte authentication tag is included in the standard WebCrypto `crypto.subtle.encrypt` output. |
| `salt` | hex string | required | required | 32 bytes. Per-blob random; regenerated on every encrypt and on every lazy migration. |
| `iv` | hex string | required | required | 16 bytes. Per-encrypt random. See §5.2 for the IV-width rationale. |
| `kdf` | string | absent or `"pbkdf2"` | `"argon2id"` | Required in v3; absent or `"pbkdf2"` in v2. |
| `kdfParams` | object | absent | required | Argon2id parameters. See §5.1. |
| `createdAt` | integer | required | required | Unix milliseconds at first creation. Preserved across lazy migration. |

Any wallet blob whose `version` field is missing MUST be treated as `version = 2` (legacy). Any blob whose `version > 3` MUST be rejected — the wallet does not understand the format and refuses to silently downgrade.

## 4. Inner (plaintext) JSON

The plaintext that gets AES-GCM-encrypted into `encryptedData` is a single JSON object:

```
{
  "mnemonic":         <BIP-39 phrase string, MXD-02 §2>,
  "privateKey":       <hex string of raw private-key bytes>,
  "privateKeySeed":   <legacy field; preserved if present>,
  "privateKeySalt":   <legacy field; preserved if present>,
  "publicKey":        <hex string, mirrors blob-level publicKey>,
  "address":          <"mx…", mirrors blob-level address>,
  "algoId":           <integer, mirrors blob-level algoId>,
  "createdAt":        <unix-ms, mirrors blob-level createdAt>
}
```

The duplication between blob-level and inner fields is intentional: an attacker without the password cannot tamper with the inner JSON (AES-GCM authenticates), and a casual inspection of `localStorage` reveals only the public address and algorithm — never the mnemonic or private key.

## 5. Key derivation and cipher

### 5.1 v3 — Argon2id (current)

Per RFC 9106. Parameters are embedded in the blob's `kdfParams` field at encrypt time and read back verbatim at decrypt time. The defaults a fresh wallet uses are:

| Parameter | Value | Notes |
|---|---|---|
| `t` (iterations) | `3` | Time cost. |
| `m` (memory) | `65536` | KiB; equals 64 MiB. |
| `p` (parallelism) | `4` | Lanes. |
| `dkLen` | `32` | Output bytes (= AES-256 key size). |

Salt is the 32 bytes of `salt`. Output is the 32-byte AES-256 key.

A wallet MAY produce blobs with stronger parameters (larger `t`, `m`, or `p`); the only normative requirement is that `kdfParams` faithfully describes what was used. A wallet MUST NOT silently weaken parameters during lazy migration.

### 5.2 v2 — PBKDF2-HMAC-SHA-256 (legacy decrypt-only)

| Parameter | Value | Notes |
|---|---|---|
| Hash | SHA-256 | The KDF inner hash. See §8.2 for SHA-256-vs-SHA-512 commentary. |
| Iterations | `600000` | The OWASP 2023 floor. Older blobs at `100000` MUST also be accepted (some pre-2024 wallets shipped that count); the iteration count is read from any explicit `iterations` field if present, else MUST default to `600000`. |
| Salt | 32 bytes | Read from blob's `salt`. |
| Output | 32 bytes | The AES-256 key. |

Wallets MUST NOT produce new v2 blobs. v2 exists solely so that pre-MXD-05 wallets keep opening.

### 5.3 AES-256-GCM (both versions)

| Parameter | Value | Notes |
|---|---|---|
| Algorithm | AES-256-GCM | Per NIST SP 800-38D. |
| Key | 32 bytes from KDF | §5.1 or §5.2. |
| IV | 16 bytes | Random per encrypt. The reference implementation uses 16 bytes rather than the GCM-recommended 12 because the WebCrypto `AesGcmParams.iv` field accepts arbitrary 1–N byte IVs and the implementation chose 16 to align with the salt width in the original 2023 codebase. The construction remains secure as long as IV uniqueness holds within a single key (and the per-encrypt random regeneration ensures it). |
| Tag | 16 bytes | Default GCM tag length, included as the trailing 16 bytes of `encryptedData` per WebCrypto. |
| AAD | none | No additional authenticated data is bound. |

## 6. Lazy migration v2 → v3

On every successful unlock, the wallet MUST inspect the loaded blob's `version`. If `version < 3`:

1. Decrypt the blob using the legacy KDF dispatched by `version`.
2. Re-encrypt the resulting plaintext using §5.1 (Argon2id) and §5.3 (AES-256-GCM), with a freshly generated `salt` and `iv`.
3. Write the new v3 blob back to the same storage key, replacing the v2 blob.
4. Return the decrypted plaintext to the caller.

If step 3 fails (storage quota, race against another tab, transient I/O error), the wallet MUST still return the decrypted plaintext from step 1. Migration is best-effort — the user is never blocked on unlock by a migration failure. The next successful unlock retries the migration.

Migration MUST NOT prompt the user. The password the user just typed is sufficient for both decrypt and re-encrypt.

## 7. Test vectors

Test vectors will be provided as `MXD-05-test-vectors.json` in a follow-up Dispatch C work item. Vector classes:

- v2 decrypt of a known plaintext at the OWASP 600k iteration count.
- v2 decrypt at the legacy 100k iteration count (produced by some pre-2024 wallets).
- v3 encrypt then decrypt round-trip with default Argon2id parameters.
- v3 decrypt with non-default `kdfParams` (proves parameters are read from the blob, not hard-coded).
- Lazy migration: v2 input → v3 output (verifying the resulting blob decrypts to the same plaintext under the same password).
- Negative: v2 blob with wrong password (rejection at GCM tag verify).
- Negative: v3 blob with `kdfParams` mutated post-encrypt (rejection at GCM tag verify because the password+mutated-params produces the wrong AES key, GCM tag fails).

## 8. Security considerations

### 8.1 Threat model

The defender is a user whose laptop or browser profile is later acquired by an attacker (loss, theft, malware extraction of `localStorage`, forensic image of disk). The attacker has the wallet blob but does not have the password. The attacker has bounded compute — the GPU and ASIC budgets of a well-resourced individual or small team but not a state-level adversary with custom silicon.

The encryption layer is **not** a defense against:

- Live-process key extraction (the password is held in memory while the wallet is unlocked; the seed and private key are decrypted into memory; both are recoverable by anything with read access to the running process).
- A rogue or compromised browser extension (full DOM access trumps every at-rest measure).
- A malicious in-browser script delivered through a wallet UI XSS (same).

### 8.2 SHA-256 in v2 vs SHA-512 elsewhere

The MXD protocol elsewhere uses SHA-512 (chain_id derivation, sighash double-hash, validation-chain commit hashes). v2 wallet blobs use SHA-256 inside PBKDF2. This is **not** a security regression and is **not** worth migrating away from on its own — migration to v3 is justified by the KDF family change (PBKDF2 → Argon2id), not by the inner hash.

The cryptographic argument: PBKDF2's brute-force cost is dominated by the iteration count, not by the inner hash. SHA-256 and SHA-512 have indistinguishable attack cost per iteration on classical hardware, and PBKDF2's HMAC structure provides no asymmetric advantage to either. The v3 jump (memory-hard Argon2id) imposes a real cost wall that GPU and ASIC attackers cannot trivially scale; that is the security delta.

This rationale is why v2 blobs remain readable indefinitely: replacing them is desirable but not urgent, and lazy migration handles it transparently as wallets organically open them.

### 8.3 IV width

GCM's design recommends a 12-byte IV. The reference implementation uses 16 bytes (§5.3) — this is sound but slightly wasteful (4 bytes of stored IV that are not read back into the GCM IV slot at the algorithm level; WebCrypto silently accepts the extra bytes per the AES-GCM specification's variable-length IV provision). Implementations of MXD-05 that produce new v3 blobs MAY use either 12 or 16 bytes; readers MUST accept both lengths transparently because they encounter both.

### 8.4 Argon2id parameter inflation

A wallet implementation MAY raise `t`, `m`, or `p` above the defaults of §5.1 over time as hardware evolves. Doing so silently in lazy migration is acceptable provided the new parameters are recorded in `kdfParams` so subsequent unlocks reproduce the same key. A wallet MUST NOT lower parameters in lazy migration: a v3 blob that decrypted successfully has already paid its KDF cost once; downgrading would constitute a silent security regression.

### 8.5 Public-material disclosure

The blob's cleartext fields `address`, `publicKey`, `algoId`, and `createdAt` are intentionally not encrypted: a wallet may need to display the user's address in a "select wallet to unlock" UI before any password has been entered. These fields are public information by design (the address appears on every transaction the wallet ever signed) and disclose nothing that an on-chain observer could not already learn.

## 9. References

- **MXD-01**: Address Format (the `addr32` and `algoId` reproduced in the blob).
- **MXD-02**: Mnemonic & HD Key Derivation (defines the mnemonic stored as inner `mnemonic`).
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Key Derivation (PQ wallet variant; same encryption layer applies).
- **RFC 9106**: Argon2 Memory-Hard Function for Password Hashing.
- **RFC 8018**: PKCS #5: Password-Based Cryptography Specification (PBKDF2).
- **NIST SP 800-38D**: Galois/Counter Mode (GCM).
- **OWASP Password Storage Cheat Sheet**: Source of the 600k PBKDF2-SHA-256 floor.
- **AUDIT_2026-05-05_v6.md** finding **L6-1**: motivated the v3 introduction and lazy migration rule.
- Reference implementation: `MXDNetwork/wallet-client/src/crypto/keyEncryption.js`, `MXDNetwork/wallet-client/src/wallet/storage.js`.

## 10. Change log

| Date | Version | Change |
|---|---|---|
| 2026-05-06 | 1.0.0 | Initial draft. Formalizes the v2/v3 dual format and the lazy-migration rule. Closes audit finding L6-1. |
