# MXD-PQ-01: Dilithium5 / ML-DSA-87 Hierarchical Deterministic Key Derivation

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.2 |
| **Created** | 2026-04-27 |
| **Updated** | 2026-04-28 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-02, MXD-03 |
| **Supersedes** | The experimental placeholder previously defined in MXD-03 §5.3 (`info = "MXD-DILITHIUM5-V0"`). Keys derived under that placeholder are NOT grandfathered by this spec. |

## 1. Abstract

This document defines hierarchical deterministic (HD) derivation of Dilithium5 / ML-DSA-87 keypairs from a BIP-39 mnemonic. The chain mirrors SLIP-10 ed25519 in shape — `HMAC-SHA-512(chain, 0x00 ‖ priv ‖ ser32(i))` per hardened step — but uses a distinct master-key constant so that the Dilithium5 key tree is cryptographically independent of the Ed25519 key tree derived under MXD-02.

The intermediate value carried at each tree node is a 32-byte `ξ` (xi) seed; ML-DSA-87 key generation runs **only at the leaf**, never at intermediate nodes. The full 4896-byte ML-DSA-87 private key is therefore never stored at any non-leaf level.

## 2. Terminology

| Term | Meaning |
|---|---|
| `BIP-39 seed` | The 64-byte output of MXD-02 §4. |
| `ξ` (xi) | A 32-byte seed used as input to `ML-DSA-87.KeyGen`. The HD chain propagates `ξ` values, not full ML-DSA-87 private keys. |
| `chain32` | The 32-byte chain code propagated alongside `ξ`. |
| `master_xi32` | The `ξ` at the root of the MXD-PQ-01 tree. |
| `master_chain32` | The chain code at the root of the MXD-PQ-01 tree. |
| `path` | A sequence of hardened indices, identical in shape to MXD-02's path. |

## 3. Master derivation

```
seed             := BIP-39 seed (per MXD-02 §4)
I                := HMAC-SHA-512( key = "ml-dsa seed", data = seed )
master_xi32      := I[0..31]
master_chain32   := I[32..63]
```

The 11-byte ASCII string `"ml-dsa seed"` (`6D 6C 2D 64 73 61 20 73 65 65 64`) is the master-key constant for this spec. It MUST be used verbatim. It is **deliberately distinct** from SLIP-10 ed25519's `"ed25519 seed"` and from any other future MXD-defined master constant, so that:

- The Ed25519 key tree of MXD-02 and the Dilithium5 key tree of MXD-PQ-01, derived from the same BIP-39 seed, are cryptographically independent at every level.
- An attacker who somehow recovers `ξ` at any node in either tree learns nothing about the corresponding node in the other tree.

This is a strict information-theoretic separation, not a heuristic one. Two distinct HMAC-SHA-512 keys produce statistically independent outputs given any common input.

## 4. Hardened child derivation

ML-DSA-87 has no notion of public-only derivation; this spec defines hardened derivation only. Every level of every path uses an index ≥ 2^31.

For each hardened index `i` (where `i = i_normal + 2^31`):

```
data            := 0x00 ‖ parent_xi32 ‖ ser32_be(i)
I               := HMAC-SHA-512( key = parent_chain32, data = data )
child_xi32      := I[0..31]
child_chain32   := I[32..63]
```

Where `ser32_be(i)` is the 32-bit big-endian encoding of `i`. The leading `0x00` byte mirrors SLIP-10 ed25519 §"Master key generation"/"Private parent → private child" — kept identical in shape so implementations can share code structure between MXD-02 and MXD-PQ-01.

To traverse a path, repeat this step once per hardened index, threading `(child_xi32, child_chain32)` into the next step as `(parent_xi32, parent_chain32)`.

## 5. Canonical derivation path

```
m / 44' / 19800' / account' / 0'
```

The path is structurally identical to MXD-02 §7.1:

| Position | Index (raw) | Index (hardened, hex) | Meaning |
|---|---|---|---|
| 1 | 44 | `0x8000002C` | BIP-44 purpose |
| 2 | 19800 | `0x80004D58` | MXD coin type (provisional, see MXD-02 §7.2) |
| 3 | `account` | `0x80000000 + account` | User-facing account number |
| 4 | 0 | `0x80000000` | External chain (always 0) |

Wallets MAY expose Ed25519 (MXD-02) and Dilithium5 (MXD-PQ-01) keypairs at the same `account` value side-by-side. Because the master constants differ (§3), the two keypairs are independent; sharing the path structure is purely a UX convenience for users who want one mental model across algorithms.

## 6. Leaf key generation

ML-DSA-87 key generation runs only after the path is fully traversed:

```
xi32                := xi at m/44'/19800'/account'/0'
(priv4896, pub2592) := ML-DSA-87.KeyGen( xi32 )    // FIPS 204 §6.1, deterministic
```

ML-DSA-87 key generation is deterministic given a 32-byte seed. The same `xi32` always produces the same `(priv4896, pub2592)`.

Implementations MUST use FIPS 204 §6.1 `ML-DSA.KeyGen` with the seed `ξ` provided as the 32-byte input. Implementations MUST NOT use the version of `ML-DSA.KeyGen` that internally samples `ξ` from a CSPRNG; the seed is supplied externally by this spec.

## 7. Public key and address derivation

```
pub2592       := the public key produced in §6
addr32        := SHA-512( 0x02 ‖ pub2592 )[0..31]      // MXD-01 §4
checksum4     := SHA-512( SHA-512( version_byte ‖ addr32 ) )[0..3]   // MXD-01 §6
address       := "mx" ‖ Base58( version_byte ‖ addr32 ‖ checksum4 )  // MXD-01 §8
```

For mainnet, `version_byte = 0x33`. For testnet, `version_byte = 0x3B`. Both are reserved for Dilithium5 in MXD-01 §5; this spec promotes that reservation to active use.

## 8. End-to-end worked example

Like MXD-02 §9, the values below are illustrative and reproducible from any conformant implementation. **All hex values will be filled in by the reference implementation alongside `MXD-PQ-01-test-vectors.json`** before this spec moves to `Final`.

```
mnemonic    = "abandon abandon abandon abandon abandon abandon
               abandon abandon abandon abandon abandon about"
passphrase  = ""
account     = 0

BIP-39 seed (64 bytes)         = <hex, identical to MXD-02 worked example>
master_xi32                    = <hex>
master_chain32                 = <hex>

m/44'                          xi32 = <hex>  chain32 = <hex>
m/44'/19800'                   xi32 = <hex>  chain32 = <hex>
m/44'/19800'/0'                xi32 = <hex>  chain32 = <hex>
m/44'/19800'/0'/0'             xi32 = <hex>  chain32 = <hex>

ML-DSA-87.KeyGen(xi32):
  priv4896                     = <hex, 9792 hex chars>
  pub2592                      = <hex, 5184 hex chars>

addr32                         = <hex, 64 hex chars>
checksum4                      = <hex>
address (mainnet)              = "mx<...~50 chars...>"
```

## 9. Conformance

A wallet implementing MXD-PQ-01 MUST:

- Implement all of §3, §4, §5, §6, §7.
- Use the master-key constant `"ml-dsa seed"` exactly as specified in §3.
- Use FIPS 204 §6.1 `ML-DSA.KeyGen` (deterministic from seed) for leaf key generation.
- Reject any non-hardened index in any path level.
- Hold the 32-byte `ξ` seed at intermediate path nodes; never compute the full 4896-byte private key except at the leaf the wallet actively signs with.

A wallet that supports MXD-02 (Ed25519 HD) MAY additionally implement MXD-PQ-01. A wallet that supports only MXD-PQ-01 (no Ed25519) is conformant; it cannot interoperate with `version_byte = 0x32` addresses but it can produce `0x33` addresses and sign for them.

## 10. Migration from the experimental placeholder

The experimental placeholder previously defined in MXD-03 §5.3 (`HKDF-Expand-SHA-512(BIP-39 seed, info="MXD-DILITHIUM5-V0", L=32)`) is **superseded** by this spec. Wallets that derived a Dilithium5 keypair under the placeholder produce keys at a different `ξ` than this spec does for the same mnemonic.

This spec does NOT grandfather placeholder-derived keys. Wallets MUST migrate by:

1. Generating an MXD-PQ-01-derived keypair under the same mnemonic.
2. Sending all funds from the placeholder-derived address to the MXD-PQ-01-derived address via a normal MXD-04 transaction.
3. Discarding the placeholder-derived key from active use.

If no production wallet has shipped with the placeholder by the time this spec reaches `Final`, this section becomes informational. The placeholder MUST NOT be re-introduced under any future spec.

## 11. Test vectors

See `MXD-PQ-01-test-vectors.json`. The vector set MUST include, at minimum:

- The same mnemonic as MXD-02's primary vector (`"abandon × 11 about"`, no passphrase, account=0), demonstrating that the BIP-39 seed is shared between MXD-02 and MXD-PQ-01 but the resulting trees diverge at the master step.
- A vector with non-empty BIP-39 passphrase.
- A vector with `account = 7`.
- A vector demonstrating that, given the same mnemonic, the MXD-02 Ed25519 and MXD-PQ-01 Dilithium5 master `ξ` / `priv32` values differ in every byte (consequence of the distinct master-key constant of §3).

Vector format mirrors MXD-02-test-vectors.json with `xi32` replacing `priv32` at intermediate nodes and full `(priv4896, pub2592)` at the leaf.

## 12. Security considerations

- **Master-key separation is the load-bearing assumption of §3.** If the master constants of MXD-02 and MXD-PQ-01 ever collide (or one is a prefix of another), the two key trees lose their independence. The constants `"ed25519 seed"` (12 bytes) and `"ml-dsa seed"` (11 bytes) are byte-disjoint as strings; future MXD-defined master constants MUST preserve this property.
- **`ξ` confidentiality.** A leaked `ξ` at any path node compromises every descendant of that node, identically to how a leaked `priv32` does in SLIP-10 ed25519. Wallets MUST treat `ξ` with the same confidentiality as a private key.
- **Signature size implications.** ML-DSA-87 signatures are 4627 bytes. Wallets MUST NOT assume that signatures fit in any fixed-size buffer derived from the Ed25519 case. Hardware wallets in particular need explicit sizing.
- **Determinism vs randomness in signing.** This spec applies only to key derivation. ML-DSA-87 signing itself can be deterministic or randomized per FIPS 204 §6.2; either choice is permitted by MXD-03 §5.4. Deterministic signing produces reproducible signatures (useful for test vectors); randomized signing offers some side-channel margin. Wallet implementers should choose based on their threat model.
- **Address-layer separation from Ed25519 is enforced by `algo_id`.** Per MXD-01 §4, `addr32` includes the algorithm byte. A Dilithium5 address (`algo_id = 0x02`, version `0x33`) cannot be confused with an Ed25519 address (`algo_id = 0x01`, version `0x32`) even if some adversary could construct collisions in `pub2592` vs `pub32`.
- **Side-channel posture (lattice-specific).** Lattice-signature implementations have non-trivial side-channel surfaces, particularly in the Number Theoretic Transform (NTT) used for polynomial multiplication and in rejection sampling during signing. Not all FIPS 204 implementations are constant-time; the published reference implementation has historically required explicit configuration to disable variable-time optimizations. Wallets SHOULD use ML-DSA-87 implementations that have been formally vetted for constant-time execution (e.g., `liboqs >= 0.10` in its constant-time configuration; the NIST reference implementation with constant-time variants enabled). Wallets exposed to adversarial timing observation — shared-tenant cloud, untrusted browser extensions, contested-execution environments, network-observable signing services — MUST validate side-channel hardening explicitly before claiming MXD-PQ-01 conformance. Unlike Ed25519, where the broad library ecosystem has converged on constant-time defaults, ML-DSA-87 implementations remain heterogeneous as of 2026; due diligence is on the wallet author, not on the spec.

## 13. References

- **FIPS 204**: Module-Lattice-Based Digital Signature Standard. ML-DSA-87.KeyGen is §6.1.
- **SLIP-10**: Universal private key derivation from master private key. The shape of §3 and §4 mirrors SLIP-10's ed25519 sub-spec.
- **RFC 6234**: HMAC-SHA-512 used in §3 and §4.
- **MXD-01**: Address Format.
- **MXD-02**: Mnemonic & HD Key Derivation.
- **MXD-03**: Signing & Verification.

## 14. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-27 | 1.0.0 | Initial draft. Replaces the experimental HKDF placeholder of MXD-03 §5.3. |
| 2026-04-27 | 1.0.1 | Second-audit revision **N3**: new §12 bullet on lattice-specific side-channel posture (NTT timing leaks, rejection-sampling timing leaks, recommended use of `liboqs >= 0.10` constant-time configuration or NIST reference implementation with constant-time variants). |
| 2026-04-24 | 1.0.2 | FIPS 204 size cascade (editorial): ML-DSA-87 private key 4864 → 4896 bytes, signature 4627 bytes (was 4595). Placeholder field names `priv4864` → `priv4896`, hex-char count 9728 → 9792. Public key (2592) and pub5184-hex count unchanged. No wire-format change. |
