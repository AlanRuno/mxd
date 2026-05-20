# MXD-03: Signing and Verification

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.1 |
| **Created** | 2026-04-26 |
| **Updated** | 2026-04-28 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01 |

## 1. Abstract

This document specifies the digital-signature primitives used by MXD: Ed25519 (mandatory) per RFC 8032, and Dilithium5 / ML-DSA-87 (reserved, activated under MXD-PQ-01) per FIPS 204. It defines key sizes, signature sizes, the canonical export form of private keys, the algorithm-dispatch and length-validation rules every consumer MUST apply, and the cross-context domain-separation contract that consumers MUST honor when constructing the bytes that get signed.

This document does **not** define what bytes are signed (that responsibility belongs to consuming specs — MXD-04 for transactions, future specs for blocks, validator votes, handshake challenges) and it does **not** define how Dilithium5 keypairs are derived from a mnemonic (see MXD-PQ-01 for that).

## 2. Terminology

| Term | Meaning |
|---|---|
| `algo_id` | One-byte algorithm identifier from MXD-01 §3. |
| `priv` | Algorithm-specific private key bytes. Length per §4 / §5. |
| `pub` | Algorithm-specific public key bytes. Length per §4 / §5. |
| `sig` | Signature bytes produced by an algorithm. Length per §4 / §5. |
| `msg` | The bytes signed by the primitive. Constructed by the consuming spec; its content is opaque to MXD-03. |
| `domain tag` | A unique ASCII prefix prepended to `msg` by a consuming spec to defend against cross-context replay. See §7. |

## 3. Algorithm registry

This registry mirrors MXD-01 §3 and is normative.

| `algo_id` | Algorithm | Status (this spec) | Reference |
|---|---|---|---|
| `0x01` | Ed25519 | Mandatory | RFC 8032 §5.1 |
| `0x02` | Dilithium5 / ML-DSA-87 | Reserved (active under MXD-PQ-01) | FIPS 204 |
| `0x03` | Composite-Ed25519-MLDSA87 (AND-hybrid) | Reserved (registry slot only; spec body is MXD-PQ-03, not yet drafted) | — |
| Any other | — | MUST be rejected | — |

A conformant MXD-03 implementation MUST implement Ed25519. It MAY implement Dilithium5; if it does, key derivation follows MXD-PQ-01. It MUST NOT sign or verify under `algo_id = 0x03` until MXD-PQ-03 is published.

## 4. Ed25519 (mandatory)

### 4.1 Variant

MXD uses **pure** Ed25519 per RFC 8032 §5.1. Implementations MUST NOT use Ed25519ph (pre-hashed) or Ed25519ctx (with context). Pure Ed25519 takes the raw `msg` bytes and hashes them internally as part of the signing computation.

### 4.2 Sizes

| Quantity | Length (bytes) |
|---|---|
| Private key seed (canonical) | 32 |
| Public key | 32 |
| Signature | 64 |

### 4.3 Canonical private key export

The MXD canonical export form of an Ed25519 private key is the **32-byte seed** described in RFC 8032 §5.1.5 (the random 32 bytes from which the expanded key material is derived).

Some libraries (notably libsodium) expose a 64-byte secret-key form that concatenates the seed and the corresponding public key: `sk_libsodium = seed (32) ‖ pub (32)`. Wallets using such libraries:

- MUST extract `sk_libsodium[0..31]` as the canonical 32-byte seed when exporting a private key (e.g., for backup, for cross-implementation compatibility, or for inclusion in test vectors).
- MAY hold the 64-byte form internally for performance.
- MUST NOT confuse the 64-byte form with a "private key length" elsewhere in the protocol — wherever this spec or its consumers refer to an Ed25519 private-key byte string, the 32-byte seed is meant.

### 4.4 Signing

Per RFC 8032 §5.1.6:

```
sig := Ed25519_Sign( priv32, msg )    // returns 64 bytes
```

Ed25519 signatures are deterministic: signing the same `msg` with the same `priv32` always produces the same `sig`. There is no per-signature randomness to manage.

### 4.5 Verification

Per RFC 8032 §5.1.7:

```
ok := Ed25519_Verify( pub32, msg, sig )    // returns bool
```

### 4.6 Mandatory rejection rules

Per RFC 8032 §5.1.7 paragraphs on encoding:

- Implementations MUST reject signatures whose `R` or `S` components are non-canonically encoded (RFC 8032 §8.4).
- Implementations MUST reject public keys that decode to non-canonical points (RFC 8032 §8.5).
- Implementations MUST reject signatures whose length is not exactly 64 bytes.
- Implementations MUST reject public keys whose length is not exactly 32 bytes.

These are not optional optimizations; protocol-level non-malleability depends on them.

## 5. Dilithium5 / ML-DSA-87 (reserved; activated by MXD-PQ-01)

### 5.1 Variant

ML-DSA-87 per FIPS 204. FIPS 204 (published 2024) renamed Dilithium-Round-3-level-5 to ML-DSA-87; both names refer to the same algorithm and are normative aliases in this spec.

### 5.2 Sizes

| Quantity | Length (bytes) |
|---|---|
| Private key | 4896 |
| Public key | 2592 |
| Signature | 4627 |

### 5.3 Key derivation

HD derivation of Dilithium5 keypairs from a BIP-39 mnemonic is **normatively specified by MXD-PQ-01**. Wallets MUST NOT use any other Dilithium5 HD scheme for production wallet keys. In particular, the experimental HKDF-Expand placeholder previously published in this section under MXD-03 v1.0.0 (`info = "MXD-DILITHIUM5-V0"`) is **withdrawn** and superseded by MXD-PQ-01; wallets that ever derived keys under that placeholder MUST migrate per MXD-PQ-01 §10.

For non-wallet contexts (e.g., one-shot keypair generation for protocol-internal use), implementations MAY call FIPS 204 §6.1 `ML-DSA.KeyGen` directly with a CSPRNG-sampled seed. Such keys are not subject to MXD-PQ-01's HD requirements.

### 5.4 Signing and verification

```
sig := ML-DSA-87_Sign(   priv4896, msg )    // returns 4627 bytes
ok  := ML-DSA-87_Verify( pub2592,  msg, sig )    // returns bool
```

Per FIPS 204, ML-DSA-87 signing is randomized by default (the implementation samples a per-signature randomness `ρ′`). Implementations MAY use the deterministic-signing variant defined in FIPS 204 §6.2 if reproducibility is required (e.g., for test vectors); both variants produce verifying signatures.

### 5.5 Mandatory rejection rules

- Implementations MUST reject Dilithium5 signatures whose length is not exactly 4627 bytes.
- Implementations MUST reject Dilithium5 public keys whose length is not exactly 2592 bytes.
- Per FIPS 204 §3, implementations MUST reject keys and signatures that fail FIPS 204's input-validation checks (range checks on encoded coefficients, etc.).

## 6. Algorithm dispatch and length validation

A generic verifier in any consuming spec MUST implement the following algorithm:

```
verify_mxd(algo_id, pub, msg, sig) -> bool

  // Length validation BEFORE dispatch.
  // Returning false on length mismatch is correct; passing wrong-length
  // bytes into the underlying primitive is NOT correct, because some
  // libraries silently truncate, pad, or undefined-behavior.

  if algo_id == 0x01:
      if len(pub) != 32 or len(sig) != 64:
          return false
      return Ed25519_Verify(pub, msg, sig)

  if algo_id == 0x02:
      if len(pub) != 2592 or len(sig) != 4627:
          return false
      return ML-DSA-87_Verify(pub, msg, sig)

  // algo_id == 0x03 is reserved (MXD-PQ-03) but not active in this spec.

  return false   // unknown algo_id
```

The signing side mirrors this:

```
sign_mxd(algo_id, priv, msg) -> sig

  if algo_id == 0x01:
      if len(priv) != 32:
          ERROR
      return Ed25519_Sign(priv, msg)

  if algo_id == 0x02:
      if len(priv) != 4896:
          ERROR
      return ML-DSA-87_Sign(priv, msg)

  ERROR
```

Length validation is mandatory in both directions and is part of the conformance criteria of MXD-03.

## 7. Domain separation

This spec deliberately does NOT define what `msg` is. Pure Ed25519 has no built-in domain separation, and MXD signs many distinct kinds of objects (transactions, block headers, validator votes, handshake challenges, etc.). Without a domain separator, a 64-byte digest could in principle be valid as a signature on more than one kind of object, even if the protocol layers compute different digests in practice.

To defend against cross-context replay, **every consuming spec MUST construct its `msg` with a unique ASCII domain tag prefix.**

The contract:

```
msg = domain_tag ‖ context_specific_bytes
```

Where `domain_tag`:

- Begins with the four bytes `"MXD-"`.
- Includes the consuming spec's identifier (e.g., `"TX"` for MXD-04, `"BLK"` for a future block-signing spec).
- Includes a version suffix (`"V1"`, `"V2"`, …) so a future revision of the same context cannot replay against the previous one.
- Is null-terminated (`"\0"`) so it cannot be confused with `context_specific_bytes` that happen to start with the same prefix.

Example: MXD-04 specifies `domain_tag = "MXD-TX-V1\0"` (10 bytes).

Future consuming specs that add new signed-object types MUST register a unique domain tag in the **MXD-00 Domain-Tag Registry**, and the registered tags MUST be disjoint as prefixes (no tag is a prefix of another). The registry is the single source of truth for in-use and reserved tags.

A pre-MXD-03 implementation that signs raw protocol bytes without a domain tag is **NOT** conformant. The cross-context replay surface that omission creates is small in practice (different contexts produce different digests in general) but real in principle, and the cost of closing it is one byte concatenation per signature.

## 8. Test vectors

See `MXD-03-test-vectors.json`. The vector set MUST include, at minimum:

- All RFC 8032 §7.1 test vectors for Ed25519, reproduced verbatim. A conformant Ed25519 implementation produces matching `sig` outputs on these.
- At least three MXD-specific Ed25519 vectors with `msg` lengths of 0, 64, and 1024 bytes — the 64-byte case matches the size of an MXD-04 sighash.
- At least two negative cases per algorithm: wrong-length `pub` and mutated `sig`.
- For Dilithium5: at least one keypair-from-seed vector demonstrating MXD-PQ-01's HD derivation followed by an ML-DSA-87 sign/verify round trip.

Vectors are reproducible from the spec text alone — every input is hex, every expected output is hex.

## 9. Security considerations

- **Ed25519 determinism eliminates one class of fault attacks.** Because Ed25519 signing is deterministic, a faulty signer cannot leak private-key material via biased nonces. Implementations MUST NOT introduce randomness into the Ed25519 signing path under the (incorrect) belief that it improves security.
- **Cross-algorithm replay is defended at the address layer, not here.** Per MXD-01 §10.4, `algo_id` is part of the `addr32` input. A Dilithium5 signature can never satisfy an Ed25519 address because the address itself is bound to `algo_id = 0x01`. MXD-03 therefore does not need to guard against that case — it is impossible by construction.
- **Cross-context replay defended only by consumers.** Per §7. MXD-03 cannot defend against this on its own; it is a contract on consumers. The MXD-00 Domain-Tag Registry exists to make the contract auditable.
- **Length validation is a security boundary.** Some Ed25519 libraries will accept a non-32-byte public key by silently truncating or padding. Some Dilithium5 reference implementations have undefined behavior on wrong-length inputs. MXD-03's length-validation rules are the firewall that prevents this from becoming a protocol-level vulnerability.
- **Private-key memory hygiene.** Implementations SHOULD zeroize private-key buffers after use. This spec does not mandate a specific zeroization mechanism; the operational details are platform-specific.
- **No side-channel guarantees.** This spec specifies the cryptographic primitives but not their implementation. Wallets running on hardware exposed to side-channel adversaries (e.g., shared-tenant cloud, untrusted browser extensions) must rely on the side-channel posture of their underlying library. RFC 8032 implementations from libsodium, NaCl, and the standard Go/Rust ecosystems are constant-time on common platforms.
- **OR-hybrid is not defense-in-depth.** This spec lets a signer pick *one* algorithm per input. If Ed25519 breaks (CRQC arrives) every revealed `0x32`/`0x3A` pubkey is at risk; if Dilithium5 breaks (lattice cryptanalysis advance) every revealed `0x33`/`0x3B` pubkey is at risk. Neither algorithm protects against the other's failure. The forthcoming **MXD-PQ-03** composite scheme (`algo_id = 0x03`, registry slot already reserved) is the AND-hybrid that gives true defense-in-depth.

## 10. References

- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA).
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard.
- **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF). (No longer used by this spec after the MXD-PQ-01 supersession of §5.3, but referenced for historical clarity.)
- **MXD-01**: Address Format.
- **MXD-02**: Mnemonic & HD Key Derivation (Ed25519).
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Key Derivation. Normative for §5.3.

## 11. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-26 | 1.0.0 | Initial draft. |
| 2026-04-27 | 1.1.0 | Audit revision F4: §5.3 experimental HKDF placeholder withdrawn; HD derivation of Dilithium5 keys is now normatively specified by MXD-PQ-01. Audit revision F2: registry row `algo_id = 0x03` (Composite-Ed25519-MLDSA87) reserved. New §9 bullet on OR-hybrid limitations. §7 updated to reference the MXD-00 Domain-Tag Registry as the source of truth for tag uniqueness. |
| 2026-04-24 | 1.1.1 | FIPS 204 size cascade (editorial): ML-DSA-87 private key 4864 → 4896 bytes, signature 4595 → 4627 bytes to match actual FIPS 204 §6.1 / §6.3 values. Public key (2592) unchanged. No wire-format change — the implementation already used FIPS 204 sizes. |
