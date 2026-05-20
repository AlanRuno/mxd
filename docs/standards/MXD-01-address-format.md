# MXD-01: Address Format

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.2 |
| **Created** | 2026-04-26 |
| **Updated** | 2026-04-27 |
| **Author(s)** | MXD Project |
| **Requires** | — |

## 1. Abstract

This document defines the canonical byte layout, derivation algorithm, and string encoding of an MXD address. An address is the human-readable, error-detecting identifier of an account on the MXD blockchain. It commits to a specific signature algorithm (`algo_id`) and a specific public key, such that a transaction output to an address can only be spent by a signature whose algorithm and key match.

This document does **not** define how the public key is generated (see MXD-02 for Ed25519 HD, MXD-PQ-01 for Dilithium5 HD) or how it is used to sign transactions (see MXD-03, MXD-04). A wallet implementing this spec alone can validate, parse, and emit addresses but cannot send or receive value.

## 2. Terminology

| Term | Meaning |
|---|---|
| `algo_id` | One-byte identifier of the signature algorithm. See §3. |
| `pubkey` | The raw public-key bytes for the chosen `algo_id`. Length is algorithm-dependent. |
| `addr32` | The 32-byte hash commitment to `(algo_id ‖ pubkey)`. See §4. |
| `version_byte` | One byte identifying network and algorithm. See §5. |
| `checksum4` | 4-byte error-detection suffix derived by double SHA-512. See §6. |
| `Base58Check` (MXD form) | Base58 encoding of `(version_byte ‖ addr32 ‖ checksum4)`. **Note:** uses double SHA-512 for the checksum, not double SHA-256 as in Bitcoin. See §10. |

The Base58 alphabet is the standard Bitcoin alphabet:
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (no `0`, `O`, `I`, `l`).

## 3. Algorithm registry

| `algo_id` | Algorithm | Status (this spec) | Reference |
|---|---|---|---|
| `0x00` | — | Reserved (never assign) | — |
| `0x01` | Ed25519 | Mandatory | RFC 8032 §5.1 |
| `0x02` | Dilithium5 / ML-DSA-87 | Reserved (active under MXD-PQ-01 / MXD-PQ-00) | FIPS 204 |
| `0x03` | Composite-Ed25519-MLDSA87 (AND-hybrid) | Reserved (registry slot only; spec body is MXD-PQ-03, not yet drafted) | — |
| `0x04–0xFF` | — | Reserved | — |

Conformant implementations MUST implement `0x01`. They MAY additionally implement `0x02`. Until MXD-PQ-03 is published:

- Wallets MUST NOT generate keypairs under `algo_id = 0x03`.
- Wallets MUST NOT sign transactions whose inputs declare `algo_id = 0x03`.
- **Wallets MUST refuse to construct transaction outputs whose recipient address parses to `algo_id = 0x03`.** Such addresses parse to a valid `(algo_id, addr32)` per §9 — the prohibition is on *sending* to them, not on parsing them — because the recipient cannot spend the resulting UTXO under any currently-published spec, and silently emitting outputs to such addresses would lock funds until MXD-PQ-03 ships.
- Nodes MUST reject any transaction whose inputs reference `algo_id = 0x03`.

Any other algo_id value MUST be rejected by parsers.

**Node-side enforcement gap (informative).** Nodes cannot enforce the wallet-side output-construction prohibition above, because `TxOutput` (per MXD-04 §4.2) carries only `recipient_addr32` — there is no `algo_id` field at the output layer for nodes to inspect. The wallet layer is the sole enforcement point for outbound `algo_id = 0x03` references. Non-conformant wallets that ignore the prohibition create UTXOs that will be unspendable until MXD-PQ-03 ships; nodes MUST treat such outputs as ordinary opaque-hash outputs without special handling. This asymmetry is intentional and is the structural reason the wallet-side rule above is normative (`MUST refuse to construct`) rather than a node-enforced check.

The pubkey lengths bound to each `algo_id`:

| `algo_id` | Pubkey length (bytes) |
|---|---|
| `0x01` | 32 |
| `0x02` | 2592 |
| `0x03` | 2624 (= 32 + 2592, concatenated; final length confirmed by MXD-PQ-03 when drafted) |

## 4. `addr32` derivation

```
addr32 = SHA-512( algo_id_byte ‖ pubkey_bytes )[0..31]
```

The first 32 bytes (most significant) of the SHA-512 output. `algo_id_byte` is the single byte from §3; `pubkey_bytes` is the raw public key (length per §3).

**Note.** Earlier drafts of this spec (and the legacy MXD codebase) used `RIPEMD-160(SHA-512(...))` for a 20-byte address hash. That truncation is incompatible with MXD's stated post-quantum security target (see §10.1): a 20-byte hash exposes a ~2^80 second-preimage cost under Grover, undercutting the SHA-512 hashing policy elsewhere in the spec. MXD-01 v1.1.0 widens to a 32-byte address hash (~2^128 second-preimage cost under Grover) to keep the address layer consistent with the rest of MXD's PQ posture.

**Note on SHA-512 truncation (not SHA-512/256).** The truncation `SHA-512(x)[0..31]` denotes the first 32 bytes of the standard 64-byte SHA-512 output (FIPS 180-4 §6.4). It is **not** the FIPS 180-4 §6.7 `SHA-512/256` variant, which uses a different set of initial hash values and produces a different output for the same input. An implementation that reflexively substitutes a `SHA-512/256` library will silently produce wrong addresses. Conformant implementations MUST compute full SHA-512 and truncate.

## 5. Version-byte registry

| Byte | Network | Algorithm | Status |
|---|---|---|---|
| `0x32` (50) | Mainnet | Ed25519 | Mandatory |
| `0x33` (51) | Mainnet | Dilithium5 | Reserved (active under MXD-PQ-01) |
| `0x34` (52) | Mainnet | Composite-Ed25519-MLDSA87 | Reserved (registry slot for MXD-PQ-03) |
| `0x3A` (58) | Testnet | Ed25519 | Mandatory |
| `0x3B` (59) | Testnet | Dilithium5 | Reserved (active under MXD-PQ-01) |
| `0x3C` (60) | Testnet | Composite-Ed25519-MLDSA87 | Reserved (registry slot for MXD-PQ-03) |

All other version-byte values MUST be rejected. The version byte both labels the network and disambiguates the algorithm without requiring inspection of the pubkey length.

## 6. Checksum

```
checksum4 = SHA-512( SHA-512( version_byte ‖ addr32 ) )[0..3]
```

The first 4 bytes (most significant) of the second SHA-512 output. 4-byte length matches Bitcoin's Base58Check checksum size; the hash function differs (see §10).

## 7. Address payload

```
payload37 = version_byte ‖ addr32 ‖ checksum4   (1 + 32 + 4 = 37 bytes)
```

## 8. String encoding

```
address_string = "mx" ‖ Base58( payload37 )
```

The literal two ASCII characters `"mx"` (`0x6D 0x78`) are concatenated **after** Base58 encoding. They are not part of the Base58Check payload and are not covered by the checksum. Any Base58Check decoder operating on `address_string[2:]` will produce `payload37` directly.

The total length of `address_string` is variable due to Base58 (37 bytes encode to 50–51 Base58 characters in practice), giving a typical address length of 52–53 characters. Implementations MUST NOT rely on a fixed length when validating; they MUST validate by decoding.

## 9. Parsing and validation

A conformant parser MUST implement the following algorithm:

```
parse(address_string) -> (algo_id, addr32)  or  ERROR

  if len(address_string) < 4:
      ERROR("too short")
  if address_string[0..2] != "mx":
      ERROR("missing prefix")

  payload37 = Base58_decode(address_string[2..])
  if payload37 is None or len(payload37) != 37:
      ERROR("invalid base58 or wrong length")

  version_byte = payload37[0]
  addr32       = payload37[1..33]
  checksum4    = payload37[33..37]

  expected = SHA-512( SHA-512( version_byte ‖ addr32 ) )[0..3]
  if expected != checksum4:
      ERROR("checksum mismatch")

  if version_byte not in {0x32, 0x33, 0x34, 0x3A, 0x3B, 0x3C}:
      ERROR("unknown version byte")

  algo_id =
      0x01  if version_byte in {0x32, 0x3A}
      0x02  if version_byte in {0x33, 0x3B}
      0x03  if version_byte in {0x34, 0x3C}

  return (algo_id, addr32)
```

Implementations MUST NOT accept any address whose checksum is invalid, even if the version byte and length are correct.

This spec defines no special-case sentinel addresses. Implementations MUST NOT bypass §9 validation for any literal string.

## 10. Design rationale (informative)

### 10.1 Why SHA-512 throughout, not SHA-256?

MXD's threat model includes future quantum adversaries. Grover's algorithm reduces the effective preimage resistance of an n-bit hash from 2^n to 2^(n/2) operations on a sufficiently large quantum computer. Under this model:

- SHA-256 retains ~128 bits of post-quantum preimage resistance — uncomfortably close to the boundary often considered minimally adequate.
- SHA-512 retains ~256 bits — comfortably conservative.

Choosing SHA-512 throughout MXD's wallet primitives keeps the address layer at the same security margin as the rest of the protocol. Truncating SHA-512 output to 32 bytes (§4) preserves a ~2^128 second-preimage margin under Grover (n/2 of the 256-bit truncated output), which remains comfortably above the levels broadly considered adequate for digital-signature-grade hash use.

The cost to integrators is approximately five lines of non-standard code (a Base58Check variant with SHA-512 in place of SHA-256). MetaMask Snap reviewers and crypto auditors will ask "why SHA-512?"; the answer is "post-quantum hash hardening" and the spec text supplies the chain of reasoning.

### 10.2 Why a 32-byte address hash (`addr32`) instead of HASH160?

Earlier drafts used `RIPEMD-160(SHA-512(algo_id ‖ pubkey))`, copying Bitcoin's HASH160 convention. The independent audit of 2026-04-27 flagged this as internally inconsistent with §10.1: truncating the SHA-512 stream to 160 bits leaves only ~2^80 second-preimage resistance under Grover — far below the 2^128 floor §10.1's reasoning implies and well below the ~2^256 figure casual readers might infer from "SHA-512 throughout."

MXD-01 v1.1.0 widens the address hash to 32 bytes (`SHA-512(algo_id ‖ pubkey)[0..31]`) so that the address layer matches the protocol's stated PQ posture. The cost is:

- Address strings grow from ~36 to ~52 characters.
- Per-output address-hash storage in transactions grows from 20 to 32 bytes (one-time +60% on output overhead, much smaller as a fraction of total tx size).
- HASH160 was a Bitcoin-derived convenience; integrator libraries that already implement HASH160 must be replaced with SHA-512-and-truncate, which is a one-line change.

The alternative — keeping HASH160 and rewording §10.1 to acknowledge the 80-bit floor — was rejected as honest but inconsistent with MXD's external "post-quantum" branding. If MXD's address layer is a weak link, the chain's PQ claim is materially weakened.

### 10.3 Why the `"mx"` prefix outside Base58Check?

A user-visible literal prefix gives addresses a unique visual identity in mixed-chain environments (block explorers, multi-chain wallets, copy/paste UIs) without consuming entropy in the Base58Check payload. Putting it outside the encoding means any standard Base58Check decoder works on `address_string[2:]` directly — integrators do not need an MXD-specific Base58 implementation.

### 10.4 Why `algo_id` inside the address-hash input?

Including the algorithm byte in the hashed material guarantees that two public keys with the same byte pattern but different algorithms produce different addresses. This is essential for the hybrid-crypto design: an Ed25519 32-byte key and the first 32 bytes of a Dilithium5 2592-byte key cannot collide on the same `addr32`.

### 10.5 Why reserve `0x03` for a composite scheme now?

The audit (F2) noted that the existing hybrid-crypto design is **OR-hybrid**: the signer picks one algorithm per input. If either Ed25519 or Dilithium5 breaks (CRQC for the former, lattice cryptanalysis advance for the latter), every address using that algorithm whose pubkey is revealed becomes drainable. A defense-in-depth posture requires **AND-hybrid**: a single signature object that requires BOTH algorithms to verify. That is the future MXD-PQ-03 spec.

Reserving the `algo_id = 0x03` and version-byte slots `0x34`/`0x3C` now keeps the wire format forward-compatible at zero cost. When MXD-PQ-03 is drafted, no registry collision needs to be retrofitted.

## 11. Test vectors

See `MXD-01-test-vectors.json` for normative reference vectors. Each vector consists of an `(algo_id, pubkey_hex)` tuple and the expected `address_string`, plus a set of negative cases (each labelled with the specific failure reason from §9).

A reference implementation that produces matching outputs for all positive vectors and rejects all negative vectors with the labelled reason is conformant.

## 12. Security considerations

- **Address-only knowledge does not leak the public key.** Because `addr32` is a truncated hash, the full pubkey is hidden until the owner first spends from the address. For Ed25519 this is largely a privacy / quantum-future-proofing property; once the pubkey is revealed by spending, full Ed25519-strength assumptions apply. For Dilithium5 (under MXD-PQ-01), the pubkey reveal is a tractable-by-quantum risk only if a CRQC against ML-DSA-87 emerges.
- **Address-hash second-preimage is ~2^128 under Grover.** Per §10.2, finding a (different) `(algo_id', pubkey')` that hashes to a chosen `addr32` requires ~2^128 quantum operations. This is the operative PQ figure for the address layer; the SHA-512 input gives ~2^256 *classical* second-preimage resistance.
- **Checksum is not a MAC.** It defends against accidental corruption (typos, transmission errors) but not against an active adversary who wants to substitute a different valid address. Wallets MUST display the full address string for user verification before signing transactions to it.
- **Cross-version replay defended.** The version byte is part of both the displayed address and the checksum input. An Ed25519 mainnet address (`0x32`) cannot be confused with a Dilithium5 mainnet address (`0x33`) or any testnet address.
- **Cross-algorithm collision impossible.** Per §10.4, `algo_id` is hashed into `addr32`, so two distinct (`algo_id`, `pubkey`) pairs cannot share an address regardless of pubkey-byte coincidence.
- **No length-only validation.** Some chains use prefix matching as a fast pre-validation. MXD's variable Base58 length makes this unreliable; full §9 validation is the only conformant check.

## 13. References

- **SHA-512**: NIST FIPS 180-4, §6.4.
- **Base58**: Bitcoin alphabet as defined in any standard Base58 implementation.
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA). Defines Ed25519.
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard. Defines ML-DSA-87 (Dilithium5).
- **MXD-PQ-00**: PQ-Ready Wallet Profile. Binds the address-version-byte registry of §5 to the deprecation calendar of MXD-PQ-00 §5.
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Key Derivation. Activates `algo_id = 0x02` for production wallet use.

## 14. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-26 | 1.0.0 | Initial draft. |
| 2026-04-27 | 1.1.0 | Audit revision F3: addr20 (HASH160) widened to addr32 (SHA-512[0..31]). Audit revision F2: registry slot `algo_id = 0x03` (Composite-Ed25519-MLDSA87) and version bytes `0x34`/`0x3C` reserved. §10.2 rewritten; §10.5 added. |
| 2026-04-27 | 1.1.1 | Second-audit revisions: **N1** (clarified in §4 that `SHA-512(x)[0..31]` is *not* FIPS 180-4 SHA-512/256). **N2** (§3 prohibition on `algo_id = 0x03` expanded into explicit bullets covering keypair generation, signing, output construction, and node rejection — closing the silent-fund-locking footgun before MXD-PQ-03 ships). |
| 2026-04-27 | 1.1.2 | Third-audit cosmetic revision **T4**: added one paragraph after the §3 four-bullet list explaining the structural reason the output-construction prohibition is wallet-side-only (`TxOutput` carries no `algo_id` for nodes to inspect). Documentation only; no wire-format change. |
