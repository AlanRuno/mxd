# MXD-04: Transaction Format and Sighash

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.5 |
| **Created** | 2026-04-26 |
| **Updated** | 2026-04-29 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-03 |
| **Supersedes** | `docs/serialization_spec_v4.md` (transaction-related portions only) |

## 1. Abstract

This document defines the canonical byte serialization of a v1 MXD transaction, the sighash construction (the exact bytes a wallet signs), and the broadcast form (transaction + signatures) that nodes accept on submission endpoints. Together with MXD-01, MXD-02 (or MXD-PQ-01 for Dilithium5 wallets), and MXD-03, this document is sufficient for a third-party wallet to construct, sign, and submit a valid MXD transaction.

## 2. Terminology

| Term | Meaning |
|---|---|
| `tx` | A transaction, in either canonical (unsigned) or broadcast (signed) form. |
| `chain_id` | A 32-bit identifier of the MXD chain on which the transaction is valid. See §3.1. |
| `input` | A reference to a previously-created UTXO that this `tx` consumes. |
| `output` | A new UTXO created by this `tx`, owned by a recipient address. |
| `UTXO` | An unspent transaction output: a pair `(amount, addr32)` identified by `(prev_tx_hash, output_index)`. |
| `prev_tx_hash` | The 64-byte `txid` of the transaction that originally created the UTXO this input consumes. |
| `output_index` | The 0-based index of the consumed UTXO in its originating transaction's output list. |
| `tip` | A voluntary fee, in base units, that the spender chooses to overpay. Nodes may prioritize on tip but are not obligated to. |
| `sighash` | The 64-byte digest a wallet signs. Defined in §7. |
| `txid` | The 64-byte transaction identifier. Equal to the sighash. Defined in §9. |
| `base unit` | The smallest currency unit. `1 MXD = 10^8 base units`. |

## 3. Encoding primitives

All multi-byte integers are encoded in **big-endian** (network byte order). The integer types used by this spec:

| Type | Width (bytes) |
|---|---|
| `u8` | 1 |
| `u16` | 2 |
| `u32` | 4 |
| `u64` | 8 |

There are no varints. There are no floating-point numbers. There are no length-prefixed strings; addresses appear in the wire format only as their 32-byte `addr32` (the `"mx"` prefix and Base58Check wrapping of MXD-01 are display forms only).

Variable-length byte arrays are length-prefixed by an integer field whose name and width are specified inline (e.g., `public_key_length: u16` precedes `public_key`). The arrays of inputs and outputs are length-prefixed by the top-level `input_count` and `output_count` fields; there are no separators between consecutive `TxInput` or `TxOutput` records.

### 3.1 `chain_id` registry

| `chain_id` | Network | Status |
|---|---|---|
| `0x4D58_0001` (`"MX\0\x01"`) | MXD mainnet | Active |
| `0x4D58_0002` (`"MX\0\x02"`) | MXD testnet | Active |
| `0x4D58_FFFF` | Reserved for local-development networks | Active |
| All other values | — | Reserved (a future MXD spec MAY assign for sister chains, layer-2 deployments, or planned forks) |

The `chain_id` field commits a transaction to the chain it was constructed for. A signed transaction with `chain_id = 0x4D58_0001` cannot be replayed on testnet, and vice versa. See §13.3.

The high two bytes (`0x4D58 = "MX"`) are MXD's namespace prefix. Future sister chains under MXD governance will allocate values within this namespace; non-MXD chains MUST NOT use this prefix.

## 4. Canonical (unsigned) transaction structure

This is the form whose bytes feed into the sighash construction of §7. It does **not** include any signature material.

```
canonical_tx_bytes :=

  version            u32     // = 2 for MXD-04 v1
  chain_id           u32     // per §3.1
  input_count        u32     // ≥ 0; coinbase txs have 0
  output_count       u32     // ≥ 1
  voluntary_tip      u64     // base units; may be 0
  timestamp          u64     // unix seconds
  inputs             input_count × TxInput_unsigned
  outputs            output_count × TxOutput
```

There is no trailing `is_coinbase` byte. Coinbase status is determined implicitly from `input_count == 0`.

### 4.1 `TxInput_unsigned`

```
TxInput_unsigned :=

  prev_tx_hash       [u8; 64]                     // txid of the source tx
  output_index       u32                          // 0-based UTXO index in source tx
  algo_id            u8                           // per MXD-01 §3
  public_key_length  u16                          // 32 (Ed25519) or 2592 (Dilithium5)
  public_key         [u8; public_key_length]      // raw pubkey bytes
```

Each input independently declares its `algo_id` and `public_key`. Single-sender wallets repeat the same values across all inputs; multi-party constructions may mix.

### 4.2 `TxOutput`

```
TxOutput :=

  recipient_addr32   [u8; 32]                     // MXD-01 addr32
  amount             u64                          // base units; MUST be > 0
```

The `recipient_addr32` is the 32-byte hash from MXD-01 §4. Wallets handling user-typed addresses obtain `recipient_addr32` by parsing the `"mx…"` string per MXD-01 §9 and discarding the version byte and checksum (the algorithm is committed to by the address as a whole, not by `recipient_addr32` alone — see §11.5).

## 5. Coinbase transactions (informative)

A coinbase transaction creates new MXD as the reward for block production and has `input_count == 0`. Coinbase txs are emitted by validators, not by user wallets, and are not signed in the user-tx sense.

A user-side wallet (including a MetaMask Snap) constructing transactions per this spec will always set `input_count >= 1` and never produce a coinbase tx. This section is included for completeness; the rest of MXD-04 implicitly addresses non-coinbase txs.

## 6. Money rules

- All `amount` and `voluntary_tip` fields are denominated in base units. `1 MXD = 10^8 base units`. The valid range is `[0, 2^64 − 1]`.
- Output amounts MUST be strictly positive (`amount > 0`). Zero-output txs are invalid.
- `voluntary_tip` MAY be zero. MXD has no mandatory fee; nodes accept tx where `Σ(input_amounts) ≥ Σ(output_amounts) + voluntary_tip` regardless of whether `voluntary_tip` is zero.
- Wallets MUST NOT add an implicit base fee. The displayed total a user authorizes is exactly `Σ(output_amounts) + voluntary_tip`.

## 7. Sighash construction

The bytes a wallet signs are **not** the canonical tx bytes directly. They are prefixed with a domain tag per MXD-03 §7:

```
domain_tag        := "MXD-TX-V1\0"           // 10 bytes ASCII + NUL
sighash_input     := domain_tag ‖ canonical_tx_bytes
sighash           := SHA-512( SHA-512( sighash_input ) )
```

The result is exactly 64 bytes. This is the `msg` argument to MXD-03's `Ed25519_Sign` (or `ML-DSA-87_Sign`) primitive.

The domain tag is normative and MUST appear exactly as the 10-byte sequence `4D 58 44 2D 54 58 2D 56 31 00`. It is registered in MXD-00's Domain-Tag Registry. Future revisions of MXD-04 (if they ever exist as `MXD-04-V2` or a successor spec number) MUST use a different domain tag so that signatures from this spec cannot be replayed against future tx formats and vice versa.

## 8. Per-input signing

Every input in a transaction is signed **independently** using the private key matching that input's `public_key`.

```
for each input i in tx.inputs:
    sig_i := sign_mxd(  algo_id  = input_i.algo_id,
                        priv     = priv_for(input_i.public_key),
                        msg      = sighash )
```

The same `sighash` is fed into every signing operation. This means:

- A 1-input tx requires 1 signature.
- A 3-input tx where all inputs are owned by the same key requires 3 signatures, all of the same 64-byte digest, with the same key — they will be byte-identical for Ed25519 (which is deterministic) but MUST still each appear in the broadcast form (one per input).
- A 3-input tx where the inputs are owned by 3 different keys requires 3 distinct signatures over the same `sighash`.

This spec defines **no SIGHASH variants**. Every signature commits to the entire transaction (all inputs, all outputs, the tip, the timestamp, the chain_id). There is no `SIGHASH_NONE`, `SIGHASH_SINGLE`, or `SIGHASH_ANYONECANPAY` mode.

## 9. Transaction identifier (`txid`)

```
txid := sighash
```

A transaction's `txid` is its sighash — the 64-byte double-SHA-512 of the domain-tagged canonical bytes. Because the canonical bytes do not include signatures, the `txid` is determined the moment the tx is constructed (before signing). Signatures are not malleable post-signing for Ed25519 (deterministic, length-checked), so the `txid` is stable across all valid serializations of the same logical transaction.

The `txid` is used as `prev_tx_hash` in subsequent inputs that consume this transaction's outputs.

## 10. Broadcast (signed) transaction structure

The broadcast form extends the canonical form by appending signatures to each input and by inserting a `tx_hash` field (a non-authoritative pre-parse dedup hint; see §10.1) immediately after `timestamp`:

```
broadcast_tx_bytes :=

  version            u32
  chain_id           u32
  input_count        u32
  output_count       u32
  voluntary_tip      u64
  timestamp          u64
  tx_hash            [u8; 64]                       // see §10.1; pre-parse dedup hint
  inputs             input_count × TxInput_signed
  outputs            output_count × TxOutput
```

```
TxInput_signed :=

  prev_tx_hash       [u8; 64]
  output_index       u32
  algo_id            u8
  public_key_length  u16
  public_key         [u8; public_key_length]
  signature_length   u16                          // 64 (Ed25519) or 4627 (Dilithium5 / ML-DSA-87)
  signature          [u8; signature_length]
```

The `signature` field is the raw signature bytes from MXD-03's `sign_mxd`.

Note: the canonical (unsigned) and broadcast (signed) forms differ in the `tx_hash` field (not present in canonical bytes) and the trailing `signature_length` and `signature` of each input. A verifier reconstructs `canonical_tx_bytes` from `broadcast_tx_bytes` by removing the `tx_hash` field and stripping the trailing two fields of each input.

### 10.1 The `tx_hash` field — non-authoritative pre-parse hint

Position: 64 bytes after `timestamp`, before the first `TxInput_signed`.

`tx_hash` carries the SAME 64-byte value as the canonical sighash defined in §7 — i.e. `SHA-512(SHA-512("MXD-TX-V1\0" ‖ canonical_tx_bytes))`. It is included in the broadcast format as an **optimization for P2P gossip**: when a node receives a transaction message from a peer, it can:

1. Read the first 32 + 64 = 96 bytes of the message.
2. Look up `tx_hash` in its mempool / recently-seen-tx cache.
3. If found, drop the duplicate without parsing the rest of the message.

This is a meaningful optimization because mempool gossip generates many redundant copies of each transaction, one per peer per propagation round.

**`tx_hash` is non-authoritative.** It is NOT part of the sighash input (§7), NOT included in the canonical bytes signed by inputs (§4), and NOT trusted by validating nodes. Receivers MUST recompute the sighash from the canonical bytes per §7 and compare to the included `tx_hash` before treating the transaction as valid. A peer that broadcasts a wrong `tx_hash` wastes its own bandwidth — the receiver's mempool dedup misses, the receiver parses the full transaction, recomputes the real sighash, and either accepts or rejects per §11.

**Implementation MUST:**
- Compute `tx_hash` per §7 before serialization (do not transmit a stale or zero value).
- Recompute and compare on deserialization; reject the tx if `received tx_hash != computed sighash`.

**The canonical (unsigned) tx bytes of §4 do NOT include `tx_hash`.** Sighash construction in §7 is unchanged. Wallet-side signing only needs §4 + §7.

`tx_hash` was added to the broadcast format in commit `fdb5148` (Feb 2026) as part of the P2P transaction broadcast handler, simultaneously with the `MXD_MSG_TRANSACTIONS` gossip message type. It is also present in the block-storage format for the same reason: the `block_to_json` HTTP endpoint reads cached `tx_hash` directly without recomputing per-transaction.

## 11. Validation rules

A node receiving a broadcast tx MUST apply all of the following checks. Any failure rejects the tx.

### 11.1 Version

`version == 2`. Other values are reserved for future spec numbers.

### 11.2 Chain identifier

`chain_id` MUST equal the node's configured chain identifier. A tx with `chain_id` for a different network MUST be rejected without further validation (it cannot be replayed on this chain).

### 11.3 Timestamp drift

`abs( tx.timestamp − node_clock_unix_seconds ) ≤ 60`. Wallets SHOULD set `timestamp` to the wallet's current unix-seconds clock at the moment of construction.

### 11.4 Output presence and positivity

`output_count >= 1`, and every output's `amount > 0`.

### 11.5 UTXO existence

For each input, `(prev_tx_hash, output_index)` MUST refer to an output that exists in the chain's UTXO set at validation time. A spent or unknown UTXO rejects the tx.

### 11.6 Algorithm and address binding

For each input, let `consumed_utxo` be the output the input refers to. Let `(version_byte_consumed, addr32_consumed)` be the version byte and `addr32` of the address that owns `consumed_utxo`. Then:

- The input's `algo_id` MUST equal the `algo_id` corresponding to `version_byte_consumed` per MXD-01 §9 (`0x01` for `0x32`/`0x3A`, `0x02` for `0x33`/`0x3B`, `0x03` for `0x34`/`0x3C` once MXD-PQ-03 is active).
- `SHA-512( input.algo_id ‖ input.public_key )[0..31]` MUST equal `addr32_consumed`.

Together these checks ensure the input declares the right algorithm and presents the public key whose owner is authorized to spend the UTXO.

### 11.7 Conservation

`Σ(input_amounts) >= Σ(output_amounts) + voluntary_tip`.

The `voluntary_tip` is implicitly destroyed (or, equivalently from the wallet's perspective, donated to the validator that includes the tx). There is no explicit fee output.

### 11.8 Signature

For each input:

```
sig_ok := verify_mxd(
            algo_id = input.algo_id,
            pub     = input.public_key,
            msg     = sighash_of_canonical_form_of_this_tx,
            sig     = input.signature
          )
```

`sig_ok` MUST be true for every input.

The verifier reconstructs `canonical_tx_bytes` from `broadcast_tx_bytes` by stripping the trailing `signature_length` and `signature` of each input; recomputes `sighash` per §7; and runs MXD-03's `verify_mxd` per input.

### 11.9 Mempool dedup hint

A node SHOULD use the `tx_hash` field in the broadcast header (§10.1) to perform a fast pre-parse duplicate check against its mempool / recently-seen-tx cache. If the lookup hits, the node MAY discard the message immediately without parsing the rest.

If the lookup misses, the node MUST parse the full transaction, recompute the sighash per §7, and compare to the received `tx_hash`. A mismatch MUST cause the transaction to be rejected. Matching is a prerequisite for further validation (§11.1–§11.8).

MXD-04 does not otherwise specify mempool deduplication policy. A node MAY drop or accept a re-submitted identical-`txid` tx according to its own mempool rules; it is not a protocol-level error.

## 12. Test vectors

See `MXD-04-test-vectors.json`. The vector set MUST include, at minimum:

### 12.1 Vector A — 1 input, 1 output

A simple "Alice sends to Bob" transaction. Demonstrates the basic path from a path-derived keypair (per MXD-02 worked example) through canonical bytes through sighash through final broadcast bytes. Includes the full hex of every intermediate value and an explicit `chain_id` of `0x4D58_0001` (mainnet).

### 12.2 Vector B — 1 input, 2 outputs (with change)

Demonstrates change handling. Alice spends a UTXO larger than the amount sent; the second output returns change to her own address. Includes a vector where change would fall below dust threshold and is dropped into tip instead.

### 12.3 Vector C — 2 inputs, 1 output (same-sighash multi-input)

Demonstrates that all inputs sign the same `sighash`. Includes one vector where both inputs are owned by the same key (signatures are byte-identical for Ed25519 deterministic signing) and one where the two inputs are owned by different keys.

### 12.4 Vector D — testnet `chain_id`

A tx constructed for testnet (`chain_id = 0x4D58_0002`). Verifies that the same logical tx with a different `chain_id` produces a completely different sighash and txid.

### 12.5 Negative cases

At least 9 negative cases, each labelled with the specific failure rule (the bullet list below is non-exhaustive; the `MXD-04-test-vectors.json` file is the authoritative count):

- Wrong `version`.
- Wrong `chain_id` (e.g., mainnet tx submitted to testnet node).
- Timestamp drift > 60 seconds.
- Output `amount == 0`.
- Pubkey `addr32` mismatch with claimed UTXO owner.
- Mutated `signature` (any single-byte flip).
- Output construction to a `0x34` / `0x3C` (composite) recipient address — wallet-side refusal per **MXD-01 §3** until MXD-PQ-03 ships.

Each vector includes full hex traces. A reference implementation that produces matching outputs for positive vectors and rejects negative vectors with the labelled reason is conformant.

## 13. Security considerations

### 13.1 Cross-context replay

Defended by the `"MXD-TX-V1\0"` domain tag. A 64-byte digest produced by some other MXD protocol layer (block, validator vote, handshake challenge) cannot be replayed as a transaction signature, because that digest will not have been produced from a `domain_tag` starting with `"MXD-TX-V1\0"`. The defense is only as strong as future specs honoring the disjoint-tag requirement of MXD-03 §7 and the MXD-00 Domain-Tag Registry.

### 13.2 Transaction malleability

Ed25519 signatures are deterministic and length-checked, so a third-party relayer cannot produce a different valid signature for the same `(priv, msg)` pair. The `algo_id` and `public_key` are part of the `canonical_tx_bytes` that the signature commits to, so a relayer cannot substitute them. The `signature_length` and `signature` are not part of `canonical_tx_bytes`, but they are length-bounded by the algorithm registry of MXD-03; an attempt to "mutate" them either produces an invalid signature (rejection by §11.8) or is a length violation (rejection by MXD-03 §6).

MXD transactions are therefore **non-malleable** under MXD-03's length-validation regime.

### 13.3 Cross-fork replay

Defended by the `chain_id` field added in MXD-04 v1.1.0. A signed tx with `chain_id = 0x4D58_0001` (mainnet) has a sighash that includes the mainnet chain_id; the same logical tx prepared for testnet would have a different sighash and a different signature. Replay across MXD chains is therefore prevented at the protocol layer, not just at the node-rule layer.

This defends against three classes of risk:

- Mainnet ↔ testnet replay: a developer's testnet tx cannot be lifted onto mainnet.
- Sister-chain replay: if MXD ever forks for governance reasons or stands up a layer-2 deployment, transactions on one chain cannot be replayed on another.
- Local-dev replay: a transaction signed on a local-dev chain (`chain_id = 0x4D58_FFFF`) cannot accidentally land on a public chain.

### 13.4 Wallet UX guidance (informative)

- Wallets SHOULD display `Σ(output_amounts)`, `voluntary_tip`, and the recipient address(es) before signing.
- Wallets SHOULD warn the user if `voluntary_tip` is unusually high relative to recent network norms (anti-fat-finger).
- Wallets SHOULD verify that every output's `recipient_addr32` parses to a syntactically valid address per MXD-01 §9 before construction; passing an unparseable address through is a wallet bug.
- Wallets SHOULD NOT submit a tx whose `timestamp` is more than 30 seconds in the past (gives the tx room before the §11.3 60-second window closes).
- Wallets SHOULD make the `chain_id` selection visible to the user (mainnet vs testnet vs local-dev) and warn if a tx is being constructed for a non-mainnet chain when the wallet is operating in a "real funds" mode.

### 13.5 Voluntary-tip semantics (informative)

`voluntary_tip` is, from the protocol's perspective, just an unspent residual: the difference between input sum and output sum that nodes do not redistribute. Validators MAY prioritize transactions with higher tips when constructing blocks; they are not required to. Wallets MUST NOT promise users a specific confirmation time as a function of tip.

## 14. References

- **MXD-01**: Address Format (addr32 derivation; current at v1.1.x).
- **MXD-02**: Mnemonic & HD Key Derivation (Ed25519 path).
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Key Derivation (PQ path).
- **MXD-03**: Signing & Verification.
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA).
- **FIPS 180-4**: Secure Hash Standard (SHA-512).
- **`docs/serialization_spec_v4.md`**: Predecessor document, partially superseded by MXD-04 (transaction sections only; non-transaction sections remain in force pending further MXD-NN specs).

## 15. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-26 | 1.0.0 | Initial draft. Replaces transaction-related portions of `serialization_spec_v4.md`. |
| 2026-04-27 | 1.1.0 | Audit revision F8: `chain_id: u32` field added between `version` and `input_count`. New §3.1 chain_id registry, new §11.2 validation rule, new §13.3 cross-fork-replay analysis. Audit revision F3 cascade: `recipient_addr20` → `recipient_addr32`, §11.6 binding rule updated to `SHA-512(...)[0..31]`. Vector D (testnet chain_id) and the wrong-`chain_id` negative case added to the §12 vector set. |
| 2026-04-27 | 1.1.1 | Second-audit revision **N4**: §12.5 negative-case count corrected from "at least 6" to "at least 8" to match the eight cases enumerated in `MXD-04-test-vectors.json`. Editorial only; no semantic change. |
| 2026-04-27 | 1.1.2 | Third-audit cosmetic revisions: **T1** (§12.5 count corrected to "at least 9" after the v1.1.1 patch round added the composite-output-refusal vector; the bullet enumeration is now explicitly non-exhaustive with the JSON as authoritative count). **T2** (dropped the stale `v1.1.0` version pin on the MXD-01 reference in §14; current major-minor is now expressed as `v1.1.x`). |
| 2026-04-28 | 1.1.3 | Audit-fixup **M-1**: corrected stale `4595` signature-size comment in §10 `TxInput_signed` to `4627` (Dilithium5 / ML-DSA-87 FIPS 204). No wire-format change; the normative size in MXD-03 §5.2 was already 4627. |
| 2026-04-29 | 1.1.4 | Audit-fixup-v2 **restore H-1**: re-added `tx_hash[64]` field to §10 broadcast pseudocode; new §10.1 documents it as a non-authoritative pre-parse P2P gossip deduplication hint. §11.9 expanded with dedup-hint validation rule. `tx_hash` was incorrectly removed in the prior audit pass based on a minimalist reading of the spec; this revision aligns the spec with the implementation rationale. No change to §4 canonical bytes or §7 sighash construction. |
| 2026-04-29 | 1.1.5 | Editorial: registry bump cascade for the node block-protocol v6 addr32 cascade (see MXD-00 v1.1.6 changelog). MXD-04 transaction format is **unchanged** — `recipient_addr32` was already 32 bytes since v1.1.0 (F3 cascade). The block-format widening (`proposer_id`, `validator_id`, etc.) is consensus-layer and remains under the **MXD-CONS-01** reservation in MXD-00. This row exists to keep MXD-04's index-version aligned with MXD-00 across the cascade. |
