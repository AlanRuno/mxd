# MXD-CONS-01: Validator Consensus Signatures

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.0 |
| **Created** | 2026-05-06 |
| **Updated** | 2026-05-06 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-03 |

## 1. Abstract

This document defines the canonical bytes that a validator signs on the consensus layer of the MXD protocol. Three distinct signed-object types are governed by this spec:

1. **Validation chain signatures** — per-validator signatures that accumulate on a block as it propagates through the rapid table, forming a cumulative, ordering-committed chain that prevents reordering, splicing, and substitution.
2. **Validator join / exit requests** — the signed bytes a node produces to announce membership transitions in the rapid table.
3. **Genesis announce** — the signed bytes a node produces during the genesis-coordination phase to commit its identity into the genesis block's membership set.

All three use distinct domain tags from the MXD-00 Domain-Tag Registry (`"MXD-CONS-1\0"` for validation chain and genesis, `"MXD-VAL-V1\0"` for join/exit), preventing cross-context replay between them and against the wallet-layer (`"MXD-TX-V1\0"`), bridge-layer (`"MXD-BRG-V1\0"`), and P2P-layer (`"MXD-P2P-V1\0"`) signed objects.

## 2. Terminology

| Term | Meaning |
|---|---|
| `block_hash` | The 64-byte SHA-512 hash of the block header (excluding the validation_chain itself, the validator_signatures field, and the total_supply field). |
| `chain_position` | The 0-based index of a signature within a block's `validation_chain` array. |
| `chain_hash` | A cumulative cryptographic commitment over all prior signatures in a validation chain. Defined in §3.1. |
| `addr32` | The 32-byte MXD-01 address of the signing validator. |
| `algo_id` | MXD-01 §3 algorithm identifier (`0x01` Ed25519 or `0x02` Dilithium5). |

## 3. Validation chain signatures

A validation chain is the ordered list `validation_chain[0..N-1]` of `mxd_validator_signature_t` records attached to each block, where each entry contains the validator's identity, signature, and metadata. As a block circulates through the rapid table, validators append signatures one at a time; the order of accumulation is committed cryptographically through `chain_hash` so that a block reaching a peer without its full chain cannot be silently rewritten.

### 3.1 `chain_hash` construction

`chain_hash` is computed iteratively per position:

```
chain_hash_0 = SHA-512(block_hash)

chain_hash_N = SHA-512(chain_hash_{N-1} ‖ validation_chain[N-1].signature_bytes)
                                                                        for N >= 1
```

Where `validation_chain[N-1].signature_bytes` is the raw signature output of the validator at position `N-1` (no length prefix; the signature size is implied by the signing validator's `algo_id` per MXD-03 §5).

This construction means the signer at `chain_position = K` commits, through their signed `chain_hash_K`, to the exact ordered sequence of all signatures at positions `0..K-1`. A reorder, omission, or substitution of any prior signature changes `chain_hash_K`, invalidating every signature from position K onward.

Position 0 (the proposer's own signature) commits only to the block hash; it is the seed of the chain.

### 3.2 Signed bytes per position

For each `chain_position = K`, the validator at that position signs the following 147 bytes:

```
signed_bytes :=

  domain_tag        "MXD-CONS-1\0"   11 bytes
  block_hash        [u8; 64]         64 bytes
  chain_hash_K      [u8; 64]         64 bytes
  timestamp_be      u64 BE            8 bytes  (mxd_htonll of the signature's timestamp_ms)

  total                             147 bytes
```

The domain tag bytes are exactly:

```
4D 58 44 2D 43 4F 4E 53 2D 31 00
```

The signature is produced by MXD-03's `Ed25519_Sign` or `ML-DSA-87_Sign` primitive over the 147-byte `signed_bytes`. There is no pre-hash.

### 3.3 Verification rules

A node verifying a block's validation chain MUST:

1. **Structural invariants.** For every position K:
   - `validation_chain[K].chain_position == K` (sequential, no gaps, no duplicates).
   - For K >= 1, `validation_chain[K].timestamp >= validation_chain[K-1].timestamp` (monotonically non-decreasing).
   - `validation_chain[K].validator_id` is unique within the chain (no validator signs twice).
2. **Cryptographic verification.** For every position K:
   - Recompute `chain_hash_K` per §3.1 from `block_hash` and `validation_chain[0..K-1].signature_bytes`.
   - Reconstruct `signed_bytes` per §3.2.
   - Look up the validator's registered public key by `validator_id` in the on-chain validator set.
   - Verify the signature with MXD-03's `verify_mxd(algo_id, pubkey, msg = signed_bytes, sig = validation_chain[K].signature)`.
   - Reject the block on any verification failure.

### 3.4 Storage-path crypto verification rule

**Every block stored on disk MUST have all signatures in its validation chain cryptographically verified per §3.3 before the block is committed to RocksDB.**

Pre-v7 the storage path checked only the structural invariants of §3.3.1 (sequential chain_position, monotonic timestamps, validator uniqueness). A block delivered through a path that bypassed the signature-by-signature P2P ingest (e.g., bulk sync, validation-chain relay, locally-proposed blocks at storage time) could be persisted with structurally-valid but cryptographically-forged signatures. v7 closes this gap: `mxd_verify_validation_chain_integrity` now invokes the full `mxd_verify_validation_chain` (§3.3) on every storage path, not just on the structural invariants.

The performance cost is bounded: each block carries at most one signature per rapid-table member (typically 5–10 in mainnet/testnet), and the `chain_hash` recomputation is `O(N²)` in the chain length but with `N ≤ 10` and SHA-512 throughput, it is negligible at the block-store cadence (one block per ~5 seconds).

## 4. Validator join / exit signatures

When a node requests admission to (or voluntary departure from) the rapid table, it produces a signed request. The signed bytes are:

```
signed_bytes :=

  domain_tag        "MXD-VAL-V1\0"   11 bytes
  op_type           u8                1 byte   (0x00 = JOIN, 0x01 = EXIT)
  addr32            [u8; 32]         32 bytes  (the requester's MXD-01 addr32)
  timestamp_be      u64 BE            8 bytes  (mxd_htonll of milliseconds since the Unix epoch)

  total                              52 bytes
```

The domain tag bytes are exactly:

```
4D 58 44 2D 56 41 4C 2D 56 31 00
```

### 4.1 `op_type` rationale

`op_type` distinguishes JOIN from EXIT in the signed bytes themselves. Without it, an EXIT signature captured from one validator at time T could be replayed as a JOIN signature against the same validator at the same T — both actions are addr32+timestamp tuples, and the request structures share the layout. With `op_type` in the signed bytes, the cross-action replay is cryptographically prevented: a JOIN signature has a `0x00` byte at offset 11; an EXIT signature has a `0x01`. They are not interchangeable.

The `op_type` byte is in the signed bytes only — it does not need to appear on the wire because the receiving handler already knows from the message type which action it is processing; the signed-bytes inclusion is purely a defense against future protocol shapes that might unify JOIN and EXIT into one wire-level submission.

### 4.2 Verification

A node verifying an incoming JOIN or EXIT request MUST:

1. Reconstruct the 52-byte `signed_bytes` from the on-the-wire `addr32`, `timestamp`, and the message type (JOIN → `op_type=0x00`, EXIT → `op_type=0x01`).
2. Verify the signature with MXD-03's `verify_mxd(algo_id, pubkey, msg = signed_bytes, sig = request.signature)` where `pubkey` is the public key carried in the request body.
3. Confirm `addr32 == SHA-512(algo_id ‖ pubkey)[0..31]` per MXD-01 §4. The request asserts an identity; the public key + algo_id presented MUST hash to that identity.
4. Apply additional admission rules (stake, rate limit, etc.) per the validator-management policy. Those rules are out of scope for this spec.

## 5. Genesis announce signatures

During genesis coordination, each prospective genesis validator broadcasts its identity and public key. Each announce message carries a signature over the following bytes:

```
signed_bytes :=

  domain_tag        "MXD-CONS-1\0"   11 bytes
  addr32            [u8; 32]         32 bytes  (the announcer's addr32)
  pubkey            [u8; N]           N bytes  (raw public key — 32 for Ed25519, 2592 for Dilithium5)
  timestamp_be      u64 BE            8 bytes  (mxd_htonll of milliseconds since the Unix epoch)

  total                       (51 + N) bytes
```

The same `"MXD-CONS-1\0"` domain tag as the validation chain is reused, but the field schema is distinct (an addr32 + pubkey + timestamp prefix without `block_hash`/`chain_hash`); the consumer MUST dispatch by message type (`MXD_MSG_GENESIS_ANNOUNCE` vs. validation-chain ingest) and reconstruct the appropriate field schema. Because both schemas have different total lengths (147 bytes for validation-chain entries; `51 + N` bytes for genesis announce — 83 bytes for Ed25519, 2643 bytes for Dilithium5), the disjoint-prefixes property of MXD-03 §7 holds even though the domain tag is shared: a captured signature cannot be replayed across the two schemas because the signed-byte lengths differ and the verifier reconstructs the schema from message context.

There is no length prefix on `pubkey` in the signed bytes. The verifier knows `pubkey_len` from the wire (which carries an explicit 2-byte big-endian `pubkey_length` field per the genesis-announce wire format) and reconstructs the signed bytes by copying that many bytes between the addr32 and the timestamp.

The wire format of the genesis-announce message itself is:

```
algo_id           u8                            1 byte
node_address      [u8; 32]                     32 bytes (addr32)
pubkey_length     u16 BE                        2 bytes
pubkey            [u8; pubkey_length]      variable
timestamp         u64 BE                        8 bytes
signature_length  u16 BE                        2 bytes
signature         [u8; signature_length]   variable
```

The wire format includes `algo_id` and `pubkey_length` so the receiver can dispatch the verify primitive and reconstruct the signed bytes; the signed bytes themselves do not include either (the addr32 already binds the algo_id transitively because addr32 = SHA-512(algo_id ‖ pubkey)[0..31]).

## 6. Test vectors

Test vectors will be provided as `MXD-CONS-01-test-vectors.json` in a follow-up Dispatch C work item. Vector classes:

- Validation chain: 1-signature chain (proposer only) — full hex of `block_hash`, `chain_hash_0`, `signed_bytes`, signature.
- Validation chain: 3-signature chain — full hex of every `chain_hash_K` and a verification trace per position.
- Validation chain negative: signature at position 1 mutated; validation MUST fail at position 1 and at every later position.
- Validation chain negative: signatures at positions 1 and 2 swapped (reorder); MUST fail because `chain_hash_1` and `chain_hash_2` no longer match the order they signed.
- Validator join: addr32 + Ed25519 pubkey, full hex of 52-byte signed_bytes.
- Validator exit: same payload structure with `op_type = 0x01`.
- Validator join/exit cross-replay negative: a JOIN signature presented as an EXIT request MUST fail verification.
- Genesis announce: Ed25519 (83-byte signed_bytes) and Dilithium5 (2643-byte signed_bytes) variants.

## 7. Security considerations

### 7.1 Validation chain ordering commitment

The cumulative `chain_hash` construction (§3.1) is the load-bearing defense against adversarial reordering. An attacker who controls a non-validator peer and observes the on-the-wire signature stream cannot construct a reordered chain that verifies — every signature past position 0 commits to an explicit `chain_hash_K` whose value depends on the exact sequence of all prior signatures' raw bytes. Reordering any prior signature breaks that commitment.

This is strictly stronger than the BFT-style "I sign the block hash" pattern, where signatures are independently valid and can be repackaged in any order. MXD's chain-hash pattern is closer in spirit to a Merkle prefix commitment but linearized; it suits a 5–10-validator rapid table where signature order carries semantic weight (latency-of-attestation is one of the validator-scoring inputs).

### 7.2 Storage-path verification

The §3.4 rule (every stored block has its full chain crypto-verified) is the closure for AUDIT_2026-05-05_v6.md concern 2. Pre-v7 the protocol relied on the assumption that all blocks reaching the storage path had been ingested signature-by-signature through the P2P pipeline that does verify each signature. That assumption was unsafe because bulk-sync, RSC relay, and proposer-side store paths all bypassed it. v7 makes verification a precondition of storage with no bypass.

### 7.3 Cross-context replay

The disjoint domain tags (`"MXD-CONS-1\0"`, `"MXD-VAL-V1\0"`, plus the wallet/bridge/P2P tags from MXD-00) prevent cross-context replay between every signed-object type defined in any current MXD spec. Within a domain, the schema fields (block_hash, chain_hash, addr32, op_type, timestamp) further disambiguate sub-uses, with the practical guarantee that a signature produced for one schema cannot satisfy a verifier that reconstructs a different schema.

### 7.4 Domain-tag overload (genesis vs. validation chain)

Both genesis announce and validation chain signatures use `"MXD-CONS-1\0"`. This is intentional: both are "consensus-layer commitments" in the protocol's semantic taxonomy. The field-schema disjointness (§5) is the operational defense — a verifier reconstructs the schema appropriate to the message context, and a captured signature for one schema fails to verify against a reconstruction of the other schema because the field offsets and total lengths do not align.

A future spec MAY introduce `"MXD-CONS-2\0"` to disambiguate further if the operational defense ever proves insufficient (e.g., if a future genesis-announce schema accidentally matched a future validation-chain length). At present, no such collision exists.

## 8. References

- **MXD-01**: Address Format. The addr32 and algo_id registries.
- **MXD-03**: Signing & Verification. The disjoint-domain rule of §7 and the length-validation regime of §6.
- **MXD-00**: Standards Index. The Domain-Tag Registry where `"MXD-CONS-1\0"` and `"MXD-VAL-V1\0"` are registered.
- **AUDIT_2026-05-05_v6.md** findings **L6-4** (validator join/exit op_type), **L6-5** (validation-chain and genesis announce domain tag), and **concern 2** (storage-path crypto verification).
- Reference implementation:
  - Validation chain construction: `src/blockchain/mxd_rsc.c` — `mxd_compute_chain_hash` (~line 601), `mxd_add_validator_signature_to_block` (~line 670), `mxd_verify_validation_chain_integrity` (~line 806).
  - Validation chain verification: `src/blockchain/mxd_blockchain_validation.c` — `mxd_verify_validation_chain` (~line 117).
  - Validator join/exit: `src/blockchain/mxd_validator_management.c` — JOIN sign block (~line 122), EXIT sign block (~line 206), JOIN verify block (~line 274).
  - Genesis announce: `src/blockchain/mxd_rsc.c` — `mxd_init_genesis_coordination` (~line 2354), `mxd_broadcast_genesis_announce` (~line 2391), `mxd_handle_genesis_announce` (~line 2460); also `src/mxd_genesis_handler.c`.

## 9. Change log

| Date | Version | Change |
|---|---|---|
| 2026-05-06 | 1.0.0 | Initial draft. Formalizes the v7 validation chain signed bytes, the validator join/exit signed bytes, the genesis announce signed bytes, and the storage-path crypto verification rule. Closes audit findings L6-4, L6-5, concern 2. |
