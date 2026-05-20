# MXD-CONS-01: Validator Consensus Signatures

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.0 |
| **Created** | 2026-05-06 |
| **Updated** | 2026-05-20 |
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

When a node requests admission to the rapid table, it produces a signed JOIN request. The signed bytes are:

```
signed_bytes :=

  domain_tag        "MXD-VAL-V1\0"   11 bytes
  op_type           u8                1 byte   (0x00 = JOIN, 0x01 = EXIT (deprecated), 0x02 = EVICT (reserved))
  addr32            [u8; 32]         32 bytes  (the requester's MXD-01 addr32)
  timestamp_be      u64 BE            8 bytes  (mxd_htonll of milliseconds since the Unix epoch)

  total                              52 bytes
```

The domain tag bytes are exactly:

```
4D 58 44 2D 56 41 4C 2D 56 31 00
```

### 4.1 `op_type` registry

| `op_type` | Name | Status | Notes |
|---|---|---|---|
| `0x00` | JOIN | Active (v1.1.0) | Self-signed admission request. Distributed via the gossip wire format in §4.3 and drained by proposers per §4.5. |
| `0x01` | EXIT | **Deprecated** (v1.1.0) | Self-driven exits were removed when permissionless JOIN landed: a validator that wants to leave simply lets its balance drop below the §4.4 threshold, after which peers EVICT it. The op_type byte remains reserved so a captured EXIT signature cannot be repurposed as JOIN against the same addr32/timestamp. |
| `0x02` | EVICT | Reserved | Peer-initiated removal of a validator whose on-chain balance has fallen below the §4.4 stake threshold. Wire format and apply semantics will be defined in a forthcoming MXD-CONS-01 v1.2.x revision (Phase 3 of the validator-management roadmap). |
| `0x03`+ | — | Reserved | — |

`op_type` distinguishes operations in the signed bytes themselves. Without it, an EXIT signature captured from one validator at time T could be replayed as a JOIN signature against the same validator at the same T — both actions are addr32+timestamp tuples, and the request structures share the layout. With `op_type` in the signed bytes, the cross-action replay is cryptographically prevented: a JOIN signature has a `0x00` byte at offset 11; an EXIT signature has a `0x01`; an EVICT will have `0x02`. They are not interchangeable.

The `op_type` byte is in the signed bytes only — it does not need to appear on the wire because the receiving handler already knows from the P2P message type which action it is processing; the signed-bytes inclusion is the defense against future protocol shapes that might unify the requests into one wire-level submission.

### 4.2 Request-level verification

A node verifying an incoming JOIN request (either as the originating signer's own submit-time self-check or as a gossip-receiver's pre-pool check) MUST:

1. Reconstruct the 52-byte `signed_bytes` from the on-the-wire `addr32`, `timestamp`, and the message type (JOIN → `op_type=0x00`).
2. Verify the signature with MXD-03's `verify_mxd(algo_id, pubkey, msg = signed_bytes, sig = request.signature)` where `pubkey` is the public key carried in the request body (see §4.3 wire format).
3. Confirm `addr32 == SHA-512(algo_id ‖ pubkey)[0..31]` per MXD-01 §4. The request asserts an identity; the public key + algo_id presented MUST hash to that identity.
4. Confirm the request's `timestamp` lies within the validity window: between `now - 5 minutes` and `now + 1 minute`. A request older than 5 minutes or more than 1 minute in the future is rejected.
5. Confirm `stake_amount >= total_supply / 1000` where `total_supply` is read from the latest finalized block (height - 1) and `stake_amount` is the wire-side declared stake. The on-chain balance lookup `mxd_get_balance(addr32)` MUST also be `>=` the declared `stake_amount` (the wire field cannot exceed the actual balance).

### 4.3 JOIN gossip wire format

A signed JOIN request is broadcast to all peers via the P2P message type `MXD_MSG_VALIDATOR_JOIN_REQUEST` (numeric type `19` in the v7 message-type registry). The payload framing is:

```
algo_id           u8                            1 byte   (0x01 Ed25519 / 0x02 Dilithium5 per MXD-01 §3)
addr32            [u8; 32]                     32 bytes  (the joining validator's MXD-01 addr32)
pubkey_len        u16 BE                        2 bytes
pubkey            [u8; pubkey_len]         variable      (32 for Ed25519, 2592 for Dilithium5)
stake_amount      u64 BE                        8 bytes  (mxd_htonll of base units; advisory — the on-chain balance is authoritative)
timestamp         u64 BE                        8 bytes  (same timestamp used in the §4 signed bytes)
signature_len     u16 BE                        2 bytes
signature         [u8; signature_len]      variable      (64 for Ed25519, 4627 for Dilithium5 per MXD-03)

total                                          variable
  Ed25519                                       149 bytes
  Dilithium5                                  ~2899 bytes (32+2+2592 pubkey + 2+4627 sig + 32+8+8+1 header)
```

Note that `op_type` does NOT appear on the wire — the P2P message type carries that semantic, and the signed-bytes inclusion (§4) is what binds the signature to the operation. Receivers reconstruct the 52-byte canonical bytes by prefixing `"MXD-VAL-V1\0" || 0x00` to the wire-side `addr32 || timestamp_be` before calling `verify_mxd`.

Gossip propagation uses epidemic broadcast with a per-node 256-entry LRU seen-set keyed by `(msg_type, addr32, timestamp)`. A peer that has already accepted (or pre-marked, in the broadcasting node's case) a fingerprint silently drops the duplicate. The seen-set is in-memory only; restart resets it, which is the intended behavior because requests older than 5 minutes are rejected on age anyway (§4.2 rule 4).

### 4.4 Auto-trigger eligibility

A node MAY submit a JOIN request automatically when all of the following are true:

1. The chain is past genesis (`height > 0`) and the local rapid table is loaded.
2. The local addr32 is NOT already in the rapid table.
3. `local_balance >= floor(total_supply_at_height_minus_1 / 1000)`. This is the universal **0.10 % stake threshold** — it scales with supply so the cost of becoming a validator tracks the size of the chain.
4. The node has not submitted a JOIN within the last 5 minutes (anti-spam cooldown matching the §4.2 rule-4 age limit, so a request never lives in the gossip layer longer than the rate limit).

The reference implementation polls these conditions every 60 seconds after a 30-second warm-up post-startup (`src/node/main.c::auto_join_thread_func`). Operators MAY disable the auto-trigger and submit JOINs through an out-of-band path; the on-chain rules are identical either way.

### 4.5 Proposer drain and block inclusion

When a proposer is assembling a block, before freezing the transaction set, it drains its local JOIN pool into the block's `rapid_membership_entries[]` array. For each pending request the proposer:

1. Re-runs §4.2 request-level verification against the current `total_supply` and on-chain balance.
2. Confirms the candidate addr32 is NOT already in the local rapid table (the drain is a no-op for already-active validators).
3. Calls `mxd_append_membership_entry(block, addr32, algo_id, pubkey, sig, timestamp)` which performs **§4.7 storage-path verification** before storing the entry in `block->rapid_membership_entries[]`.

The resulting block carries a `rapid_membership_count` field with the number of new entries appended; downstream peers see this count in the wire-format block header.

Bounding rules:
- Maximum membership entries per block: 10 (proposer-side cap; prevents large-batch attacks that bloat blocks).
- Maximum total rapid-table size: bounded by the table's `capacity` (typically 50 for current networks). A proposer skips JOINs that would push the table past capacity.

### 4.6 Apply-block: rapid_table update

When a peer finalizes a block (`mxd_process_validation_chain` reaches quorum and the block is stored), the peer MUST apply each `rapid_membership_entries[i]` to its in-memory rapid table:

1. If the candidate addr32 is NOT already present, append a new `mxd_node_stake_t` whose `stake_amount` is the current `mxd_get_balance(addr32)`, mark `active=1`, and initialize the metrics with the current time.
2. Register the candidate's `(addr32, algo_id, pubkey)` triple as a known validator-pubkey binding so the §3 validation-chain verifier can look it up when signing future blocks.

The next consensus tick after the apply step uses the new (N+1)-element rapid table for proposer selection (§3.1's `prev_block_hash || height_be` index modulo the new count), so the newly-admitted validator participates from the block immediately following its admission.

Without this apply step, the on-disk block and the in-memory rapid table would diverge until the next process restart's `mxd_rebuild_rapid_table_from_blockchain` resync — which is incorrect: the network's effective validator set is the in-memory table on every running node, not a future re-derived snapshot.

### 4.7 Storage-path verification

**Every membership entry stored in any block — whether by the proposer at propose time, or by a peer applying a received block — MUST have its signature cryptographically verified against the MXD-VAL-V1 canonical bytes (§4) before the entry is accepted into `block->rapid_membership_entries[]`.**

Specifically, `mxd_append_membership_entry` reconstructs the 52-byte canonical:

```
"MXD-VAL-V1\0" || 0x00 || entry.node_address || htobe64(entry.timestamp)
```

from the entry's own fields and calls `verify_mxd(entry.algo_id, entry.signature, canonical_bytes, entry.public_key)`. A verification failure aborts the append.

This is the §3.4 storage-path-verify rule, lifted into the validator-membership domain. Pre-v1.1.0 the append function verified the entry's signature against a per-block `mxd_calculate_membership_digest(block)` — a vestige of the genesis-only design where validators signed an agreed empty-block digest at consensus time. Because the JOIN signature was created over MXD-VAL-V1 bytes (not a block digest), the genesis-era verify could never accept a JOIN-signed entry; the rule above is the corrected verification that matches the §4 signed-bytes contract.

For **height == 0 (genesis) blocks**, signature verification is skipped at append time because the genesis signatures were collected over an empty-block digest at consensus formation and the current genesis block has coinbase txs (different merkle root), so the historical digest is no longer reproducible. The genesis signatures were already verified inbound during the genesis-coordination phase (§5).

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

Two JSON files cover the spec:

| File | Scope | Generator |
|---|---|---|
| [`MXD-CONS-01-test-vectors.json`](./MXD-CONS-01-test-vectors.json) | v1.0.0 vectors: §3 validation chain (`chain_hash_0`, multi-position chains, integrity), §4 JOIN/EXIT 52-byte canonicals, §5 genesis-announce canonicals. | [`wallet-client/scripts/gen_mxd_cons01_vectors.mjs`](https://github.com/AlanRuno/mxd/blob/main/wallet-client/scripts/gen_mxd_cons01_vectors.mjs) (in the wallet-client subtree; uses `@noble/curves`). |
| [`MXD-CONS-01-validator-management-test-vectors.json`](./MXD-CONS-01-validator-management-test-vectors.json) | v1.1.0 additions: §4.3 149-byte gossip wire-format breakdown, cross-replay negative test. | [`scripts/gen_mxd_cons01_vectors.mjs`](./scripts/gen_mxd_cons01_vectors.mjs) (standalone — Node WebCrypto only, no third-party deps). |

Both are regenerated deterministically; updating either layout MUST re-run the matching generator and commit the JSON alongside the spec change.

### 6.1 v1.1.0 vector coverage

| Vector | Class | Description |
|---|---|---|
| `validator_join_ed25519` | Positive | 52-byte JOIN canonical bytes + Ed25519 signature; verifies as JOIN. Includes the 149-byte gossip wire payload with full byte-level breakdown. |
| `validator_exit_ed25519_deprecated` | Reference | 52-byte EXIT canonical bytes + signature. EXIT is deprecated in v1.1.0 — vector exists only for the cross-replay test below. |
| `cross_replay_join_sig_as_exit_negative` | Negative | A JOIN signature presented against EXIT canonical bytes MUST fail verification. This is the load-bearing `op_type` defense (§4.1). |

### 6.2 Determinism inputs (v1.1.0)

| Input | Value |
|---|---|
| `seed_hex` | `4242…` (32 bytes of `0x42`) |
| `pubkey_hex` | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12` (derived from seed via Ed25519) |
| `addr32_hex` | `4d33c191345773c1a9d30205e4ab821701b440e350e4a488828b92adb41c9e56` (= SHA-512(`0x01 ‖ pubkey`)[0..31]) |
| `timestamp_ms` | `1737936000000` (2026-01-27 00:00:00Z) |
| `stake_base_units` | `60500000` |

The 149-byte wire payload total matches the observed length on testnet during the v1.1.0 validation broadcast (tcpdump on testnet-0, 2026-05-20) — useful as a sanity check on a reference implementation's framing.

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
  - Validator join (v1.1.0): `src/blockchain/mxd_validator_management.c` — JOIN sign block (~line 122), §4.2 verify (~line 274). Gossip broadcast: `mxd_broadcast_validator_join_request` (~line 722). Gossip receive: `mxd_handle_validator_join_message` (~line 957). Auto-trigger thread: `src/node/main.c::auto_join_thread_func` (~line 192).
  - Proposer drain + apply: `src/blockchain/mxd_rsc.c::mxd_process_validation_chain` — drain at ~line 3697, apply at ~line 1230 (`mxd_apply_membership_deltas`). Storage-path verify: `src/blockchain/mxd_blockchain.c::mxd_append_membership_entry` (~line 765).
  - Genesis announce: `src/blockchain/mxd_rsc.c` — `mxd_init_genesis_coordination` (~line 2354), `mxd_broadcast_genesis_announce` (~line 2391), `mxd_handle_genesis_announce` (~line 2460); also `src/mxd_genesis_handler.c`.

## 9. Change log

| Date | Version | Change |
|---|---|---|
| 2026-05-06 | 1.0.0 | Initial draft. Formalizes the v7 validation chain signed bytes, the validator join/exit signed bytes, the genesis announce signed bytes, and the storage-path crypto verification rule. Closes audit findings L6-4, L6-5, concern 2. |
| 2026-05-20 | 1.1.0 | Permissionless validator JOIN. Adds §4.1 op_type registry, §4.3 JOIN gossip wire format, §4.4 auto-trigger eligibility (0.10 % stake threshold), §4.5 proposer drain + block inclusion, §4.6 apply-block rapid_table update, §4.7 storage-path membership verification (mirrors §3.4 for membership entries). Deprecates `op_type=0x01` EXIT (self-driven exits removed in favor of peer-driven EVICT). Reserves `op_type=0x02` for EVICT (Phase 3, forthcoming). Replaces §6 test-vector placeholder with the deterministic JSON file produced by `scripts/gen_mxd_cons01_vectors.mjs`. Validated end-to-end on testnet: a sixth validator self-joined a 5-node chain via the auto-trigger, all peers accepted gossip, the next proposer included the entry in the block, and the entry applied to every peer's in-memory rapid table on finalize (libmxd.so SHA `51ceb3c4698c74c1`, testnet block h=10–22). |
