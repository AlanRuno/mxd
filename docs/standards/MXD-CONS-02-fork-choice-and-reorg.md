# MXD-CONS-02: Fork Choice and Reorganization

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.1 |
| **Created** | 2026-05-09 |
| **Updated** | 2026-05-12 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-CONS-01, MXD-04 |

## 1. Abstract

When two valid blocks exist at the same chain height, every node must be able to **deterministically pick one** (so all nodes converge on the same canonical chain without coordination), **roll back** if its current head loses, **re-pool transactions** that were in the demoted block, and **apply** the new head's UTXO state going forward. This document defines the rules.

This spec governs node-local behavior on block ingest. It does not change any wire format, signed-bytes layout, or domain tag. A node implementing MXD-CONS-02 interoperates with peers running pre-MXD-CONS-02 v7 binaries — the only practical difference is the MXD-CONS-02 node will not stay on a losing fork.

## 2. Terminology

| Term | Meaning |
|---|---|
| `canonical head` | The block at the local chain tip that the node currently considers the truth. |
| `fork` | Two or more distinct blocks (different `block_hash`) at the same `height`. |
| `common ancestor` | The most recent block in both forks' parent chains; the height at which the forks diverged. |
| `reorg` | The act of switching the canonical head from one fork to another, including rolling back demoted blocks and applying the promoted ones. |
| `reorg depth` | `current_canonical_height - common_ancestor_height`. |
| `quorum` | A block whose `validation_count >= ceil(2 * validator_count / 3)`. For 5 validators, quorum = 4 signatures. Equivalent to `mxd_block_has_validation_quorum`. |
| `block delta` | The set of UTXOs spent and created by a block, stored under key `delta:{block_hash}` for use during reorg-rollback. |

## 3. Fork-choice rule

Given two distinct blocks A and B at the same height, the node picks the canonical block per the following hierarchy. The first rule that produces a non-tie outcome wins; subsequent rules are skipped.

### 3.1 Quorum first

If exactly one of A and B has reached quorum, the quorum block wins.

```
if A.validation_count >= QUORUM_THRESHOLD(N) and B.validation_count < QUORUM_THRESHOLD(N):
    return A
if B.validation_count >= QUORUM_THRESHOLD(N) and A.validation_count < QUORUM_THRESHOLD(N):
    return B
```

Where `QUORUM_THRESHOLD(N) = ceil(2N / 3)` and N is the validator count (= `block.rapid_membership_count`). For N=5, threshold = 4.

This rule respects the BFT-style finality threshold MXD already uses elsewhere (`mxd_block_has_validation_quorum`). A block at quorum is "BFT-finalized" and cannot be reorged out for a non-quorum competitor.

### 3.2 Else, signature count

If both A and B are at the same quorum status (both at quorum or both sub-quorum), the block with more validation signatures wins:

```
if A.validation_count > B.validation_count:
    return A
if B.validation_count > A.validation_count:
    return B
```

This captures the "more validators agree" signal without giving any single node disproportionate influence.

### 3.3 Else, lexicographic block-hash tiebreaker

If A and B have equal sig counts (typically a 0-vs-0 race at the moment a fallback proposer fires), the block with the lex-smaller `block_hash` wins:

```
return memcmp(A.block_hash, B.block_hash, 64) < 0 ? A : B
```

The `block_hash` is the 64-byte SHA-512 output of the block header. The bytewise lex comparison is uniform-random, so half of all sig-tied forks resolve to A and half to B — but consistently across all 5 nodes. There is no semantic preference; the rule exists only to break ties deterministically.

### 3.4 Implementation reference

`int mxd_compare_forks(const mxd_block_t *a, const mxd_block_t *b)` returning `<0` if A wins, `>0` if B wins, `0` only on full tie (impossible if hashes differ). Defined in `include/mxd_fork_choice.h`, implemented in `src/blockchain/mxd_fork_choice.c`.

## 4. Reorganization primitive

When `mxd_store_block` is called with a block at height N:

| Pre-state | Action |
|---|---|
| No block stored at height N | Apply UTXOs, advance head, write block delta. (Today's path; unchanged by this spec.) |
| Block at height N has same `block_hash` as new block | Idempotent; return success. |
| Block at height N has different `block_hash` | Fork detected. Continue with §4.1. |

### 4.1 Fork resolution

1. Compute `common_ancestor_height` and `common_ancestor_hash` by walking back through `prev_hash` pointers in the local block store (existing canonical chain) and the new fork's lineage.
2. Compute `reorg_depth = current_canonical_height - common_ancestor_height`.
3. If `reorg_depth > MXD_MAX_REORG_DEPTH` (= 10), refuse the reorg. The block is dropped with an `INFO`-level log; no state change. This protects against deep-history rewrites (intentional or accidental).
4. If `common_ancestor_height == 0` and the new fork attempts to demote block 0 (genesis), refuse. Genesis is hard-special-cased and never reorgs.
5. Run `mxd_compare_forks(existing_block, new_block)`:
   - If existing wins, store new block in the alternates pool keyed by `(height, block_hash)` but do not promote. The alternates pool may be cleared periodically once `current_head_height - alternate_height > MXD_MAX_REORG_DEPTH`.
   - If new wins, proceed to §4.2.

### 4.2 Rollback then replay

Reorg is performed in two phases, in this order:

**Phase 1 — Rollback** (from current canonical head down to common ancestor):

For each block being demoted:
1. Load the block delta from `delta:{block_hash}`.
2. **Reverse UTXO changes:** re-create each spent UTXO; delete each created UTXO. The delta record makes this O(|spent| + |created|) per block.
3. **Re-pool transactions** per the categories in §5.

**Phase 2 — Replay** (from common ancestor up to new fork's tip, including the new block being added):

For each block being promoted:
1. Validate the block per the existing `mxd_verify_validation_chain_integrity` (which since v7 includes cryptographic signature verification per MXD-CONS-01 §3.4).
2. Apply UTXO changes; record the new delta to `delta:{block_hash}`.
3. Remove the block's transactions from the mempool (already mined) and from any `pending_bridge_queue` (for v3 bridge mints).

After both phases complete successfully, update the canonical head pointer.

If any phase fails partway, the node is in an inconsistent state and **must abort and exit**. There is no in-place recovery — recovery is via restart from the last consistent on-disk state. Aborts of this kind should never happen in practice; if they do, they are a v7.x bug and should be reported.

### 4.3 Implementation reference

The reorg path is folded into `mxd_store_block` in `src/mxd_blockchain_db.c`. The pre-v7.1 unconditional-apply path is preserved as `store_block_unconditional` and called only when no fork is detected. The block-delta read/write helpers live in `src/blockchain/mxd_block_delta.c`.

## 5. Transaction categories on rollback

A block being rolled back may contain transactions in five categories. Each is handled differently.

### 5.1 Coinbase + tip-redistribution transactions

These are protocol-generated by the proposer of the demoted block. They are **discarded**, not re-pooled. The new canonical fork's proposer generates its own coinbase + tip-redistribution. Users are not affected.

### 5.2 User transactions already on the canonical fork

If a user transaction is present on both the demoted block and the canonical fork (typically because both fork camps mined the same mempool tx), the rollback **leaves the canonical copy untouched** and discards the demoted-side instance silently. The user's tx is still confirmed.

### 5.3 User transactions only on the demoted block

These transactions are **re-added to the local mempool** with an `re_added_after_reorg=true` diagnostic flag, then re-broadcast to peers. The next block on the canonical fork should re-mine them. Users observe the tx as `confirmed → unconfirmed → confirmed` in the next block — annoying but acceptable.

### 5.4 Double-spend conflicts

If the demoted block and the canonical block contain conflicting transactions (e.g., user X spent UTXO U on the demoted block, user Y spent the same UTXO U on the canonical block), the demoted-side tx goes back to mempool but its referenced inputs are now spent on the canonical chain. The mempool's normal tx-validation step will fail on insertion, and the tx is dropped with an `INVALID_AFTER_REORG` log. Users on the demoted side observe the tx as `confirmed → unconfirmed → dropped`, with no replacement.

This is the **only user-visible failure mode** of a reorg. Operators should communicate this risk to wallet authors (e.g., wait for ≥1 reorg-depth-margin before treating a tx as final). MXD-CONS-02 does not impose a confirmation-depth recommendation; that is a wallet-policy decision.

### 5.5 Dependent transaction graphs

If two transactions Y and X are both on the demoted block and Y spends an output of X, both go back to the mempool. The mempool retains the dependency: the next canonical block should mine X first; subsequent blocks then mine Y. If X is dropped (per §5.4), Y stays in mempool until either it is dropped due to absence of its parent UTXO or X is re-confirmed.

## 6. UTXO delta storage format

Each block stores a serialized delta record under RocksDB key `delta:{block_hash}` (70 bytes: 6-byte ASCII prefix `"delta:"` followed by the 64-byte `block_hash`). The format is binary; structured per-entry rather than generic-key-string. Spent entries reference the UTXO being consumed; created entries carry the full UTXO record so it can be re-created on rollback.

```
spent_count          u32 BE             4 bytes
per spent (xN):
  prev_tx_hash       u8[64]            64 bytes  — the tx hash whose output this UTXO came from
  output_index       u32 BE             4 bytes  — the output index within that tx
                                                   (spent UTXO = "spent_count × 68 bytes" total)

created_count        u32 BE             4 bytes
per created (xM):
  tx_hash            u8[64]            64 bytes  — the tx in this block that created the UTXO
  output_index       u32 BE             4 bytes  — output index in that tx
  owner_addr         u8[32]            32 bytes  — addr32 of the UTXO owner
  amount             u64 BE             8 bytes  — value in base units
                                                   (created UTXO = "created_count × 108 bytes" total)
```

Total serialized length = `4 + 68·spent_count + 4 + 108·created_count`.

Structured form is chosen (rather than a generic key+blob format) so the rollback path can re-create the spent UTXO record from `(prev_tx_hash, output_index)` and the in-memory address-pubkey-index without round-tripping to the underlying UTXO store's key format. Both fields are network/big-endian where they are multi-byte integers; the hashes and addresses are byte arrays in their canonical order.

### 6.1 Atomicity guarantee

Delta records are written **atomically with the block** by `mxd_store_block`: the delta-key Put is added to the same `rocksdb_writebatch` as the block's height-key and hash-key Puts. A crash mid-write therefore cannot leave a block stored without its delta — either the entire batch lands or none of it does. This guarantee is load-bearing: the reorg-rollback path (§4.2) assumes the delta is present for every demoted block.

Delta records are read on rollback only. They MAY be garbage-collected once the block is older than `MXD_MAX_REORG_DEPTH` from the current canonical head, but implementations are not required to do so.

### 6.2 Implementation reference

- Serialization: `mxd_block_delta_serialize` / `mxd_block_delta_deserialize` in `src/blockchain/mxd_block_delta.c`.
- Key construction: `mxd_block_delta_make_key` in same file (exposed via `include/mxd_block_delta.h` as `MXD_BLOCK_DELTA_KEY_LEN = 70`).
- Atomic write: `mxd_store_block` in `src/mxd_blockchain_db.c` adds the delta to its WriteBatch alongside the block-key Puts.

## 7. Reorg depth limit

`MXD_MAX_REORG_DEPTH = 10`.

Any reorg that would demote more than 10 blocks from the current canonical head is **refused**. The new block is dropped with a diagnostic log (`reorg too deep: depth=N, max=10`). Genesis (height 0) is hard-special-cased to never reorg, regardless of depth.

The 10-block limit is a defense against:
- **Deep reorg attacks** where a partition healing introduces a much-longer alternate chain.
- **State inconsistency** from buggy delta records: deeper rollbacks compound any per-block delta errors.
- **Unbounded resource use** during rollback (each demoted block adds work).

Operators experiencing chronic deep-reorg refusals should investigate the partition (likely an extended network split) rather than increase the limit.

## 8. Validator double-signing

MXD-CONS-02 v1.0.0 does **not** punish validators that sign two competing blocks at the same height. A validator on a losing fork loses its `tip_share` from the demoted block (the demoted coinbase is discarded); that is the only natural penalty.

Slashing for double-signing is reserved for a future MXD-CONS-03 spec. Implementing it requires:
- Gossip protocol for slash evidence (e.g., a paired-signatures-at-same-height proof)
- On-chain slash transaction type
- Validator stake forfeiture mechanism

None of these are in scope for v7.x. Validators that double-sign today are tolerated but their double-signing has no positive impact on either fork's chances.

## 9. Soak validation (informative)

The reorg implementation was validated on a 5-node testnet (`mxd-test-node-testing-0..4`) with a 16-hour soak driving 1 user transaction every 10 minutes (96 active rounds). Observed:

- 30 divergence events flagged (some real forks, some single-node sync lags)
- 100% resolved within 1-2 rounds via reorg or natural sync
- 0 permanent forks
- 0 height stalls
- 0 validator dropouts
- Chain advanced 103 blocks at average 1.07 blocks/round under traffic

Soak telemetry is archived at `F:/Proyectos/v7_soak_archive.log`.

## 10. References

- **Code:**
  - `include/mxd_fork_choice.h` — fork-choice API
  - `src/blockchain/mxd_fork_choice.c` — `mxd_compare_forks`, `mxd_find_common_ancestor`
  - `include/mxd_block_delta.h` — UTXO delta serialization API
  - `src/blockchain/mxd_block_delta.c` — `mxd_block_delta_serialize`, `mxd_block_delta_deserialize`
  - `src/mxd_blockchain_db.c` — `mxd_store_block` (fork-choice + reorg integration)
- **Tests:**
  - `tests/test_fork_choice.c` — synthetic fork-choice scenarios
  - `tests/test_reorg.c` — reorg primitive (UTXO reversal, mempool re-add, depth limit, genesis untouchable)
- **Audit:** `F:/Proyectos/AUDIT_2026-05-07_v7_pre_mainnet.md` F7-6 (the finding this spec answers)
- **MXD-CONS-01** for the validation-chain canonical bytes that MXD-CONS-02 reorgs preserve.

## 11. Changelog

- **v1.0.0 (2026-05-09)** — Initial draft. Hierarchical fork-choice rule (quorum → sig count → hash); 10-block reorg depth limit; UTXO delta storage; transaction-category rollback semantics; no slashing for v7.x.
- **v1.0.1 (2026-05-12)** — §6 UTXO delta storage format corrected (F8-12 from `AUDIT_2026-05-09_v8_pre_mainnet_delta.md`). v1.0.0 described a generic `u16 key_len + key string` encoding that was unimplementable as written and did not match the deployed serialization. v1.0.1 documents the actual structured layout (`u8[64] prev_tx_hash + u32 output_index` per spent; `u8[64] tx_hash + u32 output_index + u8[32] owner_addr + u64 amount` per created). §6.1 split out and clarifies that delta-write is now genuinely atomic with the block via a single `rocksdb_writebatch` (F8-1, fixed in `mxd_store_block`).
