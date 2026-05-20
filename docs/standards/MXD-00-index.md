# MXD-00: Standards Index

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.9 |
| **Created** | 2026-04-26 |
| **Updated** | 2026-05-12 |
| **Author(s)** | MXD Project |
| **Requires** | — |

## Abstract

This document is the registry of all MXD wallet and protocol cryptography specifications. Every spec is published as a separate `MXD-NN-*.md` file in this directory, each with its own version, status, and (where applicable) test vectors as `MXD-NN-test-vectors.json` alongside it.

For wallet integrators (MetaMask Snaps, exchanges, hardware wallets, indexers): a conformant Ed25519 wallet implementation requires reading **MXD-01**, **MXD-02**, **MXD-03**, and **MXD-04** in that order. Wallets claiming **post-quantum readiness** additionally implement **MXD-PQ-01** and conform to **MXD-PQ-00**. RFC 8032, BIP-39, SLIP-10, SLIP-44, and FIPS 204 are inherited normative references.

## Specification series

The numbering space is divided into two tracks:

- `MXD-NN` — main wallet/protocol specs.
- `MXD-PQ-NN` — post-quantum sub-track for specs that exclusively concern Dilithium5 / ML-KEM / future PQ algorithms, including conformance profiles that reference them.

Within either track, numbers are allocated sequentially as specs reach `Draft` status.

## Status field

Every spec carries one of:

- `Draft` — under review; bytes-on-the-wire may change. Implementations SHOULD NOT depend on a draft for production.
- `Final` — frozen. Once `Final`, a spec is immutable in the BIP/SLIP tradition. Editorial fixes bump the patch version; clarifications that don't change wire format bump the minor version; **anything that changes bytes-on-the-wire requires a new spec number**, not a major bump.
- `Superseded by MXD-NN` — historical. Listed here for completeness; do not implement.
- `Withdrawn` — abandoned without successor.

## Registry

### Main track

| ID | Title | Status | Version | Abstract |
|---|---|---|---|---|
| MXD-00 | Standards Index | Draft | 1.1.7 | This document. |
| MXD-01 | Address Format | Draft | 1.1.2 | The bytes of an MXD address: `"mx" + Base58Check(version ‖ addr32 ‖ checksum)` where `addr32 = SHA-512(algo_id ‖ pubkey)[0..31]`. Defines the `algo_id` and version-byte registries. |
| MXD-02 | Mnemonic & HD Key Derivation | Draft | 1.1.0 | BIP-39 mnemonic + SLIP-10 ed25519 hierarchical derivation along `m/44'/19800'/account'/0'`. The MXD "PIN" is absorbed into the BIP-39 25th-word passphrase. |
| MXD-03 | Signing & Verification | Draft | 1.1.1 | Ed25519 (mandatory, per RFC 8032 §5.1) and Dilithium5 / ML-DSA-87 (reserved for use under MXD-PQ-01). Length validation rules and the cross-context domain-separation contract that consumers MUST honor. |
| MXD-04 | Transaction Format & Sighash | Draft | 1.1.5 | Canonical byte serialization of a v1 MXD transaction, including a `chain_id` field for cross-fork replay protection. The sighash construction uses the `"MXD-TX-V1\0"` domain tag. Broadcast format includes a `tx_hash[64]` pre-parse dedup hint (§10.1). |
| MXD-05 | Wallet-at-rest Encryption | Draft | 1.0.0 | Local mnemonic storage format and KDF parameters: v3 Argon2id (current; t=3, m=64MiB, p=4) and v2 PBKDF2-HMAC-SHA-256 (legacy decrypt-only). AES-256-GCM cipher in both versions. Lazy migration v2→v3 on every successful unlock. |
| MXD-06 | P2P Handshake | Draft | 1.0.0 | Wire format and challenge protocol for the node-to-node handshake. Signed payload uses `"MXD-P2P-V1\0"` domain tag (84 bytes total = tag + challenge + ts + algo_id + addr32). Handshake protocol_version is `6` after v7 cutover. |
| MXD-API-01 | Bridge Oracle Attestation | Draft | 1.0.0 | HTTP request format and signed-message canonical bytes for the `/bridge/submit` BSC→MXD attestation pipeline. Canonical message is 220 bytes prefixed with `"MXD-BRG-V1\0"` and an algo_id byte. `mxd_chain_id = SHA-512(genesis_block_hash)[0..31]`. `recipient` is 64-hex addr32 (was 40-hex HASH160 pre-v7). |
| MXD-CONS-01 | Validator Consensus Signatures | Draft | 1.0.0 | Canonical bytes for validator-side consensus signing: validation-chain entries (`"MXD-CONS-1\0"` + block_hash + chain_hash + ts_be = 147 bytes), validator join/exit requests (`"MXD-VAL-V1\0"` + op_type + addr32 + ts_be = 52 bytes), and genesis announce (`"MXD-CONS-1\0"` + addr32 + pubkey + ts_be). |
| MXD-CONS-02 | Fork Choice and Reorganization | Draft | 1.0.1 | Hierarchical fork-choice rule (quorum → sig count → lex-smaller block_hash). Per-block UTXO delta storage for clean rollback (atomic with block-write via WriteBatch). 10-block reorg-depth limit; genesis hard-special-cased. Five transaction-category rollback semantics (coinbase / dual-fork / demoted-only / double-spend / dependent graphs). No double-signing slashing in v7.x. |

### Post-quantum sub-track

| ID | Title | Status | Version | Abstract |
|---|---|---|---|---|
| MXD-PQ-00 | Post-Quantum Ready Wallet Profile | Draft | 1.0.3 | A conformance profile that wallets MUST satisfy to be marketed as "post-quantum" or "PQ-ready". Binds wallets to MXD-PQ-01 by default and acknowledges the deprecation calendar for classical addresses (2030-01-01 onwards). |
| MXD-PQ-01 | Dilithium5 / ML-DSA-87 HD Key Derivation | Draft | 1.0.2 | SLIP-10-shaped HD derivation for ML-DSA-87 keypairs. Distinct master constant (`"ml-dsa seed"`) keeps the PQ key tree cryptographically independent from MXD-02's Ed25519 tree. Replaces the experimental placeholder of MXD-03 §5.3. |

### Reserved future numbers

The following IDs are reserved and not yet drafted. Reservation does not imply commitment to write the spec on any particular timeline.

| ID | Working title | Purpose |
|---|---|---|
| MXD-02-EXT | Argon2id Passphrase Wrapper | Optional wrapper that applies Argon2id to the BIP-39 seed before SLIP-10 master derivation, mitigating low-entropy passphrase brute-force risk (see MXD-02 §"Passphrase strength"). |
| MXD-PQ-02 | Hybrid KEM | Key Encapsulation Mechanism reservation (anticipated: ML-KEM-768 + X25519 hybrid per `draft-ietf-tls-hybrid-design`). For future encrypted P2P channels, encrypted mempool propagation, and wallet-at-rest public-key wrap. |
| MXD-PQ-03 | Composite Ed25519+ML-DSA-87 Signatures | Body spec for `algo_id = 0x03`, a composite signature scheme that requires BOTH algorithms to verify (AND-hybrid, not OR-hybrid). The registry slot is reserved in MXD-01 §3 and MXD-03 §3 today; the spec body is not yet drafted. |

## Domain-tag registry

This registry binds each consuming spec to a unique ASCII domain tag prefixed onto its signed bytes per MXD-03 §7. The disjoint-prefixes rule (no tag is a prefix of another) is enforced by maintaining the registry below.

Each tag is its identifier ASCII bytes followed by a single NUL terminator (`0x00`). Tag total lengths are not all equal because the identifiers vary in length.

| Tag (ASCII) | Bytes (hex) | Length | Used by | Status |
|---|---|---|---|---|
| `"MXD-TX-V1\0"` | `4D 58 44 2D 54 58 2D 56 31 00` | 10 | MXD-04 §7 (transaction sighash) | Active |
| `"MXD-VAL-V1\0"` | `4D 58 44 2D 56 41 4C 2D 56 31 00` | 11 | MXD-CONS-01 §4 (validator join/exit) | Active |
| `"MXD-P2P-V1\0"` | `4D 58 44 2D 50 32 50 2D 56 31 00` | 11 | MXD-06 §5 (P2P handshake) | Active |
| `"MXD-BRG-V1\0"` | `4D 58 44 2D 42 52 47 2D 56 31 00` | 11 | MXD-API-01 §4 (bridge oracle attestation) | Active |
| `"MXD-CONS-1\0"` | `4D 58 44 2D 43 4F 4E 53 2D 31 00` | 11 | MXD-CONS-01 §3, §5 (validation chain, genesis announce) | Active |

Future consuming specs that introduce new signed-object types MUST add a row here. The MXD-00 maintainer is responsible for verifying the disjoint-prefixes invariant before any such addition is accepted.

The reference implementation pins these byte sequences in `include/mxd_domain_tags.h` and `src/mxd_domain_tags.c` with a byte-exact unit-test assertion in `tests/test_v7_domain_tags.c`.

Tags MUST be byte-distinct sequences such that no tag is a prefix of another. Inspection of the table confirms this: `"MXD-TX-..."`, `"MXD-VAL-..."`, `"MXD-P2P-..."`, `"MXD-BRG-..."`, and `"MXD-CONS-..."` differ in their fifth byte at the latest, before any common-prefix collision could arise.

A domain tag is **active** when the spec that defines it is `Draft` or `Final`. There are currently no reserved (unimplemented) tags — every tag in the registry is in use by an active spec.

## Conformance levels

A wallet implementation claiming "MXD-01..04 conformant" MUST:

1. Implement Ed25519 (`algo_id = 0x01`) end-to-end per the four mandatory specs.
2. Reject any address whose version byte is not in MXD-01 §5's registry.
3. Reject any signature whose length does not match its declared `algo_id` (MXD-03 §6).
4. Compute sighashes using the `"MXD-TX-V1\0"` domain tag (MXD-04 §7).
5. Include a `chain_id` field in canonical transaction bytes per MXD-04 §4.

A "thin wallet" (e.g., a MetaMask Snap exposing one address) MAY further restrict itself to:

- 12-word BIP-39 mnemonics only.
- The single derivation path `m/44'/19800'/0'/0'` (account = 0).
- Ed25519 only (no Dilithium5 awareness).

Such a wallet is fully MXD-01..04 conformant. It is **not** PQ-Ready (see MXD-PQ-00).

A "PQ-Ready wallet" additionally satisfies MXD-PQ-00 §4 and acknowledges the deprecation calendar of MXD-PQ-00 §5.

### Consensus-layer scope (informative)

The MXD-01..04 conformance levels and the PQ-Ready profile (MXD-PQ-00) describe **wallet-layer** properties only. Validator signatures over the validation chain, validator-membership transitions, genesis-coordination, and the P2P handshake are now governed by **MXD-06** (handshake) and **MXD-CONS-01** (consensus signatures); the BSC→MXD bridge oracle attestation is governed by **MXD-API-01**. The MXD-05 spec covers wallet-at-rest encryption; it is wallet-layer but is not part of the MXD-01..04 conformance bundle (a wallet that does not persist itself locally can be MXD-01..04 conformant without implementing MXD-05).

A wallet may be PQ-Ready while its underlying chain's consensus layer is still Ed25519. A cryptographically-relevant quantum computer (CRQC) capable of breaking Ed25519 could compromise consensus regardless of wallet-layer choices. Honest publishers SHOULD distinguish "PQ wallet" from "PQ chain" when communicating the security properties of an MXD deployment.

#### Node block-protocol version registry (informative)

The MXD node tags every block with a `version: u32` field. The block-protocol numbering, cross-referenced here against the reference implementation at `include/mxd_protocol_version.h`, is:

| Block `version` | Description |
|---|---|
| 1 | Initial layout. |
| 2 | (Reserved.) |
| 3 | Adds `contracts_state_root` (smart-contract state commitment). |
| 4 | Adds `validator_scores_root` and on-chain `validator_score_entry_t` records (48 bytes each: `address[20] ‖ stake[8] ‖ blocks_proposed[4] ‖ blocks_signed[4] ‖ latency[8] ‖ blocks_since_joined[4]`). |
| 5 | Adds `next_proposer[20]` to the hashed header (deterministic next-block proposer). |
| 6 | **addr32 cascade.** Widens validator identity throughout the block format to MXD-01 `addr32` (32 bytes): `proposer_id[32]`, `next_proposer[32]`, `validator_score_entry_t.validator_address[32]` (entry size grows 48→60 bytes), `validator_signature_t.validator_id[32]`, and `rapid_membership_entry_t.node_address[32]`. P2P handshake bumps to handshake-protocol version 5 in concert. |
| 7 | **Domain-tag cascade.** No further widening of fields, but every consensus-layer signed-byte sequence is now domain-tagged per the registry above (MXD-VAL-V1, MXD-P2P-V1, MXD-BRG-V1, MXD-CONS-1). `mxd_chain_id` derivation switches from SHA-256 to SHA-512 truncation (`SHA-512(genesis_hash)[0..31]`); the fallback proposer-index hash switches from SHA-256 to SHA-512 likewise. P2P handshake `protocol_version` bumps `5 → 6` in concert with the MXD-P2P-V1 signed-payload introduction. **`activation_height = 0` on mainnet, testnet, and devnet — v7 is wire-format-breaking and requires a fresh genesis on every deployment.** |

This table is informative only. The normative source is `include/mxd_protocol_version.h`.

## Versioning policy

- **Patch (`x.y.Z`)** — typo, clarification, restructured prose. No semantic change.
- **Minor (`x.Y.0`)** — new optional field, expanded conformance language, additional test vectors, registry additions that do not break existing wire formats. Existing implementations remain conformant without change.
- **Major (`X.0.0`)** — RESERVED. In practice, any wire-format-breaking change is published as a new spec number with this spec marked `Superseded by MXD-NN`. The major version number on a `Final` spec is therefore stable at `1`.

## References

- `MXD-01-address-format.md`
- `MXD-02-mnemonic-and-hd-derivation.md`
- `MXD-03-signing-and-verification.md`
- `MXD-04-transaction-format-and-sighash.md`
- `MXD-05-wallet-at-rest-encryption.md`
- `MXD-06-p2p-handshake.md`
- `MXD-API-01-bridge-oracle-attestation.md`
- `MXD-CONS-01-validator-consensus-signatures.md`
- `MXD-CONS-02-fork-choice-and-reorg.md`
- `MXD-PQ-00-pq-ready-wallet-profile.md`
- `MXD-PQ-01-dilithium5-hd-derivation.md`

## Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-26 | 1.0.0 | Initial draft. Registers MXD-01..04 as Draft. |
| 2026-04-27 | 1.1.0 | Audit revisions: registers MXD-PQ-00 and MXD-PQ-01 as Draft. Adds Domain-Tag Registry. Adds Reserved entries for MXD-02-EXT (F7), MXD-CONS-01 (F6), MXD-PQ-02 (F5), MXD-PQ-03 composite signatures (F2). Adds Consensus-Layer Scope informative note. Updates Conformance Levels to require chain_id (F8). |
| 2026-04-27 | 1.1.1 | Second-audit revisions cascaded: registry version bumps for MXD-01 (1.1.1, N1+N2), MXD-04 (1.1.1, N4), MXD-PQ-00 (1.0.1, N5+N6), MXD-PQ-01 (1.0.1, N3). MXD-02 and MXD-03 unchanged (no second-audit findings touched them). |
| 2026-04-27 | 1.1.2 | Third-audit cosmetic revisions cascaded: registry version bumps for MXD-01 (1.1.2, T4), MXD-04 (1.1.2, T1+T2), MXD-PQ-00 (1.0.2, T3). All changes are documentation-only (no wire-format change). MXD-02 / MXD-03 / MXD-PQ-01 unchanged in this round. |
| 2026-04-27 | 1.1.3 | FIPS 204 size cascade (editorial): ML-DSA-87 sk 4864→4896, sig 4595→4627. Registry bumps: MXD-03 (1.1.1), MXD-PQ-00 (1.0.3), MXD-PQ-01 (1.0.2). No wire-format change. (Row date corrected from 2026-04-24 to 2026-04-27 — N-3 audit fix.) |
| 2026-04-28 | 1.1.4 | Audit-fixup cascade: MXD-04 bumped to 1.1.3 (§10 stale 4595→4627 comment corrected, M-1). |
| 2026-04-29 | 1.1.5 | Audit-fixup-v2 cascade: MXD-04 bumped to 1.1.4 (§10.1 tx_hash pre-parse dedup hint specced; §11.9 dedup rule added — undoes H-1 spec removal). N-3 changelog date corrected (v1.1.3 row was dated 2026-04-24; corrected to 2026-04-27 to restore monotonic ordering). |
| 2026-04-29 | 1.1.6 | Documents the node block-protocol v6 (addr32 cascade) under "Consensus-layer scope (informative)": validator identity widened from 20 to 32 bytes throughout the block format (`proposer_id`, `next_proposer`, `validator_score_entry_t.validator_address`, `validator_signature_t.validator_id`, `rapid_membership_entry_t.node_address`); score-entry size grows 48→60 bytes. P2P handshake protocol_version simultaneously bumped 4→5 to gate on the widened signed handshake payload. Wallet-layer specs (MXD-01..04, MXD-PQ-00, MXD-PQ-01) are unchanged. |
| 2026-05-06 | 1.1.7 | **v7 protocol bump.** Promotes four reserved spec numbers to Draft status: **MXD-05** (wallet-at-rest encryption — Argon2id v3 + PBKDF2 v2 lazy-migration); **MXD-06** (P2P handshake — `MXD-P2P-V1\0` 84-byte signed payload, `protocol_version` bumped 5→6); **MXD-CONS-01** (consensus signatures — `MXD-CONS-1\0` 147-byte validation-chain entries, `MXD-VAL-V1\0` 52-byte join/exit, MXD-CONS-1 genesis announce); **MXD-API-01** (bridge oracle attestation — `MXD-BRG-V1\0` 220-byte canonical message, `mxd_chain_id = SHA-512(genesis_hash)[0..31]`, addr32 recipient). Domain-Tag Registry expanded with the four new active tags (MXD-VAL-V1, MXD-P2P-V1, MXD-BRG-V1, MXD-CONS-1) — all 11 bytes; the original MXD-TX-V1 remains 10 bytes. Block-protocol v7 entry added: `activation_height = 0` on mainnet/testnet/devnet (fresh-genesis required). Reserved entries for MXD-05/MXD-06/MXD-API-01/MXD-CONS-01 dropped from the §"Reserved future numbers" table because those numbers are now active. Closes audit findings L6-1, L6-3, L6-4, L6-5, M6-1, concern 2 (per AUDIT_2026-05-05_v6.md). |
| 2026-05-09 | 1.1.8 | **v7.1 binary-only release** (chain stays on v7 protocol; no wire-format change). Promotes new spec **MXD-CONS-02** (Fork Choice and Reorganization, Draft v1.0.0): hierarchical fork-choice rule (quorum → sig count → lex-smaller block_hash); per-block UTXO delta storage for clean rollback; 10-block reorg-depth limit; genesis untouchable; five transaction-category rollback semantics (coinbase / dual-fork / demoted-only / double-spend / dependent graphs); no double-signing slashing in v7.x. Closes pre-mainnet audit F7-6 (the 5-node testnet's permanent forks under realistic GCP-network jitter). Validated by ~16h, ~96-active-round soak: 30 divergence events, 0 permanent forks, 100% reorg recovery. Editorial fix (F7-1): Domain-Tag Registry test-file path corrected from the stale `tests/blockchain/test_v7_signing_canonical.c` to the actual `tests/test_v7_domain_tags.c`. Closes audit findings F7-1, F7-3 (both addressed in commit `9ae2c88`), F7-5 (config IP reconcile, also `9ae2c88`), F7-6 (this spec + its merge commit). |
| 2026-05-12 | 1.1.9 | Round 8 pre-mainnet delta audit follow-ups: **MXD-CONS-02 v1.0.0 → v1.0.1**. §6 UTXO delta storage format corrected to match the deployed structured serialization (`u8[64] prev_tx_hash + u32 output_index` per spent; `u8[64] tx_hash + u32 output_index + u8[32] owner_addr + u64 amount` per created) — v1.0.0's generic key-string format was unimplementable as written (F8-12). §6.1 split out and now correctly describes that delta-write is atomic with block-write via the same `rocksdb_writebatch` in `mxd_store_block` (F8-1, fixed in code as well). Editorial: `mxd_fork_choice.h` header comment quorum-threshold formula corrected from stale `ceil(2/3*N)+1` to `ceil(2N/3)` to match both the spec and the implementation (F8-7). Round-8 CRITICAL "testnet stall" finding withdrawn after live verification: chain is correctly dormant when mempool is empty per `mxd_consensus_tick` by-design behavior; advances within seconds of a tx submission. F8-2/F8-8 (bridge-mint reorg semantics) deferred to bridge re-enable milestone because bridge is disabled in v7.1. Remaining LOW findings (F8-3/4/5/6/9/10/11) tracked as post-mainnet backlog. |
