# MXD-API-01: Bridge Oracle Attestation

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.0 |
| **Created** | 2026-05-06 |
| **Updated** | 2026-05-06 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-03 |

## 1. Abstract

This document defines the wire format and signing protocol for the BSC→MXD bridge oracle attestation pipeline. An off-chain oracle observes a `Deposit` event on the BSC bridge contract and produces a signed attestation that an MXD node will accept as authority for minting the corresponding amount on MXD. The MXD-API-01 attestation is the unique pre-condition for a `bridge_mint` transaction.

This spec is normative on the bytes the MXD C node accepts at its `/bridge/submit` HTTP endpoint and on the canonical bytes the oracle signs. It is **not** normative on the BSC-side Solidity contract layout (deployment of which is a separate operational milestone) — but it constrains the contract by requiring that `Deposit.mxdRecipient` be a 32-byte field; a contract that emits a 20-byte recipient cannot interoperate with an MXD-API-01 v7 oracle.

## 2. Terminology

| Term | Meaning |
|---|---|
| `oracle` | An off-chain process that watches BSC for `Deposit` events and submits attestations to an MXD node. |
| `algo_id` | MXD-01 §3 algorithm identifier (`0x01` Ed25519 or `0x02` Dilithium5). The deployed bridge oracles use `0x02`. |
| `addr32` | A 32-byte MXD-01 address. The `recipient` field is an addr32. |
| `bridge_contract` | The 64-byte SHA-512 hash of the BSC contract's deployment data, used as a stable on-chain identifier independent of the BSC contract address format. |
| `mxd_chain_id` | A 32-byte MXD chain identifier derived from the genesis block hash. See §5. Distinct from MXD-04's `chain_id: u32` field — that field identifies the MXD network at the transaction-layer; this 32-byte field is a separate, replay-protection field for bridge attestations. |

## 3. HTTP request format

The oracle submits a single `POST /bridge/submit` request per BSC `Deposit` event. The request body is `application/json` with the following fields. Field order is not significant.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | MUST be `"bridge_mint"`. |
| `bridge_contract` | hex string | yes | 128 hex chars (64 bytes). |
| `source_chain_id` | string | yes | One of `"bsc_testnet_97"` or `"bsc_mainnet_56"`. Other values are rejected. |
| `source_tx_hash` | hex string | yes | 64 hex chars (32 bytes). The BSC transaction hash that emitted the `Deposit` event. |
| `source_block_number` | JSON number | yes | The BSC block number of the deposit. |
| `recipient` | hex string | yes | 64 hex chars (32 bytes). The MXD addr32 of the recipient. **Pre-v7 was 40 hex chars (20 bytes).** |
| `amount` | JSON number | yes | The mint amount in MXD base units. MUST be > 0. |
| `oracle_pubkey` | hex string | yes | Raw public-key bytes of the signing oracle. 64 hex chars (Ed25519, 32 bytes) or 5184 hex chars (Dilithium5, 2592 bytes). |
| `oracle_algo_id` | JSON number | yes | `1` (Ed25519) or `2` (Dilithium5). |
| `oracle_signature` | hex string | yes | The oracle's signature over the §4 canonical message. 128 hex chars (Ed25519, 64 bytes) or 9254 hex chars (Dilithium5, 4627 bytes). |

The request body is a flat JSON object. There is no enclosing `{ "transaction": {...} }` wrapper.

### 3.1 Field encodings on the wire

The receiving C node parses these JSON fields and produces an internal `mxd_bridge_payload_t`:

- `bridge_contract` (128 hex chars) → `payload.bridge_contract[64]` byte-for-byte.
- `source_chain_id` string → `payload.source_chain_id[32]` with the integer chain id (`97` or `56`) written into the first 4 bytes as `uint32_t` in **big-endian byte order**, the remaining 28 bytes zeroed. (v7 alignment with MXD-04 §3 "BE everywhere".)
- `source_tx_hash` (64 hex chars) → `payload.source_tx_hash[32]` byte-for-byte.
- `source_block_number` JSON number → `payload.source_block_number: u64` (in-memory representation is host-native; the canonical signed message of §4 encodes it big-endian).
- `recipient` (64 hex chars) → `payload.recipient_addr[32]` byte-for-byte.
- `amount` JSON number → `payload.amount: u64` (in-memory representation is host-native; the canonical signed message of §4 encodes it big-endian).

## 4. Canonical signed message

The oracle signs the following 220 bytes:

```
canonical_message :=

  domain_tag             "MXD-BRG-V1\0"   11 bytes  (per MXD-00 Domain-Tag Registry)
  algo_id                u8                1 byte   (matches oracle_algo_id)
  bridge_contract        [u8; 64]         64 bytes
  source_chain_id        [u8; 32]         32 bytes  (uint32 chain id in first 4 bytes BE; rest zero)
  source_tx_hash         [u8; 32]         32 bytes
  source_block_number    u64 BE            8 bytes
  recipient              [u8; 32]         32 bytes  (addr32)
  amount                 u64 BE            8 bytes
  mxd_chain_id           [u8; 32]         32 bytes  (per §5)

  total                                  220 bytes
```

The domain tag bytes are exactly:

```
4D 58 44 2D 42 52 47 2D 56 31 00
```

Field offsets:

| Offset | Field | Width |
|---|---|---|
| 0 | `domain_tag` | 11 |
| 11 | `algo_id` | 1 |
| 12 | `bridge_contract` | 64 |
| 76 | `source_chain_id` | 32 |
| 108 | `source_tx_hash` | 32 |
| 140 | `source_block_number` (BE) | 8 |
| 148 | `recipient` | 32 |
| 180 | `amount` (BE) | 8 |
| 188 | `mxd_chain_id` | 32 |
| 220 | (end) | — |

The signature is produced by MXD-03's `Ed25519_Sign` or `ML-DSA-87_Sign` primitive (selected by `algo_id`) over the 220-byte `canonical_message`. There is no pre-hash.

### 4.1 `algo_id` binding

Including `algo_id` in the signed bytes (offset 11) prevents a Dilithium5 signature from being replayed against an Ed25519 allowlist entry, even if both algorithms shared a single oracle identity. A v7 verifier that locates an oracle in the allowlist by `(algo_id, pubkey)` tuple and reconstructs the canonical message with the on-the-wire `oracle_algo_id` will reject a cross-algorithm replay because the signed bytes' offset-11 byte does not match what the alleged signer would have signed.

## 5. `mxd_chain_id` derivation

`mxd_chain_id` is a 32-byte MXD-side chain identifier derived from the genesis block hash:

```
mxd_chain_id := SHA-512( genesis_block.block_hash )[0..31]
```

That is, the SHA-512 of the 64-byte genesis block hash, truncated to the first 32 bytes.

### 5.1 Why SHA-512 and why truncate

SHA-512 is used (rather than SHA-256) for consistency with the rest of the v7 cryptographic surface — addresses, sighashes, and the chain-hash construction of MXD-CONS-01 §3 are all SHA-512-based. The 32-byte truncation provides a 256-bit identifier (sufficient collision resistance for chain disambiguation) and aligns with the addr32 width.

The post-quantum justification: SHA-512 is currently believed to retain ~256 bits of pre-image resistance against a Grover-style quantum attack, vs. ~128 bits for SHA-256. A bridge that survives the v7 horizon requires the longer hash family to provide the same long-term security floor as the address layer (which moved to SHA-512 in MXD-01 v1.1.x).

### 5.2 Fallback when genesis is unavailable

If the C node cannot retrieve the genesis block (a transient state on a freshly bootstrapped node before genesis has been stored), `mxd_chain_id` MUST default to 32 zero bytes. The oracle's signing implementation also falls back to zeros when the field is unknown to the caller. This means a deposit attestation produced before the chain has a stable genesis MAY succeed verification on a node in the same pre-genesis state but fail verification on a fully-synced node — this is acceptable because such pre-genesis attestations are operationally useless (the node has no UTXO state to mint into yet) and the failure mode is fail-closed.

## 6. Validation rules

The MXD node MUST apply all of the following before accepting a `/bridge/submit` request. Any failure rejects the request with a 4xx HTTP status; the `bridge_mint` transaction is **not** broadcast.

1. **JSON parse and field presence.** All fields of §3 are present and have the right JSON type.
2. **Field length sanity.** `bridge_contract` is 128 hex chars, `source_tx_hash` is 64 hex chars, `recipient` is 64 hex chars, `oracle_pubkey` length matches `oracle_algo_id` (64 hex chars for Ed25519, 5184 hex chars for Dilithium5), `oracle_signature` length matches `oracle_algo_id` (128 hex chars for Ed25519, 9254 hex chars for Dilithium5).
3. **Recognized source chain.** `source_chain_id ∈ {"bsc_testnet_97", "bsc_mainnet_56"}`.
4. **Positive amount.** `amount > 0`.
5. **Oracle in allowlist.** The `(oracle_algo_id, oracle_pubkey)` tuple matches one of the entries in the node's configured `bridge_oracle_pubkeys` allowlist. There is **no validator-set fallback** — if the oracle is not on the explicit allowlist, the request is rejected with HTTP 403.
6. **Canonical reconstruction.** The node assembles the 220-byte `canonical_message` per §4 from the parsed fields and the locally-derived `mxd_chain_id` (§5).
7. **Signature verify.** `verify_mxd(oracle_algo_id, oracle_pubkey, msg = canonical_message, sig = oracle_signature)` per MXD-03 returns success.

On all validations passing, the node proceeds to construct and broadcast a `bridge_mint` v3 transaction whose embedded `mxd_bridge_payload_t` echoes the same fields. Replay defense is provided by the on-chain `bridge_replay:source_tx_hash` index, which the transaction-validation pipeline checks at block-inclusion time. An oracle that submits the same `source_tx_hash` twice will succeed at the HTTP layer the second time but the resulting transaction will be rejected at block-validation time as a duplicate.

### 6.1 Oracle allowlist configuration

The node's `bridge_oracle_pubkeys` allowlist is configured at start-up (per `mxdlib/include/mxd_config.h`'s `http.bridge_oracle_pubkeys` array). The allowlist is **not** drawn from the validator set — bridge oracles are a separate role from block-producing validators, and conflating them would conflate trust models. Operational policy MAY establish a single physical operator running both an oracle and a validator, but the cryptographic identities (and therefore the keypairs) MUST remain distinct because the spec layers (MXD-API-01 vs. MXD-CONS-01) bind to different domain tags.

## 7. BSC-side requirements (informative)

For a BSC bridge contract to interoperate with an MXD-API-01 v7 oracle, the contract MUST emit a `Deposit` event whose `mxdRecipient` field is `bytes32`:

```
event Deposit(
    address indexed depositor,
    bytes32 indexed mxdRecipient,
    uint256 amount,
    uint256 timestamp
);
```

Pre-v7 contracts emitted `bytes20 mxdRecipient` (the legacy HASH160 address). A v7 oracle reading a v6 contract's `Deposit` events will encounter a 20-byte recipient that does not satisfy the §3 validation rule of `recipient` being 64 hex chars (32 bytes). This is the operational meaning of "v7 is a wire-format-breaking change requiring a fresh genesis": the old bridge contract is unreadable by v7 oracles, and the new contract cannot be deployed without a coordinated cutover.

This spec does not normatively specify the contract source — the contract is governed by its own deployment pipeline. The constraint here is on the field width; details of contract upgradeability, admin keys, and so on are governance concerns.

## 8. Test vectors

Test vectors will be provided as `MXD-API-01-test-vectors.json` in a follow-up Dispatch C work item. Vector classes:

- Dilithium5 oracle: full `POST` body (JSON), full hex of the 220-byte canonical message, signature, expected accept.
- Ed25519 oracle: same with the shorter pubkey and signature.
- Negative: oracle not in allowlist (HTTP 403).
- Negative: signature mutated by one byte.
- Negative: `recipient` is 40 hex chars (legacy v6 width); MUST be rejected with HTTP 400.
- Negative: `amount = 0`; MUST be rejected with HTTP 400.
- Negative: cross-algorithm replay (Dilithium5 signature presented with `oracle_algo_id = 1`); MUST be rejected at signature verify because the canonical message reconstructs with `algo_id = 0x01` at offset 11 and the signature was produced over `algo_id = 0x02`.

## 9. Security considerations

### 9.1 Cross-context replay

Defended by the `"MXD-BRG-V1\0"` domain tag. A signature over an MXD-04 transaction sighash, an MXD-CONS-01 validation-chain entry, an MXD-CONS-01 genesis announce, an MXD-VAL-V1 join/exit request, or an MXD-P2P-V1 handshake cannot be replayed as a bridge attestation, because each spec uses a different domain tag (per MXD-00's disjoint-prefixes registry).

### 9.2 Cross-chain replay

Defended by the `mxd_chain_id` field (§5). A bridge attestation signed for mainnet has `mxd_chain_id = SHA-512(mainnet_genesis_hash)[0..31]`; the same logical attestation prepared for testnet would have a different `mxd_chain_id`, a different canonical message, and a different signature. A captured mainnet attestation cannot be replayed against a testnet node.

This complements (and is independent of) MXD-04's `chain_id: u32` field, which protects the wrapping `bridge_mint` transaction from cross-MXD-network replay.

### 9.3 Cross-algorithm replay

Defended by the `algo_id` byte at offset 11 of the canonical message (§4.1). A signature produced under `algo_id = 0x02` (Dilithium5) cannot be presented as if it were `algo_id = 0x01` (Ed25519) because the canonical message at the verifier reconstructs with the on-the-wire `oracle_algo_id` and the signed bytes commit to that byte's value.

### 9.4 Replay across deposits

Defended by the on-chain `bridge_replay:source_tx_hash` index. The same `source_tx_hash` cannot be minted twice because the second `bridge_mint` transaction's UTXO-validation pipeline checks the index. This is enforced at block-inclusion time, not at HTTP-submit time, so the HTTP layer accepts repeated submits and downstream block validation rejects them; an oracle MAY observe the second `bridge_mint` in the mempool but will not see it confirmed.

### 9.5 Pre-v7 196-byte canonical message

The pre-v7 (v6 era) canonical message was 196 bytes (or 208 bytes with the `mxd_chain_id` field added in v6 H5-1). It carried no domain tag and no `algo_id` byte, and used a 20-byte (HASH160) recipient. A signature produced for that pre-v7 canonical message has none of the v7 defenses (no domain separation, no algo binding, narrower recipient identity) and is **not** interoperable with v7 verification: a v7 verifier reconstructs a different byte sequence and rejects.

The v7 cutover is a one-shot wire flip; the oracle and the node must redeploy together. There is no transitional dual-format support.

## 10. References

- **MXD-01**: Address Format. The addr32 width and SHA-512 derivation of the `recipient` field.
- **MXD-03**: Signing & Verification. The Ed25519 and Dilithium5 primitives, the disjoint-domain rule of §7, and the length-validation regime of §6.
- **MXD-00**: Standards Index. The Domain-Tag Registry where `"MXD-BRG-V1\0"` is registered.
- **AUDIT_2026-04-29_v5.md** finding **C5-1**: motivated the `mxd_chain_id` field and the cross-chain replay defense.
- **AUDIT_2026-05-05_v6.md** findings **M6-1** (SHA-512 chain_id and 220-byte canonical message) and **L6-3** (algo_id binding).
- Reference implementation (node): `mxdlib/src/mxd_http_api.c`, `handle_bridge_submit` (~line 1080) and the canonical-message reconstruction (~line 1257).
- Reference implementation (chain id): `mxdlib/src/mxd_transaction.c`, `mxd_get_chain_id` (~line 1715).
- Reference implementation (oracle): `mxd-bridge-oracle/src/utils/mxd-signer.js`, `signBridgeMintTransaction` (~line 39); `mxd-bridge-oracle/src/monitors/bnb-monitor.js`, the `/bridge/submit` POST builder (~line 813).

## 11. Change log

| Date | Version | Change |
|---|---|---|
| 2026-05-06 | 1.0.0 | Initial draft. Formalizes the v7 220-byte canonical message, the SHA-512-based `mxd_chain_id`, the addr32 recipient, and the oracle-allowlist policy. Closes audit findings M6-1, L6-3, and the C5-1 cross-chain replay rule. |
