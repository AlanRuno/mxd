# MXD-06: P2P Handshake

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.0 |
| **Created** | 2026-05-06 |
| **Updated** | 2026-05-06 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-03 |

## 1. Abstract

This document defines the wire format and signing protocol for the MXD node-to-node handshake message. A handshake authenticates each peer to the other before any block, transaction, or peer-list traffic is exchanged. The handshake is symmetric: each side produces a signed payload, sends it, and verifies the peer's reply. Mutual success activates the connection; any failure causes the connection to be closed without further exchange.

## 2. Terminology

| Term | Meaning |
|---|---|
| `protocol_version` | The wire-format version of the handshake itself (currently `6`). This is **not** the block-protocol version of the chain (which is `7` after the v7 cutover; see MXD-00 §"Node block-protocol version registry"). The two version numbers evolve independently. |
| `algo_id` | MXD-01 §3 algorithm identifier of the node's keypair. `0x01` (Ed25519) or `0x02` (Dilithium5). |
| `addr32` | The peer's MXD-01 32-byte address. Bound into the signed payload so a stolen signature cannot be replayed under a different identity. |
| `challenge` | A 32-byte random nonce. Used to prevent replay of a previously captured handshake message. |
| `node_id` | The peer's `"mx…"` Base58Check display address (MXD-01 §9), kept on the wire as a 256-byte ASCII field for human-readable logging. The signed payload binds the underlying `addr32`, not the textual form. |

## 3. Wire format

The handshake payload is sent as the body of an `MXD_MSG_HANDSHAKE` message. The full packet layout is:

```
mxd_wire_header_t (87 bytes) || handshake_payload (variable)
```

The wire header (`mxd_wire_header_t`) is shared with all P2P message types and is out of scope for this document; the handshake payload starts immediately after it.

### 3.1 Handshake payload

| Offset | Field | Type | Width | Notes |
|---|---|---|---|---|
| 0 | `node_id` | ASCII | 256 | The peer's display address, NUL-padded. |
| 256 | `protocol_version` | u32 BE | 4 | `6` after v7 cutover; see §4. |
| 260 | `listen_port` | u16 BE | 2 | The peer's TCP listen port for further connections. |
| 262 | `algo_id` | u8 | 1 | `0x01` or `0x02`. |
| 263 | `public_key_length` | u16 BE | 2 | `32` for Ed25519, `2592` for Dilithium5. |
| 265 | `public_key` | bytes | `public_key_length` | Raw public-key bytes. |
| 265 + pk | `challenge` | bytes | 32 | 32 bytes of random per CSPRNG. |
| 297 + pk | `timestamp` | u64 BE | 8 | Unix seconds at the moment the handshake was constructed. |
| 305 + pk | `signature_length` | u16 BE | 2 | `64` for Ed25519, `4627` for Dilithium5. |
| 307 + pk | `signature` | bytes | `signature_length` | Signature over the §5 signed payload. |
| 307 + pk + sig | `network_type_len` | u8 | 1 | Length of the trailing `network_type` ASCII string (without NUL). |
| 308 + pk + sig | `network_type` | ASCII | `network_type_len` | `"mainnet"`, `"testnet"`, or `"devnet"`. |

All multi-byte integers are big-endian. The `public_key`, `challenge`, and `signature` byte arrays are appended as-is.

### 3.2 Algorithm dispatch

`algo_id` selects the signature primitive used for `signature`:

| `algo_id` | Algorithm | `public_key_length` | `signature_length` |
|---|---|---|---|
| `0x01` | Ed25519 | `32` | `64` |
| `0x02` | Dilithium5 / ML-DSA-87 | `2592` | `4627` |

Length validation MUST happen before primitive dispatch (per MXD-03 §6). A handshake whose `public_key_length` or `signature_length` does not match its `algo_id` MUST be rejected without invoking the verify primitive.

## 4. Protocol version

`protocol_version` MUST equal the receiver's expected version exactly. There is no forward or backward compatibility band: a peer running an older or newer handshake protocol is hard-rejected at handshake parse time.

| MXD code revision | `protocol_version` |
|---|---|
| Pre-v6 (HASH160 era) | `4` |
| v6 (addr32 cascade) | `5` |
| v7 (domain-tag cascade — current) | `6` |

The v6→v7 jump on handshake `protocol_version` (5→6) is what gates MXD-P2P-V1 domain-tagged signed payloads (§5). A peer running v6 code paths produces a signature over the pre-tag payload (32-byte addr32 only); a peer running v7 produces a signature over the §5 tagged payload. Without the version bump, a v7 peer would silently fail to verify a v6 peer's signature with no diagnostic at the version layer; the bump turns that into a clean rejection at packet-parse time.

## 5. Signed payload

The bytes a peer signs (and the peer on the receiving side reconstructs to verify) are:

```
signed_payload :=

  domain_tag      "MXD-P2P-V1\0"   11 bytes  (per MXD-00 Domain-Tag Registry)
  challenge       [u8; 32]         32 bytes  (the 32-byte nonce from §3.1)
  timestamp       u64 BE            8 bytes  (mirrors §3.1)
  algo_id         u8                1 byte   (mirrors §3.1)
  addr32          [u8; 32]         32 bytes  (the signer's MXD-01 addr32)

  total                            84 bytes
```

The domain tag bytes are exactly:

```
4D 58 44 2D 50 32 50 2D 56 31 00
```

The `addr32` MUST be the address derived from the same `(algo_id, public_key)` carried in the handshake payload — `SHA-512(algo_id ‖ public_key)[0..31]` per MXD-01 §4. Receivers MUST recompute the addr32 from the on-the-wire `algo_id` and `public_key` and compare; mismatch is grounds for rejection (the peer is presenting a key that does not own the claimed identity).

The signature is produced by MXD-03's `Ed25519_Sign` or `ML-DSA-87_Sign` primitive (selected by `algo_id`) over the 84-byte `signed_payload`. There is no pre-hash — the signature primitive takes the message bytes directly.

## 6. Validation rules

A receiver MUST apply all of the following and reject any handshake that fails:

1. **Header parse.** The 256-byte `node_id`, 4-byte `protocol_version`, 2-byte `listen_port`, 1-byte `algo_id`, and 2-byte `public_key_length` parse cleanly within the message bytes.
2. **Protocol version match.** `protocol_version == 6` (see §4).
3. **Algo and length sanity.** `algo_id ∈ {0x01, 0x02}`. `public_key_length` and `signature_length` match the table in §3.2 for the declared `algo_id`.
4. **Network match.** `network_type` (case-sensitive) matches the receiver's configured network. A mainnet node MUST refuse a testnet handshake and vice versa. (This is in addition to the MXD-04 chain_id defense at the transaction layer; the network gate at handshake time prevents transaction-layer leakage in the first place.)
5. **Address consistency.** `addr32_derived := SHA-512(algo_id ‖ public_key)[0..31]` equals the addr32 implied by the textual `node_id` (the receiver decodes the `"mx…"` Base58Check form per MXD-01 §9 and compares the inner 32 bytes).
6. **Signed-payload reconstruction.** The receiver assembles the 84-byte payload of §5 from the on-the-wire fields and verifies the signature.
7. **Timestamp drift.** Implementation-defined; the reference implementation does not enforce a strict bound on `timestamp` because the 32-byte `challenge` already provides nonce freshness for replay defense. Implementers MAY apply a window if their threat model requires it.

## 7. Handshake flow

```
A                                                  B
|                                                   |
|-- HANDSHAKE (A's payload, signed) --------------->|
|                                                   |  validate per §6
|                                                   |  generate session_token[16]
|                                                   |  send HANDSHAKE reply
|<-- HANDSHAKE (B's payload, signed) ---------------|
|<-- SESSION_TOKEN (16 random bytes) ---------------|
|<-- GET_PEERS (over TCP) --------------------------|
| validate per §6                                   |
| generate session_token[16]                        |
|-- HANDSHAKE reply complete ---------------------->|
|-- SESSION_TOKEN ---------------------------------->|
|                                                   |
| connection active                                 |
```

The session token is a 16-byte random opaque value each side mints for the other. Subsequent messages on the connection echo the peer's session token in the wire header; messages with a wrong session token MUST be dropped. The session-token mechanism is not part of this spec's signed-payload defense — it is an additional in-connection identity check above the layer this spec defines.

## 8. Test vectors

Test vectors will be provided as `MXD-06-test-vectors.json` in a follow-up Dispatch C work item. Vector classes:

- Ed25519 handshake: full payload bytes, signed-payload bytes, signature, derived `addr32`, expected accept.
- Dilithium5 handshake: same, with the longer pubkey and signature.
- Negative: wrong `protocol_version` (e.g., `5`).
- Negative: addr32 derived from `(algo_id, public_key)` does not match `node_id`.
- Negative: signature mutated by one byte.
- Negative: `network_type` mismatch.
- Negative: `signature_length` does not match `algo_id` (Ed25519 with a 4627-byte signature; Dilithium5 with a 64-byte signature).

## 9. Security considerations

### 9.1 Cross-context replay

Defended by the `"MXD-P2P-V1\0"` domain tag. A signature over an MXD-04 transaction sighash, an MXD-CONS-01 validation-chain entry, or a future P2P message type cannot be replayed as a handshake signature, because each starts with a different domain tag (per MXD-00's disjoint-prefixes registry).

Pre-v7 handshakes signed `addr20` or `addr32` directly with no domain prefix. A captured pre-v7 signature for a handshake at timestamp T cannot be replayed as a v7 handshake signature even at the same T, because the v7 signed bytes are a different sequence (tag-prefixed and with timestamp/algo_id/addr32 ordering); the cross-version replay window closes hard at the v7 cutover.

### 9.2 Identity binding

Binding `addr32` and `algo_id` into the signed payload means a peer cannot claim someone else's identity even if they somehow obtained that identity's public key. The signature MUST be produced with the matching private key, and the receiver verifies it with the on-the-wire public key — at which point the on-the-wire `algo_id` and `public_key` are already pinned by the signature being valid.

### 9.3 Replay defense

The 32-byte `challenge` is a random nonce regenerated on every handshake construction. A passive eavesdropper who replays a captured handshake at a different time presents the same challenge bytes; the receiver has no per-peer challenge memory but does observe the bound `timestamp`, and (by §5) the signature commits to that timestamp. An active replay against the same peer at a different time would still validate the signature (the nonce is in the signed bytes, not in a verifier-side state), but the connection would establish a stale session — the consumer (block-relay logic, peer-discovery logic) acts on the established TCP connection itself, not the handshake message after the fact, so a replay does not unlock any further capability the attacker did not already have.

### 9.4 Algorithm hard-rejection

The handshake explicitly rejects unknown `algo_id` values and length-mismatched signatures before invoking the verify primitive (§3.2). This closes a class of parser-confusion attacks where a peer might offer an `algo_id` of `0x03` (the reserved composite slot) and a 4627-byte signature, hoping the receiver dispatches to Dilithium5; the size match is incidental and the dispatch does the wrong thing. The MXD-03 §6 length-validation regime, applied before primitive dispatch, is the defense.

## 10. References

- **MXD-01**: Address Format. The `addr32` and `algo_id` registries.
- **MXD-03**: Signing & Verification. The Ed25519 and Dilithium5 primitives, the disjoint-domain rule of §7, and the length-validation regime of §6.
- **MXD-00**: Standards Index. The Domain-Tag Registry where `"MXD-P2P-V1\0"` is registered.
- **AUDIT_2026-05-05_v6.md** finding **L6-5**: motivated the protocol_version bump and the addition of the MXD-P2P-V1 domain tag.
- Reference implementation: `src/mxd_p2p.c`, in particular the `create_signed_handshake` function (~line 1242) and the `handle_handshake_message` verify path (~line 1352) — the byte layouts at lines 1274–1282 (sign) and 1440–1448 (verify) are the normative source.

## 11. Change log

| Date | Version | Change |
|---|---|---|
| 2026-05-06 | 1.0.0 | Initial draft. Formalizes the v7 handshake. Closes audit finding L6-5. |
