#!/usr/bin/env node
/*
 * gen_mxd_cons01_vectors.mjs — regenerate the MXD-CONS-01 JSON test vectors
 * covering MXD-VAL-V1 JOIN / EXIT canonical-bytes + reference signature.
 *
 * Deterministic: every input (seed, timestamp) is fixed, so re-runs produce
 * bit-identical output. Updating the spec MUST re-run this script and commit
 * the resulting MXD-CONS-01-test-vectors.json alongside the doc changes.
 *
 *   node gen_mxd_cons01_vectors.mjs > MXD-CONS-01-test-vectors.json
 */

import { createHash, webcrypto } from 'node:crypto';

function sha512(buf) {
  const h = createHash('sha512');
  h.update(buf);
  return new Uint8Array(h.digest());
}

// Node 22 WebCrypto Ed25519 — same primitive the wallet UI uses in production
// (wallet-client/src/crypto/ed25519.js). PKCS8 wrapper for the seed is the
// "DER-prefix-the-32-byte-seed" trick from wallet-client's signer.
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
  0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

async function ed25519Sign(seed, msg) {
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed.slice(0, 32), PKCS8_PREFIX.length);
  const key = await webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const sig = await webcrypto.subtle.sign('Ed25519', key, msg);
  return new Uint8Array(sig);
}

async function ed25519PublicFromSeed(seed) {
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed.slice(0, 32), PKCS8_PREFIX.length);
  const priv = await webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await webcrypto.subtle.exportKey('jwk', priv);
  // jwk.x is the public key in base64url
  const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64 + '='.repeat((4 - b64.length % 4) % 4);
  return new Uint8Array(Buffer.from(pad, 'base64'));
}

async function ed25519Verify(pubkey, msg, sig) {
  const key = await webcrypto.subtle.importKey('raw', pubkey, { name: 'Ed25519' }, false, ['verify']);
  return await webcrypto.subtle.verify('Ed25519', key, sig, msg);
}

function hex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function u64be(n) {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

const DOMAIN_VAL = new Uint8Array([0x4d, 0x58, 0x44, 0x2d, 0x56, 0x41, 0x4c, 0x2d, 0x56, 0x31, 0x00]); // "MXD-VAL-V1\0"
const ALGO_ED25519 = 0x01;
const OP_JOIN = 0x00;
const OP_EXIT = 0x01;

// Deterministic seed: 0x42 * 32
const seed = new Uint8Array(32).fill(0x42);
const pubkey = await ed25519PublicFromSeed(seed);

// addr32 = SHA-512(algo_id || pubkey)[0..31] per MXD-01 §4
const addrInput = new Uint8Array(1 + pubkey.length);
addrInput[0] = ALGO_ED25519;
addrInput.set(pubkey, 1);
const addr32 = sha512(addrInput).slice(0, 32);

// Fixed timestamp (2026-01-27 00:00:00 UTC, ms since epoch)
const timestamp_ms = 1737936000000;

function buildCanonical(op_type) {
  const buf = new Uint8Array(DOMAIN_VAL.length + 1 + 32 + 8);
  let o = 0;
  buf.set(DOMAIN_VAL, o); o += DOMAIN_VAL.length;
  buf[o++] = op_type;
  buf.set(addr32, o); o += 32;
  buf.set(u64be(timestamp_ms), o);
  return buf;
}

const joinCanonical = buildCanonical(OP_JOIN);
const exitCanonical = buildCanonical(OP_EXIT);

const joinSig = await ed25519Sign(seed, joinCanonical);
const exitSig = await ed25519Sign(seed, exitCanonical);

// Reproduce the MXD_MSG_VALIDATOR_JOIN_REQUEST wire payload per
// mxd_serialize_join_request (mxd_validator_management.c:597).
//   algo_id(1) | addr32(32) | pk_len_be(2) | pubkey | stake_be(8) | ts_be(8) | sig_len_be(2) | sig
const stake = 60_500_000n; // 0.605 MXD in base units
function buildWire(op_type, sig) {
  const parts = [];
  parts.push(new Uint8Array([ALGO_ED25519]));
  parts.push(addr32);
  parts.push(new Uint8Array([0, pubkey.length]));
  parts.push(pubkey);
  parts.push(u64be(stake));
  parts.push(u64be(timestamp_ms));
  parts.push(new Uint8Array([0, sig.length]));
  parts.push(sig);
  // op_type is NOT on the wire — receiver knows from message type
  const total = parts.reduce((s, p) => s + p.length, 0);
  void op_type;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const joinWire = buildWire(OP_JOIN, joinSig);

const verifyJoin = await ed25519Verify(pubkey, joinCanonical, joinSig);
const verifyExit = await ed25519Verify(pubkey, exitCanonical, exitSig);
const crossJoinAsExit = await ed25519Verify(pubkey, exitCanonical, joinSig);

const vectors = {
  spec: 'MXD-CONS-01 v1.1.0',
  generator: 'gen_mxd_cons01_vectors.mjs',
  constants: {
    domain_tag_hex: hex(DOMAIN_VAL),
    domain_tag_ascii: 'MXD-VAL-V1\\0',
    op_type_join: '0x00',
    op_type_exit_deprecated: '0x01',
    op_type_evict_reserved: '0x02 (Phase 3, not yet specified)',
    algo_id_ed25519: '0x01',
    ed25519_pubkey_len: 32,
    ed25519_sig_len: 64,
    canonical_signed_bytes_total: 52,
    timestamp_units: 'milliseconds since Unix epoch, big-endian u64'
  },
  fixtures: {
    seed_hex: hex(seed),
    pubkey_hex: hex(pubkey),
    addr32_hex: hex(addr32),
    timestamp_ms,
    stake_base_units: stake.toString()
  },
  vectors: [
    {
      name: 'validator_join_ed25519',
      description: '52-byte JOIN canonical bytes signed with deterministic Ed25519 keypair (seed=0x42×32). Verifies as JOIN; MUST fail verification as EXIT.',
      canonical_signed_bytes_hex: hex(joinCanonical),
      canonical_signed_bytes_breakdown: {
        domain_tag_11: hex(joinCanonical.slice(0, 11)),
        op_type_1: hex(joinCanonical.slice(11, 12)),
        addr32_32: hex(joinCanonical.slice(12, 44)),
        timestamp_be_8: hex(joinCanonical.slice(44, 52))
      },
      signature_hex: hex(joinSig),
      verify_join_expected: true,
      verify_join_actual: verifyJoin,
      gossip_wire_payload_hex: hex(joinWire),
      gossip_wire_payload_breakdown: {
        algo_id_1: '01',
        addr32_32: hex(addr32),
        pubkey_len_be_2: '0020',
        pubkey_32: hex(pubkey),
        stake_be_8: hex(u64be(stake)),
        timestamp_be_8: hex(u64be(timestamp_ms)),
        sig_len_be_2: '0040',
        sig_64: hex(joinSig)
      },
      gossip_wire_payload_length: joinWire.length
    },
    {
      name: 'validator_exit_ed25519_deprecated',
      description: 'EXIT canonical bytes (op_type=0x01). DEPRECATED in v1.1.0 — self-driven exits are no longer accepted by Phase 1+2+4 code; EVICT (op_type=0x02, Phase 3) replaces this path. Included only for cross-replay vector below.',
      canonical_signed_bytes_hex: hex(exitCanonical),
      signature_hex: hex(exitSig),
      verify_exit_expected: true,
      verify_exit_actual: verifyExit
    },
    {
      name: 'cross_replay_join_sig_as_exit_negative',
      description: 'A JOIN signature MUST NOT verify when presented against EXIT canonical bytes. This is the load-bearing op_type defense.',
      canonical_bytes_under_test_hex: hex(exitCanonical),
      signature_under_test_hex: hex(joinSig),
      verify_expected: false,
      verify_actual: crossJoinAsExit
    }
  ]
};

console.log(JSON.stringify(vectors, null, 2));
