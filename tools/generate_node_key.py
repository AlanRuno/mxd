#!/usr/bin/env python3
"""
Generate MXD node_keys.v2 file with a fresh Ed25519 keypair.

Usage:
    python3 generate_node_key.py                  # prints to stdout (binary)
    python3 generate_node_key.py --out node_keys.v2  # writes to file
    python3 generate_node_key.py --info            # prints key info (hex)

Format (106 bytes):
    "MXDK" (4) | version=2 (1) | algo_id=1 (1) | pubkey_len BE (2) | privkey_len BE (2) | pubkey (32) | privkey (64)
"""

import sys
import struct
import hashlib
import os

try:
    from nacl.signing import SigningKey
    USE_NACL = True
except ImportError:
    USE_NACL = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    USE_CRYPTOGRAPHY = True
except ImportError:
    USE_CRYPTOGRAPHY = False


def generate_keypair():
    """Generate Ed25519 keypair, returns (public_key_32, private_key_64)"""
    if USE_NACL:
        sk = SigningKey.generate()
        privkey_seed = bytes(sk)  # 32-byte seed
        pubkey = bytes(sk.verify_key)  # 32 bytes
        # Ed25519 "private key" in NaCl is seed(32) + pubkey(32) = 64 bytes
        privkey = privkey_seed + pubkey
        return pubkey, privkey
    elif USE_CRYPTOGRAPHY:
        sk = Ed25519PrivateKey.generate()
        pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Raw private key from cryptography is 32-byte seed
        privkey_seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        # MXD expects 64-byte private key: seed(32) + pubkey(32)
        privkey = privkey_seed + pubkey
        return pubkey, privkey
    else:
        print("ERROR: Install 'pynacl' or 'cryptography' package:", file=sys.stderr)
        print("  pip install pynacl", file=sys.stderr)
        print("  pip install cryptography", file=sys.stderr)
        sys.exit(1)


def build_keyfile(pubkey, privkey):
    """Build node_keys.v2 binary data"""
    magic = b"MXDK"
    version = struct.pack("B", 2)
    algo_id = struct.pack("B", 1)  # Ed25519
    pubkey_len = struct.pack("!H", len(pubkey))   # big-endian uint16
    privkey_len = struct.pack("!H", len(privkey))  # big-endian uint16
    return magic + version + algo_id + pubkey_len + privkey_len + pubkey + privkey


def derive_address(algo_id, pubkey):
    """Derive MXD addr32 per MXD-01 v1.1.x §4: SHA-512(algo_id || pubkey)[0..31]"""
    data = bytes([algo_id]) + pubkey
    return hashlib.sha512(data).digest()[:32]


def main():
    info_mode = "--info" in sys.argv
    out_file = None
    if "--out" in sys.argv:
        idx = sys.argv.index("--out")
        if idx + 1 < len(sys.argv):
            out_file = sys.argv[idx + 1]

    pubkey, privkey = generate_keypair()
    keyfile_data = build_keyfile(pubkey, privkey)

    assert len(keyfile_data) == 106, f"Expected 106 bytes, got {len(keyfile_data)}"

    if info_mode:
        address = derive_address(1, pubkey)
        print(f"Algorithm:   Ed25519 (algo_id=1)")
        print(f"Public key:  {pubkey.hex()}")
        print(f"Address:     {address.hex()}")
        print(f"File size:   {len(keyfile_data)} bytes")
        print()
        print("DO NOT share the private key or this file contents.")
        print(f"To save: python3 {sys.argv[0]} --out node_keys.v2")
    elif out_file:
        with open(out_file, "wb") as f:
            f.write(keyfile_data)
        os.chmod(out_file, 0o600)
        address = derive_address(1, pubkey)
        print(f"Key written to {out_file} (106 bytes)", file=sys.stderr)
        print(f"Address: {address.hex()}", file=sys.stderr)
    else:
        # Binary output to stdout (for piping to Secret Manager)
        sys.stdout.buffer.write(keyfile_data)


if __name__ == "__main__":
    main()
