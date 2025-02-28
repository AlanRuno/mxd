# DHT Implementation Documentation

## Overview
The Distributed Hash Table (DHT) implementation provides peer discovery and value storage capabilities for the MXD network. It uses a Kademlia-based routing algorithm with 160-bit node IDs derived from public keys.

## Features
1. Kademlia DHT Implementation
   - 160-bit node IDs (SHA-1 hash of public key)
   - k-bucket routing table (k=20)
   - XOR-based distance metric
   - Parallel lookups (α=3)

2. NAT Traversal Support
   - UDP hole punching
   - Active/passive node detection
   - Connection maintenance

3. Value Storage
   - Distributed key-value storage
   - 24-hour expiration
   - SHA-1 based key hashing

## Performance Impact
- Memory Usage:
  - Routing table: ~4KB per k-bucket
  - Node state: ~128 bytes per node
  - Value storage: Variable, with automatic pruning

- Network Traffic:
  - Lookup: O(log n) messages
  - Store: O(k) messages
  - Background refresh: ~1 message per bucket per hour

- CPU Usage:
  - Node ID calculation: Negligible (one-time SHA-1)
  - XOR distance: O(1)
  - Routing updates: O(log n)

## Whitepaper Requirements
This implementation satisfies the following requirements from the whitepaper:
1. "Decentralized peer discovery without central servers"
2. "Resilient network topology with redundant connections"
3. "NAT traversal for universal connectivity"
4. "Efficient value storage and retrieval"

## Integration
The DHT is integrated with:
1. P2P networking (mxd_p2p.c)
   - Automatic peer discovery
   - Connection management
   - Message routing

2. Cryptography (mxd_crypto.c)
   - Node ID generation
   - Message signing
   - Key derivation

## Future Improvements
1. IPv6 support
2. Enhanced security measures
   - Node ID verification
   - DoS protection
3. Value replication strategies
4. Geographic node clustering

## Testing
Comprehensive test suite in test_dht.c covers:
1. Node ID generation and routing
2. k-bucket management
3. Value storage and retrieval
4. NAT traversal
5. Network simulation
6. Performance benchmarks
