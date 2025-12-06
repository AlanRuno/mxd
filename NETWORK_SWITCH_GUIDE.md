# MXD Network Switcher Guide

This guide explains how to use the `switch_network.sh` script to easily switch your MXD node between testnet and mainnet configurations.

## Quick Start

```bash
# Switch to testnet (default)
./switch_network.sh

# Switch to mainnet
./switch_network.sh default_config.json mainnet

# Switch a specific config file
./switch_network.sh my_node.json testnet
```

## What the Script Does

The script automatically configures three critical components for network isolation:

### 1. Network Type Configuration
Updates the `network_type` field in your JSON config file to either `"testnet"` or `"mainnet"`.

### 2. Network Magic Environment Variable
Sets `MXD_NETWORK_MAGIC` in a `.env` file:
- **Testnet**: `0x54455354` (hex for "TEST")
- **Mainnet**: `0x4D584431` (hex for "MXD1")

This is the **primary security mechanism** that prevents cross-network communication. Every P2P message is validated against this magic number.

### 3. Bootstrap Nodes
Automatically configures appropriate bootstrap nodes:
- **Testnet**: Local nodes (`127.0.0.1:8001`, `127.0.0.1:8002`)
- **Mainnet**: Production nodes (`node1.mxd.network:8000`, `node2.mxd.network:8000`)

## Usage Examples

### Example 1: First-time Setup (Testnet)
```bash
# Create and configure for testnet
./switch_network.sh my_testnet_node.json testnet

# Load environment variables
source .env

# Start your node
./mxd_node my_testnet_node.json
```

### Example 2: Switch Existing Node to Mainnet
```bash
# Switch to mainnet
./switch_network.sh production_node.json mainnet

# Load environment variables
source .env

# Start your node (connects to production network!)
./mxd_node production_node.json
```

### Example 3: Multiple Test Nodes
```bash
# Create testnet bootstrap node
./switch_network.sh testnet_bootstrap.json testnet
# Edit the config to set port 8000 and empty bootstrap_nodes

# Create testnet node 1
./switch_network.sh testnet_node1.json testnet
# Edit the config to set port 8001

# Create testnet node 2
./switch_network.sh testnet_node2.json testnet
# Edit the config to set port 8002

# Load env and start all nodes
source .env
./mxd_node testnet_bootstrap.json &
./mxd_node testnet_node1.json &
./mxd_node testnet_node2.json &
```

## Command-Line Options

```
Usage: ./switch_network.sh [config_file] [network_type]

Arguments:
  config_file   - Path to config file (default: default_config.json)
  network_type  - 'testnet' or 'mainnet' (default: testnet)
```

## Security Guarantees

When you switch networks using this script, you get **complete network isolation**:

1. ✅ **Message-level isolation**: All P2P messages include the network magic and are validated. Messages from different networks are automatically rejected.

2. ✅ **Bootstrap isolation**: Different networks use different bootstrap nodes, creating separate DHT networks.

3. ✅ **Configuration validation**: The node validates that `network_type` is either "testnet" or "mainnet" on startup.

**Result**: Testnet nodes CANNOT communicate with mainnet nodes, even if they try.

## Environment Variables

The script creates/updates a `.env` file with:
```bash
MXD_NETWORK_MAGIC=0x54455354  # or 0x4D584431 for mainnet
```

**Important**: You must load this file before starting your node:
```bash
source .env
```

Or export it manually:
```bash
export MXD_NETWORK_MAGIC=0x54455354
```

## Configuration File Format

The script creates/updates JSON config files with this structure:

### Testnet Config
```json
{
    "node_id": "node_1234567890",
    "network_type": "testnet",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Node",
    "initial_stake": 100.0,
    "metrics_interval": 1000,
    "metrics_port": 8080,
    "bootstrap_nodes": ["127.0.0.1:8001", "127.0.0.1:8002"]
}
```

### Mainnet Config
```json
{
    "node_id": "node_1234567890",
    "network_type": "mainnet",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Node",
    "initial_stake": 100.0,
    "metrics_interval": 1000,
    "metrics_port": 8080,
    "bootstrap_nodes": ["node1.mxd.network:8000", "node2.mxd.network:8000"]
}
```

## Advanced Usage

### Custom Bootstrap Nodes
After running the script, you can manually edit the config file to add custom bootstrap nodes:

```json
{
    "bootstrap_nodes": [
        "my-bootstrap.example.com:8000",
        "backup-bootstrap.example.com:8000"
    ]
}
```

### Multiple Network Environments
You can maintain separate config files for different environments:

```bash
# Development testnet
./switch_network.sh dev-testnet.json testnet

# Staging testnet
./switch_network.sh staging-testnet.json testnet

# Production mainnet
./switch_network.sh production.json mainnet
```

## Troubleshooting

### Issue: Node connects to wrong network
**Solution**: Make sure you ran `source .env` or exported `MXD_NETWORK_MAGIC` before starting the node.

### Issue: Cannot connect to bootstrap nodes
**Solution**: 
- For testnet: Make sure your bootstrap nodes are running locally
- For mainnet: Check your internet connection and firewall settings

### Issue: Script says "Python not available"
**Solution**: The script will still update `network_type` using sed, but bootstrap nodes won't be updated. Install Python 3 or manually edit the bootstrap_nodes in your config file.

## Related Documentation

- Main README: See `README.md` for general MXD documentation
- Network Architecture: See `docs/MODULES.md` for P2P and DHT details
- Configuration Reference: See `include/mxd_config.h` for all config options

## Safety Notes

⚠️ **Mainnet Warning**: When switching to mainnet, you will connect to the **production network**. Make sure:
- Your node is properly configured
- You understand the implications
- You have backed up any important data
- This is intentional and not a mistake

💡 **Recommendation**: Always test on testnet first before connecting to mainnet.
