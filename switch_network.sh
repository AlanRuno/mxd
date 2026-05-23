#!/bin/bash


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-default_config.json}"
NETWORK_TYPE="${2:-testnet}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo -e "${BLUE}Usage: $0 [config_file] [network_type]${NC}"
    echo ""
    echo "Arguments:"
    echo "  config_file   - Path to config file (default: default_config.json)"
    echo "  network_type  - 'testnet' or 'mainnet' (default: testnet)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Switch default_config.json to testnet"
    echo "  $0 node.json mainnet           # Switch node.json to mainnet"
    echo "  $0 custom.json testnet         # Switch custom.json to testnet"
    echo ""
}

if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    print_usage
    exit 0
fi

if [[ "$NETWORK_TYPE" != "testnet" ]] && [[ "$NETWORK_TYPE" != "mainnet" ]]; then
    echo -e "${RED}Error: network_type must be 'testnet' or 'mainnet'${NC}"
    print_usage
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}  MXD Network Switcher${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo ""
echo -e "Config file:   ${GREEN}$CONFIG_FILE${NC}"
echo -e "Target network: ${GREEN}$NETWORK_TYPE${NC}"
echo ""

if [[ "$NETWORK_TYPE" == "mainnet" ]]; then
    NETWORK_MAGIC="0x4D584431"  # "MXD1" in hex
    BOOTSTRAP_NODES='["node1.mxd.network:8000", "node2.mxd.network:8000"]'
    echo -e "${YELLOW}⚠ Switching to MAINNET - will connect to production network${NC}"
else
    NETWORK_MAGIC="0x54455354"  # "TEST" in hex
    BOOTSTRAP_NODES='["127.0.0.1:8001", "127.0.0.1:8002"]'
    echo -e "${GREEN}✓ Switching to TESTNET - will connect to test network${NC}"
fi

echo ""

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${YELLOW}Config file not found. Creating new config file...${NC}"
    
    NODE_ID="node_$(date +%s)"
    
    cat > "$CONFIG_FILE" <<EOF
{
    "node_id": "$NODE_ID",
    "network_type": "$NETWORK_TYPE",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Node",
    "initial_stake": 100.0,
    "metrics_interval": 1000,
    "metrics_port": 8080,
    "bootstrap_nodes": $BOOTSTRAP_NODES
}
EOF
    
    echo -e "${GREEN}✓ Created new config file: $CONFIG_FILE${NC}"
else
    echo -e "Updating existing config file..."
    
    TEMP_FILE=$(mktemp)
    
    if command -v python3 &> /dev/null; then
        python3 << EOF
import json
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    config['network_type'] = '$NETWORK_TYPE'
    config['bootstrap_nodes'] = $BOOTSTRAP_NODES
    
    with open('$TEMP_FILE', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("${GREEN}✓ Updated config file${NC}")
except Exception as e:
    print("${RED}Error updating config: " + str(e) + "${NC}")
    sys.exit(1)
EOF
        
        if [[ $? -eq 0 ]]; then
            mv "$TEMP_FILE" "$CONFIG_FILE"
        else
            rm -f "$TEMP_FILE"
            exit 1
        fi
    else
        sed -i.bak "s/\"network_type\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"network_type\": \"$NETWORK_TYPE\"/" "$CONFIG_FILE"
        echo -e "${GREEN}✓ Updated network_type in config${NC}"
        echo -e "${YELLOW}⚠ Warning: Bootstrap nodes not updated (Python not available). Please update manually.${NC}"
    fi
fi

echo ""
echo -e "${BLUE}─── Environment Variables ───${NC}"
echo ""
echo -e "Setting ${GREEN}MXD_NETWORK_MAGIC${NC} environment variable..."
echo ""

ENV_FILE="$SCRIPT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
    if grep -q "^MXD_NETWORK_MAGIC=" "$ENV_FILE"; then
        sed -i.bak "s/^MXD_NETWORK_MAGIC=.*/MXD_NETWORK_MAGIC=$NETWORK_MAGIC/" "$ENV_FILE"
    else
        echo "MXD_NETWORK_MAGIC=$NETWORK_MAGIC" >> "$ENV_FILE"
    fi
else
    echo "MXD_NETWORK_MAGIC=$NETWORK_MAGIC" > "$ENV_FILE"
fi

echo -e "${GREEN}✓ Updated .env file${NC}"
echo ""

echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Network switch complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo -e "1. Load environment variables:"
echo -e "   ${GREEN}source .env${NC}"
echo ""
echo -e "2. Start your node:"
echo -e "   ${GREEN}./mxd_node $CONFIG_FILE${NC}"
echo ""
echo -e "Current settings:"
echo -e "  • Network type:  ${GREEN}$NETWORK_TYPE${NC}"
echo -e "  • Network magic: ${GREEN}$NETWORK_MAGIC${NC}"
echo -e "  • Config file:   ${GREEN}$CONFIG_FILE${NC}"
echo ""

if [[ "$NETWORK_TYPE" == "mainnet" ]]; then
    echo -e "${RED}⚠⚠⚠ WARNING ⚠⚠⚠${NC}"
    echo -e "${RED}You are configured for MAINNET. This will connect to the production network.${NC}"
    echo -e "${RED}Make sure this is intentional!${NC}"
    echo ""
fi

echo -e "To export the environment variable for this session:"
echo -e "${GREEN}export MXD_NETWORK_MAGIC=$NETWORK_MAGIC${NC}"
echo ""
