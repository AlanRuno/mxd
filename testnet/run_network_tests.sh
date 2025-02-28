#!/bin/bash

# Start bootstrap node
echo "Starting bootstrap node..."
cd node0
../build/lib/mxd_dht_tests --config config.json &
BOOTSTRAP_PID=$!
sleep 5  # Wait for bootstrap node initialization

# Start node1
echo "Starting node1..."
cd ../node1
../build/lib/mxd_dht_tests --config config.json &
NODE1_PID=$!
sleep 5

# Start node2
echo "Starting node2..."
cd ../node2
../build/lib/mxd_dht_tests --config config.json &
NODE2_PID=$!
sleep 5

# Run P2P tests
echo "Running P2P tests..."
../build/lib/mxd_p2p_tests --network

# Cleanup
kill $BOOTSTRAP_PID $NODE1_PID $NODE2_PID
