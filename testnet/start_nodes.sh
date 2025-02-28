#!/bin/bash

# Kill any existing nodes
pkill -f mxd_dht_tests || true
sleep 2

# Function to wait for node initialization
wait_for_node() {
    local node_dir=$1
    local pid=$2
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if ! ps -p $pid > /dev/null; then
            echo "Node process $pid died. Check $node_dir/node.log"
            return 1
        fi
        
        if grep -q "DHT service started on port" "$node_dir/node.log" 2>/dev/null; then
            echo "Node in $node_dir initialized successfully"
            return 0
        fi
        
        echo "Waiting for node initialization... ($((attempt + 1))/$max_attempts)"
        sleep 1
        attempt=$((attempt + 1))
    done
    
    echo "Node initialization timed out"
    return 1
}

# Start bootstrap node
echo "Starting bootstrap node..."
cd node0
rm -f node.log
../../build/lib/mxd_dht_tests --network --config config.json > node.log 2>&1 &
BOOTSTRAP_PID=$!
cd ..
echo "Bootstrap node started with PID $BOOTSTRAP_PID"

# Wait for bootstrap node
if ! wait_for_node "node0" $BOOTSTRAP_PID; then
    exit 1
fi

# Start node1
echo "Starting node1..."
cd node1
rm -f node.log
../../build/lib/mxd_dht_tests --network --config config.json > node.log 2>&1 &
NODE1_PID=$!
cd ..
echo "Node1 started with PID $NODE1_PID"

# Wait for node1
if ! wait_for_node "node1" $NODE1_PID; then
    exit 1
fi

# Start node2
echo "Starting node2..."
cd node2
rm -f node.log
../../build/lib/mxd_dht_tests --network --config config.json > node.log 2>&1 &
NODE2_PID=$!
cd ..
echo "Node2 started with PID $NODE2_PID"

# Wait for node2
if ! wait_for_node "node2" $NODE2_PID; then
    exit 1
fi

echo "All nodes started successfully. Checking status..."
ps aux | grep mxd_dht_tests | grep -v grep

echo -e "\nNode logs:"
for node in node{0,1,2}; do
    echo -e "\n=== $node log ==="
    tail -n 20 $node/node.log
done
