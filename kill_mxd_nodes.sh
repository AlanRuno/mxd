#!/bin/bash


echo "Searching for mxd_node processes..."

PIDS=$(pgrep -f "mxd_node" 2>/dev/null)

if [ -z "$PIDS" ]; then
    echo "No mxd_node processes found."
    exit 0
fi

echo "Found mxd_node processes:"
ps aux | grep "[m]xd_node"

echo ""
echo "Killing processes..."

for PID in $PIDS; do
    echo "Killing PID $PID..."
    kill -9 $PID 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✓ Successfully killed PID $PID"
    else
        echo "  ✗ Failed to kill PID $PID (may require sudo)"
    fi
done

echo ""
echo "Verifying all processes are killed..."
sleep 1

REMAINING=$(pgrep -f "mxd_node" 2>/dev/null)
if [ -z "$REMAINING" ]; then
    echo "✓ All mxd_node processes have been killed."
else
    echo "⚠ Some processes are still running:"
    ps aux | grep "[m]xd_node"
    echo ""
    echo "You may need to run this script with sudo:"
    echo "  sudo ./kill_mxd_nodes.sh"
fi
