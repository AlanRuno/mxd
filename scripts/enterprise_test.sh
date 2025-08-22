#!/bin/bash

set -e

echo "Running MXD Enterprise Features Test Suite"
echo "=========================================="

cd "$(dirname "$0")/.."

if [ ! -f "build/Makefile" ]; then
    echo "Installing dependencies..."
    ./install_dependencies.sh
fi

echo "Building MXD library..."
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

echo "Running enterprise features tests..."
if [ -f "build/lib/mxd_enterprise_features_tests" ]; then
    ./build/lib/mxd_enterprise_features_tests
else
    echo "Enterprise features tests not found, building..."
    cd build
    make mxd_enterprise_features_tests
    cd ..
    ./build/lib/mxd_enterprise_features_tests
fi

echo "Running load testing framework..."
./scripts/load_test.sh --type transaction --tps 25 --duration 10
./scripts/load_test.sh --type network --peers 5 --duration 10

echo "Testing backup functionality..."
mkdir -p /tmp/mxd_test_data
echo "test blockchain data" > /tmp/mxd_test_data/blockchain.db

export MXD_BACKUP_DIR="/tmp/mxd_test_backups"
export MXD_DATA_DIR="/tmp/mxd_test_data"
export MXD_BACKUP_RETENTION="1"

./scripts/backup.sh

if [ -f "/tmp/mxd_test_backups/mxd_backup_"*.tar.gz ]; then
    echo "✓ Backup creation successful"
    
    BACKUP_FILE=$(ls /tmp/mxd_test_backups/mxd_backup_*.tar.gz | head -1)
    ./scripts/verify_backup.sh "$BACKUP_FILE"
    echo "✓ Backup verification successful"
    
    ./scripts/restore.sh "$BACKUP_FILE" "/tmp/mxd_restored_data"
    echo "✓ Backup restoration successful"
else
    echo "✗ Backup creation failed"
    exit 1
fi

rm -rf /tmp/mxd_test_data /tmp/mxd_test_backups /tmp/mxd_restored_data

echo ""
echo "✓ All enterprise features tests passed!"
echo "Enterprise production readiness implementation completed successfully."
