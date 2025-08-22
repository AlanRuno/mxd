#!/bin/bash

set -e

TEST_TYPE="transaction"
TARGET_TPS=50
DURATION=60
PEERS=10
VALIDATORS=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            TEST_TYPE="$2"
            shift 2
            ;;
        --tps)
            TARGET_TPS="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --peers)
            PEERS="$2"
            shift 2
            ;;
        --validators)
            VALIDATORS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Starting MXD Load Test"
echo "Type: $TEST_TYPE"
echo "Target TPS: $TARGET_TPS"
echo "Duration: ${DURATION}s"
echo "========================"

if [ ! -f "build/lib/mxd_enterprise_features_tests" ]; then
    echo "Building MXD library..."
    mkdir -p build
    cd build
    cmake ..
    make -j$(nproc)
    cd ..
fi

case $TEST_TYPE in
    "transaction")
        echo "Running transaction load test..."
        ./build/lib/mxd_enterprise_features_tests --test-type transaction --tps $TARGET_TPS --duration $DURATION
        ;;
    "network")
        echo "Running network load test..."
        ./build/lib/mxd_enterprise_features_tests --test-type network --peers $PEERS --duration $DURATION
        ;;
    "consensus")
        echo "Running consensus load test..."
        ./build/lib/mxd_enterprise_features_tests --test-type consensus --validators $VALIDATORS --duration $DURATION
        ;;
    *)
        echo "Unknown test type: $TEST_TYPE"
        echo "Available types: transaction, network, consensus"
        exit 1
        ;;
esac

echo "Load test completed!"
