#!/bin/bash
#
# Run Valgrind memory analysis
# More thorough than ASan but slower
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
BUILD_DIR="$PROJECT_ROOT/build-valgrind"

echo "MXD Valgrind Memory Analysis"
echo "============================"
echo ""

# Check if valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo "ERROR: valgrind is not installed"
    echo "Install with: sudo apt-get install valgrind"
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Compile with debug symbols
echo "Compiling with debug symbols..."
cmake "$PROJECT_ROOT" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0" \
    &> /dev/null

make -j$(nproc) &> /dev/null || {
    echo "ERROR: Compilation failed"
    exit 1
}

# Run valgrind tests
echo ""
echo "Running Valgrind tests..."
echo ""

# Test 1: Memory leak check
echo "1. Memory Leak Detection"
echo "   (This may take a few minutes...)"
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --verbose \
    --log-file=valgrind-leak.txt \
    ./test_security

if grep -q "ERROR SUMMARY: 0 errors" valgrind-leak.txt && \
   grep -q "definitely lost: 0 bytes" valgrind-leak.txt; then
    echo "   ✓ No memory leaks detected"
else
    echo "   ✗ Memory leaks found!"
    echo "   See: $BUILD_DIR/valgrind-leak.txt"
    grep "definitely lost" valgrind-leak.txt | head -n 5
fi

# Test 2: Invalid memory access
echo ""
echo "2. Invalid Memory Access Detection"
valgrind \
    --tool=memcheck \
    --read-var-info=yes \
    --track-origins=yes \
    --log-file=valgrind-memcheck.txt \
    ./test_security &> /dev/null

if grep -q "ERROR SUMMARY: 0 errors" valgrind-memcheck.txt; then
    echo "   ✓ No invalid memory access detected"
else
    echo "   ✗ Invalid memory access found!"
    echo "   See: $BUILD_DIR/valgrind-memcheck.txt"
    grep "Invalid " valgrind-memcheck.txt | head -n 5
fi

# Test 3: Callgrind (performance profiling)
echo ""
echo "3. Performance Profiling (Callgrind)"
echo "   (Analyzing hotspots...)"
valgrind \
    --tool=callgrind \
    --callgrind-out-file=callgrind.out \
    ./test_security &> /dev/null

echo "   ✓ Profiling complete"
echo "   Analyze with: kcachegrind callgrind.out"

# Test 4: Cachegrind (cache profiling)
echo ""
echo "4. Cache Profiling (Cachegrind)"
valgrind \
    --tool=cachegrind \
    --cachegrind-out-file=cachegrind.out \
    ./test_security &> /dev/null

echo "   ✓ Cache analysis complete"
echo "   Analyze with: cg_annotate cachegrind.out"

# Summary
echo ""
echo "============================"
echo "Valgrind analysis complete!"
echo ""
echo "Reports generated:"
echo "  Memory leaks:     $BUILD_DIR/valgrind-leak.txt"
echo "  Memory access:    $BUILD_DIR/valgrind-memcheck.txt"
echo "  Performance:      $BUILD_DIR/callgrind.out"
echo "  Cache:            $BUILD_DIR/cachegrind.out"
echo ""
echo "To view detailed reports:"
echo "  less $BUILD_DIR/valgrind-leak.txt"
echo "  kcachegrind $BUILD_DIR/callgrind.out"
