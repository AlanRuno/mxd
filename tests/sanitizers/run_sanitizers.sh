#!/bin/bash
#
# Run all sanitizer tests
# Tests for memory leaks, undefined behavior, race conditions, etc.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
BUILD_DIR="$PROJECT_ROOT/build-sanitizers"

echo "MXD Sanitizer Test Suite"
echo "========================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Function to run test with sanitizer
run_sanitizer_test() {
    local sanitizer=$1
    local test_name=$2
    local flags=$3

    echo -e "${YELLOW}Testing with $sanitizer...${NC}"

    # Clean build
    rm -rf sanitizer-$sanitizer
    mkdir -p sanitizer-$sanitizer
    cd sanitizer-$sanitizer

    # Compile with sanitizer
    echo "Compiling..."
    cmake "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fsanitize=$sanitizer $flags -g -O1" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=$sanitizer" \
        &> /dev/null

    make -j$(nproc) &> /dev/null || {
        echo -e "${RED}✗ Compilation failed with $sanitizer${NC}"
        cd ..
        return 1
    }

    # Run test
    echo "Running tests..."
    if ./$test_name > test_output.txt 2>&1; then
        echo -e "${GREEN}✓ $sanitizer: No issues found${NC}"
        cd ..
        return 0
    else
        echo -e "${RED}✗ $sanitizer: Issues detected!${NC}"
        echo "Last 20 lines of output:"
        tail -n 20 test_output.txt
        cd ..
        return 1
    fi
}

# Test 1: AddressSanitizer (memory errors)
echo ""
echo "1. AddressSanitizer (ASan)"
echo "   Detects: buffer overflows, use-after-free, double-free"
run_sanitizer_test "address" "test_security" "-fno-omit-frame-pointer"

# Test 2: UndefinedBehaviorSanitizer (undefined behavior)
echo ""
echo "2. UndefinedBehaviorSanitizer (UBSan)"
echo "   Detects: signed overflow, null pointer dereference, misaligned access"
run_sanitizer_test "undefined" "test_security" "-fno-sanitize-recover=undefined"

# Test 3: MemorySanitizer (uninitialized memory)
echo ""
echo "3. MemorySanitizer (MSan)"
echo "   Detects: use of uninitialized memory"
# Note: MSan requires all dependencies to be built with MSan
# Skip if dependencies aren't available
if command -v clang &> /dev/null; then
    echo "   (Requires MSan-instrumented dependencies - skipping)"
else
    run_sanitizer_test "memory" "test_security" "-fno-omit-frame-pointer"
fi

# Test 4: ThreadSanitizer (race conditions)
echo ""
echo "4. ThreadSanitizer (TSan)"
echo "   Detects: data races, deadlocks"
echo "   (Requires multi-threaded code - skipping for now)"

# Test 5: LeakSanitizer (memory leaks)
echo ""
echo "5. LeakSanitizer (LSan)"
echo "   Detects: memory leaks"
cd "$BUILD_DIR"
rm -rf sanitizer-leak
mkdir -p sanitizer-leak
cd sanitizer-leak

echo "Compiling..."
cmake "$PROJECT_ROOT" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=leak -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=leak" \
    &> /dev/null

make -j$(nproc) &> /dev/null || {
    echo -e "${RED}✗ Compilation failed with LeakSanitizer${NC}"
    cd ..
    exit 1
}

echo "Running tests..."
export LSAN_OPTIONS="suppressions=$SCRIPT_DIR/lsan.supp"
if ./test_security > test_output.txt 2>&1; then
    echo -e "${GREEN}✓ LeakSanitizer: No leaks detected${NC}"
else
    echo -e "${RED}✗ LeakSanitizer: Leaks detected!${NC}"
    echo "Last 20 lines of output:"
    tail -n 20 test_output.txt
fi

cd "$BUILD_DIR"

echo ""
echo "========================"
echo "Sanitizer tests complete!"
echo ""
echo "Summary:"
echo "  AddressSanitizer:  See output above"
echo "  UBSan:             See output above"
echo "  LeakSanitizer:     See output above"
echo ""
echo "For detailed results, check: $BUILD_DIR/sanitizer-*/test_output.txt"
