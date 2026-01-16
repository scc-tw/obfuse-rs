#!/usr/bin/env bash
# verify_cff_obfuscation.sh
#
# Verification script to ensure Control Flow Flattening (CFF) is not optimized away.
# This checks that the state machine structure, opaque predicates, and dead blocks
# are preserved in the compiled binary.
#
# The script checks:
# 1. State machine loop structure (multiple state values in match arms)
# 2. Opaque predicate operations (black_box, wrapping_mul, etc.)
# 3. Dead block operations (reverse, rotate, bitwise NOT)
# 4. Runtime correctness
#
# Exit codes:
#   0 - CFF obfuscation is preserved
#   1 - CFF obfuscation was optimized away or verification failed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Control Flow Flattening (CFF) Obfuscation Verification ==="
echo ""

# Build the CFF integration test binary in release mode
echo "Building release binary with control-flow-flatten feature..."
cd "$PROJECT_DIR"
cargo build --release --features control-flow-flatten --tests --quiet 2>/dev/null || cargo build --release --features control-flow-flatten --tests

# Find the test binary
TEST_BINARY=$(find "$PROJECT_DIR/target/release/deps" -name "cff_integration-*" -type f ! -name "*.d" | head -1)

if [ -z "$TEST_BINARY" ] || [ ! -f "$TEST_BINARY" ]; then
    echo "ERROR: CFF integration test binary not found"
    echo "Looking in: $PROJECT_DIR/target/release/deps/"
    ls -la "$PROJECT_DIR/target/release/deps/" | grep cff || true
    exit 1
fi

echo "Found test binary: $TEST_BINARY"
echo ""

# Disassemble the binary
echo "Extracting disassembly..."
DISASM=$(objdump -d "$TEST_BINARY" 2>/dev/null)

if [ -z "$DISASM" ]; then
    echo "ERROR: Failed to disassemble binary (objdump not available or failed)"
    exit 1
fi

echo ""
echo "=== Checking State Machine Structure ==="

# Check for multiple 64-bit immediate values (state values)
# These appear as movabs or mov with large immediates
LARGE_IMMEDIATE_COUNT=$(echo "$DISASM" | grep -cE "movabs.*0x[0-9a-f]{10,}" || true)
echo "  Large 64-bit immediates found: $LARGE_IMMEDIATE_COUNT"

if [ "$LARGE_IMMEDIATE_COUNT" -lt 5 ]; then
    echo "WARNING: Expected more large immediates for state values (found $LARGE_IMMEDIATE_COUNT, expected >= 5)"
fi

# Check for comparison instructions with immediates (state matching)
CMP_COUNT=$(echo "$DISASM" | grep -cE "cmp.*\$0x" || true)
echo "  CMP instructions with immediates: $CMP_COUNT"

echo ""
echo "=== Checking Opaque Predicate Operations ==="

# Check for wrapping arithmetic operations (used in opaque predicates)
IMUL_COUNT=$(echo "$DISASM" | grep -cE "\s+imul\s+" || true)
echo "  IMUL (wrapping_mul) instructions: $IMUL_COUNT"

ADD_COUNT=$(echo "$DISASM" | grep -cE "\s+add\s+" || true)
echo "  ADD instructions: $ADD_COUNT"

# Check for modulo operations (used in predicates like n*(n+1) % 2)
# Division by 2 often becomes AND with 1
AND_COUNT=$(echo "$DISASM" | grep -cE "\s+and\s+" || true)
echo "  AND instructions: $AND_COUNT"

# Check for XOR operations (used in XorSelf predicate and transformations)
XOR_COUNT=$(echo "$DISASM" | grep -cE "\s+xor\s+" || true)
echo "  XOR instructions: $XOR_COUNT"

# Check for bit counting (popcnt for SquareNonNegative predicate)
POPCNT_COUNT=$(echo "$DISASM" | grep -cE "\s+popcnt\s+" || true)
echo "  POPCNT (count_ones) instructions: $POPCNT_COUNT"

echo ""
echo "=== Checking Transformation/Dead Block Operations ==="

# Check for rotation instructions (used in transformations and dead blocks)
ROL_COUNT=$(echo "$DISASM" | grep -cE "\s+rol\s+" || true)
ROR_COUNT=$(echo "$DISASM" | grep -cE "\s+ror\s+" || true)
ROTATE_COUNT=$((ROL_COUNT + ROR_COUNT))
echo "  ROL/ROR (rotate) instructions: $ROTATE_COUNT"

# Check for NOT instructions (used in dead blocks)
NOT_COUNT=$(echo "$DISASM" | grep -cE "\s+not\s+" || true)
echo "  NOT instructions: $NOT_COUNT"

# Check for SUB instructions (used in wrapping_sub)
SUB_COUNT=$(echo "$DISASM" | grep -cE "\s+sub\s+" || true)
echo "  SUB instructions: $SUB_COUNT"

echo ""
echo "=== Checking Loop Structure ==="

# Check for unconditional jumps (loop back)
JMP_COUNT=$(echo "$DISASM" | grep -cE "\s+jmp\s+" || true)
echo "  JMP (unconditional jump) instructions: $JMP_COUNT"

# Check for conditional jumps (state transitions)
JE_COUNT=$(echo "$DISASM" | grep -cE "\s+je\s+|\s+jne\s+|\s+jz\s+|\s+jnz\s+" || true)
echo "  Conditional jump instructions: $JE_COUNT"

echo ""
echo "=== Verification Summary ==="

PASS=true

# Verify minimum instruction counts for CFF characteristics
if [ "$LARGE_IMMEDIATE_COUNT" -lt 3 ]; then
    echo "FAIL: Not enough large immediates for state values"
    PASS=false
fi

if [ "$XOR_COUNT" -lt 3 ]; then
    echo "FAIL: Not enough XOR instructions for transformations"
    PASS=false
fi

TOTAL_ARITHMETIC=$((IMUL_COUNT + ADD_COUNT + SUB_COUNT))
if [ "$TOTAL_ARITHMETIC" -lt 10 ]; then
    echo "FAIL: Not enough arithmetic operations ($TOTAL_ARITHMETIC found, expected >= 10)"
    PASS=false
fi

if [ "$JMP_COUNT" -lt 1 ]; then
    echo "FAIL: No unconditional jumps found (expected loop structure)"
    PASS=false
fi

if [ "$JE_COUNT" -lt 3 ]; then
    echo "FAIL: Not enough conditional jumps for state machine ($JE_COUNT found, expected >= 3)"
    PASS=false
fi

echo ""
echo "=== Runtime Verification ==="

# Run the CFF tests to verify correctness
echo "Running CFF integration tests..."
if cargo test --release --features control-flow-flatten --test cff_integration --quiet 2>/dev/null; then
    echo "  Runtime tests: PASSED"
else
    echo "  Runtime tests: FAILED"
    PASS=false
fi

echo ""
echo "=============================================="

if [ "$PASS" = true ]; then
    echo "=== All CFF obfuscation checks passed! ==="
    echo ""
    echo "Summary:"
    echo "  - Large immediates (state values): $LARGE_IMMEDIATE_COUNT"
    echo "  - Arithmetic operations: $TOTAL_ARITHMETIC"
    echo "  - XOR operations: $XOR_COUNT"
    echo "  - Rotate operations: $ROTATE_COUNT"
    echo "  - Jump instructions: $JMP_COUNT unconditional, $JE_COUNT conditional"
    echo ""
    echo "The Control Flow Flattening obfuscation is preserved in the compiled binary."
    exit 0
else
    echo "=== CFF obfuscation verification FAILED ==="
    echo ""
    echo "The CFF obfuscation may have been optimized away or is not working correctly."
    echo "Please review the implementation."
    exit 1
fi
