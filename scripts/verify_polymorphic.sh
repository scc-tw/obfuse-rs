#!/usr/bin/env bash
# Verification script to ensure polymorphic decryption is not optimized away
# This checks that transformation instructions are present in the compiled binary

set -e

echo "🔍 Polymorphic Decryption Verification Script"
echo "=============================================="
echo ""

# Build the polymorphic example in release mode (with optimizations)
echo "📦 Building release binary with polymorphic mode..."
cargo build --release --example polymorphic --features polymorphic --quiet

BINARY="target/release/examples/polymorphic"

if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found: $BINARY"
    exit 1
fi

echo "✅ Binary built successfully"
echo ""

# Check for transformation instructions in the disassembly
echo "🔬 Analyzing binary for transformation instructions..."
echo ""

# Disassemble the binary
DISASM=$(objdump -d "$BINARY" 2>/dev/null)

if [ -z "$DISASM" ]; then
    echo "❌ Failed to disassemble binary (objdump not available or failed)"
    exit 1
fi

# Check for XOR instructions
XOR_COUNT=$(echo "$DISASM" | grep -c "xor\s" || true)
echo "  XOR instructions found: $XOR_COUNT"

# Check for ADD instructions (wrapping_add)
ADD_COUNT=$(echo "$DISASM" | grep -c "add\s" || true)
echo "  ADD instructions found: $ADD_COUNT"

# Check for SUB instructions (wrapping_sub)
SUB_COUNT=$(echo "$DISASM" | grep -c "sub\s" || true)
echo "  SUB instructions found: $SUB_COUNT"

# Check for ROL instructions (rotate left)
ROL_COUNT=$(echo "$DISASM" | grep -c "rol\s" || true)
echo "  ROL (rotate left) instructions found: $ROL_COUNT"

# Check for ROR instructions (rotate right)
ROR_COUNT=$(echo "$DISASM" | grep -c "ror\s" || true)
echo "  ROR (rotate right) instructions found: $ROR_COUNT"

echo ""

# Verification criteria
PASS=true

if [ $XOR_COUNT -lt 5 ]; then
    echo "⚠️  Warning: Expected more XOR instructions (found $XOR_COUNT, expected >= 5)"
    PASS=false
fi

if [ $ADD_COUNT -lt 10 ]; then
    echo "⚠️  Warning: Expected more ADD instructions (found $ADD_COUNT, expected >= 10)"
    PASS=false
fi

if [ $SUB_COUNT -lt 5 ]; then
    echo "⚠️  Warning: Expected more SUB instructions (found $SUB_COUNT, expected >= 5)"
    PASS=false
fi

# Check for at least one rotate instruction (either ROL or ROR)
ROTATE_COUNT=$((ROL_COUNT + ROR_COUNT))
if [ $ROTATE_COUNT -lt 1 ]; then
    echo "❌ FAIL: No rotation instructions found (expected >= 1)"
    PASS=false
fi

echo ""
echo "🔍 Checking for key derivation code..."

# Check for CONSTANTS array pattern - look for sequences of constant bytes
CONST_PATTERN_COUNT=$(echo "$DISASM" | grep -c "movb.*,.*(%r" || true)
echo "  Constant loading patterns found: $CONST_PATTERN_COUNT"

if [ $CONST_PATTERN_COUNT -lt 10 ]; then
    echo "⚠️  Warning: Expected more constant loading patterns (found $CONST_PATTERN_COUNT, expected >= 10)"
    PASS=false
fi

echo ""
echo "🔍 Checking that no central decrypt function exists..."

# Check for decrypt symbols (should be 0 in polymorphic mode)
DECRYPT_SYMBOLS=$(nm "$BINARY" 2>/dev/null | grep -i "decrypt" || true)

if [ -n "$DECRYPT_SYMBOLS" ]; then
    echo "❌ FAIL: Found decrypt symbols in binary (should be none in polymorphic mode):"
    echo "$DECRYPT_SYMBOLS"
    PASS=false
else
    echo "✅ No central decrypt symbols found (as expected)"
fi

echo ""
echo "🔍 Verifying binary runs correctly..."

# Run the binary and check output
OUTPUT=$(cargo run --release --example polymorphic --features polymorphic --quiet 2>&1 | tail -3)
EXPECTED_PATTERNS=("sk_live_abc123" "P@ssw0rd!2024" "jwt_secret_xyz789")

for PATTERN in "${EXPECTED_PATTERNS[@]}"; do
    if echo "$OUTPUT" | grep -q "$PATTERN"; then
        echo "✅ Output contains expected pattern: $PATTERN"
    else
        echo "❌ FAIL: Output missing expected pattern: $PATTERN"
        PASS=false
    fi
done

echo ""
echo "=============================================="

if [ "$PASS" = true ]; then
    echo "✅ VERIFICATION PASSED"
    echo ""
    echo "Summary:"
    echo "  - Transformation instructions present in binary"
    echo "  - Key derivation code detected"
    echo "  - No central decrypt function found"
    echo "  - Runtime execution works correctly"
    echo ""
    echo "The polymorphic decryption is working as expected!"
    exit 0
else
    echo "❌ VERIFICATION FAILED"
    echo ""
    echo "The polymorphic decryption may have been optimized away or is not working correctly."
    echo "Please review the implementation."
    exit 1
fi
