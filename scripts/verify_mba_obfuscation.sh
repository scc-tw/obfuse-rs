#!/bin/bash
# verify_mba_obfuscation.sh
#
# This script verifies that the MBA (Mixed Boolean-Arithmetic) transformations
# are not optimized away by the compiler. It builds the library in release mode
# and checks the assembly output to ensure obfuscation is preserved.
#
# The script checks:
# 1. The mba_xor_deep function has a minimum number of instructions
# 2. The dummy constants (D1-D4) appear in the assembly
# 3. The function is not trivially simplified to just XOR
#
# Exit codes:
#   0 - MBA obfuscation is preserved
#   1 - MBA obfuscation was optimized away or verification failed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== MBA Obfuscation Verification ==="
echo ""

# Build in release mode with XOR feature
echo "Building release binary with XOR feature..."
cd "$PROJECT_DIR"
cargo build --release --no-default-features --features xor 2>/dev/null

# Find the library file
RLIB_FILE="$PROJECT_DIR/target/release/libobfuse_core.rlib"

if [ ! -f "$RLIB_FILE" ]; then
    echo "ERROR: Library file not found: $RLIB_FILE"
    exit 1
fi

# Extract assembly for mba_xor_deep function
# Use section boundary detection to extract the complete function
echo "Extracting assembly for mba_xor_deep..."

# Find the function and extract until the next function/section header
# The function ends at "ret" followed by a blank line or section header
ASSEMBLY=$(objdump -d "$RLIB_FILE" 2>/dev/null | \
    awk '/mba_xor_deep/{found=1} found{print; if(/^$/ && found>1) exit} found{found++}' | \
    head -300)

# Fallback to simpler grep if awk didn't capture enough
if [ "$(echo "$ASSEMBLY" | wc -l)" -lt 20 ]; then
    ASSEMBLY=$(objdump -d "$RLIB_FILE" 2>/dev/null | grep -A 300 "mba_xor_deep" | \
        sed -n '1,/^Disassembly of section/p' | head -n -1)
fi

if [ -z "$ASSEMBLY" ]; then
    echo "ERROR: Could not find mba_xor_deep function in disassembly"
    exit 1
fi

# Count the number of instructions
INSTRUCTION_COUNT=$(echo "$ASSEMBLY" | grep -E "^\s+[0-9a-f]+:" | wc -l)

echo "Found $INSTRUCTION_COUNT instructions in mba_xor_deep"

# Minimum expected instructions for proper obfuscation
# A simple XOR would be ~3 instructions, we expect at least 50
MIN_INSTRUCTIONS=50

if [ "$INSTRUCTION_COUNT" -lt "$MIN_INSTRUCTIONS" ]; then
    echo "FAILED: mba_xor_deep has only $INSTRUCTION_COUNT instructions"
    echo "Expected at least $MIN_INSTRUCTIONS instructions for proper obfuscation"
    echo ""
    echo "Assembly output:"
    echo "$ASSEMBLY"
    exit 1
fi

echo "✓ Instruction count check passed ($INSTRUCTION_COUNT >= $MIN_INSTRUCTIONS)"

# Check for presence of dummy constants in the assembly
# D1=0x5a, D2=0xa5, D3=0x3c, D4=0xc3
D1_COUNT=$(echo "$ASSEMBLY" | grep -c "\$0x5a" || true)
D2_COUNT=$(echo "$ASSEMBLY" | grep -c "\$0xa5" || true)
D3_COUNT=$(echo "$ASSEMBLY" | grep -c "\$0x3c" || true)
D4_COUNT=$(echo "$ASSEMBLY" | grep -c "\$0xc3" || true)

echo "Dummy constant occurrences: D1=$D1_COUNT, D2=$D2_COUNT, D3=$D3_COUNT, D4=$D4_COUNT"

TOTAL_CONSTANTS=$((D1_COUNT + D2_COUNT + D3_COUNT + D4_COUNT))

if [ "$TOTAL_CONSTANTS" -lt 4 ]; then
    echo "FAILED: Not enough dummy constants found in assembly"
    echo "Expected at least 4 constant occurrences, found $TOTAL_CONSTANTS"
    exit 1
fi

echo "✓ Dummy constants check passed ($TOTAL_CONSTANTS occurrences found)"

# Check that it's not just a simple XOR instruction
# A trivially simplified function would be just: mov, xor, ret (3-5 instructions)
# Check if the function ends too quickly (within first 10 lines)
FIRST_10_LINES=$(echo "$ASSEMBLY" | head -10)
RET_IN_FIRST_10=$(echo "$FIRST_10_LINES" | grep -c "	ret$" || true)

if [ "$RET_IN_FIRST_10" -gt 0 ] && [ "$INSTRUCTION_COUNT" -lt 10 ]; then
    echo "FAILED: Function appears to be trivially simplified (ret found too early)"
    echo "Assembly:"
    echo "$ASSEMBLY" | head -20
    exit 1
fi

echo "✓ Non-trivial assembly check passed"

# Check for MBA-characteristic operations (and, or, add, sub mixed together)
AND_COUNT=$(echo "$ASSEMBLY" | grep -cE "\s+and\s+" || true)
ADD_COUNT=$(echo "$ASSEMBLY" | grep -cE "\s+add\s+" || true)
SUB_COUNT=$(echo "$ASSEMBLY" | grep -cE "\s+sub\s+" || true)
XOR_COUNT=$(echo "$ASSEMBLY" | grep -cE "\s+xor\s+" || true)

echo "Operation counts: AND=$AND_COUNT, ADD=$ADD_COUNT, SUB=$SUB_COUNT, XOR=$XOR_COUNT"

TOTAL_OPS=$((AND_COUNT + ADD_COUNT + SUB_COUNT + XOR_COUNT))

if [ "$TOTAL_OPS" -lt 8 ]; then
    echo "FAILED: Not enough MBA operations found"
    echo "Expected at least 8 MBA operations (and/add/sub/xor), found $TOTAL_OPS"
    exit 1
fi

echo "✓ MBA operations check passed ($TOTAL_OPS operations found)"

echo ""
echo "=== All MBA obfuscation checks passed! ==="
echo ""
echo "Summary:"
echo "  - Instructions: $INSTRUCTION_COUNT"
echo "  - Dummy constants: $TOTAL_CONSTANTS"
echo "  - MBA operations: $TOTAL_OPS"
echo ""
echo "The MBA obfuscation is preserved in the compiled binary."

exit 0
