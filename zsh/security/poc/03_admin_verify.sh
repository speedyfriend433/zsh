#!/bin/bash
# ADMIN-ONLY VERIFICATION. Requires root (same as any admin inspecting /root
# after the fact -- this is not part of the attack, the attacker never runs
# or needs this).
set -uo pipefail

PROOF=/root/pwned_by_zlogout_poc.txt
CONTROL=/root/should_not_exist.txt

echo "[admin] checking outcome:"
if [ -f "$CONTROL" ]; then
    echo "    FAIL: .zshrc ran (should have been blocked by PRIVILEGED)"
else
    echo "    OK:   .zshrc correctly blocked by PRIVILEGED"
fi

if [ -f "$PROOF" ]; then
    echo "    VULN: .zlogout ran despite PRIVILEGED -- owner is $(stat -c '%U:%G' "$PROOF")"
    echo "    --- contents (written by code the attacker authored, with root's privileges) ---"
    cat "$PROOF"
else
    echo "    OK:   .zlogout did not run (not vulnerable on this build)"
fi
