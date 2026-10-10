#!/bin/bash
# ADMIN-ONLY, ONE-TIME SETUP. Requires root/sudo.
#
# This step is NOT part of the attack. It only recreates the ordinary,
# already-existing real-world precondition for this bug class: a zsh
# binary that runs with elevated effective privileges relative to the
# real user invoking it. On a real system this precondition already
# exists without any attacker action, e.g.:
#   - a setuid-root zsh (same thing this script does), or
#   - Apple's installer flow invoking genuinely-root zsh and marking it
#     PRIVILEGED via APPLE_PKGKIT_ESCALATING_ROOT / CS_INSTALLER.
# An attacker does not need sudo and is never asked for a password here
# or anywhere in 02_attacker_exploit.sh.
set -euo pipefail

ZSH_BIN="${1:?usage: 01_admin_setup.sh /path/to/built/zsh}"
WORK=/tmp/zlogout_poc
SUID_ZSH="$WORK/zsh-suid"

mkdir -p "$WORK"
cp "$ZSH_BIN" "$SUID_ZSH"
chown root:root "$SUID_ZSH"
chmod 4755 "$SUID_ZSH"
chmod 1777 "$WORK"            # world-traversable so the unprivileged user can reach it

id poc_attacker >/dev/null 2>&1 || useradd -m -s /bin/bash poc_attacker

echo "[admin] installed setuid-root zsh at $SUID_ZSH:"
ls -la "$SUID_ZSH"
echo "[admin] unprivileged test account ready:"
id poc_attacker
echo
echo "[admin] setup done. Everything from here runs as poc_attacker, no sudo, no password."
