# Finding 2: zsh `PRIVILEGED` is not durable — `unsetopt privileged` silently no-ops (and still clears the flag) when real UID == effective UID == 0

**Target:** `speedyfriend433/zsh` (Apple's zsh fork, upstream base 5.9), branch `claude/trusting-babbage-twmg8u`, HEAD `666e91a` ("zsh-118")
**Class:** CWE-696 / CWE-284 (Improper Access Control) — a protection flag that can be cleared without the privilege reduction it's supposed to represent
**Relationship to Finding 1:** Distinct root cause. **Survives Finding 1's fix.** Verified against a build with Apple's own `.zlogout` patch applied.
**Confidence:** The core primitive (uid unchanged, flag cleared anyway) is fully verified by build + test below. The real-world trigger on macOS (whether `CS_INSTALLER`/`APPLE_PKGKIT_ESCALATING_ROOT` sessions ever run `unsetopt privileged` or equivalent) is **not** verified — I don't have access to Apple's actual installer internals from this environment. See "What's confirmed vs. inferred" at the end.

## Summary

Finding 1 showed that `.zlogout` wasn't gated by `PRIVILEGED` at all, and that Apple patched it in commit `666e91a` for `__APPLE__` builds. This finding shows that patch is **necessary but not sufficient**: the `PRIVILEGED` flag itself can be cleared with **zero actual privilege change** whenever the shell's real UID is already 0 — which is exactly the situation Apple's own `CS_INSTALLER` / `APPLE_PKGKIT_ESCALATING_ROOT` mechanism creates (a genuinely-root process, marked `PRIVILEGED` purely as a "don't trust this dotfile" signal, with no real/effective UID difference to begin with).

Once that flag is cleared — by any code running inside the session, including the shell's own documented best-practice idiom — **every** gate keyed on `unset(PRIVILEGED)` reopens: `.zlogout` (even with Finding 1's fix applied), and `.zshenv`/`.zprofile`/`.zshrc`/`.zlogin` if they haven't been sourced yet in that process.

## Root cause

`Src/options.c`, in `dosetopt()` (the code path behind `setopt`/`unsetopt`), handling `optno == PRIVILEGED && !value`:

```c
} else if(optno == PRIVILEGED && !value) {
    /* unsetting PRIVILEGED causes the shell to make itself unprivileged */
    ...
    if (setresgid(getgid(), getgid(), getgid())) { ... return -1; }
    ...
    if (setresuid(getuid(), getuid(), getuid())) { ... return -1; }
    ...
    /* no check anywhere that getuid() != 0 before any of this */
}
...
new_opts[optno] = value;   // unconditionally clears PRIVILEGED on success
```

This logic assumes the classic setuid scenario: real UID ≠ effective UID, so `setresuid(getuid(), getuid(), getuid())` genuinely drops effective privilege down to the lower real UID, and that's an intentional, irreversible, well-documented safety feature. The zsh manual explicitly teaches scripts to do this:

> `unsetopt privileged || exit` (`Doc/Zsh/options.yo:2455`)

But when real UID is **already 0** (no setuid involved — this is Apple's `CS_INSTALLER`/env-var-driven case specifically, not the classic one), `setresgid(0,0,0)` / `setresuid(0,0,0)` succeed trivially, change nothing, and the function falls through to clearing `opts[PRIVILEGED]` anyway. There is no check anywhere in this path for "is there actually a lower privilege to drop to." The flag goes from "this dotfile source is untrusted" to "trusted" with the process remaining full root throughout.

Apple's `PARANOID` option — used for the same kind of "don't trust this even though we're root" signalling (`Src/init.c:286`, `check_managed_config()`) — correctly avoids this problem: it has **no entry in the `setopt`/`unsetopt` name table** (`options.c`), so it can't be flipped by running code at all. `PRIVILEGED` doesn't get that protection, because it's also the long-standing, documented, user-facing option for classic setuid scripts — Apple can't silently lock it down without breaking that use case.

## PoC: proving this survives Finding 1's fix

To isolate this from Finding 1, I didn't just test the unpatched build — I took this repo's own source, applied Apple's exact `666e91a` fix to `.zlogout` unconditionally (removing the `#ifdef __APPLE__`, so the protection is active), rebuilt from that patched source, and re-ran the test against it.

**Patch applied before building** (mechanical, 3-line diff):
```diff
 if (islogin && !subsh) {
-#ifdef __APPLE__
     if (unset(PRIVILEGED))
         sourcehome(".zlogout");
-#else
-    sourcehome(".zlogout");
-#endif
```

**`finding2_poc.sh`** (root; self-cleaning). Two scenarios in the same `PRIVILEGED` session:

```bash
#!/bin/bash
set -euo pipefail
ZSH_BIN="${1:?usage: finding2_poc.sh /path/to/built/zsh}"
VICTIM_DIR=/tmp/finding2_poc_home
PROOF="$VICTIM_DIR/fired.txt"
trap 'rm -rf "$VICTIM_DIR"' EXIT

mkdir -p "$VICTIM_DIR"
cat > "$VICTIM_DIR/.zlogout" <<EOF
id >> $PROOF
echo "fired via .zlogout, euid=\$(id -u)" >> $PROOF
EOF
export ZDOTDIR="$VICTIM_DIR" HOME="$VICTIM_DIR"

run() {
    rm -f "$PROOF"
    printf '%s' "$2" | "$ZSH_BIN" -p -l -i 2>&1 | tail -6
    [ -f "$PROOF" ] && echo "FIRED: $(cat "$PROOF")" || echo "did not fire"
}

run "A (control)" 'id
exit
'

run "B (the bug)" 'id
unsetopt privileged
id
exit
'
```

## Fresh run output, against the *patched* (Finding-1-fixed) build

```
[*] real/effective uid of this whole demo: uid=0(root) gid=0(root) groups=0(root)

=== SCENARIO A (control): PRIVILEGED session, exits normally, no unsetopt ===
uid=0(root) gid=0(root) groups=0(root)
  RESULT: .zlogout did not fire

=== SCENARIO B (the bug): PRIVILEGED session runs the documented 'unsetopt privileged' idiom, then exits ===
before unsetopt:
uid=0(root) gid=0(root) groups=0(root)
after unsetopt (should be IDENTICAL to above if this were a real privilege drop):
uid=0(root) gid=0(root) groups=0(root)
  RESULT: .zlogout FIRED -- uid=0(root) gid=0(root) groups=0(root)
fired via .zlogout, euid=0
```

Scenario A on the patched binary is the expected, correct Finding-1-fixed behavior: `.zlogout` stays blocked. Scenario B, same patched binary, same session type, same real root the entire time (`id` output is byte-for-byte identical before and after `unsetopt privileged`) — but because something inside the session ran the one command zsh's own manual recommends privileged scripts run, `.zlogout` fires anyway. **The fix from Finding 1 is present and does nothing here, because its precondition (`PRIVILEGED` being set) was falsified by an unrelated, "successful," zero-effect command.**

For contrast, I also ran this same two-scenario test against the *unpatched* (upstream, no `.zlogout` guard at all) build — both scenarios fire there, which simply reproduces Finding 1 and doesn't by itself distinguish this bug; that log is included for completeness (`finding2_run_unpatched_build.log`) but the patched-build run above is the one that actually isolates Finding 2.

## Why this matters beyond `.zlogout`

The `.zlogout` fire is just the easiest single gate to observe. The actual defect is structural: `PRIVILEGED` is the *only* signal several independent protections rely on (startup-file sourcing, `PM_DONTIMPORT_SUID` parameter import in `Src/params.c:768`, trap handling in `Src/signals.c:672`), and none of them re-validate that the flag's clearing ever corresponded to a real privilege reduction. Any one of those is reopened the same way.

## Fix

Two independent options, either sufficient on its own:
1. In `options.c`'s `PRIVILEGED`-unset handler, refuse (return `-1`, as it already does for the "can't drop" error cases) when `getuid() == 0` and no real privilege reduction occurred — i.e., don't allow `unsetopt privileged` to be a no-op-but-still-succeed.
2. Stop overloading the user-facing `PRIVILEGED` option for the `CS_INSTALLER`/`APPLE_PKGKIT_ESCALATING_ROOT` "don't trust this even though we're root" signal. Use a second, internal-only flag for that purpose — exactly the pattern Apple already uses correctly for `PARANOID`, which has no `setopt`/`unsetopt` entry and can't be touched by running code.

## What's confirmed vs. inferred

- **Confirmed by build + test:** `unsetopt privileged` succeeds and leaves `id` completely unchanged when real UID is already 0; `opts[PRIVILEGED]` is cleared regardless; this reopens a gate that was otherwise correctly closed by Finding 1's exact fix, verified by applying that fix to a fresh build and re-testing against it.
- **Not confirmed (can't be, from this environment):** whether any real macOS code path that sets `PRIVILEGED` via `CS_INSTALLER`/`APPLE_PKGKIT_ESCALATING_ROOT` ever executes `unsetopt privileged` or an equivalent (`set +p`) before that process's eventual exit or further dotfile consultation. That depends on Apple's actual installer/postinstall script conventions, which I have no visibility into from this Linux sandbox. The primitive this finding demonstrates is real and lives in shared, non-`__APPLE__`-gated code identical to what macOS ships; whether it's reachable in practice on a given macOS version is a scoping question for whoever can inspect real installer scripts or has Apple-internal context.
