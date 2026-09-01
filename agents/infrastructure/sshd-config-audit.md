---
slug: sshd-config-audit
name: SSHD Configuration Hardening Audit
description: 'sshd_config security checks: PermitRootLogin yes, PermitEmptyPasswords yes, Protocol 1 (deprecated), no idle timeout (ClientAliveInterval missing), MaxAuthTries commented out, PasswordAuthentication enabled — all weaken SSH security posture.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'PermitRootLogin|PermitEmptyPasswords|ClientAliveInterval|MaxAuthTries|PasswordAuthentication'
        in:
          - '**/sshd_config'
          - '**/*.conf'
          - '**/ssh/**'
        notIn:
          - '**/node_modules/**'
        label: sshd_config directives found
where:
  filePatterns:
    - '**/sshd_config'
    - '**/sshd_config.d/**'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
  preFilter:
    - regex: 'PermitRootLogin\s+yes'
      label: Root login permitted
    - regex: 'PermitEmptyPasswords\s+yes'
      label: Empty passwords allowed
    - regex: '^Protocol\s+1'
      label: SSH Protocol 1 (deprecated, insecure)
    - regex: '#\s*MaxAuthTries|^MaxAuthTries\s+[6-9]|^MaxAuthTries\s+[1-9][0-9]'
      label: MaxAuthTries commented out or set too high
    - regex: 'PasswordAuthentication\s+yes'
      label: Password authentication enabled (should use keys only)
    - regex: '# This is the sshd server system-wide configuration file'
      label: Standard sshd_config file header
references:
  - CWE-307
  - CWE-521
  - CWE-284
---

You are auditing committed `sshd_config` files for security hardening gaps. Each misconfiguration weakens SSH against brute-force, unauthorized access, or protocol downgrade attacks.

## Checks to perform

### PermitRootLogin — should be "no"

```
PermitRootLogin yes     # critical: direct root login allowed
PermitRootLogin no      # correct
PermitRootLogin prohibit-password  # acceptable: root via key only
```

Direct root login bypasses audit trails (actions are not attributed to a user) and allows brute-force to directly target the most privileged account.

### PermitEmptyPasswords — should be "no"

```
PermitEmptyPasswords yes  # critical: accounts without passwords can log in
PermitEmptyPasswords no   # correct
```

Accounts with empty passwords (common on misconfigured systems) become accessible to anyone.

### Protocol version — should not include "1"

```
Protocol 1    # critical: SSH Protocol 1 has known cryptographic weaknesses
Protocol 2    # correct
```

SSHv1 is vulnerable to man-in-the-middle attacks and session hijacking. Modern OpenSSH (7.6+) dropped Protocol 1 support entirely — this finding indicates very old software.

### Idle timeout — ClientAliveInterval should be set

```
# ClientAliveInterval   # high: commented out — idle sessions never expire
ClientAliveInterval 0   # high: disabled — no timeout
ClientAliveInterval 300 # correct: 5-minute timeout
```

Without an idle timeout, unattended SSH sessions (e.g., from a workstation left unlocked) remain open indefinitely.

### MaxAuthTries — should be 3 or less

```
#MaxAuthTries           # high: default is 6 — brute-force opportunity
MaxAuthTries 6          # high: default, too permissive
MaxAuthTries 3          # correct: limits brute-force attempts
```

### PasswordAuthentication — should be "no" if key auth is enforced

```
PasswordAuthentication yes  # high: allows password-based brute-force
PasswordAuthentication no   # correct: key-only authentication
```

## True positive criteria

Flag at critical:
1. `PermitRootLogin yes`
2. `PermitEmptyPasswords yes`
3. `Protocol 1`

Flag at high:
4. `#MaxAuthTries` or `MaxAuthTries >= 6`
5. `ClientAliveInterval` not set or set to 0
6. `PasswordAuthentication yes` (if no key-based fallback enforcement)

## What to ignore

- Configurations in documentation or example files (non-functional)
- Settings overridden by `sshd_config.d/*.conf` drop-ins (look for the effective value)

Report: each misconfigured directive found, its current value, and the recommended safe value.
