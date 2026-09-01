---
slug: ansible-vault-committed
name: Ansible Vault Encrypted Secret Committed
description: 'Ansible Vault-encrypted files or inline vault strings committed to the repository alongside a discoverable vault password. The vault password in CI config or a committed password file decrypts all encrypted secrets at once.'
version: 0.1.0
author: agentgg
noiseTier: normal
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '^\$ANSIBLE_VAULT;[0-9]+\.[0-9]+;AES256'
      label: Ansible Vault encrypted file header
    - regex: '!\s*vault\s*\|'
      label: Ansible inline vault string
    - regex: '\$ANSIBLE_VAULT;'
      label: Ansible Vault marker (any version)
references:
  - CWE-321
  - CWE-798
  - 'OWASP-A02:2021'
---

You are reviewing repositories for Ansible Vault-encrypted secrets committed alongside a findable vault password. The vault encryption is symmetric — if the vault password is discoverable, all encrypted secrets are exposed at once.

## Vault formats

**Encrypted file header:**
```
$ANSIBLE_VAULT;1.1;AES256
<hex-encoded encrypted data>
```

**Inline vault string (YAML):**
```yaml
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  31313131...
```

## When this is a finding

Vault files alone are not a finding — the encryption is working as intended. Flag when BOTH are present:

1. **Vault-encrypted files are committed** AND
2. **The vault password is also findable:**
   - A file named `.vault_pass`, `.vault_password`, `vault_pass.txt`, or similar is committed
   - A CI config (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`) contains `ANSIBLE_VAULT_PASSWORD` set to a literal string
   - `ansible.cfg` has `vault_password_file = /path/to/committed/file`

## Cross-file analysis

When vault markers are found, actively look for:
1. Any file named `.vault_pass*` or `vault_password*` in the repository
2. CI/CD config files containing `ANSIBLE_VAULT_PASSWORD` with a literal value
3. `ansible.cfg` with `vault_password_file` pointing to a file that exists in the repo

## True positive criteria

Flag at critical severity:
1. Vault-encrypted files committed AND vault password file also committed in plaintext

Flag at high severity:
2. Vault-encrypted files committed AND CI config contains `ANSIBLE_VAULT_PASSWORD=<literal>`

Note only (do not flag as vulnerability):
3. Vault-encrypted files committed without any findable vault password

## Examples

Critical:
```
# Both present in repo:
group_vars/production/vault.yml   # $ANSIBLE_VAULT;1.1;AES256 ...
.vault_pass                       # plaintext: mysupersecretpassword
```

High:
```yaml
# .github/workflows/deploy.yml
env:
  ANSIBLE_VAULT_PASSWORD: hunter2
```

Report how many vault files are present, whether the vault password is also findable, and what variables are encrypted (readable from the variable names in the YAML).
