---
slug: hashicorp-vault-token
name: HashiCorp Vault / Terraform Cloud Token Exposure
description: 'Hardcoded HashiCorp Terraform Cloud / HCP API tokens (atlasv1 prefix) or Vault root/service tokens in source or config. These tokens grant access to infrastructure state, secret backends, and cloud credentials managed by Vault.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}'
      label: HashiCorp Terraform Cloud / HCP API token (atlasv1)
    - regex: '(?i)vault.{0,30}(?:token|auth).{0,20}["\s=:]+s\.[a-zA-Z0-9]{24}\b'
      label: HashiCorp Vault service token (s. prefix)
    - regex: '\bhvs\.[a-zA-Z0-9_-]{90,120}\b'
      label: HashiCorp Vault service token (hvs. prefix, newer format)
    - regex: '\bhvb\.[a-zA-Z0-9_-]{90,120}\b'
      label: HashiCorp Vault batch token (hvb. prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded HashiCorp Vault or Terraform Cloud tokens. HashiCorp tools manage infrastructure state and secrets — a leaked token is often the key to cloud credentials, database passwords, and TLS certificates stored in Vault.

## Token formats

**Terraform Cloud / HCP (HashiCorp Cloud Platform):**
```
<14-char-id>.atlasv1.<60-70-char-base64url>
```
Example: `xxxxxxxxxxxxxx.atlasv1.yyyyyyyyyyyyy...`

Used to authenticate with Terraform Cloud's API: read/write workspace state, trigger runs, access variables (which may contain cloud credentials), and manage organizations.

**HashiCorp Vault service tokens (older format):**
```
s.<24-alphanumeric>
```
Example: `s.7vgRBvSM7cKLPjy0vFxMTF1K`

**HashiCorp Vault service tokens (newer format):**
```
hvs.<90-120-char-base64url>
```

**Vault batch tokens:**
```
hvb.<90-120-char-base64url>
```

Root tokens (`hvs.` with no TTL policy) are the most dangerous — they bypass all Vault policies.

## What a leaked token enables

**Terraform Cloud token:** access to all workspaces the token's user can reach — this includes reading workspace variables, which often contain `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and other cloud credentials.

**Vault token:** depends on attached policies. A broad or root token grants:
- Reading any secret (database passwords, API keys, TLS private keys)
- Writing secrets (injection attacks)
- Managing Vault auth methods and policies
- Generating dynamic cloud credentials (AWS, GCP, Azure via Vault's secrets engines)

## Cross-file analysis

1. Look for what secrets or workspaces the token accesses — determines blast radius
2. Check if the token appears in `.terraformrc`, `~/.terraform.d/credentials.tfrc.json`, or Terraform backend config — these are common locations for committed tokens
3. For Vault tokens, look for `VAULT_ADDR` nearby to identify which Vault cluster is affected

## True positive criteria

Flag when ALL hold:
1. The value matches one of the patterns above
2. It is a string literal, not an environment variable reference
3. It is not an obvious placeholder or test value

## What to ignore

- `VAULT_TOKEN` read from environment: `os.getenv("VAULT_TOKEN")`, `process.env.VAULT_TOKEN`
- Terraform backend config using env vars: `token = var.tfc_token` or `token = ""`  with the actual value in a `.tfvars` that is gitignored
- Test tokens in clearly scoped test fixtures against a local dev Vault

## Examples

True positives:
```
# .terraformrc or credentials.tfrc.json committed to repo
credentials "app.terraform.io" {
  token = "xxxxxxxxxxxxxx.atlasv1.yyyyyyyyyyyyyyyy..."
}
```
```yaml
# CI config
VAULT_TOKEN: hvs.CAESINH2...
VAULT_ADDR: https://vault.prod.internal:8200
```

False positives to skip:
```
token = var.vault_token
```
```yaml
VAULT_TOKEN: ${VAULT_TOKEN}
```

Report which token format it is (Terraform Cloud vs Vault), what cluster/org it targets if visible, and what secrets or workspaces the surrounding code accesses.
