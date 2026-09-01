---
slug: plaid-api-key
name: Plaid API Key Exposure
description: 'Hardcoded Plaid secret keys or access tokens in source or config. Plaid connects to bank accounts — leaked credentials can access linked bank account data, balances, and transaction history.'
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
    - regex: '(?i)(?:plaid|PLAID_SECRET|PLAID_CLIENT_SECRET).{0,30}[=:"''\s]+[a-f0-9]{30,}'
      label: Plaid secret key in named variable
    - regex: '\baccess-(?:production|development|sandbox)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
      label: Plaid access token (access-{env}-UUID format)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Plaid credentials. Plaid provides access to users' bank account data — leaking credentials exposes financial data and enables unauthorized bank account access.

## Credential types

**Client Secret (32-64 hex chars):** authenticates the application to Plaid's API. Combined with Client ID.

**Access token:** `access-<environment>-<UUID>` — per-user tokens granting access to a specific linked bank account.

**Client ID:** ~24 alphanumeric chars — public, not a secret by itself.

## What leaked credentials enable

**Client Secret:** exchange public tokens for access tokens (link bank accounts without user consent).

**Access token (`access-production-...`):** read bank balances and transaction history, read account numbers and routing numbers, initiate transfers (if Plaid Transfer enabled).

## True positive criteria

Flag at critical severity:
1. `access-production-...` token — this is a live user's bank connection

Flag at high severity:
2. `PLAID_SECRET` set to a literal hex string

Flag at lower severity:
3. `access-sandbox-...` or `access-development-...` tokens

## What to ignore

- `PLAID_CLIENT_ID` — public identifier
- Link tokens — temporary, short-lived

## Examples

True positive:
```env
PLAID_SECRET=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
PLAID_ACCESS_TOKEN=access-production-a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Report the environment (production/development/sandbox), what Plaid products are used (Transactions, Auth, Transfer), and whether user-level access tokens are hardcoded.
