---
slug: square-api-key
name: Square Payment API Key Exposure
description: 'Hardcoded Square access tokens (sq0atp- or EAAA prefix) or OAuth secrets (sq0csp-) in source or config. Grants access to Square payment processing, customer profiles, inventory, and transaction history.'
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
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bsq0atp-[0-9A-Za-z_\-]{22}\b'
      label: Square access token (sq0atp-)
    - regex: '\bsq0csp-[0-9A-Za-z_\-]{43}\b'
      label: Square OAuth client secret (sq0csp-)
    - regex: '\bEAAA[A-Za-z0-9]{60,}\b'
      label: Square production OAuth access token (EAAA prefix)
    - regex: '\bEAAB[A-Za-z0-9]{60,}\b'
      label: Square sandbox OAuth access token (EAAB prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Square payment credentials.

## Token formats

**Access token:** `sq0atp-<22 alphanumeric chars>`
**OAuth client secret:** `sq0csp-<43 alphanumeric chars>` — used to authenticate OAuth flows
**OAuth access token:** `EAAA...` (production) or `EAAB...` (sandbox) + 60+ chars

## What leaked credentials enable

- Process payment charges on the merchant's Square account
- Read all transaction history (amounts, customer names, card types)
- Access customer profiles and stored card tokens
- Create or void refunds
- Read inventory and loyalty program data

## True positive criteria

Flag at high severity:
1. Any `sq0atp-`, `sq0csp-`, or `EAAA...` token — string literal, not env var

Flag at lower severity:
2. `EAAB...` sandbox token — note credential pattern

## Examples

True positive:
```python
client = Client(access_token='sq0atp-AbCdEfGhIjKlMnOpQrStU', environment='production')
```
```env
SQUARE_ACCESS_TOKEN=EAAAEMypBjAWlongtokenhere...
```

Report whether the token is production or sandbox and what Square APIs the code uses.
