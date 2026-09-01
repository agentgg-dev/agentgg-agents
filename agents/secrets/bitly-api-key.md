---
slug: bitly-api-key
name: Bitly API Key Exposure
description: 'Hardcoded Bitly OAuth access tokens (R_ prefix + 32 hex) in source or config. Grants access to create, read, and delete short links, access click analytics, and manage custom branded domains.'
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
    - regex: '\bR_[0-9a-f]{32}\b'
      label: Bitly OAuth access token (R_ prefix)
    - regex: '(?i)(?:bitly|BITLY_TOKEN|BITLY_API_KEY).{0,30}[=:"''\s]+[A-Za-z0-9_\-]{20,}'
      label: Bitly token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Bitly API credentials.

## Token format

```
R_<32 lowercase hex characters>
```

## What a leaked token enables

- Create, update, and delete any short link in the account
- Read click analytics for all links (reveals campaign data, visitor counts)
- Enumerate all links (may reveal internal URLs "obscured" via short links)
- Modify redirect targets — redirect legitimate short links to attacker-controlled pages

## True positive criteria

Flag when ALL hold:
1. Value matches `R_[0-9a-f]{32}` exactly
2. String literal, not `process.env.BITLY_TOKEN`
3. Not a placeholder

## What to ignore

- Bitly short link URLs (`https://bit.ly/...`) — not credentials
- The domain `bit.ly` without an adjacent token

## Examples

True positive:
```python
bitly_token = 'R_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
```

Report what the code does with the token (create links for end-user redirects is higher risk).
