---
slug: algolia-api-key
name: Algolia API Key Exposure
description: 'Hardcoded Algolia Admin API keys or Search-Only API keys committed to source. Admin keys allow index creation/deletion and full data access; Search-Only keys still expose search analytics and index contents.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)algolia.{0,30}[=:"''\s]+[a-z0-9]{32}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Algolia key near algolia keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{32})(?:[''"\n\r\s`;]|$)'
      label: Algolia 32-char API key pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Algolia API keys.

## Key types

- **Admin API key**: 32-char hex string. Full control — create/delete indices, modify settings, read/write all data.
- **Search-Only API key**: also 32-char hex. Can query indices, reveals full index contents and analytics.
- **Application ID**: appears alongside the key but is not itself a secret.

## True positive criteria

Flag when ALL hold:
1. A 32-char lowercase hex string appears near `algolia`, `ALGOLIA_API_KEY`, `ALGOLIA_ADMIN_KEY`, or `X-Algolia-API-Key`
2. It is a string literal, not `process.env.ALGOLIA_API_KEY` or `${{ secrets.ALGOLIA_KEY }}`
3. Not a test/placeholder value like `YOUR_API_KEY_HERE` or `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## What to ignore

- The Algolia Application ID (10-char uppercase alphanumeric like `YH9Q6E5QRM`) — not a secret, can be public
- Placeholder values or documentation examples
- References to `process.env`, `os.environ`, secret manager calls

Report: whether it appears to be an Admin key or Search-Only key (based on variable name like `ALGOLIA_ADMIN_KEY` vs. `ALGOLIA_SEARCH_KEY`), and where in the codebase it appears.
