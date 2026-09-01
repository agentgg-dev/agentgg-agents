---
slug: snyk-api-key
name: Snyk API Key Exposure
description: 'Hardcoded Snyk API tokens (UUID format near snyk context) in source or config. Grants access to Snyk vulnerability reports, project scan results, and organization settings.'
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
    - regex: '(?i)(?:snyk|SNYK_TOKEN|SNYK_API_KEY).{0,30}[=:"''\s]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
      label: Snyk API token (UUID format near "snyk")
    - regex: '(?i)(?:SNYK_TOKEN|SNYK_API)\s*[=:]\s*[''"]?[a-f0-9\-]{36}\b'
      label: Snyk token env var with UUID value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Snyk API tokens.

## Token format

Snyk API tokens are UUIDs: `<xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>`

Found in `SNYK_TOKEN` environment variable.

## What a leaked token enables

- Read all Snyk projects and their vulnerability reports (reveals which known CVEs are in your dependencies — valuable to attackers planning targeted attacks)
- Trigger new security scans
- Read ignored vulnerabilities (reveals accepted risk decisions)
- Access organization settings and member list
- In some configs: access integrated source repositories

## True positive criteria

Flag when ALL hold:
1. UUID appears near "snyk", `SNYK_TOKEN`, or `SNYK_API`
2. String literal, not `${{ secrets.SNYK_TOKEN }}`
3. Not a placeholder UUID (all zeros, `xxxxxxxx-xxxx...`)

## Examples

True positive:
```yaml
env:
  SNYK_TOKEN: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Report which Snyk organization or projects are associated with the token.
