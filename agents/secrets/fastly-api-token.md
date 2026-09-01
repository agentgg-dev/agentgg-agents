---
slug: fastly-api-token
name: Fastly API Token Exposure
description: 'Hardcoded Fastly API tokens committed to source. Grants access to CDN configuration, edge cache management, TLS certificate management, and service traffic routing.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)fastly.{0,30}[=:"''\s]+[a-z0-9_-]{32}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Fastly API token near fastly keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:fastly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9=_\-]{32})(?:[''"\n\r\s`;]|$)'
      label: Fastly 32-char API token
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Fastly API tokens.

## Token format

Fastly API tokens: 32-char alphanumeric string (may include `-` and `_`). Created at manage.fastly.com/account/personal/tokens.

## What a leaked token enables

- Read and modify Fastly service configuration (CDN routing, cache rules, VCL)
- Purge or invalidate CDN cache — can cause cache poisoning or force revalidation
- Manage TLS certificates and domains
- Access Fastly logging endpoints which may contain user traffic data

## True positive criteria

Flag when ALL hold:
1. A 32-char string appears near `fastly`, `FASTLY_TOKEN`, `FASTLY_API_KEY`, or `Fastly-Key` HTTP header
2. String literal, not `process.env.FASTLY_SERVICE_TOKEN`
3. Not a Fastly service ID (those are alphanumeric with a different structure)

## What to ignore

- Fastly service IDs — not secret, used as routing identifiers
- `process.env.FASTLY_API_TOKEN` — safe env reference

Report: whether the token appears in infrastructure/deploy scripts (higher risk) vs. application code, and any Fastly service IDs visible nearby.
