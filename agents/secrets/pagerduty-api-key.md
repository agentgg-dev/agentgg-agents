---
slug: pagerduty-api-key
name: PagerDuty API Key Exposure
description: 'Hardcoded PagerDuty API keys or integration keys in source or config. API keys grant access to on-call schedules and incident management; integration keys allow triggering or resolving incidents.'
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
    - regex: '(?i)(?:pagerduty|PAGERDUTY_TOKEN|PD_TOKEN|PD_API_KEY).{0,30}[=:"''\s]+[A-Za-z0-9+/_\-]{20,}'
      label: PagerDuty API token in named variable
    - regex: '\bu\+[a-zA-Z0-9_\-]{18}\b'
      label: PagerDuty user API token (u+ prefix)
    - regex: '(?i)(?:routing_key|integration_key|service_key)\s*[=:"''\s]+[a-f0-9]{32}'
      label: PagerDuty Events API integration key (32 hex)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded PagerDuty credentials.

## Credential types

**REST API key:** 20+ alphanumeric chars near `PAGERDUTY_TOKEN`/`PD_API_KEY`. Full account access.

**User API token (`u+...`):** personal user token.

**Events API v2 integration key:** 32 lowercase hex chars in `routing_key`/`integration_key` fields. Used to send alerts to a service.

## What leaked credentials enable

**REST API key:** read on-call schedules (who is on-call, their contact info), silence alerts, create fake incidents, modify escalation policies.

**Integration key:** send arbitrary alerts (noise injection), trigger or resolve real incidents.

## True positive criteria

Flag when ALL hold:
1. Credential appears near "pagerduty", `PD_TOKEN`, or in a `routing_key`/`integration_key` field
2. String literal, not env var reference
3. Not a placeholder

## Examples

True positive:
```yaml
pagerduty:
  routing_key: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```

Report whether it's a REST API key (full account access) or an Events API key (alert-only).
