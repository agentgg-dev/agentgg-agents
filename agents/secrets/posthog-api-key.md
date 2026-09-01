---
slug: posthog-api-key
name: PostHog API Key Exposure
description: 'Hardcoded PostHog project API keys (phc_ prefix, 43 chars) or personal API keys in source or config. Grants access to product analytics data, feature flags, and user session recordings.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
    - regex: '\bphc_[a-zA-Z0-9_]{43}\b'
      label: PostHog project API key (phc_ prefix)
    - regex: '(?i)(?:POSTHOG_API_KEY|POSTHOG_PERSONAL_API_KEY).{0,20}[=:"''\s]+[A-Za-z0-9_\-]{40,}'
      label: PostHog personal API key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded PostHog credentials. PostHog is an open-source product analytics platform.

## Credential types

**Project API key (`phc_...`):** used to capture events from client or server. This key is semi-public (used in browser JS) but should not be embedded in server-side code that also has backend access.

**Personal API key:** used to access the PostHog API for reading analytics data, feature flags, and session recordings. Should never be public.

## What a leaked personal API key enables

- Read all analytics events, user properties, and session recordings (may contain PII)
- Access feature flag configurations
- Read cohort definitions and experiment results
- Access user email addresses and custom properties sent as analytics data

## True positive criteria

Flag at higher severity:
1. A personal API key (long alphanumeric near `POSTHOG_PERSONAL_API_KEY`) — string literal

Flag at lower severity:
2. A `phc_` project key in server-side backend code (not browser JS where it's expected)

## What to ignore

- `phc_` keys in browser JavaScript bundles — expected usage for event capture
- Environment variable references

## Examples

True positive (personal API key):
```python
import posthog
posthog.personal_api_key = 'AbCdEfGhIjKlMnOpQrStUvWxYz01234567890123456789'
```

Report whether it's a project key (semi-public) or personal API key (should be private).
